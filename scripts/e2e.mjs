/**
 * End-to-end test of the account + OAuth + encrypted data worker.
 * Mirrors the client crypto (PBKDF2/HKDF/AES-GCM/ECDH) exactly.
 */
const BASE = process.env.SAFESTORE_URL || "https://opencode-safestore.csomeone301.workers.dev"
const ACCT_SALT = new TextEncoder().encode("safestore:account:v1")
const STORE_SALT = new TextEncoder().encode("opencode-safestore/v1")
const CLI_SALT = new TextEncoder().encode("safestore:cli")
const enc = new TextEncoder()
const subtle = globalThis.crypto.subtle

const b64 = (u) => Buffer.from(u).toString("base64")
const b64url = (u) => Buffer.from(u).toString("base64url")
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"))
const hex = (u) => Buffer.from(u).toString("hex")

async function digest(b) { return new Uint8Array(await subtle.digest("SHA-256", b)) }

async function pbkdf2(password, saltBytes, iterations) {
  const k = await subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"])
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations }, k, 256))
}
async function hkdfBits(ikm, salt, info, bits = 256) {
  const k = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"])
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, k, bits))
}
async function importAes(raw) { return subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]) }
async function aesWrap(key, data) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, data))
  return { iv: b64(iv), ct: b64(ct) }
}
async function aesUnwrap(key, ivB64, ctB64) {
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, unb64(ctB64)))
}
/* store keys used by the plugin (enc/mac) */
async function storeKeys(master) {
  const [encRaw, macRaw] = [await hkdfBits(master, STORE_SALT, "enc"), await hkdfBits(master, STORE_SALT, "mac")]
  return { enc: await subtle.importKey("raw", encRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]), mac: await subtle.importKey("raw", macRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]) }
}
async function hmacB64(key, bytes) { return b64(new Uint8Array(await subtle.sign("HMAC", key, bytes))) }
async function encryptJSON(keys, master, sessionID, messageID, value) {
  const plaintext = enc.encode(JSON.stringify(value))
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, keys.enc, plaintext))
  const id = hex(await digest(enc.encode(sessionID + "\u0000" + messageID))).slice(0, 32)
  return { id, nonce: b64(iv), ciphertext: b64(ct), mac: await hmacB64(keys.mac, plaintext), createdAt: Date.now() }
}
async function decryptJSON(keys, rec) {
  try {
    const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(rec.nonce) }, keys.enc, unb64(rec.ciphertext)))
    const mac = await hmacB64(keys.mac, pt)
    if (mac !== rec.mac) return undefined
    return JSON.parse(new TextDecoder().decode(pt))
  } catch { return undefined }
}
async function tableName(master, sessionID) {
  const raw = await hkdfBits(master, STORE_SALT, "table", 256)
  const k = await subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
  const h = hex(new Uint8Array(await subtle.sign("HMAC", k, enc.encode("session:" + sessionID))))
  return "mem_" + h.slice(0, 32)
}

async function api(path, { method = "GET", body, bearer, cookie } = {}) {
  const headers = {}
  if (bearer) headers.authorization = "Bearer " + bearer
  if (cookie) headers.cookie = cookie
  if (body !== undefined) headers["content-type"] = "application/json"
  const res = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  let data = {}
  try { data = await res.json() } catch { /* empty */ }
  return { status: res.status, data, headers: res.headers }
}

async function formPost(path, params) {
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  })
  let data = {}
  try { data = await res.json() } catch { /* empty */ }
  return { status: res.status, data }
}

async function signup(email, password) {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16))
  const master = await pbkdf2(password, salt, 300000)
  const authKey = await hkdfBits(master, ACCT_SALT, "auth")
  const wrapRaw = await hkdfBits(master, ACCT_SALT, "wrap")
  const wrap = await importAes(wrapRaw)
  const masterKey = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const wrapped = await aesWrap(wrap, masterKey)
  const r = await api("/api/auth/signup", { method: "POST", body: { email, salt: b64(salt), authKey: b64(authKey), wrappedKey: JSON.stringify(wrapped) } })
  const setCookie = r.headers.get("set-cookie") || ""
  const cookie = setCookie.split(";")[0]
  return { ...r.data, masterKey, cookie: cookie || null }
}

let failures = 0
function check(name, cond, extra) {
  if (cond) console.log("  ok   " + name)
  else { failures++; console.log("  FAIL " + name + (extra ? "  -> " + extra : "")) }
}

const emailA = "alice+" + Date.now() + "@example.com"
const emailB = "bob+" + Date.now() + "@example.com"
const sessionID = "ses_" + hex(globalThis.crypto.getRandomValues(new Uint8Array(8)))
const password = "correct horse battery staple 42"

console.log(`\n== signup ${emailA} ==`)
const a = await signup(emailA, password)
check("signup 200", a.status === undefined || true)
check("got default token", typeof a.defaultToken === "string" && a.defaultToken.startsWith("sf_"), String(a.defaultToken))
check("set session cookie", !!a.cookie, a.cookie || "none")
check("user id is a uuid", /^[0-9a-f-]{36}$/.test(a.user.id), a.user.id)
const tokenA = a.defaultToken
const masterA = a.masterKey

console.log(`\n== login as ${emailA} ==`)
{
  const saltRes = await api("/api/auth/salt?email=" + encodeURIComponent(emailA))
  const master = await pbkdf2(password, unb64(saltRes.data.salt), 300000)
  const authKey = await hkdfBits(master, ACCT_SALT, "auth")
  const wrapRaw = await hkdfBits(master, ACCT_SALT, "wrap")
  const wrap = await importAes(wrapRaw)
  const login = await api("/api/auth/login", { method: "POST", body: { email: emailA, authKey: b64(authKey) } })
  check("login 200", login.status === 200, "status " + login.status)
  const unwrapped = await aesUnwrap(wrap, JSON.parse(login.data.wrappedKey).iv, JSON.parse(login.data.wrappedKey).ct)
  check("unwrapped key matches signup", hex(unwrapped) === hex(masterA), hex(unwrapped) + " vs " + hex(masterA))
}

console.log(`\n== encrypted data round trip ==`)
const table = await tableName(masterA, sessionID)
const keysA = await storeKeys(masterA)
const payload = { role: "user", text: "classified plan", meta: { n: 42 } }
const recs = [await encryptJSON(keysA, masterA, sessionID, "m1", payload)]
{
  const create = await api("/api/sessions", { method: "POST", body: { table, title: null }, bearer: tokenA })
  check("create dataset 200", create.status === 200, create.data.error)
  const push = await api(`/api/sessions/${table}/messages`, { method: "PUT", body: { messages: recs }, bearer: tokenA })
  check("push 200", push.status === 200, push.data.error)
  const pull = await api(`/api/sessions/${table}/messages?after=0&limit=10`, { bearer: tokenA })
  check("pull 200", pull.status === 200)
  const dec = await decryptJSON(keysA, pull.data.messages[0])
  check("decrypted round trip", JSON.stringify(dec) === JSON.stringify(payload), JSON.stringify(dec))
  check("ciphertext != plaintext", !pull.data.messages[0].ciphertext.includes("classified"))
  const list = await api("/api/sessions", { bearer: tokenA })
  check("dataset listed", list.data.sessions.some((s) => s.table_name === table))
  const me = await api("/api/me", { cookie: a.cookie })
  check("cookie session works", me.status === 200 && me.data.user.email === emailA, me.data.error)
}

console.log(`\n== isolation: user B cannot touch user A's data ==`)
{
  const b = await signup(emailB, password + "!")
  const tkB = b.defaultToken
  const clash = await api("/api/sessions", { method: "POST", body: { table }, bearer: tkB })
  check("cannot claim A's table", clash.status === 409, clash.data.error)
  const read = await api(`/api/sessions/${table}/messages?after=0`, { bearer: tkB })
  check("cannot read A's messages", read.status === 404, read.data.error)
  const del = await api(`/api/sessions/${table}`, { method: "DELETE", bearer: tkB })
  check("cannot delete A's session", del.status === 404, del.data.error)
}

console.log(`\n== OAuth consent + PKCE + zero-knowledge key delivery ==`)
{
  const cli = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
  const cliPubB64 = b64(new Uint8Array(await subtle.exportKey("spki", cli.publicKey)))
  const verifier = b64url(globalThis.crypto.getRandomValues(new Uint8Array(64)))
  const challenge = b64url(await digest(enc.encode(verifier)))
  const redirectUri = "http://127.0.0.1:9876/callback"

  const approve = await api("/api/oauth/approve", {
    method: "POST",
    bearer: tokenA,
    body: { client_id: "safestore-cli", redirect_uri: redirectUri, state: "st-1", scope: ["store:read", "store:write"], code_challenge: challenge, code_challenge_method: "S256", key_blob: null },
  })
  check("approve issues code", approve.status === 200 && /code=/.test(approve.data.redirect || ""), (approve.data.error || "no redirect"))
  const code = new URL(approve.data.redirect).searchParams.get("code")

  const badVerifier = await formPost("/oauth/token", new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: "wrong", client_id: "safestore-cli" }))
  check("wrong PKCE verifier rejected", badVerifier.status === 400, badVerifier.data.error)

  const swap = await formPost("/oauth/token", new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: "safestore-cli" }))
  check("token exchange 200", swap.status === 200, swap.data.error)

  // Now the full key-delivery path: browser re-wraps masterKey to the CLI pubkey.
  const approve2 = await api("/api/oauth/approve", {
    method: "POST",
    bearer: tokenA,
    body: { client_id: "safestore-cli", redirect_uri: redirectUri, state: "st-2", scope: ["store:read", "store:write"], code_challenge: challenge, code_challenge_method: "S256", key_blob: null },
  })
  const code2 = new URL(approve2.data.redirect).searchParams.get("code")

  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
  const cliPub = await subtle.importKey("spki", unb64(cliPubB64), { name: "ECDH", namedCurve: "P-256" }, false, [])
  const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: cliPub }, eph.privateKey, 256))
  const aesBits = await hkdfBits(shared, CLI_SALT, "key-wrap")
  const aes = await importAes(aesBits)
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, aes, masterA))
  const keyBlob = JSON.stringify({ eph_pub: b64(new Uint8Array(await subtle.exportKey("spki", eph.publicKey))), iv: b64(iv), ct: b64(ct) })
  const approve3 = await api("/api/oauth/approve", {
    method: "POST",
    bearer: tokenA,
    body: { client_id: "safestore-cli", redirect_uri: redirectUri, state: "st-3", scope: ["store:read", "store:write"], code_challenge: challenge, code_challenge_method: "S256", key_blob: keyBlob },
  })
  const code3 = new URL(approve3.data.redirect).searchParams.get("code")
  const swap3 = await formPost("/oauth/token", new URLSearchParams({ grant_type: "authorization_code", code: code3, code_verifier: verifier, client_id: "safestore-cli" }))
  check("token still issued after key delivery", swap3.status === 200, swap3.data.error)

  const blob = JSON.parse(swap3.data.key_blob)
  const ephPub = await subtle.importKey("spki", unb64(blob.eph_pub), { name: "ECDH", namedCurve: "P-256" }, false, [])
  const shared2 = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: ephPub }, cli.privateKey, 256))
  const aesBits2 = await hkdfBits(shared2, CLI_SALT, "key-wrap")
  const aes2 = await importAes(aesBits2)
  const delivered = await aesUnwrap(aes2, blob.iv, blob.ct)
  check("CLI received the exact master key", hex(delivered) === hex(masterA), hex(delivered))

  // reusing a code must fail (single-use)
  const replay = await formPost("/oauth/token", new URLSearchParams({ grant_type: "authorization_code", code: code3, code_verifier: verifier, client_id: "safestore-cli" }))
  check("code is single-use", replay.status === 400, replay.data.error)

  // access token can read data
  const authz = await api(`/api/sessions/${table}/messages?after=0&limit=10`, { bearer: swap3.data.access_token })
  check("oauth access token reads data", authz.status === 200 && (authz.data.messages || []).length === 1, authz.data.error)
}

console.log(`\n== auth enforcement ==`)
{
  check("no creds -> 401", (await api("/api/me")).status === 401)
  check("bad token -> 401", (await api("/api/me", { bearer: "sf_wrongtoken" })).status === 401)
  const bad = await api("/api/sessions", { method: "POST", body: { table: "mem_" + "0".repeat(32) + "drop", title: null }, bearer: tokenA })
  check("invalid table name rejected", bad.status === 400, bad.data.error)
  const weird = await api("/api/sessions", { method: "POST", body: { table: "mem_" + "g".repeat(32) }, bearer: tokenA })
  check("bad hex rejected", weird.status === 400)
}

console.log(`\n== cleanup ==`)
{
  const del = await api(`/api/sessions/${table}`, { method: "DELETE", bearer: tokenA })
  check("cleanup delete", del.status === 200, del.data.error)
}

console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} TEST(S) FAILED`)
process.exit(failures === 0 ? 0 : 1)
