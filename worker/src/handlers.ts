/**
 * Account, API-key, app (OAuth client), OAuth consent, and dataset handlers.
 */
import {
  type AuthContext,
  type Env,
  createWebSession,
  escapeHtml,
  fail,
  fromBase64,
  getAuth,
  hasScope,
  json,
  randomHex,
  readJson,
  safeEqual,
  SESSION_COOKIE,
  serializeCookie,
  clearCookie,
  sha256Hex,
  SESSION_MAX_AGE,
  toBase64,
  uuid,
  WEB_SCOPES,
} from "./core"

const TABLE_RE = /^mem_[0-9a-f]{32,64}$/
const MAX_CIPHERTEXT_CHARS = 512 * 1024
const MAX_RECORDS_PER_PUSH = 200
const CODE_TTL_MS = 10 * 60 * 1000
const ACCESS_TTL_MS = 30 * 24 * 60 * 60 * 1000

/* -- built-in CLI app --------------------------------------------------- */
export const CLI_CLIENT_ID = "safestore-cli"
const CLI_APP = {
  id: CLI_CLIENT_ID,
  name: "safestore CLI",
  scopes: ["store:read", "store:write"],
  api_url: "http://127.0.0.1",
}
const LOOPBACK_RE = /^http:\/\/(127\.0\.0\.1|localhost)(:\d{1,5})?(\/.*)?$/

/* -- small helpers ------------------------------------------------------ */
interface UserRow {
  id: string
  email: string
  salt: string
  auth_verifier: string
  server_salt: string
  wrapped_key: string | null
  created_at: number
}

function isEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254
}
function b64Json(value: unknown): string | null {
  if (typeof value !== "string" || !value) return null
  try {
    JSON.parse(value)
    return value
  } catch {
    return null
  }
}
function publicUser(user: UserRow) {
  return { id: user.id, email: user.email, created_at: user.created_at }
}
/**
 * Verifier for the client-derived authKey. authKey is already the output of
 * PBKDF2-300k + HKDF on the client, so a plain SHA-256 verifier is secure and
 * keeps the free Worker plan inside its CPU budget (150k-iteration PBKDF2 on
 * Worker-side kills the isolate).
 */
async function verifierFor(authKeyB64: string): Promise<string> {
  return sha256Hex(authKeyB64)
}
async function requireAuth(req: Request, env: Env): Promise<AuthContext | Response> {
  const auth = await getAuth(req, env)
  if (!auth) return fail(401, "authentication required")
  return auth
}
function isResponse(value: unknown): value is Response {
  return value instanceof Response
}

/* -- auth: salt / signup / login ---------------------------------------- */
export async function handleSalt(req: Request, env: Env, url: URL): Promise<Response> {
  const email = (url.searchParams.get("email") ?? "").trim().toLowerCase()
  const user = email
    ? await env.DB.prepare("SELECT salt FROM users WHERE email = ?").bind(email).first<{ salt: string }>()
    : null
  // Deterministic fake salt for unknown emails so existence cannot be probed.
  let salt = user?.salt
  if (!salt) {
    const hexSalt = await sha256Hex(`nouser:${email}`)
    const bytes = new Uint8Array(16)
    for (let i = 0; i < 16; i++) bytes[i] = parseInt(hexSalt.slice(i * 2, i * 2 + 2), 16)
    salt = toBase64(bytes)
  }
  return json({ salt })
}

export async function handleSignup(req: Request, env: Env): Promise<Response> {
  const body = await readJson<Record<string, unknown>>(req)
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : ""
  if (!isEmail(email)) return fail(400, "invalid email")
  if (typeof body.salt !== "string" || typeof body.authKey !== "string") return fail(400, "missing credentials")
  const wrappedKey = b64Json(body.wrappedKey)
  if (!wrappedKey) return fail(400, "missing wrapped key")

  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first<{ id: string }>()
  if (existing) return fail(409, "email already registered", { code: "email_taken" })

  const id = uuid()
  const serverSalt = randomHex(16)
  const authVerifier = await verifierFor(body.authKey)
  const now = Date.now()
  try {
    await env.DB.prepare(
      "INSERT INTO users (id, email, salt, auth_verifier, server_salt, wrapped_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
      .bind(id, email, body.salt, authVerifier, serverSalt, wrappedKey, now)
      .run()
  } catch {
    return fail(409, "email already registered", { code: "email_taken" })
  }

  // Auto-provision a default API token so the CLI/plugin work immediately.
  const defaultKey = await createApiKey(env, id, "default", ["store:read", "store:write"])

  const session = await createWebSession(env, id)
  return json(
    {
      user: { id, email, created_at: now },
      defaultToken: defaultKey.token,
      apiKey: defaultKey.public,
    },
    200,
    { "set-cookie": serializeCookie(SESSION_COOKIE, session, SESSION_MAX_AGE) },
  )
}

export async function handleLogin(req: Request, env: Env): Promise<Response> {
  const body = await readJson<Record<string, unknown>>(req)
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : ""
  const authKey = typeof body.authKey === "string" ? body.authKey : ""
  if (!isEmail(email) || !authKey) return fail(400, "invalid credentials")

  const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first<UserRow>()
  // Always do the work to keep timing consistent and avoid enumeration.
  const computed = await verifierFor(authKey)
  if (!user || !(await safeEqual(computed, user.auth_verifier))) return fail(401, "invalid email or password")

  const session = await createWebSession(env, user.id)
  return json(
    { user: publicUser(user), wrappedKey: user.wrapped_key, scopes: WEB_SCOPES },
    200,
    { "set-cookie": serializeCookie(SESSION_COOKIE, session, SESSION_MAX_AGE) },
  )
}

export async function handleLogout(req: Request, env: Env): Promise<Response> {
  const cookies = req.headers.get("cookie") ?? ""
  const match = /(?:^|;\s*)sf_session=([^;]+)/.exec(cookies)
  if (match) {
    const tokenHash = await sha256Hex(decodeURIComponent(match[1]))
    await env.DB.prepare("DELETE FROM web_sessions WHERE token_hash = ?").bind(tokenHash).run()
  }
  return json({ ok: true }, 200, { "set-cookie": clearCookie(SESSION_COOKIE) })
}

export async function handleMe(req: Request, env: Env): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(auth.userId).first<UserRow>()
  if (!user) return fail(401, "account not found")
  return json({ user: publicUser(user), wrappedKey: user.wrapped_key, scopes: [...auth.scopes], kind: auth.kind })
}

/* -- API keys ----------------------------------------------------------- */
async function createApiKey(env: Env, userId: string, name: string, scopes: string[]) {
  const token = `sf_${randomHex(24)}`
  const id = uuid()
  const now = Date.now()
  await env.DB.prepare(
    "INSERT INTO api_keys (id, user_id, name, prefix, token_hash, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(id, userId, name, token.slice(0, 11), await sha256Hex(token), scopes.join(" "), now)
    .run()
  return { token, public: { id, name, prefix: token.slice(0, 11), scopes, created_at: now } }
}

export async function handleListKeys(req: Request, env: Env): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  const rows = await env.DB.prepare(
    "SELECT id, name, prefix, scopes, created_at, last_used_at, revoked_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
  )
    .bind(auth.userId)
    .all()
  return json({ keys: rows.results ?? [] })
}

export async function handleCreateKey(req: Request, env: Env): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  if (!hasScope(auth, "keys:write") && auth.kind === "api") return fail(403, "missing scope keys:write")
  const body = await readJson<Record<string, unknown>>(req)
  const name = typeof body.name === "string" && body.name.trim() ? body.name.trim().slice(0, 60) : "api key"
  const requested = Array.isArray(body.scopes) ? body.scopes.filter((s): s is string => typeof s === "string") : ["store:read", "store:write"]
  const scopes = requested.filter((s) => ["store:read", "store:write", "keys:write", "apps:write"].includes(s))
  const created = await createApiKey(env, auth.userId, name, scopes.length ? scopes : ["store:read"])
  return json({ token: created.token, key: created.public }, 201)
}

export async function handleRevokeKey(req: Request, env: Env, id: string): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  await env.DB.prepare("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND user_id = ?").bind(Date.now(), id, auth.userId).run()
  return json({ ok: true })
}

/* -- apps (OAuth clients) ----------------------------------------------- */
export async function handleListApps(req: Request, env: Env): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  const rows = await env.DB.prepare(
    "SELECT id, name, redirect_uris, scopes, api_url, secret_prefix, created_at FROM apps WHERE user_id = ? ORDER BY created_at DESC",
  )
    .bind(auth.userId)
    .all()
  const apps = (rows.results ?? []).map((row: any) => ({
    ...row,
    redirect_uris: JSON.parse(row.redirect_uris),
    scopes: row.scopes.split(/[,\s]+/).filter(Boolean),
  }))
  return json({ apps })
}

export async function handleCreateApp(req: Request, env: Env): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  if (!hasScope(auth, "apps:write") && auth.kind === "api") return fail(403, "missing scope apps:write")
  const body = await readJson<Record<string, unknown>>(req)
  const name = typeof body.name === "string" && body.name.trim() ? body.name.trim().slice(0, 60) : ""
  if (!name) return fail(400, "name required")
  const redirect_uris = Array.isArray(body.redirect_uris)
    ? body.redirect_uris.filter((u): u is string => typeof u === "string" && /^https?:\/\//.test(u)).slice(0, 10)
    : []
  if (redirect_uris.length === 0) return fail(400, "at least one http(s) redirect URI required")
  const scopes = Array.isArray(body.scopes)
    ? body.scopes.filter((s): s is string => typeof s === "string" && ["store:read", "store:write"].includes(s))
    : []
  const api_url = typeof body.api_url === "string" ? body.api_url.slice(0, 300) : ""
  const id = `app_${randomHex(8)}`
  const secret = `sfas_${randomHex(24)}`
  const now = Date.now()
  await env.DB.prepare(
    "INSERT INTO apps (id, user_id, name, redirect_uris, scopes, api_url, secret_hash, secret_prefix, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(id, auth.userId, name, JSON.stringify(redirect_uris), scopes.join(" "), api_url, await sha256Hex(secret), secret.slice(0, 12), now)
    .run()
  return json(
    {
      app: { id, name, redirect_uris, scopes, api_url, secret_prefix: secret.slice(0, 12), created_at: now },
      client_secret: secret,
    },
    201,
  )
}

export async function handleDeleteApp(req: Request, env: Env, id: string): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  await env.DB.prepare("DELETE FROM apps WHERE id = ? AND user_id = ?").bind(id, auth.userId).run()
  return json({ ok: true })
}

/* -- OAuth -------------------------------------------------------------- */
interface ResolvedClient {
  id: string
  name: string
  scopes: string[]
  redirectUris: string[]
  secretHash?: string
  builtin: boolean
}
async function resolveClient(env: Env, clientId: string): Promise<ResolvedClient | null> {
  if (clientId === CLI_CLIENT_ID) {
    return { id: CLI_CLIENT_ID, name: CLI_APP.name, scopes: CLI_APP.scopes, redirectUris: [], builtin: true }
  }
  const row = await env.DB.prepare("SELECT id, name, redirect_uris, scopes, secret_hash FROM apps WHERE id = ?")
    .bind(clientId)
    .first<any>()
  if (!row) return null
  return {
    id: row.id,
    name: row.name,
    scopes: row.scopes.split(/[,\s]+/).filter(Boolean),
    redirectUris: JSON.parse(row.redirect_uris),
    secretHash: row.secret_hash,
    builtin: false,
  }
}
function validRedirect(client: ResolvedClient, uri: string): boolean {
  if (client.builtin) return LOOPBACK_RE.test(uri)
  return client.redirectUris.includes(uri)
}

/** GET /authorize -> decide redirect-to-signup vs render the consent page. */
export async function handleAuthorize(req: Request, env: Env, url: URL): Promise<Response | { boot: unknown }> {
  const auth = await getAuth(req, env)
  if (!auth) {
    return { boot: { redirect: `/signup?next=${encodeURIComponent(url.pathname + url.search)}` } }
  }
  const clientId = url.searchParams.get("client_id") ?? ""
  const redirectUri = url.searchParams.get("redirect_uri") ?? ""
  const scope = (url.searchParams.get("scope") ?? "").split(/[,\s]+/).filter(Boolean)
  const state = url.searchParams.get("state") ?? ""
  const codeChallenge = url.searchParams.get("code_challenge")
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? "S256"
  const cliPubkey = url.searchParams.get("cli_pubkey") ?? ""

  const client = await resolveClient(env, clientId)
  if (!client) return fail(400, "unknown client_id")
  if (!validRedirect(client, redirectUri)) return fail(400, "invalid redirect_uri")
  const requestedScopes = scope.filter((s) => client.scopes.includes(s))
  if (requestedScopes.length === 0) requestedScopes.push(...client.scopes)

  const user = await env.DB.prepare("SELECT id, email FROM users WHERE id = ?").bind(auth.userId).first<{ id: string; email: string }>()
  return {
    boot: {
      route: "consent",
      user: user ? { id: user.id, email: user.email } : null,
      consent: {
        clientId: client.id,
        appName: client.name,
        scopes: requestedScopes,
        redirectUri,
        state,
        codeChallenge,
        codeChallengeMethod,
        cliPubkey,
        builtin: client.builtin,
      },
    },
  }
}

export async function handleApprove(req: Request, env: Env): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  const body = await readJson<Record<string, unknown>>(req)
  const clientId = typeof body.client_id === "string" ? body.client_id : ""
  const redirectUri = typeof body.redirect_uri === "string" ? body.redirect_uri : ""
  const state = typeof body.state === "string" ? body.state : ""
  const scope = Array.isArray(body.scope) ? body.scope.filter((s): s is string => typeof s === "string") : []
  const codeChallenge = typeof body.code_challenge === "string" ? body.code_challenge : null
  const codeChallengeMethod = typeof body.code_challenge_method === "string" ? body.code_challenge_method : "S256"
  const keyBlob = typeof body.key_blob === "string" && body.key_blob.length < 65_536 ? body.key_blob : null

  const client = await resolveClient(env, clientId)
  if (!client) return fail(400, "unknown client_id")
  if (!validRedirect(client, redirectUri)) return fail(400, "invalid redirect_uri")
  if (codeChallengeMethod !== "S256" || !codeChallenge) return fail(400, "PKCE S256 required")

  const granted = scope.filter((s) => client.scopes.includes(s))
  const code = randomHex(32)
  const now = Date.now()
  await env.DB.prepare(
    "INSERT INTO auth_codes (code_hash, app_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, key_blob, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
  )
    .bind(await sha256Hex(code), clientId, auth.userId, redirectUri, granted.join(" "), codeChallenge, codeChallengeMethod, keyBlob, now, now + CODE_TTL_MS)
    .run()

  const sep = redirectUri.includes("?") ? "&" : "?"
  const location = `${redirectUri}${sep}code=${encodeURIComponent(code)}${state ? `&state=${encodeURIComponent(state)}` : ""}`
  return json({ ok: true, redirect: location })
}

export async function handleDeny(req: Request, env: Env): Promise<Response> {
  const body = await readJson<Record<string, unknown>>(req)
  const redirectUri = typeof body.redirect_uri === "string" ? body.redirect_uri : ""
  const state = typeof body.state === "string" ? body.state : ""
  const client = await resolveClient(env, typeof body.client_id === "string" ? body.client_id : "")
  if (!client || !validRedirect(client, redirectUri)) return fail(400, "invalid request")
  const sep = redirectUri.includes("?") ? "&" : "?"
  return json({ ok: true, redirect: `${redirectUri}${sep}error=access_denied${state ? `&state=${encodeURIComponent(state)}` : ""}` })
}

export async function handleToken(req: Request, env: Env): Promise<Response> {
  const contentType = req.headers.get("content-type") ?? ""
  let body: Record<string, unknown>
  if (contentType.includes("application/json")) body = await readJson(req)
  else {
    const text = await req.text()
    body = Object.fromEntries(new URLSearchParams(text))
  }
  if (body.grant_type !== "authorization_code") return fail(400, "unsupported grant_type")
  const code = typeof body.code === "string" ? body.code : ""
  const verifier = typeof body.code_verifier === "string" ? body.code_verifier : ""
  const clientId = typeof body.client_id === "string" ? body.client_id : ""
  if (!code || !verifier || !clientId) return fail(400, "missing fields")

  const client = await resolveClient(env, clientId)
  if (!client) return fail(400, "unknown client_id")
  if (!client.builtin) {
    const secret = typeof body.client_secret === "string" ? body.client_secret : ""
    if (!secret || !client.secretHash || !(await safeEqual(await sha256Hex(secret), client.secretHash))) {
      return fail(401, "invalid client_secret")
    }
  }

  const codeHash = await sha256Hex(code)
  const row = await env.DB.prepare("SELECT * FROM auth_codes WHERE code_hash = ?").bind(codeHash).first<any>()
  if (!row || row.used || row.expires_at < Date.now()) return fail(400, "invalid or expired code")
  if (row.app_id !== clientId) return fail(400, "code/client mismatch")

  // PKCE S256 check
  const challenge = toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))))
  if (challenge !== row.code_challenge) return fail(400, "PKCE verification failed")

  await env.DB.prepare("UPDATE auth_codes SET used = 1 WHERE code_hash = ?").bind(codeHash).run()

  const accessToken = `sfa_${randomHex(24)}`
  const now = Date.now()
  await env.DB.prepare(
    "INSERT INTO access_tokens (token_hash, app_id, user_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(await sha256Hex(accessToken), clientId, row.user_id, row.scope, now, now + ACCESS_TTL_MS)
    .run()

  const user = await env.DB.prepare("SELECT email FROM users WHERE id = ?").bind(row.user_id).first<{ email: string }>()
  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.floor(ACCESS_TTL_MS / 1000),
    scope: row.scope,
    key_blob: row.key_blob,
    account: user?.email ?? null,
    user_id: row.user_id,
  })
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "")
}

/* -- dataset sessions (owner-scoped, still client-encrypted) ------------ */
async function ownDataset(env: Env, userId: string, table: string): Promise<{ ok: boolean; owner?: string }> {
  const row = await env.DB.prepare("SELECT owner_id FROM dataset_sessions WHERE table_name = ?").bind(table).first<{ owner_id: string }>()
  if (!row) return { ok: false }
  return { ok: row.owner_id === userId, owner: row.owner_id }
}

export async function handleCreateDataset(req: Request, env: Env): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  if (!hasScope(auth, "store:write")) return fail(403, "missing scope store:write")
  const body = await readJson<Record<string, unknown>>(req)
  const table = typeof body.table === "string" ? body.table : ""
  if (!TABLE_RE.test(table)) return fail(400, "invalid table name")
  const title = typeof body.title === "string" ? body.title.slice(0, 200) : null

  const existing = await env.DB.prepare("SELECT owner_id FROM dataset_sessions WHERE table_name = ?").bind(table).first<{ owner_id: string }>()
  if (existing && existing.owner_id !== auth.userId) return fail(409, "table already claimed by another account")

  const now = Date.now()
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS "${table}" (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      id TEXT NOT NULL UNIQUE,
      nonce TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      mac TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )`,
  ).run()
  await env.DB.prepare(
    `INSERT INTO dataset_sessions (table_name, owner_id, title, created_at, updated_at, message_count)
     VALUES (?, ?, ?, ?, ?, 0)
     ON CONFLICT(table_name) DO UPDATE SET updated_at = excluded.updated_at, title = COALESCE(excluded.title, dataset_sessions.title)`,
  )
    .bind(table, auth.userId, title, now, now)
    .run()
  return json({ ok: true, table })
}

export async function handleListDatasets(req: Request, env: Env): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  const rows = await env.DB.prepare(
    "SELECT table_name, title, created_at, updated_at, message_count FROM dataset_sessions WHERE owner_id = ? ORDER BY updated_at DESC LIMIT 1000",
  )
    .bind(auth.userId)
    .all()
  return json({ sessions: rows.results ?? [] })
}

export async function handlePush(req: Request, env: Env, table: string): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  if (!hasScope(auth, "store:write")) return fail(403, "missing scope store:write")
  if (!TABLE_RE.test(table)) return fail(400, "invalid table name")
  const own = await ownDataset(env, auth.userId, table)
  if (!own.ok) return fail(404, "unknown session")

  const body = await readJson<{ messages?: unknown }>(req)
  if (!Array.isArray(body.messages) || body.messages.length === 0) return fail(400, "messages required")
  if (body.messages.length > MAX_RECORDS_PER_PUSH) return fail(413, "too many messages")

  const now = Date.now()
  const stmts = []
  for (const raw of body.messages) {
    const m = raw as Record<string, unknown>
    const id = typeof m.id === "string" ? m.id : ""
    const nonce = typeof m.nonce === "string" ? m.nonce : ""
    const ciphertext = typeof m.ciphertext === "string" ? m.ciphertext : ""
    const mac = typeof m.mac === "string" ? m.mac : ""
    const createdAt = typeof m.createdAt === "number" ? m.createdAt : now
    if (!id || !nonce || !ciphertext || !mac) return fail(400, "malformed message")
    if (ciphertext.length > MAX_CIPHERTEXT_CHARS) return fail(413, "message too large")
    stmts.push(
      env.DB.prepare(
        `INSERT INTO "${table}" (id, nonce, ciphertext, mac, created_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext, mac = excluded.mac, created_at = excluded.created_at`,
      ).bind(id, nonce, ciphertext, mac, createdAt),
    )
  }
  await env.DB.batch(stmts)
  const count = await env.DB.prepare(`SELECT COUNT(*) AS n FROM "${table}"`).first<{ n: number }>()
  await env.DB.prepare("UPDATE dataset_sessions SET updated_at = ?, message_count = ? WHERE table_name = ?").bind(now, count?.n ?? 0, table).run()
  return json({ ok: true, accepted: stmts.length, count: count?.n ?? 0 })
}

export async function handlePull(req: Request, env: Env, table: string, url: URL): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  if (!hasScope(auth, "store:read")) return fail(403, "missing scope store:read")
  if (!TABLE_RE.test(table)) return fail(400, "invalid table name")
  const own = await ownDataset(env, auth.userId, table)
  if (!own.ok) return fail(404, "unknown session")

  const after = Math.max(0, Number(url.searchParams.get("after") ?? "0") || 0)
  const limit = Math.min(Math.max(1, Number(url.searchParams.get("limit") ?? "200") || 200), 500)
  const rows = await env.DB.prepare(
    `SELECT seq, id, nonce, ciphertext, mac, created_at FROM "${table}" WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
  )
    .bind(after, limit)
    .all()
  return json({ ok: true, table, messages: rows.results ?? [] })
}

export async function handleDeleteDataset(req: Request, env: Env, table: string): Promise<Response> {
  const auth = await requireAuth(req, env)
  if (isResponse(auth)) return auth
  if (!hasScope(auth, "store:write")) return fail(403, "missing scope store:write")
  if (!TABLE_RE.test(table)) return fail(400, "invalid table name")
  const own = await ownDataset(env, auth.userId, table)
  if (!own.ok) return fail(404, "unknown session")
  await env.DB.prepare(`DROP TABLE IF EXISTS "${table}"`).run()
  await env.DB.prepare("DELETE FROM dataset_sessions WHERE table_name = ? AND owner_id = ?").bind(table, auth.userId).run()
  return json({ ok: true })
}

/* -- plugin distribution ------------------------------------------------ */
export async function handlePluginMeta(env: Env): Promise<Response> {
  const row = await env.DB.prepare("SELECT version, sha256, created_at FROM plugin_releases ORDER BY created_at DESC LIMIT 1").first<any>()
  if (!row) return fail(404, "no plugin released yet")
  return json({ version: row.version, sha256: row.sha256, created_at: row.created_at, url: "/plugin/latest.js" })
}

export async function handlePluginSource(env: Env): Promise<Response> {
  const row = await env.DB.prepare("SELECT version, sha256, source FROM plugin_releases ORDER BY created_at DESC LIMIT 1").first<any>()
  if (!row) return fail(404, "no plugin released yet")
  return new Response(row.source, {
    headers: {
      "content-type": "text/javascript; charset=utf-8",
      "cache-control": "no-store",
      "x-safestore-version": row.version,
      "x-safestore-sha256": row.sha256,
    },
  })
}

export async function handleAdminPublish(req: Request, env: Env): Promise<Response> {
  const header = req.headers.get("authorization") ?? ""
  const token = header.replace(/^Bearer\s+/i, "")
  if (!env.ADMIN_TOKEN || !token || !(await safeEqual(token, env.ADMIN_TOKEN))) return fail(401, "unauthorized")
  const body = await readJson<Record<string, unknown>>(req, 4 * 1024 * 1024)
  const version = typeof body.version === "string" ? body.version : ""
  const source = typeof body.source === "string" ? body.source : ""
  if (!version || !source) return fail(400, "version and source required")
  const sha256 = await sha256Hex(source)
  await env.DB.prepare(
    `INSERT INTO plugin_releases (version, sha256, source, created_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(version) DO UPDATE SET sha256 = excluded.sha256, source = excluded.source, created_at = excluded.created_at`,
  )
    .bind(version, sha256, source, Date.now())
    .run()
  return json({ ok: true, version, sha256 })
}

export { escapeHtml }
