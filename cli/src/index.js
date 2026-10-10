#!/usr/bin/env node
/**
 * sf - the safestore CLI.
 *
 *   sf auth login     log in via the browser (PKCE + consent), unwrap your
 *                     safestore key locally, mint a long-lived API key and
 *                     install the cloud plugin into OpenCode.
 *   sf auth status    show who you are logged in as.
 *   sf auth logout    remove saved credentials.
 *   sf plugin update  force-reinstall the plugin bundle from the cloud.
 *
 * No dependencies. Node >= 18.
 */
import { createServer } from "node:http"
import { webcrypto as crypto } from "node:crypto"
import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from "node:fs"
import { homedir } from "node:os"
import { join, dirname } from "node:path"
import { spawn } from "node:child_process"

const DEFAULT_URL = "https://opencode-safestore.csomeone301.workers.dev"
const CONFIG_DIR = process.env.XDG_CONFIG_HOME
  ? join(process.env.XDG_CONFIG_HOME, "opencode")
  : join(homedir(), ".config", "opencode")
const CONFIG_FILE = join(CONFIG_DIR, "opencode-safestore.json")
const PLUGIN_DIR = join(CONFIG_DIR, "plugins")
const PLUGIN_FILE = join(PLUGIN_DIR, "opencode-safestore.js")
const CLI_CLIENT_ID = "safestore-cli"

const subtle = crypto.subtle
const encoder = new TextEncoder()

/* ------------------------------- helpers -------------------------------- */
const log = { info: (m) => console.log(`\u2713 ${m}`), warn: (m) => console.warn(`! ${m}`), step: (m) => console.log(`\u00b7 ${m}`), error: (m) => console.error(`\u00d7 ${m}`) }

function b64(bytes) { return Buffer.from(bytes).toString("base64") }
function b64url(bytes) { return Buffer.from(bytes).toString("base64url") }
function unb64(value) { return new Uint8Array(Buffer.from(value, "base64")) }
function sha256hex(bytes) { return Buffer.from(bytes).toString("hex") }
async function digest(bytes) { return new Uint8Array(await subtle.digest("SHA-256", bytes)) }

function readConfig() {
  try { if (existsSync(CONFIG_FILE)) return JSON.parse(readFileSync(CONFIG_FILE, "utf8")) } catch { /* ignore */ }
  return null
}
function writeConfig(config) {
  mkdirSync(dirname(CONFIG_FILE), { recursive: true })
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 })
  log.info("credentials saved to " + CONFIG_FILE)
}

function openBrowser(url) {
  log.step("opening browser\u2026")
  const platform = process.platform
  const preferred = process.env.BROWSER
  const commands =
    preferred
      ? [[preferred, [url]]]
      : platform === "darwin"
        ? [["open", [url]]]
        : platform === "win32"
          ? [["cmd", ["/c", "start", "", url]]]
          : [["xdg-open", [url]]]
  for (const [cmd, args] of commands) {
    try {
      const child = spawn(cmd, args, { detached: true, stdio: "ignore" })
      child.unref()
      return
    } catch { /* try next */ }
  }
  log.warn("could not open a browser automatically.")
  console.log("\n  Open this URL manually:\n\n    " + url + "\n")
}

async function installPlugin(base, config) {
  let meta = null
  let source = null
  try {
    const metaRes = await fetch(`${base}/plugin/latest.json`, { signal: AbortSignal.timeout(15_000) })
    if (metaRes.ok) meta = await metaRes.json()
  } catch { /* ignore */ }
  if (meta) {
    const srcRes = await fetch(`${base}${meta.url}`, { signal: AbortSignal.timeout(20_000) })
    if (srcRes.ok) source = await srcRes.text()
  }
  // Fallback: if the cloud has no release yet, use the bundle shipped with this repo.
  if (!source) {
    const local = join(dirname(new URL(import.meta.url).pathname), "../../plugin/dist/opencode-safestore.js")
    try {
      if (existsSync(local)) source = readFileSync(local, "utf8")
    } catch { /* ignore */ }
  }
  if (!source) return null

  const hash = sha256hex(await digest(encoder.encode(source)))
  if (meta && hash !== meta.sha256) {
    log.warn(`plugin integrity check failed (hash ${hash.slice(0, 12)}\u2026). Not installing.`)
    return null
  }
  mkdirSync(PLUGIN_DIR, { recursive: true })
  writeFileSync(PLUGIN_FILE, source, { mode: 0o600 })
  if (config) { config.plugin_version = meta ? meta.version : "local"; config.plugin_hash = hash.slice(0, 16); writeConfig(config) }
  return meta ? meta.version : "local"
}

/* ------------------------------- auth login ----------------------------- */
async function authLogin() {
  const previous = readConfig()
  const base = (previous && previous.url) || process.env.SAFESTORE_URL || DEFAULT_URL

  log.step("generating a fresh device key (zero-knowledge key delivery)\u2026")
  const deviceKeys = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
  const cliPubkey = b64(new Uint8Array(await subtle.exportKey("spki", deviceKeys.publicKey)))

  const verifier = b64url(crypto.getRandomValues(new Uint8Array(64)))
  const challenge = b64url(await digest(encoder.encode(verifier)))
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)))

  let code = null
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://localhost")
    if (url.pathname !== "/callback") { res.writeHead(404).end(); return }
    const got = url.searchParams.get("code")
    const gotState = url.searchParams.get("state")
    if (!got || gotState !== state) {
      res.writeHead(400, { "content-type": "text/plain" }).end("state mismatch. close this tab and run sf auth login again.")
      return
    }
    code = got
    res.writeHead(302, { location: `${base}/cli/success?app=${encodeURIComponent("safestore CLI")}` })
    res.end()
  })
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
  const port = server.address().port
  const redirectUri = `http://127.0.0.1:${port}/callback`

  const params = new URLSearchParams({
    client_id: CLI_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: "store:read store:write",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    cli_pubkey: cliPubkey,
  })
  openBrowser(`${base}/authorize?${params.toString()}`)

  log.step("waiting for approval\u2026")
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for approval (60s)")), 60_000)
    const tick = setInterval(() => { if (code) { clearInterval(tick); clearTimeout(timer); resolve() } }, 200)
  })
  server.close()

  log.step("exchanging code\u2026")
  const tokenRes = await fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: CLI_CLIENT_ID }),
  })
  const tokenData = await tokenRes.json().catch(() => ({}))
  if (!tokenRes.ok) throw new Error(`token exchange failed: ${tokenData.error ?? tokenRes.status}`)

  if (!tokenData.key_blob) throw new Error("no key_blob in token response - the browser could not deliver your key")
  log.step("unwrapping your safestore key locally\u2026")
  const blob = JSON.parse(tokenData.key_blob)
  const ephPub = await subtle.importKey("spki", unb64(blob.eph_pub), { name: "ECDH", namedCurve: "P-256" }, false, [])
  const shared = await subtle.deriveBits({ name: "ECDH", public: ephPub }, deviceKeys.privateKey, 256)
  const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"])
  const aesBits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: encoder.encode("safestore:cli"), info: encoder.encode("key-wrap") },
    hk, 256)
  const aes = await subtle.importKey("raw", aesBits, { name: "AES-GCM" }, false, ["decrypt"])
  const masterKey = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(blob.iv) }, aes, unb64(blob.ct)))

  log.step("minting a long-lived API key for the plugin\u2026")
  let token = tokenData.access_token
  try {
    const keyRes = await fetch(`${base}/api/keys`, {
      method: "POST",
      headers: { authorization: `Bearer ${tokenData.access_token}`, "content-type": "application/json" },
      body: JSON.stringify({ name: "sf cli", scopes: ["store:read", "store:write"] }),
    })
    const keyData = await keyRes.json().catch(() => ({}))
    if (keyRes.ok && keyData.token) token = keyData.token
  } catch { /* fall back to the access token */ }

  const config = {
    url: base,
    token,
    key: b64(masterKey),
    user_id: tokenData.user_id,
    email: tokenData.account || "unknown",
    installed_at: new Date().toISOString(),
  }
  writeConfig(config)

  log.step("installing the cloud plugin into OpenCode\u2026")
  const version = await installPlugin(base, config)

  log.info(`logged in as ${config.email}`)
  if (version) log.info(`plugin installed${version === "local" ? " (from local bundle)" : ` v${version}`} in ${PLUGIN_DIR}`)
  else log.warn("plugin not installed yet - run `sf plugin update` once a release exists.")
  log.info("restart OpenCode to load the plugin. Your sessions will sync encrypted.")
  console.log("\n  You are logged in to safestore. You may close this safely.\n")
}

/* ------------------------------- status/logout -------------------------- */
function authStatus() {
  const config = readConfig()
  if (!config) {
    console.log("Not logged in. Run `sf auth login` first.")
    process.exit(1)
  }
  const mask = (s) => (s ? s.slice(0, 6) + "\u2026" + s.slice(-4) : "-")
  console.log(`safestore CLI\n  account:   ${config.email}\n  user id:   ${config.user_id}\n  url:       ${config.url}\n  token:     ${mask(config.token)}\n  key:       ${mask(config.key)}\n  plugin:    ${config.plugin_version ?? "not installed"}`)
}

function authLogout() {
  try { if (existsSync(CONFIG_FILE)) { unlinkSync(CONFIG_FILE); log.info("logged out - credentials removed") } else log.warn("not logged in") } catch (e) { log.error(e.message) }
}

async function pluginUpdate() {
  const config = readConfig()
  if (!config) { log.error("not logged in. Run `sf auth login` first."); process.exit(1) }
  const base = config.url || process.env.SAFESTORE_URL || DEFAULT_URL
  const version = await installPlugin(base, config)
  if (version) log.info(`plugin ${version === "local" ? "from local bundle" : `v${version}`} installed to ${PLUGIN_DIR}`)
  else log.error("no plugin available yet - publish a release first.")
}

/* --------------------------------- main --------------------------------- */
async function main() {
  const [, , cmd, sub, ...rest] = process.argv
  try {
    if (cmd === "auth") {
      if (sub === "login") await authLogin()
      else if (sub === "status") authStatus()
      else if (sub === "logout") authLogout()
      else throw new Error("usage: sf auth <login|status|logout>")
    } else if (cmd === "plugin" && sub === "update") {
      await pluginUpdate()
    } else {
      console.log(`safestore CLI

  sf auth login      log in through the browser, install the cloud plugin
  sf auth status     show account / key status
  sf auth logout     remove this device's credentials
  sf plugin update   re-fetch and reinstall the plugin bundle`)
      process.exit(cmd ? 1 : 0)
    }
  } catch (error) {
    log.error(error instanceof Error ? error.message : String(error))
    process.exit(1)
  }
}
main()
