/**
 * opencode-safestore - shared core for the account / OAuth / data worker.
 *
 * Zero-knowledge notes:
 *  - The server never receives the user's password. The web client derives
 *    `authKey` and `wrapKey` from the password with PBKDF2 + HKDF and only
 *    `authKey` (a password-equivalent verifier) crosses the wire.
 *  - The user's safestore (encryption) key is stored wrapped by `wrapKey`
 *    (AES-256-GCM). The server cannot unwrap it.
 */

/* -- D1 minimal typings ------------------------------------------------- */
export interface D1Result<T = unknown> {
  results?: T[]
  success: boolean
  meta: Record<string, unknown>
}
export interface D1Stmt {
  bind(...values: unknown[]): D1Stmt
  first<T = unknown>(): Promise<T | null>
  all<T = unknown>(): Promise<D1Result<T>>
  run(): Promise<D1Result>
}
export interface D1DB {
  prepare(query: string): D1Stmt
  batch<T = unknown>(statements: D1Stmt[]): Promise<D1Result<T>[]>
  exec(query: string): Promise<{ count: number; duration: number }>
}
export interface Env {
  DB: D1DB
  ADMIN_TOKEN?: string
  [key: string]: unknown
}

/* -- encoding ----------------------------------------------------------- */
const encoder = new TextEncoder()
const decoder = new TextDecoder()

export function toBase64(bytes: Uint8Array): string {
  let binary = ""
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  return btoa(binary)
}
export function fromBase64(value: string): Uint8Array {
  const binary = atob(value)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}
export function toHex(bytes: Uint8Array): string {
  let hex = ""
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0")
  return hex
}
export function randomHex(bytes = 32): string {
  return toHex(crypto.getRandomValues(new Uint8Array(bytes)))
}
export function uuid(): string {
  return crypto.randomUUID()
}

export async function sha256Hex(value: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))))
}

export async function pbkdf2Bits(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length = 32,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"])
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    length * 8,
  )
  return new Uint8Array(bits)
}

/** Constant-time compare that does not leak length (hashes both sides). */
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256Hex(a), sha256Hex(b)])
  let diff = 0
  for (let i = 0; i < ha.length; i++) diff |= ha.charCodeAt(i) ^ hb.charCodeAt(i)
  return diff === 0
}

/* -- HTTP helpers ------------------------------------------------------- */
const SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...SECURITY_HEADERS, ...headers },
  })
}
export function fail(status: number, message: string, extra: Record<string, unknown> = {}): Response {
  return json({ error: message, ...extra }, status)
}
export function html(body: string, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy":
        "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      ...SECURITY_HEADERS,
      ...headers,
    },
  })
}
export function redirect(location: string, status = 302, headers: Record<string, string> = {}): Response {
  return new Response(null, { status, headers: { location, "cache-control": "no-store", ...SECURITY_HEADERS, ...headers } })
}
export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
}

export async function readJson<T>(req: Request, maxBytes = 2 * 1024 * 1024): Promise<T> {
  const length = Number(req.headers.get("content-length") ?? "0")
  if (length > maxBytes) throw new Error("payload too large")
  const text = await req.text()
  if (text.length > maxBytes) throw new Error("payload too large")
  return (text ? JSON.parse(text) : {}) as T
}

/* -- cookies ------------------------------------------------------------ */
export const SESSION_COOKIE = "sf_session"
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000

export function parseCookies(req: Request): Record<string, string> {
  const header = req.headers.get("cookie") ?? ""
  const out: Record<string, string> = {}
  for (const part of header.split(";")) {
    const index = part.indexOf("=")
    if (index === -1) continue
    out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim())
  }
  return out
}
export function serializeCookie(name: string, value: string, maxAgeSeconds: number): string {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`
}
export function clearCookie(name: string): string {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
}

/* -- schema ------------------------------------------------------------- */
let schemaReady = false
export async function ensureSchema(db: D1DB): Promise<void> {
  if (schemaReady) return
  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      salt TEXT NOT NULL,
      auth_verifier TEXT NOT NULL,
      server_salt TEXT NOT NULL,
      wrapped_key TEXT,
      created_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS web_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      prefix TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      scopes TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      last_used_at INTEGER,
      revoked_at INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS apps (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      redirect_uris TEXT NOT NULL,
      scopes TEXT NOT NULL,
      api_url TEXT,
      secret_hash TEXT NOT NULL,
      secret_prefix TEXT,
      created_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS auth_codes (
      code_hash TEXT PRIMARY KEY,
      app_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope TEXT NOT NULL,
      code_challenge TEXT,
      code_challenge_method TEXT,
      key_blob TEXT,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS access_tokens (
      token_hash TEXT PRIMARY KEY,
      app_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS dataset_sessions (
      table_name TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL,
      title TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      message_count INTEGER NOT NULL DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS plugin_releases (
      version TEXT PRIMARY KEY,
      sha256 TEXT NOT NULL,
      source TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_dataset_owner ON dataset_sessions(owner_id)`,
  ]
  for (const sql of statements) await db.prepare(sql).run()
  schemaReady = true
}

/* -- auth --------------------------------------------------------------- */
export type AuthKind = "web" | "api" | "oauth"
export interface AuthContext {
  userId: string
  scopes: Set<string>
  kind: AuthKind
  keyId?: string
  appId?: string
}

export const WEB_SCOPES = ["store:read", "store:write", "keys:write", "apps:write"]

export async function getAuth(req: Request, env: Env): Promise<AuthContext | null> {
  const authHeader = req.headers.get("authorization") ?? ""

  if (/^Bearer\s+/i.test(authHeader)) {
    const token = authHeader.replace(/^Bearer\s+/i, "").trim()
    if (!token) return null
    const tokenHash = await sha256Hex(token)

    const oauth = await env.DB.prepare(
      "SELECT app_id, user_id, scope, expires_at FROM access_tokens WHERE token_hash = ?",
    )
      .bind(tokenHash)
      .first<{ app_id: string; user_id: string; scope: string; expires_at: number }>()
    if (oauth && oauth.expires_at > Date.now()) {
      return { userId: oauth.user_id, scopes: new Set(oauth.scope.split(/[,\s]+/).filter(Boolean)), kind: "oauth", appId: oauth.app_id }
    }

    const key = await env.DB.prepare(
      "SELECT id, user_id, scopes FROM api_keys WHERE token_hash = ? AND revoked_at IS NULL",
    )
      .bind(tokenHash)
      .first<{ id: string; user_id: string; scopes: string }>()
    if (key) {
      await env.DB.prepare("UPDATE api_keys SET last_used_at = ? WHERE id = ?").bind(Date.now(), key.id).run()
      return { userId: key.user_id, scopes: new Set(key.scopes.split(/[,\s]+/).filter(Boolean)), kind: "api", keyId: key.id }
    }
    return null
  }

  const cookie = parseCookies(req)[SESSION_COOKIE]
  if (!cookie) return null
  const tokenHash = await sha256Hex(cookie)
  const row = await env.DB.prepare(
    "SELECT user_id, expires_at FROM web_sessions WHERE token_hash = ?",
  )
    .bind(tokenHash)
    .first<{ user_id: string; expires_at: number }>()
  if (!row || row.expires_at < Date.now()) return null
  return { userId: row.user_id, scopes: new Set(WEB_SCOPES), kind: "web" }
}

export function hasScope(auth: AuthContext, scope: string): boolean {
  return auth.scopes.has(scope)
}

export async function createWebSession(env: Env, userId: string): Promise<string> {
  const token = randomHex(32)
  const tokenHash = await sha256Hex(token)
  const now = Date.now()
  await env.DB.prepare(
    "INSERT INTO web_sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
  )
    .bind(tokenHash, userId, now, now + SESSION_TTL_MS)
    .run()
  return token
}

export const SESSION_MAX_AGE = Math.floor(SESSION_TTL_MS / 1000)
