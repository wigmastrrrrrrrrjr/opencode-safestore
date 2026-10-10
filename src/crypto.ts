/**
 * Client-side cryptography for opencode-safestore.
 *
 * The master key never leaves the machine running OpenCode. All sub-keys are
 * derived from it with HKDF-SHA256 and domain-separated info labels, so the
 * same master key yields independent keys for encryption, integrity, table
 * naming and message ids.
 *
 *   enc   AES-256-GCM   message bodies
 *   mac   HMAC-SHA-256  integrity tag over the plaintext ("keyed hash")
 *   table HMAC-SHA-256  per-session table name  -> mem_<hex>
 *   id    HMAC-SHA-256  opaque per-message id
 */

const subtle = globalThis.crypto.subtle
const encoder = new TextEncoder()
const decoder = new TextDecoder()

const HKDF_SALT = encoder.encode("opencode-safestore/v1")

export interface Keys {
  enc: CryptoKey
  mac: CryptoKey
  table: CryptoKey
  id: CryptoKey
}

export interface CipherRecord {
  id: string
  nonce: string
  ciphertext: string
  mac: string
  createdAt: number
}

/* -- base64 --------------------------------------------------------------- */

export function toBase64(bytes: Uint8Array): string {
  let binary = ""
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
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

/* -- key handling --------------------------------------------------------- */

export function generateMasterKey(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32))
  return toBase64(bytes)
}

export function normaliseMasterKey(raw: string): Uint8Array {
  const trimmed = raw.trim()
  // accept base64 (preferred) or 64-char hex
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    const out = new Uint8Array(32)
    for (let i = 0; i < 32; i++) out[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16)
    return out
  }
  const bytes = fromBase64(trimmed)
  if (bytes.length !== 32) throw new Error("master key must be 32 bytes (base64 or 64-char hex)")
  return bytes
}

async function derive(master: CryptoKey, info: string): Promise<Uint8Array> {
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: encoder.encode(info) },
    master,
    256,
  )
  return new Uint8Array(bits)
}

export async function deriveKeys(masterKey: Uint8Array): Promise<Keys> {
  const base = await subtle.importKey("raw", masterKey, "HKDF", false, ["deriveBits"])
  const [encRaw, macRaw, tableRaw, idRaw] = await Promise.all([
    derive(base, "enc"),
    derive(base, "mac"),
    derive(base, "table"),
    derive(base, "id"),
  ])
  const [enc, mac, table, id] = await Promise.all([
    subtle.importKey("raw", encRaw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]),
    subtle.importKey("raw", macRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    subtle.importKey("raw", tableRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
    subtle.importKey("raw", idRaw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
  ])
  return { enc, mac, table, id }
}

/* -- primitives ----------------------------------------------------------- */

async function hmacHex(key: CryptoKey, value: string): Promise<string> {
  const digest = await subtle.sign("HMAC", key, encoder.encode(value))
  return toHex(new Uint8Array(digest))
}

async function hmacB64(key: CryptoKey, bytes: Uint8Array): Promise<string> {
  const digest = await subtle.sign("HMAC", key, bytes)
  return toBase64(new Uint8Array(digest))
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** Opaque, deterministic per-session table name. Reveals nothing on its own. */
export async function tableName(keys: Keys, sessionID: string): Promise<string> {
  const hex = await hmacHex(keys.table, `session:${sessionID}`)
  return `mem_${hex.slice(0, 32)}`
}

/** Opaque per-message id used for idempotent upserts. */
export async function recordID(keys: Keys, sessionID: string, messageID: string): Promise<string> {
  const hex = await hmacHex(keys.id, `${sessionID}\u0000${messageID}`)
  return hex.slice(0, 32)
}

/* -- encrypt / decrypt ---------------------------------------------------- */

export async function encryptJSON(
  keys: Keys,
  sessionID: string,
  messageID: string,
  value: unknown,
  createdAt = Date.now(),
): Promise<CipherRecord> {
  const plaintext = encoder.encode(JSON.stringify(value))
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await subtle.encrypt({ name: "AES-GCM", iv }, keys.enc, plaintext)
  return {
    id: await recordID(keys, sessionID, messageID),
    nonce: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(encrypted)),
    mac: await hmacB64(keys.mac, plaintext),
    createdAt,
  }
}

/** Returns the decrypted value, or `undefined` when the record fails integrity. */
export async function decryptJSON<T = unknown>(keys: Keys, record: CipherRecord): Promise<T | undefined> {
  try {
    const plaintext = new Uint8Array(
      await subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(record.nonce) },
        keys.enc,
        fromBase64(record.ciphertext),
      ),
    )
    const expected = fromBase64(await hmacB64(keys.mac, plaintext))
    if (!equalBytes(expected, fromBase64(record.mac))) return undefined
    return JSON.parse(decoder.decode(plaintext)) as T
  } catch {
    return undefined
  }
}
