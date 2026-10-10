/**
 * End-to-end smoke test: derive keys, encrypt locally, push ciphertext to the
 * deployed Worker, pull it back, and decrypt. Also checks tamper detection and
 * deterministic table naming, then cleans up.
 *
 *   OPENCODE_SAFESTORE_URL=... OPENCODE_SAFESTORE_TOKEN=... bun scripts/smoke.ts
 */
import assert from "node:assert/strict"

import { decryptJSON, deriveKeys, encryptJSON, normaliseMasterKey, tableName } from "../src/crypto.js"
import { Store } from "../src/store.js"

const url = process.env.OPENCODE_SAFESTORE_URL
const token = process.env.OPENCODE_SAFESTORE_TOKEN
const master = process.env.OPENCODE_SAFESTORE_KEY ?? Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64")

if (!url || !token) {
  console.error("set OPENCODE_SAFESTORE_URL and OPENCODE_SAFESTORE_TOKEN")
  process.exit(2)
}

const keys = await deriveKeys(normaliseMasterKey(master))
const store = new Store({ url, token })

const sessionID = `ses_smoke_${Math.random().toString(36).slice(2)}`
const table = await tableName(keys, sessionID)
console.log("session:", sessionID)
console.log("table  :", table)

assert.match(table, /^mem_[0-9a-f]{32}$/, "table name shape")

await store.ensureSession(table)

const original = {
  id: "msg_1",
  type: "user",
  content: [{ type: "text", text: "hello from safestore \u2603" }],
  time: { created: Date.now() },
}
const record = await encryptJSON(keys, sessionID, "msg_1", original)
assert.ok(!JSON.stringify(record).includes("hello"), "ciphertext must not contain plaintext")

await store.push(table, [record])
const pulled = await store.pullAll(table)
assert.equal(pulled.length, 1, "one record round-trips")

const decrypted = await decryptJSON(keys, pulled[0])
assert.deepEqual(decrypted, original, "decrypted payload matches original")

// Tamper detection: flip one ciphertext character.
const tampered = { ...pulled[0], ciphertext: pulled[0].ciphertext.slice(0, -2) + (pulled[0].ciphertext.endsWith("AA") ? "BB" : "AA") }
assert.equal(await decryptJSON(keys, tampered), undefined, "tampered record is rejected")

// Deterministic naming.
assert.equal(await tableName(keys, sessionID), table, "table name is deterministic")

await store.deleteSession(table)
console.log("\n\u2705 smoke test passed: encrypt -> store -> decrypt, tamper-rejected, deterministic naming")
