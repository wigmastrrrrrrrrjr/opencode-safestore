/**
 * opencode-safestore - end-to-end encrypted session memory for OpenCode.
 *
 * Every session is mirrored into its own Cloudflare D1 table by the
 * `opencode-safestore` Worker. The table name and every stored message are
 * derived/encrypted on this machine with a master key that never leaves it, so
 * a full dump of D1 shows only opaque `mem_<hex>` tables and ciphertext.
 *
 * Configuration (environment wins over plugin options):
 *   OPENCODE_SAFESTORE_URL    Worker base URL, e.g. https://opencode-safestore.<acct>.workers.dev
 *   OPENCODE_SAFESTORE_TOKEN  bearer token matching the Worker secret SAFESTORE_TOKEN
 *   OPENCODE_SAFESTORE_KEY    optional base64 (or 64-char hex) 32-byte master key.
 *                             If omitted, a key is generated once and stored in
 *                             the plugin's local OpenCode storage.
 *
 * All network work is best-effort and detached from the session so a Worker
 * outage can never break or slow down a chat.
 */

import { Plugin } from "@opencode/plugin"
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

import { decryptJSON, deriveKeys, encryptJSON, generateMasterKey, normaliseMasterKey, tableName, type Keys } from "./crypto.js"
import { Store } from "./store.js"

const MASTER_KEY_STORAGE = "masterKey"

interface ResolvedConfig {
  store: Store
  keys: Keys
  masterKey: string
  generatedKey: boolean
}

interface RecallInput {
  query?: unknown
  sessionID?: unknown
  limit?: unknown
  full?: unknown
}

function log(message: string): void {
  console.error(`[safestore] ${message}`)
}

function optionString(options: unknown, key: string): string | undefined {
  if (!options || typeof options !== "object") return undefined
  const value = (options as Record<string, unknown>)[key]
  return typeof value === "string" && value.length > 0 ? value : undefined
}

function envValue(key: string): string | undefined {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
  const value = env?.[key]
  return value && value.length > 0 ? value : undefined
}

/** Credentials written by `sf auth login`. The Worker stores only ciphertext. */
function fileConfig(): { url?: string; token?: string; key?: string } | null {
  try {
    const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
    const dir = env?.XDG_CONFIG_HOME ?? join(homedir(), ".config")
    const raw = readFileSync(join(dir, "opencode", "opencode-safestore.json"), "utf8")
    const parsed = JSON.parse(raw) as Record<string, unknown>
    return {
      url: typeof parsed.url === "string" && parsed.url.length > 0 ? parsed.url : undefined,
      token: typeof parsed.token === "string" && parsed.token.length > 0 ? parsed.token : undefined,
      key: typeof parsed.key === "string" && parsed.key.length > 0 ? parsed.key : undefined,
    }
  } catch {
    return null
  }
}

/** Pull readable fragments out of a stored session-message shape. */
function textPreview(value: unknown, full: boolean): string {
  if (full) return JSON.stringify(value, null, 2)
  const fragments: string[] = []
  const visit = (node: unknown): void => {
    if (node === null || node === undefined) return
    if (typeof node === "string") {
      fragments.push(node)
      return
    }
    if (Array.isArray(node)) {
      for (const item of node) visit(item)
      return
    }
    if (typeof node === "object") {
      const record = node as Record<string, unknown>
      if (typeof record.text === "string") fragments.push(record.text)
      else if (typeof record.content === "string") fragments.push(record.content)
      else if (Array.isArray(record.content)) visit(record.content)
      else if (record.type && typeof record.type === "string") fragments.push(`[${record.type}]`)
    }
  }
  visit((value as Record<string, unknown>)?.content ?? value)
  const joined = fragments.join("\n").trim()
  return joined.length > 0 ? joined.slice(0, 1_500) : JSON.stringify(value).slice(0, 500)
}

export default Plugin.define({
  id: "opencode-safestore",
  async setup(ctx) {
    const file = fileConfig()
    const url = envValue("OPENCODE_SAFESTORE_URL") ?? optionString(ctx.options, "url") ?? file?.url
    const token = envValue("OPENCODE_SAFESTORE_TOKEN") ?? optionString(ctx.options, "token") ?? file?.token

    if (!url || !token) {
      log("disabled: run `sf auth login` (or set OPENCODE_SAFESTORE_URL / OPENCODE_SAFESTORE_TOKEN) to enable encrypted memory.")
      return () => {}
    }

    /* -- master key resolution ------------------------------------------ */

    let masterKey = envValue("OPENCODE_SAFESTORE_KEY") ?? file?.key
    let generatedKey = false
    if (!masterKey) {
      const stored = await ctx.storage.get(MASTER_KEY_STORAGE)
      if (typeof stored === "string" && stored.length > 0) {
        masterKey = stored
      } else {
        masterKey = generateMasterKey()
        generatedKey = true
        await ctx.storage.set(MASTER_KEY_STORAGE, masterKey)
      }
    }

    let keys: Keys
    try {
      keys = await deriveKeys(normaliseMasterKey(masterKey))
    } catch (error) {
      log(`disabled: invalid master key (${error instanceof Error ? error.message : String(error)})`)
      return () => {}
    }

    const config: ResolvedConfig = {
      store: new Store({ url, token }),
      keys,
      masterKey,
      generatedKey,
    }

    if (generatedKey) {
      log("generated a new master key and stored it locally. Back it up - without it, stored memory cannot be decrypted.")
    }

    /* -- per-session sync ----------------------------------------------- */

    const dirty = new Set<string>()
    const running = new Set<string>()
    const ensured = new Set<string>()
    const synced = new Map<string, Set<string>>()

    const ensureSession = async (sessionID: string): Promise<void> => {
      const table = await tableName(config.keys, sessionID)
      if (ensured.has(table)) return
      let title: string | null = null
      try {
        const getter = (ctx.session as { get?: (opts: { sessionID: string }) => Promise<unknown> }).get
        const meta = (await getter?.({ sessionID })) as { title?: unknown } | undefined
        const titleText = meta?.title
        if (typeof titleText === "string" && titleText.length > 0) {
          // Store the title encrypted so a D1 dump reveals nothing about it.
          const record = await encryptJSON(config.keys, sessionID, "__title__", { t: titleText })
          title = JSON.stringify({ nonce: record.nonce, ciphertext: record.ciphertext, mac: record.mac })
        }
      } catch {
        /* title is optional */
      }
      await config.store.ensureSession(table, title)
      ensured.add(table)
    }

    const syncSession = async (sessionID: string): Promise<void> => {
      const messages = await ctx.session.context({ sessionID })
      if (!Array.isArray(messages) || messages.length === 0) return
      const table = await tableName(config.keys, sessionID)
      await ensureSession(sessionID)

      const seen = synced.get(sessionID) ?? new Set<string>()
      const pending: Array<{ messageID: string; record: Awaited<ReturnType<typeof encryptJSON>> }> = []
      for (const message of messages) {
        const messageID = (message as { id?: unknown })?.id
        if (typeof messageID !== "string" || messageID.length === 0) continue
        if (seen.has(messageID)) continue
        const createdAt = (message as { time?: { created?: number } })?.time?.created ?? Date.now()
        pending.push({ messageID, record: await encryptJSON(config.keys, sessionID, messageID, message, createdAt) })
      }
      if (pending.length === 0) return

      await config.store.push(
        table,
        pending.map((entry) => entry.record),
      )
      for (const entry of pending) seen.add(entry.messageID)
      synced.set(sessionID, seen)
    }

    const run = async (sessionID: string): Promise<void> => {
      running.add(sessionID)
      try {
        while (dirty.has(sessionID)) {
          dirty.delete(sessionID)
          try {
            await syncSession(sessionID)
          } catch (error) {
            log(`sync failed for ${sessionID}: ${error instanceof Error ? error.message : String(error)}`)
          }
        }
      } finally {
        running.delete(sessionID)
      }
    }

    const schedule = (sessionID: string): void => {
      dirty.add(sessionID)
      if (!running.has(sessionID)) void run(sessionID)
    }

    await ctx.session.hook("context", (event) => {
      schedule(event.sessionID)
    })

    /* -- recall tool (decrypts locally) --------------------------------- */

    await ctx.tool.transform((editor) => {
      editor.add({
        name: "safestore_recall",
        description:
          "Search the end-to-end encrypted memory of a session. Records are decrypted locally; the server only ever held ciphertext.",
        input: {
          type: "object",
          properties: {
            query: { type: "string", description: "Case-insensitive substring to match. Omit for the most recent records." },
            sessionID: { type: "string", description: "Session to search. Defaults to the current session." },
            limit: { type: "number", description: "Maximum matches to return (default 20)." },
            full: { type: "boolean", description: "Return the full decrypted message instead of a short preview." },
          },
          additionalProperties: false,
        },
        execute: async (rawInput: unknown, toolCtx) => {
          const input = (rawInput ?? {}) as RecallInput
          const sessionID =
            typeof input.sessionID === "string" && input.sessionID.length > 0
              ? input.sessionID
              : toolCtx.sessionID
          const limit =
            typeof input.limit === "number" && Number.isFinite(input.limit)
              ? Math.min(Math.max(1, Math.trunc(input.limit)), 100)
              : 20
          const query = typeof input.query === "string" ? input.query.toLowerCase() : undefined

          try {
            const table = await tableName(config.keys, sessionID)
            const records = await config.store.pullAll(table)
            const matches: Array<{ seq: number; text: string }> = []
            for (const record of records) {
              const value = await decryptJSON(config.keys, record)
              if (value === undefined) continue
              const preview = textPreview(value, input.full === true)
              if (query && !preview.toLowerCase().includes(query)) continue
              matches.push({ seq: record.seq, text: preview })
            }
            const selected = matches.slice(-limit)
            if (selected.length === 0) return { content: "No matching encrypted memory found." }
            const body = selected.map((m) => `#${m.seq}\n${m.text}`).join("\n\n---\n\n")
            return { content: `Decrypted ${selected.length} record(s) for ${sessionID}:\n\n${body}` }
          } catch (error) {
            return { content: `safestore recall failed: ${error instanceof Error ? error.message : String(error)}` }
          }
        },
      })
    })

    return () => {
      dirty.clear()
    }
  },
})
