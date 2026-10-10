/**
 * Thin client for the opencode-safestore Worker.
 *
 * Only ciphertext crosses the wire. The Worker is treated as an untrusted,
 * write-mostly blob store: it authenticates us with a bearer token, but the
 * confidentiality of stored data does not depend on it.
 */

import type { CipherRecord } from "./crypto.js"

export interface StoreOptions {
  url: string
  token: string
  timeoutMs?: number
  fetchImpl?: typeof fetch
}

export interface PulledRecord extends CipherRecord {
  seq: number
}

export class Store {
  private readonly base: string
  private readonly token: string
  private readonly timeoutMs: number
  private readonly fetchImpl: typeof fetch

  constructor(options: StoreOptions) {
    this.base = options.url.replace(/\/+$/, "")
    this.token = options.token
    this.timeoutMs = options.timeoutMs ?? 15_000
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis)
  }

  private async request(method: string, path: string, body?: unknown): Promise<any> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)
    try {
      const response = await this.fetchImpl(`${this.base}${path}`, {
        method,
        signal: controller.signal,
        headers: {
          authorization: `Bearer ${this.token}`,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      const text = await response.text()
      const payload = text ? JSON.parse(text) : {}
      if (!response.ok) {
        throw new Error(`safestore ${method} ${path} -> ${response.status} ${payload?.error ?? text}`)
      }
      return payload
    } finally {
      clearTimeout(timer)
    }
  }

  async ensureSession(table: string, title?: string | null): Promise<void> {
    await this.request("POST", "/api/sessions", { table, title: title ?? undefined })
  }

  async push(table: string, records: CipherRecord[]): Promise<void> {
    if (records.length === 0) return
    for (let i = 0; i < records.length; i += 200) {
      await this.request("PUT", `/api/sessions/${table}/messages`, {
        messages: records.slice(i, i + 200),
      })
    }
  }

  async pullAll(table: string): Promise<PulledRecord[]> {
    const out: PulledRecord[] = []
    let after = 0
    for (;;) {
      const page = await this.request("GET", `/api/sessions/${table}/messages?after=${after}&limit=500`)
      const messages: PulledRecord[] = page.messages ?? []
      out.push(...messages)
      if (messages.length < 500) break
      after = messages[messages.length - 1].seq
    }
    return out
  }

  async deleteSession(table: string): Promise<void> {
    await this.request("DELETE", `/api/sessions/${table}`)
  }

  async health(): Promise<boolean> {
    try {
      const response = await this.fetchImpl(`${this.base}/health`, { signal: AbortSignal.timeout(5_000) })
      return response.ok
    } catch {
      return false
    }
  }
}
