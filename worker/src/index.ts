/**
 * opencode-safestore - account + OAuth consent server for the safestore plugin.
 *
 * The Worker is still zero-knowledge for session content: it only stores
 * client-encrypted ciphertext. It also runs the account system, the developer
 * dashboard, the OAuth authorization-code + PKCE flow, and the cloud plugin
 * distribution endpoint that the `sf` CLI installs from.
 */
import { type Env, ensureSchema, html, redirect, fail, SESSION_COOKIE, parseCookies, json } from "./core"
import {
  handleSalt,
  handleSignup,
  handleLogin,
  handleLogout,
  handleMe,
  handleListKeys,
  handleCreateKey,
  handleRevokeKey,
  handleListApps,
  handleCreateApp,
  handleDeleteApp,
  handleAuthorize,
  handleApprove,
  handleDeny,
  handleToken,
  handleCreateDataset,
  handleListDatasets,
  handlePush,
  handlePull,
  handleDeleteDataset,
  handlePluginMeta,
  handlePluginSource,
  handleAdminPublish,
  CLI_CLIENT_ID,
} from "./handlers"
import appHtml from "./app.html"
import appCss from "./app.css"
import appJs from "./app.js"

export { CLI_CLIENT_ID }

function renderApp(boot: unknown): Response {
  const safe = JSON.stringify(boot).replaceAll("<", "\\u003c").replaceAll("\u2028", "\\u2028").replaceAll("\u2029", "\\u2029")
  return html(appHtml.replace("__BOOT_JSON__", safe))
}

async function isLoggedIn(req: Request, env: Env): Promise<boolean> {
  // Cheap check: presence of a session cookie that maps to a live row.
  const token = parseCookies(req)[SESSION_COOKIE]
  if (!token) return false
  const hash = await sha256Hex(token)
  const row = await env.DB.prepare("SELECT expires_at FROM web_sessions WHERE token_hash = ?").bind(hash).first<{ expires_at: number }>()
  return !!row && row.expires_at > Date.now()
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("")
}

const SUCCESS_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>safestore - logged in</title><style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0f14;color:#e6edf3;
font:16px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.card{max-width:30rem;padding:2.5rem;text-align:center}
.badge{width:64px;height:64px;border-radius:50%;margin:0 auto 1.25rem;display:grid;place-items:center;
background:radial-gradient(circle at 35% 30%,#1f6feb,#0b3d91);box-shadow:0 0 0 8px rgba(31,111,235,.12)}
h1{font-size:1.35rem;margin:0 0 .5rem}
p{color:#9aa7b4;margin:.25rem 0}
a{color:#58a6ff}
</style></head><body><div class="card">
<div class="badge">&#10003;</div>
<h1>You are logged in</h1>
<p id="app">You are logged in to safestore. You may close this safely.</p>
<p>The CLI has received your credentials. Return to your terminal.</p>
<p><a href="/app">Go to dashboard</a></p>
</div></body></html>`

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url)
    const path = url.pathname
    const method = req.method.toUpperCase()

    try {
      await ensureSchema(env.DB)

      if (path === "/health") return json({ ok: true, service: "opencode-safestore", time: Date.now() })

      // static assets
      if (path === "/app.css") {
        return new Response(appCss, { headers: { "content-type": "text/css; charset=utf-8", "cache-control": "no-store" } })
      }
      if (path === "/app.js") {
        return new Response(appJs, {
          headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
        })
      }

      // plugin distribution (public - the source is not secret)
      if (path === "/plugin/latest.json" && method === "GET") return handlePluginMeta(env)
      if (path === "/plugin/latest.js" && method === "GET") return handlePluginSource(env)
      if (path === "/admin/plugin" && method === "POST") return handleAdminPublish(req, env)

      // auth API
      if (path === "/api/auth/salt" && method === "GET") return handleSalt(req, env, url)
      if (path === "/api/auth/signup" && method === "POST") return handleSignup(req, env)
      if (path === "/api/auth/login" && method === "POST") return handleLogin(req, env)
      if (path === "/api/auth/logout" && method === "POST") return handleLogout(req, env)
      if (path === "/api/me" && method === "GET") return handleMe(req, env)

      // keys
      if (path === "/api/keys" && method === "GET") return handleListKeys(req, env)
      if (path === "/api/keys" && method === "POST") return handleCreateKey(req, env)
      if (path.startsWith("/api/keys/") && method === "DELETE") return handleRevokeKey(req, env, path.slice("/api/keys/".length))

      // apps
      if (path === "/api/apps" && method === "GET") return handleListApps(req, env)
      if (path === "/api/apps" && method === "POST") return handleCreateApp(req, env)
      if (path.startsWith("/api/apps/") && method === "DELETE") return handleDeleteApp(req, env, path.slice("/api/apps/".length))

      // oauth
      if (path === "/api/oauth/approve" && method === "POST") return handleApprove(req, env)
      if (path === "/api/oauth/deny" && method === "POST") return handleDeny(req, env)
      if (path === "/oauth/token" && method === "POST") return handleToken(req, env)

      // datasets
      if (path === "/api/sessions" && method === "POST") return handleCreateDataset(req, env)
      if (path === "/api/sessions" && method === "GET") return handleListDatasets(req, env)
      const dsMatch = /^\/api\/sessions\/(mem_[0-9a-f]{32,64})(\/messages)?$/.exec(path)
      if (dsMatch) {
        const table = dsMatch[1]
        const isMessages = !!dsMatch[2]
        if (isMessages && method === "PUT") return handlePush(req, env, table)
        if (isMessages && method === "GET") return handlePull(req, env, table, url)
        if (!isMessages && method === "DELETE") return handleDeleteDataset(req, env, table)
      }

      // pages
      if (path === "/cli/success" && method === "GET") {
        return html(SUCCESS_PAGE)
      }
      if (path === "/authorize" && method === "GET") {
        const result = await handleAuthorize(req, env, url)
        if (result instanceof Response) return result
        if ((result.boot as any)?.redirect) return redirect((result.boot as any).redirect)
        return renderApp(result.boot)
      }
      if (path === "/app" && method === "GET") {
        if (!(await isLoggedIn(req, env))) return redirect(`/signup?next=${encodeURIComponent("/app")}`)
        return renderApp({ route: "dashboard" })
      }
      if (path === "/signup" && method === "GET") {
        if (await isLoggedIn(req, env)) return redirect("/app")
        return renderApp({ route: "signup", next: url.searchParams.get("next") ?? "/app" })
      }
      if (path === "/login" && method === "GET") {
        if (await isLoggedIn(req, env)) return redirect("/app")
        return renderApp({ route: "login", next: url.searchParams.get("next") ?? "/app" })
      }
      if (path === "/" && method === "GET") {
        return redirect((await isLoggedIn(req, env)) ? "/app" : "/signup")
      }

      return fail(404, "not found")
    } catch (error) {
      const message = error instanceof Error ? error.message + " | " + (error.stack ?? "").slice(0, 500) : String(error)
      console.error("safestore 500:", error)
      return fail(500, "internal error: " + message)
    }
  },
}
