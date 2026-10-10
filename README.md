# opencode-safestore

End-to-end encrypted session memory for [OpenCode](https://opencode.ai), backed by
Cloudflare D1 and fronted by a zero-knowledge Worker called `opencode-safestore`.

Every OpenCode session is mirrored, message by message, into its **own D1 table**.
Table names and every stored field are produced on **your** machine with a master
key that never leaves it. A dump of the database shows only opaque `mem_<hex>`
tables of base64 ciphertext and keyed hashes — it does not show messages, session
titles, or even which account owns what beyond an owner id.

This generation adds a full **account layer**: sign up on the dashboard, manage
API keys and OAuth apps, and connect devices with a CLI (`sf auth login`) that
delivers your encryption key to the new device **end-to-end** and installs the
plugin from the cloud into OpenCode.

```
OpenCode ──(AES-256-GCM + HMAC)──►  opencode-safestore Worker ──► Cloudflare D1
    ▲                                      │
    │  master key (local only)             │  ciphertext only
    └──────────────────────────────────────┘
      sf auth login ──browser consent──►  (PKCE + P-256 ECDH key delivery)
```

## Security model

| Item | Where it lives | Visible server-side? |
| --- | --- | --- |
| Account password | Your device (PBKDF2 pre-hash) | Never transmitted |
| Safestore master key | Your devices, wrapped by your password | No (server has only the wrapped copy) |
| Session table name | `mem_` + HMAC-SHA-256 of the session id | Hex hash only |
| Message bodies / roles / tool calls | AES-256-GCM ciphertext | No |
| Integrity tag | HMAC-SHA-256 over the plaintext | Hash only |
| Session title | Encrypted with the master key | No |
| API key / OAuth token | Hashed server-side | Hash only |
| Timestamps / counts / table names of *registered* sessions | D1 metadata | Yes (metadata only) |

Key hierarchy (HKDF-SHA-256, domain-separated): `enc` (AES-256-GCM), `mac`
(HMAC-SHA-256), `table` (naming), `id` (record ids).

### Zero-knowledge account login

- The browser derives `authKey` and `wrapKey` from your password (PBKDF2 300k +
  HKDF). Only `authKey` crosses the wire; the server stores a re-hashed verifier.
- Your safestore master key is stored wrapped by `wrapKey`. **The server never
  sees your password or your master key in plaintext.**
- When a device logs in (`sf auth login`), the browser re-wraps the master key to
  the device's ephemeral P-256 key over an encrypted channel — the server only
  ever handles ciphertext, so it cannot read the key.

> Metadata that remains visible by design: which encrypted sessions exist, their
> record counts, sizes and timestamps. Padding/decoy rows would be needed to hide
> those; content and titles are never revealed.

## Components

- `worker/` — the Cloudflare Worker: signup/login, session cookie, dashboard SPA
  (`/app`), OAuth authorization-code + PKCE consent (`/authorize`), token
  exchange (`/oauth/token`), API keys, OAuth apps, owner-scoped dataset API,
  cloud plugin distribution (`/plugin/latest.js`). D1: `users`, `web_sessions`,
  `api_keys`, `apps`, `auth_codes`, `access_tokens`, `dataset_sessions`,
  `plugin_releases`.
- `cli/` — `sf`: `auth login|status|logout`, `plugin update`. No dependencies.
- `src/` — the OpenCode plugin (crypto + store + sync + `safestore_recall`).
- `scripts/` — `deploy.sh`, `publish-plugin.sh`, `smoke.ts`, `e2e.mjs`.

## 1. Deploy the Worker

```sh
cd worker
wrangler d1 create opencode-safestore      # once; paste the id into wrangler.toml
wrangler deploy                            # D1 id is already wired in
```

Optional secrets (set with `wrangler secret put …`):
- `ADMIN_TOKEN` — only needed to publish plugin releases over HTTP.

## 2. Publish the plugin bundle

```sh
scripts/publish-plugin.sh                 # builds dist/opencode-safestore.js
```

With `ADMIN_TOKEN` and `SAFESTORE_URL` exported it posts to `/admin/plugin`;
otherwise it prints a `wrangler d1 execute … --file=…` command for you to run.

## 3. Log in and connect a device

```sh
cli/src/index.js auth login               # or: npm link, then `sf auth login`
```

This opens `/authorize` → consent screen (signed in via cookie, or redirected to
`/signup`). After approval the CLI:

1. exchanges the PKCE code for an access token,
2. receives the master key re-wrapped to its ephemeral key and unwraps it locally,
3. mints a long-lived API key for the plugin,
4. writes `~/.config/opencode/opencode-safestore.json` (mode 0600),
5. downloads the latest plugin from the Worker into
   `~/.config/opencode/plugins/opencode-safestore.js` and verifies its SHA-256.

Restart OpenCode to load the plugin. It reads the config file (or env
`OPENCODE_SAFESTORE_URL` / `_TOKEN` / `_KEY`).

## API surface (summary)

- `POST /api/auth/signup|login`, `GET /api/auth/salt`, `POST /api/auth/logout`, `GET /api/me`
- `GET|POST /api/keys`, `DELETE /api/keys/:id`
- `GET|POST /api/apps`, `DELETE /api/apps/:id`
- `GET /authorize`, `POST /api/oauth/approve|deny`, `POST /oauth/token`
- `POST /api/sessions`, `GET /api/sessions`, `PUT|GET /api/sessions/:table/messages`, `DELETE /api/sessions/:table`
- `GET /plugin/latest.json|.js`, `POST /admin/plugin`

## Threat notes

- The account system is "zero-knowledge at rest": a DB leak exposes no messages
  and no passwords, but a malicious server could brute-force a *weak* password
  offline (same as any password-based scheme). Use a strong password.
- OAuth codes are single-use, 10-minute TTL, PKCE (S256) mandatory, loopback
  redirects restricted.
- Dataset tables are registered per-account; cross-account access is rejected by
  the Worker even though the Worker cannot decrypt the content.

## Development

```sh
bun build src/index.ts --target=node --format=esm --external @opencode/plugin --outfile=dist/opencode-safestore.js
node scripts/e2e.mjs        # full live-checks against the deployed Worker
```
