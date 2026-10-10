#!/usr/bin/env bash
# Deploy the opencode-safestore Worker and print the URL + token setup commands.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/../worker"

if grep -q "REPLACE_WITH_YOUR_DATABASE_ID" wrangler.toml; then
  echo "Creating D1 database 'opencode-safestore'..."
  out="$(bunx wrangler d1 create opencode-safestore 2>&1 || true)"
  printf '%s\n' "$out"
  id="$(printf '%s' "$out" | grep -oE 'database_id = "[0-9a-f-]+"' | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
  if [ -z "${id:-}" ]; then
    echo "Could not detect a database id. Create it manually, then paste it into wrangler.toml." >&2
    exit 1
  fi
  sed -i "s/REPLACE_WITH_YOUR_DATABASE_ID/$id/" wrangler.toml
  echo "Wrote database_id=$id"
fi

TOKEN_FILE="$here/../.safestore-token"
if [ ! -f "$TOKEN_FILE" ]; then
  openssl rand -base64 48 | tr -d '\n' > "$TOKEN_FILE"
  echo "Generated a new SAFESTORE_TOKEN in .safestore-token"
fi
printf '%s' "$(cat "$TOKEN_FILE")" | bunx wrangler secret put SAFESTORE_TOKEN

bunx wrangler deploy

echo
echo "Export these before starting OpenCode:"
echo "  export OPENCODE_SAFESTORE_URL=\"https://opencode-safestore.<your-subdomain>.workers.dev\""
echo "  export OPENCODE_SAFESTORE_TOKEN=\"$(cat "$TOKEN_FILE")\""
echo "  export OPENCODE_SAFESTORE_KEY=\"\$(openssl rand -base64 32)\"   # keep this safe"
