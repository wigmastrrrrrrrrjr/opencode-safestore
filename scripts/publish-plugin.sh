#!/usr/bin/env bash
# Build the single-file plugin and publish it to D1 via the Worker admin
# endpoint (if ADMIN_TOKEN + SAFESTORE_URL are set) or via `wrangler d1 execute`.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/.."

bun build src/index.ts --target=node --format=esm --external @opencode/plugin --outfile=dist/opencode-safestore.js >/dev/null

VERSION="${1:-$(date +%Y.%m.%d.%H%M%S)}"
SOURCE_FILE="$PWD/dist/opencode-safestore.js"
SHA="$(sha256sum "$SOURCE_FILE" | awk '{print $1}')"

if [ -n "${ADMIN_TOKEN:-}" ] && [ -n "${SAFESTORE_URL:-}" ]; then
  echo ">> publishing v$VERSION via Worker admin endpoint"
  python3 - "$SAFESTORE_URL" "$ADMIN_TOKEN" "$VERSION" "$SOURCE_FILE" <<'PY'
import json, sys, urllib.request, urllib.error
url, token, version, srcdir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
source = open(srcdir).read()
req = urllib.request.Request(url.rstrip("/") + "/admin/plugin", method="POST",
    data=json.dumps({"version": version, "source": source}).encode(),
    headers={"authorization": "Bearer " + token, "content-type": "application/json"})
try:
    print(urllib.request.urlopen(req, timeout=30).read().decode())
except urllib.error.HTTPError as e:
    sys.exit("publish failed: " + e.read().decode())
PY
else
  TMP="$(mktemp)"
  python3 - "$TMP" "$VERSION" "$SHA" "$SOURCE_FILE" <<'PY'
import sys, time
out, version, sha, srcdir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
source = open(srcdir).read()
sql = "INSERT OR REPLACE INTO plugin_releases (version, sha256, source, created_at) VALUES ('%s', '%s', '%s', %d);" % (
    version.replace("'", "''"), sha, source.replace("'", "''"), int(time.time() * 1000))
open(out, "w").write(sql)
PY
  echo ">> plugin bundle: dist/opencode-safestore.js ($(wc -c < "$SOURCE_FILE") bytes, sha256 $SHA)"
  echo ">> publish with (from the worker/ directory):"
  echo "   wrangler d1 execute opencode-safestore --remote --file=$TMP"
fi
