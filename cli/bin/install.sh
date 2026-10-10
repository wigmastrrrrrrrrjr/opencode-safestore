#!/usr/bin/env bash
# Install sf CLI
set -euo pipefail
REPO="https://github.com/csomeone301/opencode-safestore"
BIN="$HOME/.local/bin"
mkdir -p "$BIN"
TEMP="$(mktemp -d)"
trap "rm -rf '$TEMP'" EXIT
if command -v git >/dev/null 2>&1; then
  git clone --depth 1 "$REPO" "$TEMP" 2>/dev/null || (curl -sSL "${REPO}/archive/refs/heads/main.tar.gz" | tar xzf - -C "$TEMP" --strip-components 1)
else
  curl -sSL "${REPO}/archive/refs/heads/main.tar.gz" | tar xzf - -C "$TEMP" --strip-components 1
fi
cp "$TEMP/cli/src/index.js" "$BIN/sf"
chmod +x "$BIN/sf"
echo "Installed sf to $BIN/sf"
