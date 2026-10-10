#!/usr/bin/env bash
# Run this ON THE PHONE (e.g. in Termux) once you have the opencode-safestore
# folder available there. It copies the plugin into shared storage/Downloads.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="${1:-$HOME/storage/downloads}"
mkdir -p "$dest"
rm -rf "$dest/opencode-safestore"
cp -r "$here" "$dest/opencode-safestore"
echo "Copied plugin to: $dest/opencode-safestore"
echo "Reference it from opencode.jsonc as:"
echo "  \"package\": \"file://$(cd "$dest/opencode-safestore" && pwd)\""
