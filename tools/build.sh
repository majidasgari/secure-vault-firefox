#!/usr/bin/env bash
# Build the .xpi (a plain zip of extension/) into dist/.
# Usage: tools/build.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

command -v zip >/dev/null || { echo "zip is not installed (sudo apt install zip)" >&2; exit 1; }

ver="$(python3 -c "import json;print(json.load(open('extension/manifest.json'))['version'])")"
out="dist/secure-vault-browser-${ver}.xpi"

mkdir -p dist
rm -f "$out"
( cd extension && zip -qr "../${out}" . -x '*.DS_Store' -x '__MACOSX/*' )

echo "built: $root/$out"
unzip -l "$out" | tail -n +4
