#!/bin/bash
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" = true && "${RUNNER_OS:-}" = macOS ]]
image="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
work="$(mktemp -d)"
trap 'hdiutil detach "$work/mount" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
test ! -e '/Applications/Ekubo Wallet 2.app'
hdiutil attach "$image" -nobrowse -readonly -mountpoint "$work/mount"
app="$work/mount/Ekubo Wallet 2.app"
codesign --verify --deep --strict "$app"
test "$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$app/Contents/Info.plist")" = org.ekubo.wallet.v2
test -x "$app/Contents/MacOS/ekubo-wallet-v2"
test -x "$app/Contents/MacOS/ekubo-wallet-v2-mcp-bridge"
ditto "$app" '/Applications/Ekubo Wallet 2.app'
codesign --verify --deep --strict '/Applications/Ekubo Wallet 2.app'
rm -rf '/Applications/Ekubo Wallet 2.app'
printf '%s\n' 'Final DMG mount/install/signature verification passed; interactive desktop acceptance remains separate.'
