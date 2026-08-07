#!/bin/bash
# Rehearse the macOS half of .github/workflows/release.yml against the real
# credentials, without tagging or publishing anything.
#
# This runs the same sequence the release job runs: a throwaway keychain, the
# .p12 imported into it, the vendored Apple intermediate imported beside it, a
# hardened-runtime timestamped signature, the same `ditto` archive, and a real
# `notarytool submit --wait`. A pass here means the credentials and the chain
# are sound; what it cannot cover is the workflow's own secret plumbing, which
# only a run on GitHub exercises.
#
# Usage: contrib/rehearse-macos-signing.sh [path/to/binary]

set -euo pipefail

vault="${EKUBO_SIGNING_VAULT:-$HOME/.private/ekubo-apple-signing}"
p12="$vault/DeveloperID.p12"
p8="$vault/AuthKey_B4PZFL5V6Z.p8"
identity="Developer ID Application: Ekubo, Inc. (25NDUU3KKC)"
key_id="B4PZFL5V6Z"
issuer_id="5a547f85-021c-4fca-a753-9caedb9a19b3"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
intermediate="$repo_root/.github/apple/DeveloperIDG2CA.cer"
expected_digest=f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a

binary="${1:-$repo_root/target/release/ekubo-wallet}"

for required in "$p12" "$p8" "$intermediate"; do
  if [ ! -f "$required" ]; then
    echo "missing: $required" >&2
    exit 1
  fi
done

if [ ! -f "$binary" ]; then
  echo "==> building $binary"
  (cd "$repo_root" && cargo build --release)
fi

actual_digest="$(shasum -a 256 "$intermediate" | cut -d ' ' -f 1)"
if [ "$actual_digest" != "$expected_digest" ]; then
  echo "the vendored intermediate does not match its pinned SHA-256" >&2
  exit 1
fi

work="$(mktemp -d)"
keychain="$work/rehearsal.keychain-db"
keychain_password="rehearsal-$$"

# The release job repoints the user keychain search list at its own keychain,
# and this rehearsal must do the same to prove the temporary keychain alone can
# build the chain. Capture the real list first and put it back unconditionally,
# because leaving it replaced would break signing and keychain access globally.
original_keychains="$(security list-keychains -d user | sed -e 's/^[[:space:]]*"//' -e 's/"$//')"

restore() {
  local status=$?
  # shellcheck disable=SC2086
  security list-keychains -d user -s $original_keychains 2>/dev/null || true
  security delete-keychain "$keychain" 2>/dev/null || true
  rm -rf "$work"
  if [ "$status" -eq 0 ]; then
    echo "==> keychain search list restored; rehearsal artifacts removed"
  else
    echo "==> failed (exit $status); keychain search list restored" >&2
  fi
}
trap restore EXIT

printf 'p12 export password: '
read -rs p12_password
printf '\n'

echo "==> creating a throwaway keychain"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"

echo "==> importing the identity and the Apple intermediate"
security import "$p12" -k "$keychain" -P "$p12_password" -T /usr/bin/codesign
security import "$intermediate" -k "$keychain"
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain"

valid="$(security find-identity -v -p codesigning "$keychain" |
  sed -n 's/^ *\([0-9][0-9]*\) valid identities found.*/\1/p')"
if [ "${valid:-0}" -lt 1 ]; then
  echo "no valid codesigning identity: the .p12 password may be wrong, or the chain did not resolve" >&2
  exit 1
fi
echo "==> $valid valid identity in the temporary keychain"

echo "==> signing with hardened runtime and a secure timestamp"
staged="$work/ekubo-wallet"
cp "$binary" "$staged"
codesign --force --options runtime --timestamp --sign "$identity" "$staged"
codesign --verify --strict --verbose=2 "$staged"
codesign -dv --verbose=4 "$staged" 2>&1 | grep -E "^Authority|^Timestamp|^TeamIdentifier"

echo "==> packaging exactly as the release job does"
package="$work/ekubo-wallet-rehearsal"
mkdir -p "$package"
install -m 0755 "$staged" "$package/ekubo-wallet"
ln -s ekubo-wallet "$package/ew"
install -m 0644 "$repo_root/LICENSE" "$package/LICENSE"
install -m 0644 "$repo_root/README.md" "$package/README.md"
cp -R "$repo_root/completions" "$package/completions"
cp -R "$repo_root/examples" "$repo_root/schemas" "$package/"
ditto -c -k --sequesterRsrc --keepParent "$package" "$package.zip"

echo "==> submitting to the Notary service (this takes a few minutes)"
xcrun notarytool submit "$package.zip" \
  --key "$p8" --key-id "$key_id" --issuer "$issuer_id" --wait

echo
echo "==> rehearsal passed: signed, chained, timestamped, and notarized"
echo "    Nothing was tagged, published, or stapled. A bare executable cannot"
echo "    take a stapled ticket, so Gatekeeper resolves it online at first run."
