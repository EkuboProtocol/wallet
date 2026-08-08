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

# Resolve this script's own path before deriving the repository from it. The
# name it was invoked by decides which tree gets built below, and building a
# tree runs its `build.rs` and every build script under it — with the signing
# vault already located and about to be unlocked. A symlink into somebody
# else's checkout would have made that somebody else's code, so the link is
# followed to the file that actually holds these lines.
script_path="${BASH_SOURCE[0]}"
while [ -L "$script_path" ]; do
  link_target="$(readlink "$script_path")"
  case "$link_target" in
    /*) script_path="$link_target" ;;
    *) script_path="$(dirname "$script_path")/$link_target" ;;
  esac
done
repo_root="$(cd "$(dirname "$script_path")/.." && pwd -P)"

# And having resolved it, say what it must be. A build is only safe here
# because it is this repository's build.
if ! grep -q '^name = "ekubo-wallet"$' "$repo_root/Cargo.toml" 2>/dev/null; then
  echo "$repo_root is not the ekubo-wallet repository; refusing to build in it" >&2
  exit 1
fi

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

# Read without echo, then passed to `security import` as an argument, which is
# the only way that command takes one: omitting -P asks for it through a GUI
# panel instead, which is not a prompt a terminal rehearsal should depend on.
#
# So it is in this process's argv for the length of the import, and run 6251
# raised that (187014). On macOS a process's arguments are readable by its own
# user and by root, not by other users, so what this exposes is exactly the
# same-user attacker that `docs/threat-model.md` already accepts as residual —
# one who can read this argv can also read the keystrokes that produced it.
# Recorded rather than worked around, because every alternative here is worse
# than the thing it avoids.
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

# Signing is the last step that needs the keychain: notarization authenticates
# with the .p8. Hand the login keychain back now rather than holding the search
# list for the length of the wait, which is minutes at best and has run past
# forty-five for a first submission from a new team.
# shellcheck disable=SC2086
security list-keychains -d user -s $original_keychains
echo "==> keychain search list restored; notarization does not need it"

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

# Interrupting the wait is safe and costs nothing: the archive is already
# uploaded and the Notary service finishes regardless. Note the submission id
# it prints below and ask for the verdict later with
#   xcrun notarytool info <id> --key ... --key-id ... --issuer ...
echo "==> submitting to the Notary service"
echo "    A first submission from a new team can take far longer than the"
echo "    usual few minutes. Ctrl-C is safe; the verdict survives by id."
xcrun notarytool submit "$package.zip" \
  --key "$p8" --key-id "$key_id" --issuer "$issuer_id" --wait

echo
echo "==> rehearsal passed: signed, chained, timestamped, and notarized"
echo "    Nothing was tagged, published, or stapled. A bare executable cannot"
echo "    take a stapled ticket, so Gatekeeper resolves it online at first run."
