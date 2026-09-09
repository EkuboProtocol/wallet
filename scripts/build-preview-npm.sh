#!/usr/bin/env bash
#
# Build the browser package from the same crate and the same weights the
# desktop wallet uses.
#
# Output is a plain npm package in `dist/npm/`: a `.wasm`, ESM glue, and
# TypeScript definitions generated from the Rust signatures. `wasm-pack`
# produces all three, which is why the JS side needs no hand-written types and
# cannot drift from the Rust.
#
# The weights are embedded in the `.wasm` rather than fetched. That costs
# 2.43 MB of download and buys three things worth more: one artifact instead of
# two, no CORS or asset-path configuration for the consumer, and no way for the
# code and the weights to be different versions -- which for a model that
# renders text next to a signing decision is the failure worth designing out.
#
# Usage:
#   scripts/build-preview-npm.sh [cpu|webgpu]     (default: cpu)

set -euo pipefail

BACKEND="${1:-cpu}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/dist/npm"

case "$BACKEND" in
  cpu)    FEATURES=(--no-default-features) ;;
  webgpu) FEATURES=() ;;
  *) echo "usage: $0 [cpu|webgpu]" >&2; exit 2 ;;
esac

command -v wasm-pack >/dev/null || {
  echo "wasm-pack is required: cargo install wasm-pack" >&2
  exit 1
}

# `--target web` emits an ESM module that works from a bundler, from Node, and
# from a bare <script type="module">. `bundler` would be smaller for webpack
# users and unusable everywhere else.
cd "$REPO/crates/ekubo-wallet-preview-wasm"
wasm-pack build \
  --release \
  --target web \
  --out-dir "$OUT" \
  --out-name ekubo-tx-preview \
  -- --profile wasm-release "${FEATURES[@]}"

# wasm-pack names the package after the crate. Rename it to the scope this is
# published under, and record which backend was built so a consumer can tell
# a 4 MB CPU build from an 8 MB WebGPU one without measuring it.
python3 - "$OUT" "$BACKEND" <<'PY'
import json
import pathlib
import sys

out, backend = pathlib.Path(sys.argv[1]), sys.argv[2]
manifest = out / "package.json"
package = json.loads(manifest.read_text(encoding="utf-8"))
package["name"] = "@ekubo/tx-preview"
package["description"] = (
    "A 2.4 MB transaction-preview model that runs in the browser: "
    "category, risk band and one sentence, from a decoded transaction."
)
package["keywords"] = ["ethereum", "wallet", "erc-7730", "clear-signing", "wasm"]
package["ekuboBackend"] = backend
manifest.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
print(f"wrote {manifest} ({backend} backend)")
PY

cp "$REPO/crates/ekubo-wallet-preview-wasm/README.md" "$OUT/README.md"
ls -la "$OUT"
