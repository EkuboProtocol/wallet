#!/usr/bin/env bash
#
# Fit the transaction-preview model on a DigitalOcean GPU droplet.
#
# Training does not need a GPU -- `preview-train --device cpu` is the default
# and works anywhere -- but it needs *video memory*, and an integrated GPU with
# a 2 GB carve-out has too little: cubecl sizes its wgpu memory pool from the
# adapter's reported memory and asks for one ~3 GB allocation that fails. A
# droplet with real VRAM turns eighty minutes of CPU fitting into a few.
#
# The droplet is destroyed on every exit path, including failure and Ctrl-C.
# It bills by the hour, so leaving one running is the expensive mistake and the
# trap below is the thing that prevents it. The temporary SSH key is removed
# with it.
#
# Usage:
#   scripts/train-preview-remote.sh /tmp/labeled.jsonl [epochs]
#
# Requires: doctl authenticated, rsync, ssh.

set -euo pipefail

CORPUS="${1:?usage: $0 <labeled-corpus.jsonl> [epochs]}"
EPOCHS="${2:-12}"
IMAGE="${PREVIEW_DROPLET_IMAGE:-gpu-h100x1-base}"

# Tried in order, cheapest first, until one is actually creatable.
#
# A single hard-coded size fails outright roughly as often as it works: GPU
# capacity moves, and a size the API lists as `available` in a region still
# answers "Size is not available in this region" when that region is full.
# Any of these fits a 1.2M-parameter model many times over, so the only thing
# that distinguishes them here is price.
#
# `PREVIEW_DROPLET_SIZE` and `PREVIEW_DROPLET_REGION` override the list
# entirely, for when you want a specific machine.
CANDIDATES=(
  "gpu-4000adax1-20gb tor1"
  "gpu-l40sx1-48gb tor1"
  "gpu-6000adax1-48gb tor1"
  "gpu-h100x1-80gb tor1"
  "gpu-h100x1-80gb ams3"
  "gpu-h100x1-80gb nyc2"
)
if [ -n "${PREVIEW_DROPLET_SIZE:-}" ]; then
  CANDIDATES=("${PREVIEW_DROPLET_SIZE} ${PREVIEW_DROPLET_REGION:-tor1}")
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="ekubo-preview-train-$STAMP"
KEY="$HOME/.ssh/preview-train-$STAMP"
DROPLET_ID=""
KEY_ID=""

cleanup() {
  local status=$?
  set +e
  if [ -n "$DROPLET_ID" ]; then
    echo "destroying droplet $DROPLET_ID" >&2
    doctl compute droplet delete "$DROPLET_ID" --force >/dev/null 2>&1
  fi
  if [ -n "$KEY_ID" ]; then
    doctl compute ssh-key delete "$KEY_ID" --force >/dev/null 2>&1
  fi
  rm -f "$KEY" "$KEY.pub"
  exit $status
}
trap cleanup EXIT INT TERM

ssh-keygen -t ed25519 -f "$KEY" -N "" -C "$NAME" -q
KEY_ID="$(doctl compute ssh-key import "$NAME" --public-key-file "$KEY.pub" \
  --format ID --no-header)"

for candidate in "${CANDIDATES[@]}"; do
  read -r SIZE REGION <<<"$candidate"
  echo "trying a $SIZE in $REGION" >&2
  if DROPLET_ID="$(doctl compute droplet create "$NAME" \
      --size "$SIZE" --image "$IMAGE" --region "$REGION" \
      --ssh-keys "$KEY_ID" --tag-name ekubo-preview-train --wait \
      --format ID --no-header 2>/dev/null)" && [ -n "$DROPLET_ID" ]; then
    break
  fi
  DROPLET_ID=""
done
if [ -z "$DROPLET_ID" ]; then
  echo "no GPU droplet could be created; every candidate size was unavailable" >&2
  exit 1
fi
IP="$(doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)"
echo "droplet $DROPLET_ID ($SIZE, $REGION) at $IP" >&2

SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$KEY" "root@$IP")
for _ in $(seq 1 60); do
  "${SSH[@]}" true 2>/dev/null && break
  sleep 5
done

# libvulkan1 is the loader; the NVIDIA image already ships the ICD beside it.
"${SSH[@]}" "DEBIAN_FRONTEND=noninteractive apt-get update -qq \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libvulkan1 build-essential pkg-config \
  && curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal" >/dev/null

rsync -az --delete --exclude 'target/' --exclude '.git/' --exclude '.claude/' \
  -e "ssh -o StrictHostKeyChecking=no -i $KEY" "$REPO/" "root@$IP:/root/wallet/"
rsync -az -e "ssh -o StrictHostKeyChecking=no -i $KEY" "$CORPUS" "root@$IP:/root/labeled.jsonl"

# The build-time updater key only has to be canonical base64; this binary never
# checks for an update, and nothing it produces is shipped.
"${SSH[@]}" "cd /root/wallet && PATH=/root/.cargo/bin:\$PATH \
  EKUBO_UPDATER_PUBLIC_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  cargo build --release -p ekubo-wallet-preview --features train"

"${SSH[@]}" "cd /root/wallet && ./target/release/preview-train \
  --corpus /root/labeled.jsonl --out /root/preview.bin --epochs $EPOCHS --device gpu"

# Both files, always together. The fingerprint is what `weights::load` checks
# to refuse weights fitted against a different build, so retrieving the weights
# without it leaves a checkout that refuses its own model -- which is how this
# script failed the first time it was used for real.
MODEL="$REPO/crates/ekubo-wallet-preview/model"
rsync -az -e "ssh -o StrictHostKeyChecking=no -i $KEY" \
  "root@$IP:/root/preview.bin" "root@$IP:/root/preview.fingerprint" "$MODEL/"
echo "wrote $MODEL/preview.bin and $MODEL/preview.fingerprint" >&2
