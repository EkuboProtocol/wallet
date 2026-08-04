#!/bin/sh
# Build this checkout with cargo and install it: a shorthand for
# EKUBO_WALLET_LOCAL_SOURCE=<this repository> sh install.sh
# All other install.sh environment variables still apply.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
EKUBO_WALLET_LOCAL_SOURCE="$SCRIPT_DIR" export EKUBO_WALLET_LOCAL_SOURCE
exec sh "$SCRIPT_DIR/install.sh" "$@"
