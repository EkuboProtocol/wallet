#!/bin/sh
# Build this checkout with cargo and install it: a shorthand for
# EKUBO_WALLET_LOCAL_SOURCE=<this repository> sh install.sh
# All other install.sh environment variables still apply.
set -eu

# Resolve to the wrapper's own physical location before deciding what to run.
# `dirname "$0"` names whatever path invoked this script, so a symlink planted
# in another directory would point both the exported source tree and the
# delegated install.sh at that directory instead of this checkout.
SCRIPT_PATH=$0
while [ -L "$SCRIPT_PATH" ]; do
  LINK_TARGET=$(readlink -- "$SCRIPT_PATH")
  case $LINK_TARGET in
    /*) SCRIPT_PATH=$LINK_TARGET ;;
    *) SCRIPT_PATH=$(dirname -- "$SCRIPT_PATH")/$LINK_TARGET ;;
  esac
done
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd -P)
EKUBO_WALLET_LOCAL_SOURCE="$SCRIPT_DIR" export EKUBO_WALLET_LOCAL_SOURCE
exec sh "$SCRIPT_DIR/install.sh" "$@"
