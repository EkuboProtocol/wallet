#!/bin/sh
# Install the ekubo-wallet release binary, register it with detected agents, and
# install shell completion. Review this script before piping it to a shell.
#
# The archive is never trusted on its own: this script downloads SHA256SUMS,
# verifies the archive digest against it, and — when Cosign is installed —
# additionally verifies the keyless Sigstore bundle for SHA256SUMS against the
# release workflow identity before any file is extracted or made executable.
#
# Set EKUBO_WALLET_LOCAL_SOURCE to a checkout of this repository to build with
# `cargo build --locked --release` and install that build instead of a release
# download; agent registration and completions work identically.
set -eu

REPOSITORY=${EKUBO_WALLET_REPOSITORY:-EkuboProtocol/wallet-mcp-server}
VERSION=${EKUBO_WALLET_VERSION:-latest}
LOCAL_SOURCE=${EKUBO_WALLET_LOCAL_SOURCE:-}
SERVER_NAME=ekubo-wallet
: "${HOME:?HOME is required}"

log() {
  printf '%s\n' "ekubo-wallet: $*"
}

warn() {
  printf '%s\n' "ekubo-wallet: warning: $*" >&2
}

fail() {
  printf '%s\n' "ekubo-wallet: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

# Single-quote a value so it survives being pasted into a shell. Quoting this
# script's own uses of a path does nothing for a command line printed for an
# operator to copy: that text is reparsed by their shell, not by this one.
shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

need uname
need tar

# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS/$ARCH" in
  Linux/x86_64) TARGET=x86_64-unknown-linux-gnu; ARCHIVE_EXTENSION=tar.gz ;;
  Linux/aarch64 | Linux/arm64) TARGET=aarch64-unknown-linux-gnu; ARCHIVE_EXTENSION=tar.gz ;;
  Darwin/x86_64) TARGET=x86_64-apple-darwin; ARCHIVE_EXTENSION=zip ;;
  Darwin/arm64) TARGET=aarch64-apple-darwin; ARCHIVE_EXTENSION=zip ;;
  *)
    [ -n "$LOCAL_SOURCE" ] \
      || fail "no prebuilt binary for $OS/$ARCH; build from source with EKUBO_WALLET_LOCAL_SOURCE"
    TARGET=unsupported
    ARCHIVE_EXTENSION=none
    ;;
esac
if [ "$ARCHIVE_EXTENSION" = zip ] && [ -z "$LOCAL_SOURCE" ]; then
  need unzip
fi

# ---------------------------------------------------------------------------
# Download transport
#
# GitHub CLI is preferred because it carries existing credentials, which is what
# a private or pre-release repository needs. curl is used otherwise.
# ---------------------------------------------------------------------------

DOWNLOADER=none
if [ -z "$LOCAL_SOURCE" ]; then
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    DOWNLOADER=gh
  elif command -v curl >/dev/null 2>&1; then
    DOWNLOADER=curl
  else
    fail "an authenticated 'gh' or 'curl' is required to download the release"
  fi
fi

WORK_DIRECTORY=$(mktemp -d)
cleanup() {
  rm -rf "$WORK_DIRECTORY"
}
trap cleanup EXIT INT TERM

# curl, with any bearer token supplied out of band. A process's arguments are
# readable by anything else running as this user for as long as it lives, so
# the token travels on stdin as a --config document rather than in argv. The
# quoting is curl's own config syntax: a backslash and a double quote are the
# only characters that need escaping inside its quoted values.
curl_authenticated() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    printf 'header = "Authorization: Bearer %s"\n' \
      "$(printf '%s' "$GITHUB_TOKEN" | sed 's/[\\"]/\\&/g')" \
      | curl --config - "$@"
  else
    curl "$@"
  fi
}

api() {
  api_path=$1
  if [ "$DOWNLOADER" = gh ]; then
    gh api "$api_path"
  else
    set -- -fsSL -H "Accept: application/vnd.github+json"
    curl_authenticated "$@" "https://api.github.com/$api_path"
  fi
}

resolve_version() {
  if [ "$VERSION" != latest ]; then
    printf '%s\n' "${VERSION#v}"
    return
  fi
  api "repos/$REPOSITORY/releases/latest" \
    | tr ',' '\n' \
    | sed -n 's/.*"tag_name" *: *"v\{0,1\}\([^"]*\)".*/\1/p' \
    | head -n 1
}

TAG=""
PACKAGE=""
ARCHIVE=""
if [ -z "$LOCAL_SOURCE" ]; then
  RESOLVED_VERSION=$(resolve_version)
  [ -n "$RESOLVED_VERSION" ] || fail "could not resolve a release version for $REPOSITORY"
  TAG="v$RESOLVED_VERSION"
  PACKAGE="ekubo-wallet-$RESOLVED_VERSION-$TARGET"
  ARCHIVE="$PACKAGE.$ARCHIVE_EXTENSION"
fi

download_asset() {
  asset=$1
  destination=$2
  if [ "$DOWNLOADER" = gh ]; then
    gh release download "$TAG" --repo "$REPOSITORY" --pattern "$asset" \
      --dir "$WORK_DIRECTORY" --clobber >/dev/null 2>&1 || return 1
    [ -f "$WORK_DIRECTORY/$asset" ] || return 1
    [ "$WORK_DIRECTORY/$asset" = "$destination" ] || mv "$WORK_DIRECTORY/$asset" "$destination"
  else
    set -- -fsSL -o "$destination"
    curl_authenticated "$@" \
      "https://github.com/$REPOSITORY/releases/download/$TAG/$asset" || return 1
  fi
}

if [ -n "$LOCAL_SOURCE" ]; then
  # -------------------------------------------------------------------------
  # Local build: compile the checkout and stage it like an extracted archive.
  # No download or signature verification applies; you are trusting your own
  # working tree and toolchain.
  # -------------------------------------------------------------------------
  need cargo
  [ -f "$LOCAL_SOURCE/Cargo.toml" ] \
    || fail "EKUBO_WALLET_LOCAL_SOURCE=$LOCAL_SOURCE is not a repository checkout"
  log "building $LOCAL_SOURCE with cargo build --locked --release"
  (cd "$LOCAL_SOURCE" && cargo build --locked --release) \
    || fail "local build failed"
  SOURCE_DIRECTORY="$WORK_DIRECTORY/local"
  mkdir -p "$SOURCE_DIRECTORY/completions" "$SOURCE_DIRECTORY/contrib/polkit"
  install -m 0755 "$LOCAL_SOURCE/target/release/ekubo-wallet" "$SOURCE_DIRECTORY/ekubo-wallet"
  install -m 0644 "$LOCAL_SOURCE"/completions/* "$SOURCE_DIRECTORY/completions/"
  if [ -f "$LOCAL_SOURCE/contrib/polkit/com.ekubo.wallet.policy" ]; then
    install -m 0644 "$LOCAL_SOURCE/contrib/polkit/com.ekubo.wallet.policy" \
      "$SOURCE_DIRECTORY/contrib/polkit/"
  fi
else

log "downloading $ARCHIVE from $REPOSITORY $TAG"
download_asset "$ARCHIVE" "$WORK_DIRECTORY/$ARCHIVE" \
  || fail "could not download $ARCHIVE; check the release assets for $TAG"
download_asset SHA256SUMS "$WORK_DIRECTORY/SHA256SUMS" \
  || fail "could not download SHA256SUMS; refusing to install an unverified archive"

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

if command -v cosign >/dev/null 2>&1; then
  if download_asset SHA256SUMS.sigstore.json "$WORK_DIRECTORY/SHA256SUMS.sigstore.json"; then
    if cosign verify-blob \
      --bundle "$WORK_DIRECTORY/SHA256SUMS.sigstore.json" \
      --certificate-identity "https://github.com/$REPOSITORY/.github/workflows/release.yml@refs/tags/$TAG" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "$WORK_DIRECTORY/SHA256SUMS" >/dev/null 2>&1; then
      log "verified the Sigstore signature over SHA256SUMS"
    else
      fail "Sigstore verification of SHA256SUMS failed; refusing to install"
    fi
  else
    # Every release this script installs publishes a bundle, so its absence is
    # not "an older release" — it is a download that failed or was answered by
    # something else. Falling back to the checksum alone here would let anyone
    # who can fail one request choose which verification runs, which is the
    # weaker one. Refuse instead, and make the downgrade an explicit decision
    # the operator states rather than one an attacker makes for them.
    if [ "${EKUBO_WALLET_ALLOW_UNSIGNED:-0}" = "1" ]; then
      warn "no Sigstore bundle for SHA256SUMS; continuing on the checksum alone \
because EKUBO_WALLET_ALLOW_UNSIGNED=1"
    else
      fail "no Sigstore bundle published for SHA256SUMS at $TAG. cosign is \
installed, so this release should have one; a missing bundle means the download \
failed or was tampered with. Retry, or set EKUBO_WALLET_ALLOW_UNSIGNED=1 to \
install on the checksum alone."
    fi
  fi
else
  warn "cosign is not installed; verifying the checksum only. Install cosign to also verify the release signature."
fi

if command -v sha256sum >/dev/null 2>&1; then
  OBSERVED=$(sha256sum "$WORK_DIRECTORY/$ARCHIVE" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  OBSERVED=$(shasum -a 256 "$WORK_DIRECTORY/$ARCHIVE" | cut -d' ' -f1)
else
  fail "sha256sum or shasum is required to verify the download"
fi
EXPECTED=$(awk -v archive="$ARCHIVE" '$2 == archive || $2 == "*" archive { print $1 }' \
  "$WORK_DIRECTORY/SHA256SUMS" | head -n 1)
[ -n "$EXPECTED" ] || fail "SHA256SUMS does not list $ARCHIVE"
[ "$OBSERVED" = "$EXPECTED" ] || fail "checksum mismatch for $ARCHIVE; refusing to install"
log "verified the SHA-256 checksum of $ARCHIVE"

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

if [ "$ARCHIVE_EXTENSION" = zip ]; then
  unzip -q "$WORK_DIRECTORY/$ARCHIVE" -d "$WORK_DIRECTORY/extracted"
else
  mkdir -p "$WORK_DIRECTORY/extracted"
  tar -C "$WORK_DIRECTORY/extracted" -xzf "$WORK_DIRECTORY/$ARCHIVE"
fi
SOURCE_DIRECTORY="$WORK_DIRECTORY/extracted/$PACKAGE"
[ -d "$SOURCE_DIRECTORY" ] || fail "archive did not contain $PACKAGE"

fi
[ -f "$SOURCE_DIRECTORY/ekubo-wallet" ] || fail "staged files did not contain the ekubo-wallet executable"

BIN_DIR=${EKUBO_WALLET_BIN_DIR:-$HOME/.local/bin}
mkdir -p "$BIN_DIR"
install -m 0755 "$SOURCE_DIRECTORY/ekubo-wallet" "$BIN_DIR/ekubo-wallet"
# Gatekeeper marks anything downloaded as quarantined; clearing the attribute
# after verification avoids a spurious first-run block.
if [ "$OS" = Darwin ] && command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "$BIN_DIR/ekubo-wallet" >/dev/null 2>&1 || :
fi
# `ew` is a symlink, not a second binary: the OS keychain identifies clients
# by the resolved executable, so one keychain grant covers both names.
ln -sf ekubo-wallet "$BIN_DIR/ew"
CLI_BIN="$BIN_DIR/ekubo-wallet"
log "installed $("$CLI_BIN" version) to $BIN_DIR"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on PATH; add it before running ekubo-wallet" ;;
esac

# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------

# Detection and use must name the same file. `command -v` resolves through
# PATH, and resolving a second time to run what was found leaves a window in
# which the answer can change — and makes the check evidence about one file
# while the work happens on another. Each agent's path is resolved once here
# and every later reference goes through the captured value.
CODEX_BIN=$(command -v codex 2>/dev/null || :)
CLAUDE_BIN=$(command -v claude 2>/dev/null || :)
GEMINI_BIN=$(command -v gemini 2>/dev/null || :)
CURSOR_BIN=$(command -v cursor 2>/dev/null || command -v cursor-agent 2>/dev/null || :)

register_codex() {
  "$CODEX_BIN" mcp remove "$SERVER_NAME" >/dev/null 2>&1 || :
  "$CODEX_BIN" mcp add "$SERVER_NAME" -- "$CLI_BIN" server
}

register_claude() {
  "$CLAUDE_BIN" mcp remove "$SERVER_NAME" --scope user >/dev/null 2>&1 || :
  "$CLAUDE_BIN" mcp add "$SERVER_NAME" --scope user -- "$CLI_BIN" server
}

register_gemini() {
  "$GEMINI_BIN" mcp remove "$SERVER_NAME" --scope user >/dev/null 2>&1 || :
  "$GEMINI_BIN" mcp add "$SERVER_NAME" "$CLI_BIN" server --scope user
}

register_cursor() {
  "$CLI_BIN" __configure-agent cursor "$CLI_BIN" server
}

if [ "${EKUBO_WALLET_SKIP_AGENTS:-0}" != "1" ]; then
  AGENT_COUNT=0
  if [ -n "$CODEX_BIN" ]; then
    AGENT_COUNT=$((AGENT_COUNT + 1))
    if register_codex >/dev/null; then log "configured Codex"; else warn "could not configure Codex"; fi
  fi
  if [ -n "$CLAUDE_BIN" ]; then
    AGENT_COUNT=$((AGENT_COUNT + 1))
    if register_claude >/dev/null; then log "configured Claude Code at user scope"; else warn "could not configure Claude Code"; fi
  fi
  if [ -n "$GEMINI_BIN" ]; then
    AGENT_COUNT=$((AGENT_COUNT + 1))
    if register_gemini >/dev/null; then log "configured Gemini CLI at user scope"; else warn "could not configure Gemini CLI"; fi
  fi
  if [ -n "$CURSOR_BIN" ] || [ -d "$HOME/.cursor" ]; then
    AGENT_COUNT=$((AGENT_COUNT + 1))
    if register_cursor >/dev/null; then log "configured Cursor globally"; else warn "could not configure Cursor"; fi
  fi
  if [ "$AGENT_COUNT" -eq 0 ]; then
    warn "no supported agent CLI or Cursor installation was detected; the binary and completion are still installed"
  fi
fi

# ---------------------------------------------------------------------------
# Shell completion
# ---------------------------------------------------------------------------

install_completion_file() {
  completion_shell=$1
  completion_file=$2
  completion_directory=$(dirname "$completion_file")
  mkdir -p "$completion_directory"
  # `mktemp` creates the file itself and fails if the name already exists, so
  # a name guessed in advance cannot stand in for it. A redirection into a
  # predictable path would follow whatever is already there, handing the write,
  # the chmod, and the rename to a file this script never chose.
  completion_temporary=$(mktemp "$completion_directory/.ekubo-wallet.XXXXXXXX") || return 1
  if ! "$CLI_BIN" completion "$completion_shell" > "$completion_temporary"; then
    rm -f "$completion_temporary"
    return 1
  fi
  chmod 0644 "$completion_temporary"
  mv "$completion_temporary" "$completion_file"
}

install_completion_alias() {
  completion_source=$1
  completion_alias=$2
  completion_alias_directory=$(dirname "$completion_alias")
  mkdir -p "$completion_alias_directory"
  completion_alias_temporary=$(mktemp "$completion_alias_directory/.ekubo-wallet.XXXXXXXX") || return 1
  cp "$completion_source" "$completion_alias_temporary"
  chmod 0644 "$completion_alias_temporary"
  mv "$completion_alias_temporary" "$completion_alias"
}

append_once() {
  rc_file=$1
  marker=$2
  line_one=$3
  line_two=${4:-}
  if [ -f "$rc_file" ] && grep -F "$marker" "$rc_file" >/dev/null 2>&1; then
    return
  fi
  mkdir -p "$(dirname "$rc_file")"
  printf '\n%s\n%s\n' "$marker" "$line_one" >> "$rc_file"
  if [ -n "$line_two" ]; then printf '%s\n' "$line_two" >> "$rc_file"; fi
}

if [ "${EKUBO_WALLET_SKIP_COMPLETIONS:-0}" != "1" ]; then
  LOGIN_SHELL=${SHELL:-}
  COMPLETION_SHELL=${EKUBO_WALLET_SHELL:-${LOGIN_SHELL##*/}}
  case "$COMPLETION_SHELL" in
    bash)
      COMPLETION_FILE="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/ekubo-wallet"
      install_completion_file bash "$COMPLETION_FILE"
      install_completion_alias "$COMPLETION_FILE" "$(dirname "$COMPLETION_FILE")/ew"
      append_once "$HOME/.bashrc" "# ekubo-wallet completion" "[ -r $(shell_quote "$COMPLETION_FILE") ] && . $(shell_quote "$COMPLETION_FILE")"
      log "installed Bash completion"
      ;;
    zsh)
      COMPLETION_DIRECTORY="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions"
      COMPLETION_FILE="$COMPLETION_DIRECTORY/_ekubo-wallet"
      install_completion_file zsh "$COMPLETION_FILE"
      install_completion_alias "$COMPLETION_FILE" "$COMPLETION_DIRECTORY/_ew"
      ZSH_RC="${ZDOTDIR:-$HOME}/.zshrc"
      append_once "$ZSH_RC" "# ekubo-wallet completion" "fpath=($(shell_quote "$COMPLETION_DIRECTORY") \$fpath)" "autoload -Uz compinit && compinit"
      log "installed Zsh completion"
      ;;
    fish)
      COMPLETION_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/ekubo-wallet.fish"
      install_completion_file fish "$COMPLETION_FILE"
      install_completion_alias "$COMPLETION_FILE" "$(dirname "$COMPLETION_FILE")/ew.fish"
      log "installed Fish completion"
      ;;
    *)
      warn "unsupported login shell '$COMPLETION_SHELL'; run 'ekubo-wallet completion bash|zsh|fish' manually"
      ;;
  esac
fi

# The polkit action must land in a root-owned system directory, so this script
# only stages it where the user can install it with one deliberate sudo command.
#
# That staging directory is writable by the user, and the file sits in it until
# the operator gets round to running the sudo line — possibly a long time. This
# file decides how polkit authenticates the owner, so replacing it in that
# window is a way to weaken the prompt that guards signing. The staged copy is
# therefore read-only, and the printed command verifies a digest computed here
# rather than trusting whatever is at the path when it finally runs.
if [ "$OS" = Linux ] && [ -f "$SOURCE_DIRECTORY/contrib/polkit/com.ekubo.wallet.policy" ]; then
  POLKIT_STAGE="${XDG_DATA_HOME:-$HOME/.local/share}/ekubo-wallet/polkit"
  POLKIT_FILE="$POLKIT_STAGE/com.ekubo.wallet.policy"
  mkdir -p "$POLKIT_STAGE"
  install -m 0444 "$SOURCE_DIRECTORY/contrib/polkit/com.ekubo.wallet.policy" "$POLKIT_FILE"
  POLKIT_DIGEST=""
  if command -v sha256sum >/dev/null 2>&1; then
    POLKIT_DIGEST=$(sha256sum "$POLKIT_FILE" | cut -d' ' -f1)
  elif command -v shasum >/dev/null 2>&1; then
    POLKIT_DIGEST=$(shasum -a 256 "$POLKIT_FILE" | cut -d' ' -f1)
  fi
  log "owner authentication needs the polkit action installed once:"
  if [ -n "$POLKIT_DIGEST" ]; then
    log "  printf '%s  %s\\n' $(shell_quote "$POLKIT_DIGEST") $(shell_quote "$POLKIT_FILE") | sha256sum -c \\"
    log "    && sudo install -m 0644 $(shell_quote "$POLKIT_FILE") /usr/share/polkit-1/actions/"
    log "the digest is checked first so a file replaced since now cannot be installed"
  else
    log "  sudo install -m 0644 $(shell_quote "$POLKIT_FILE") /usr/share/polkit-1/actions/"
    warn "no sha256sum or shasum available, so the command above cannot verify \
the staged file; check it before running it"
  fi
fi

log "installation complete; restart active agent and shell sessions"
log "create an account with: ekubo-wallet account create primary"
