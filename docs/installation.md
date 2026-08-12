# Installation

Install the signed native package for the platform:

- macOS: notarized `.app` distributed in a `.dmg`.
- Windows: signed per-user NSIS installer.
- Linux: AppImage or `.deb`, including desktop entry, icons,
  StatusNotifierItem integration, and the polkit policy.

The app launches without arguments. On startup it detects supported agents and
upserts a credential-free `ekubo-wallet` MCP entry for each one. This never
opens an authentication prompt. A login launch stays hidden
when a tray host exists; on Linux without a tray host it retains a minimized
taskbar window.

Settings detects Codex, Claude Code, Gemini CLI, Cursor,
and opencode. Automatic installation uses the typed configuration adapter for
that agent, creates a timestamped backup before changing an existing file,
writes atomically, validates, and rolls back on failure. Settings and the tray
both provide **Reinstall MCP Server**, which upserts every detected agent again;
Settings also retains per-agent repair, OAuth access revocation, and removal.
The remote Ekubo MCP entry is installed by default and remains independently
removable.

The local server advertises `wallet://skills/use-ekubo-wallet/SKILL.md` and
includes its trigger guidance in the MCP handshake: agents are told to discover
Ekubo Wallet for onchain EVM work and when “wallet” may mean a crypto wallet.
No separate agent skill file is installed or maintained on disk.

Codex entries use the fixed Streamable HTTP `url` and `auth = "oauth"`; no
static header, bearer token, refresh token, or client secret is written to any
managed configuration. The user starts authentication from the harness (for
Codex, **Authenticate** or `codex mcp login ekubo-wallet`). Ekubo Wallet must be
running. Its local consent page offers one-day, one-week, and one-month session
lifetimes, then requires operating-system human presence before access is
granted. Access tokens last 10 minutes and refresh rotation cannot extend the
selected absolute expiry. The harness is responsible for its OAuth credential
storage.

After the first agent authorization, the app installs a current-user
launch-at-login entry. Login startup stays hidden when the native tray is
available. If Linux has no StatusNotifierItem host, the compact wallet window
opens instead so the service cannot become inaccessible.

## Running locally on macOS

`cargo run --release` runs an unbundled Unix executable. macOS can show its
window and tray item, but it has no application bundle metadata from which to
load a Dock icon. To exercise the real bundle and its generated icon locally:

```sh
cargo install cargo-packager --locked
cargo packager --release --formats app
open "target/release/bundle/macos/Ekubo Wallet.app"
```

The packaged app gets its Dock icon from the `icons` entry under
`package.metadata.packager` in `Cargo.toml`. The editable source is
`assets/app-icon.svg`; `assets/app-icon-512.png` is its checked raster export
for packagers that do not accept SVG application icons.
