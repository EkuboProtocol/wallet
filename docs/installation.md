# Installation

Install the signed native package for the platform:

- macOS: notarized `.app` distributed in a `.dmg`.
- Windows: signed per-user NSIS installer.
- Linux: AppImage or `.deb`, including desktop entry, icons,
  StatusNotifierItem integration, and the polkit policy.

The app launches without arguments. On startup it detects supported agents and
upserts a credential-free `ekubo_wallet` MCP entry for each one. The key is
spelled with an underscore because harnesses derive the tool names the model
sees from it, and Codex rewrites `-` to `_` when it does; a hyphenated key
therefore reaches the model under a name its own `resources/list` does not
accept. This never
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

Claude Desktop is distinct from Claude Code and does not read `~/.claude.json`
for local HTTP servers. Install the `ekubo-wallet.mcpb` asset published with
the wallet release from **Settings → Extensions → Advanced settings → Install
Extension**. The extension is a dependency-free JavaScript adapter launched by
Claude Desktop's bundled Node.js runtime. It exposes stdio to Claude and
forwards messages only to the fixed `http://127.0.0.1:61744/mcp` endpoint.

The Claude Desktop adapter performs OAuth dynamic client registration and PKCE
against the running wallet. It retains access and refresh credentials only in
process memory: it never writes them to the extension, an agent configuration
file, or disk. Restarting Claude Desktop can therefore require owner
authorization again. The wallet must be running before Claude uses its tools.

The local server advertises `wallet://skills/use-ekubo-wallet/SKILL.md` and
includes its trigger guidance in the MCP handshake: agents are told to discover
Ekubo Wallet for onchain EVM work and when “wallet” may mean a crypto wallet.
No separate agent skill file is installed or maintained on disk.

Codex entries use the fixed Streamable HTTP `url` and `auth = "oauth"`; no
static header, bearer token, refresh token, or client secret is written to any
managed configuration. The user starts authentication from the harness (for
Codex, **Authenticate** or `codex mcp login ekubo_wallet`). Ekubo Wallet must be
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

## Building the Claude Desktop extension

The same cross-platform MCP Bundle is published for macOS, Windows, and Linux:

```sh
cd integrations/claude-desktop
npm ci
npm test
npm run validate
npm run pack
```

The output is `integrations/claude-desktop/dist/ekubo-wallet.mcpb`.
