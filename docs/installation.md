# Installation

Install the signed native package for the platform:

- macOS: notarized `.app` distributed in a `.dmg`.
- Windows: signed per-user NSIS installer.
- Linux: AppImage, `.deb`, or `.rpm`, including desktop entry, icons,
  StatusNotifierItem integration, and the polkit policy.

The app launches without arguments. On startup it detects supported agents and
upserts an authenticated `ekubo-wallet` MCP entry for each one. The first
successful installation enables launch-at-login. A login launch stays hidden
when a tray host exists; on Linux without a tray host it retains a minimized
taskbar window.

Settings detects Codex, Claude Code, Gemini CLI, Cursor,
and opencode. Automatic installation uses the typed configuration adapter for
that agent, creates a timestamped backup before changing an existing file,
writes atomically, validates, and rolls back on failure. Settings and the tray
both provide **Reinstall MCP Server**, which upserts every detected agent again;
Settings also retains per-agent repair, token rotation, revocation, and removal.
The remote Ekubo MCP entry is installed by default and remains independently
removable.

Codex entries use a Streamable HTTP `url` and static `http_headers` map. Tokens
are written directly into the agent configuration and are never displayed
again after installation.

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
`package.metadata.packager` in `Cargo.toml`; `build.rs` deterministically
generates the checked design at `target/packager-assets/icon-512.png`.
