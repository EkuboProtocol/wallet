# Installation

Install the signed native package for the platform:

- macOS: notarized `.app` distributed in a `.dmg`.
- Windows: signed per-user NSIS installer.
- Linux: AppImage, `.deb`, or `.rpm`, including desktop entry, icons,
  StatusNotifierItem integration, and the polkit policy.

The app launches without arguments. On first agent registration it can enable
launch-at-login. A login launch stays hidden when a tray host exists; on Linux
without a tray host it retains a minimized taskbar window.

Settings detects Codex, Claude Code, Gemini CLI, Cursor,
and opencode. Registration displays the exact typed configuration diff, creates
a timestamped backup, writes atomically, validates, and rolls back on failure.
Each installation can be repaired, rotated, revoked, or removed independently.
The remote Ekubo MCP entry is offered by default and remains independently
removable.

Codex entries use a Streamable HTTP `url` and static `http_headers` map. Tokens
appear only in the one-time registration diff and are not displayed again.

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
