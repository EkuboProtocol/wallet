# Installation

Install the signed native package for the platform:

- macOS: notarized `.app` distributed in a `.dmg`.
- Windows: signed per-user NSIS installer.
- Linux: AppImage, `.deb`, or `.rpm`, including desktop entry, icons,
  StatusNotifierItem integration, and the polkit policy.

The app launches without arguments. On first agent registration it can enable
launch-at-login. A login launch stays hidden when a tray host exists; on Linux
without a tray host it retains a minimized taskbar window.

The Connections → Agents screen detects Codex, Claude Code, Gemini CLI, Cursor,
and opencode. Registration displays the exact typed configuration diff, creates
a timestamped backup, writes atomically, validates, and rolls back on failure.
Each installation can be repaired, rotated, revoked, or removed independently.
The remote Ekubo MCP entry is offered by default and remains independently
removable.

Codex entries use a Streamable HTTP `url` and static `http_headers` map. Tokens
appear only in the one-time registration diff and are not displayed again.
