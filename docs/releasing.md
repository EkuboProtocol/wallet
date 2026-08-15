# Releasing

The normal `main` workflow owns formatting, tests, Clippy, dependency notices,
and target-filtered OSV-Scanner gates for both known vulnerabilities and the
SPDX license allowlist on every shipped platform. Explicit informational
advisory exceptions live in `osv-scanner.toml` with reasons and expiry dates.
Release packaging is a deliberate two-stage process; neither stage executes a
release tag.

First, manually run **Build unsigned release artifacts** with a release tag and
the exact 40-character commit SHA that passed CI. Its macOS, Windows, and Linux
jobs have only repository read permission, receive no secret or OIDC token,
and build that SHA. Each artifact set includes a manifest binding the tag,
commit, platform, filename, byte count, and SHA-256 digest. The embedded updater
verification key is a public repository variable.

Second, manually run **Sign and publish release** with that exact build run ID
and tag. The protected release environment verifies the run came from the
unsigned-build workflow, succeeded, and produced three mutually consistent
manifests whose bytes still hash exactly. Only after that check do isolated
trusted jobs receive Apple, Azure, or Minisign credentials. The publishing job
creates the release at the verified commit SHA and uploads only the strict
native-asset allowlist. No trusted job checks out or executes build-run source.

`cargo-packager` produces the unsigned macOS app, per-user NSIS installer,
AppImage, and DEB on native runners. The trusted stage signs the macOS app,
creates the distributed DMG and updater tar, applies mandatory Authenticode to
Windows, and Minisign-signs final updater artifacts and `latest.json`. The
macOS job waits for notarization acceptance and staples the distributed DMG
before its final updater signature is created. Missing Apple, Azure, or update
signing configuration fails the protected stage.

Packaging verifies that every native package contains a runnable
`ekubo-wallet-mcp-bridge` that initializes over stdio, reports the tagged
version, advertises dynamic tool refresh, and returns the deterministic offline
tool catalog. The helper itself is not an authorization boundary. The retired
Claude Desktop plugin archive is not built or published.

Before release, smoke-test a bridge launched by each supported harness (Codex,
Claude Code, Claude Desktop, Gemini CLI, Cursor, OpenCode, and Grok Build). Start the
harness while the wallet is closed, then open, close, and reopen the wallet.
The harness must observe `notifications/tools/list_changed` and resume tool
calls after both connections without restarting its own process. A harness
release that no longer supports dynamic tool refresh blocks the wallet release.

Native update artifacts are signed by a dedicated Minisign key held only in the
protected release environment. The trusted workflow publishes a signed
`latest.json` binding version, target, format, canonical artifact URL, SHA-256
digest, and detached artifact signature. The updater also reads the package
version back from the bundled application binary (or NSIS ProductVersion) and
requires it to equal the authenticated manifest version before installation.

Updates require explicit confirmation after the stable version is shown.
Download completes and verifies before shutdown. The packaged macOS app,
Windows installer, and Linux AppImage update in place; DEB installations use
the release-page fallback. MCP and WalletConnect shut down gracefully
immediately before installation and relaunch.
