# Releasing

The normal `main` workflow owns formatting, tests, Clippy, dependency notices,
and the RustSec audit. A release tag starts the separate packaging workflow; it
does not repeat those checks. `cargo-packager` produces DMG, per-user NSIS,
AppImage, and DEB artifacts on their native runners.

The protected release environment requires the update-signing key on every
platform and Apple signing/notarization credentials on macOS. The macOS runner
signs the app and DMG, submits the exact DMG that the release distributes to
Apple's notary service, records the submission ID in the job summary, and exits
as soon as the upload succeeds. It does not spend runner time waiting for
Apple's verdict. Consequently, a successful release job means that the upload
completed and Apple returned a submission ID, not that notarization was
accepted. Once Apple accepts the DMG, it publishes tickets for the disk image
and its nested app. Gatekeeper can retrieve those tickets online, including for
a copy downloaded while notarization was still pending; because the release
artifacts are not stapled, their first launch requires network access.

Developer ID signing on macOS and Authenticode signing on Windows are mandatory.
Linux packages contain the exact helper protected by the embedded SHA-256 and
the release's Minisign chain. Packaging fails unless every native package
contains an executable `ekubo-wallet-mcp-bridge`; the macOS and Windows checks
also verify the helper's platform signature after extracting it from the
package. The retired Claude Desktop plugin archive is not built or published.

Before tagging, smoke-test a bridge launched by each supported harness (Codex,
Claude Code, Claude Desktop, Gemini CLI, Cursor, and OpenCode). Start the
harness while the wallet is closed, then open, close, and reopen the wallet.
The harness must observe `notifications/tools/list_changed` and resume tool
calls after both connections without restarting its own process. A harness
release that no longer supports dynamic tool refresh blocks the wallet release.

Native update artifacts are signed by a dedicated Minisign key held only in the
protected release environment. CI compiles the public key into the app,
publishes a signed `latest.json` binding version, target, format, canonical
artifact URL, SHA-256 digest, and detached artifact signature, verifies the
final platform-signed artifacts, and attaches Sigstore provenance. The updater
also reads the package version back from the bundled application binary (or the
NSIS ProductVersion) and requires it to equal the authenticated manifest
version before installation.

Updates require explicit confirmation after the stable version is shown.
Download completes and verifies before shutdown. The packaged macOS app,
Windows installer, and Linux AppImage update in place; DEB installations use
the release-page fallback. MCP and WalletConnect shut down gracefully
immediately before installation and relaunch.
