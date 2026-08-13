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

Windows Authenticode signing is applied only when its trusted-signing
configuration is available; the workflow currently permits an otherwise
update-signed Windows installer when it is not.

The release workflow also tests, validates, and publishes the cross-platform
`ekubo-wallet-plugin.zip` Claude Desktop plugin. The plugin has no runtime
dependency installation and contains no credential material. The obsolete
MCPB format is not published because current Claude Desktop versions do not
import it.

Its manifest, npm package, and lockfile repeat the wallet's version. The
plugin's own test suite holds all of them to the root `Cargo.toml`, and
`contrib/sync-claude-desktop-version.py` is what rewrites them: bump the
version in `Cargo.toml`, run the script, and commit what it changed. Tagging
additionally requires the tag and manifest to name the same version.

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
