# Releasing

Tagged CI validates formatting, tests, dependency policy, and packaged startup
on macOS, Windows, and Linux. `cargo-packager` produces DMG, per-user NSIS,
AppImage, DEB, and RPM artifacts. Platform signing/notarization is mandatory for
published desktop artifacts.

Update metadata and packages are signed by a dedicated Minisign key held only
in the protected release environment. CI compiles the public key into the app,
publishes signed `latest.json`, retains platform signatures, and attaches
Sigstore provenance.

Updates require explicit confirmation after version and notes are shown.
Download completes and verifies before shutdown. AppImage uses verified
replacement; DEB/RPM launches the native package-install flow. MCP and
WalletConnect shut down gracefully immediately before installation and relaunch.
