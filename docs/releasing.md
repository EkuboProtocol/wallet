# Releasing

Tagged CI validates formatting, tests, dependency policy, and packaged startup
on macOS, Windows, and Linux. `cargo-packager` produces DMG, per-user NSIS,
AppImage and DEB artifacts. Platform signing/notarization is mandatory for
published desktop artifacts.

The release workflow also tests, validates, and publishes the cross-platform
`ekubo-wallet.mcpb` Claude Desktop extension. Its manifest and npm package
versions must match the Rust package version before tagging. The extension has
no runtime dependency installation and contains no credential material.

Update metadata and packages are signed by a dedicated Minisign key held only
in the protected release environment. CI compiles the public key into the app,
publishes signed `latest.json`, retains platform signatures, and attaches
Sigstore provenance.

Updates require explicit confirmation after the stable version is shown.
Download completes and verifies before shutdown. The packaged macOS app,
Windows installer, and Linux AppImage update in place; DEB installations use
the release-page fallback. MCP and WalletConnect shut down gracefully
immediately before installation and relaunch.
