# Releasing

Tagged CI validates formatting, tests, dependency policy, and packaged startup
on macOS, Windows, and Linux. `cargo-packager` produces DMG, per-user NSIS,
AppImage and DEB artifacts. Platform signing/notarization is mandatory for
published desktop artifacts.

The release workflow also tests, validates, and publishes the cross-platform
`ekubo-wallet.mcpb` Claude Desktop extension. The extension has no runtime
dependency installation and contains no credential material.

Its manifest, npm package, and lockfile repeat the wallet's version. The
bundle's own test suite holds all of them to the root `Cargo.toml`, and
`contrib/sync-claude-desktop-version.py` is what rewrites them: bump the
version in `Cargo.toml`, run the script, and commit what it changed. Tagging
additionally requires the tag to name that same version, so `v1.0.0-rc.7` will
not publish a wallet that calls itself anything else.

Update metadata and packages are signed by a dedicated Minisign key held only
in the protected release environment. CI compiles the public key into the app,
publishes signed `latest.json`, retains platform signatures, and attaches
Sigstore provenance.

Updates require explicit confirmation after the stable version is shown.
Download completes and verifies before shutdown. The packaged macOS app,
Windows installer, and Linux AppImage update in place; DEB installations use
the release-page fallback. MCP and WalletConnect shut down gracefully
immediately before installation and relaunch.
