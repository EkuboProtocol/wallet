# Releasing

The normal `main` workflow owns formatting, tests, Clippy, dependency notices,
and target-filtered OSV-Scanner gates for both known vulnerabilities and the
SPDX license allowlist on every shipped platform. Explicit informational
advisory exceptions live in `osv-scanner.toml` with reasons and expiry dates.
Release packaging is a deliberate two-stage process; neither stage executes
code with signing credentials.

First, manually run **Build unsigned release artifacts** with any branch, tag,
or exact commit SHA. The workflow resolves that reference and computes the
build identity itself: an exact `v<package-version>` tag produces that package
version, while any other reference produces `<package-version>+<short-sha>`.
Its macOS, Windows, and Linux jobs have only repository read permission,
receive no secret or OIDC token, and build the resolved commit. Each artifact
set includes a manifest binding the requested reference, computed version,
commit, platform, filename, byte count, and SHA-256 digest. The embedded updater
verification key is a public repository variable. Each platform restores and
saves its own release-mode Rust cache; failed builds never populate it.

Second, manually run **Sign and publish release** with that exact build run ID
and the existing `v<computed-version>` tag. The protected release environment
verifies the run used the trusted workflow on `main`, succeeded, produced three
mutually consistent manifests whose bytes still hash exactly, and resolved the
tag to the manifested commit. Only after that check do isolated trusted jobs
receive Apple, Azure, or Minisign credentials. The publishing job creates the
release at the verified commit SHA and uploads only the strict native-asset
allowlist. No trusted job checks out or executes build-run source.

When the protected `AZURE_TRUSTED_SIGNING_ENABLED` environment variable is
`true`, Windows signing exchanges GitHub's short-lived OIDC token with Azure
through the pinned Azure Login action. Trusted Signing is restricted to that
Azure CLI credential; interactive, cached, developer-tool, workload,
environment, and managed-identity fallbacks are disabled. When it is `false`,
the workflow skips Azure, proves the installer remains Authenticode-unsigned,
and still applies the mandatory detached updater signature before publication.

The Azure app registration must trust exactly the immutable GitHub subject
`repo:EkuboProtocol@135474885/wallet@1322111549:environment:release` with issuer
`https://token.actions.githubusercontent.com` and audience
`api://AzureADTokenExchange`. Its service principal has the **Artifact Signing
Certificate Profile Signer** role scoped only to the `ekubo` signing account.
The protected `AZURE_TRUSTED_SIGNING_PROFILE` secret names the
`ekubo-release` public-trust profile.

For the initial activation, wait until the identity validation is **Completed**
in the Azure portal, copy its identity validation ID, and create the reserved
profile:

```sh
az artifact-signing certificate-profile create \
  --resource-group ekubo-signing \
  --account-name ekubo \
  --name ekubo-release \
  --profile-type PublicTrust \
  --identity-validation-id '<completed-identity-validation-id>'
```

Until that profile exists, keep `AZURE_TRUSTED_SIGNING_ENABLED` set to `false`.
Releases then carry an intentionally Authenticode-unsigned Windows installer,
which can display an Unknown publisher or SmartScreen warning, while retaining
the same signed updater metadata, artifact digest, and detached updater
signature checks. Set the variable to `true` only after the profile exists; a
missing or unusable profile then fails closed. No client secret is required or
permitted for the GitHub release identity.

`cargo-packager` produces the unsigned macOS app, per-user NSIS installer,
AppImage, and DEB on native runners. The trusted stage signs the macOS app,
creates the distributed DMG and updater tar, applies Authenticode to Windows
when enabled, and Minisign-signs final updater artifacts and `latest.json`.
The macOS job waits for notarization acceptance and staples the distributed
DMG before its final updater signature is created. Missing Apple or updater
signing configuration fails the protected stage; missing Azure configuration
also fails it whenever Authenticode is enabled.

Packaging verifies that every native package contains a runnable
`ekubo-wallet-mcp-bridge` that initializes over stdio, reports the computed
build version, advertises dynamic tool refresh, and returns the deterministic
offline tool catalog. The helper itself is not an authorization boundary. The
retired Claude Desktop plugin archive is not built or published.

Before release, smoke-test a bridge launched by each supported harness (Codex,
Claude Code, Claude Desktop, Gemini CLI, Cursor, OpenCode, and Grok Build). Start the
harness while the wallet is closed, then open, close, and reopen the wallet.
The harness must observe `notifications/tools/list_changed` and resume tool
calls after both connections without restarting its own process. A harness
release that no longer supports dynamic tool refresh blocks the wallet release.
Also connect a packaged bridge to a test server that reports a different build
version during MCP initialization. The bridge must exit unsuccessfully after
that one attempt, print both versions to stderr, and never enter its reconnect
loop.

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
