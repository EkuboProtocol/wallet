# Signed release setup

GitHub Releases are the canonical prebuilt-binary channel. A `v<version>` tag
whose version matches `Cargo.toml` starts `.github/workflows/release.yml`. The
workflow builds on native GitHub-hosted runners, signs macOS and Windows in the
protected `release` environment, emits checksums, creates keyless Sigstore
bundles and GitHub build-provenance attestations, and publishes all files in one
GitHub Release.

Each archive contains `ekubo-wallet`, its `ew` alias, the README, license, shell
completions, the policy JSON Schema, and the policy/decoding examples. Linux
archives also contain the polkit action required for owner-authenticated
operations. The workflow source is release-ready; the
repository/environment configuration and signing values below are the
remaining operator inputs.

## Platform signing is optional, and its absence is stated in the release

Checksums, keyless Sigstore bundles, and GitHub build-provenance attestations
are unconditional: every release has them, and the workflow fails rather than
publishing without them.

Apple and Azure platform code signing is detected per platform:

- With a **complete** credential set, the platform binaries are signed (and, on
  macOS, notarized). Verification failure fails the release.
- With **no** credential for a platform, that platform is packaged unsigned, a
  workflow warning is emitted, and the generated release notes say plainly that
  the archive is unsigned and that Gatekeeper or SmartScreen will object.
- With a **partial** credential set, the release fails. A half-configured
  signing setup is an operator error, not a reason to silently downgrade.

Sign before distributing to anyone outside the team. An unsigned release is
appropriate for internal testing, where the recipient verifies the checksum and
Sigstore bundle instead.

The workflow deliberately does not publish to crates.io. A crates.io package is
a public source archive, not a binary distribution, and publishing there would
be inconsistent with keeping this code all-rights-reserved. If Ekubo later
chooses public source distribution, crates.io trusted publishing should be
added as a separate protected job after the required first manual publication.

## Accounts and one-time configuration

### GitHub

1. Create or use the Ekubo GitHub organization and create the repository at
   `EkuboProtocol/secure-wallet-mcp-server` (or update `Cargo.toml` and documentation
   if the final owner differs).
2. Enable GitHub Actions. Artifact attestations work for public repositories;
   private-repository attestations require GitHub Enterprise Cloud.
3. Create an environment named `release`. Restrict deployment tags to `v*`, add
   required reviewers, prevent self-review, and disable administrator bypass.
4. Protect `main`, require the `CI` checks, require pull-request review, and
   prevent force pushes and deletion. Add a tag ruleset for `v*` that restricts
   creation and prevents updates/deletion.
5. Enable **Settings → General → Releases → Immutable releases**. The release
   command uploads assets while the release is a draft and publishes only after
   every upload succeeds; immutability then binds the tag and assets.
6. Store the Apple and Azure values below on the `release` environment, not as
   unprotected repository-level values.

The workflow pins every third-party action to a full commit SHA. Dependabot
should be enabled for GitHub Actions so those pins receive reviewed updates.

### Apple Developer

An Apple Developer Program organization membership for **Ekubo, Inc.** is
required for software distributed outside the Mac App Store.

1. Have the Account Holder create a **Developer ID Application** certificate.
   Export the certificate and private key as a password-protected `.p12` file.
2. Have an Account Holder or Admin enable App Store Connect API access and
   create a **team** API key usable by `notarytool`. An individual API key does
   not support `notarytool`. Download the `.p8` file immediately; Apple permits
   it to be downloaded only once.
3. Add these `release` environment secrets:

   - `APPLE_CODESIGN_IDENTITY`: the complete Developer ID Application identity,
     including the team ID.
   - `APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64`: base64 of the `.p12` bytes.
   - `APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD`: the export password.
   - `APPLE_NOTARY_API_KEY_P8_BASE64`: base64 of the team API `.p8` bytes.
   - `APPLE_NOTARY_KEY_ID`: the App Store Connect key ID.
   - `APPLE_NOTARY_ISSUER_ID`: the App Store Connect issuer UUID.

The workflow uses hardened-runtime signing, a secure timestamp, and
`xcrun notarytool --wait`. It fails closed if signing or notarization fails.

### Microsoft Azure Artifact Signing

Create an Azure account/subscription and Microsoft Entra tenant for Ekubo. Azure
Artifact Signing (formerly Trusted Signing) is Microsoft's managed and
recommended public-trust code-signing path for Win32 software.

1. Register the `Microsoft.CodeSigning` resource provider, create an Artifact
   Signing account, complete **public** organization identity validation for
   Ekubo, Inc., and create a **Public Trust** certificate profile. Availability
   and identity-validation countries are limited; check Microsoft's current
   supported-region list before opening the account.
2. Create a dedicated Microsoft Entra application/service principal for this
   release workflow. Do not create a client secret.
3. Add a federated credential for GitHub Actions with entity type
   **Environment**, repository `EkuboProtocol/secure-wallet-mcp-server`, and
   environment `release`. Its subject is
   `repo:EkuboProtocol/secure-wallet-mcp-server:environment:release`.
4. Assign only **Artifact Signing Certificate Profile Signer** to that service
   principal, scoped to the one certificate profile.
5. Add these `release` environment secrets:

   - `AZURE_CLIENT_ID`
   - `AZURE_TENANT_ID`
   - `AZURE_SUBSCRIPTION_ID`

6. Add these `release` environment variables:

   - `AZURE_ARTIFACT_SIGNING_ENDPOINT`, for example
     `https://eus.codesigning.azure.net/`
   - `AZURE_ARTIFACT_SIGNING_ACCOUNT`
   - `AZURE_ARTIFACT_SIGNING_PROFILE`

The private signing key remains in Microsoft's service. GitHub exchanges its
OIDC identity for a short-lived Azure credential, so there is no Azure password
or certificate in GitHub.

## Release procedure

1. Update `Cargo.toml`, commit through a reviewed pull request, and wait for CI.
2. Create an annotated tag named exactly `v<version>` on the reviewed `main`
   commit and push it.
3. Review and approve the jobs waiting on the `release` environment only after
   checking the tag, commit, and workflow diff.
4. Wait for `Release signed binaries` to complete. Do not upload replacement
   assets manually.
5. Verify the release is shown as immutable and independently verify at least
   one asset using the commands below.

Linux users must install the packaged polkit action before policy exceptions,
policy/network changes, key export, or wallet removal can authenticate:

```sh
sudo install -m 0644 contrib/polkit/com.ekubo.wallet.policy \
  /usr/share/polkit-1/actions/com.ekubo.wallet.policy
```

## Verify a download

First verify the checksum from the release directory:

```sh
sha256sum --check SHA256SUMS
```

Verify the GitHub provenance (replace the owner if the final repository differs):

```sh
gh attestation verify ekubo-wallet-<version>-<target>.<archive> \
  --repo EkuboProtocol/secure-wallet-mcp-server
```

Verify its keyless Sigstore signature with the adjacent `.sigstore.json` file:

```sh
cosign verify-blob \
  --bundle ekubo-wallet-<version>-<target>.<archive>.sigstore.json \
  --certificate-identity-regexp \
  '^https://github.com/EkuboProtocol/secure-wallet-mcp-server/.github/workflows/release.yml@refs/tags/v[0-9]' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ekubo-wallet-<version>-<target>.<archive>
```

On macOS, `codesign -dv --verbose=4 ekubo-wallet` shows the Developer ID and
`spctl --assess --type execute --verbose=4 ekubo-wallet` asks Gatekeeper to
assess it. On Windows, inspect the executable's **Digital Signatures** tab or
run `Get-AuthenticodeSignature .\ekubo-wallet.exe` in PowerShell.

Those two commands fail for an unsigned release, which is expected and is stated
in that release's notes. Do not clear the macOS quarantine attribute or dismiss
the SmartScreen warning until the checksum and Sigstore bundle above verify.

`install.sh` performs the same verification automatically: it refuses to install
without a matching `SHA256SUMS` entry and, when `cosign` is present, refuses to
install unless the Sigstore bundle over `SHA256SUMS` verifies against this
workflow's identity at the release tag.

Supply-chain signatures prove which reviewed workflow produced a binary; they
do not make a compromised source tree safe. Keep the release environment,
branch/tag rules, action-SHA updates, and reviewer separation in place.
