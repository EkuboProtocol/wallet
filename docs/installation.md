# Installation

Every release attaches prebuilt archives for Linux (x86-64, arm64), macOS
(Intel, Apple Silicon), and Windows (x86-64), plus `SHA256SUMS`, keyless
Sigstore bundles, and GitHub build-provenance attestations.

The installer downloads the archive for your platform, **verifies the Sigstore
signature over `SHA256SUMS` and the archive's SHA-256 checksum against it
before extracting anything**, installs
`ekubo-wallet` and `ew`, registers the server with every agent CLI it detects
(Codex, Claude Code, Gemini CLI, and Cursor), and installs completion for your
login shell:

```sh
curl -fsSL https://raw.githubusercontent.com/EkuboProtocol/wallet-mcp-server/main/install.sh | sh
```

Read [`install.sh`](../install.sh) before piping it to a shell. Replace `main` with
an exact release tag for a reproducible installation.

`cosign` is required. The checksum file travels the same path as the archive it
describes, from the same host, so whoever can substitute one can substitute both
and the comparison still passes — it catches a truncated download, not a chosen
one. The signature is the part that names a builder. If `cosign` is missing the
installer stops and says so; install it from
[the Sigstore docs](https://docs.sigstore.dev/cosign/installation/), or set
`EKUBO_WALLET_ALLOW_UNSIGNED=1` to proceed on the checksum alone and accept what
that does not prove.

While the repository is private, the installer needs credentials to reach the
release assets. It uses the GitHub CLI when you are logged in (`gh auth login`),
and otherwise honors `GITHUB_TOKEN`.

Useful environment variables:

| Variable | Effect |
| --- | --- |
| `EKUBO_WALLET_VERSION` | Install an exact version instead of the latest release. |
| `EKUBO_WALLET_BIN_DIR` | Install destination. Defaults to `~/.local/bin`. |
| `EKUBO_WALLET_SKIP_AGENTS=1` | Install the binary without touching agent configuration. |
| `EKUBO_WALLET_SKIP_COMPLETIONS=1` | Install the binary without touching shell configuration. |
| `EKUBO_WALLET_SHELL` | Override login-shell detection for completion (`bash`, `zsh`, or `fish`). |

## Manual installation

Download the archive for your platform from the
[releases page](https://github.com/EkuboProtocol/wallet-mcp-server/releases),
verify it, and put the executables on `PATH`:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify ekubo-wallet-<version>-<target>.tar.gz \
  --repo EkuboProtocol/wallet-mcp-server
tar -xzf ekubo-wallet-<version>-<target>.tar.gz
install -m 0755 ekubo-wallet-<version>-<target>/ekubo-wallet ~/.local/bin/
ln -sf ekubo-wallet ~/.local/bin/ew
```

macOS archives are `.zip` rather than `.tar.gz`. If a release is published
without Apple signing — its notes say so explicitly — Gatekeeper blocks the
first run until you verify the download and then clear the quarantine
attribute with `xattr -d com.apple.quarantine ./ekubo-wallet`.

See [the release guide](releasing.md#verify-a-download) for the complete
verification commands.

## Register the MCP server manually

The installer is optional. Any MCP client can launch the installed binary:

```json
{
  "mcpServers": {
    "ekubo-wallet": {
      "command": "ekubo-wallet",
      "args": ["server"]
    }
  }
}
```

Use an absolute path, such as `/home/you/.local/bin/ekubo-wallet`, if the agent
does not inherit your login shell's `PATH`. Confirm the installed build with
`ekubo-wallet version`.

Do not ask an agent to clone this repository or run the human CLI on your
behalf.

Codex may separately ask whether it may invoke `wallet_send_execution_plan`,
because that tool truthfully advertises that its broadcast phase can cause an
irreversible on-chain transaction. That client permission is independent of the
wallet's own simulation, policy, and human-approval gates. For a trusted local
installation, choose **Always allow**, or pre-approve only that one tool in
`~/.codex/config.toml`:

```toml
[mcp_servers.ekubo-wallet.tools.wallet_send_execution_plan]
approval_mode = "approve"
```

That suppresses the duplicate prompt without weakening anything: the MCP process
still cannot sign a plan that policy rejects, and for an exceptional plan it can
only broadcast bytes already reviewed and signed through the separate CLI. Keep
the tool's `destructiveHint` accurate rather than relabeling an on-chain
broadcast as harmless.
