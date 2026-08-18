# Ekubo Wallet

Ekubo Wallet is a native GPUI desktop wallet for EVM accounts used by people,
local AI agents, and WalletConnect dapps. One tray-first process owns encrypted
state and private keys. The separately bundled `ekubo-wallet-mcp-bridge` speaks
stdio for local agent harnesses; the wallet application itself has no
command-line, terminal, or webview mode.

> [!WARNING]
> **Windows and Linux key-storage limitation:** the current builds store raw
> account keys and the SQLCipher database key in a per-user credential service
> that does not isolate them to Ekubo Wallet. Same-user malware, including a
> prompt-injected local agent that can execute programs as the user, can extract
> those keys outside the wallet and bypass policy and native review. Read the
> [platform threat-model section](docs/threat-model.md#critical-windows-and-linux-credential-store-limitation)
> before using either build with valuable accounts.

User-facing installation and usage documentation lives at
[docs.ekubo.org/wallet](https://docs.ekubo.org/wallet). This repository retains
the source, build instructions, and implementation-specific security
documentation.

## Development

The workspace requires Rust 1.94.1 or newer.

```text
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

GPUI is pinned to Zed revision
`cc053a4a6fa2fd0e8793201ed9099466af1be0b1`; `gpui-component` is pinned to
`26cc9366abb27ccedce386ac99a615a8fa7018da`. The application consumes only the
Apache-2.0 GPUI infrastructure, not Zed's GPL workspace/UI crates.

See [architecture](docs/architecture.md), the system-wide
[threat model](docs/threat-model.md), the code-oriented
[security boundary](docs/security-boundary.md), and the
[release process](docs/releasing.md). The enforced policy vocabulary—including
flat prepared-envelope matchers and the `review` effect—is documented in
[policy authoring](docs/policy-authoring.md).

## License

See [LICENSE](LICENSE).
