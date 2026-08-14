# Ekubo Wallet

Ekubo Wallet is a native GPUI desktop wallet for EVM accounts used by people,
local AI agents, and WalletConnect dapps. One tray-first process owns encrypted
state and private keys. The separately bundled `ekubo-wallet-mcp-bridge` speaks
stdio for local agent harnesses; the wallet application itself has no
command-line, terminal, or webview mode.

User-facing installation and usage documentation lives at
[docs.ekubo.org/wallet](https://docs.ekubo.org/wallet). This repository retains
the source, build instructions, and implementation-specific security
documentation.

## Development

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
[release process](docs/releasing.md).

## License

See [LICENSE](LICENSE).
