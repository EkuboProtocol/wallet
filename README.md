# Ekubo Wallet 2

Ekubo Wallet is a native GPUI desktop wallet for EVM accounts used by people,
local AI agents, and WalletConnect dapps. Linux and Windows v2 separate the
desktop from protected service custody. The `ekubo-wallet-v2-mcp-bridge`
speaks stdio for local agents. macOS retains its platform custody backend.

Windows owner authorization uses an isolated native Hello collector controlled
by a protected broker; no desktop-provided approval boolean is accepted. Windows
requires the HWND consent API available on Windows 11 (build 22000 or later) and
configured Windows Hello. See the current [service-isolation status](docs/service-isolation.md)
for native acceptance and release validation.

V2 uses separate application, data, helper and update-channel identities so
released 1.x remains independently runnable. An explicit first-run move retires
the selected old profile after verified credential cleanup; shared credentials and recovery
limits are documented in the service-isolation status. Fresh setup never moves
1.x state automatically. Released 1.x retains the
[credential-store limitation](docs/threat-model.md#critical-windows-and-linux-credential-store-limitation).

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
`52b2927a1bac46be5d50ad341ac00b665e13764b`; `gpui-component` is pinned to
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
