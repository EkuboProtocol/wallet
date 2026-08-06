# Development

The repository tracks Rust `stable`. CI verifies Linux, macOS, and Windows.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo build --locked --release
```

The ignored live tests require an RPC that supports `eth_simulateV1`:

```sh
cargo test --locked --all-features live_ -- --ignored --nocapture
```

`tests/live_networks.rs` is a live matrix that exercises reads, simulation, and
simulation forks against every default network's real RPC. It is skipped unless
`EKUBO_WALLET_LIVE_RPC_TESTS=1` is set, and each chain's endpoint can be
overridden with `EKUBO_WALLET_LIVE_RPC_<chain-id>`:

```sh
EKUBO_WALLET_LIVE_RPC_TESTS=1 cargo test --locked --all-features \
  --test live_networks -- --nocapture
```

To build and install your local checkout — same agent registration and shell
completions as a release install, no download or signature verification, since
you are trusting your own working tree:

```sh
./install-local.sh
```

(a shorthand for `EKUBO_WALLET_LOCAL_SOURCE=. sh install.sh`; every other
installer environment variable still applies)

Or point an MCP client directly at `target/release/ekubo-wallet server`. Regenerate the committed policy schema
with `cargo run --bin ekubo-wallet -- policy schema > schemas/policy.schema.json`;
a test fails if it is stale.

Releases are cut by pushing a `v<version>` tag matching `Cargo.toml`. See
[the release guide](releasing.md).
