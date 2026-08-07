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

## Vendored data

Two data sets are compiled into the binary rather than fetched: the
clear-signing registry under `crates/ekubo-wallet-core/clearsign/`, and the
curated default token list at `crates/ekubo-wallet-core/default-tokens.json`.
Both decide what a reviewer reads before signing, so both are committed and
reviewable in a diff instead of being downloaded during the build.

Refresh the token list — the only step that reaches the network — with:

```sh
contrib/vendor-default-tokens.py          # rewrite the vendored snapshot
contrib/vendor-default-tokens.py --check  # fail if it is stale
```

It reads `tokens.json` — the complete generated document, ~17,000 EVM rows —
rather than the ~170-row hand-maintained `curated-tokens.json` seed; pass
`--url` to vendor the curated file instead. It drops logo URLs and interface
ranking hints the wallet cannot use, drops non-EVM rows, and renames fields to
the ones `parse_token_list` already accepts, so the embedded list is read by
the same parser as a list imported by hand, differing only in its size limits
(an import is capped at what one person can verify in a review screen; the
vendored list is not reviewed at run time at all).

The diff is too large to read row by row, so what to check on a refresh is the
`source_url` and `source_sha256` the snapshot records, and the row count.

Releases are cut by pushing a `v<version>` tag matching `Cargo.toml`. See
[the release guide](releasing.md).
