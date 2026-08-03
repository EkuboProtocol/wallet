# Secure Wallet MCP Server

`ekubo-wallet` is a local EVM wallet, command-line tool, and stdio MCP server
designed so that transaction policy is enforced inside the same process that
holds the signing key.

> [!IMPORTANT]
> This repository is an active Rust rewrite and is not ready for production.
> Key custody and the initial CLI are implemented, but the MCP, policy,
> simulation, signing, and broadcast paths are still being completed.

## Security model

- MCP clients can request structured actions; they cannot request arbitrary
  hash or transaction signatures.
- Newly generated keys go directly into the operating system credential store.
- Raw-key export remains available for recovery, but requires an interactive
  terminal, an exact confirmation phrase, and platform human-presence approval.
- Export is recorded as an irreversible custody-state transition. After export,
  the application no longer claims that its policy is the exclusive signing
  path for that address.
- Imported wallets are likewise marked as externally known.

See [the architecture](docs/architecture.md) for the trust boundaries and
[the release guide](docs/releasing.md) for CI, native code signing,
notarization, provenance, and required account configuration.

## Development

The repository tracks Rust `stable`. CI updates to the latest stable release on
every run and verifies Linux, macOS, and Windows builds.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

Current CLI commands can be inspected with:

```sh
cargo run --locked -- --help
```

## Licensing

No open-source license is granted. See [LICENSE](LICENSE).
