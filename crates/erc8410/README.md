# ERC-8410 execution plans

A `#![no_std]` Rust library using `alloc` for execution-plan types,
JSON parsing, validation, and the Ekubo wallet's approval digest. It has no
wallet, network, storage, signing, or operating-system dependencies.

Validation preserves the wallet's existing schema version 1 rules, resource
limits, and capability support (`atomic_batch`). This is the wallet's supported
plan profile, not a general capability negotiation engine. The digest is the
wallet's existing approval identity, not a claim of a standardized ERC digest;
it excludes gas, decode hints, failure policy, capabilities, and extensions.

```rust
use erc8410::ExecutionPlan;

fn digest(json: &str) -> anyhow::Result<String> {
    let plan = ExecutionPlan::from_json(json)?;
    Ok(format!("{:#x}", plan.digest()))
}
```

Use `from_json` for untrusted JSON: it checks input bytes before parsing and
validates the result. `parse(Value)` also validates; direct Serde deserialization
and public-field construction require an explicit `validate()` call.

Default features are empty. Enable `schema` for the wallet's Schemars definitions.
Digest serialization has explicit field ordering and is unaffected by other
dependencies enabling `serde_json/preserve_order`.

From the repository root:

```sh
cargo test -p erc8410 --no-default-features
cargo test -p erc8410 --features schema,serde_json/preserve_order
rustup target add wasm32-unknown-unknown
cargo check -p erc8410 --target wasm32-unknown-unknown --no-default-features
```

See [the JavaScript adapter](../erc8410-wasm/README.md) for browser and Node usage.
