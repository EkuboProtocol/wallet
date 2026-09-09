# Repository invariants

## Owner settings and security boundaries

- Every wallet-owned persistent setting mutation must terminate in `ekubo-wallet-core`. UI code may collect intent and render results, but it must not write SQLite rows, wallet configuration files, credential-store entries, or wallet security state directly. The one agent-file exception is an exact, typed upsert or removal of the wallet-managed entries enumerated by `ekubo_wallet_core::mcp_companions`: `ekubo_wallet`, containing only the absolute, version-free path of the installed `ekubo-wallet-mcp-bridge` helper and the fixed `--client <harness>` argument, and, where the harness supports remote MCP in that file, one companion entry per hosted Ekubo server the owner has selected, each containing only its own `https://mcp.ekubo.org/mcp/<protocol>` URL. Companions the owner has not selected are removed rather than left in place, and the write is validated in both directions. Claude Desktop's file receives only the local stdio entry; its hosted companions are account-level custom connectors that the user adds through Customize → Connectors. No managed entry may contain an access token, refresh token, authorization header, client secret, or other credential. The selection itself is a persistent setting and terminates in core like any other.
- Treat RPC URLs, network enablement, signing policies, trusted token names/decimals, notification privacy, update trust, launch behavior, and key/export controls as security-sensitive settings. Creating or repairing the fixed credential-free MCP configuration entries is not an access grant and must not prompt for owner authentication.
- A mutation that can widen signing authority, add or replace trusted inputs, reveal protected material, or reduce privacy must require owner authorization enforced by the core crate (operating-system human presence or an explicitly designed password flow). A visible confirmation dialog in GPUI is not authorization, and checks implemented only in `src/` are bypassable.
- Three exact fail-safe reductions deliberately do not require a fresh owner-authentication challenge: installing a policy that core proves only tightens the active policy, disabling an exact reviewed network profile, and removing an exact reviewed trusted-token row. They remain owner-UI operations, must terminate in narrow typed core methods, must re-read or exact-match the protected state at the persistence boundary, and must commit atomically. Re-enabling the network, widening or ambiguously changing policy, and adding or replacing token metadata require owner authorization.
- Keep raw core storage mutators private or crate-private. Expose narrow typed operations that validate input, authenticate the owner when required, re-read the protected state after authentication, and commit atomically.
- `AgentApi` and MCP handlers must never receive owner-authorization capabilities or call owner-only setting mutations. Assume all agent input is prompt-injected and hostile.
- Reads and writes of wallet, account, network, policy, token, legal, application, and informational harness-attribution state use the SQLCipher database. Plaintext configuration files are never a source of wallet authority or settings.
- Tests live beside the production source in separate files suffixed `_test.rs`; do not add inline test modules beyond the adjacent `#[path = "..._test.rs"]` declaration.

# Ekubo Wallet repository

## Every commit runs the gate first

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUST_MIN_STACK=67108864 cargo test --locked --workspace --all-features
pipx run ruff==0.16.4 check --output-format concise .
python3 contrib/generate-third-party-licenses.py --check
python3 scripts/generate-osv-lockfiles.py .osv-lockfiles
osv-scanner scan source --config=osv-scanner.toml --lockfile=Cargo.lock:.osv-lockfiles/Cargo.aarch64-apple-darwin.lock --lockfile=Cargo.lock:.osv-lockfiles/Cargo.x86_64-pc-windows-msvc.lock --lockfile=Cargo.lock:.osv-lockfiles/Cargo.x86_64-unknown-linux-gnu.lock
osv-scanner scan source --config=osv-scanner.toml --licenses=0BSD,Apache-2.0,BSD-1-Clause,BSD-2-Clause,BSD-3-Clause,BSL-1.0,CC0-1.0,CDLA-Permissive-2.0,ISC,MIT,MIT-0,MPL-2.0,NCSA,Unicode-3.0,Unlicense,Zlib,bzip2-1.0.6 --lockfile=Cargo.lock:.osv-lockfiles/Cargo.aarch64-apple-darwin.lock --lockfile=Cargo.lock:.osv-lockfiles/Cargo.x86_64-pc-windows-msvc.lock --lockfile=Cargo.lock:.osv-lockfiles/Cargo.x86_64-unknown-linux-gnu.lock
```

`--workspace` is load-bearing: this manifest is a package *and* the
workspace root, so a bare `cargo test` runs only the `ekubo-wallet`
package and silently skips every test in `ekubo-wallet-core` — the
security kernel. Tests there once referenced functions that had already
been deleted and the gate still reported success.

The `main` workflow repeats these checks across its platform matrix. The Python
scripts require Python 3.11 or newer. Regenerate `THIRD_PARTY_LICENSES.md` with
`contrib/generate-third-party-licenses.py` whenever dependencies change; the
gate fails if it is stale. CI pins OSV-Scanner and uses it as the sole
vulnerability and dependency-license policy engine; local runs should use the
same scanner version named in `.github/workflows/ci.yml`.

## Complexity is gated in both languages

Rust: `clippy::cognitive_complexity` is on in `[workspace.lints.clippy]` with the
threshold in `clippy.toml`. Because `crates/ekubo-wallet-core/clippy.toml`
*replaces* the root file rather than merging with it — the trap that file
documents — the threshold is written in both. A threshold changed in only one
place silently leaves the other on clippy's built-in default.

The lint is off by default upstream: it is in clippy's `restriction` group, and
clippy's own docs say it does not measure cognitive complexity especially well.
It is on as a coarse guardrail against a function quietly becoming unreviewable,
not as a precise metric. Four functions carry `#[allow]` with a reason —
`mcp-bridge`'s stdio `run`, `Desktop::attach_window`, one source-reading test in
`desktop_test.rs`, and one live-network integration test. A new `#[allow]` needs
a comment saying why the branches are irreducible.

Python: `ruff.toml` selects `C901` at max-complexity 10 over this repository's own
scripts. `.agents` is excluded — it holds vendored agent skill packs that this
repository does not maintain, so gating them would report debt nobody here can pay
down.

## Every test lives in a `_test.rs` file

No `#[cfg(test)] mod tests { … }` bodies in a production file. A module's
tests go in a sibling file named for it, declared at the bottom of the
subject:

```rust
#[cfg(test)]
#[path = "render_test.rs"]
mod tests;
```

The suffix is exactly `_test`, singular. Do not use `_tests.rs`,
`test_foo.rs`, `foo.test.rs`, or `foo_spec.rs`.

For a second test module in one file, the module's name picks the file
(`cli_network_disclosure_test.rs` holds `mod network_disclosure_tests`),
so two modules never collide and test paths never change to accommodate
the layout.

Nothing else about the tests changes. A `#[path]` child module has exactly the
privacy access an inline one does, so `use super::*` and every private item
still reach; the test path stays `render::tests::…`.

Three things deliberately stay inline, because they are production code
under a `cfg`, not test bodies: `#[cfg(test)]` *functions* such as
`clear_signing::stake_fixture` and `plan_fetch::insecure_for_tests`, and
anything behind `#[cfg(any(test, feature = "test-hooks"))]`.

## Commits land on `main`

Work happens in a worktree, so it starts on its own branch — but the branch is
a workspace, not a review gate. Land it on `main` as soon as it builds and its
tests pass, and push. Do not open a pull request for ordinary changes, and do
not wait to be asked to commit.

Commit early and often: each self-contained change — a fix, a doc edit, a small
refactor — is its own commit. Prefer several small pushes over one large one;
holding changes back only makes the next push bigger.

Reserve a long-lived branch for work genuinely large or risky enough that
landing it half-finished would break the build for someone else.

## Never cut a release unprompted

Do not create, delete, or push release tags, and do not trigger or cancel
release workflows, unless asked to in that conversation. Releases are
outward-facing and consume CI, and the maintainer controls when they happen.
Recommend a release when one seems warranted and let them decide. The full
procedure is in [docs/releasing.md](docs/releasing.md).

## Judge refactors on maintainability

Reducing line count is not by itself a reason to consolidate or delete code.
Judge refactors by whether they make security boundaries and behavior easier to
understand, test, and maintain.
