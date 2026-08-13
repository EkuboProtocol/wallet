# Ekubo Wallet repository

## Every commit runs the gate first

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUST_MIN_STACK=67108864 cargo test --locked --workspace --all-features
python3 contrib/generate-third-party-licenses.py --check
(cd integrations/claude-desktop && npm ci && npm test && npm run validate && npm run pack)
cargo audit
```

`--workspace` is load-bearing: this manifest is a package *and* the
workspace root, so a bare `cargo test` runs only the `ekubo-wallet`
package and silently skips every test in `ekubo-wallet-core` — the
security kernel. Tests there once referenced functions that had already
been deleted and the gate still reported success.

The `main` workflow repeats these checks across its platform matrix. The Python
scripts require Python 3.11 or newer. Regenerate `THIRD_PARTY_LICENSES.md` with
`contrib/generate-third-party-licenses.py` whenever dependencies change; the
gate fails if it is stale.

## Every test lives in a `_test.rs` file

No `#[cfg(test)] mod tests { … }` bodies in a production file. A module's
tests go in a sibling file named for it, declared at the bottom of the
subject:

```rust
#[cfg(test)]
#[path = "render_test.rs"]
mod tests;
```

The suffix is exactly `_test`, singular. `_tests.rs`, `test_foo.rs`,
`foo.test.rs`, and `foo_spec.rs` are all billed by `v12`; only `*_test.rs`
is excluded by default, and inline test bodies are billed as part of the
file that holds them. Getting this wrong costs money silently — audit
pricing is measured UTF-8 bytes, so the mistake shows up as a bigger
invoice and nothing else.

For a second test module in one file, the module's name picks the file
(`cli_network_disclosure_test.rs` holds `mod network_disclosure_tests`),
so two modules never collide and test paths never change to accommodate
the layout.

Nothing else about the tests changes. A `#[path]` child module has exactly
the privacy access an inline one does, so `use super::*` and every private
item still reach; the test path stays `render::tests::…`.

Three things deliberately stay inline, because they are production code
under a `cfg`, not test bodies: `#[cfg(test)]` *functions* such as
`clear_signing::stake_fixture` and `plan_fetch::insecure_for_tests`, and
anything behind `#[cfg(any(test, feature = "test-hooks"))]`.

The cost of this is that an audit no longer reads the tests. That is
usually right — tests are not the security boundary — but it does give up
findings about the tests themselves, and run 6161 had one (a fixture
pairing bytes with a hash that could not occur in production). Pass the
files as explicit `paths` to opt them back in when that is what you want.

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

## Judge refactors on maintainability, not audit cost

Shrinking the audit corpus is therefore never a reason to consolidate or
delete code; argue those changes on reviewability alone. The `_test.rs` rule
above is not an exception to that: it moves code rather than removing it, and
the reviewability argument for it stands on its own.

Pricing is measured from the submitted corpus and can change. Use the audit
tool's estimate for the exact current submission rather than preserving a
historical dollar or byte count here.

When audit spend does matter, scope with `paths` and prefer a diff review per
change over repeated full audits. Keep the core authorization code and native
review rendering in scope: approval gating and hostile-text presentation are
security-relevant display behavior.
