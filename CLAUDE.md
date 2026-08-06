# wallet-mcp-server

## Every commit runs the gate first

```sh
cargo fmt          # mandatory, never skip
cargo clippy --workspace --all-targets
cargo test --workspace
```

`--workspace` is load-bearing: this manifest is a package *and* the
workspace root, so a bare `cargo test` runs only the `ekubo-wallet`
package and silently skips every test in `ekubo-wallet-core` — the
security kernel. Tests there once referenced functions that had already
been deleted and the gate still reported success.

Nothing reviews this downstream, so an unformatted or unbuilt commit is a
defect that reaches `main` directly. Regenerate `THIRD_PARTY_LICENSES.md` with
`contrib/generate-third-party-licenses.py` whenever dependencies change; a test
fails if it is stale.

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

Push to `main` directly. Do not open a branch or a pull request for ordinary
changes, and do not wait to be asked to commit. Commit early and often: each
self-contained change — a fix, a doc edit, a small refactor — is its own
commit, pushed as soon as it builds and its tests pass.

Reserve a long-lived branch for work genuinely large or risky enough that
landing it half-finished would break the build for someone else.

## Never cut a release unprompted

Do not create, delete, or push release tags, and do not trigger or cancel
release workflows, unless asked to in that conversation. Releases are
outward-facing and consume CI, and the maintainer controls when they happen.
Recommend a release when one seems warranted and let them decide. The full
procedure is in [docs/releasing.md](docs/releasing.md).

## Interactive terminal UX uses ratatui

`ratatui` (crossterm backend, sharing the existing crossterm dependency) is the
only terminal UI library here; `inquire` is gone. `src/tx_browser.rs` is the
pattern: alternate screen, per-frame layout so resizing cannot break it, and a
toned `Span`/`Line` document model reusing `tui::Tone`.

The rule that matters now is not which library but **one command, one screen
mode**. `src/fullscreen.rs` draws on the alternate screen; `tui.rs`'s
`confirm`, `pick`, and `text` open an inline viewport at the cursor and print
the line they answered into the scrollback. Both are ratatui, and mixing them
inside one command is the defect: the terminal flips modes at every step and
the finished prompts pile up behind the full-screen view. That is what left
half-typed address-book forms on the screen after the browser exited.

So: a command that shows any full-screen surface stays full-screen to its last
question. Build from `fullscreen`'s pieces — `pick_table`, `edit_form`,
`confirm_review`, `TextField`, `decision_pane`, `SearchableTable` — and let
only the finished result reach the scrollback, once, after the screen is
released. A command that never opens a screen may use the inline prompts
throughout; `wallet create`'s starting-policy question and the inline approval
fallback are the two that legitimately do.

The one unavoidable handover is platform owner authentication: a polkit text
agent prompts on the same terminal, so release the screen around it and
re-enter afterwards, as `address_book_browser` does.

## Judge refactors on maintainability, not audit cost

A full `v12` audit costs roughly $525 (measured 2026-08-06, after the test
split: 44 files, 1,112,246 bytes, $526.34; it was $619.12 with test modules
inline). Excluding the four TUI browser modules — `tx_browser`,
`address_book_browser`, `fullscreen`, `pager` — saves only tens of dollars.

Shrinking the audit corpus is therefore never a reason to consolidate or
delete code; argue those changes on reviewability alone. The `_test.rs` rule
above is not an exception to that: it moves code rather than removing it, and
the reviewability argument for it stands on its own.

Pricing is measured UTF-8 bytes plus per-file overhead, and it is not linear —
26% fewer bytes bought 15% off — so a large part of the price is fixed and
trimming is worth less than byte counts suggest. `v12_estimate_cost` is free
and takes a `zipUid`, so measure a hypothetical layout instead of guessing.

When audit spend does matter, scope with `paths` and prefer a diff review per
change over repeated full audits. Keep `tui.rs` and `render.rs` in scope
regardless: the approve/reject picker and terminal-escape sanitization are
security-relevant display code.
