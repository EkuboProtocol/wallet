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

A full `v12` audit of `src/` costs roughly $550 (measured 2026-08-05: 32,079
LOC, $549.52). Excluding the four TUI browser modules — `tx_browser`,
`address_book_browser`, `fullscreen`, `pager`, about 3.3K LOC — saves only
about $32. Shrinking the audit corpus is therefore never a reason to
consolidate or delete code; argue those changes on reviewability alone.

When audit spend does matter, scope with `paths` and prefer a diff review per
change over repeated full audits. Keep `tui.rs` and `render.rs` in scope
regardless: the approve/reject picker and terminal-escape sanitization are
security-relevant display code.
