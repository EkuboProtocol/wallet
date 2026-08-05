# wallet-mcp-server

## Every commit runs the gate first

```sh
cargo fmt          # mandatory, never skip
cargo clippy --all-targets
cargo test
```

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
approved direction, and `src/tx_browser.rs` is the pattern: alternate screen,
per-frame layout so resizing cannot break it, and a toned `Span`/`Line`
document model reusing `tui::Tone`. Extend that approach for new or reworked
list and detail views rather than adding `inquire` prompts — inquire sizes its
page once and breaks on short or resized terminals. `tui.rs`'s confirm and
select helpers still wrap inquire, and `cli.rs` and `address_book_browser.rs`
still call its text and password prompts — those are the migration candidates.

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
