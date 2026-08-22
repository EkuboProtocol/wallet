---
name: gpui-design-guide
description: The GPUI Component design guide, as it applies to the Ekubo Wallet desktop interface. Read before changing anything that renders — a route in `src/desktop.rs`, an overlay, a dialog, a row, a label, an empty state, a spacing or colour value. Covers hierarchy, theme tokens, the rem scale, alignment spines, component semantics (Button vs Link, DropdownMenu vs ContextMenu), interaction states, dense-data surfaces, and interface copy. Also records the wallet-specific carve-outs where this repository's security requirements outrank the guide.
metadata:
  source: https://longbridge.github.io/gpui-component/docs/design-guides
  retrieved: 2026-08-22
---

# GPUI Component design guide

The full normative text is vendored at
[`references/gpui-component-design-guides.md`](references/gpui-component-design-guides.md).
Read it — this file is an index and a set of local amendments, not a
replacement. **Must** in that document is a correctness constraint, **should**
is the default that needs a stated reason to override, **may** is optional.

The wallet composes `gpui-component` at the revision pinned in `Cargo.toml`
(`package.metadata.gpui-revisions`). The guide is newer than that pin, so a
rule may describe an API this build does not have. When they disagree, the
vendored library wins: check `~/.cargo/git/checkouts` or the `gpui-component`
skill for the real signature rather than inferring one from the prose.

## What the wallet already is

One shell, decided already: a fixed navigation rail on the left, one page to
its right, overlays above both. The nine rail destinations are `Route::ALL` in
`src/desktop.rs` — Accounts, Inbox, Portfolio, Policies, Automations,
WalletConnect, Tokens, Networks, Settings — in a deliberate order, each with a
`label()` and a one-line `description()`. Every one of them renders through a
`render_*` method on the same view.

That means most design work here is *within* a stable shell: hierarchy inside a
page, the geometry of a repeated row, the wording of a label, the state of a
control. Do not propose a new shell, a dashboard grid, or a second navigation
axis. Do not add a rail entry without a task that needs a permanent home.

## The rules that bite in this codebase

**Colour comes from `cx.theme()`, by meaning.** The interface already resolves
~350 colours this way, so a raw `rgb`/`hsla`/hex literal in a render path is a
defect, not a shortcut. `danger`, `warning`, `success`, and `info` carry their
meanings and nothing else — never decoration, never the only carrier of a
state. If the role you need does not exist, add it to the theme layer in
`src/desktop.rs`'s theme construction, not at the call site.

**Geometry comes from the rem scale.** `p_4()`, `gap_2()`, `text_sm()`,
`h_8()`, `size_4()` and component `Size` values scale with the window's base
font; `px(...)` does not. Fixed pixels are for physical or external boundaries
— a one-device-pixel hairline, a window inset, a raster dimension, a hit-test
minimum, a virtual-list height hint. This file has ~110 `px(...)` call sites
and some are exactly those legitimate cases. Treat each one as a question with
an answer: if the value is product spacing, typography, icon size, or ordinary
control geometry, it belongs on the relative scale; if it is a real boundary,
say so in a comment where it is defined. Do not run a blanket sweep — a
mechanical replacement that changes rhythm at the default zoom is worse than
the literal it removed.

**Emphasis is a budget.** One focal point per surface. `primary` marks the one
default commitment in a decision area — the thing Enter does — not merely the
only button on screen, not "the important-looking one". An `Add`, `Refresh`, or
`Open` command is a default, outline, or ghost Button. A row of coloured badges
means a grouping decision is missing.

**Button means application action; Link means a URL.** Everything internal —
rail rows, tabs, list items, opening a detail, revealing a panel — is a Button,
a native navigation component, or an Action. Underlining is reserved for
something that opens a browser or a mail client. This matters more here than in
most products: a wallet that styles a signing command like a link has
misrepresented what activation does.

**Selection is state, not polish.** Tabs, rail destinations, filter segments,
selected rows, and a Button that owns an open popup all need a persistent
selected/open treatment that survives losing hover. Hover alone never explains
a relationship, and keyboard users have no hover at all.

**Commands live where their frequency puts them.** Primary action visible;
region-scoped secondaries behind a visible `DropdownMenu`; object-scoped
commands in a `ContextMenu`; a hover-revealed icon only as a shortcut to
something reachable another way. Never the only path to a destructive or
essential command.

**Alignment is structural.** Sibling regions share one content inset. Repeated
rows keep identity, metadata, status, numbers, and trailing actions in the same
lanes, and an absent icon or badge must not move the label beside it. Equal
gaps are equal to the rendered pixel, and the fix is the shared owner — a
constant, a token, a helper — never a compensating offset at one call site.
Numbers right-align; prose and identifiers lead.

**Copy is sentence case, unpunctuated, and specific.** No trailing period on a
label, button, tab, heading, or short state; full sentences in explanations and
errors keep theirs. A single `…` character on any command that opens a dialog,
sheet, or window, or that needs more input before it can complete — and on
nothing else. Name the result: `Delete`, not `Confirm deletion`; `Discard
changes`, not `Yes`. Errors say what happened and how to recover.

**Every state is a design surface.** Empty, loading, error, offline,
locked/read-only, and permission-denied are not afterthoughts on a page that
usually has data. An empty state explains the next action.

## Wallet amendments

These override the guide where they conflict. They exist because this is a
signing surface, not a content application.

**Context economy stops at the review boundary.** The guide tells you to delete
text the surrounding surface already establishes. That is correct for a rail
label or a dialog body — and wrong for approval and signing UI. Repetition in a
review card, an approval fact list, a policy diff, or an exact-payload block is
deliberate: the reader is confirming that two independent statements of the
same thing agree. Improve the *hierarchy* and *alignment* of those surfaces
freely. Do not compress their information, collapse a fact behind disclosure,
or drop a restatement because the title already said it.

**A dialog is not authorization.** Per `AGENTS.md`, owner authorization is
enforced in `ekubo-wallet-core`. A visual change must not move, weaken, or
appear to satisfy an authorization step, and UI code must not begin writing
settings directly in the name of a smoother flow. Design work stops at
collecting intent and rendering results.

**Truncation has a cost here.** Addresses, amounts, chain names, and calldata
are decision-critical. Ellipsize only where the full value stays reachable —
tooltip, detail view, copy action — and never in the middle of a value whose
prefix and suffix are what the reader compares.

**Motion stays scarce.** Short transitions to explain appearance and dismissal;
nothing ambient, nothing that must be watched to understand a state.

## Before calling a surface done

Run the guide's own review questions — is the task clear, does every action
keep its promise, is hierarchy restrained, could it do less better, is the
structure exact, does it follow the component system, does it survive every
state, has it been seen in a real window.

Then, mechanically:

- `cargo fmt --all --check`
- `cargo test --locked --workspace --all-features desktop_render` — every route
  and overlay is laid out and painted in `src/desktop_render_test.rs`. A
  surface that panics or lays out to nothing fails there. It asserts layout,
  not appearance.
- The full gate in `CLAUDE.md` before landing.

A render test passing is not a design review, and a screenshot is not proof.
Keyboard path, focus restoration, theme in both modes, window minimum, and the
failure states are part of the work.
