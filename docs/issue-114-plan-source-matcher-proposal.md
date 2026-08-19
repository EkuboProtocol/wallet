# Issue #114 — the plan source matcher

Rules could constrain the calls a plan makes and the envelope prepared to carry
them. They could not constrain *who asked*. Issue #114 asked for that:
WalletConnect but only on certain domains, an agent but only when it
self-identifies as Codex.

This document is the design, and it is implemented.

## What the wallet actually knows about a request

Provenance is not one fact and the parts do not have the same standing. Before
this, they were flattened into one display string, `plan_source`, whose only
job is to be read by a person. The prefix convention in
`pending::validate_plan_source` already drew the line this design keeps: a bare
host is something TLS proved, `WalletConnect: …` is something a dapp typed
about itself.

| Fact | Standing | Where it comes from |
| --- | --- | --- |
| Which channel delivered the plan | **Proved** | Core is the thing being called, so it knows whether `execute_automatic` was reached from the WalletConnect handler, an MCP tool, or the automation scheduler. |
| Host that served the plan artifact | **Proved** | `plan_fetch::vetted_host`, behind a pinned TLS client. Exists only for a plan fetched over https. |
| Installed automation id | **Proved** | The scheduler names the row the owner installed. |
| Dapp domain | **Claimed** | `AppMetadata.url`, typed by whoever wrote the dapp. Unverified. |
| Agent harness kind | **Claimed** | The `--client` argument the stdio bridge passed. |

## The shape: one `source` slot, tagged by channel

```json
{
  "effect": "allow",
  "label": "Rebalances from Codex only",
  "source": { "agent": { "client": { "eq": "codex" } } },
  "to": { "eq": "0x…" }
}
```

```json
{ "source": { "walletconnect": { "domain": { "in": ["app.ekubo.org"] } } } }
{ "source": { "agent": { "plan_host": { "eq": "mcp.ekubo.org" } } } }
{ "source": { "automation": { "id": { "eq": "claim-rewards" } } } }
```

Tagged rather than a flat bag of `source_*` fields, because the channel and the
fields that only exist inside it must not come apart. A flat bag can spell
"automation, on domain ekubo.org" — a rule that parses, installs, and then
matches nothing for the rest of its life. The tagged form cannot express it.

`SourceMatcher` is its own type rather than a `Predicate`, for the same reason:
its subject is not a value in the ABI domain every other slot speaks, and
pretending otherwise would put the channel vocabulary inside a string literal.

| Channel | Field | Standing |
| --- | --- | --- |
| `walletconnect` | `domain` | claimed — host of the URL the dapp gave for itself |
| `agent` | `client` | claimed — the harness kind the bridge passed |
| `agent` | `plan_host` | proved — the TLS host that served the plan |
| `automation` | `id` | proved — the installed automation |

### Absence is a non-match

Naming a field at all — even as `any_value` — requires the request to carry it.
A plan with no agent claim does not match `{"agent": {"client": "any_value"}}`.
This is what `delegation` already does for an envelope with no authorization,
and it has the property everything else rests on: **adding a source matcher to
a rule can only ever shrink what that rule matches.**

So constraining an existing `allow` by source is proved a tightening by
`is_tightening` and installs from the owner UI with no fresh OS challenge —
correctly, because it takes authority away. A *new* `allow` that exists only
because of a claim is a widening, and already required owner authentication.

A source the wallet cannot name is `RequestSource::Unknown`, which no matcher
covers. That is what a pending row stored before the column existed reads back
as, and what an MCP dry run of not-yet-installed automation bytecode reports.

## Effects are not restricted, and the two hazards that leaves

A tempting rule would be "claimed fields may only appear on `deny` and
`review`". It is the wrong rule: it would refuse the issue's own example, which
is an allow-narrowing use, and it buys nothing, because a claim cannot widen.

What the claims must not do is let the owner believe they bought a security
boundary. Both hazards are written into `docs/policy-authoring.md`,
`docs/threat-model.md`, the JSON Schema field descriptions, and the sentence
`SourceMatcher::describe` puts in the permission diff:

**A claimed agent is not an authenticated agent.** The threat model puts a
same-user process in scope and says it "can access the local MCP IPC by
design". Any local process can run the bridge with `--client codex`. So
`allow … {"agent": {"client": {"eq": "codex"}}}` is not a defence against local
malware, and a deny on "not Codex" is escaped by claiming Codex. It is a
workflow boundary — it keeps an honest Claude Code session out of a rule
written for a Codex loop — and it is worth having as one.

**A claimed domain is chosen by the dapp at pairing.** A phishing dapp serving
from anywhere may put `app.ekubo.org` in its metadata. The pairing review says
so and lists cautions, but one careless session approval and a domain-gated
`allow` signs for that dapp from then on. The stronger version of this matcher
is a per-session identity minted when the owner approves a session, so a rule
names *the session the owner approved* rather than a string the dapp chose.
That is a larger change and is deliberately out of scope; this shape leaves
room for it.

## Typed predicates

`StringPredicate` and `NumberPredicate` wrap `Predicate` transparently and
restrict it to the forms one value type can answer. The wrapper checks
applicability as it deserializes, so `{"gt": "5"}` on a domain is refused where
it is written; more usefully, the published JSON Schema for a source field
names only `eq`, `in`, `any`, `all`, `not`, and `length` — an editor completing
a domain never offers `selector`, `each`, or `tuple`.

Only the source fields use them so far. The existing slots keep plain
`Predicate`, whose type is not always knowable from the document alone
(`calldata` holds `bytes` whose decoded arguments take whatever types the named
ABI gives them). Retrofitting the slots that *are* schema-pinned — `to`,
`chain_id`, `native_value`, and the envelope fields — is a natural follow-up
and is not done here.

## Plumbing

`RequestSource` is a closed structure core builds and hands to `evaluate_policy`
beside `PreparedTransactionFacts`, for the same reason: it is a matched
subject, not something a predicate literal resolves against. `PolicyContext`
stays one address.

It is persisted on the pending row in a new `request_source` column
(schema version 10, additive, not backfilled), so the review a human opens is
evaluated against the source the request actually arrived with, and so the
audit record says what the policy matched on. It is recorded beside a
simulation handle too, because sending from one re-simulates and re-evaluates.

`plan_source` is untouched and still never matched. Keeping the two apart is
deliberate: one is a line assembled for a person and half-authored by the
requester, the other is a closed structure core built. Collapsing them would
put dapp-authored text on the authorization path.

## What changed

* `core/source.rs` — new: `RequestSource`, `SourceMatcher`, and the three
  channel structs, with `source_test.rs`.
* `core/predicate.rs` — `StringPredicate` and `NumberPredicate`.
* `core/policy.rs` — the `source` slot, through `evaluate`, `is_narrower_than`,
  `described_constraints`, and the two presets.
* Construction at each channel: the WalletConnect handler, the MCP server, the
  automation scheduler, and both automation dry runs.
* `pending.rs` column and `policy_store.rs` migration to schema 10.
* `schemas/policy.schema.json`, `docs/policy-authoring.md`,
  `docs/threat-model.md`, `docs/automation.md`.
* `examples/policies/scoped-to-the-asker.json`, exercised in
  `tests/example_policies.rs`.
