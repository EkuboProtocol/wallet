# Policies

A policy is `chains` → decimal chain ID or `"*"` → that chain's rules. The `"*"`
entry applies only when no exact chain ID entry exists, so an exact entry
replaces rather than extends the fallback. Without a wildcard, a permission on
one chain never applies to another.

Each chain configures the maximum calls in one atomic batch, a `native_value`
guard, and an unordered set of `rules`.

## How a call is decided

Every call in a plan is graded on its own, against the whole rule set:

- any matching `deny` rule denies,
- otherwise any matching `allow` rule allows,
- otherwise the call is denied.

Those three lines are three *outcomes*, and they are not interchangeable:

| Outcome | When | What happens |
| --- | --- | --- |
| `allowed` | every call matched an `allow` rule and every guard was satisfied | signs automatically, no prompt |
| `requires_approval` | no rule covers some call | queues for explicit human approval in the CLI |
| `rejected` | a `deny` rule matched | refused outright — nothing signs, nothing queues, and no approval can override it |

The distinction between the two negative outcomes is the point. A `deny` rule is
the owner having already answered; an approval prompt that can talk them out of
it makes the rule decoration, so there is no such prompt. Matching no rule is
the owner having said nothing, which is a question rather than a refusal, and
that is exactly the case a human may still answer at the terminal. A rejected
plan never reaches the pending queue at all: the only way forward is to change
the policy, which is its own explicit CLI action with its own permission diff.

Rules are a **set**, not a list. Order carries no meaning, and deny always beats
allow, so a rule can be read without reading the rules around it. That is also
what lets the permission diff shown before a policy is installed be a diff of
the document rather than a simulation of it.

In that diff, `+` and `-` mean *more* and *less* signing authority, not
"present in the proposal" and "absent from it". The two come apart for deny
rules, and in the direction that matters: a deny that disappears hands
authority back, so it is a `+` reading `stops denying`, while a deny that
appears is a `-` reading `starts denying`. A chain that gains or loses its own
entry is likewise diffed against the `"*"` fallback that governed it before or
governs it after, since that — not "nothing" — is the authority being replaced.

A rule is a conjunction of optional predicate slots — `to`, `from`, `value`,
`calldata` — plus its `effect`. **A slot that is absent constrains nothing.** A
rule naming only `to` permits every function that contract has, including any
batching entry point that forwards elsewhere; the permission diff says so out
loud rather than leaving it to be inferred.

## Predicates

One predicate language applies to every slot and, through `selector`, to every
decoded argument underneath it.

| Predicate | Meaning |
| --- | --- |
| `"any_value"` | Matches anything, including calldata this policy cannot decode. |
| `{"eq": "…"}` | Equal to one literal. |
| `{"in": ["…", "…"]}` | Equal to one of a set. |
| `"is_wallet"` | The address is this wallet. |
| `{"selector": {"abi": "…", "args": {…}}}` | Calldata is a call to this exact function; `args` constrain its parameters by name. |
| `{"each": …}` | Every element of an array satisfies the inner predicate. |
| `{"any": [...]}` / `{"all": [...]}` / `{"not": …}` | Boolean combinators. |
| `{"length": …}` | The element or byte count satisfies the inner predicate. |

Literals are written one of exactly two ways: **hex with a `0x` prefix**, or
**decimal with no prefix**. Bare hex is refused rather than guessed at, because
`10` is a legal spelling of both sixteen and ten.

`is_wallet` is what makes a rule portable — "the proceeds must come back to me"
without naming an address. Every other address is named outright, with `eq` or
`in`.

There were once two more: `is_token` and `is_address_book`, which deferred to
the local token database and address book. They are gone, and a policy naming
either is now refused rather than parsed into something weaker. The reason is
that those two stores exist to tell a person what they are looking at, and
reading them into an authorization decision gave one row two jobs: an entry
added so a transfer would read `Coinbase deposit` instead of `0x8f3c…21ab` also
widened what could be signed without asking. Afterwards nothing could tell the
two uses apart — not the owner confirming the row, and not a later reader of the
policy. A policy that means to allow an address says so in the policy, where the
permission diff can show it moving.

Token names and address-book aliases still do the job they were for: they
describe a transaction to the person approving it. They no longer decide
anything.

## Naming the function, not the selector

A `selector` predicate carries the function's full signature and derives the
four-byte selector from it. A policy therefore can never allowlist four bytes
whose meaning it does not know, and a reviewer reads
`approve(address spender, uint256 amount)` rather than `0x095ea7b3`.

Every parameter must be named, because rules refer to arguments by name.
Arguments are decoded strictly: the wallet re-encodes what it decoded and
requires the original bytes back, which rejects trailing garbage, non-canonical
offsets, and dirty address padding in one comparison. A rule cannot be satisfied
by an alternate encoding that the target contract's decoder would read
differently.

Anything unanswerable is a non-match — calldata too short, a decode that fails,
a predicate applied to the wrong shape — and since an unmatched call is denied,
uncertainty denies.

## Nested calls

There is no special support for batching functions, and none is needed:
`{"each": {"selector": …}}` over a `bytes[]` argument constrains each inner call
using the same vocabulary as the outer one.

```json
"calldata": { "selector": {
  "abi": "multicall(bytes[] data)",
  "args": { "data": { "each": { "selector": {
    "abi": "transfer(address to, uint256 amount)",
    "args": { "to": { "in": ["0x2222222222222222222222222222222222222222"] } }
  }}}}
}}
```

A `bytes` argument left unconstrained is *unconstrained* — the wallet does not
try to guess at an encoding it was not told about. Prefer plans that emit
separate steps over plans that nest calls: this wallet already executes a
multi-step plan as one atomic EIP-7702 Calibur batch, so a producer needing
atomicity does not need a router's `multicall`, and separate steps are each
graded on their own.

## Native value

`native_value` is a chain-level predicate applied to **every call**, on top of
whichever rule matched. It is a guard, not a grant: no rule can widen it. Omit
it and it is `{"eq": "0"}`, so a document that never mentions native value never
sends any.

## There are no amounts

A per-transaction ceiling is not a spending limit when the same agent may ask
again immediately, so the format does not offer one. What a rule bounds is
*which* calls may be made, not how much they move. Never describe a policy as
capping spend.

## What a policy never reads

Every predicate is decided from the execution plan's own bytes and the address
of the signing wallet. That is the whole of it: not the token database, not the
address book, and nothing the RPC reported — observed balances, transfer logs,
gas, or whether the simulation succeeded.

The endpoint is the only witness to a simulation, so a rule scored against what
it reported is one a dishonest endpoint could relax by misreporting what a
transaction did, while still reading like a limit that binds.

Simulation still gates signing: a plan that does not simulate successfully is
refused whatever the policy says, and the balance changes a simulation reports
are shown at approval time. Neither is a policy predicate — one is a
precondition, the other a display.

A queued request has no expiry, and the document has no setting that gives it
one. Nothing about what may be signed is decided by reading this machine's
clock. A transaction that must not execute after some moment carries that
deadline in the calldata the user approved, where the chain enforces it.

`max_calls_per_batch` accepts up to 4096; real batches are bounded by the
selected policy, memory, encoded transaction size, and the per-chain gas cap.

## Files

Policy documents have a generated [JSON Schema](../schemas/policy.schema.json)
derived from the same types the wallet enforces. Print the current one with
`ekubo-wallet policy schema`, and reference it as the top-level `$schema` value
for editor completion. Starting points live in [`examples/`](../examples):

| File | Purpose |
| --- | --- |
| [`policy.json`](../examples/policy.json) | The allow-all profile, one of the two choices `account create` offers. |
| [`policies/deny-all.json`](../examples/policies/deny-all.json) | Exactly what `policy require-approval` installs, and the default for imported wallets. |
| [`policies/token-budget.template.json`](../examples/policies/token-budget.template.json) | One chain, one router, one token: a bounded approval, a swap paying back to this wallet, and a blanket deny on operator grants. |
| [`policies/approval-wildcards.template.json`](../examples/policies/approval-wildcards.template.json) | How an exact chain entry replaces the wildcard, and how the metadata predicates read. |
| [`policies/allow-all-with-approval.template.json`](../examples/policies/allow-all-with-approval.template.json) | Exactly what `policy allow-all` installs. |

Worked examples, each demonstrating one thing the engine can express. Every
verdict below is asserted in [`tests/example_policies.rs`](../tests/example_policies.rs),
so an example that stopped meaning what its label says would fail the build:

| File | Shows |
| --- | --- |
| [`transfers-to-named-addresses.json`](../examples/policies/transfers-to-named-addresses.json) | Move the tokens this policy names, only to the recipients it names. Any amount — a rule bounds which calls, not how much. |
| [`revoke-approvals-only.json`](../examples/policies/revoke-approvals-only.json) | An argument deciding between two identical selectors: `approve(spender, 0)` passes, `approve(spender, 1)` does not. |
| [`swap-proceeds-to-self.json`](../examples/policies/swap-proceeds-to-self.json) | `each` over an `address[]` path and `is_wallet` on the recipient, so proceeds must come back and every hop must be confirmed. |
| [`deny-blanket-operators.json`](../examples/policies/deny-blanket-operators.json) | Deny-precedence: a blanket allow with `setApprovalForAll(true)` and allowance-growth refused over the top of it. |
| [`native-sends-only.json`](../examples/policies/native-sends-only.json) | `{"eq": "0x"}` as the plain-send idiom, plus the `native_value` guard. |
| [`batched-calls.json`](../examples/policies/batched-calls.json) | `each` composed with `selector` to constrain what a batching entry point may carry, with no recursion machinery. |
| [`predicate-edge-cases.json`](../examples/policies/predicate-edge-cases.json) | `not`, `all`, `any`, `length`, and a `native_value` set. The corners, one per rule. |

Two corners worth knowing, both exercised by those tests: `each` over an empty
array is vacuously true, so an empty batch is permitted — it carries nothing to
object to. And an `any` with no branches never matches, while an `all` with no
branches always does.

Template chain IDs, addresses, and signatures must be replaced and verified
before use. An agent can help draft a copy, but applying it stays an explicit
human CLI action:

```sh
ekubo-wallet policy validate ./my-policy.json   # parses and digests; changes nothing
ekubo-wallet policy set primary ./my-policy.json
ekubo-wallet policy allow-all primary
ekubo-wallet policy show primary
```

`policy validate` needs no wallet, no database, and no authentication, so a
policy can be drafted and checked before anything exists to apply it to. It also
type-checks every predicate against the signature it sits under, so a rule that
could only ever fail is refused at install time rather than silently never
matching at signing time.

Policy changes increment a local revision and invalidate every approval that has
not yet been signed.
