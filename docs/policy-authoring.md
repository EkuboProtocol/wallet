# Authoring wallet policies

A policy is one JSON document that decides which calls this wallet signs
automatically; anything a policy does not permit queues for explicit human
approval instead of failing. The complete schema is at `wallet://schemas/policy`.
Propose changes with `wallet_propose_policy`, always starting from the exact
document and revision returned by `wallet_get_policy`.

## Structure

- `chains` maps a canonical decimal chain ID (or `"*"` for every chain) to that
  chain's rules. An exact chain key completely replaces `"*"` for that chain;
  the two are never merged.
- Each chain has `max_calls_per_batch`, a `native_value` guard, and an unordered
  set of `rules`.
- Literals are hex with a `0x` prefix, or decimal with no prefix. Never bare hex.
- Policies are stateless per-call rules. There are no amount limits, budgets,
  daily caps, or spend counters, so never promise those — a rule bounds *which*
  calls may be made, not how much they move.

## How a rule reads

```json
{
  "effect": "allow",
  "label": "Approve only this router to spend only this token",
  "to": { "eq": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" },
  "calldata": {
    "selector": {
      "abi": "approve(address spender, uint256 amount)",
      "args": { "spender": { "eq": "0x1111111111111111111111111111111111111111" } }
    }
  }
}
```

`effect` is `allow` or `deny`. The slots `to`, `from`, `value`, and `calldata`
are all optional predicates, ANDed together.

**An absent slot constrains nothing.** A rule with only `to` permits every
function that contract has, including any batching entry point. Write the
`calldata` slot unless the user genuinely wants the whole contract.

Rules are an unordered set: any matching `deny` denies, otherwise any matching
`allow` allows, otherwise the call is denied. So a blanket `deny` rule is a
one-line way to close something off regardless of what else the document grants.

The two ways a call can fail are not the same, and this matters when you propose
a policy. A call **no rule covers** queues for human approval — that is the
ordinary path, and it is fine for a policy to leave routine one-offs uncovered.
A call a **`deny` rule matches** is refused outright: it never queues, no
approval overrides it, and the only way forward is changing the policy. Reach
for `deny` when the user wants something foreclosed, not merely gated.

## Predicates

`"any_value"`, `{"eq": …}`, `{"in": [...]}`, `"is_wallet"`,
`{"selector": {"abi": …, "args": {…}}}`, `{"each": …}`, `{"any": [...]}`,
`{"all": [...]}`, `{"not": …}`, `{"length": …}`.

- `is_wallet` keeps a rule portable: use it for the recipient of a swap or claim
  rather than hard-coding the address.
- Every other address is named in the policy, with `eq` or `in`. There is no
  predicate that defers to the token database or the address book: those
  describe a transaction to the person approving it and decide nothing. Naming
  the addresses here is also what lets the permission diff show the owner
  exactly what a proposal would add.
- A `selector` predicate must give the function's full signature with every
  parameter named. The four-byte selector is derived from it.

## Proposing well

- Grant the minimum that enables the user's stated goal: exact targets, exact
  signatures, and argument predicates — widen only when the user asks.
- Work backwards from the planned action: a transfer needs a rule whose
  `calldata` is a `transfer(...)` selector with the recipient constrained; an
  approval needs an `approve(...)` selector with the spender constrained; a
  contract interaction needs its `to` and its signature; sending native value
  needs the chain's `native_value` guard widened.
- Prefer plans that emit separate steps to plans that nest calls in a
  `multicall`. This wallet already executes a multi-step plan as one atomic
  EIP-7702 batch, so nesting buys nothing and an unconstrained `bytes` argument
  grants everything that payload can reach. If you must allow a batching
  function, constrain its payload with `{"each": {"selector": …}}`.
- The user reviews a minimized permission diff plus your rationale. Write the
  rationale for a human: what they asked for, which rules enable it, and why the
  predicates are drawn where they are.
