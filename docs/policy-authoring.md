# Authoring wallet policies

A policy is one JSON document that decides which calls this wallet signs
automatically. The complete schema is at `wallet://schemas/policy`. Propose
changes with `wallet_propose_policy`, always starting from the exact document
and revision returned by `wallet_get_policy`.

## Structure

```json
{
  "version": 1,
  "chains": {
    "*": { "max_calls_per_batch": 16, "native_value": { "eq": "0" }, "rules": [] }
  }
}
```

- `chains` maps a canonical decimal chain ID (or `"*"` for every chain) to that
  chain's rules. An exact chain key completely replaces `"*"` for that chain;
  the two are never merged. A chain with neither entry is ungoverned, and its
  plans queue for approval.
- `version` must be `1`. A top-level `$schema` is optional and used only for
  editor completion.
- `max_calls_per_batch` is 1 to 4096, default 16, and bounds one atomic batch.
- `native_value` is a chain-level `uint256` predicate over wei, applied to
  **every** call on top of whichever rule matched. It is a guard, not a grant:
  no rule can widen it. Omit it and it is `{"eq": "0"}`, so a document that
  never mentions native value never sends any.
- `label`, on a chain or a rule, is 1-160 characters shown verbatim to the
  human reviewing the change.
- Literals are hex with a `0x` prefix, or decimal with no prefix. Never bare hex.
- Policies are stateless per-call rules. There are no amount limits, budgets,
  daily caps, or spend counters, so never promise those — a rule bounds *which*
  calls may be made, not how much they move.

## The three outcomes

Every call in a plan is graded on its own against the whole rule set:

| Outcome | When | What happens |
| --- | --- | --- |
| `allowed` | every call matched an `allow` rule and every guard held | signs automatically, no prompt |
| `requires_approval` | some call matched no rule | queues for explicit human approval in the CLI |
| `rejected` | some call matched a `deny` rule | refused outright: nothing signs, nothing queues, and no approval overrides it |

The two negative outcomes are not the same, and the difference decides how you
propose. A call **no rule covers** queues — that is the ordinary path, and it is
fine for a policy to leave routine one-offs uncovered. A call a **`deny` rule
matches** is foreclosed: it never reaches the pending queue, sending it only
fails, and the only way forward is another policy change. Reach for `deny` when
the user wants something shut off, not merely gated.

Only a `deny` rule rejects. Every other refusal — no matching rule, the
`native_value` guard, `max_calls_per_batch`, an ungoverned chain — queues for
approval.

Rules are an unordered **set**: any matching `deny` beats every `allow`, so a
rule means the same wherever it sits, and one blanket `deny` closes something
off regardless of what else the document grants.

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
are all optional predicates, ANDed together. `value` is this call's native value
in wei; `from` is rarely needed, since a plan's sender is already the selected
wallet. `{"eq": "0x"}` on `calldata` is the plain-native-send idiom.

**An absent slot constrains nothing.** A rule with only `to` permits every
function that contract has, including any batching entry point. Write the
`calldata` slot unless the user genuinely wants the whole contract.

## Predicates

One vocabulary applies to every slot and, through `selector`, to every decoded
argument underneath it.

| Predicate | Meaning |
| --- | --- |
| `"any_value"` | Matches anything, including calldata the wallet cannot decode. |
| `{"eq": "…"}` | Equal to one literal. |
| `{"in": ["…", "…"]}` | Equal to one of a set. Never empty. |
| `{"selector": {"abi": "…", "args": {…}}}` | The `bytes` value is a call to this exact function; `args` constrain its parameters by name, and a parameter left out is unconstrained. |
| `{"each": …}` | Every element of an array satisfies the inner predicate; an empty array passes vacuously. |
| `{"any": [...]}` | At least one branch matches. Empty never matches. |
| `{"all": [...]}` | Every branch matches. Empty matches vacuously. |
| `{"not": …}` | The inner predicate does not match. |
| `{"length": …}` | Element count of an array, or byte length of `bytes` or `string`, as a `uint256`. |

Predicates are type-checked against the signature they sit under when the policy
is installed, so a rule that could only ever fail is refused then rather than
silently never matching at signing time: `selector` needs `bytes`, `each` needs
an array, `length` needs an array, `bytes`, or `string`, and every literal must
parse as its parameter's type and fit that type's declared width.

- `"$self"` is this wallet's own address, and the only variable there is. Write
  `{"eq": "$self"}` for the recipient of a swap or claim rather than hard-coding
  an address; it is a literal, so it also sits in a set beside named addresses —
  `{"in": ["$self", "0x…"]}`. It compares only against addresses, and any other
  `$name` is refused when the policy is installed.
- Every other address is named in the policy, with `eq` or `in`. There is no
  predicate that defers to the token database or the address book: those
  describe a transaction to the person approving it and decide nothing. Naming
  the addresses here is also what lets the permission diff show the owner
  exactly what a proposal would add.
- A `selector` predicate must give the function's full signature with every
  parameter named. The four-byte selector is derived from it.

## What a rule cannot be talked out of

Arguments are decoded strictly: the wallet re-encodes what it decoded, requires
the original bytes back, and checks every word against its declared width.
Calldata failing that is *undecided* rather than absent — it satisfies no
`allow`, and it trips every `deny` that named its selector. An alternate
encoding therefore cannot slip a call past a rule written to stop it, and cannot
satisfy one written to permit it either.

Nothing beyond the plan's own bytes and this wallet's address reaches a
decision: not the token database, not the address book, and nothing the RPC
reported — balances, transfer logs, gas, or whether the simulation succeeded.
Nor the clock: a queued request never expires, and no setting gives it a
deadline. Simulation gates signing separately, as a precondition rather than a
policy predicate.

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
- Propose the complete replacement document, never a patch, with
  `source_revision` set to the active revision from `wallet_get_policy`.
- The user reviews a minimized permission diff plus your rationale and applies
  it with `ekubo-wallet policy review <wallet-id>` in their own terminal; no MCP
  tool can change the active policy. Write the rationale for a human: what they
  asked for, which rules enable it, and why the predicates are drawn where they
  are.
- A newer proposal replaces a pending one, and any policy change invalidates
  every approval not yet signed.
