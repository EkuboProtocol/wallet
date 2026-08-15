# Policy authoring for agents

Read the active policy and schema before proposing a complete replacement.
Bind the proposal to the returned revision and explain its purpose. An agent
cannot install a policy: the owner reviews a minimized permission diff in the
native Policies screen. Core compares the proposed document with the current
policy at the persistence boundary. A widening or ambiguous transition requires
OS owner authentication; a transition that core proves only tightens authority
can be installed from the owner UI without an additional OS challenge.

Policy version 1 is intentionally small. It contains one ordered `rules` list.
Every rule must have an `effect` of `allow`, `review`, or `deny`. Matchers are
flat fields on the rule: `chain_id`, `to`, `native_value`, and `calldata`
describe one planned call, while `transaction_type`, `nonce`, `gas_limit`,
`max_fee_per_gas`, `max_priority_fee_per_gas`, `delegation`, `envelope_to`, and
`envelope_native_value` describe the prepared transaction envelope outside
that call. Present matchers are ANDed;
an omitted matcher means any value. Rules are evaluated from top to bottom and
the first matching rule decides each call. A call reaching the end needs owner
review, as does a matching `review` rule. A matching deny rejects without queuing
or offering an approval override. Calls are evaluated
independently, then the transaction takes the least-privileged result: any
deny rejects it, otherwise any review or unmatched call queues it, and only a
batch whose every call resolves to allow can sign automatically.

Prepared-envelope matchers are evaluated only after simulation and exact
transaction preparation. A rule containing one cannot match a context with no
prepared envelope. `delegation` matches only the signed EIP-7702 authorization
target; a transaction with no authorization does not match it.
Documents are limited to 256 rules.

The empty policy is the default and asks the owner about every transaction. A
matcherless deny rule disables transaction signing. A matcherless allow rule is
the danger-marked **Allow anything** preset. All three presets still go through
the same diff, current-state check, and atomic core installation path. Whether
an OS challenge is required depends on the transition from the active policy:
only a provable tightening can omit it.

The guided editor is the primary interface. It presents rules in their actual
order and supports adding, editing, removing, and moving them. Use exact or set
predicates for networks, targets, and native value. For calldata, name the full
canonical ABI function signature and constrain typed arguments. The predicate
language also supports integer comparisons (`lt`, `lte`, `gt`, `gte`) and
composition with `any`, `all`, `not`, `each`, `selector`, and `length`.
Advanced JSON is an escape hatch, not a separate policy path.

A selector ABI must name every top-level parameter, and `args` refers to those
names. For example, an ERC-20 approval capped at one million raw units is:

```json
{
  "selector": {
    "abi": "approve(address spender, uint256 amount)",
    "args": {
      "spender": { "eq": "0x1111111111111111111111111111111111111111" },
      "amount": { "lte": "1000000" }
    }
  }
}
```

Tuple components are constrained positionally because Solidity selector types
do not preserve component names. A `tuple` array must have exactly the ABI
tuple's arity; a predicate constrains that position and `null` leaves just that
position unconstrained. This example constrains the first and third components:

```json
{ "tuple": [{ "eq": "1" }, null, { "eq": "true" }] }
```

Tuple predicates nest for nested tuples. For an array of tuples, compose the
shapes as `{ "each": { "tuple": [...] } }`. Use the same exact-arity rule at
every tuple level. The explicit `"any_value"` predicate remains valid, but
`null` is the canonical spelling for an unconstrained tuple position.

Prefer the narrowest rule that expresses the operation. For example, put a
matcherless `review` rule first to review every transaction, or constrain
`envelope_native_value` with `gt` to review any prepared transaction moving
more than a threshold from the wallet. Put exceptions before
broad rules: order is authority, and installation rejects a later rule that is
provably shadowed by an earlier one. There is no `from` matcher, chain map,
batch-count limit, or cumulative budget. `native_value` is per call;
`envelope_native_value` is the value on the prepared outer transaction.

For tightening comparisons, authority is ordered `deny < review < allow`.
Core permits a challenge-free owner-UI installation only when it can prove the
whole transition moves downward in that order without broadening a matcher.

Never rely on display labels, token symbols, or decoded RPC effects for
authorization. They are review context, not policy inputs. Prepared envelope
facts come from the wallet's own exact transaction preparation. The only policy variable is `$self`,
usable where an address literal is expected and
resolved to the signing wallet.
