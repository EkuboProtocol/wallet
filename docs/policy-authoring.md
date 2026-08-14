# Policy authoring for agents

Read the active policy and schema before proposing a complete replacement.
Bind the proposal to the returned revision and explain its purpose. An agent
cannot install a policy: the owner reviews a minimized permission diff in the
native Policies screen and authenticates before installation.

Policy version 1 is intentionally small. It contains one ordered `rules` list.
Every rule must have an `effect` of `allow` or `deny` and may constrain
`chain_id`, `to`, `native_value`, and `calldata`. Present matchers are ANDed;
an omitted matcher means any value. Rules are evaluated from top to bottom and
the first matching rule decides each call. A call reaching the end needs owner
approval. A matching deny rejects the complete transaction without offering an
approval override. Every call in a batch must match an allow rule.
Documents are limited to 256 rules.

The empty policy is the default and asks the owner about every transaction. A
matcherless deny rule disables transaction signing. A matcherless allow rule is
the danger-marked **Allow anything** preset. All three presets still go through
the same diff, final state check, and OS-authenticated installation path.

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

Prefer the narrowest rule that expresses the operation. Put exceptions before
broad rules: order is authority, and installation rejects a later rule that is
provably shadowed by an earlier one. There is no `from` matcher, chain map,
batch-count limit, cumulative budget, or delegation matcher. `native_value` is
a per-call condition. EIP-7702 delegation safety remains a separate core
preflight check and cannot be weakened by policy JSON.

Never rely on display labels, token symbols, RPC simulation output, or other
network-provided facts for authorization. They are review context, not policy
inputs. The only policy variable is `$self`, usable where an address literal is
expected and resolved to the signing wallet.
