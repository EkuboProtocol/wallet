# Policies

A policy is `chains` → decimal chain ID or `"*"` → address-keyed maps. The `"*"`
entry applies only when no exact chain ID entry exists, so an exact entry
replaces rather than extends the fallback. Without a wildcard, a permission for
an address on one chain never applies to that address on another chain. Each
chain policy independently configures the maximum calls in one atomic batch,
native value per transaction, non-token targets with allowed four-byte selectors
or an explicit any-calldata opt-in, approval spenders with per-token ceilings,
and token policies with per-transaction spend limits and direct-transfer
recipient maps. Exact address entries always take precedence over wildcards.

Amounts are decimal strings in the asset's smallest unit: `10000000000` is
10,000 units of a six-decimal token. There is no amount wildcard; use a
deliberately large integer for an effectively unbounded ceiling. A wildcard
token budget applies its limits separately to each observed token rather than
pooling unlike raw units.

Token spend is measured during the exact RPC simulation. For every concretely
configured token the wallet conservatively uses the larger of the wallet's net
balance decrease and the sum of outgoing standard `Transfer` events, and it
discovers outgoing transfers from other token contracts so a `"*"` token rule
covers them. This catches tokens pulled by routers or pre-existing allowances,
not only direct `transfer` calldata.

Simulation is not a policy setting. Every plan is simulated before it can sign,
and a simulation that does not succeed is an error finding of its own, so a
reverting plan is never allowed no matter what the rest of the document
permits. Policies written before this was fixed may still carry the retired
`require_simulation` field; it is discarded when the document is read.

Policy documents have a generated [JSON Schema](../schemas/policy.schema.json)
derived from the same types the wallet enforces. Print the current one with
`ekubo-wallet policy schema`, and reference it as the top-level `$schema` value
for editor completion. Starting points live in [`examples/`](../examples):

| File | Purpose |
| --- | --- |
| [`policy.json`](../examples/policy.json) | The allow-all profile, one of the two choices `wallet create` offers. |
| [`policies/deny-all.json`](../examples/policies/deny-all.json) | Exactly what `policy require-approval` installs, and the default for imported wallets. |
| [`policies/token-budget.template.json`](../examples/policies/token-budget.template.json) | One chain, one router, one token, with capped allowance and per-transaction spend. |
| [`policies/approval-wildcards.template.json`](../examples/policies/approval-wildcards.template.json) | How exact entries override wildcards for spenders, tokens, and chains. |
| [`policies/allow-all-with-approval.template.json`](../examples/policies/allow-all-with-approval.template.json) | Exactly what `policy allow-all` installs. |

Template chain IDs, addresses, and selectors must be replaced and verified
before use. An agent can help draft a copy, but applying it stays an explicit
human CLI action:

```sh
ekubo-wallet policy validate ./my-policy.json   # parses and digests; changes nothing
ekubo-wallet policy set primary ./my-policy.json
ekubo-wallet policy allow-all primary
ekubo-wallet policy show primary
```

`policy validate` needs no wallet, no database, and no authentication, so a
policy can be drafted and checked before anything exists to apply it to.

A queued request has no expiry, and the policy document has no setting that
gives it one: it waits until the user approves or rejects it, or until a policy
change invalidates it. Nothing about what may be signed is decided by reading
this machine's clock, which its owner — or anything running as them — can set
to whatever they like. A transaction that must not execute after some moment
carries that deadline in the calldata the user approved, where the chain
enforces it and re-simulation at approval time surfaces it as a failure.

`max_calls_per_batch` accepts up to 4096; the transfer and execution-plan tool
schemas impose no list maximum of their own, so real batches are bounded by the
selected policy, memory, encoded transaction size, and the per-chain gas cap.

Policy changes increment a local revision and invalidate every approval that has
not yet been signed.
