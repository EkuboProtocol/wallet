# Policies

A policy is `chains` → decimal chain ID or `"*"` → address-keyed maps. The `"*"`
entry applies only when no exact chain ID entry exists, so an exact entry
replaces rather than extends the fallback. Without a wildcard, a permission for
an address on one chain never applies to that address on another chain. Each
chain policy independently configures the maximum calls in one atomic batch,
native value per transaction, non-token targets with allowed four-byte selectors
or an explicit any-calldata opt-in, approval spenders with per-token ceilings,
and token policies with a direct-transfer amount limit and recipient maps. Exact
address entries always take precedence over wildcards.

Amounts are decimal strings in the asset's smallest unit: `10000000000` is
10,000 units of a six-decimal token. There is no amount wildcard; use a
deliberately large integer for an effectively unbounded ceiling. A wildcard
token rule applies its limit separately to each token it covers rather than
pooling unlike raw units.

Every predicate is decided from the execution plan's own bytes. Nothing the RPC
reports — observed balances, transfer logs, gas, or whether the simulation
succeeded — reaches a policy decision. That is deliberate: the configured
endpoint is the only witness to a simulation, so a rule scored against what it
reported is one a dishonest endpoint can relax by misreporting what a
transaction did, while still reading like a limit that binds. A limit that
silently stops binding is worse than no limit, because the author trusts it.

The cost is a real gap, and it is better known than discovered. A token moved
without appearing in calldata — pulled by a router, or spent by a counterparty
under an allowance granted earlier — is not bounded by `max_transfer_amount`,
because nothing in the plan declares that amount. What bounds it is whatever
authorized the call in the first place: the `targets` entry and selector that
permitted the router, and the `approval_spenders` ceiling that decided how much
that spender could ever pull. Write those two as the real limit on a routed
spend; `max_transfer_amount` bounds a direct `transfer` and nothing else.

Simulation still runs, and still gates signing. A plan that does not simulate
successfully is refused whatever the policy says, and the balance changes a
simulation reports are shown at approval time so a human sees the predicted
effect. Neither of those is a policy predicate: one is a precondition, the other
is a display.

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
