# Authoring wallet policies

A policy is one JSON document that decides which transactions this wallet
signs automatically; anything a policy does not permit queues for explicit
human approval instead of failing. The complete schema is at
wallet://schemas/policy. Propose changes with wallet_propose_policy, always
starting from the exact document and revision returned by wallet_get_policy.

## Structure

- `chains` maps a canonical decimal chain ID (or `"*"` for every chain) to
  that chain's rules. An exact chain key completely replaces `"*"` for that
  chain; the two are never merged.
- Every amount is a decimal string in the asset's smallest unit (wei for
  native value, base units for tokens — respect each token's decimals).
- Addresses are lowercase `0x` strings; `"*"` is a wildcard key.
- Policies are stateless per-transaction rules. There are no daily limits,
  rolling windows, or spend counters, so never promise those.

## Per-chain rules

- `native.max_value_per_transaction`: total wei the transaction may send.
- `max_calls_per_batch`: how many calls one atomic batch may contain.
- `targets`: which contracts may be called and with what calldata —
  `allow_empty_calldata` (plain native sends), `allow_any_calldata`, or an
  `allowed_selectors` map of exact four-byte selectors.
- `approval_spenders`: which spenders may receive ERC-20 approvals (including
  recognized EIP-712 permits), per token, with `max_amount` caps.
- `tokens`: per-token `max_transfer_amount` (measured from the transfer
  activity of the plan's simulation) and the exact `transfer_recipients`
  allowed.

## Proposing well

- Grant the minimum that enables the user's stated goal: exact targets,
  selectors, spenders, tokens, recipients, and bounded amounts — widen a
  wildcard only when the user explicitly wants that.
- To enable a planned action, work backwards from it: an ERC-20 transfer
  needs the token under `tokens` with the recipient listed and a sufficient
  spend limit; an approval or permit needs the spender under
  `approval_spenders` for that token; a contract interaction needs its target
  and selector under `targets`; sending native value needs a native limit.
- The user reviews a minimized permission diff plus your rationale. Write the
  rationale for a human: what they asked for, which lines enable it, and why
  the amounts are sized as they are.
