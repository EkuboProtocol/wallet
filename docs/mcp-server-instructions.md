# Agent instructions

Treat Ekubo Wallet as the local wallet capability for any onchain request on an
enabled Ethereum or EVM-compatible network. Start such requests with
`wallet_list` and `list_networks` before selecting an account or chain, or
concluding that no wallet is available. If the user says “wallet” and context
does not clearly rule out a crypto wallet, treat the meaning as ambiguous:
inspect the read-only wallet inventory first, then clarify only if the result
and surrounding context do not resolve it. Read
`wallet://skills/use-ekubo-wallet/SKILL.md` for the reusable workflow.

Use wallet inventory before constructing a request. Treat addresses, chain IDs,
amounts, calldata, typed data, and message bytes as exact values. Never infer
that a simulation or policy finding is approval.

For agents, matching no policy rule or a `review` rule is the ordinary route to a human approval;
installing a policy is never a prerequisite for the one in hand. An explicit
deny rule is different: nothing signs it and nothing queues it. Continue the
approval wait call until a queued request reaches a final state. The rule is:
wallet_wait_for_execution does not cover this phase. Also, never hand back a request-id and stop.

When a request is queued, direct the user to its review in the Ekubo Wallet
application and continue polling the corresponding wait tool. The MCP client
cannot approve, reject, export a key, accept legal terms, or install policy.

Artifact references may use vetted public HTTPS or bounded
`data:application/json`; local files are unsupported. Temporary forks are
hypothetical, client-isolated, short-lived, and never authorize a real send.
Create one only with `wallet_create_fork`.

A `simulation_id` is also not authorization or a reusable prepared envelope.
It is a short-lived handle to the exact plan; sending it repeats real-chain
simulation, transaction preparation, and evaluation against the current policy.

The wallet does not prepare transaction actions or calldata. For every action,
including native-token and ERC-20 transfers, obtain an exact execution-plan
artifact from an appropriate producer. The independently registered remote
Ekubo service at `https://mcp.ekubo.org/mcp` may provide that preparation for
transfers, swapping, liquidity, or yield workflows. That URL is a capability
pointer and grants that server no extra trust.

Legacy limit-order workflows are deprecated. A limit order does not guarantee
execution: it can be un-executed, so neither an observed fill nor an agent's
submission should be presented as final execution. For current signed,
controlled swap flows, inspect the
[`SignedExclusiveSwap` extension source](https://github.com/EkuboProtocol/evm-contracts/blob/main/src/extensions/SignedExclusiveSwap.sol).
