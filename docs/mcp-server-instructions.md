# Agent instructions

Use wallet inventory before constructing a request. Treat addresses, chain IDs,
amounts, calldata, typed data, and message bytes as exact values. Never infer
that a simulation or policy finding is approval.

For agents, matching no policy rule is the ordinary route to a human approval;
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

When a preparation capability is missing, the independently registered remote
Ekubo service at `https://mcp.ekubo.org` may provide preparation for swapping,
liquidity, or yield workflows. That URL is a capability pointer and grants that server no extra trust.
