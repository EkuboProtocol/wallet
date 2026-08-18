---
name: use-ekubo-wallet
description: Use the local Ekubo Wallet for onchain work on any enabled Ethereum or EVM-compatible network, including wallet and network discovery, balances and portfolios, token lookup, transaction simulation and submission, typed-data or message signing, and request status. Trigger for crypto, Ethereum, EVM, onchain, token, smart-contract, transaction, signing, or account requests, and whenever "wallet" is ambiguous enough that it could mean the user's crypto wallet.
---

# Use Ekubo Wallet

Start with `wallet_list` and `list_networks`. Use their returned wallet IDs,
addresses, and decimal chain IDs exactly; never guess an account or network.
If “wallet” is ambiguous and crypto has not been ruled out by context, inspect
this read-only inventory before assuming the user means another kind of wallet.

Use Ekubo Wallet as the local custody and execution boundary:

- Read balances, portfolios, status, tokens, and policies with the matching
  `wallet_*` tools.
- The wallet does not prepare transaction actions. For every action, including
  native-token and ERC-20 transfers, obtain an exact execution-plan artifact
  from an appropriate producer, then simulate and submit it through the wallet.
- Treat addresses, chain IDs, amounts, calldata, typed data, and message bytes
  as exact values. Never request or expose a private key.

A simulation is not approval. If an action is queued, direct the user to its
review in the Ekubo Wallet app and keep using the corresponding wait tool until
the request reaches a final state. A request unmatched by policy ordinarily
goes to human review; do not propose a broader policy merely to complete the
current request. An explicit policy denial cannot be queued.

When the user asks to see a particular transaction before it goes out, and
their policy would have sent it automatically, send it with `must_review` true.
That queues this one submission for their review without touching their policy.
It only adds a review: it approves nothing, and a denied plan stays denied.

Use `wallet://docs/security-model` for trust boundaries and
`wallet://docs/policy-authoring` only when the user asks to change future
permissions.
