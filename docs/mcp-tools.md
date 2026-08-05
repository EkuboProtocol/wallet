# MCP tools

| Tool | Purpose |
| --- | --- |
| `wallet_list` | Public wallet metadata plus configured network names and chain IDs. Never key material or RPC URLs. |
| `wallet_add_network` | The only MCP configuration mutation. Requires a complete profile and OS owner authentication, and never replaces an existing chain ID. |
| `wallet_get_status` | Address, native balance, transaction count, and current EIP-7702 delegation. |
| `wallet_get_policy` | The active policy and its revision. |
| `wallet_batch_eth_call` | One to 128 ordered reads with optional inline decoding. Accepts a `fork_id` to read simulated state. |
| `wallet_list_tokens` | Page through the local token database, optionally per chain. |
| `wallet_add_token` | Verify one token's symbol/name/decimals on-chain via Multicall3 and store it. Duplicate chain/address pairs fail. |
| `wallet_import_token_list` | Bulk-import up to 1000 tokens; each new token is verified on-chain, existing pairs are skipped, never overwritten. |
| `wallet_get_portfolio` | Native balance plus every known token's nonzero balance for any address, via Multicall3, pinned to a reported block. |
| `wallet_get_balances` | Balances for an explicit list of up to 1000 token addresses (0x0 = native), via the Ekubo TokenDataFetcher lens where deployed, else per-token Multicall3 reads. Failures read as zero; only nonzero balances return. |
| `wallet_decode_abi_result` | Local decoding of previously obtained bytes. No RPC or transaction work. |
| `wallet_simulate_execution_plan` | Exact-plan simulation and policy evaluation without signing. With a `fork_id`, simulates on top of that fork and appends the plan on success. |
| `wallet_create_fork` | Open a temporary simulation fork pinned to the current block, for simulating a sequence of dependent actions end to end. |
| `wallet_discard_fork` | Discard a fork and everything applied to it. Forks also expire on their own. |
| `wallet_send_transfers` | Any non-empty list of `{token, to, amount}` items (`token` `0x0` = native), which may mix the native token and any number of ERC-20 contracts, sent as one transaction. Takes the same `on_simulation_failure` choice as `wallet_send_execution_plan`. |
| `wallet_send_execution_plan` | Validate, simulate, policy-check, sign, and broadcast; or submit an already-approved request ID. `on_simulation_failure` chooses what a failed simulation does: `request_approval` (the default) queues it for the user to override, `fail` returns the error and queues nothing. Policy denials queue for approval either way — only the user can grant a policy exception. |
| `wallet_wait_for_approval` | Poll one pending request for up to 55 seconds; the agent repeats it after each timeout until the CLI approves or rejects. Cannot approve or submit anything itself. |
| `wallet_get_execution_status` | Reconcile a submitted request against the chain. |
| `wallet_wait_for_execution` | Wait for the plan to be executed: bounded polling for the receipt, plus an optional number of confirmations before resolving. |
| `wallet_sign_typed_data` | Sign an exact EIP-712 payload. Recognized permits (ERC-2612, canonical Permit2) are policy-checked like `approve()` calls and sign automatically when allowed; everything else queues for CLI approval. |
| `wallet_wait_for_typed_data` | Poll a pending typed-data request; returns the signature once the CLI approves and signs. Cannot approve or sign itself. |
| `wallet_sign_message` | Sign an exact EIP-191 `personal_sign` message — dapp logins (ERC-4361), ownership proofs, off-chain attestations. Always queues for CLI approval; no policy path. Raw `eth_sign` over a bare 32-byte digest is refused. |
| `wallet_wait_for_message` | Poll a pending message request; returns the signature once the CLI approves and signs. Cannot approve or sign itself. |
| `wallet_address_book` | Read-only lookups of user-configured per-chain address aliases. Mutations are CLI-only with owner authentication. |
| `wallet_get_legal` | Legal acceptance status plus the full Terms of Service, Privacy Policy, or Third-Party Licenses text. The only tool available before acceptance. |
| `wallet_propose_policy` | Propose a complete replacement policy for human review, bound to the active revision, with a required rationale. One proposal per wallet; the latest prevails. Applied only via `ekubo-wallet policy review`, which shows a minimized permission diff. |

MCP operations select networks only with canonical decimal `chain_id` strings
such as `"1"` or `"4663"`; profile names are CLI and display metadata. No tool
schema contains a private key, password, mnemonic, seed, or policy-administration
input. There is no spend-history tool, because there is no spend accounting.

This wallet builds no calldata, so swapping, providing liquidity, and claiming
or compounding yield need a tool that produces execution plans. The server
instructions point an agent at the Ekubo MCP server (`https://mcp.ekubo.org`)
when the user wants one of those and nothing connected can prepare it. That is
a capability pointer, not a trust statement: a plan from there is validated,
simulated, and policy-checked exactly like a plan from anywhere else, and no
code path in this process treats a plan's origin as meaningful.

On simulation failure, `simulation.failure` reports a category, the raw revert
bytes and selector when available, decoded `Error(string)`/`Panic(uint256)`
data, and a recommended action. Retry identical calldata only for
`retry_same_plan`, which normally means a transient RPC failure; for
`reprepare_plan`, including any revert or slippage, return to the originating
tool for freshly prepared calldata.

## Token database and portfolio

The wallet keeps a local token database in a **separate, unencrypted SQLite
file** (`tokens.db`) beside the encrypted policy database. Token metadata is
public display data: MCP tools may write it without owner authentication, and
nothing in the signing or policy path ever reads it.

Its integrity rules are structural rather than procedural. The
`(chain_id, address)` pair is the primary key, so a conflicting entry is
impossible: `wallet_add_token` fails on a duplicate, and
`wallet_import_token_list` skips existing pairs and reports counts — an entry
is never overwritten. Every new token's `symbol`, `name`, and `decimals` are
read from the token contract itself through Multicall3 on the configured
chain's RPC, not trusted from the submitted list, and contracts that answer
neither `symbol()` nor `decimals()` are rejected. Hostile metadata is
control-stripped and length-capped before storage.

`wallet_get_portfolio` turns the database into a portfolio reader for **any**
address, not just configured wallets: one Multicall3 batch per 200 tokens
reads `balanceOf` for every known token on the chain, alongside the native
balance (`getEthBalance`) and a pinned block number, on any EVM chain where
Multicall3 is deployed — which is effectively all of them. Zero balances are
omitted unless requested; balances are raw smallest-unit decimal strings with
the stored decimals/symbols attached.

Inspect the database from the CLI with `ekubo-wallet token list [chain-id]`.

## Simulation forks

A one-shot simulation answers "does this plan work against the chain as it is
now?". It cannot answer "does this whole sequence work?", because step N+1
depends on state step N has not produced yet, and preparation tools reading
chain state mid-sequence would build step N+1 from the wrong world.

`wallet_create_fork(wallet_id, chain_id)` opens a temporary fork pinned to the
current block. Pass its `fork_id` to `wallet_simulate_execution_plan` for each
step in order: the plan runs on top of everything already applied to the fork
and, if execution succeeds, is appended. Pass the same `fork_id` to
`wallet_batch_eth_call`, `wallet_get_balances`, `wallet_get_portfolio`, and
`wallet_get_status` to read the world as it would be after those steps.

A fork is nothing but an ordered list of already-validated plans plus one
pinned parent block. No simulated state is stored: each call replays the whole
list as consecutive `eth_simulateV1` blocks, where every block inherits the
previous block's state, so the configured RPC still executes everything and
there is still no local EVM or `eth_getProof` path. Replay is quadratic in the
calls a session sends, which is why a fork holds at most 8 plans, a wallet
holds at most 4 forks, and forks expire after five minutes.

Forks have no bearing on policy or signatures. A fork cannot create a pending
request, produce signed bytes, mark anything approved, or satisfy a policy
rule. Policy findings on a fork are reported exactly as on a real simulation
but are advisory — an agent learning a sequence would be blocked before
bothering the user is most of the value, and `wallet_get_policy` already
returns the whole policy document anyway. Submission always re-simulates and
re-policy-checks against real chain state, so "it passed on the fork" never
substitutes for that. There is no CLI surface, and no fork state is shown at
approval time.

Every fork-backed result carries a `fork` block with the pinned parent block,
the simulated block the result came from, how many plans are applied, the
expiry, and `hypothetical: true`. Forks deliberately expose no block or time
controls, but `eth_simulateV1` numbers each block it simulates, so applying a
plan advances the simulated block by one and the `block.number` and
`block.timestamp` a contract observes are ahead of the pinned parent. That
artifact is reported rather than hidden. `wallet_get_status` on a fork also
reports the transaction count from the pinned parent, flagged with
`transaction_count_is_pinned_parent`, because simulation runs without
transaction validation and never advances a nonce.

An agent flow is: create fork → simulate the approval on it → read allowances
through it → prepare the swap against those reads → simulate the swap on it →
show the user the net effect of the whole sequence → then submit the real
plans one at a time through the normal approval path, with no `fork_id`.

## Local read decoding

`wallet_batch_eth_call` is the normal read path. It runs ordered reads on a
decimal chain ID, uses Multicall3 by default with an individual `eth_call`
fallback, sends `msg.sender`-dependent calls individually, and can decode each
exact result in the same call. `block_parameter` accepts `latest`, `pending`,
`safe`, `finalized`, `earliest`, or a canonical hexadecimal block quantity.

Five decode plan kinds are supported: `function_result`, `abi_parameters`,
`multicall3`, `function_result_bytes_array`, and `semantic_value`. Complete
inputs for each are in [`examples/abi-decoding.json`](../examples/abi-decoding.json),
which the test suite parses so the documented shapes cannot drift.

Every result carries `decode_status`; a successful RPC call stays `success: true`
even when decoding fails, and `usable: false` marks a failed required decode.
Raw `return_data` is omitted only when `include_raw` is false and every requested
decode succeeded. Decoded integers are decimal strings, addresses are
checksummed, named tuples become objects, and the decoder rejects malformed or
non-canonical bytes, trailing data, ambiguous overloads, and limit violations.

Semantic codecs are separately named and versioned local transformations applied
on top of authoritative generic decoding. A request is only a compatibility
assertion: it cannot install, fetch, import, or execute caller-selected code, and
only an allowlisted adapter compiled into the wallet runs. An unrecognized
identity returns `unsupported_codec` while retaining the original value and raw
bytes.
