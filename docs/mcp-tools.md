# MCP tools

| Tool | Purpose |
| --- | --- |
| `wallet_list` | Public wallet metadata plus configured network names, chain IDs, and RPC URLs. Never key material. |
| `wallet_propose_network` | Suggest a complete network profile for the owner to accept in `ekubo-wallet network review`. Writes nothing: a proposal for a configured chain ID is an edit of that network, one for an unconfigured chain ID is an addition, and neither resolves until accepted. The endpoint is admitted when proposed and its chain ID verified when accepted. A name or alias belonging to a different chain is refused outright, since no confirmation could resolve it. |
| `wallet_get_status` | Address, native balance, transaction count, and current EIP-7702 delegation. |
| `wallet_get_policy` | The active policy and its revision. |
| `wallet_batch_eth_call` | One to 128 ordered reads with optional inline decoding. Accepts a `fork_id` to read simulated state. |
| `wallet_list_tokens` | Page through the tokens the owner has confirmed, optionally per chain. |
| `wallet_search_tokens` | Find confirmed tokens by symbol, name, or exact address, optionally within one chain. |
| `wallet_propose_tokens` | Suggest up to 1000 tokens, with the list's own symbol/name/decimals, for the owner to confirm in the CLI. Inline or by `token_list_reference`. Writes no names. |
| `wallet_get_portfolio` | Native balance plus every known token's nonzero balance for any address, via Multicall3, pinned to a reported block. |
| `wallet_get_balances` | Balances for an explicit list of up to 1000 token addresses (0x0 = native), via the Ekubo TokenDataFetcher lens where deployed, else per-token Multicall3 reads. Failures read as zero; only nonzero balances return. |
| `wallet_decode_abi_result` | Local decoding of previously obtained bytes. No RPC or transaction work. |
| `wallet_simulate_execution_plan` | Resolve the exact plan from the producer's `artifact_reference` envelope, passed through verbatim as `reference` — the wallet fetches the body (public https or an inline `data:application/json` URI) and verifies the envelope's integrity digest and byte count — then simulate and policy-evaluate it without signing. Against real chain state it returns a `simulation_id` the send can consume instead of simulating again. With a `fork_id`, simulates on top of that fork and appends the plan on success, and returns no `simulation_id`: fork results are hypothetical. |
| `wallet_create_fork` | Open a temporary simulation fork pinned to the current block, for simulating a sequence of dependent actions end to end. |
| `wallet_discard_fork` | Discard a fork and everything applied to it. Forks also expire on their own. |
| `wallet_send_transfers` | Any non-empty list of `{token, to, amount}` items (`token` `0x0` = native), which may mix the native token and any number of ERC-20 contracts, sent as one transaction. Takes the same `on_simulation_failure` choice as `wallet_send_execution_plan`. |
| `wallet_send_execution_plan` | Resolve a plan from a producer `reference` envelope, then validate, simulate, policy-check, sign, and broadcast it; send a `simulation_id` already produced against real chain state without simulating it again; or submit an already-approved request ID. Exactly one of the three. `on_simulation_failure` chooses what a failed simulation does: `request_approval` (the default) queues it for the user to override, `fail` returns the error and queues nothing. Policy denials queue for approval either way — only the user can grant a policy exception. |
| `wallet_wait_for_approval` | Poll one pending request for up to 55 seconds; the agent repeats it after each timeout until the CLI approves or rejects. The only tool that blocks through the human pause. Cannot approve or submit anything itself. |
| `wallet_get_execution_status` | Reconcile a submitted request against the chain. |
| `wallet_attempt_cancel` | Outbid a broadcast-but-unmined transaction with a 0-value self-send at its own nonce. The one signing path that consults no policy: every field derives from the stored envelope and the chain — target is the wallet itself, calldata empty, no authorization list, fees from the incumbent envelope plus a bounded market bump — so it can only narrow an in-flight authorization to nothing, at the cost of gas. Fails if the transaction already mined; repeating the call reprices a cancellation that is itself stuck. |
| `wallet_wait_for_execution` | Wait for the plan to be executed: bounded polling for the receipt, plus an optional number of confirmations before resolving. Polls a broadcast transaction only — a request still awaiting approval returns immediately, so it never substitutes for `wallet_wait_for_approval`. |
| `wallet_sign_typed_data` | Queue an exact EIP-712 payload for CLI approval. Always queues; no policy path, not even for recognized permits (ERC-2612, canonical Permit2), which are decoded into the approvals they grant as review information only. |
| `wallet_wait_for_typed_data` | Poll a pending typed-data request; returns the signature once the CLI approves and signs. Cannot approve or sign itself. |
| `wallet_sign_message` | Sign an exact EIP-191 `personal_sign` message — dapp logins (ERC-4361), ownership proofs, off-chain attestations. Always queues for CLI approval; no policy path. Raw `eth_sign` over a bare 32-byte digest is refused. |
| `wallet_wait_for_message` | Poll a pending message request; returns the signature once the CLI approves and signs. Cannot approve or sign itself. |
| `wallet_address_book` | Read-only lookups of user-configured per-chain address aliases. Mutations are CLI-only and confirmed in the terminal. |
| `wallet_get_legal` | Legal acceptance status plus the full Terms of Service, Privacy Policy, or Third-Party Licenses text. The only tool available before acceptance. |
| `wallet_propose_policy` | Propose a complete replacement policy for human review, bound to the active revision, with a required rationale. One proposal per wallet; the latest prevails. Applied only via `ekubo-wallet policy review`, which shows a minimized permission diff. |

MCP operations select networks only with canonical decimal `chain_id` strings
such as `"1"` or `"4663"`; profile names are CLI and display metadata. No tool
schema contains a private key, password, mnemonic, seed, or policy-administration
input. There is no spend-history tool, because there is no spend accounting.

This wallet builds no protocol calldata. Its only two internal constructors
are the ERC-20 `transfer` encoding behind `wallet_send_transfers` and the
fixed-shape, empty-calldata cancellation envelope — so swapping, providing
liquidity, and claiming or compounding yield need a tool that produces
execution plans. The server
instructions point an agent at the Ekubo MCP server (`https://mcp.ekubo.org`)
when the user wants one of those and nothing connected can prepare it. That is
a capability pointer, not a trust statement: a plan from there is validated,
simulated, and policy-checked exactly like a plan from anywhere else, and no
code path in this process treats a plan's origin as meaningful.

Plans arrive by reference rather than as inline tool arguments, because the
agent relaying a producer's tool result into a wallet tool call pays for
every byte of it as model output. A producer returns an `artifact_reference`
envelope — the https URL holding the plan body and an `integrity` block
(keccak256 of its exact bytes plus their count) — and the agent passes the
whole envelope through unchanged as the tool's `reference` argument. The
wallet fetches the body itself (public https only: default port, no
credentials, fragments, or redirects, no private or reserved addresses even
after DNS resolution, 16 MiB cap), recomputes the digest and byte count,
refuses a mismatch, and then validates the plan exactly as if it had been
supplied inline. The body is the only source of truth: the envelope carries
no descriptive duplicate of its contents for anyone to trust or cross-check. The envelope tolerates additive producer fields;
`integrity` is strict, and both it and `bytes` are mandatory for anything
fetched over the network. A plan held locally travels as an envelope whose
URL is a `data:application/json;base64` URI of its exact bytes and touches no
network (there the bytes are the reference, so integrity is verified only
when supplied). A 404 means the reference expired: re-run the producer's
preparation tool. These fetches are the only outbound requests this process
makes that are not a configured chain RPC.

Read-call bundles travel under the same discipline. A producer returns a
`read_calls_reference` envelope whose stored body is an exact
`wallet_batch_eth_call` argument object (`chain_id`, optional
`block_parameter` and `from`, `calls` with their decode plans), and the agent
passes the whole envelope unchanged as `wallet_batch_eth_call`'s `reference`
argument with the reference's `chain_id` and no inline `calls`. The same
admission policy, integrity verification, and size cap apply. The fetched
body is parsed against exactly the inline argument surface with unknown
fields rejected, so a bundle can never carry a `fork_id`, a nested
reference, or any field the tool call itself did not declare, and its
`chain_id` must equal the one the tool call selected. The body alone supplies
`block_parameter`, `from`, and `calls`; `fork_id` remains a tool-call
decision, so a bundle can be read against a fork.

`eth_simulateV1` is the most expensive request this wallet makes, and an agent
that simulates a plan to show the user what it does should not pay for that
work twice. A simulation against real chain state returns a `simulation_id`;
passing it to `wallet_send_execution_plan` instead of the plan sends exactly
what was simulated, with no second simulation. The recorded entry carries the
plan too, so the two cannot disagree. It is usable once, expires two minutes
after it was produced, and is refused if the wallet, chain, or active policy
revision has moved since — in each of those cases simulate again and send the
new identifier. Fork simulations return no `simulation_id` at all.

On simulation failure, `simulation.failure` reports a category, the raw revert
bytes and selector when available, decoded `Error(string)`/`Panic(uint256)`
data, and a recommended action. Retry identical calldata only for
`retry_same_plan`, which normally means a transient RPC failure; for
`reprepare_plan`, including any revert or slippage, return to the originating
tool for freshly prepared calldata.

## Token database and portfolio

The token database is where a token's **name** comes from. When the owner
reviews a transaction, the symbol they read is looked up here and nowhere
else; a token with no row is shown as `0xaddress (unlisted token)` and its
amounts stay in base units. Nothing in the signing or policy path reads it,
but a name the owner trusts is worth forging, so the rows live **inside the
encrypted policy database** (`policies.db`) where a file edit outside this
process cannot alter them. A leftover plain `tokens.db` from an unreleased
build is deleted on sight rather than imported — a file anyone can write is
not a curator, and the whole point of the table is that someone the owner
chose put every row in it.

Names come from token lists, never from token contracts. A contract's
`symbol()` returns whatever its author wrote, so reading it would let any
deployed address call itself `USDC` on the screen where the owner decides. A
curated list is a claim by someone the owner chose to trust; a contract's own
answer is a claim by the counterparty they are being protected from.

**Only the owner can name a token.** `wallet_propose_tokens` writes to a
separate proposals table that no display path reads. Suggestions become names
only when the owner confirms them with `ekubo-wallet token review`, which
groups them by the list that vouched for them so a whole list is one decision
rather than hundreds. The owner can also import a list themselves with
`ekubo-wallet token import <file>`, which reads the standard token-list shape,
or pipe one in with `ekubo-wallet token import -`:

```sh
curl -fsSL https://prod-api.ekubo.org/tokens | ekubo-wallet token import -
```

The pipe exists because a list is the largest thing an agent is ever asked to
carry, and carrying it costs output tokens per field — roughly fifty thousand
of them for a thousand-token list. A shell pipe costs none, because the bytes
never enter the conversation at all. It changes nothing else: the review
screen still opens (every prompt reads the terminal, not standard input), and
nothing is named until the owner accepts it.

Agents get the same saving through a `token_list_reference` envelope, below.

The chain is asked one question, and it is not about identity. When the owner
accepts, each address is checked to confirm something token-like lives there,
so a typo or a dead entry cannot become a named row. Only whether it answers
is used; what it answers is never decoded.

`decimals()` is never called. Every value a contract returns is chosen by
whoever deployed it, `decimals` no less than `symbol`, so checking the list
against it would let the counterparty overrule the curator the owner picked.
The list is the authority on both the name and the scale of every amount
displayed for a token. A tripwire test fails the build if a `decimals()` call
reappears.

Integrity rules are structural. The `(chain_id, address)` pair is the primary
key, so an entry is never overwritten and a second list cannot rename a token
the owner already confirmed. Hostile metadata is control-stripped and
length-capped before storage, and again at render time: a stored symbol keeps
only the characters real symbols use and is dropped entirely if it still
contains `0x`, so it cannot forge the `SYMBOL (0xaddress)` suffix.

`wallet_get_portfolio` turns the database into a portfolio reader for **any**
address, not just configured wallets: one Multicall3 batch per 200 tokens
reads `balanceOf` for every known token on the chain, alongside the native
balance (`getEthBalance`) and a pinned block number, on any EVM chain where
Multicall3 is deployed — which is effectively all of them. Zero balances are
omitted unless requested; balances are raw smallest-unit decimal strings with
the stored decimals/symbols attached.

Inspect the database from the CLI with `ekubo-wallet token list [chain-id]`,
or find one with `ekubo-wallet token search <query>`.

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
Calls are supplied either inline or by a producer's `read_calls_reference`
envelope passed verbatim as `reference` (mutually exclusive with inline
`calls`; with `reference`, leave `from` unset and `block_parameter` at its
default — the fetched body governs both).

Token lists are the third referenced artifact, and the one where the saving is
largest. A producer returns a `token_list_reference` envelope whose stored
body is a curated token list; the agent passes it verbatim as the `reference`
argument of `wallet_propose_tokens` or `wallet_get_balances`, with no inline
`tokens`. The same admission policy, integrity verification, and size cap
apply, plus a 4 MiB list-specific cap and the existing 1000-entry limit.

The parser is deliberately more tolerant than the read-call one, because a
token list is a published document rather than an exact argument object:
`chain_id` is accepted alongside `chainId`, a chain ID may be a JSON number, a
decimal string, or `0x`-hex, and unknown fields are ignored so a curator
adding a logo URL does not break the import. Entries whose address is not a
20-byte EVM address — the Starknet rows in a multi-ecosystem list — are
skipped and counted in `skipped_non_evm` rather than failing the list.

Tolerance here costs nothing, because a token list authorizes nothing. It
carries display names that reach a proposals table no display path reads, and
every one of them still waits for the owner in `ekubo-wallet token review`.
`wallet_get_balances` does not even read the names: it takes the addresses on
the selected chain and ignores the rest, so one canonical multi-chain list
serves every chain without being restated.

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
