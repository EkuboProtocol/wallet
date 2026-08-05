# Ekubo Wallet MCP Server

`ekubo-wallet` is a local EVM wallet, command-line tool, and stdio MCP server.
It enforces transaction policy in the same process that reads the signing key,
and exposes no arbitrary-message, arbitrary-hash, or raw-transaction signing
tool. `ew` is an equivalent short name for the same executable — a symlink on
macOS and Linux and a forwarding shim on Windows — so the OS credential store
sees one client identity and a single keychain grant covers both names.

It is a general-purpose wallet, not a companion to any particular protocol,
dapp, or other MCP server. Any tool can produce a signer-neutral execution plan;
this wallet validates, simulates, and policy-checks every plan identically
regardless of where it came from, and treats all of them as untrusted input.

This is security-sensitive software. It has not been independently audited, and
nothing here should be read as a claim that it has.

## What it provides

- OS-credential-store custody for generated or imported secp256k1 keys.
- A stateless, per-transaction policy for chains, targets, selectors, native
  value, ERC-20 recipients and spends, approval spenders and amounts, and batch
  size.
- Exact execution through a direct EIP-1559 transaction or one atomic Calibur
  batch, with EIP-7702 authorization when required.
- Simulation through the configured RPC's typed `eth_simulateV1` method. There
  is no local EVM, `eth_getProof` state reconstruction, or `eth_call`
  fallback for signing decisions.
- Temporary simulation forks so an agent can simulate a chain of dependent
  actions — and read the world between them — before the user is asked to
  approve the first step. Forks are hypothetical throughout and never sign,
  approve, or satisfy a policy rule.
- SQLCipher-backed policy and pending-transaction storage.
- Deterministic ABI return/error decoding, bounded batch reads, native/ERC-20
  transfer helpers, pending approval, receipt reconciliation, and exact-byte
  rebroadcast after ambiguous submission.

There are deliberately no daily limits, rolling windows, spend counters,
reservations, or spend-history command/tool. Pending transaction rows are
lifecycle records, not spending-accounting state.

## Install from a release binary

Every release attaches prebuilt archives for Linux (x86-64, arm64), macOS
(Intel, Apple Silicon), and Windows (x86-64), plus `SHA256SUMS`, keyless
Sigstore bundles, and GitHub build-provenance attestations.

The installer downloads the archive for your platform, **verifies its SHA-256
checksum against `SHA256SUMS` before extracting anything**, additionally
verifies the Sigstore signature when `cosign` is installed, installs
`ekubo-wallet` and `ew`, registers the server with every agent CLI it detects
(Codex, Claude Code, Gemini CLI, and Cursor), and installs completion for your
login shell:

```sh
curl -fsSL https://raw.githubusercontent.com/EkuboProtocol/wallet-mcp-server/main/install.sh | sh
```

Read [`install.sh`](install.sh) before piping it to a shell. Replace `main` with
an exact release tag for a reproducible installation.

While the repository is private, the installer needs credentials to reach the
release assets. It uses the GitHub CLI when you are logged in (`gh auth login`),
and otherwise honors `GITHUB_TOKEN`.

Useful environment variables:

| Variable | Effect |
| --- | --- |
| `EKUBO_WALLET_VERSION` | Install an exact version instead of the latest release. |
| `EKUBO_WALLET_BIN_DIR` | Install destination. Defaults to `~/.local/bin`. |
| `EKUBO_WALLET_SKIP_AGENTS=1` | Install the binary without touching agent configuration. |
| `EKUBO_WALLET_SKIP_COMPLETIONS=1` | Install the binary without touching shell configuration. |
| `EKUBO_WALLET_SHELL` | Override login-shell detection for completion (`bash`, `zsh`, or `fish`). |

### Manual installation

Download the archive for your platform from the
[releases page](https://github.com/EkuboProtocol/wallet-mcp-server/releases),
verify it, and put the executables on `PATH`:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify ekubo-wallet-<version>-<target>.tar.gz \
  --repo EkuboProtocol/wallet-mcp-server
tar -xzf ekubo-wallet-<version>-<target>.tar.gz
install -m 0755 ekubo-wallet-<version>-<target>/ekubo-wallet ~/.local/bin/
ln -sf ekubo-wallet ~/.local/bin/ew
```

macOS archives are `.zip` rather than `.tar.gz`. If a release is published
without Apple signing — its notes say so explicitly — Gatekeeper blocks the
first run until you verify the download and then clear the quarantine
attribute with `xattr -d com.apple.quarantine ./ekubo-wallet`.

See [the release guide](docs/releasing.md#verify-a-download) for the complete
verification commands.

### Register the MCP server manually

The installer is optional. Any MCP client can launch the installed binary:

```json
{
  "mcpServers": {
    "ekubo-wallet": {
      "command": "ekubo-wallet",
      "args": ["server"]
    }
  }
}
```

Use an absolute path, such as `/home/you/.local/bin/ekubo-wallet`, if the agent
does not inherit your login shell's `PATH`. Confirm the installed build with
`ekubo-wallet version`.

Do not ask an agent to clone this repository or run the human CLI on your
behalf.

Codex may separately ask whether it may invoke `wallet_send_execution_plan`,
because that tool truthfully advertises that its broadcast phase can cause an
irreversible on-chain transaction. That client permission is independent of the
wallet's own simulation, policy, and human-approval gates. For a trusted local
installation, choose **Always allow**, or pre-approve only that one tool in
`~/.codex/config.toml`:

```toml
[mcp_servers.ekubo-wallet.tools.wallet_send_execution_plan]
approval_mode = "approve"
```

That suppresses the duplicate prompt without weakening anything: the MCP process
still cannot sign a plan that policy rejects, and for an exceptional plan it can
only broadcast bytes already reviewed and signed through the separate CLI. Keep
the tool's `destructiveHint` accurate rather than relabeling an on-chain
broadcast as harmless.

## First use

Accept the legal documents, then create a wallet from your own terminal:

```sh
ekubo-wallet legal show terms      # or: privacy, licenses
ekubo-wallet legal accept          # separate terms + privacy acknowledgments
ekubo-wallet wallet create primary
ekubo-wallet wallet list
ekubo-wallet policy show primary
```

Every MCP tool except `wallet_get_legal` is disabled until the current Terms
of Service are accepted and the Privacy Policy is separately acknowledged.
Acceptance binds the exact document digests, so a release that changes a
document (including its generated list of default RPC endpoints) requires
re-acceptance before the wallet works again. An agent can read the documents
and acceptance state, but only the interactive CLI can accept them.

Policy defaults differ by how the key arrived, because the risk differs:

- `wallet create` generates a fresh, unfunded key and installs the wildcard
  allow-all policy: successfully simulated actions sign automatically, and
  policy or simulation failures queue for explicit approval. Replace it with
  an appropriately restrictive policy before funding the address.
- `wallet import` brings in a key that usually already controls funds, so it
  installs the require-approval policy: nothing signs automatically until you
  deliberately choose otherwise.

Both profiles are one command to install at any time, and every transaction
under the require-approval profile still runs the full simulation and decoded
review before you approve it in the terminal:

```sh
ekubo-wallet policy require-approval primary   # every transaction needs explicit CLI approval
ekubo-wallet policy allow-all primary          # simulated + policy-clean transactions sign automatically
ekubo-wallet policy validate ./policy.json     # or draft something in between
ekubo-wallet policy set primary ./policy.json
ekubo-wallet policy review primary             # review an agent-proposed policy change
```

Agents can propose policy changes with the `wallet_propose_policy` tool
(guided by the `wallet://docs/policy-authoring` and `wallet://schemas/policy`
resources), but only `policy review` applies one: it shows a minimized
human-readable diff of the permissions against the current policy together
with the agent's rationale, requires terminal approval plus OS owner
authentication, and fails closed if the policy changed since the proposal was
written.

Policy changes, exceptional approvals, network changes, key export, and wallet
removal require an interactive terminal and OS-backed owner authentication.
On Linux, first install the polkit action shipped in the archive:

```sh
sudo install -m 0644 contrib/polkit/com.ekubo.wallet.policy \
  /usr/share/polkit-1/actions/com.ekubo.wallet.policy
```

Linux also needs a working Secret Service provider for credential storage. If
polkit, Windows Hello, or macOS Local Authentication is unavailable, sensitive
operations fail closed.

Start the MCP server over stdio with `ekubo-wallet server`. It publishes the
`wallet://docs/security-model` resource. Run `ekubo-wallet --help` for the
complete CLI, or install a packaged completion:

```sh
ekubo-wallet completion zsh > ~/.zfunc/_ekubo-wallet
```

## Networks

These presets are configured on first run. `network presets` prints the built-in
catalog, and `network reset` replaces the configured list with fresh copies of
the presets while preserving wallets and policies. Configuration permits one RPC
profile per chain ID so MCP calls remain unambiguous.

`network list` prints each profile in full, including its complete RPC URL, so
the configuration can be read back and edited. RPC URLs are configuration rather
than key material, and the human CLI does not redact them. No MCP tool returns
an RPC URL: `wallet_list` deliberately omits them so an agent can discover valid
chain IDs without seeing provider credentials.

| CLI name | Chain ID | Max transaction gas | Default public RPC |
| --- | ---: | ---: | --- |
| `ethereum` | 1 | 16,777,216 | `https://rpc.mevblocker.io` |
| `base` | 8453 | 16,777,216 | `https://mainnet.base.org` |
| `arbitrum` | 42161 | 32,000,000 | `https://arb1.arbitrum.io/rpc` |
| `robinhood` | 4663 | 32,000,000 | `https://rpc.mainnet.chain.robinhood.com` |
| `monad` | 143 | 30,000,000 | `https://rpc.monad.xyz` |
| `ink` | 57073 | 16,777,216 | `https://rpc-gel.inkonchain.com` |
| `optimism` | 10 | 16,777,216 | `https://mainnet.optimism.io` |
| `gnosis` | 100 | 16,777,216 | `https://rpc.gnosischain.com` |
| `berachain` | 80094 | 16,777,216 | `https://rpc.berachain.com` |
| `megaeth` | 4326 | 10,000,000,000 | `https://mainnet.megaeth.com/rpc` |

Each is an endpoint its own chain or its operator publishes for wallet use, so
what you are connecting to is documented somewhere you can read rather than
aggregated from a directory. They are public, shared, rate-limited, and carry
no availability guarantee. They are not contacted merely by starting the
server. The configured RPC must support `eth_simulateV1` including sequential
calls, logs, native-transfer tracing, and state overrides; it also observes the
full simulation intent, so prefer a trusted dedicated provider.

The published Monad and MegaETH endpoints do not implement `eth_simulateV1`, so
nothing can be simulated on those chains and nothing signs automatically: every
plan fails simulation and queues for explicit approval. Point them at a provider
that supports the method before using them.

`network add` starts from whatever already describes the chain — the
configured network with that name or alias, otherwise the built-in preset — so
changing one field means naming only that field. Point a preset chain at a
dedicated endpoint, keeping everything else:

```sh
ekubo-wallet network add base --rpc-url https://your-provider.example/base
```

Omitting `--rpc-url` makes the CLI prompt for it, which keeps an endpoint key
out of shell history. The prompt shows what you type: an RPC URL is
configuration this machine's owner already owns, not a signing credential, and
`network list` prints configured URLs in full. The complete URL is also shown
in the authorization prompt, so a typo is caught before it is saved.

A chain that is neither configured nor a preset needs its complete profile.
Run it in a terminal and every missing value is prompted for in one pass, with
defaults for the usual answers:

```sh
ekubo-wallet network add mychain 987654
```

Or pass them as flags for a scripted install. Any that are missing are
reported together, with an explanation and an example each, rather than one per
attempt:

```sh
ekubo-wallet network add mychain 987654 \
  --display-name "My Chain" \
  --alias mychain-mainnet \
  --native-currency-name Ether \
  --native-currency-symbol ETH \
  --native-currency-decimals 18 \
  --max-gas-limit 16777216 \
  --block-explorer-url https://explorer.example.com \
  --documentation-url https://docs.example.com \
  --rpc-url https://rpc.example.com
```

Transaction gas never comes from an agent or execution plan. The wallet doubles
the gas reported by `eth_simulateV1`, adds the EIP-7702 authorization cost when
needed, and caps the signed limit at the lower of the network profile's
`max_gas_limit` and the simulated block gas limit.

## Policies

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
not only direct `transfer` calldata, so finite token limits require
`require_simulation: true`.

Policy documents have a generated [JSON Schema](schemas/policy.schema.json)
derived from the same types the wallet enforces. Print the current one with
`ekubo-wallet policy schema`, and reference it as the top-level `$schema` value
for editor completion. Starting points live in [`examples/`](examples):

| File | Purpose |
| --- | --- |
| [`policy.json`](examples/policy.json) | The default profile a created wallet receives. |
| [`policies/deny-all.json`](examples/policies/deny-all.json) | Exactly what `policy require-approval` installs, and the default for imported wallets. |
| [`policies/token-budget.template.json`](examples/policies/token-budget.template.json) | One chain, one router, one token, with capped allowance and per-transaction spend. |
| [`policies/approval-wildcards.template.json`](examples/policies/approval-wildcards.template.json) | How exact entries override wildcards for spenders, tokens, and chains. |
| [`policies/allow-all-with-approval.template.json`](examples/policies/allow-all-with-approval.template.json) | Exactly what `policy allow-all` installs. |

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

`approval_expiry_seconds` (600 by default, overridable per chain) sets the time
between request creation and signing. An unsigned request becomes terminally
expired at that deadline and can no longer be approved, rejected, or submitted.
`max_calls_per_batch` accepts up to 4096; the transfer and execution-plan tool
schemas impose no list maximum of their own, so real batches are bounded by the
selected policy, memory, encoded transaction size, and the per-chain gas cap.

Policy changes increment a local revision and invalidate every approval that has
not yet been signed.

## Reviewing an exceptional approval

When policy rejects a plan or simulation fails, the wallet stores an owner-only
pending record whose digest commits to every ordered call. `ekubo-wallet review
<request-id>` then re-simulates and prints the exact nonce, gas, fees, calls, and
delegation alongside a decoded reading of each step:

```text
Call 1: kind=Approval; target=0xa0b8…eb48; value=0 wei; selector=0x095ea7b3; calldata=68 bytes
Call 1 reads as: approve spender 0x1111…1111 for 1000 USDC (1000000000 base units)
Simulated net balance change (excludes live gas): USDC (0xa0b8…eb48): -1000 USDC (-1000000000 base units)
```

When a vendored [ERC-7730](https://eips.ethereum.org/EIPS/eip-7730)
clear-signing descriptor matches the exact chain, contract, and function
selector, the call renders as its declared intent plus labeled, formatted
fields — token amounts with symbols and decimals, dates, durations, enums, and
nested multicall actions:

```text
Call 1 reads as: Swap on Ekubo [Ekubo Protocol — Ekubo MEV-Capture Router]
Call 1 ·: Pool token 0: 0x1111…
Call 1 ·: Specified pool token: Token 1
Call 1 ·: Specified amount: 1000000
```

Descriptors are vendored in [`clearsign/`](clearsign), embedded at compile
time, and never fetched from the network; the test suite re-derives every
selector and validates every display path, so updating the snapshot is a
reviewed git commit that cannot silently drift.

Otherwise, standard `approve`, `transfer`, `transferFrom`, `setApprovalForAll`,
and `multicall(bytes[])` calldata is decoded locally. Token symbols and decimals
come from bounded, best-effort reads of the configured RPC; when a lookup fails
the line degrades to exact base units rather than to a guess, and all
descriptor- and token-supplied text is sanitized so it cannot forge additional
review output. Effectively unlimited allowances and blanket `setApprovalForAll`
grants raise explicit warnings.

These readings are supplemental. The review digest binds the exact ordered
calldata, and the displayed target, selector, and value remain authoritative.
An agent must never run the approval command for you.

## MCP tools

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

### Token database and portfolio

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

### Simulation forks

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

### Local read decoding

`wallet_batch_eth_call` is the normal read path. It runs ordered reads on a
decimal chain ID, uses Multicall3 by default with an individual `eth_call`
fallback, sends `msg.sender`-dependent calls individually, and can decode each
exact result in the same call. `block_parameter` accepts `latest`, `pending`,
`safe`, `finalized`, `earliest`, or a canonical hexadecimal block quantity.

Five decode plan kinds are supported: `function_result`, `abi_parameters`,
`multicall3`, `function_result_bytes_array`, and `semantic_value`. Complete
inputs for each are in [`examples/abi-decoding.json`](examples/abi-decoding.json),
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

## EIP-7702 batching

Multi-call plans execute through [Uniswap Calibur](https://github.com/Uniswap/calibur),
a non-upgradeable EIP-7702 singleton with ERC-7821 batch execution. Only the
canonical v1.1.0 deployment at `0x000000005c84F8Fd50b21CAC312528A64437030e` is
accepted, and its runtime code is verified before delegation. The wallet neither
deploys nor accepts a configurable implementation.

A one-call plan is sent directly to its target and never checks or uses
delegation. Two or more ordered calls become one `revertOnFailure` Calibur batch:
an undelegated wallet includes a self-executed authorization, an
already-canonical wallet sends a normal transaction to itself, and a wallet
delegated elsewhere has that delegation replaced with canonical Calibur in the
same transaction.

Replacing a delegation changes persistent account code even if the batch later
reverts, and can expose storage-layout incompatibilities left by the previous
delegate. Use a separate wallet if a prior delegation or its storage must be
preserved. Accounts holding arbitrary bytecode rather than an EIP-7702
delegation designator are rejected.

## Local storage

`EKUBO_WALLET_HOME`, when set, is the complete data directory. Otherwise the
platform defaults are below. They are deliberately distinct from the
TypeScript `wallet-mcp-server` directories and keychain entries: the storage
formats are incompatible, and the two servers must never read each other's
state.

| Platform | Data directory | Encrypted database |
| --- | --- | --- |
| macOS | `~/Library/Application Support/org.ekubo.wallet` | `policies.db` |
| Linux | `${XDG_STATE_HOME}/ekubo-wallet`, or `~/.local/state/ekubo-wallet` | `policies.db` |
| Windows | `%LOCALAPPDATA%\Ekubo\wallet` | `policies.db` |

The one SQLCipher file contains separate `wallet_policies`,
`pending_transactions`, `pending_typed_data`, `pending_messages`, `tokens`,
`address_book`, `legal_acceptance`, and `policy_proposals` tables. Token metadata, address
aliases, and legal acceptance deliberately live inside the authenticated
encrypted database rather than in plain files: they carry no signing
authority, but a file edit outside this process must not be able to forge
acceptance, retarget an alias, or misrepresent a token. A pre-existing plain
`tokens.db` is imported once (constraint-checked, never overwriting) and
removed; leftover `address_book.db` or `legal.json` files from unreleased
builds are deleted without being trusted. A pending row stores its normalized execution
plan and digest, policy revision, expiry and lifecycle status; once signed it
also stores the exact serialized transaction and hash before the first RPC
submission. An exceptional approval additionally records the digest of its
reviewed nonce, gas, fees, call, and delegation fields. Retries only rebroadcast
those persisted bytes. Inspect the ledger with `ekubo-wallet transaction list`
and `ekubo-wallet transaction show <request-id-or-hash>`: on a terminal these
open a human-readable view — `list` is an interactive browser with relative
ages, expandable details, block-explorer links, and receipt-decoded token
balance changes. It draws one page sized to the terminal and scrolls with the
arrow keys, so a long history never outgrows the screen; `Done` is the first
entry and `Esc` also leaves the browser. Every reporting command prints exact JSON instead when
`--json` is passed or when stdout is not a terminal, so scripts and agents
always receive machine-readable output.

The random 256-bit database key is stored separately under credential-service
name `org.ekubo.wallet.policy-database-key.v1`. Wallet private keys use
`org.ekubo.wallet.private-key.v1` and the wallet ID as their account. The
unencrypted `config.json` in the same data directory contains wallet metadata
and network configuration, including RPC URLs; it contains no private key.

## Security boundary

The MCP client, model output, configured RPC, and local files are treated as
untrusted. Before normal signing, the process validates the plan, simulates its
exact target/value/calldata, evaluates the active encrypted policy, resolves
nonce/fees, loads the key, signs locally, validates the recovered sender and
complete envelope, and durably stores the bytes and hash before broadcasting.

Exceptional signing has an additional boundary: the CLI re-simulates, prepares
the exact nonce/gas/fees/delegation without loading the key, shows those fields,
binds OS authentication to their review digest, rechecks configuration and
policy, and signs the prepared object without another RPC lookup.

EIP-712 typed data follows the same shape. Recognized permits (ERC-2612 and
canonical Permit2, matched by their complete type encodings) are evaluated
against the policy's approval-spender rules exactly like `approve()` calldata
and sign automatically only when allowed. Every other payload — and every
policy-denied permit — queues in the encrypted database for CLI review, which
displays the complete payload, requires terminal approval plus OS owner
authentication bound to the signing hash, and only then signs.

EIP-191 `personal_sign` messages queue the same way, with no automatic path at
all: no policy can score what a message signature authorizes. The CLI prints the
exact bytes as hex beside their text, escapes control characters, terminal
escape sequences, and Unicode bidirectional overrides so the message cannot
repaint or reorder the screen reviewing it, and parses recognized ERC-4361
sign-in messages into labeled fields with warnings for an unconfigured or
disagreeing chain, an expired or post-dated login, a domain that disagrees with
its own URI, and any listed resources. A sign-in message naming an account other
than the signing wallet is refused outright, and legacy raw `eth_sign` over a
bare 32-byte digest is refused because no approval screen can describe it
honestly. A message signature binds no chain, so a `chain_id` sent with one is
displayed as the requester's claim.

SQLCipher protects confidentiality and page integrity, but there is no external
anti-rollback anchor. Restoring an older valid encrypted database can restore
an older policy or an already-signed pending record. See
[the threat model](docs/threat-model.md) and
[architecture](docs/architecture.md) for the precise guarantees and residual
risks, and [approval UX](docs/approval-ux.md) for the actual approval flow.

## Development

The repository tracks Rust `stable`. CI verifies Linux, macOS, and Windows.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release
```

The ignored live tests require an RPC that supports `eth_simulateV1`:

```sh
cargo test --locked --all-features live_ -- --ignored --nocapture
```

`tests/live_networks.rs` is a live matrix that exercises reads, simulation, and
simulation forks against every default network's real RPC. It is skipped unless
`EKUBO_WALLET_LIVE_RPC_TESTS=1` is set, and each chain's endpoint can be
overridden with `EKUBO_WALLET_LIVE_RPC_<chain-id>`:

```sh
EKUBO_WALLET_LIVE_RPC_TESTS=1 cargo test --locked --all-features \
  --test live_networks -- --nocapture
```

To build and install your local checkout — same agent registration and shell
completions as a release install, no download or signature verification, since
you are trusting your own working tree:

```sh
./install-local.sh
```

(a shorthand for `EKUBO_WALLET_LOCAL_SOURCE=. sh install.sh`; every other
installer environment variable still applies)

Or point an MCP client directly at `target/release/ekubo-wallet server`. Regenerate the committed policy schema
with `cargo run --bin ekubo-wallet -- policy schema > schemas/policy.schema.json`;
a test fails if it is stale.

Releases are cut by pushing a `v<version>` tag matching `Cargo.toml`. See
[the release guide](docs/releasing.md).

## Licensing

No open-source license is granted. See [LICENSE](LICENSE).
