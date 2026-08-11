# Networks

`network presets` prints the built-in defaults; `network presets --search <term>`
and `network presets --all` search the complete compiled-in registry. `network
reset` asks for a yes or no and then replaces the configured list with fresh
copies of the defaults, preserving wallets and policies. Configuration permits
one profile per chain ID so MCP calls remain unambiguous.

## Several endpoints per network

A network carries a **list** of RPC endpoints rather than one, and every read
walks that list in order until one answers. That is the difference between a
wallet that stops working when a public endpoint rate-limits it and one that
does not: simulation gates signing, so a single refused request used to mean
nothing could be signed on that chain until the endpoint recovered.

Failover is per request, not a choice made once at startup, because public RPCs
do not fail as a unit — they refuse one request and serve the next, or answer
reads while refusing `eth_simulateV1`. Each attempt re-verifies the chain ID
before its answer is used, so an endpoint pointed at the wrong chain is skipped
rather than believed. When every endpoint fails, the error names each one and
what it said.

Two things are deliberately *not* failed over. Simulation moves to the next
endpoint only on an RPC-level failure — a revert or a setup error is a fact
about the plan or the chain, and asking five more endpoints returns the same
answer more slowly. Broadcasting runs its full send-and-reconcile against each
endpoint in turn, because a rejection such as `already known` or `nonce too
low` describes a submission that *succeeded*, and only the endpoint that
produced it can be asked what it meant.

`network list` prints every configured endpoint in full, so the configuration
can be read back and edited. RPC URLs are configuration rather than key
material, and nothing redacts them: the CLI, MCP tools (`wallet_list` returns
each network's endpoint list), and surfaced RPC errors all show them verbatim.
A provider credential embedded in an RPC URL is read-only and easy to rotate,
so use one whose disclosure would be an inconvenience, not a loss.

## How the endpoints are ordered: `rpc_strategy`

| Strategy | Behavior |
| --- | --- |
| `ordered` (default) | Try endpoints in configured order and use the first successful answer. |
| `random` | Shuffle the endpoint order for each operation, then use the first successful answer. |

Both strategies are failover mechanisms, not trust amplification. A coherent
lie from the endpoint that answers first is still authoritative: the wallet
checks that a simulation is internally consistent and linked to its parent
block, not that the endpoint's view of the chain is true. `random` spreads
traffic and makes it less predictable which operator sees a request; it does
not verify one operator against another. Use a backend with its own verification
model if that distinction matters.

Set the strategy alongside any other network field in `network add`, the
interactive `network edit` form, or an agent's `wallet_propose_network` (which
still queues for owner review). It defaults to `ordered` and is omitted from
`config.json` at that default.
## Where the endpoints come from

Releases before this one shipped one endpoint per network, each chosen because
the chain or its operator published it for wallet use. The defaults are now
**measured** instead: candidates come from chainlist.org — the
ethereum-lists/chains registry plus DefiLlama's curated extras — and
`contrib/rpc-probe` asks each one for the exact requests this wallet makes,
including an `eth_simulateV1` pinned to a block with an EIP-7702 delegation
designator installed by a state override. Only endpoints that answered are
shipped, ranked by capability first, then by operator diversity (so the first
two entries are never the same provider), then by latency. Endpoints requiring
an API key are excluded outright: shipping one hands out a credential nobody
here owns or can rotate.

Where a chain publishes its own endpoint, that one still leads the list — but
never when doing so would put a node without `eth_simulateV1` ahead of one that
has it.

An endpoint being listed means it answered correctly on the day it was
measured. It does **not** mean its operator is trustworthy: a public RPC sees
every address the wallet asks about and every transaction it broadcasts, and
can lie about any answer. Nothing in the signing path treats an endpoint as
authoritative — see [threat-model.md](threat-model.md) — but for a wallet
holding value worth protecting, point it at a dedicated provider or your own
node.

## Defaults

The 45 networks below are configured on first run: every EVM mainnet Alchemy
serves that has at least one working public endpoint. The registry compiled
into the binary is much larger — 852 chains, 1,462 endpoints, 224 of them
simulation-capable — and any of it can be configured with one command.

| CLI name | Chain ID | Max transaction gas | Endpoints | Can simulate |
| --- | ---: | ---: | ---: | --- |
| `ethereum` | 1 | 16,777,216 | 6 | 6 of 6 |
| `optimism` | 10 | 16,777,216 | 6 | 6 of 6 |
| `rootstock` | 30 | 6,800,000 | 2 | **none** |
| `bnb` | 56 | 16,777,216 | 6 | 6 of 6 |
| `gnosis` | 100 | 16,777,216 | 6 | 4 of 6 |
| `unichain` | 130 | 16,777,216 | 4 | 2 of 4 |
| `polygon` | 137 | 16,777,216 | 6 | 6 of 6 |
| `monad` | 143 | 30,000,000 | 5 | **none** |
| `sonic` | 146 | 16,777,216 | 6 | 3 of 6 |
| `opbnb` | 204 | 16,777,216 | 4 | **none** |
| `lens` | 232 | 16,777,216 | 2 | **none** |
| `fraxtal` | 252 | 16,777,216 | 6 | 3 of 6 |
| `boba` | 288 | 16,777,216 | 4 | **none** |
| `zksync` | 324 | 16,777,216 | 6 | **none** |
| `shape` | 360 | 16,777,216 | 2 | 1 of 2 |
| `worldchain` | 480 | 16,777,216 | 5 | **none** |
| `astar` | 592 | 16,777,216 | 2 | **none** |
| `flow` | 747 | 16,777,216 | 1 | **none** |
| `metis` | 1088 | 16,777,216 | 6 | **none** |
| `moonbeam` | 1284 | 16,777,216 | 6 | **none** |
| `sei` | 1329 | 16,777,216 | 3 | **none** |
| `story` | 1514 | 16,777,216 | 6 | 6 of 6 |
| `soneium` | 1868 | 16,777,216 | 3 | 1 of 3 |
| `ronin` | 2020 | 16,777,216 | 1 | **none** |
| `abstract` | 2741 | 16,777,216 | 1 | **none** |
| `megaeth` | 4326 | 10,000,000,000 | 4 | 2 of 4 |
| `robinhood` | 4663 | 32,000,000 | 5 | 5 of 5 |
| `mantle` | 5000 | 16,777,216 | 4 | **none** |
| `superseed` | 5330 | 16,777,216 | 2 | 1 of 2 |
| `race` | 6805 | 16,777,216 | 1 | **none** |
| `zetachain` | 7000 | 16,777,216 | 4 | **none** |
| `base` | 8453 | 16,777,216 | 6 | 6 of 6 |
| `plasma` | 9745 | 16,777,216 | 1 | 1 of 1 |
| `apechain` | 33139 | 16,777,216 | 2 | 1 of 2 |
| `mode` | 34443 | 16,777,216 | 3 | 2 of 3 |
| `arbitrum` | 42161 | 32,000,000 | 6 | 6 of 6 |
| `celo` | 42220 | 16,777,216 | 3 | 2 of 3 |
| `avalanche` | 43114 | 16,777,216 | 6 | **none** |
| `ink` | 57073 | 16,777,216 | 4 | 3 of 4 |
| `linea` | 59144 | 16,777,216 | 5 | 3 of 5 |
| `bob` | 60808 | 16,777,216 | 4 | 2 of 4 |
| `berachain` | 80094 | 16,777,216 | 6 | 5 of 6 |
| `blast` | 81457 | 16,777,216 | 5 | **none** |
| `scroll` | 534352 | 16,777,216 | 6 | 1 of 6 |
| `zora` | 7777777 | 16,777,216 | 2 | 1 of 2 |

Endpoints are public, shared, rate-limited, and carry no availability
guarantee. They are not contacted merely by starting the server.

### Chains where nothing signs automatically

Simulation is the whole signing path — there is no local EVM and no `eth_call`
fallback — so a chain whose public endpoints do not implement `eth_simulateV1`
cannot sign automatically: every plan fails simulation and queues for explicit
approval. Nineteen of the defaults are in that position today, marked **none**
above: `rootstock`, `monad`, `opbnb`, `lens`, `boba`, `zksync`, `worldchain`,
`astar`, `flow`, `metis`, `moonbeam`, `sei`, `ronin`, `abstract`, `mantle`,
`race`, `zetachain`, `avalanche`, and `blast`. Their nodes answer `-32601
method not found`; this is a property of those chains' clients, not of the
selection. Point them at a provider that implements the method to sign on them:

```sh
ekubo-wallet network add avalanche --rpc-url https://your-provider.example/avax
```

MegaETH used to be in that list and no longer is — its published endpoint still
lacks the method, but two others in its list have it, and failover finds them.

### Upgrading from a single-endpoint configuration

An existing `config.json` is never rewritten by an upgrade, so a wallet
installed before this change keeps the exact networks it had: its single
`rpc_url` is read as a one-entry list, and an endpoint you configured yourself
stays the only one used. That is deliberate — silently adding third-party
endpoints to a network someone pointed at their own node would send their
traffic somewhere they did not choose.

To take the new fallbacks for a network, name it again:

```sh
ekubo-wallet network add ethereum      # re-offers the built-in list, for review
```

or `network reset` to replace every configured network with fresh defaults,
which discards custom endpoints. Either way the shipped endpoint list is
disclosed in the privacy policy, and changing it requires a fresh
acknowledgment before signing resumes.

## Adding a network

`network add` starts from whatever already describes the chain: the configured
network with that name or alias, otherwise the compiled-in registry — all 852
chains of it, not just the defaults. So configuring a chain the wallet did not
default to is a chain ID and a confirmation rather than a hunt for a working
endpoint:

```sh
ekubo-wallet network presets --search celo
ekubo-wallet network add 42220
```

Point any chain at a dedicated endpoint, keeping everything else. `--rpc-url`
is repeatable, and supplying it replaces the whole list rather than appending
to it, so the command says what the network should reach:

```sh
ekubo-wallet network add base \
  --rpc-url https://your-provider.example/base \
  --rpc-url https://mainnet.base.org
```

Run it with no arguments and the first question is the chain ID, because that
is what says which network you mean. A chain the configuration or the registry
already describes keeps its own name and settings, and the only remaining
question is the endpoints; a chain nothing here knows about is named and
described from scratch. Naming a chain ID that is already configured replaces
that profile rather than failing: one profile per chain ID is the rule, so
there is nothing else the second definition could mean.

Omitting `--rpc-url` makes the CLI prompt for it, which keeps an endpoint key
out of shell history; several endpoints can be typed separated by commas or
spaces. The prompt shows what you type: an RPC URL is configuration this
machine's owner already owns, not a signing credential, and `network list`
prints configured URLs in full. Every endpoint is shown in the authorization
prompt, so a typo is caught before it is saved.

A chain that is in neither the configuration nor the registry needs its
complete profile. Run it in a terminal and every missing value is prompted for
in one pass, with defaults for the usual answers:

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
  --rpc-url https://rpc.example.com \
  --rpc-url https://rpc-backup.example.com
```

A network may list at most 8 endpoints. Failover walks them in order, so the
length of the list is also the worst case a caller waits through when the chain
is genuinely unreachable: every endpoint ahead of the working one costs its own
timeout.

Transaction gas never comes from an agent or execution plan. The wallet doubles
the gas reported by `eth_simulateV1`, adds the EIP-7702 authorization cost when
needed, and caps the signed limit at the lower of the network profile's
`max_gas_limit` and the simulated block gas limit.

**Set `max_gas_limit` on any custom network.** Every default carries one.
Without it the only ceiling left is the block gas limit the endpoint itself
reported, so the endpoint bounds its own pricing — and on the automatic path no
human sees the fee before it is signed. Gas is native value the policy does not
score: `native_value` guards what a call *sends*, not what it costs. A
profile-level ceiling is the one bound on that which does not depend on the
endpoint being honest.

**Set `max_fee_per_gas` too, in wei, if you run automatic transactions.** A
gas limit bounds only one of the two factors. The other is the EIP-1559
`maxFeePerGas`, which comes from `eth_maxPriorityFeePerGas` and the block's
base fee as one endpoint reports them, and which reached the signature
unchanged: no policy rule speaks about fees, and an automatic transaction is by
definition one nobody reviews. With `max_fee_per_gas` set, a preparation whose
estimate exceeds it is refused rather than signed — refused rather than
clamped, because a clamped fee is an envelope that may never mine while it
holds the wallet's one in-flight slot for that chain. It is unset by default,
since a number that is right for one chain is wrong for most.

## Regenerating the registry

The vendored `crates/ekubo-wallet-core/networks.json` is produced by
`contrib/rpc-probe`, which talks to the network and is never run at build time
or at run time — a release carries exactly what was measured and reviewed:

```sh
bun contrib/rpc-probe/collect.mjs /tmp/probe          # gather candidates
bun contrib/rpc-probe/probe.mjs   /tmp/probe          # measure them (~25 min)
bun contrib/rpc-probe/select.mjs  /tmp/probe \
  --out crates/ekubo-wallet-core/networks.json        # rank and write
```

`collect.mjs` reads chainlist's extras, which are a JavaScript module rather
than data: getting the map out means running the file, with the privileges of
whoever is regenerating the registry — the same machine that holds the signing
material. So the fetch is pinned to a commit and the bytes are checked against
a digest recorded beside it, and the script refuses to run anything else.
Updating that pin is a deliberate change with a reviewable diff, and it means
reading the upstream diff first; it is not something to do because the script
asked.

`curated.json` holds the hand-written names, aliases, gas ceilings, and pinned
first endpoints for the chains that ship as defaults; `alchemy-chains.json`
holds the chain IDs that decide which chains are defaults. Regenerating changes
the disclosed endpoint list, which changes the privacy policy text and requires
a fresh acknowledgment before signing resumes — that is deliberate.

## Running your own node

The configured endpoint executes every simulation, so it decides whether a plan
appears to succeed, what gas it carries, and what predicted effects a human is
shown before approving. No policy predicate reads any of that — every rule is
decided from the plan's own bytes — but availability, correct pricing, and the
truthfulness of the approval screen still rest on the endpoint. Pointing the
wallet at a node you run yourself is the one configuration with no RPC trust
assumption left in it, and it is the right answer for a wallet holding value
you would mind losing.

A loopback endpoint is accepted from your own configuration:

```sh
ekubo-wallet network add ethereum --rpc-url http://127.0.0.1:8545
```

That replaces the whole endpoint list with your node. To keep public endpoints
behind it as fallbacks, list them after it — but note that doing so means a
request your node cannot answer silently goes to a third party instead.

`http` and loopback are admitted here deliberately. An owner configuring a local
node from their own terminal is naming a machine they already control, so the
scheme and address rules that apply to an endpoint an *agent* proposes do not
apply to one you type yourself: `wallet_propose_network` still requires public
`https` with no credentials and no private or reserved address, because an MCP
caller is not the owner. The two paths are separate on purpose, and pinned by
test.

The requirement your node must meet is `eth_simulateV1`, including sequential
calls, logs, native-transfer tracing, and state overrides. That is the whole
signing path — there is no local EVM and no `eth_call` fallback — so verify the
method exists on your client and version before relying on it. A node that does
not implement it is not unusable, but nothing will sign automatically: every
plan fails simulation and queues for explicit approval.

Note that running your own node removes trust in *whoever answers the socket*,
not trust in consensus. A node still follows whichever chain its peers and
configuration point it at; what it removes is a third party in a position to
answer your queries differently from everyone else's.
