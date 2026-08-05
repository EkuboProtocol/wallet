# Networks

These presets are configured on first run. `network presets` prints the built-in
catalog, and `network reset` asks for a yes or no and then replaces the
configured list with fresh copies of the presets, preserving wallets and
policies. Configuration permits one RPC
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

Run it with no arguments and the first question is the chain ID, because that
is what says which network you mean. A chain that a preset or the
configuration already describes keeps its own name and settings, and the only
remaining question is the endpoint; a chain nothing here knows about is named
and described from scratch. Naming a chain ID that is already configured
replaces that profile rather than failing: one profile per chain ID is the
rule, so there is nothing else the second definition could mean.

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
