# Ekubo Wallet

A local EVM wallet that an AI agent can use on its own, under rules you write.

`ekubo-wallet` is one binary that is three things: a command-line wallet you
drive yourself, an MCP server your agent drives, and a WalletConnect client for
the dapps you already use. It holds your keys, decides what may be signed
without asking you, simulates every transaction before signing it, and asks in
your terminal for everything else.

> **This is security-sensitive software.** It has not been independently
> audited, and nothing here should be read as a claim that it has.

## Why this exists

Ask Claude or Codex to rebalance a position and it gets all the way to the end
before stopping, because something has to sign and every wallet in production
was built around a person clicking a button. Give the agent a key in an
environment variable instead and you have handed it unlimited authority over
everything you own.

This wallet takes the third option: you write down in advance what may be
signed without you, and the wallet enforces it in the same process that reads
the key. Everything outside those rules queues in your terminal with a decoded,
simulated review attached.

## Install

```sh
tag=v1.0.0-rc.0   # the release you are installing
base=https://github.com/EkuboProtocol/wallet-mcp-server/releases/download/$tag
d=$(mktemp -d)
curl -fsSL -o "$d/install.sh" "$base/install.sh"
curl -fsSL -o "$d/install.sh.sigstore.json" "$base/install.sh.sigstore.json"
cosign verify-blob \
  --bundle "$d/install.sh.sigstore.json" \
  --certificate-identity \
  "https://github.com/EkuboProtocol/wallet-mcp-server/.github/workflows/release.yml@refs/tags/$tag" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$d/install.sh"
sh "$d/install.sh"
```

The installer is verified before it runs. It carries a Sigstore signature of
its own, published with the release, and the commands above check that
signature against the release workflow that produced it. This matters more than
it looks: a shell begins executing a piped script as it arrives, so an
installer nobody checked has already run by the time any check inside it could
apply — and "read it before piping it to a shell" is advice a reader cannot act
on when the bytes are executing as they download.

Once verified, it downloads the archive for your platform, verifies a Sigstore
signature over `SHA256SUMS` and the archive's checksum against it before
extracting anything, installs `ekubo-wallet`, registers it with every agent it
finds (Claude Code, Codex, Gemini CLI, Cursor, opencode), and installs shell
completion.

`cosign` is required. See [installation](docs/installation.md) to install
without it, to use a release archive directly, or to register the MCP server by
hand.

The installer also registers the Ekubo protocol server at
`https://mcp.ekubo.org/mcp`, which is what gives a fresh install something to do
— quotes, swaps, bridging, liquidity — beyond holding keys. It prepares
unsigned transactions and never sees a key. Skip it with
`EKUBO_WALLET_SKIP_COMPANION=1`, or remove both later with `ekubo-wallet
meta-agent remove`.

On Linux, install the polkit action shipped in the archive before signing, and
make sure a Secret Service provider is running. If you used `install.sh`, it
measured a digest from the packaged file in its own private temporary, staged
a read-only copy, and printed a `sudo` command carrying that digest — run that
one. If it could find no sha256 tool it deliberately prints no command at all,
and says so. Either way it does not install the action for you, and it does
nothing about the Secret Service provider.

Installing manually, run this immediately after extracting the archive, before
anything else touches the extraction directory. A plain `sudo install` from
that directory trusts whatever bytes are at the path when root reads them;
this hands `sha256sum` and `install` the same bytes, and refuses anything that
is not a regular file — a symlink to a regular file still passes, and it is
the digest check after it that catches a path pointed somewhere unexpected. It
cannot protect a copy you already let sit around, only the file you extract
and check in the same breath. See [first use](docs/first-use.md) for the full
reasoning.

```sh
POLKIT_DIGEST=$(sha256sum contrib/polkit/com.ekubo.wallet.policy | cut -d' ' -f1)
sudo sh -c '[ -f "$2" ] || { echo "not a regular file: $2" >&2; exit 1; }; t=$(mktemp) || exit 1; head -c 65536 "$2" > "$t" && printf "%s  %s\n" "$1" "$t" | sha256sum -c >/dev/null && install -m 0644 "$t" /usr/share/polkit-1/actions/com.ekubo.wallet.policy; status=$?; rm -f "$t"; exit $status' sh "$POLKIT_DIGEST" contrib/polkit/com.ekubo.wallet.policy
```

## First run

```sh
ekubo-wallet legal accept              # terms + privacy, acknowledged separately
ekubo-wallet account create primary    # asks which policy to start under
ekubo-wallet status                    # is this set up, and does it need me?
```

`account create` asks whether the new wallet starts under **require-approval**
(nothing signs without you) or **allow-all** (anything that simulates cleanly
signs immediately). The cursor starts on require-approval, and that is also
what a non-interactive run gets. `account import` always installs
require-approval, because an imported key usually already controls funds.

Then restart your agent so it picks up the new MCP server, and try asking it
something:

> "What's in my wallet?"
>
> "Swap 100 USDC for ETH on Base, but show me the simulated result first."

See [first use](docs/first-use.md) for the full walkthrough.

## The setup most people should start with

Two wallets on the same machine, doing two different jobs.

**A hot wallet** holding an amount you would be annoyed to lose and unbothered
to explain. Anything that simulates cleanly signs immediately, so the agent
never blocks. This is what claims fees, compounds, rebalances at 3am, and
cancels its own stuck transactions.

```sh
ekubo-wallet account create hot --policy allow-all
```

**A vault** holding the rest. Every transaction gets the full simulation and
decoded review, and nothing signs until you approve it in the terminal. An
agent can still drive it all day; each action costs you one prompt with the
balance changes already computed.

```sh
ekubo-wallet account create vault --policy require-approval
```

In between there are scoped policies, which is where the rule engine earns its
keep — one chain, one router, one token pair, and a blanket deny over the top.
Start from [`examples/policies/token-budget.template.json`](examples/policies/token-budget.template.json)
and read [policies](docs/policies.md).

> **The policy is the security boundary.** Keys carry no biometric or presence
> requirement, deliberately: this wallet exists so an agent can work unattended,
> and a key the OS will not release without a live human cannot sign at 3am.
> Whatever a wallet's policy permits is reachable without a further gate, so
> choose it — and fund the wallet — on that basis. See
> [security boundary](docs/security-boundary.md).

## Policies in a minute

A policy maps chain IDs to rules. Every call in a transaction is graded on its
own against the whole rule set, and there are three outcomes:

| Outcome | When | What happens |
| --- | --- | --- |
| `allowed` | every call matched an `allow` rule | signs automatically, no prompt |
| `requires_approval` | no rule covers some call | queues for approval in your terminal |
| `rejected` | a `deny` rule matched | refused outright; no approval can override it |

Rules are a set, order carries no meaning, and deny always beats allow, so you
can read one rule without reading the rules around it. Calldata is matched by
function signature rather than by four bytes, so you can never allowlist a
selector whose meaning you do not know:

```json
{
  "effect": "allow",
  "to": { "eq": "0x…" },
  "calldata": { "selector": {
    "abi": "approve(address spender, uint256 amount)",
    "args": { "spender": { "in": ["0x…"] }, "amount": { "eq": "0" } }
  }}
}
```

There are no spending limits, and there will not be any: a per-day ceiling is
not a limit when the same agent can ask again tomorrow. A rule bounds *which*
calls may be made.

```sh
ekubo-wallet policy show primary
ekubo-wallet policy allow-all primary
ekubo-wallet policy require-approval primary
ekubo-wallet policy validate ./my-policy.json   # needs no wallet or database
ekubo-wallet policy set primary ./my-policy.json
ekubo-wallet policy review primary              # apply an agent's proposal
```

Your agent can draft a policy and propose it, and `policy review` shows you a
human-readable diff of what would change about its authority, plus the agent's
rationale, before you confirm it in the terminal.

## Using it as your everyday wallet

Nothing here is agent-only. Paste a WalletConnect link and a dapp gets a v2
session under a scope you fix when you approve the connection, proposing
transactions and signatures through the same policy and the same review an
agent gets. EIP-5792 batched calls are served.

Every off-chain signature — EIP-712 typed data and EIP-191 messages, permits
included — is reviewed by you. There is no automatic path, because a
per-transaction limit cannot bound something whose holder redeems it whenever
they like. Sign-in messages parse into labeled fields with warnings for an
expired login or a domain that disagrees with its own URI, and legacy
`eth_sign` over a bare digest is refused outright.

## What it provides

- **Custody** in the OS credential store (Keychain, Credential Manager, Secret
  Service) for generated or imported secp256k1 keys, kept out of the encrypted
  database so the data directory is never key-bearing.
- **A stateless policy** over chains, targets, selectors and their decoded
  arguments, native value, ERC-20 recipients and spends, approval spenders and
  amounts, and batch size.
- **Simulation before every signature**, through the configured RPCs' typed
  `eth_simulateV1`. Each network carries several endpoints and fails over
  between them, so one public RPC rate-limiting you does not stop you signing.
- **Simulation forks**, so an agent can simulate a chain of dependent actions —
  and read the world between them — before you are asked to approve the first
  step. Forks never sign, approve, or satisfy a policy rule.
- **Atomic execution** as a direct EIP-1559 transaction or one EIP-7702 Calibur
  batch, with signed bytes persisted before the first broadcast so an ambiguous
  submission is rebroadcast byte-for-byte rather than re-signed.
- **Readable approvals**: ERC-7730 clear signing, decoded amounts with real
  symbols and decimals, warnings on unlimited allowances and blanket operator
  grants, and sanitized token names so a hostile token cannot forge a review
  field.
- **45 networks** configured by default from a compiled-in registry of 852, and
  roughly **17,000 tokens across 34 chains** seeded into the database at
  creation and shipped inside the binary.
- **Portfolio reads** for any address, bounded batch reads, transfer helpers,
  receipt reconciliation, and cancellation of a stuck transaction at its own
  nonce.

It is a general-purpose wallet rather than a companion to any protocol. Any
tool can produce an execution plan; this wallet validates, simulates, and
policy-checks every plan identically and treats all of them as untrusted input.
Plans arrive by reference — an https URL verified against a published keccak256
digest, a `data:` URI carrying it inline, or a `file:` path described with
`ekubo-wallet meta-reference` — so the agent relaying one passes a line of text
instead of the whole body.

## What it deliberately does not do

- **No daily limits, rolling windows, or spend counters.** See above.
- **No presence check on the automatic path.** The OS will release the key
  without a fingerprint, on purpose.
- **No protection against an attacker already running code as you.** Both
  secrets live in the same credential store behind the same login. The
  protection is against secrets at rest leaving the machine.
- **No local EVM and no `eth_call` fallback** for signing decisions, so a chain
  whose RPCs lack `eth_simulateV1` is a chain this wallet will not sign on.
- **No protocol calldata of its own** beyond an ERC-20 transfer and the
  cancellation envelope. Swapping and providing liquidity need a plan from a
  producer.
- **No anti-rollback anchor** on the encrypted database: restoring an older
  valid copy restores an older policy.

## Documentation

**Using it**

| Page | What's in it |
| --- | --- |
| [Installation](docs/installation.md) | Release archives, manual install, registering the MCP server by hand |
| [First use](docs/first-use.md) | Legal acceptance, creating a wallet, choosing its policy |
| [Policies](docs/policies.md) | What a policy can express, the shipped templates, editing one |
| [Approval flow](docs/approval-ux.md) | Reviewing and resolving a request in the terminal |
| [MCP tools](docs/mcp-tools.md) | Every tool, the token database, simulation forks, local decoding |
| [WalletConnect](docs/walletconnect.md) | Connecting to a dapp, what it may propose, the relay |
| [Networks](docs/networks.md) | Default networks, endpoint failover, adding a chain, RPC requirements |
| [Batching](docs/batching.md) | How multi-call plans execute atomically through EIP-7702 |

**How it works, and what it does not protect against**

| Page | What's in it |
| --- | --- |
| [Security boundary](docs/security-boundary.md) | What is trusted, why keys sit outside the database, why nothing enforces presence |
| [Threat model](docs/threat-model.md) | Signing invariants, attack analysis, residual risks |
| [Architecture](docs/architecture.md) | Components, the signing pipeline, storage and lifecycle |
| [Audit map](docs/audit-map.md) | Audit scope, the two signing paths, where each claim is enforced |
| [Local storage](docs/storage.md) | Data directory, the encrypted database, credential-store entries |

**Working on it**

| Page | What's in it |
| --- | --- |
| [Development](docs/development.md) | Building, testing, the checks CI runs |
| [Releasing](docs/releasing.md) | Signing, provenance, trusted publishing |

Resolution logs for the automated security reviews run during development are
in [`audits/`](audits), one file per run, with a verdict and a fixing commit
recorded per finding.

## Licensing

Licensed under the [Functional Source License, FSL-1.1-MIT](LICENSE). In
plain terms: read it, build it, run it, audit it, patch it, and use it for
anything you like — except offering it, or a derivative of it, as a competing
product. Each release becomes plain MIT two years after it ships.
