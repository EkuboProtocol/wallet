# Ekubo Wallet MCP Server

`ekubo-wallet` is a local EVM wallet, command-line tool, and stdio MCP server.
It enforces transaction policy in the same process that reads the signing key,
and exposes no arbitrary-message, arbitrary-hash, or raw-transaction signing
tool.

It is a general-purpose wallet, not a companion to any particular protocol,
dapp, or other MCP server. Any tool can produce a signer-neutral execution plan;
this wallet validates, simulates, and policy-checks every plan identically
regardless of where it came from, and treats all of them as untrusted input.
Plans arrive by URL — a producer reference's public https URL, verified
against the keccak256 digest published beside it, a `data:application/json`
URI carrying the plan inline, or a `file:` URL naming a body written to this
machine's disk and described with `ekubo-wallet meta-reference <path>` — so the
agent relaying a plan between servers, or assembling one of its own out of
several, passes a line of text instead of the plan body.

The installer registers the Ekubo protocol server alongside this wallet so a
new install can actually transact, and that is a packaging convenience rather
than a hole in the paragraph above: nothing in this wallet knows that server
from any other producer, and its plans get the same treatment as everyone
else's. It can be declined at install time.

This is security-sensitive software. It has not been independently audited, and
nothing here should be read as a claim that it has.


## Quick install

The installer downloads the archive for your platform, **verifies the Sigstore
signature over `SHA256SUMS` and the archive's SHA-256 checksum against it
before extracting anything**, installs `ekubo-wallet`, registers it with every
agent CLI it detects (Codex, Claude Code, Gemini CLI, and Cursor), and installs
completion for your login shell:

```sh
curl -fsSL https://raw.githubusercontent.com/EkuboProtocol/wallet-mcp-server/main/install.sh | sh
```

Read [`install.sh`](install.sh) before piping it to a shell. Replace `main` with
an exact release tag for a reproducible installation.

`cosign` is required: the checksum file is served from the same place as the
archive, so it catches a truncated download rather than a chosen one, and the
signature is what names a builder. See
[installation](docs/installation.md) if you need to install without it.

The installer registers a second server alongside the wallet: the Ekubo
protocol server at `https://mcp.ekubo.org/mcp`, as `ekubo`. That is what makes
a fresh install able to quote, swap, bridge, and provide liquidity rather than
only hold keys. It is a convenience, not an exception — it prepares unsigned
plans and never sees a key, and every plan it produces is validated,
simulated, and policy-checked here exactly like a plan from anywhere else.
`EKUBO_WALLET_SKIP_COMPANION=1` installs the wallet without it, and
`ekubo-wallet meta-agent remove` takes both back.

Then accept the legal documents and create a wallet:

```sh
ekubo-wallet legal accept
ekubo-wallet account create primary
```

`account create` asks which policy template the new account starts under. See
[first use](docs/first-use.md) for what each one permits, and
[installation](docs/installation.md) for release archives, manual installation,
and registering the server by hand.


## What it provides

- OS-credential-store custody for generated or imported secp256k1 keys.
- A stateless, per-transaction policy for chains, targets, selectors, native
  value, ERC-20 recipients and spends, approval spenders and amounts, and batch
  size.
- Exact execution through a direct EIP-1559 transaction or one atomic Calibur
  batch, with EIP-7702 authorization when required.
- Simulation through the configured RPCs' typed `eth_simulateV1` method. Each
  network carries several endpoints and fails over between them, so one public
  RPC rate-limiting the wallet does not stop it signing. There
  is no local EVM, `eth_getProof` state reconstruction, or `eth_call`
  fallback for signing decisions.
- Temporary simulation forks so an agent can simulate a chain of dependent
  actions — and read the world between them — before the user is asked to
  approve the first step. Forks are hypothetical throughout and never sign,
  approve, or satisfy a policy rule.
- Human approval for every off-chain signature — EIP-712 typed data and EIP-191
  messages alike, permits included. No policy authorizes a signature, because a
  per-transaction limit cannot bound something its holder redeems whenever it
  likes.
- A WalletConnect v2 session, from a pasted link, that lets a dapp propose
  transactions and signatures under exactly the privileges an agent has — the
  same plan, the same policy, the same review — and under a scope fixed when
  you approve the connection.
- SQLCipher-backed policy and pending-transaction storage.
- Deterministic ABI return/error decoding, bounded batch reads, native/ERC-20
  transfer helpers, pending approval, receipt reconciliation, and exact-byte
  rebroadcast after ambiguous submission.

There are deliberately no daily limits, rolling windows, spend counters,
reservations, or spend-history command/tool. Pending transaction rows are
lifecycle records, not spending-accounting state.


## Documentation

Using it:

- [Installation](docs/installation.md) — release archives, manual install,
  registering the MCP server by hand
- [First use](docs/first-use.md) — accepting the legal documents, creating a
  wallet, choosing its policy
- [Networks](docs/networks.md) — the 45 default networks and the 852-chain
  registry behind them, endpoint failover, adding a chain, RPC requirements
- [Policies](docs/policies.md) — what a policy can express, the shipped
  templates, editing one
- [MCP tools](docs/mcp-tools.md) — every tool, the token database, simulation
  forks, local read decoding
- [Approval flow](docs/approval-ux.md) — reviewing and resolving an exceptional
  request in the terminal
- [WalletConnect](docs/walletconnect.md) — connecting to a dapp from a pasted
  link, what a dapp may propose, the relay project id
- [Batching](docs/batching.md) — how multi-call plans execute atomically through
  EIP-7702

How it works, and what it does not protect against:

- [Security boundary](docs/security-boundary.md) — what is trusted, why keys sit
  outside the database, why nothing enforces presence
- [Threat model](docs/threat-model.md) — signing invariants, attack analysis,
  residual risks
- [Architecture](docs/architecture.md) — components, the signing pipeline,
  storage and lifecycle
- [Audit map](docs/audit-map.md) — the audit scope, the two signing paths,
  and where each security claim is enforced in code
- [Local storage](docs/storage.md) — data directory, the encrypted database,
  credential-store entries

Working on it:

- [Development](docs/development.md) — building, testing, the checks CI runs
- [Releasing](docs/releasing.md) — signing, provenance, and the
  trusted-publishing setup

> **The policy is the security boundary.** Keys carry no biometric or presence
> requirement, deliberately: this wallet exists so an agent can work unattended,
> and a key the OS will not release without a live human cannot sign at 3am.
> Whatever a wallet's policy permits is reachable without a further gate, so
> choose it — and fund the wallet — on that basis. See
> [security boundary](docs/security-boundary.md).

## Licensing

No open-source license is granted. See [LICENSE](LICENSE).
