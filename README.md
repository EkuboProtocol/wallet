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
Plans arrive by URL — a producer reference's public https URL, verified
against the keccak256 digest published beside it, or a `data:application/json`
URI carrying the plan inline — so the agent relaying a plan between servers
passes a line of text instead of the plan body.

This is security-sensitive software. It has not been independently audited, and
nothing here should be read as a claim that it has.


## Quick install

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
- Simulation through the configured RPC's typed `eth_simulateV1` method. There
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
- [Networks](docs/networks.md) — built-in profiles, adding a chain, RPC
  requirements
- [Policies](docs/policies.md) — what a policy can express, the shipped
  templates, editing one
- [MCP tools](docs/mcp-tools.md) — every tool, the token database, simulation
  forks, local read decoding
- [Approval flow](docs/approval-ux.md) — reviewing and resolving an exceptional
  request in the terminal
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
