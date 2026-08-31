# MCP transport security

Local harnesses start the installed `ekubo-wallet-mcp-bridge` command over
stdio with one fixed `--client` argument. The bridge completes MCP
initialization without the wallet, keeps stdout exclusively for MCP frames,
and uses stderr for diagnostics. It remains alive while the harness stdin is
open, reconnects automatically when a same-version wallet opens or restarts,
and enforces a 24 MiB frame ceiling in both directions. If wallet
initialization reports an incompatible bridge protocol, the bridge exits with a
diagnostic instead of retrying; the harness must launch the matching installed
helper in a new agent session. The installed path is fixed rather than
versioned, so it always holds the current wallet's helper and that next launch
matches without any change to the harness configuration.

Compatibility is decided on the bridge protocol in `bridge_protocol.rs`, which
the wallet publishes under a private `_meta` key in its `initialize` result —
not on build identity. The bridge forwards frames without interpreting tool
schemas, arguments, or results, so a wallet that adds a tool or changes any
behaviour behind one stays compatible with a bridge built before it, and only
a change to the framing, the hello frame, the sentinel ids, the reconnect
replay, or the capability set is a reason to refuse. Requiring exact build
agreement instead made every wallet update break live agent sessions. A wallet
that publishes no protocol predates the constant, and is still held to exact
build agreement, which is what those builds expect.

This is a compatibility guard and not an authorization control. The helper is
not an authorization boundary, and a bridge is not trusted by virtue of its
version: the wallet authenticates the peer by UID and applies its own policy
and approval rules to every request whatever bridge delivered it.

The wallet singleton listens on same-user local IPC only. macOS and Linux use
`mcp.sock` inside the wallet's private `0700` data directory; the socket is
`0600` and the accepted peer UID must match the directory owner. Windows uses
a named pipe restricted to the current user's SID and verifies the connected
peer SID. Native package signatures protect helper distribution integrity, not
IPC access. Same-user local code execution is the authorization boundary.

On Windows and Linux, that boundary currently extends beyond IPC: the generic
per-user credential backend does not isolate the SQLCipher key or raw account
keys to Ekubo Wallet. Same-user malware, or a prompt-injected harness allowed
to execute local programs, can query those credentials directly and create an
external signer without using MCP. The restricted MCP interface below never
exports a key, but it cannot enforce policy or review on a signer created by
this out-of-process credential-store bypass. See the
[threat model](threat-model.md#critical-windows-and-linux-credential-store-limitation).

Every bridge connection receives a new MCP session UUID and a freshly
restricted `WalletMcpServer`. The IPC layer receives `AgentApi`, not `OwnerApi`.
`AgentApi` is a server factory; the server it constructs intentionally opens
typed SQLCipher-backed stores and a narrow core execution authority. Those
capabilities let MCP tools read agent-visible wallet state, persist proposals
and transaction lifecycle records, and ask core only to run the guarded
automatic-transaction or exact-cancellation path. MCP never receives a
directly callable `KeyStore`, raw-key load, or arbitrary-signature operation;
the core authority privately owns the key-store dependency behind its two
guarded methods.

The server receives no owner-authorization capability and no operation that
exports raw key material, decides a native review, installs a signing policy,
accepts legal terms, or mutates owner-only settings. Its typed stores do not
expose an unrestricted database handle to MCP handlers, and the signer is used
only through core's guarded transaction paths. The bridge-provided harness
kind is stored only as untrusted activity attribution such as “via Claude
Desktop”; it never authorizes an operation.

Before its first wallet connection the bridge advertises an empty tool list.
After connection it replays the harness initialization parameters, refreshes
the catalog, and emits `notifications/tools/list_changed` when the catalog
changes. If the same-version wallet stops, in-flight requests fail clearly,
the last catalog is retained for useful offline errors, and the bridge
reconnects without a harness restart. A version mismatch is terminal.

Managed agent configuration contains the absolute installed helper path and
exact fixed harness argument under `ekubo_wallet`. Harnesses that support
remote MCP in the same file also receive the credential-free companion
`https://mcp.ekubo.org/mcp` under `ekubo`. Claude Desktop is different: its
JSON file contains only local stdio servers, so the user adds the companion as
an account-level custom connector through Customize → Connectors. Installing
or repairing managed file entries creates no credential and requires no owner
authentication. Grok Build uses its native `~/.grok/config.toml`
`[mcp_servers]` table with the same exact two managed entries.
Settings derives each larger check or X from those exact managed entries and
offers a typed install or removal for that agent alone.
It does not treat the number of live bridge processes as installation status:
harnesses start and stop their stdio bridges as needed.
The local transport has no HTTP listener, OAuth routes, bearer credentials, or
login flow. The hosted companion is an independent HTTPS service.

Execution simulation uses the configured RPC's `eth_simulateV1`; fork results
remain hypothetical and submission re-simulates against real chain state.
Recorded simulation IDs are short-lived plan handles only: consuming one runs
fresh simulation, exact envelope preparation, and current-policy evaluation.
There is no local EVM or `eth_getProof` reconstruction; no simulated state is stored or reconstructed locally.
In particular, a simulation fork cannot create a pending request.

Signing policy is scoped to the wallet account, not the requesting MCP session.
A rule with no `source` matcher matches whoever asks, so an allow rule proposed
for an agent also permits an equivalent transaction requested by an installed
automation or a connected dapp.

A rule may carry a `source` matcher naming the channel — `agent`,
`walletconnect`, or `automation` — and, within `agent`, the harness kind and
the TLS-vetted host that served the plan. The harness kind is the `--client`
argument the bridge passed and stays untrusted: a same-user process is in scope
and can pass any of them, so such a rule separates one honest harness from
another rather than excluding a hostile one. There is still no matcher for the
MCP session, and none for the recorded `plan_source` text, which remains
informational activity context. Naming a source only ever shrinks what a rule
matches, so a harness claim can restrict a permission and can never create one.
MCP can ask for one otherwise allowed submission to receive native review, but
that request can only add review and cannot override a deny or approve anything.
Token symbols and decimals are owner-confirmed display metadata and are never read from the contract.
