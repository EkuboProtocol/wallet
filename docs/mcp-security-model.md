# MCP transport security

Local harnesses start the installed `ekubo-wallet-mcp-bridge` command over
stdio with one fixed `--client` argument. The bridge completes MCP
initialization without the wallet, keeps stdout exclusively for MCP frames,
and uses stderr for diagnostics. It remains alive while the harness stdin is
open, reconnects automatically when the wallet opens or restarts, and enforces
a 24 MiB frame ceiling in both directions.

The wallet singleton listens on same-user local IPC only. macOS and Linux use
`mcp.sock` inside the wallet's private `0700` data directory; the socket is
`0600` and the accepted peer UID must match the directory owner. Windows uses
a named pipe restricted to the current user's SID and verifies the connected
peer SID. Code signatures protect packaged helper integrity, not IPC access.
Same-user local code execution is the authorization boundary.

Every bridge connection receives a new MCP session UUID and a freshly
restricted `WalletMcpServer`. The transport receives `AgentApi` only: it has no
owner authorization, database, Keychain, custody, export, or settings-mutation
capability. The bridge-provided harness kind is stored only as untrusted
activity attribution such as “via Claude Desktop”; it never authorizes an
operation.

Before its first wallet connection the bridge advertises an empty tool list.
After connection it replays the harness initialization parameters, refreshes
the catalog, and emits `notifications/tools/list_changed` when the catalog
changes. If the wallet stops, in-flight requests fail clearly, the last catalog
is retained for useful offline errors, and the bridge reconnects without a
harness restart.

Managed agent configuration contains the absolute installed helper path and
exact fixed harness argument under `ekubo_wallet`. It also retains the
credential-free, always-installed companion `https://mcp.ekubo.org/mcp` under
`ekubo`.
Installing or repairing them creates no credential and requires no owner
authentication.
The local transport has no HTTP listener, OAuth routes, bearer credentials, or
login flow. The hosted companion is an independent HTTPS service.

Execution simulation uses the configured RPC's `eth_simulateV1`; fork results
remain hypothetical and submission re-simulates against real chain state.
There is no local EVM or `eth_getProof` reconstruction; no simulated state is stored or reconstructed locally.
In particular, a simulation fork cannot create a pending request.
Token symbols and decimals are owner-confirmed display metadata and are never read from the contract.
