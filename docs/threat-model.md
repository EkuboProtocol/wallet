# Desktop wallet threat model

This document describes the current desktop wallet. `docs/security-boundary.md`
provides the companion code-oriented boundary map.

## Assets and trust boundaries

Protected assets include private keys, signed transactions and messages, owner
policy, network and token metadata, update authority, and privacy-sensitive
settings. Wallet authority lives in SQLCipher or the OS credential store;
plaintext configuration files are not wallet authority.

`ekubo-wallet-core` is the security kernel. GPUI, MCP agents, dapps, RPC
servers, relays, token lists, update hosting, clipboard contents, imported
files, and the harness-reported client kind are untrusted. Agent input is
assumed prompt-injected and hostile. OS human-presence services, platform
credential storage, release signing keys, and pinned dependencies are trusted
within their documented purposes.

An unlocked-window attacker may automate GPUI but cannot satisfy a fresh OS
human-presence challenge. A same-user process can access the local MCP IPC by
design and can deny service. Debugger/injection access, a compromised loaded
dependency or OS, and control of the wallet process are out of scope.

## Owner authorization

Security-sensitive mutations terminate in core through narrow typed
operations. A visible dialog is not authorization. Core requests human
presence, issues a short-lived scope-bound capability, re-reads protected state
after authentication, and commits atomically. Dapp approval binds the exact
review and account. Update authorization binds publisher, version, platform,
format, canonical URL, and verified digest.

## Local MCP IPC

Harnesses spawn a minimal stdio bridge which survives wallet downtime and
connects to the singleton through same-user local IPC. Unix uses a `0600`
socket in the wallet's `0700` data directory and rejects a foreign UID. Windows
uses a current-user-only named-pipe DACL and rejects a foreign peer SID. Helper
signatures establish package integrity and do not authorize IPC.

Each bridge connection creates a fresh restricted MCP server and session UUID.
Only `AgentApi` enters that server; owner authorization, raw storage, custody,
exports, and owner-only mutations do not. Harness kind is informational
activity attribution only. The local stack has no HTTP or OAuth surface.
Managed configurations contain only the installed helper command with a fixed
`--client` argument and the independent hosted companion URL.

## WalletConnect and dapps

Pairing URIs and relay traffic are untrusted. Pairing and session keys are
separate; a settled session accepts only approved accounts, chains, and
methods. Approval authenticates the exact proposal-derived review and account,
then re-reads account, network, and review state. Sessions have a fixed
seven-day deadline; incoming extension requests cannot move it.

## RPC, transactions, and policy

RPC responses, simulations, fee data, receipts, and broadcasts are untrusted.
Signing uses a server-authored review identity which changes with displayed
content. Account replacement, digests, policy, simulation, nonce, and fee
assumptions are revalidated at signing. Policy can reduce prompts but cannot
grant custody, exports, settings mutation, or owner capabilities.

## Updates and release supply chain

Update metadata and hosting are untrusted. `latest.json` and artifacts are
Minisign-verified; core checks the bundled version marker and repeats checks
immediately before installation. Platform signing precedes final updater
signing. Apple and Windows signing services and release keys remain trust
dependencies whose compromise requires publication halt, key rotation through
a trusted channel, and an audit of released bytes and workflow logs.

The signed native package covers the separately bundled MCP helper during
distribution. The wallet atomically installs a versioned copy in its private
per-user directory, but does not treat the helper's hash or code signature as
authorization: any process already running as the same user can connect to the
local MCP endpoint directly.

## Local platform and lifecycle

The OS credential store protects the database key and account keys.
Notifications default to privacy-preserving content. Explicit Quit disconnects
WalletConnect, stops local MCP IPC, and installs only an already verified,
exactly authorized update. Hiding or closing windows does not mutate protected
state.

SQLCipher authenticates pages at rest but does not provide freshness. A
same-user process able to replace the database may roll it back to an earlier
valid state. Backups therefore remain sensitive; rollback can restore old
settings or erase local audit history.

## Residual risks and response

The wallet cannot make a compromised OS, injected process, dependency,
authenticated owner session, release key, or platform signing service
trustworthy. Physical attackers able to satisfy OS authentication,
administrators controlling OS facilities, denial of service, traffic analysis,
and recovery from total host compromise are out of scope. Suspected local
compromise calls for disconnecting dapps, rotating affected wallet keys, and
rebuilding from pinned source.

Security regressions are guarded by adjacent Rust tests, IPC capability and
schema-boundary tests, action-pin checks, updater fixtures, and release
signature verification. Trust-boundary changes must update this document and
their tests together.
