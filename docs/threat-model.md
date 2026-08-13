# Desktop wallet threat model

This document describes the security model of the current desktop wallet. It is maintained with the implementation; `docs/security-boundary.md` gives the companion code-oriented boundary map.

## Assets and trust boundaries

The protected assets are private keys, signed transactions and messages, owner policy, network and token metadata, OAuth grants and credentials, update authority, and privacy-sensitive application settings. Wallet, account, network, policy, token, legal, application, and MCP-client state lives in the SQLCipher database. Plaintext files are not wallet authority.

`ekubo-wallet-core` is the security kernel. GPUI is a presentation and intent-collection surface. The loopback MCP HTTP transport, MCP agents, dapps, RPC servers, relays, token lists, update hosting, clipboard contents, and imported files are untrusted. Agent input is assumed to be prompt-injected and hostile. OS human-presence services, the SQLCipher/key-store platform facilities, the release signing keys, and pinned build dependencies are trusted within their documented purposes.

An unlocked-window attacker may click or automate GPUI but cannot satisfy a fresh OS human-presence challenge. A process already running as the same OS user can observe or alter much of that user's environment and can deny service; loopback alone is not protection from it, so bearer-token checks and core authorization still apply. A process with debugger/injection access, a compromised loaded dependency, a compromised OS/kernel, or control of the wallet process is in-process compromise and is out of scope: it can read or rewrite memory before any Rust capability boundary executes.

## Owner authorization

Security-sensitive mutations terminate in core through narrow typed operations. A visible GPUI confirmation is not authorization. Core asks the operating system for human presence, issues a short-lived scope-bound capability, re-reads protected state after authentication, and commits atomically. Raw storage mutators remain private or crate-private.

Authorizations are separated by purpose: agent access, dapp access, update trust, signing policy, network settings, trusted token metadata, and notification privacy. Dapp approval is single-use and binds the exact review identity and selected account. Update authorization binds publisher, version, platform target, format, canonical artifact URL, and the verified package SHA-256. OAuth revocation and client removal bind the registered client identity and redirect URI set and reject stale state.

## MCP and OAuth

The MCP server listens only on the fixed loopback endpoint and requires an OAuth access token for the exact MCP resource. Dynamic registration grants no access. OAuth authorization, code issuance, refresh, revocation, and client removal terminate in core; authorization and revocation require OS human presence and re-read the registered client and redirect URI after authentication. Credentials are issued only by the token endpoint.

The HTTP server holds `OAuthApi`, a protocol-only capability, plus `AgentApi`. It never receives `OwnerApi`, a raw database handle, owner authorization, custody, export, policy mutation, or client-revocation methods. Wallet-managed agent configuration contains only the exact `ekubo_wallet` loopback URL and OAuth mode; it never stores tokens or changes a harness-wide credential-store policy.

## WalletConnect and dapps

Pairing URIs and relay traffic are untrusted credentials and input. Pairing and session keys are separate; a settled session accepts only the approved account, chains, and methods. Proposal metadata is self-asserted and displayed as such. Approval authenticates the exact proposal-derived review and account, then re-reads the account, networks, and review identity before key agreement or settlement.

The wallet is the session controller. Settlement creates a fixed seven-day deadline that is shown in the UI. Incoming `wc_sessionExtend` receives `UNAUTHORIZED_EXTEND` (3004) and cannot move the deadline; renewal requires disconnecting and approving a new session. Expiry gates every session method, and replay identifiers are bounded.

## RPC, transactions, and policy

RPC endpoints, chain responses, simulations, fee data, receipts, and broadcasts are untrusted. Network configuration changes require core authorization. Signing uses a server-authored review document whose identity changes with displayed content. Account replacement, request digests, policy state, simulation state, nonce and fee assumptions are revalidated at the signing boundary. Policy can reduce prompts but cannot grant an agent custody, exports, settings mutation, or owner capabilities.

## Updates and release supply chain

Update metadata and artifact hosting are untrusted. `latest.json` is Minisign-signed, and the application verifies that signature before accepting its version, target, format, URL, or artifact signature. The separately signed artifact is verified on download. The exact verified bytes and authenticated metadata are re-read in core immediately before installation, and an ordinary quit has no installer capability.

Release workflow actions are pinned to full commit SHAs and checked by a dedicated pull-request workflow. Jobs start with no permissions and receive only their minimum permissions. Platform signing precedes final updater signing: Windows Authenticode mutates the installer first, then the final EXE is re-signed for the updater. The publish job verifies every final package signature, signs `latest.json`, verifies its signature, publishes the same bytes, and attests the release assets. Apple and Windows platform signing services remain external trust dependencies; compromise of a release private key can authorize malicious releases and requires key revocation and a trusted recovery release.

## Local platform and lifecycle

The OS credential store protects the database key and account keys. Launch-at-login changes are part of authenticated agent-access operations. Notifications default to privacy-preserving content unless the owner authorizes a change. Explicit Quit disconnects WalletConnect, stops MCP, and installs only a previously downloaded, verified, exactly authorized update. Hiding or closing ordinary windows does not silently mutate protected state.

SQLCipher authenticates database pages at rest but does not provide freshness. Filesystem snapshots, backup tools, or a same-user process able to replace the database can roll the entire encrypted store back to an earlier internally valid state. The wallet prevents partial plaintext authority and uses atomic transactions, but it does not currently maintain a hardware-backed monotonic database generation. Owners must treat backups as sensitive, and rollback can restore old policy/settings or erase local audit history; externally expired OAuth tokens and on-chain state remain bounded by their own clocks and chains.

First installation is a separate trust decision: no previously installed updater key exists to authenticate it. The owner trusts the download channel plus Apple Developer ID/notarization, Windows Authenticode, or the Linux distribution path and should verify published provenance where available. Once installed, the embedded updater public key separates update authorization from GitHub release-writing authority.

## Residual risks and response

The wallet cannot make a compromised OS, injected process, loaded dependency, authenticated owner session, release signing key, or upstream platform-signing service trustworthy. Physical attackers who can satisfy the owner's OS authentication, administrators who can replace the OS facilities, denial of service, traffic analysis, malicious-but-correct RPC censorship, and recovery from complete host compromise are explicitly out of scope. Misleading dapp identity metadata remains possible, so consequential reviews expose exact endpoints, accounts, chains, methods, and effects. Suspected credential compromise is handled by revoking the exact OAuth client, disconnecting dapps, rotating affected wallet keys, and rebuilding from pinned source. Suspected release-key compromise requires halting publication, rotating the updater key through a previously trusted distribution channel, and auditing published artifacts and workflow logs.

Security regressions are guarded by adjacent Rust tests, the HTTP capability boundary test, action-pin policy checks, updater metadata fixtures, and release signature verification. Changes to a trust boundary must update this document and the corresponding test in the same pull request.
