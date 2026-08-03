# Rust architecture

The `ekubo-wallet` artifact contains CLI, stdio MCP, and wallet-core service
modes. The MCP and CLI surfaces are deliberately adapters over the same core
services; there is no second signing implementation. On platforms where a
same-user credential store cannot identify the Ekubo executable, the core runs
under a dedicated OS service identity and is the only mode that opens
security-state storage or loads keys.

## Selected components

- `rmcp`: official Rust MCP SDK and stdio transport.
- `alloy`: Ethereum primitives, ABI support, HTTP JSON-RPC, EIP-7702 transaction
  construction, signing, and receipt handling.
- `revm` with `AlloyDB`: isolated in-process EVM execution with state fetched
  lazily from the configured RPC at a fixed block.
- `rusqlite` with bundled SQLite: policy revisions, reservations, spend
  accounting, and transaction lifecycle state in one portable binary. All
  authoritative records are MAC chained and checked against a credential-store
  anti-rollback anchor; SQLite bytes are treated as attacker-writable.
- `keyring`: platform credential-store abstraction. Production builds use
  macOS Keychain, Windows Credential Manager, and Linux Secret Service.
- `cliclack`: accessible, styled terminal prompts, warnings, and status for the
  direct-CLI approval fallback. Machine-readable command output stays on
  stdout; interactive UI stays on stderr.
- `HumanPresence`: an application-owned abstraction implemented with macOS
  LocalAuthentication, Windows UserConsentVerifier, and Linux polkit. Export
  and exceptional approval cannot be completed by MCP input alone.
- `ApprovalUi`: a presentation boundary with terminal, ephemeral loopback web,
  and MCP Apps implementations. Every implementation displays the same
  immutable server-authored request and can approve only its exact digest.

## Custody invariants

1. MCP inputs and results never contain a private key.
2. A normal signing request is accepted only as a structured execution plan.
   There is no generic `sign_hash` or `sign_transaction` command.
3. The application independently simulates, evaluates the active policy,
   reserves limits, prepares the transaction, signs, validates, and broadcasts.
4. Raw-key export is an explicit recovery transition requiring platform human
   presence. Export means the address may thereafter be controlled externally;
   the application records that fact and cannot claim exclusive enforcement.
5. Imported wallets are never described as exclusively controlled, because an
   earlier copy of their key may exist.

`KeyStore`, `HumanPresence`, `Rpc`, and fork database boundaries are traits.
This keeps platform code small and makes denial, cancellation, rollback, and
tampering behavior testable without weakening production paths.

See [the threat model](threat-model.md) for the authenticated SQLite protocol,
platform limitations, residual attacks, and release blockers. See [approval
UX](approval-ux.md) for terminal, browser, and ChatGPT-compatible review flows.
