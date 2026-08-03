# Rust architecture

The `ekubo-wallet` executable contains the CLI and stdio MCP server. The MCP
surface is deliberately an adapter over the same application services used by
the CLI; there is no second signing implementation.

## Selected components

- `rmcp`: official Rust MCP SDK and stdio transport.
- `alloy`: Ethereum primitives, ABI support, HTTP JSON-RPC, EIP-7702 transaction
  construction, signing, and receipt handling.
- `revm` with `AlloyDB`: isolated in-process EVM execution with state fetched
  lazily from the configured RPC at a fixed block.
- `rusqlite` with bundled SQLite: policy revisions, reservations, spend
  accounting, and transaction lifecycle state in one portable binary.
- `keyring`: platform credential-store abstraction. Production builds use
  macOS Keychain, Windows Credential Manager, and Linux Secret Service.
- `HumanPresence`: an application-owned abstraction implemented with macOS
  LocalAuthentication, Windows UserConsentVerifier, and Linux polkit. Export
  and exceptional approval cannot be completed by MCP input alone.

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
