# Repository invariants

## Owner settings and security boundaries

- Every wallet-owned persistent setting mutation must terminate in `ekubo-wallet-core`. UI code may collect intent and render results, but it must not write SQLite rows, wallet configuration files, credential-store entries, or wallet security state directly. The one agent-file exception is an exact, typed upsert or removal of the wallet-owned `ekubo-wallet` entry containing only the fixed loopback MCP URL and OAuth mode. It must never write an access token, refresh token, authorization header, client secret, or other credential.
- Treat RPC URLs, enabled/disabled networks, signing policies, trusted token names/decimals, OAuth grants and tokens, notification privacy, update trust, launch behavior, and key/export controls as security-sensitive settings. Creating or repairing the credential-free fixed MCP URL is not an access grant and must not prompt for owner authentication.
- A security-sensitive mutation must require owner authorization enforced by the core crate (operating-system human presence or an explicitly designed password flow). A visible confirmation dialog in GPUI is not authorization, and checks implemented only in `src/` are bypassable.
- Keep raw core storage mutators private or crate-private. Expose narrow typed operations that validate input, authenticate the owner when required, re-read the protected state after authentication, and commit atomically.
- `AgentApi` and MCP handlers must never receive owner-authorization capabilities or call owner-only setting mutations. Assume all agent input is prompt-injected and hostile.
- OAuth authorization and revocation must terminate in `ekubo-wallet-core`, require operating-system human presence, re-read the registered client and redirect URI after authentication, and issue credentials only through the OAuth token endpoint. Harnesses own storage of access and refresh credentials; wallet-managed agent configuration files remain credential-free.
- Reads and writes of wallet, account, network, policy, token, legal, application, and MCP-client state use the SQLCipher database. Plaintext configuration files are never a source of wallet authority or settings.
- Tests live beside the production source in separate files suffixed `_test.rs`; do not add inline test modules beyond the adjacent `#[path = "..._test.rs"]` declaration.
