# MCP transport security

The only MCP listener is a persisted random high port on `127.0.0.1`, route
`/mcp`, with a 24 MiB body ceiling. GET, POST, and DELETE are authenticated
before body decoding. OPTIONS, every request with `Origin`, and a request whose
`Host` is not the exact expected loopback authority are rejected. No CORS or
unauthenticated health route exists.

Each registration has a random 32-byte unpadded-base64url bearer token stored
inside SQLCipher. Authentication scans active tokens using constant-time byte
comparison. Rotation invalidates the previous value; revocation and removal are
per client. Client identity is the attribution and isolation namespace for MCP
sessions, forks, and simulations.

If the persisted port is occupied the MCP server remains offline. The owner can
choose a new port and repair managed registrations after reviewing their diffs.

This protects against accidental and unauthorized local clients. It does not
claim that plaintext loopback HTTP can defeat malicious code already executing
as the same OS account.

Execution simulation uses the configured RPC's `eth_simulateV1`; fork results
remain hypothetical and submission re-simulates against real chain state.
There is no local EVM and no `eth_getProof` reconstruction. In particular, no simulated state is stored or reconstructed locally, and a fork cannot create a pending request.
Token symbols and decimals are owner-confirmed display metadata and are never read from the contract.
