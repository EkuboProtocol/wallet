# MCP transport security

The only MCP listener is the fixed private-range port `61744` on `127.0.0.1`,
route `/mcp`, with a 24 MiB body ceiling. GET, POST, and DELETE are authenticated
before body decoding. OPTIONS, every request with `Origin`, every request with
an `Access-Control-*` header, and a request whose `Host` is not exactly
`127.0.0.1:61744` are rejected before body decoding. No CORS or unauthenticated
health route exists. OAuth discovery and registration routes are the only
mandated unauthenticated protocol surface.

Agent configuration carries only `http://127.0.0.1:61744/mcp`; installing or
repairing it creates no credential and requests no owner authentication. OAuth
uses Dynamic Client Registration for public client metadata, Authorization Code
with S256 PKCE, exact redirect-URI matching, the canonical MCP resource
indicator, and rotating refresh tokens with an owner-selected absolute
lifetime. The local, script-free consent page is the authority for the curated
access/refresh lifetime pairs. It cannot be framed (`X-Frame-Options: DENY` and
CSP `frame-ancestors 'none'`) and requires an opaque, one-use server nonce before
human presence. The native OS prompt names both the requesting client and
callback host. Only after the owner authenticates can a one-time code be
minted, and only the token endpoint returns credentials to the harness.

SQLCipher stores one-way credential hashes and client attribution. Access-token
authentication scans active hashes using constant-time byte comparison. Refresh
reuse revokes its token family; owner revocation immediately deletes the
client's active access and refresh tokens. Client identity is the attribution
and isolation namespace for MCP sessions, forks, and simulations.

If port 61744 is occupied the MCP server remains offline and reports the
collision. It does not silently select another port because that would change
the OAuth resource identity and invalidate every installed URL.

This protects against accidental and unauthorized local clients. It does not
claim that plaintext loopback HTTP can defeat malicious code already executing
as the same OS account.

Execution simulation uses the configured RPC's `eth_simulateV1`; fork results
remain hypothetical and submission re-simulates against real chain state.
There is no local EVM and no `eth_getProof` reconstruction. In particular, no simulated state is stored or reconstructed locally, and a fork cannot create a pending request.
Token symbols and decimals are owner-confirmed display metadata and are never read from the contract.
