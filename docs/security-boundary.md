# Security boundary

The [system-wide threat model](threat-model.md) defines the actors, trust
assumptions, persistence and rollback behavior, and accepted residual risks
that surround this code boundary.

Private keys and signing remain inside the core authority. MCP never receives
`OwnerApi`. Its constructed server has typed storage and signer capabilities
needed to persist requests and execute transactions allowed by policy, but no
methods for raw-key export, native-review decisions, policy installation,
legal acceptance, owner authorization, or owner-only settings mutation.

Policies may allow a transaction automatically or require native review. A
deny rule is terminal. Typed data and personal messages always require native
review because reusable off-chain authority cannot be bounded by transaction
policy. Before every signature approved through native review, the authority
re-reads current request and policy state after OS authentication. An automatic
transaction instead reaches the signer only when the current core-owned policy
allows its exact transaction fields.

Exact calldata, message bytes, complete typed data, digest, warnings, Unicode
controls, bidi controls, and confusable characters remain available in the
review. By default, transaction notifications name the account and network but
never show the request identifier or contain approval actions.

Public HTTPS and bounded `data:application/json` artifacts are supported.
Local-file artifacts are not.
