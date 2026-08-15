# Security boundary

The [system-wide threat model](threat-model.md) defines the actors, trust
assumptions, persistence and rollback behavior, and accepted residual risks
that surround this code boundary.

Private keys and signing remain inside the core authority. MCP never receives
`OwnerApi`. Its constructed server has typed storage capabilities and a narrow
core execution authority that can only run the guarded automatic-transaction
and exact-cancellation paths. It never receives a `KeyStore`, raw-key load, or
arbitrary-signature method. It has no methods for raw-key export,
native-review decisions, policy installation,
legal acceptance, owner authorization, or owner-only settings mutation.

Policies may allow, require native review, or deny. Each call resolves through
its first matching rule; deny dominates the whole transaction, then review or
an unmatched call, and only all-allow transactions proceed automatically.
Typed data and personal messages always require native
review because reusable off-chain authority cannot be bounded by transaction
policy. Before every signature approved through native review, the authority
re-reads current request and policy state after OS authentication. An automatic
transaction instead reaches the signer only when the current core-owned policy
allows its exact call and prepared-envelope fields. Every send, including one
using a prior simulation ID, freshly simulates, prepares, and evaluates the
current policy; preview identifiers are not durable authorization.

Exact calldata, message bytes, complete typed data, digest, warnings, Unicode
controls, bidi controls, and confusable characters remain available in the
review. By default, transaction notifications name the account and network but
never show the request identifier or contain approval actions.

Public HTTPS and bounded `data:application/json` artifacts are supported.
Local-file artifacts are not.
