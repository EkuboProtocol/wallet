# Threat model

Status: implemented release candidate. The listed automated checks pass in CI;
this statement is not a claim of independent security audit.

## Objective and trust boundary

An MCP client may propose a structured transaction but cannot obtain arbitrary
signatures or weaken policy. The process that reads the signing key must parse,
simulate, evaluate policy, sign, validate, persist, and broadcast the exact
transaction.

The MCP client, model-generated input, configured RPC, and filesystem are
untrusted. The wallet process and loaded code, OS credential/authentication
APIs, and explicit human input are trusted. Administrator, kernel, debugger,
malicious dependency, and arbitrary in-process code execution are out of scope.

The supported server is one `ekubo-wallet server` stdio process. There is no
privileged daemon or custom IPC. CLI management commands are local, interactive
processes and expose no generic signing primitive.

## Signing invariants

1. Private keys never appear in MCP inputs/results, policies, logs, config, or
   SQLCipher rows.
2. Signing accepts a validated structured plan, never an arbitrary digest or
   caller-supplied serialized transaction. Off-chain signatures are equally
   structured: EIP-712 typed data is parsed and re-hashed locally, and EIP-191
   messages are hashed from their exact stored bytes under the `0x19` prefix.
   Legacy raw `eth_sign` over a bare unprefixed 32-byte digest is refused,
   because that digest is indistinguishable from a transaction, permit, or
   EIP-7702 authorization hash and no approval screen can describe it
   truthfully.
   A message signature has no readable on-chain effect for the policy language
   to score, so every message queues for human review with no automatic path;
   its review escapes control characters, terminal escape sequences, and
   Unicode bidirectional overrides, because the message body is attacker-
   controlled text rendered into the approver's terminal.
3. The signed sender, chain, target, value, calldata, transaction type, nonce,
   gas, fees, and EIP-7702 authorization are constructed locally and validated
   after signing.
4. Automatic signing uses the policy revision evaluated for the simulation and
   atomically verifies that revision before the signed bytes can enter the
   submission queue.
5. Exceptional review binds the exact prepared transaction fields. After OS
   authentication, mutable local configuration and policy are reloaded and no
   further RPC lookup occurs before signing.
6. Policy exceptions, policy/network changes, key export, and wallet removal
   require OS-backed owner authentication. The MCP has no approval operation.
7. Exact signed bytes and their hash are durably stored before first
   submission. An ambiguous submission can only rebroadcast those bytes.
8. An export timestamp is committed before raw key material is returned, so a
   failed metadata write cannot leak a key unrecorded. That record is a sound
   positive and an unsound negative: a timestamp proves this tool revealed the
   key, while its absence proves only that `wallet export` never ran. Keys live
   in the OS credential store, which the owner can read with their login
   credential and anything running as them can reach, so no wallet is ever
   described as exclusively controlled and nothing in the policy, signing, or
   approval path reads the record.

## Policy and database state

Policies contain only stateless, per-transaction or per-batch controls: chains,
targets, selectors, recipients, token spends, approval spenders/amounts, native
value, and batch size. There are no daily limits, rolling windows, counters,
reservations, or spend-history records.

One SQLCipher database stores current policy rows and separate pending
lifecycle rows. Its random 256-bit key is stored outside the database in the OS
credential store and zeroized after use. Production startup does not generate a
replacement key for an existing database. It also fails if configured wallet
metadata has no corresponding policy.

SQLCipher page authentication, cipher/logical integrity checks, fixed
parameterized SQL, private filesystem permissions, disabled trusted schema,
secure deletion, full synchronization, and DELETE journal mode reduce the
filesystem attack surface. A transient rollback journal can exist during a
write; there is no persistent WAL.

## RPC boundary

Signing simulation uses `eth_simulateV1` against a pinned parent block. The
process checks returned block linkage and count, sends the exact target/value/
calldata as the first execution call, applies the precise EIP-7702 delegation
override when needed, and derives token/native observations from returned
results and logs. It does not run a local EVM, call `eth_getProof`, or fall
back to `eth_call` for a signing decision.

Temporary simulation forks extend the same request shape rather than the trust
boundary: a fork is an ordered list of already-validated plans replayed as
consecutive simulated blocks in one `eth_simulateV1` call, so the RPC remains
the only executor. A fork cannot create a pending request, produce signed
bytes, mark anything approved, or satisfy a policy rule, and its policy
findings are advisory. Submission re-simulates and re-policy-checks against
real chain state, which closes the obvious attack where an agent establishes a
benign fork history and then submits something else. Fork state is never
persisted and never shown at approval time, so a human is never asked to read
agent-supplied hypotheticals while deciding whether to sign.

The RPC still executes the EVM, supplies state, gas/fee estimates, receipts,
and transaction visibility. It can lie, censor, or be stale. Pinning and local
validation detect structural mismatches, not a coherently dishonest endpoint.
Use a trusted authenticated provider—or an independently designed quorum
boundary—for funded production wallets.

RPC URLs can contain credentials. They are never returned by MCP inventory, and
known URL strings are redacted from surfaced errors, but `config.json` stores
them locally. Use credentials whose disclosure scope is appropriate for the
local MCP host. For `wallet_add_network`, complete local validation and OS owner
authentication happen before the process makes its first request to the
proposed URL; the chain ID is verified after authentication and before storage.

## Rollback decision

There is no anti-rollback checkpoint, authenticated external event chain, or
hardware monotonic counter. An attacker who can replace `policies.db` with an
older valid encrypted copy can restore an older policy. If it was more
permissive, signing can become more permissive. This is an accepted residual
risk for this release.

Rollback can also resurrect an earlier pending state. The wallet never
implicitly re-signs a broadcast record; it reconciles the exact stored hash and
only rebroadcasts the stored envelope. A restored, still-valid signed
transaction can therefore be rebroadcast. There is no daily allowance to
replenish because no such accounting exists.

## Attack analysis

| Attack | Control and residual risk |
| --- | --- |
| Request arbitrary signature | No MCP/CLI primitive; only validated execution plans reach signing. |
| Change recipient/value/calldata after review | Plan and prepared-review digests plus post-signature envelope validation fail closed. |
| Change nonce/gas/fees after exceptional review | Prepared fields are reviewed and signed without another RPC lookup. |
| MCP approves its own exception | No approval tool; separate terminal plus OS authentication is required. |
| Edit/open encrypted policy bytes | SQLCipher authentication/integrity checks and separate key reject wrong-key or corrupt state. |
| Replace database with a new empty file | Existing wallet metadata without policy fails startup. |
| Restore older valid encrypted database | Not detected; may restore an older policy or signed transaction. Accepted residual risk. |
| Race a policy change | Revision checks cancel or reject stale signing/lifecycle transitions. |
| Flood denied requests | Identical plans deduplicate; awaiting approvals are capped at 64 per wallet. Historical terminal rows still consume disk. |
| Concurrent transactions reuse a nonce | Only one signed/submitting/broadcast row is allowed per wallet and chain. External use of the same key can still invalidate the chosen nonce. |
| Malicious RPC fabricates state | Structural pin/link checks help, but a coherent lie remains possible. Trusted RPC is required. |
| RPC or network fails after send | Bytes/hash were stored first; status remains reconcilable and only exact bytes can be retried. |
| Same-user process accesses credential APIs | Platform isolation and prompts vary; OS compromise or process injection is out of scope. |

Any future stateful allowance or daily accounting requires a new threat model
and an external rollback defense. It must not be added under this design.
