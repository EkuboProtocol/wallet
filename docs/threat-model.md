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

Execution plans arrive by caller-named URL, which adds one outbound request
that is not a configured chain RPC and one SSRF-shaped surface. The fetch
admits only public `https` on the default port — no credentials, fragments,
redirects, or private/reserved addresses, with every resolved address vetted
and pinned for the connection — caps the response at 16 MiB, verifies the
caller-supplied keccak256 digest over the exact fetched bytes when given, and
never echoes response bytes in an error. The fetched plan then passes the same
parse, validation, simulation, and policy path as any inline plan, so the URL
transport grants no authority; `data:` URIs decode locally with no network.

### Key custody, and the presence check that is deliberately absent

Private keys are individual OS credential-store entries keyed by wallet ID,
never SQLCipher rows, and the database key is a separate entry. The split is
what keeps the data directory free of key material: copies of it — backups,
syncs, snapshots, bug reports — cannot yield a key whatever else leaks, and the
database key is handled far more often than any private key, since almost every
command opens the database while only signing reads a key. It also puts the key
behind per-item access control the OS enforces, which an encrypted page cannot
once its key is resident. It does not defend against code already running as
the user: both secrets share one credential store and one login, which is why
in-process code execution is out of scope above.

The credential-store backend can mark an entry as requiring biometric or
passcode presence before release. This wallet does not use that, by design, and
the omission is load-bearing rather than pending. The product's purpose is
unattended agent operation against long-running goals, including loops; an
entry the OS will not release without a live human cannot be read at 3am, so
presence enforcement and the automatic signing path are mutually exclusive.
`send_new_plan` accordingly performs no presence check.

The consequence is explicit: **for the automatic path, the policy is the
security boundary, and key custody is not.** Anything the policy permits is
reachable by a compromised or misled agent without a further gate, so a
wallet's exposure is bounded by what its policy allows and by what it holds.
Owner authentication (`human_presence`) covers the exceptional review path,
where a human is present by definition, and configuration mutations. It is an
application-level check in the CLI process, not an OS gate on key release, and
it is not a control against in-process execution.

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
   No signature has an automatic path at all. A message signature has no
   readable on-chain effect for the policy language to score, and a typed-data
   signature has one the language cannot bound: a permit is redeemed by its
   holder whenever it likes, so a per-transaction limit that admits one permit
   admits an unbounded series of them, and this wallet keeps no counters to
   notice. Every message and every payload therefore queues for human review;
   that review escapes control characters, terminal escape sequences, and
   Unicode bidirectional overrides, because the body is attacker-controlled
   text rendered into the approver's terminal.
3. The signed sender, chain, target, value, calldata, transaction type, nonce,
   gas, fees, and EIP-7702 authorization are constructed locally and validated
   after signing.
4. Automatic signing uses the policy revision evaluated for the simulation and
   atomically verifies that revision before the signed bytes can enter the
   submission queue.
5. Exceptional review binds the exact prepared transaction fields. After OS
   authentication, mutable local configuration and policy are reloaded and no
   further RPC lookup occurs before signing.
6. Every use of key material requires OS-backed owner authentication:
   transaction, typed-data, and message signing at exceptional review, key
   export, and wallet removal. Replacing a wallet's policy requires it too:
   the policy is what stands between an agent and a signature, so rewriting
   it grants signing authority even though it touches no key material.
   Changes that grant no signing authority — networks, the address book,
   token lists — are confirmed in the local terminal and are not
   authenticated against the OS, so an owner is never asked to authenticate
   for something no signature depends on. The MCP has no approval operation.
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
