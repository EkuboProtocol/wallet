# Threat model

Last reviewed: 2026-08-03

This document describes the security target for `ekubo-wallet`, the attacks it
is intended to stop, the attacks it can only detect, and the attacks that remain
possible. The repository is an active rewrite. A control marked **required** is
a release blocker and must not be described as implemented until its tests are
merged.

## Security claim

For a wallet created inside the application and not subsequently exported, the
production service should make this narrow claim:

> A transaction signature is produced only by the wallet core after it has
> authenticated all security-relevant local state, reconstructed the exact
> transaction, evaluated the active policy and spend ledger, completed any
> required human approval, and bound the approval to that transaction digest.

This is not a claim that the application can stop all use of an address after
its private key has been imported from elsewhere or exported. Those custody
states are recorded as externally known.

The service prioritizes integrity and fail-closed behavior over availability.
A local attacker may be able to delete or corrupt state and prevent signing.
They must not be able to turn corruption into a more permissive policy or a
fresh spending allowance.

## Status legend

- **Implemented**: present in the Rust code and covered by tests where practical.
- **Required**: part of the production design but not yet implemented; release
  must remain blocked.
- **Hardening**: useful defense in depth that is platform- or deployment-specific.
- **Not prevented**: outside the security claim or impossible to prevent at this
  layer.

## Assets

The primary assets are:

1. EVM private keys and any derived signing material.
2. The active policy, policy revision history, and policy-approval evidence.
3. Spend accounting, reservations, nonces, pending requests, and transaction
   lifecycle state.
4. The exact transaction and chain context approved by a person.
5. The integrity key and anti-rollback checkpoint used to authenticate local
   state.
6. Release signing identities and the source-to-binary provenance chain.
7. RPC credentials and other configuration secrets.

The policy itself is not assumed to be confidential. Its integrity and
freshness are security critical.

## Trust boundaries

```text
Untrusted or partially trusted                       Trusted wallet boundary

ChatGPT / other MCP client ─┐
CLI caller ─────────────────┼─ structured requests ─▶ signed wallet core
MCP Apps / browser UI ──────┘                            │
                                                        ├─ policy evaluation
RPC endpoint / chain state ── untrusted responses ─────▶├─ simulation checks
                                                        ├─ approval binding
SQLite files / WAL / backups ── attacker-writable ─────▶├─ authenticated state
                                                        ├─ key use + signing
                                                        │
                                                        ├─ OS credential store
                                                        └─ OS human presence
```

The MCP client, model output, browser component, RPC server, SQLite bytes, and
ordinary configuration files are never trusted merely because they are local.
The wallet core is the sole policy decision point. In the stronger deployment
shape, the same signed binary runs a core-service mode under a protected OS
identity; CLI and MCP modes are untrusted IPC clients of that service.

## Threat actors and assumptions

### In scope

- A malicious or prompt-injected MCP client that can call every model-visible
  tool with arbitrary inputs and repeat or reorder calls.
- A third-party process that can read, replace, truncate, copy, roll back, or
  manually edit the SQLite database, journal, WAL, lock files, or ordinary
  configuration files.
- Multiple honest or malicious client instances racing policy reservations and
  transaction requests.
- A malicious website attempting CSRF, DNS rebinding, clickjacking, or token
  theft against a loopback approval page.
- A malicious or compromised RPC endpoint returning false chain state,
  simulation results, fee data, or receipts.
- Theft of a database backup or user-readable application files.
- Accidental approval, ambiguous transaction presentation, replay, and stale
  approval state.
- A compromised dependency or CI job attempting to alter release artifacts.

### Assumptions

- The operating-system kernel, trusted UI used for human presence, cryptographic
  primitives, and hardware-backed key store (when used) behave as specified.
- The attacker does not have unrestricted root, administrator, kernel, or
  physical-debug access. Such access can read process memory, replace services,
  alter security policy, or capture input.
- Ekubo's release signing and GitHub/Azure/Apple accounts are not compromised.
- A user can understand the transaction facts presented for approval. The
  application minimizes blind signing but cannot make a deceptive contract safe.
- TLS certificate validation works. The RPC operator itself may still be
  malicious.

### Important platform limitation

Code signing is provenance, not a portable filesystem principal. SQLite cannot
ask whether the process opening a database has an Ekubo signature. Windows and
Unix file ACLs normally authorize users or service identities, and generic
Windows Credential Manager or Linux Secret Service entries are commonly scoped
to a user session rather than one executable.

Therefore the design does not rely on making SQLite bytes literally
unmodifiable. It combines OS isolation with cryptographic authentication so an
unauthorized modification can cause denial of service but cannot authorize a
signature.

## Security invariants

The following invariants are release requirements:

1. Private keys never appear in MCP inputs, MCP results, logs, policy records,
   approval components, or the SQLite database.
2. No model-visible or CLI command signs an arbitrary hash, arbitrary bytes, or
   a caller-supplied serialized transaction.
3. The core constructs the transaction from a validated execution plan and
   independently derives the sender from the stored private key.
4. Every security-relevant database read is authenticated before it influences
   a signing decision. Any ambiguity fails closed.
5. The policy revision and spend/reservation ledger used for a decision are
   committed and anti-rollback anchored before the private key signs.
6. Approval names an immutable request ID and digest. Changing the chain,
   recipient, value, calldata, fees, nonce, policy result, or simulation result
   invalidates it.
7. Approval capabilities expire, are single use, and are never exposed to the
   model.
8. Policy changes, integrity-key recovery, private-key export, wallet removal,
   and policy exceptions require OS-backed human presence.
9. Export state is committed before raw key material is returned. Export or
   import permanently ends the exclusive-policy claim for that address.
10. Concurrent instances cannot spend the same policy allowance twice.

## Authenticated SQLite design

### What the keychain secret does

On first initialization, the core generates a random 256-bit state-integrity
key. It is not a user password. It is stored separately from the database in
the strongest platform credential mechanism available and is zeroized after
use.

The key authenticates security state with a versioned, domain-separated keyed
MAC. Encryption such as SQLCipher may additionally hide policy and operational
metadata, but encryption is not the policy boundary. The necessary property is
that an attacker who edits SQLite cannot create a valid authenticator.

The MAC input includes, at minimum:

- protocol and encoding version;
- installation/database UUID;
- wallet ID and derived wallet address;
- record type and monotonically increasing sequence;
- previous record digest;
- canonical record contents; and
- schema version.

Length-prefixed fields or a specified canonical encoding must be used; ad hoc
JSON concatenation is prohibited.

### Authenticated records

Policy revisions form one append-only authenticated chain. Reservations,
spend accounting, approvals, signed transaction digests, broadcasts, releases,
and cancellations form another authenticated event chain. Derived summary
tables may be rebuilt from those chains and are never authoritative on their
own.

The core verifies the complete chain, expected schema, wallet binding, and
current head before using it. A row-level MAC without a chain is insufficient
because an attacker could delete a spend or policy record.

### Anti-rollback checkpoint

An old database can contain entirely valid MACs. To detect rollback, the core
stores a small checkpoint outside SQLite in protected credential storage:

```text
database UUID
integrity epoch
latest policy sequence + head digest
latest security-event sequence + head digest
```

The database is accepted only when its authenticated heads match that
checkpoint. Replacing it with an older backup, another wallet's database, or a
fresh empty database fails closed.

Database commit happens before checkpoint advancement while a cross-process
writer lock is held. Crash recovery may accept exactly one fully authenticated
successor of the checkpoint and finish advancing the checkpoint. It must never
skip an unauthenticated gap or silently initialize a new checkpoint for an
existing wallet.

### Mutation protocol

Every security-state mutation follows this order:

1. Acquire the one-writer service/IPC lock and start `BEGIN IMMEDIATE`.
2. Read the external checkpoint and verify the authenticated database heads.
3. Validate the requested state transition and expected previous sequence.
4. Append the canonical record and its MAC; update derived views in the same
   SQLite transaction.
5. Commit with durable SQLite settings and synchronize the database.
6. Advance the external checkpoint.
7. Only then permit signing based on that state.

SQLite defensive mode, disabled extension loading, trusted-schema restrictions,
parameterized fixed SQL, private directory permissions, and integrity checks
are defense in depth. None replaces the MAC and external checkpoint.

### State-key access

A generic user-scoped keychain item is not sufficient against another process
running as the same user on every platform.

- **macOS:** package the executable in an app-like signed bundle and bind the
  data-protection keychain access group or keychain ACL to the designated code
  requirement. Use hardened runtime and library validation.
- **Windows:** prefer a Windows service under a dedicated service identity and
  a non-exportable CNG/TPM key or service-scoped protected secret. Credential
  Manager or DPAPI under the interactive user alone does not identify the
  Ekubo executable.
- **Linux:** prefer a system service with a dedicated UID, a private
  `StateDirectory`, polkit-mediated human actions, and a TPM-sealed or
  service-owned secret. Secret Service alone generally protects the desktop
  user boundary, not one signed ELF binary.

The project may ship one binary with service, MCP, and CLI subcommands. This
does not require three independent implementations: the service remains the
only process that opens the database or loads signing keys.

### Failure and recovery

- Missing integrity key, missing checkpoint, MAC failure, chain gap, unexpected
  successor, schema mismatch, or wallet-binding mismatch: quarantine state and
  refuse every signing operation.
- Corruption or deletion: refuse signing. Availability loss is preferable to a
  policy bypass.
- Restore from backup: require the matching protected checkpoint. Restoring an
  older database is rejected.
- Integrity-key reset: require explicit recovery with OS human presence, start
  a new visible integrity epoch, and preserve an audit marker. Never silently
  regenerate a key because a lookup failed.

## Attack analysis

| Attack | Intended result | Control and residual risk | Status |
| --- | --- | --- | --- |
| Edit the active policy row to raise limits or add a target | Modified canonical contents no longer match the policy-chain MAC and checkpoint; signing fails | Required |
| Delete a restrictive policy revision | Sequence/previous-head chain and checkpoint no longer match | Required |
| Restore an older, valid, more-permissive database | External head checkpoint detects rollback | Required |
| Replace the database with another wallet's database | MAC domain binds database UUID, wallet ID, address, and integrity epoch | Required |
| Edit or delete spend/reservation rows to reset a daily limit | Authoritative append-only security-event chain and checkpoint fail verification | Required |
| Tamper with SQLite WAL, journal, or derived indexes | SQLite fails or authenticated heads/records fail; attacker can still cause denial of service | Required |
| Race two service instances to reuse allowance | One core writer, `BEGIN IMMEDIATE`, expected-head comparison, and committed reservation before signing | Required |
| Delete the database or keychain checkpoint | Signing fails closed; availability is not guaranteed | Required |
| Read a stolen database backup | Private keys are absent; policy and transaction metadata may be visible unless optional database encryption is enabled | Partly implemented |
| Read the integrity key from another same-user process | Platform app binding or dedicated service identity is required; generic user-scoped keyrings do not stop this everywhere | Required |
| Patch or inject into the running wallet core | Hardened runtime/service isolation raise cost, but administrator/kernel/debugger compromise is not prevented | Hardening / not prevented |
| Invoke the signed binary from a malicious process | Inputs still traverse the same parser, policy, authenticated-state, and approval path; there is no arbitrary-sign interface | Required; interface partially implemented |
| Use a valid policy-update interface to loosen policy | Exact before/after diff, immutable digest, and OS human presence are required | Required |
| Ask the model to call an approval tool | Approval tool is component-only, requires a hidden one-time capability, and still invokes OS human presence | Required |
| Replay a prior approval | Pending request is digest-bound, expiring, single-use, and atomically consumed | Required |
| Change transaction fields after approval | Recomputed complete transaction digest must match approval and pending record | Required |
| Forge a loopback approval request from a website | Loopback-only random port, fragment-held capability, strict Host/Origin checks, POST-only mutation, CSP, no-referrer/no-store, timeout, and OS presence | Required |
| Prompt-inject the MCP client into bypassing policy | Server-side schemas and policy are authoritative; tool descriptions and model output are not authorization | Required; parser/policy implemented |
| Request an arbitrary hash or serialized transaction signature | Such a tool or command does not exist | Implemented as an interface invariant; signer not yet built |
| Extract a key through MCP | MCP has no key-returning tool; export requires an interactive terminal/UI and OS presence | Implemented for current CLI custody path |
| Export the key legitimately, then sign elsewhere | Cannot be prevented; custody changes to `exported` before output and exclusive enforcement is no longer claimed | Implemented |
| Import a key that already exists elsewhere | Cannot guarantee exclusivity; custody is `externally_known` from creation | Implemented |
| Malicious RPC lies about chain state or simulation | Verify configured chain ID, pin simulation block, enforce local semantic policy, and validate signed transaction; a single RPC can still lie about state | Required; residual risk remains |
| State changes between simulation and inclusion | Deadlines, slippage/minimum outputs, nonce/fee bounds, and policy constraints limit impact; simulation is not a guarantee | Required; residual risk remains |
| Malicious contract behaves deceptively despite simulation | Show decoded and raw targets/calldata, state changes, approvals, and warnings; contract intent cannot be proven generally | Not fully preventable |
| Compromise a release build job | Unprivileged native builds, protected signing environment, pinned actions, checksums, Sigstore bundles, provenance, and native signatures | Workflow implemented; accounts/protections must be configured |
| Compromise Apple, Azure, GitHub, or Ekubo release credentials | Separation and protected environments reduce likelihood; a fully compromised trust root can publish malicious code | Not prevented by the binary |
| Root/admin/kernel compromise | Attacker can replace services, read memory, alter UI, or weaken OS controls | Not prevented |
| Denial of service through file deletion, lock starvation, RPC outage, or request flooding | Rate limits, timeouts, and recovery tooling improve operations, but signing availability is not guaranteed | Partly preventable |

## Approval and transaction presentation

Approval presentation is pluggable, but every surface consumes the same
server-authored `ApprovalRequest` and immutable digest.

- Direct CLI uses a maintained prompt/status library, defaults to rejection,
  sanitizes terminal control characters, and then invokes OS human presence.
- Generic MCP clients may open an ephemeral loopback review page. The page is a
  presenter, not an authority, and never receives a private key.
- ChatGPT-compatible clients should use an MCP Apps inline review component.
  The model-visible tool prepares and simulates a transaction. A separate
  component-only tool consumes a one-time capability delivered in result
  metadata hidden from the model.
- Clients without rich UI receive a pending request ID and can complete it with
  a direct local CLI review command.

The UI must display chain, wallet, recipient/target, native value, token
transfers, approvals, calldata/selector, fees and limits, nonce, simulation
block, material balance/allowance changes, policy findings, expiry, and the
digest or a human-comparable fingerprint. It must never trust transaction facts
sent back by the component when approving; it loads the immutable pending
record by ID.

## Key custody and export

### Prevented under the assumptions

- Plaintext key files and accidental inclusion of private keys in SQLite,
  configuration, logs, MCP results, or release artifacts.
- Non-interactive MCP key export.
- Returning a key before recording that exclusive custody has ended.
- Treating an imported key as exclusively controlled.

### Still possible

- A person who passes OS human presence and confirms export can intentionally
  obtain the key. This is a required recovery feature.
- Malware with administrator/kernel access, process-memory access, UI control,
  or access to the same insufficiently isolated credential store may steal the
  key.
- An exported or previously imported copy can sign outside the service forever.
- Printing an exported key exposes it to terminal recording, screen capture,
  shoulder surfing, and caller-controlled output redirection; export therefore
  requires an actual terminal and explicit warnings.

## RPC and chain risks

REVM simulation improves review quality but does not create a trusted chain
oracle. The core must verify the RPC-reported chain ID, cap response sizes and
timeouts, pin all simulation reads to one block, and reject inconsistent data.
For high-value deployments, independent RPC comparison or a locally verified
node is recommended.

Even an honest simulation can diverge before inclusion because state, base fee,
oracle values, liquidity, proxy implementations, or ordering changes. Policies
should constrain outcomes in calldata (minimum received, maximum spent,
deadlines, allowed targets/selectors) rather than relying only on a successful
simulation.

## Supply-chain and release risks

The release workflow builds on native GitHub-hosted runners, uses full action
commit pins, signs macOS and Windows artifacts in a protected environment,
notarizes macOS, emits checksums and keyless Sigstore bundles, and requests
GitHub provenance attestations. These controls establish artifact provenance;
they do not prove the source or dependencies are free of vulnerabilities.

Before production release, repository branch/tag rules, required reviewers,
immutable releases, release-environment protections, Apple credentials, Azure
OIDC federation, dependency review, and incident-response ownership must be
configured and tested with a release candidate.

## Release-blocking verification

At minimum, automated tests must prove:

1. Editing every security-relevant policy field causes signing preparation to
   fail.
2. Deleting, duplicating, reordering, or editing policy and event records fails.
3. Replacing SQLite, WAL, or checkpoint with older or cross-wallet state fails.
4. A crash at every point between database commit and checkpoint advancement
   either recovers one authenticated successor or fails closed.
5. Parallel instances cannot exceed per-transaction or daily limits.
6. Approval replay, expiry, digest mismatch, and capability guessing fail.
7. Model-visible tool discovery does not expose component-only approval or raw
   signing operations.
8. Key export denial leaves custody unchanged; successful export records the
   transition before returning bytes.
9. Credential-store denial, deletion, and wrong-key substitution fail without
   silently creating new integrity state.
10. Linux, macOS, and Windows packages exercise their actual credential-store,
    human-presence, service-isolation, and native-signature paths.

## Review triggers

Update this document whenever any of the following changes:

- key store, service identity, IPC, or human-presence implementation;
- policy schema, canonical encoding, MAC, checkpoint, or recovery protocol;
- MCP tools, tool visibility, approval UI, or browser transport;
- transaction construction, simulation, RPC provider, or broadcast flow;
- key import/export behavior or custody claims;
- supported operating systems or distribution method; or
- CI, release signing, provenance, or dependency policy.
