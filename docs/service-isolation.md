# Service isolation implementation

Status: in progress. The shipped application still uses desktop-user credential
storage. The new headless runtime alone provides no OS isolation and must not
be described as fixing issue #112.

## Required outcome

On Linux and Windows, the desktop and agent must not possess the account keys,
SQLCipher key, or write access to authoritative state. A protected service under
a separate OS identity owns all three. It evaluates exact transactions against
current policy and signs allowed requests unattended. Existing wallet screens,
review content, notifications, MCP behavior, and ordinary approval flows remain
unchanged. macOS retains its existing custody behavior.

The threat remains an ordinary hostile desktop-user process using public OS
APIs. Root/administrator access, OS compromise, and arbitrary code execution
inside the protected service remain outside this boundary.

## Implementation and evidence

- The `ekubo-wallet-service` library compiles the existing authority, MCP,
  event, batch-read, and preview implementation without GPUI. Shared source
  paths are transitional: do not fork the policy implementation. Once desktop
  authority is a remote facade, relocate service implementation into this crate
  and remove direct desktop compilation of it.
- Its tests include the existing MCP policy and simulated transaction pipeline.
  These demonstrate runtime behavior, not process isolation.
- Linux core storage now requires root-owned owner configuration, a distinct
  non-root service UID, protected directory ownership/modes, and a process-long
  exclusive profile lock. Key files are published atomically without replacement,
  read through pinned directory descriptors, and rejected for unsafe permissions,
  symlinks, hard links, wrong lengths, or wrong owners. Activating this backend
  disables desktop-keyring fallback and rejects another profile's database path.
- The Linux host activates storage before opening authority and accepts MCP only
  from the configured kernel-reported peer UID. It uses the existing MCP session
  implementation, limits concurrent connections, and drains tasks on shutdown.
  This host is not installed or connected to the desktop yet.
- Current service key files provide OS access isolation, not encryption against
  offline disk access. Before deployment, resolve protected unattended key wrapping
  and document the actual at-rest guarantee. Do not silently replace the old
  encrypted credential store with plaintext files and claim equivalent protection.
- IPC framing bounds allocations, rejects mismatched protocol versions and
  truncated responses, and does not replay interrupted operations. The frame
  codec does not authenticate peers or grant capabilities.

## Work still required before completion

1. Bootstrap Linux and Windows service identities, protected executable paths,
   private per-owner storage, authenticated endpoints, and lifecycle handling.
   Linux primitives and MCP hosting are implemented but not provisioned; Windows
   hosting and custody are not implemented.
   Reject desktop-user execution and insecure ownership/ACLs. Do not fall back
   to the desktop user's credential store if service startup fails.
2. Move raw-key and database-key persistence behind that boundary. Verify parent
   directories, symlink/reparse behavior, restrictive file permissions/ACLs,
   atomic updates, backups, and crash recovery. Client-supplied paths or user
   identifiers must never select another owner's storage.
3. Add closed typed RPC dispatch for owner, agent, dapp, scheduler, and event
   operations. Derive peer identity from the OS transport, not request fields.
   Keep policy evaluation and exact authorization binding within core/service.
   Never expose a raw-signing endpoint or trust a frontend `approved` boolean.
4. Preserve native owner authentication across sessions. Linux polkit must bind
   the actual desktop peer and exact operation; Windows must prove fresh owner
   authentication to the service despite its noninteractive service session.
   Guard export, policy widening, updates, and other protected changes there.
5. Convert desktop authority and WalletConnect to remote facades without screen
   or review-flow changes. Preserve notification attribution, export expiry,
   owner review semantics, automation lifecycle, and MCP reconnection behavior.
6. Integrate installation, authenticated updates, upgrades, rollback behavior,
   and removal. Keep the service binary and configuration unwritable by the
   desktop user. Per-user Windows installation currently needs no service;
   installing a protected service requires administrator approval. Clarification
   is pending on whether the no-UX-change requirement permits this OS prompt.
7. Migrate existing databases and credentials transactionally with authenticated
   owner binding, recovery from interruption, and verified deletion of legacy
   readable entries only after durable successful migration. Do not touch live
   wallet credentials during development. Existing key exposure cannot be undone
   by migration; account rotation is a distinct owner decision.
8. Run adversarial sibling-process tests on both native platforms, using only
   throwaway accounts: key/DB reads denied, policy writes denied, spoofed peer and
   approval claims rejected, denied transactions never signed, allowed signing
   works unattended, and upgrades/migration/restarts recover correctly.
   Current unit tests validate storage rejection cases and kernel peer lookup;
   they do not yet run a fully provisioned service and hostile sibling identity.
9. Verify desktop flows and packaged release behavior on Linux, Windows, macOS;
   run complete CI and packaging checks. Update security documentation only to
   the guarantees demonstrated by those tests. Do not close #112 before that.

A local service with protected software keys is sufficient for the stated
ordinary-process threat model; hardware-backed keys are not a prerequisite.
Keeping policy in the desktop while moving only signing would leave an
arbitrary-signing oracle and does not satisfy this objective.

## At-rest wrapping design to implement

A possible way to preserve the login-keyring at-rest property without giving
its user raw key access is to split protection across the two OS identities:

- The service owns an asymmetric unwrapping key in its private directory.
- The desktop credential store contains only an authenticated envelope of the
  wallet data key encrypted to the service public key. The service must not
  also persist that envelope as an ordinary disk file; that would defeat the
  offline protection supplied by the login keyring.
- A desktop relay supplies that ciphertext when the already-unlocked credential
  store makes it available. The service unwraps it in memory and opens its
  encrypted database/credentials. Relaying ciphertext grants no signing rights.
- Bind the enrolled envelope to the configured owner, service identity, profile,
  protocol version, and a pinned digest in protected state. Reject substitutions
  and rollbacks; changes require authenticated migration/rotation.
- The service exposes no general unwrap operation. Only the internal custody
  bootstrap consumes the envelope; neither the data key nor private unwrapping
  key crosses IPC. Use an audited envelope encryption implementation, not a new
  cryptographic construction.

This is an unimplemented design requiring review and tests, not a current
security guarantee. The current protected-file backend is an intermediate
storage/identity implementation and must not be deployed with real accounts
before the at-rest requirement is resolved.

## Latest checkpoint verification

- `cargo test --locked -p ekubo-wallet-core -p ekubo-wallet-service --lib`:
  697 core and 139 service tests passed; six ignored tests remain separate.
- The ignored isolated Secret Service startup/restart regression passed separately.
- `cargo clippy --locked -p ekubo-wallet-core --all-targets --all-features -- -D warnings` passed.
- `cargo check --locked -p ekubo-wallet --lib` passed after MCP session extraction.
- `cargo build --locked -p ekubo-wallet-service --bin ekubo-wallet-service` passed
  without test hooks. Running that binary with the desktop's actual UID refused
  execution before opening authority. No live wallet credentials were read.
- Workspace formatting and diff whitespace checks passed.

Full CI, service-crate strict Clippy, native multi-identity integration, and
packaged UX verification have not passed. The service crate still has unused
Dapp/owner methods until remote dispatch is wired. Build the standalone binary
without test hooks as well as running tests: the test feature initially masked
an incorrect use of `ConfigStore::new`, now replaced by production configuration
bound to activated service storage before user environment overrides.
