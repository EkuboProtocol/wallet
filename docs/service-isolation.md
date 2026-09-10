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
- IPC framing bounds allocations, rejects mismatched protocol versions and
  truncated responses, and does not replay interrupted operations. The frame
  codec does not authenticate peers or grant capabilities.

## Work still required before completion

1. Bootstrap Linux and Windows service identities, protected executable paths,
   private per-owner storage, authenticated endpoints, and lifecycle handling.
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
9. Verify desktop flows and packaged release behavior on Linux, Windows, macOS;
   run complete CI and packaging checks. Update security documentation only to
   the guarantees demonstrated by those tests. Do not close #112 before that.

A local service with protected software keys is sufficient for the stated
ordinary-process threat model; hardware-backed keys are not a prerequisite.
Keeping policy in the desktop while moving only signing would leave an
arbitrary-signing oracle and does not satisfy this objective.
