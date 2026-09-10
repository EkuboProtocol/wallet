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

- `ekubo-wallet-client` now owns the shared closed request protocol, framing,
  authenticated Linux transport, and typed owner methods. It depends on core's
  data types and identity validation, not on the headless authority runtime.
  The raw JSON call is crate-private. The service dispatches the same protocol
  into its existing `OwnerApi`; there is no parallel policy implementation.
  The available methods cover account/policy/network reads and edits, legal
  review, notification privacy, appearance, setup progress, testnet display,
  and companion-server selection. Account custody, signing reviews, automation,
  activity, tokens, updates, dapp access, and events still need their RPC flows.
  Network reset and proposal review, plus policy proposal listing/application/
  rejection, now use typed requests carrying the exact reviewed records. The
  service delegates them to existing owner methods, including core's native
  authentication and atomic stale-review checks. The older broad network
  install operation is not exposed; desktop forms use add/replace operations.
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
- The Linux host now registers an initial closed owner interface on the system
  bus. It covers account/policy reads, policy installation, network edits,
  notification privacy, and legal review. Requests cannot supply an identity,
  authorization proof, database path, SQL statement, or raw signing operation.
  This endpoint is not yet connected to the desktop, and its system-bus policy
  still needs installer provisioning.
- Core binds service owner authentication to the message's actual D-Bus unique
  sender and checks its UID against the protected profile. The receiving bus
  connection remains pinned through polkit authentication; disconnected callers
  are rejected before issuing an authorization proof. Request identity is
  task-local and is not inherited by spawned tasks. The polkit action grants the
  dedicated service permission to query for a desktop subject while retaining
  the existing fresh `auth_self` challenge. Installer provisioning must use the
  matching `ekubo-wallet` service principal. Legacy desktop authentication still
  uses its existing process subject.
- Owner calls subscribe to connection departure before checking identity, and
  cancel their operation future if the caller or pinned bus disconnects. This
  releases pending review reservations without moving native authentication to
  a worker task. Cancellation does not undo already committed mutations.
- The private-bus identity test passes for matching/wrong UIDs, disconnected
  callers, and task-local isolation. It does not demonstrate real polkit
  authentication across OS identities; that native integration test remains
  required. Owner RPC tests exercise the existing persistence checks, not a
  complete service deployment or desktop flow.
- The Linux owner client reads the current user's root-owned installer identity
  without activating custody. Both client and host connect through the pinned,
  root-controlled `/run/dbus` directory and ignore bus-address environment
  overrides. The client resolves the service's public name, checks its unique
  connection's UID, then addresses only that verified unique connection and
  checks response senders. A disconnect is an error, never an automatic mutation
  replay or switch to a new service. A private-bus test verifies wrong-UID
  rejection, name replacement, and disconnect behavior. The desktop facade still
  needs to adopt this transport; this code alone does not alter shipped custody.
- `automation_runtime` now shares the desktop's existing core scheduler setup
  with the headless service. It still uses `AgentExecutionAuthority`, re-resolves
  current accounts/networks/policies in core, and emits the same change events.
  The desktop's Tokio task invokes this shared code with its existing lifetime.
- Linux service scheduling is gated by live desktop sessions. `HoldDesktopSession`
  authenticates the actual caller through core before acquiring a bounded session
  lease; it subscribes to that unique bus name's departure before checking that
  the name is still live. The service runs one scheduler while any desktop is
  active and cancels it when the last session leaves. Client `close()` closes all
  clones of that connection and releases its session on Quit; cancelling only
  the pending D-Bus call is not equivalent to disconnecting. The desktop still
  needs to adopt these client methods. MCP enable/disable and Quit behavior need
  separate lifecycle integration before the no-UX-change requirement is met.
- The WalletConnect proposal channel is extracted verbatim into a shared
  headless module; the desktop continues to use its original public reexports.
  A new service review broker retains actual choices, scopes, and response
  channels. Client DTOs contain account metadata and review documents only.
  Approval consumes an exact stored choice, reserves the review against concurrent
  replacement, authenticates through core, and rechecks the account instance and
  address after authentication. Only the internal session receives the proof.
  Replays, stale identities, bad indices, and retired/reimported accounts are
  rejected. The authenticated owner endpoint now lists broker reviews and routes
  approve/reject/close requests to it. Client approval carries only a session ID,
  choice index, and reviewed identity; the response is null, with the proof sent
  only over the internal session channel. A channel collector now ingests handler
  proposals and publishes refresh events after insertion. Cancelling the
  collector closes pending decisions and serializes shutdown against delivery
  of any approval still being authenticated. The Linux host now runs the
  collector and shared headless WalletConnect runtime. Typed owner operations
  start, list, wait for, and disconnect sessions; workers receive restricted
  dapp authority. Losing the last desktop session cancels active connections,
  including connection setup. Desktop adoption and live relay validation remain.
- The owner dispatcher, session/review DTOs, review broker, and WalletConnect
  runtime are shared across platforms. Linux D-Bus authentication and dispatch
  adaptation live in `linux_owner_rpc.rs`; the runtime observes an authenticated
  desktop activity watch without receiving Unix identities or bus handles.
  Windows must supply its own protected service identity/storage, authenticated
  transport, native owner-authentication context, and desktop lease tracking.
  Its transport must also cancel pending owner operations on peer disconnect,
  preserving the initiating caller's identity throughout review/authentication.
  It must reuse the same typed operations and core authorization checks, without
  accepting a caller-supplied approval flag. The client operation methods should
  likewise be reused when a Windows transport implements the existing contract.
  No Windows transport or native Windows validation is implemented yet.

- Token management now has shared typed owner operations: inventory, manual
  addition, price display settings, exact reviewed removal, token-list fetching
  for review, and proposal listing/acceptance/rejection. The service calls the
  existing owner/core methods, retaining native authentication for trusted
  metadata and exact stored-row checks. Import result DTOs are shared with the
  desktop; no storage or authorization capability crosses the wire. The desktop
  still needs to adopt the client methods.

- Automation inventory, run history, stop, restart/relink, delete, and dry-run
  operations now have shared typed owner RPCs. The request identifies an installed
  automation; it cannot supply bytecode, policy revision, or an approval claim.
  Restart resolves the current policy in the service. Dry-run reports contain
  display data only. Cron schedules serialize as their exact expression and
  deserialize through the existing parser. Desktop adoption remains required.
- Owner automation deletion now checks the stopped state in the SQL delete, so
  a restart between the owner's state read and deletion cannot erase an enabled
  automation. The unconditional removal API was removed; store tests use the
  production stopped-only operation.

- A shared event feed now relays the existing domain-event metadata over owner
  IPC. Its in-memory journal is bounded by count and serialized size, with
  independent epoch/sequence cursors and bounded long polls. Initial connection,
  restart, eviction, or an oversized event returns an explicit refresh request;
  the desktop must capture authoritative state and then resume at the returned
  cursor. This retains changes made during snapshot capture. Local broadcast
  subscribers continue to receive the original events in journal order. No
  event or cursor conveys authority. Desktop adoption remains required.

- Activity and review inventory now have shared typed read RPCs, including
  individual transaction/message/typed-data records, owner attribution, review
  documents, transaction inspection, and receipt/status refresh. Headline and
  saved-summary batches carry bounded lists of transaction IDs; the service
  reloads the stored records instead of accepting caller-authored plans. Activity
  records and review queues are shared DTOs, not authorization capabilities.
  Desktop adoption remains required.

- Message and typed-data review decisions now have typed owner RPCs. Signing
  takes only a stored request ID and its reviewed digest; the existing owner/core
  path rechecks the payload, account, policy provisioning, and legal state and
  performs native owner authentication. Rejection preserves terminal records.
  The discard RPC delegates to core's signed-but-never-submitted state predicate.
  No caller-supplied payload, key, or approval boolean is accepted. Desktop
  adoption and native service signing validation remain required. Core signing
  borrows SQLite connections exclusively across native authentication, making
  its future transferable without sharing connections or spawning away from
  the initiating owner's task-local authentication context.
- Transaction review rendering now receives `SimulationDisplay`, a shared
  display-only DTO. The existing GUI presenter converts core simulations before
  handing frames to the view, preserving all visible facts while excluding
  `PreparedExecution` and the simulation-consumption handle. Its decoder rejects
  those authority/handle fields. The core simulation itself remains non-deserializable.
- Transaction review now has a shared service broker and typed start/frame/choice
  RPCs. The start call stays pending through the existing core orchestrator and
  exact-byte submission on the initiating authenticated owner task. A bounded
  reservation lasts through preparation, refresh, native authentication, and
  sending; duplicate reviews cannot enter while a decision is authenticating.
  The broker reuses the existing GUI presenter, relays only display documents
  and simulation facts, and requires the exact single-use frame ID and document
  identity for each choice. Refresh retires the previous frame, even when its
  document is unchanged. Close and cancellation abort without recording a
  rejection; only an explicit Reject choice follows core's rejection path.
  Cancellation drops the reservation, and broker shutdown cancels pending
  operations, including preparation before a frame exists. Review events follow
  frame insertion/removal. The core legal-store borrow is exclusive across
  awaits so the service can poll the future without sharing SQLite connections.
  The Linux host explicitly closes reviews through the shared dispatcher before
  disconnecting its owner endpoint; Windows must invoke the same lifecycle hook.
  Desktop adoption, large-frame handling, and native successful signing validation
  are still required. Dropping a client
  method future does not itself disconnect D-Bus: the desktop adapter must own
  and close the review connection when cancelling its operation.

Account creation and removal now have shared typed owner RPCs. Creation accepts
only an account name and invokes existing custody with the desktop's policy that
requires approval for every transaction. It accepts no key, policy, storage path,
or owner identity. Removal documents are authored in the service; removal checks
their identity and the exact reviewed account instance/address before calling
core's native-authenticated removal, which rechecks under its lifecycle lock.
Tests use synthetic account metadata and verify invalid/duplicate names, forged
documents, and replaced account instances fail before credential access or native
authentication. Successful service credential creation/removal, import/export
RPCs, and desktop adoption remain unverified or unfinished.

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
   The existing `walletconnect` manager and `walletconnect_handler` are headless.
   Reuse them in the service with a proposal broker: keep `DappAuthorization`
   and the stored scope/choice there, relay review documents to the desktop,
   and authenticate the selected stored document inside the owner RPC context.
   Preserve session cancellation/farewells; its non-Send session future currently
   runs through a blocking worker with a Tokio handle and must retain that model.
4. Preserve native owner authentication across sessions. Linux polkit must bind
   the actual desktop peer and exact operation; Windows must prove fresh owner
   authentication to the service despite its noninteractive service session.
   Guard export, policy widening, updates, and other protected changes there.
5. Convert desktop authority and WalletConnect to remote facades without screen
   or review-flow changes. Preserve notification attribution, export expiry,
   owner review semantics, automation lifecycle, and MCP reconnection behavior.
   The existing `DesktopSnapshot::capture` already separates cached render data
   from authority reads. Keep that presentation model while making capture use
   remote reads; do not block the UI on synchronous D-Bus calls. Large inventories
   and payloads need pagination/chunking so transport bounds cannot hide records
   or break existing large-payload screens. Startup still
   constructs local authority and launches automation against local stores, so
   adding the client crate has not changed the custody path yet.
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

- Service and client library suites pass: 208 service tests and eight client tests,
  with three integration tests ignored. Token RPC tests round-trip serialized
  requests and cover stale removal/repricing, changed proposals, forged metadata,
  replay, and network/price validation. Dapp tests cover exact stored review
  identity, account replacement, replay, collector cancellation, and shutdown
  during authentication. The approval test keeps its runtime alive across replay
  and verifies the RPC response contains no authorization proof. Automation RPC
  tests preserve lifecycle/history and resolve restart against a newer policy;
  the core tests cover restart-before-delete and exact schedule wire round trips.
  Event tests cover independent cursors, changes during snapshot capture, bounded
  history/batches, restart and eviction gaps, wake-ups, and cancelled waiter
  capacity. Owner RPC tests also round-trip configuration invalidations.
  Activity RPC tests retain terminal requests outside review queues, preserve
  hidden history lookup, enforce read limits, and inspect synthetic unsigned
  records without making network calls or reading account keys. Signature RPC
  tests reject mismatched digests, retain core legal prerequisites, and reject
  repeated rejection decisions. They stop before native authentication or key
  access; successful native service signing remains untested. Simulation-display
  tests preserve every serialized display fact while rejecting preparation
  authority and simulation-consumption handle fields.
  Transaction broker tests cover exact single-use frames, unchanged-document
  refresh, bounded reservations, retention during a simulated authentication
  wait, cancellation/shutdown, Close versus Reject, failed RPC cleanup, and
  rejection of caller-supplied authority fields. They do not perform native
  authentication or live signing; existing core pipeline tests still cover
  authoring, refresh, authentication, revalidation, and exact-byte submission
  using their synthetic chain and test presence.
- These tests use temporary encrypted state, synthetic metadata, and fake owner
  authentication. Session cancellation uses a local worker, not a live relay.
  They do not prove native polkit/Windows authentication or process isolation.
- Full workspace strict Clippy passes with all targets and features. Desktop
  library checking passes after shared session/import DTOs and connection setup
  cancellation. Formatting, diff whitespace, Ruff, and license freshness pass.
- OSV-Scanner 2.5.1 vulnerability and license checks pass against the generated
  Linux, Windows, and macOS lockfiles under the existing repository policy.
- Full workspace all-feature tests pass: 1668 passed, 11 ignored across
  30 suites (including doc tests). Core: 701 passed, six ignored; desktop
  library: 451 passed, two ignored. Log:
  `~/Documents/wallet-account-rpc-workspace-tests.log`.
- Earlier targeted evidence: all 11 service-storage tests passed; private-bus
  caller identity, client identity/replacement, desktop disconnection, and the
  isolated Secret Service startup/restart regression passed when explicitly run.
  These tests launch and stop only their own temporary daemons. The core
  library suite is included in the current workspace result above.
- The extended private-bus owner-context tests pass explicitly: caller departure
  and bus termination drop a waiting operation's reservation, a dead caller
  cannot enter another operation, and a replacement uses a distinct identity.
  Native authentication is not invoked by these tests. Log:
  `~/Documents/wallet-owner-cancellation-tests.log`.
- The standalone service build passes without test hooks after adding signature
  decisions. Its early startup guard previously refused desktop-UID execution
  before opening authority. No live wallet credentials were read. Native
  authentication and live-key signing were not exercised by this build.

Full native multi-identity integration, Windows compilation/authentication,
provisioning, migration, and packaged UX verification remain unproven. Windows
is not an installed Rust target on this development machine. No installation or
security completion is claimed by the Linux unit and compile results.

CI run `34519753381` tests commit `1695b3d` (before simulation-display,
owner-call cancellation, and the transaction broker). Its lint, execution-plan,
Linux, and macOS jobs passed; Windows was still running at the latest check.
Re-query the run before relying on its status.
