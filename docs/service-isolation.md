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

Cross-platform separation is a requirement for this change. The request/response
protocol, policy evaluation, transaction review, desktop snapshots, and session
lifecycle must remain shared. Platform adapters establish the following OS
properties before exposing that shared runtime:

| Property | Linux adapter | Windows adapter |
| --- | --- | --- |
| Service identity | Dedicated service UID | Dedicated virtual service account SID in session 0 |
| Protected installation and owner binding | Root-owned executable and configuration | Administrator-protected executable and HKLM configuration |
| Private authoritative state | Checked ownership, modes, and no-follow traversal | Checked ACLs and reparse-point-safe traversal |
| Authenticated client identity | System-bus sender credentials / Unix socket peer credentials | Kernel-verified named-pipe peer identity |
| Fresh owner authorization | Polkit bound to the actual desktop caller | Native owner-session authentication bound to the actual caller and operation |
| Service lifecycle | systemd provisioning and shutdown | SCM provisioning and shutdown |

This table is a required contract, not a claim that both adapters are complete.
Neither platform may accept caller-supplied identity or an approval boolean as
proof. Both must support unattended policy-authorized signing without exposing
raw keys to the agent. Platform-specific packaging must not leak into wallet
screens or introduce a second policy implementation.

`ServiceRuntime` now assembles authority, owner dispatch/reviews, desktop
activity, the scheduler, and WalletConnect on every platform. The Linux host
uses this shared assembly and supervisor, retaining its OS identity, storage,
D-Bus, Unix-socket, and signal handling. It cancels the shared supervisor before
closing reviews and endpoints, draining MCP requests, and stopping dapp workers.
Windows can supply its authenticated transport and SCM lifecycle around the
same runtime; those adapters and the desktop custody cutover remain unfinished.

Desktop reservations and active-session guards are shared as well. Reservations
consume bounded capacity without activating jobs. Only the platform adapter
activates a guard after authenticating the caller and arranging disconnect
monitoring. The Linux adapter retains core's owner-call context and subscribes
to bus departure before checking liveness. Guards stay inside the service;
they are activity lifetimes, not owner-authorization proofs. Shared tests cover
bounded pending admissions, cancellation while another desktop remains active,
and activity propagation into actual dapp admission. The relocated private-bus
disconnect test also passed explicitly after the refactor.

`OwnerConnection<T>` now owns typed RPC serialization, response bounds, and
zeroizing JSON buffers on every platform. Its sealed transport contract keeps
construction inside authenticated adapters. Linux `OwnerClient` is an alias
using the D-Bus adapter; Windows can supply its authenticated pipe adapter
without duplicating the owner API, snapshot reader, or session supervisor.
The shared layer never retries a failed exchange. Platform adapters remain
responsible for authenticating and pinning service identity, validating reply
provenance, and closing all connection clones. Tests cover ambiguous mutation
failure without replay, oversized requests before dispatch, oversized replies
before decoding, and snapshot reads over the same typed API. The two Linux
private-bus identity/close tests also passed explicitly after this extraction.
Windows hosting, storage, and transport are still unimplemented.
The transport extraction passed the full local gate with 1,704 tests passed,
12 ignored, plus both explicitly run private-bus tests. Formatting, workspace
Clippy, Ruff, generated licenses, vulnerability scanning, and license policy
passed. Logs: `~/Documents/wallet-transport-gate.log` and
`~/Documents/wallet-transport-private-bus.log`. Native CI for this extraction
remains required; the earlier session-checkpoint run was still active.

The uninstalled assets in `contrib/linux-service/` provide a systemd unit,
D-Bus name-ownership policy, service-account declaration, and common directory
declarations. Per-owner provisioning, activation, migration, and protected
updates remain unfinished. The unit deliberately requires existing validated
state rather than recursively repairing its ownership. An isolated-root
systemd verification and private-bus positive/negative name-ownership checks
passed; these are asset checks, not a packaged-service or Windows test.
Log: `~/Documents/wallet-service-assets-verify.log`.

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
  No Windows transport is implemented yet. Native Windows identity and
  descriptor unit tests passed in CI run `34530629466`; installed-service
  transport and owner-authentication validation remain required.

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
authentication. Successful service credential creation/removal and desktop
adoption remain unverified or unfinished.

Account import now has a typed owner RPC carrying an account name and a validated
import key. Existing custody fixes imported accounts to the approval-required
policy and rejects name/address replacement. The import wrapper owns zeroizing
text, redacts debug output, and reports validation errors without key contents.
Client-owned JSON request/response text also zeroizes on drop. These measures do
not erase all transport-library message copies. The core key type gains no
serialization or public key-export method. Tests use a public synthetic scalar
and invalid/duplicate names; successful installed-service import and desktop
import/export adoption remain required.

Private-key export now has a typed owner request that invokes existing core
custody and native authentication on the initiating caller's task. Each export
requires authentication; no approval flag, proof, or reusable export handle is
accepted. The direct reply encoder serializes the resulting reveal lease without
putting key material in an ordinary JSON Value tree. Service/client owned reply
text zeroizes on drop; zbus still owns separate message-buffer copies. The shared
lease retains the existing local 30-second reveal behavior and erases expired
values before serializing. Remote decoding starts the remaining display interval
on receipt and rejects intervals beyond 30 seconds. This interval governs UI
visibility, not revocation of bytes already delivered. The desktop still uses
its local authority; adopting this RPC and testing native export under installed
service identities remain required. Windows must use the same direct encoder
inside its authenticated call context.

Windows now has native primary-token identity reads and a dedicated virtual
service-account check. It rejects thread impersonation, LocalSystem/shared
service accounts, ordinary owner accounts, noncanonical service SIDs, mismatched
accounts, and nonzero sessions. A service SID in the token's groups is never used
as proof of account separation. Microsoft documents the distinction between
[service account tokens](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts)
and [service SID membership](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info).
The Windows configuration reader obtains the binding from the fixed 64-bit
`HKLM\SOFTWARE\EkuboWallet\Owners\<owner SID>` registry path. Each opened
component rejects registry links and requires a SYSTEM, Administrators, or
TrustedInstaller owner and no active write grants to other principals. Unknown
ACE types fail closed. Public read permissions and inherit-only entries are
allowed; every child is independently checked. A bounded binary `Profile` JSON
value binds the owner SID, dedicated service SID, and nonzero profile UUID.
The service name is derived from that UUID and resolved through Windows to
verify the configured SID. The client derives its owner from the primary token;
the service additionally verifies its dedicated primary account and session.
These checks return public identity metadata, not custody access or owner
authorization. No installer writes this configuration yet. Windows protected
storage traversal, service hosting, transport authentication, and native
owner authorization remain unimplemented.

Windows private-storage handle validation now checks a disk object's actual
attributes, rejects reparse points and multiply linked files, requires the
dedicated service SID as owner, and rejects access grants to principals other
than that service, SYSTEM, or Administrators. Registry metadata can be publicly
readable; private state cannot, so their policies remain separate while sharing
one native security-descriptor decoder. Null/missing DACLs and unsupported ACEs
fail closed. Inherit-only entries do not grant access to the current object;
every opened descendant must be checked independently. An empty DACL grants
no access and is accepted by the confidentiality check; operational access is
still required when opening the object.

The validator receives a borrowed live handle and protected installed identity.
It does not establish how the object was reached: protected ancestor traversal,
no-follow opens, retained handles, atomic writes, and migration are still
required before custody activation. It neither repairs permissions nor reads
wallet contents. Native tests exercise SDDL descriptors and synthetic ordinary
files/hard links; pure tests exercise ACL and metadata rejection. Native Windows
execution of the new tests remains required. The standalone Windows GNU Clippy
harness compiled them successfully, but is not full workspace or runtime proof.
Log: `~/Documents/wallet-win-storage-cross.log`.
The full local gate passed with 1,707 tests passed and 12 ignored, including
the new portable storage-policy tests. Formatting, workspace Clippy, Ruff,
generated licenses, vulnerability scanning, and license policy passed.
Log: `~/Documents/wallet-win-storage-gate.log`.

The native implementation follows Microsoft's handle-based
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
and [GetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle)
contracts. These APIs inspect the open object; they do not establish safe path
traversal or eliminate the need to protect its ancestors.

Windows now also has a read-only child opener using `NtCreateFile` with a live
directory handle as `RootDirectory`. It verifies the actual dedicated service
process and the parent directory, opens exactly one bounded ASCII component,
then validates the returned handle before exposing it for I/O. Separators,
alternate streams, trailing dots/spaces, and DOS device names are rejected.
The open cannot create or truncate files and does not follow a leaf reparse
point. Handles permit read sharing only, preventing incompatible data-write/delete
opens while retained. The kernel primitive has native tests for an ancestor
rename/replacement, missing children, wrong file type, and concurrent writers.
Those tests do not stand in for a provisioned service-account test.

Protected root bootstrap and retained ancestor validation are still required;
this API accepts an existing directory handle and does not establish its path
provenance. It is not connected to production custody or exposed through RPC.
See Microsoft's [NtCreateFile contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
The relative-open checkpoint passed the full local gate (1,708 tests passed,
12 ignored) and the standalone Windows GNU Clippy check including native tests.
Native execution is still pending. Logs: `~/Documents/wallet-win-path-gate.log`
and `~/Documents/wallet-win-path-cross.log`.

`PrivateStorageRoot::open` now bootstraps existing Windows profiles at the OS
ProgramData location under `EkuboWallet/Owners/<profile UUID without hyphens>`.
The owner selector resolves protected registry metadata and verifies the actual
dedicated service identity before any filesystem bootstrap. ProgramData comes
from `SHGetKnownFolderPath`, not an IPC path. Only absolute paths on fixed local
drives are accepted. Every component is opened relative to its pinned parent;
reparse points, unsafe ACLs/owners, and incompatible existing writer/delete
handles fail the open. All ancestor handles remain owned by the root object.

OS ancestors may grant namespace creation and EA/attribute writes beside
existing protected children; their ACLs must still deny untrusted deletion and
ACL/owner changes. Attribute writes can set reparse points on empty directories,
so denying data-write/delete sharing alone is insufficient. Relative opens use
`OBJ_DONT_REPARSE`, and bootstrap checks ancestor metadata again after every
ancestor has a retained child that prevents it being emptied. The Ekubo and
Owners directories have stricter machine ownership and mutation checks, and
the profile itself requires the exact service SID and private ACL. The root
exposes validated existing-file reads only. It creates no directory, repairs
no permissions, and does not yet activate custody or replace desktop startup.
The installer must provision new protected directories and quiesce migration;
this is not permission repair for a previously exposed profile.

Portable tests cover machine-path ambiguity and ancestor access policy. Native
tests now include read-only validation of the runner's actual ProgramData
ancestry. The Windows GNU harness compiles all native tests, but their latest
native execution is still pending. Logs: `~/Documents/wallet-win-root-cross.log`
and `~/Documents/wallet-win-root-tests.log`. CI now runs Windows service-boundary
tests before compiling the full desktop test suite, keeping all existing gates.
See [SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath).
The root-bootstrap checkpoint passed the full local gate with 1,710 tests
passed and 12 ignored. Formatting, workspace Clippy, Ruff, generated licenses,
vulnerability scanning, and license policy passed.
Log: `~/Documents/wallet-win-root-gate.log`.

Linux and Windows now share a non-cloneable `ProfileLock` guard around the
existing `fs2` nonblocking exclusive lock. Windows root bootstrap opens and
validates the fixed `service.lock` file before returning the profile object,
then retains the lock for the root's lifetime. The installer must provision that
file with service ownership and a private ACL; missing or unsafe files fail
startup without creating or repairing them. Linux retains its existing checked
lock-file creation path. Neither platform uses lock-file contents or a PID as
an authority claim. Drop explicitly unlocks before closing the owned handle.

The shared test runs an actual child process against a synthetic read-only
lock file, proving exclusion while held and acquisition after release. Its
ignored child helper is explicitly invoked by the parent test. A native
Windows test also covers the handle-relative open flags and refusal to delete
the locked file. The shared test passed locally and the Windows-target Clippy
harness compiled the native test; native execution of this checkpoint remains
pending. Logs: `~/Documents/wallet-profile-lock-tests.log` and
`~/Documents/wallet-profile-lock-cross.log`. The active native validation run
`34541694739` covers `41c9a81` and predates this lock checkpoint.
The lock checkpoint passed the full local gate: 1,711 tests passed and 13
ignored. The process-lock parent test explicitly ran its ignored helper twice
in separate processes. Formatting, workspace Clippy, Ruff, generated licenses,
vulnerability scanning, and license policy passed.
Log: `~/Documents/wallet-profile-lock-gate.log`.

CI now also has an independent `Windows service primitives` job. Its temporary
harness includes the production Windows identity, registry, storage, and profile
lock modules and their adjacent tests by source path. It avoids the unrelated
wallet/desktop dependency graph while retaining the full workspace matrix and
core integration checks. This is native primitive coverage, not an installed
service, migration, owner-authentication, or packaged-UX test.

`contrib/check-windows-service.py` derives direct dependency versions from the
core package's actual lockfile references, retains core dependency features and
lint settings, and verifies all resolved dependency versions, sources, and
checksums against the repository lock before compilation. Native execution is
refused on non-Windows hosts. Local preparation, deliberate dependency-mismatch
rejection, the non-Windows guard, and Windows GNU Clippy compilation passed.
Logs: `~/Documents/wallet-native-harness-prepare.log` and
`~/Documents/wallet-native-harness-cross.log`. Runtime results for the new job
are recorded below.

The earlier full CI run `34537601260` completed successfully on the desktop
session checkpoint `11054cb`. It predates the shared owner-transport extraction
and recent Windows storage work; those changes still need their own native
results.

The focused native-job checkpoint passed the full local gate: 1,711 tests
passed, 13 ignored, plus formatting, workspace Clippy, Ruff, generated licenses,
vulnerability scanning, and license policy. The generated harness also passed
Windows GNU Clippy with the exact repository-locked dependency versions.
Log: `~/Documents/wallet-native-harness-gate.log`.

The focused Windows job in run `34543869262` executed the native tests on
`6ed850a`: 21 passed, one failed, and the child helper was ignored by the outer
runner but explicitly executed by its passing parent test. Identity,
impersonation rejection, registry descriptors, private ACLs, hard-link checks,
handle-relative reads, concurrent-writer rejection, and cross-process profile
locking passed. The real ProgramData ancestry test failed because an ancestor
granted access outside the machine-directory policy. This is an unresolved
failure, not successful root-bootstrap validation. Log:
`~/Documents/wallet-native-ci-34543869262.log`.

Machine-directory errors now include the rejecting SID, access mask, and
ancestor context to identify the precise cause without weakening the policy.
The manual workflow input `windows_primitives_only=true` runs only this focused
job under a separate concurrency group. Its run title explicitly identifies
diagnostics; it does not satisfy full workspace CI or release validation. The
default remains full CI, and diagnostic runs do not cancel full runs.
These diagnostics passed the full local gate and Windows GNU Clippy. Logs:
`~/Documents/wallet-native-acl-diagnostic-gate.log` and
`~/Documents/wallet-native-acl-diagnostic-cross.log`.

Native diagnostic run `34544772632` identified the rejected entry as
`BUILTIN\Users` (`S-1-5-32-545`), mask `0x116`, on `C:\ProgramData`.
This includes attribute-write permission. It cannot be dismissed as cosmetic:
[MS-FSA's reparse-point operation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4aeefef8-92c3-4abc-af7a-a610caf8a165)
accepts either data-write or attribute-write access, and requires a directory
to be empty before setting a reparse point. A native synthetic-directory test
now exercises an attribute-only writer alongside the actual retained-handle
open mode, attempts to delete the pinned child and redirect its parent, and
uses the same reparse request on the emptied parent as a positive control.
Native run `34545729433` passed this test: the pinned child could not be deleted,
the nonempty parent rejected redirection, and the attribute-only writer could
redirect the emptied parent despite its retained handle. The run still failed
the unchanged ProgramData ACL check (22 passed, one failed, one helper ignored).
Log: `~/Documents/wallet-native-ci-34545729433.log`.

Bootstrap now accepts the observed `0x116` rights only on shared OS ancestors.
Private state and wallet-owned machine-directory policies remain strict.
Relative opens prohibit reparsing using
[`OBJ_DONT_REPARSE`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes),
and a final metadata pass runs after the complete protected chain is pinned.
This ensures a retained child prevents emptying each ancestor before custody
can use the root. The native attack test also attempts child lookup after
redirecting the parent and requires rejection. Native diagnostic run
`34546363561` passed all 23 tests on `967273f`, including the real ProgramData
check and the expanded redirection test. The child-process helper was ignored
by the outer runner but executed by its passing parent test. This validates
these primitives, not an installed service or desktop custody migration.
The full local gate also passed (1,711 tests, 13 ignored). Logs:
`~/Documents/wallet-native-ci-34546363561.log` and
`~/Documents/wallet-programdata-compat-gate.log`.
Full CI run `34546500148` is testing that checkpoint; it predates the shared
runtime assembly above.

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

- Service and client library suites pass: 210 service tests and fourteen client tests,
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
- Full workspace all-feature tests pass: 1677 passed, 11 ignored across
  30 suites (including doc tests). Core: 703 passed, six ignored; desktop
  library: 450 passed, two ignored. Log:
  `~/Documents/wallet-reconnect-barrier-workspace-tests.log`.
- Export tests preserve countdown/expiry, serialize no expired key, reject
  malformed reveal windows, preserve the D-Bus string signature, and keep
  export out of the ordinary JSON Value dispatch path. The existing countdown
  test moved from the duplicated authority module to the shared lease module.
  Service export tests fail before native authentication; installed-service
  export remains untested.
- The private-bus client identity/pinning/no-replay test passes explicitly after
  changing the owned JSON buffers to zeroize on drop. Log:
  `~/Documents/wallet-import-private-bus.log`.
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

Full native multi-identity integration, latest-head Windows compilation/authentication,
provisioning, migration, and packaged UX verification remain unproven. The
Windows GNU Rust target is now installed locally. A minimal standalone harness
type-checks and lints the native identity and registry configuration modules
and their tests for that target;
it does not compile the full Windows workspace or execute Windows code. Log:
`~/Documents/wallet-windows-identity-check.log`. No installation or security
completion is claimed by these results.

CI run `34519753381` passed all jobs, including Linux, macOS, and Windows,
for commit `1695b3d`. It predates simulation-display, owner-call cancellation,
transaction review, and custody RPC additions; it does not validate latest HEAD.

CI run `34525034188` covers `9b3bc57`, including account import but preceding
export and Windows identity work. Lint and execution-plan jobs passed. The Linux
job failed in `broken_write_fails_the_request_without_replay_and_reconnects`:
the test's `tools/list` probe can receive cached discovery before the bridge
finishes accepting the reconnect, then stdin closes before the fake server sees
the probe. The run is now terminal: macOS and Windows passed; the overall
result is failure because of that Linux test. A newer run must cover the fix
and the later changes.

The reconnect test now waits for an upstream notification forwarded by the
bridge after reconnection, rather than treating completion of the fake server's
handshake writes as proof the bridge accepted them. Its no-replay assertion is
unchanged. The repaired test passed 30 consecutive runs and the full local gate;
CI on a commit containing the fix remains required. Repetition log:
`~/Documents/wallet-reconnect-barrier-repeat.log`.

The Windows configuration policy tests reject mismatched owners, invalid service
identities, unknown fields, oversized values, unsafe registry components, null
DACLs, untrusted owners, and public write grants even when accompanied by deny
entries. Native SDDL fixtures cover descriptor decoding and inheritance.
Those fixtures and the primary-token/thread-impersonation tests executed and
passed on Windows in CI run `34530629466`. This does not validate an installed
service or actual installer registry provisioning.

The configuration checkpoint passed the full local repository gate: 1,681 tests
passed, 11 ignored; formatting, workspace Clippy, Ruff, generated-license
consistency, vulnerability scanning, and license policy passed. Logs:
`~/Documents/wallet-windows-config-workspace-tests.log`,
`~/Documents/wallet-windows-config-clippy.log`,
`~/Documents/wallet-windows-config-osv.log`, and
`~/Documents/wallet-windows-config-licenses.log`. The native Windows module
Clippy/type-check log is `~/Documents/wallet-windows-config-cross-check.log`.

Owner rebroadcast and bounded cancellation now have typed service/client calls
accepting only the stored request UUID. Both reuse existing OwnerApi/core paths,
including legal prerequisites, state reconciliation, submission claims, exact
stored bytes for rebroadcast, and core-derived bounded cancellation envelopes.
The shared action result contains display facts; core's broadcast-absence
provenance has no wire field or reverse conversion. Desktop adoption remains
outstanding. RPC tests reject unapproved records before and after legal
acceptance without changing the row; protocol tests reject replacement signing
fields and approval flags. These tests do not exercise live-key broadcasting.

The transaction-action checkpoint passed the full local gate: 1,684 tests
passed, 11 ignored, with formatting, workspace Clippy, Ruff, generated
licenses, vulnerability scanning, and license policy passing. Logs use the
`~/Documents/wallet-actions-` prefix (`workspace-tests.log`, `clippy.log`,
`osv.log`, and `licenses.log`). Native multi-platform CI remains required.

Owner portfolio loading now has a shared response model and typed service/client
call. The request contains only an optional account ID; the existing owner
implementation reads enabled networks, testnet visibility, and trusted token
rows from protected stores. Its concurrency limit and per-network error
handling are retained. Core portfolio results gain deserialization as read-only
display facts; no owner request accepts them as authority. Wire tests preserve
full-width balance strings, missing metadata, skipped-token counts, and partial
failures. A service test uses synthetic accounts and a bound non-listening local
socket to verify filtering and failure handling without public RPC access.
Desktop adoption and transport chunking for oversized snapshots remain required.

CI run `34530629466` covers `967c2ef`, including the Windows identity/configuration
checks and owner transaction actions. All jobs completed successfully, including
Linux, macOS, Windows, lint, and execution-plan checks. It predates the portfolio,
history, preview-worker, async-snapshot, and client-session checkpoints. The
Windows job log explicitly records successful native descriptor, primary-token,
and thread-impersonation tests:
`~/Documents/wallet-ci-34530629466-windows.log`.

The portfolio checkpoint passed the full local gate: 1,687 tests passed,
11 ignored; formatting, workspace Clippy, Ruff, generated licenses,
vulnerability scanning, and license policy passed. Evidence logs use the prefix
`~/Documents/wallet-portfolio-` with `workspace-tests.log`, `clippy.log`,
`osv.log`, and `licenses.log`.

Owner history clearing now has a typed service/client operation with no
caller-selected deletion scope. It delegates to the existing core stores:
finished transactions are hidden but remain directly addressable, decided
message/typed-data records are removed, and live records remain. MCP and
AgentApi gain no history-clearing operation. The wire test rejects attempts to
include pending/unsettled state or replace the storage path. The service test
uses synthetic records to verify deletion, hiding, preservation, and a no-op
second call. Existing core tests cover unsettled transaction retention.
This does not add transactional atomicity across the existing three store
operations; after any error the desktop must refresh authoritative activity.

The history RPC checkpoint passed the full local gate: 1,689 tests passed,
11 ignored; formatting, workspace Clippy, Ruff, generated licenses,
vulnerability scanning, and license policy passed. Logs use the prefix
`~/Documents/wallet-history-` with `workspace-tests.log`, `clippy.log`,
`osv.log`, and `licenses.log`.

Transaction preview generation now has a shared owner RPC accepting at most
eight stored request IDs, matching the desktop's current batch size. The service
reloads records and trusted metadata itself and reuses the existing local model
and persistence path. One blocking worker runs at a time, with sixteen admitted
requests including the running request. Waiting requests are cancellation-safe;
an abandoned running call keeps its worker/admission permits until computation
finishes. Shutdown closes admission and wakes waiting calls. Already-running
advisory computation may finish and persist its exact-plan summary; it performs
no signing and inherits no native owner-authentication context. Model failure
retains the existing optional-preview behavior. Tests exercise worker lifetime,
waiting-call cancellation, oversized input rejection, and saved-summary RPC
reads without initializing the model. Desktop adoption remains required.

Network dispatch and account-removal validation are factored into private
helpers to keep owner dispatch within the repository complexity limit. Both
remain awaited on the initiating owner task; native authorization is neither
moved into the preview worker nor represented by a transport-supplied flag.

The preview-worker checkpoint passed the full local gate: 1,694 tests passed,
11 ignored; formatting, workspace Clippy, Ruff, generated licenses,
vulnerability scanning, and license policy passed. Logs use the prefix
`~/Documents/wallet-previews-` with `workspace-tests.log`, `clippy.log`,
`osv.log`, and `licenses.log`. Native CI for this checkpoint remains required.

Desktop snapshot loading now uses a shared asynchronous `SnapshotReader`
interface and capture implementation. The production desktop calls that async
capture; its local compatibility reader dispatches SQL/decoding reads to
blocking workers. The Linux owner client implements the same interface through
typed RPCs, with no storage path or platform identity in the capture contract.
The desktop still owns local authority at startup: this is reader adoption,
not completed remote custody. The GPUI snapshot projection preserves existing
field-level failures, attribution sanitization, cached summaries, and refresh
state handling. Recent activity remains 200 rows and automation history 20;
transaction summary/headline lookups split inventories into 1000-ID requests
without truncating them. Oversized individual records and other inventory
pagination remain outstanding. Tests cover asynchronous partial failures,
batch completeness, and the local worker-backed reader over synthetic records.

The async snapshot checkpoint passed the full local gate: 1,697 tests passed,
11 ignored, including the existing desktop render suite. Formatting,
workspace Clippy, Ruff, generated licenses, vulnerability scanning, and license
policy passed. Logs use the prefix `~/Documents/wallet-snapshot-` with
`workspace-tests.log`, `clippy.log`, `osv.log`, and `licenses.log`.

The client now has a transport-independent desktop-session supervisor and an
OwnerClient entry point for it. The supervisor holds the long-running desktop
lease, closes the underlying connection on explicit Quit, dropped lifetime, or
unexpected lease completion, and reports closure failures. It never reconnects
or replays requests. `Connected` describes supervision of the authenticated
connection, not an acknowledgement of lease acceptance. The application must
await close before stopping its runtime; Drop requests closure without waiting.
Tests cover explicit close, Drop, unexpected successful/error lease completion,
and closure errors. An explicitly executed private-bus test confirms that close
invalidates retained OwnerClient clones and removes the desktop's unique bus
name. Log: `~/Documents/wallet-session-private-bus.log`. No installed service or
real wallet credentials were involved. Desktop startup adoption remains pending.

The client-session checkpoint passed the full local gate: 1,700 tests passed,
12 ignored. The private-bus clone-invalidation test was explicitly run and
passed in addition to that suite. Formatting, workspace Clippy, Ruff, generated
licenses, vulnerability scanning, and license policy passed. Logs use the
`~/Documents/wallet-session-` prefix with `workspace-tests.log`, `clippy.log`,
`private-bus.log`, `osv.log`, and `licenses.log`; `gate-exit.txt` records exit 0.
