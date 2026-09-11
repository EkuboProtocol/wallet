# Service isolation implementation

Status: in progress. The shipped application still uses desktop-user credential
storage. The new headless runtime alone provides no OS isolation and must not
be described as fixing issue #112.

The desktop now has an async `DesktopOwner` adapter with mutually exclusive
local-authority and authenticated-service-client variants. Snapshot refreshes
and the background account, token, network, activity, and automation operations
use its async methods. Local blocking operations run on workers; remote calls
use the existing typed client and never open a local store after an RPC error.
Transaction-summary requests carry stored IDs, and account imports retain
zeroizing typed input. Native authorization remains in the existing authority
and core paths. The local removal adapter checks the exact reviewed account and
document before entering native authorization, matching service dispatch.

Installed-profile startup now selects the authenticated service before opening
any local `ApplicationAuthority`. Only profiles without installed service metadata
retain the local path. Invalid metadata and service failures never fall back. Startup
settings, legal acceptance, ordinary settings mutations, signature decisions,
and account-removal reviews now use the async adapter. WalletConnect review state
now contains display-only account choices and a single-use decision handle. The
handle retains the original review independently of UI display edits; local
approvals deliver native proof directly to the session, while Linux and Windows
service approvals send only the stored review identity and selected index. The
service decision uses the same cancellation-bound connection as transaction
reviews, without reconnecting to a replacement service or replaying intent.
The application now consumes one backend-selected proposal feed. The local feed
uses the existing presenter and session events; the Linux/Windows service feed
captures an event cursor before reading authoritative proposals, deduplicates
identical full reviews, and replaces changed account/document choices. The service
broker preserves proposal arrival order, matching the local review queue. Missing
proposals, malformed snapshots, and feed failures invalidate unused decision
handles. Queued and visible expired reviews retire through the existing serial
review flow without reopening the wallet solely for a retirement update. These
liveness handles grant no authority and do not cancel authentication already in
progress merely because the broker has removed its pending row.
Pairing registration, session completion, disconnect, session-status reads, and
Quit now use a `DesktopDapps` facade selected once at startup. Its service backend
contains only the authenticated client and shared shutdown state. The existing
Cancel control remains available while registration awaits its response; a
canceled registration is disconnected when its ID arrives, without replaying a
lost start. Session read failures preserve the last snapshot and display an error.
Status reads carry a UI generation so a delayed response cannot resurrect a
session after a newer disconnect or clear a newer pairing's busy state.
Local shutdown excludes late registrations before draining relay farewells;
service shutdown closes the owner transport and releases its desktop lease while
the resident service finishes cancellation. Startup retains the acknowledged
`DesktopSession` until Quit, closes it before the Tokio runtime, and also closes it
on initial-state failure or an exit that bypasses the normal quit callback.
The service backend starts neither a local automation supervisor nor a local MCP
listener. The existing desktop paths remain for macOS and profiles not yet migrated.

Desktop-session readiness now distinguishes authenticated transport startup from
an accepted execution lease. Windows forwards the existing Hold acknowledgement
only after validating it. Linux subscribes before calling Hold and accepts only
a targeted `DesktopSessionReady` signal from the pinned unique service name with
the nonce for this exact hold. The service emits it after lease activation.
Missing acknowledgements fail startup after ten seconds and close the connection;
readiness failures wait for closure to finish and never reconnect or fall back to
local authority. This acknowledgement grants no owner authorization. The Linux
Hold signature and its service/client implementations must be installed together.
Native packaged startup and shutdown still require end-to-end verification.

The global desktop and notification consumers now subscribe through `DesktopEvents`,
which selects the local broadcast stream or authenticated service long polls. Remote
I/O stays on Tokio; a single queued batch bounds the relay, and dropping a subscription
aborts its reader. Initial/gap batches trigger fresh snapshot, token, portfolio and
selected-transaction reads, without manufacturing historical notifications. Actual
events retain their service timestamps and ordering. Reset batches carry the latest
informational MCP listener status even after the corresponding event has expired from
the journal. Transport failure ends the feed without reconnecting or replaying calls.
The window now retains `DesktopOwner` and all normal reads, reviews, and settings use
that selected backend; test fixture storage access remains test-only. Transaction
inspection results must match their active load identity, so service latency cannot
let an older reply overwrite a refresh or repopulate cleared history. Update authorization delegates to the existing
local core path only; service-backed update installation explicitly fails until the
protected service installer is implemented. No desktop authorization proof is created
for a service profile. Full packaged service behavior, installation/migration, protected updates, and
Windows native owner authorization remain to be completed.

Service MCP admission now also follows desktop lifetime on Linux and Windows.
The runtime issues a connection bound to the current active period only after OS
peer authentication. Pending desktop reservations do not enable MCP. Closing the
last active desktop cancels that period permanently, including clients waiting
for their initial handshake and running MCP sessions; quick reopen creates a new
period and cannot revive old connections. Cancellation reaches rmcp's own service
task and cleanup, and a dropped connection cannot cancel other clients. The
production service no longer exposes an unrestricted `AgentApi` to platform hosts.
This is availability control, not owner authorization, and cannot undo a transaction
already submitted. Native packaged lifetime behavior remains to be verified.

The scheduler and dapp workers now use those same permanent desktop-period tokens.
The scheduler drops its old driver before creating a replacement even when a rapid
zero-to-one transition is coalesced by the activity watch. Each dapp registration
receives a child shutdown token of its originating period, and registration rechecks
that period after inserting the session. The review collector no longer reacts to a
sampled zero count by disconnecting every session: a newly reopened desktop's sessions
cannot be swept up in the old desktop's cleanup. Canceled sessions disappear from the
in-memory list and release registration capacity; an old worker's late failure cannot
resurrect its row. Existing protocol shutdown still handles dapp farewells.

The shared `custody_provisioning` preparation step now builds the exact credential
records read by both service stores. It takes already-held keys and the expected
account inventory, checks complete inventory/exact metadata/unique names and instances,
and derives each supplied key's address before sealing. It creates a fresh wrapping
key and enrollment, seals the existing database key and each account key under their
proper identities, and exposes the desktop relay separately from service-only records.
Tests unlock the output through the actual shared `ServiceCustody` loader. This step
reads no live keyring, writes no files, authorizes no migration, and deletes nothing.
The separate staging operation validates the destination identity, publishes new
`custody-stage-<uuid>-<record>` files through Linux's pinned directory handle or
Windows' protected storage handle, and reads each record back before publishing a
completion marker last. It never replaces active credentials or stores the desktop
relay beside the wrapping key. Failure-injection tests cover interrupted writes,
corrupt readback, and destination profile mismatch. A completion marker proves only
credential staging, not activation or permission to delete legacy keys. A failure
after publication (including sync or marker readback) can leave an ambiguous stage;
recovery must inspect it before proceeding. Database copy/verification, durable
migration commit, recovery, activation, and exact legacy-credential deletion still
require installer integration.

Source database transfer now has a shared SQLCipher snapshot component,
`policy_store::migration_database::MigrationDatabaseSnapshot`. It requires the
already-held raw database key, opens without CREATE or schema upgrades, rejects
non-current schemas and non-DELETE journal mode, and takes a connection-local
exclusive lock. It exports to a fresh private encrypted temporary file, preserves
the schema/data and application/user version headers, then verifies the detached
copy while retaining the source lock. Streaming or retrying the ciphertext keeps
that lock alive; dropping the snapshot releases it. A transfer failure is not an
activation receipt. The installer must still quiesce workers, hold the account
lifecycle lock, validate source path provenance and the complete key inventory,
verify protected destination storage, and durably commit or recover activation.
The snapshot is temporary transfer material, not crash-recovery state.

This uses [SQLCipher's export function](https://www.zetetic.net/sqlcipher/sqlcipher-api/#sqlcipher_export)
and [SQLite exclusive locking mode](https://www.sqlite.org/pragma.html#pragma_locking_mode).
Do not independently open/close raw descriptors on the source during the fence:
[POSIX descriptor closure can release SQLite's process-wide locks](https://www.sqlite.org/howtocorrupt.html#_posix_advisory_locks_canceled_by_a_separate_thread_doing_close_).
Tests cover the actual current database schema, encrypted readback, header values,
source write exclusion in an independent process, failed transfer/retry, release,
wrong keys, missing sources, obsolete schemas, and WAL rejection. Native packaged
migration and Windows execution of this component remain CI/integration work.

Pending credential storage no longer requires publishing an active profile first.
Linux reads protected `/etc/ekubo-wallet/pending/<uid>.json` and opens only
`/var/lib/ekubo-wallet/pending/<profile-uuid>` under the actual service UID. Windows
reads the protected 64-bit `HKLM\\SOFTWARE\\EkuboWallet\\Pending\\<owner-SID>`
`Profile` value, validates the virtual-service account, and opens only
`ProgramData\\EkuboWallet\\Pending\\<profile-uuid-simple>`. The existing metadata
schemas, ancestor checks, private permissions/ACLs and singleton locks apply.
Pending handles expose credential staging only; they do not initialize global
custody, grant owner authorization, or open owner/agent endpoints. Windows keeps
the pending identity reader crate-private, so it cannot be passed to desktop
connection APIs as an installed identity. Active discovery still reads only
`owners`/`Owners`, and pending bootstrap refuses an existing or malformed active
profile. No fallback from damaged active custody is added. The installer must
provision these separate locations and implement verified transfer, activation,
recovery and exact legacy deletion; bootstrap alone performs none of those steps.

Both native pending-storage types now receive encrypted database frames through
`DatabaseStagingStore`. The source snapshot supplies a length and SHA-256 digest;
the receiver copies with a fixed 16 KiB buffer, checks the digest, flushes and
reads back the actual temporary file handle before immutable publication as
`custody-stage-<uuid>-wallet.db`. It consumes exactly the declared frame length,
leaving subsequent protocol bytes unread. The eventual provisioning transport must
authenticate the sender and impose admission/time bounds. A short stream, digest
mismatch or failed write leaves no published database name before rename; errors
after publication can be ambiguous and must never trigger replacement or activation.
The active `wallet.db` is not written. Only pending roots expose this receiving
interface; staged reads return a validated read-only handle. Length/digest prove
transfer integrity, not a valid database or owner authorization. Protected SQLCipher
and complete credential-inventory verification, provisioning transport, durable
activation and recovery still need integration. Tests include a real encrypted
source snapshot transferred into a temporary protected Linux root and reopened with
its original key, rejection of a different key, frame boundaries, truncation,
corruption, immutable publication and cleanup; Windows tests exercise the same
receiver through native private-file publication.

`PreparedServiceCredentials::verify_staged_inventory` now connects credential
preparation to received-database verification. It rechecks the exact immutable
credential records and completion marker, validates the protected destination
identity/enrollment, and unwraps the database key internally. The native pending
root supplies a read-only file pin and protected pathname whose lifetime retains
the root (including Windows ancestor pins). Verification opens SQLCipher READ_ONLY
without CREATE or schema migration, checks the current schema version, page/logical
integrity and foreign keys, validates wallet configuration, and compares its full
wallet metadata with the prepared account inventory. The active signing-instance
rows must also match canonical UUID, name, address and creation time exactly;
retired history remains valid without requiring retired account keys. Verification
does not rewrite, rekey, activate or authorize deletion. It is not a durable
receipt: source revalidation, authenticated provisioning transport and a durable
migration commit/recovery protocol remain required. Tests cover the native Linux
snapshot/transfer/verification path, wrong database keys, changed enrollment or
credential records, missing/changed metadata, missing or extra active instances,
older schema versions, unsupported views/triggers and broken references, with
byte-identical databases after checks. Schema-version and inventory checks alone
are not structural schema attestation: constraints and index definitions must
also be validated against trusted schema or rebuilt from compiled definitions
before activation. The copied source database cannot supply that trust itself.


`PreparedServiceCredentials::rebuild_staged_database` now creates a separate
candidate under the pending root using core's compiled current schema, then copies
only data from the read-only received snapshot. It requires the exact known table
and column inventory, permits historical column ordering, and enforces compiled
checks, uniqueness and deferred foreign keys atomically. It preserves received
rowids and application/user version headers, verifies integrity and account
inventory, and publishes a fresh immutable canonical name. Source constraints and
index SQL are never copied. Failed builds discard their temporary file; publication
never replaces an existing candidate. A post-publication flush error preserves the
ambiguous candidate for recovery. Both native stores implement the same opaque
build contract. Windows obtains delete access through the pinned object only after
SQLite closes, so its handle sharing permits the build. Tests cover weakened source
constraints, invalid rows, reordered columns, unknown state, source preservation,
Linux transfer/rebuild and native Windows publication handles. This candidate and
its digest are still not activation or legacy-key deletion authority: authenticated
transport, durable commit, recovery and installer integration remain unfinished.

The shared `migration_transfer` codec now connects a frozen source to those
pending-store primitives. Its versioned stream binds an installer-provided
owner/service/profile and fresh session ID, then sends fixed-width key bytes,
individually framed account metadata, and the length/digest-bound encrypted
snapshot. Host-selected limits separately bound account count, metadata frame and
aggregate sizes, and database size. The receiver compares destination identity and
admission limits before reading keys, validates the supplied account keys, stages
credentials, receives the exact database frame and rebuilds the canonical candidate.
It returns an opaque result retaining the pending-root borrow and service custody;
only the session/stage IDs, canonical digest and desktop relay ciphertext are
available. It exposes no activation or deletion capability. Tests include a real
synthetic account through native Linux pending storage, sender preflight, truncated
keys/database, invalid account keys, destination mismatch, unknown header fields,
frame budgets, and preservation of following protocol bytes.

Linux now has a separate pending host selected by `--provision-owner-uid`,
advertising `org.ekubo.Wallet.Provision.u<uid>` at
`/org/ekubo/Wallet/Provision` after native pending-root validation. Its
`org.ekubo.Wallet.Provision1.Transfer` method accepts a socket descriptor from
the privileged installer. It verifies the actual system-bus sender is UID 0 and
matches that sender's process ID against the connected Unix stream's kernel peer
credentials before reading any transfer bytes. The installer must create the
socketpair while privileged and retain the other end; Linux records these peer
credentials at connection/socketpair creation ([unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)).
The separate bus policy denies ordinary desktop callers. Only one worker can own
the pending root at a time; no active owner RPC, authority, scheduler or MCP starts.

The native stream uses one absolute five-minute I/O deadline. Installer disconnect,
bus loss, timeout or handler cancellation shuts down the same socket object,
waking blocked native I/O. A worker retains the profile lock until its current
SQLCipher operation finishes, including after cancellation; this prevents overlap,
but does not forcibly interrupt a database rebuild already in progress. The shared
staging reply contains session/stage IDs, canonical database descriptor and desktop
relay ciphertext only. Its parser validates the session and envelope format. A
reply still does not authorize activation or legacy-key removal. Tests exercise
kernel peer/type rejection, native read deadlines and cancellation, live identity
checks on an isolated test bus, and a full synthetic transfer/reply through the
Linux pending store.

The provisioning service unit and D-Bus policy are source assets, not installed
release components. Windows now has an explicit `windows_service_manager::run_pending`
SCM bootstrap alongside active startup. The mode is fixed before dispatcher entry;
it selects only protected pending metadata, rejects active-profile conflicts, and
still verifies the SCM-supplied service name and actual virtual-account primary
token/session before invoking its host. A console cannot enter either mode. The
Windows `--provision-owner-sid` host now accepts a separate administrator-only
provisioning pipe. It reserves a successor instance before releasing the accepted
instance, reads a fixed nonsecret preface, and authenticates the kernel client
token before processing custody data. The wire format, limits, deadline policy
and staging reply are shared core code. The Windows installer client now reads
protected pending metadata through a distinct `PendingInstallerIdentity` after
checking its actual administrator token. It validates the connected pipe's owner
and ACL before writing a preface or custody bytes, using identification-only
SQOS. Busy-instance retries occur before any writes; failed transfers never
reconnect or replay. Its successful result retains the source database fence,
and caller cancellation wakes native I/O while the worker retains that fence
until exit. The caller must also retain the source lifecycle lock. The staging
reply still grants no activation or legacy-key deletion authority. The elevated
installer entry point and durable commit/recovery coordination remain unfinished.

Native Windows installer checks now distinguish privileged installation from an
ordinary administrator-account desktop process. They require enabled Builtin
Administrators membership (including restricted-token checks) and high or system
integrity; mere group presence, deny-only membership, or medium integrity fails.
The primary-process check rejects thread impersonation and queries a read-only
copy of the actual primary token. The synchronous pipe-client helper requires an
existing thread token and has no primary-token fallback. It must be called inside
a native impersonation/revert guard after the pipe read, as the provisioning host
now does. These checks recognize existing administrator authority, grant no
elevation or fresh wallet-owner presence, and access no credentials. Tests include
native self-impersonation, a separately created token with its Administrators SID
made deny-only, and isolated pending-mode console rejection. Native Windows CI is
required in addition to cross-compilation. The token checks follow Microsoft's
[CheckTokenMembership](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership)
and [integrity-control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
contracts.

The Windows host runs the blocking transfer codec through a shared asynchronous
I/O bridge with one absolute deadline and cancellation that wakes blocked reads.
It admits one storage worker at a time. Stopping cancels transport I/O; an already
running SQLCipher operation retains the pending root until it returns. Neither a
successful transfer nor its reply activates custody. Tests cover native pipe
privilege checks, administrator ACL rights, bridge round trips and cancellation.
A real SCM fixture using distinct installer and virtual-service identities is
now included in the native Windows CI job. It creates a temporary virtual-account
service on a disposable elevated GitHub runner, reads protected pending metadata,
and exchanges random bytes through the production pending SCM and pipe code. It
refuses an existing Ekubo installation and cleans up only the objects it created.
Its native result is still required: same-user pipe fixtures and cross-compilation
do not prove cross-identity token access. This fixture does not exercise database
migration, active custody, desktop owner presence or packaged installation.

The SCM fixture exposed a `CREATOR OWNER` (`S-1-3-0`) ACE on the Windows runner's
machine `SOFTWARE` key without the inherit-only flag. Registry validation now
recognizes this exact inheritance placeholder, while still requiring a trusted
actual owner and independently checking each child's resolved ACEs. It does not
add creator groups, owner-rights SIDs or concrete creators to the trusted list.
A native `AccessCheck` test compares the unresolved placeholder with an explicit
grant to the actual client token. Microsoft's
[well-known SID specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab)
defines the placeholder replacement on inheritance. The real SCM fixture must
still pass before cross-account provisioning is considered verified.

The Linux privileged client is now implemented in core's
`linux_provisioning_client::transfer`. A root-only pending-identity reader checks
protected configuration and rejects existing or damaged active metadata without
reading credentials. The client connects to the real system bus, resolves the
configured pending service once, verifies its UID and live process, installs a
disconnection watch, then revalidates and addresses that exact unique recipient.
Only then does it create the privileged socketpair and start the shared transfer.
The descriptor method call and stream exchange run concurrently, with reply sender
and session checks; both must succeed. Neither connection failure nor service
replacement triggers replay or rediscovery. Client and host share core's native
deadline/cancellation wrapper. Successful `StagedSource` retains the source snapshot
fence and exact bus connection until installer commit/abort; the caller must also
retain the source lifecycle lock. Cancellation wakes I/O and the worker retains the
fence until it exits. Tests cover protected pending-identity reads and ordinary-user
rejection, native I/O, and live recipient UID/replacement checks on an isolated bus.
A packaged privileged round trip remains unverified.

The client takes already-supplied keys and a frozen snapshot; it does not elevate,
start a service, access the keyring, activate custody or delete legacy records.
The authorized legacy-desktop handoff and privileged installer executable remain
unfinished. Installer relay persistence, durable commit/recovery, activation and
legacy cleanup remain unfinished on both platforms.

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

The typed activity client now obtains an ordered index and then reads stored
records in byte-bounded batches. A list containing many valid, large typed-data
requests can exceed a single 16 MiB frame even though each record fits. The
service returns a fitting prefix; the client verifies its record types and IDs
against the index before requesting the remainder. Empty, oversized, duplicate,
or mismatched responses and mid-read failures produce an error rather than a
partial list. There is no mutation replay or retained server transfer cache.
The initial index preserves the existing activity membership/order; records
may advance state before their later read, and are not authorization snapshots.

Tests reconstruct a synthetic inventory exceeding one frame and compare every
record, exercise actual protected-store lookups, and reject broken batch/index
responses and disconnects. This addresses the multi-record activity reply only.
The index currently uses the existing activity query internally; reducing its
database read cost, streaming individually oversized records, and covering the
remaining review/configuration inventories are still required for the desktop
cutover. No existing activity limit or display flow was changed.

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
  and simulation facts. Start, frame lookup, and decisions share a fresh per-review
  session ID; frame lookup cannot adopt a different review of the same transaction.
  Every choice also requires the exact single-use frame ID and document identity. Refresh retires the previous frame, even when its
  document is unchanged. Close and cancellation abort without recording a
  rejection; only an explicit Reject choice follows core's rejection path.
  Cancellation drops the reservation, and broker shutdown cancels pending
  operations, including preparation before a frame exists. Review events follow
  frame insertion/removal. The core legal-store borrow is exclusive across
  awaits so the service can poll the future without sharing SQLite connections.
  The Linux host explicitly closes reviews through the shared dispatcher before
  disconnecting its owner endpoint; Windows must invoke the same lifecycle hook.
  The desktop adapter now drives this protocol with the existing single-use GUI
  prompts. It keeps the start RPC alive while fetching frames and forwarding intent,
  waits for the actual service result after a decision, and never replays an ambiguous
  failure. Linux reviews open an independently closable D-Bus peer to the already
  pinned service, without activation or custody relay. A supervisor closes it on
  completion or cancellation; dropping a method future alone would not cancel D-Bus.
  Windows cancellation drops the initiating call's pipe. Closed GUI response channels
  are discarded rather than reopening stale prompts. Installed-profile startup selects
  the service backend; large-frame handling and native successful signing validation
  are still required.

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

Private profile directories also require a full-access `OBJECT_INHERIT` grant
for the configured service SID, so database-created child files inherit a
service grant. Untrusted grants are rejected even when marked inherit-only;
the sole placeholder exception is inherit-only CREATOR OWNER inside the
already-private directory. SYSTEM and Administrators remain trusted. Provision
protected directory ACLs such as
`O:<service SID>D:P(A;OICI;FA;;;<service SID>)(A;OICI;FA;;;SY)`.
File validation does not require inheritance flags. This check is a prerequisite
for Windows database activation; it does not activate the service backend.

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
   or break existing large-payload screens. Installed-profile startup now selects service custody and omits the local
   automation and MCP workers; native packaged validation remains required.
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

## At-rest wrapping implementation and remaining integration

Windows `PrivateStorageRoot` now provides fixed database/account-key reads and
creation operations using the same `ServiceCustody` and `DataCipher` as Linux.
The root starts locked and retains its cipher privately after validating the
enrolled ciphertext. Callers no longer supply an arbitrary cipher to key writes.
The instance UUID selects an
account filename and cryptographic binding; callers cannot supply an arbitrary
write path. The root rechecks the native service process and private directory
before creating any file. Account creation/import authorization still belongs
to core's existing owner operation; these storage methods do not create account
metadata, change policy, or authorize signing.

The native writer applies an explicit protected DACL at creation, uses
`FILE_CREATE` with no sharing and no reparse traversal, and writes only sealed
82-byte ciphertext. It flushes the temporary file before a same-directory
`FileRenameInformation` operation with replacement disabled, then flushes again.
Failure before publication deletes only the owned temporary handle. Failure
after successful rename leaves the committed key for readback reconciliation.
The Windows implementation follows Microsoft's documented
[relative rename and no-replacement contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information).

Native tests cover private creation without inherited grants, conflicting and
concurrent writers, failed-validation cleanup, preservation of existing keys and
legacy plaintext, and a renamed parent path. One test retains the production
directory sharing mode throughout publication. Tests use only synthetic keys in
random temporary directories, with the test process's actual owner SID; they do
not claim installed service-account or crash-recovery coverage. Native execution
of the corrected write path remains required in addition to Windows-target
Clippy. The first native run passed 35 tests and exposed one sharing conflict
with the production directory pin. Supplying a target root handle caused a
conflicting directory reopen. The correction uses a simple name and NULL
`RootDirectory`, which Microsoft defines as renaming inside the source file's
existing directory. The source and ancestor handles remain pinned with their
original sharing protections; no caller path or working directory is consulted.

`ServiceCustody` now owns the common locked state, bounded enrollment/key reads,
and active-enrollment digest pin. Linux supplies permission-checked file handles;
Windows supplies its native ACL-checked handles. Windows unlock obtains only the
fixed `custody.json` and `wrapping.key` files and binds them to protected owner
SID, service SID, and profile UUID. Typed reads reject truncated, trailing,
plaintext, cross-purpose, and cross-instance credential data. The shared tests
exercise restart, locked failures, and refusal to replace an active cipher for
both UID and SID bindings. This completes the Windows profile object's encrypted
read/unlock path, not global backend activation or SCM/pipe integration.

The at-rest design splits protection across the two OS identities. The shared
`custody_envelope` primitive now implements symmetric key wrapping: only the
service creates and unwraps data keys, so public-key distribution is unnecessary.
The Linux protected-file backend and authenticated client bootstrap now use it.
Windows file-backend activation and the desktop application cutover remain.

- The service owns a random 256-bit wrapping key in its private directory.
- The desktop credential store contains only an authenticated envelope of the
  wallet data key encrypted with the service wrapping key. The service must not
  also persist that envelope as an ordinary disk file; that would defeat the
  offline protection supplied by the login keyring.
- A desktop relay supplies that ciphertext when the already-unlocked credential
  store makes it available. The service unwraps it in memory and opens its
  encrypted database/credentials. Relaying ciphertext grants no signing rights.
- Bind the enrolled envelope to the configured owner, service identity, profile,
  protocol version, key-generation UUID, and a pinned digest in protected state. Reject substitutions
  and rollbacks; changes require authenticated migration/rotation.
- The service exposes no general unwrap operation. Only the internal custody
  bootstrap consumes the envelope; neither the data key nor wrapping key crosses
  IPC. The data-key capability exposes only fixed-size database/account-key
  encryption, with separate purposes and a wallet-instance binding for accounts.

The implementation uses RustCrypto XChaCha20-Poly1305, with its `zeroize` feature
explicitly enabled, OS-generated 24-byte nonces, and zeroizing plaintext buffers.
The dependency was already in Cargo.lock; only direct use and zeroization feature
edges were added, without changing dependency versions. The crate reports a
[prior NCC Group audit](https://docs.rs/crate/chacha20poly1305/0.11.0);
this is not an audit of the new integration. Symmetric wrapping follows the
usual [data-key/key-encryption-key model](https://docs.cloud.google.com/kms/docs/envelope-encryption).

The fixed v1 blob is 82 bytes: `EKUBOKEY`, version byte 1, purpose byte, 24-byte
nonce, encrypted 32-byte key, and 16-byte tag. AEAD associated data contains the
ten-byte header, SHA-256 of a fixed JSON tuple identifying owner/service/profile/
generation, and the account-instance UUID (nil only for database and data keys).
Purpose bytes 1, 2, and 3 distinguish data, database, and account keys. Parsing
rejects unsupported versions, roles, lengths, and legacy plaintext. Unlock also
requires the exact envelope digest pinned in protected enrollment; the desktop
must never supply that expected digest or the binding as authority.

Tests include an independently generated libsodium 1.0.22 vector, modification
of every blob byte, wrong wrapping keys and bindings, old-enrollment replay,
cross-account/purpose substitution, malformed lengths, and reconstruction after
wrapping-key reload. The native Windows harness now includes this same source
and its tests with the exact locked dependency declarations. The independent
vector generator is `~/Documents/wallet-custody-vector.py`, using the documented
[libsodium API](https://doc.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).

Linux storage initializes locked and reads enrollment metadata (`custody.json`)
and the wrapping key (`wrapping.key`) only through its pinned private directory,
with ownership, mode, file-type, link-count, and size checks. Its root-owned
configuration now also requires the profile UUID. Unlock consumes only the
enrolled ciphertext; repeated unlock cannot replace an active data cipher.
Database/account key files contain authenticated 82-byte ciphertext, including
temporary files. Corrupt or legacy plaintext files fail instead of falling back
to the desktop credential store. Synthetic storage tests cover reopening,
substitution, locked access, permission failures, and enrollment replacement.

Both platforms use the same `CustodyEnrollment`, `WrappedDataKey`, and
`DataCipher` implementation. A shared test exercises successful enrollment and
restart with Linux UID and Windows SID bindings. Platform adapters supply the
verified identities, protected file operations, and authenticated IPC; the shared
cryptographic module does not establish OS identity. This avoids a separate
Windows cryptographic format or unlock policy.

`CustodyBootstrap` shares startup coordination across platform hosts. It accepts
only the fixed wrapped-data-key format, invokes the platform's protected unlock
operation, and withholds a successful reply until the host publishes authority.
Pending requests have bounded capacity; cancellation releases that capacity
without undoing a completed unlock. Host startup failure cannot produce a ready
reply. Unlock does not create a desktop-session lease or signing authorization.

The Linux host publishes only `/org/ekubo/Wallet/Custody` initially. Its `Unlock`
method authenticates the live bus sender through core before touching protected
custody, and accepts no identity, path, expected digest, or approval flag. Only
after unlock does the host create its MCP listener, authority, and owner API.
Termination and system-bus loss end the bootstrap wait; bus loss also stops the
active runtime. D-Bus name acquisition now means bootstrap availability, while
a successful `Unlock` reply means owner-API readiness.

Linux `OwnerClient::connect` pins the installed service's unique bus name before
loading the profile's ciphertext from the login credential store. The fixed
`org.ekubo.wallet.custody-envelope` namespace contains only this opaque blob,
keyed by the installer-attested profile UUID. Core rejects malformed/raw keys,
reads a fresh credential entry, and provides no filesystem cache or fallback.
The client sends the blob to that same pinned service and verifies reply
provenance; it never reconnects or replays the bootstrap after name replacement.
The shared envelope reader is also available for the future Windows client.

Bootstrap validation passed the full local gate (1,738 tests, 14 ignored), plus
the three explicitly enabled private-bus client tests and the isolated keyring
restart test. Those tests use synthetic enrollment and disposable same-UID
services; installed cross-UID authentication, provisioning, and migration still
require their own integration evidence.

Protected wrapping-key provisioning, transactional digest enrollment/rotation,
Windows backend/transport activation, and crash recovery/migration remain
unimplemented. These assets remain excluded from release installation; the
desktop application still uses local authority, so its custody and UX are
unchanged. Do not deploy this intermediate backend with real accounts.

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
or replays requests. The initial state is `Starting`; `Connected` now means the
service has acknowledged this connection's active desktop lease. Callers await
`DesktopSession::ready()` before allowing service-backed desktop work, and await
close before stopping the runtime; Drop requests closure without waiting.
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

The Windows private root exposes typed opens for `wallet.db` and `wallet.lock`.
These use relative `NtCreateFile` with `FILE_OPEN_IF`, an explicit private DACL
at creation, and handle validation before returning. Existing files are neither
truncated nor repaired. The returned handle permits concurrent readers/writers
but denies deletion; callers must retain it for the lifetime of the corresponding
SQLite connection. This storage primitive does not yet route `PolicyStore` or
desktop startup through the Windows service backend.

The root also exposes its OS-resolved volume GUID path, obtained from the retained
profile handle after ancestor validation. This gives the later SQLite adapter a
Win32 path tied to the pinned profile rather than a new environment-based lookup.
The root must outlive every connection using that path.

Windows core now has explicit process-wide activation through
`windows_service_custody::initialize(owner_sid)`. It verifies existing installed
service identity and private storage, starts locked, and binds configuration,
credential routing, and all fixed database/configuration/lifecycle lock files to
that root. Once active, unsupported namespaces and paths fail without falling
back to desktop credentials. A missing final credential name alone maps to
`NoEntry`; missing profile paths, unsafe ACLs, and invalid ciphertext remain
errors. Unlock continues to require authenticated transport relay.

Each service-backed `PolicyStore` retains a no-delete database handle until its
SQLite connection closes. Failed first-use token seeding resets that exact
pinned database to empty so a retry can reuse its credential; it cannot unlink
the file while other initialization handles hold it. Credential removal validates
and decrypts the exact exclusively opened file before marking that handle for
deletion. It never reopens a pathname to delete it.

Windows service owner presence fails closed pending the authenticated desktop
transport and operation-bound proof adapter. The desktop still uses its existing
backend: this activation API is not yet called by an installed SCM host, and
provisioning, migration, transport, and desktop cutover remain incomplete.

Windows owner transport endpoints now use a profile-derived local named pipe.
Creation requires the actual configured service process, sets service ownership
and an explicit protected DACL, rejects remote clients, and refuses an existing
name for the first instance. Desktop permissions use individual read/write,
synchronize, and read-control bits; they omit the append/create-instance bit
included in generic write. The client validates the connected pipe object's
owner and DACL before returning its stream, so a name or recycled PID is not
accepted as service identity.

After reading a bounded request, the server adapter must authenticate the last
read's kernel client context. That synchronous check uses identification-level
impersonation, reads the actual token SID, and always reverts before returning.
A failed revert aborts rather than allowing later service work in client context.
This proves OS account identity only. `WindowsOwnerEndpoint` now activates
locked protected custody, binds the first endpoint, and accepts at most 32
connections while retaining a pipe instance across listener replacement. The
host retains a publisher while the listener runs, opens authority after unlock,
publishes that runtime, then acknowledges readiness. SCM hosting and fresh owner
proofs remain separate; no service is installed by this code.

The stream protocol starts with an instance UUID from the authenticated service.
Clients must pin it across their lifetime and compare each call connection before
sending a request. Calls use the shared owner dispatcher and close after one
result. A separate authenticated connection relays the enrollment ciphertext,
waits for runtime readiness, then may hold a desktop lease until disconnect.
Unlock alone grants no lease. Each request is authenticated immediately after
its last read. EOF or unexpected input cancels a pending call/readiness wait;
those monitors use cancellation-safe one-byte reads. No mutation is replayed.
Secret-bearing frame readers erase partial payloads when an I/O failure occurs.
The Windows desktop client and SCM host still need to use this protocol.

The Windows `OwnerClient` now uses this stream protocol through the authenticated
core pipe connector. It invokes the login-keyring ciphertext loader only after
endpoint and greeting validation, pins the service instance, and checks every
call connection before sending its request. Lost replies never trigger replay.
A background lifetime driver sends Hold only when requested, survives cancellation
of an individual Hold future, and closes when the last client is dropped or any
clone explicitly closes. Explicit closure waits for that actual lifetime pipe to
be dropped and invalidates pending and future calls. A replaced service instance
closes all clones before receiving request bytes.

The native connector waits for a free pipe instance for at most ten seconds when
Windows reports `ERROR_PIPE_BUSY`; these retries precede all protocol writes.
Other connection/authentication failures are returned immediately. This avoids
ordinary concurrent UI reads failing in the brief interval before the server
creates its next listener instance. Desktop startup and SCM hosting still need
to select this client and keep its existing DesktopSession supervisor alive.

Windows initial owner and MCP connections now activate the installed service
through local SCM before attempting the authenticated pipe handshake. The
service name comes only from protected installer metadata for the actual owner.
Activation requests `SC_MANAGER_CONNECT` and `SERVICE_QUERY_STATUS | SERVICE_START`;
the installer must grant the owner those service rights without stop, deletion,
configuration, or ACL mutation rights. No caller-selected start arguments are
sent. A running service is left alone, an in-progress start is observed, and a
stopped service gets one start attempt. A failed or stopping service is not
automatically restarted. Existing connection clones do not reactivate or replay
requests after a lost connection.

Activation has a ten-second caller deadline and runs blocking SCM calls on a
worker. Cancellation prevents further polling/start attempts, but cannot undo
an SCM call already in progress or an accepted service start. Running status
does not authenticate the endpoint or unlock custody: the existing pipe-object
validation, service-instance pinning, and encrypted-envelope relay still apply.
Tests cover the activation state machine and use a random nonexistent name for
native SCM lookup; they do not provision or start an installed service. Packaged
activation tests, installer grants, and Windows owner-presence proofs remain
required before desktop cutover.
