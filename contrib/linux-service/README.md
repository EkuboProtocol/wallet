# Linux authority service assets

These assets are not yet included in release packages or installed by the
application. Do not start this service against real accounts: key enrollment,
transactional migration, and protected installation remain unfinished. Installed-profile
desktop remote startup is implemented but has not been verified in a packaged install. Storage
now requires encrypted credentials and starts locked. The host waits for the
authenticated client's enrolled ciphertext before constructing authority.

Credential preparation and protected staging now share a contract with Windows.
Staging creates fresh immutable record names, verifies readback, and publishes a
completion marker last. It does not activate custody, copy the database, or authorize
legacy-key deletion. Partial or ambiguous stages require installer recovery; this
primitive is not a completed migration or an installation procedure.

Pending bootstrap is separate from active discovery. The installer may provision
root-owned `/etc/ekubo-wallet/pending/<uid>.json` using the same closed identity
schema, with service-owned mode-0700 storage at
`/var/lib/ekubo-wallet/pending/<profile-uuid>`. Both pending parent directories and
all their ancestors must be root-owned and not writable by ordinary users. Core's
`pending_credential_staging_root` validates the real service process, metadata,
directory handles and singleton lock, then exposes staging only. It neither sets
the global custody backend nor activates an owner/MCP endpoint. Desktop discovery
continues to read only `owners/<uid>.json`. Existing or malformed active metadata
rejects pending bootstrap, so this is not a replacement/rotation path. The installer
must still implement verified transfer, durable activation and interruption recovery;
these paths are not an instruction to publish active metadata early.

The returned pending handle also supports streamed database receipt with the same
contract as Windows: declared length and digest, fixed-size buffering, handle-based
readback, and publication under a new stage name only after verification. This
checks transferred bytes, not SQLCipher contents or migration authorization. It
does not write active `wallet.db`; the privileged provisioning transport and final
activation remain unfinished. Core now verifies the received SQLCipher database
and key-bound account inventory, then rebuilds a separate candidate using compiled
schema and data-only copy. Linux and Windows share this contract; source constraints
and indexes cannot become service authority. Candidate publication does not
authorize activation or legacy-key deletion; durable installer recovery is still
required.

A separate pending host is now implemented in the service binary:
`--provision-owner-uid <uid>`. The new `ekubo-wallet-provision@.service` and
`org.ekubo.Wallet.Provision.conf` are source assets for its installer-only system-bus
endpoint. The installer creates a connected Unix socketpair while privileged and
passes one descriptor to `org.ekubo.Wallet.Provision1.Transfer` at
`/org/ekubo/Wallet/Provision`, destination `org.ekubo.Wallet.Provision.u<uid>`.
Core validates pending identity/storage before the endpoint is advertised. The host
requires actual D-Bus UID 0 and socket peer UID 0 with the same process ID, then
runs the shared bounded provisioning transfer and returns only a staging reply.
One worker holds the root at a time. Deadline/disconnect cancellation shuts down
native socket I/O; an in-flight SQLCipher operation retains the lock until it ends.
It never starts active wallet authority. The installer must stop the pending host
before later profile promotion. These assets are not installed by current packages;
the installer executable, source handoff, durable activation and recovery remain
unfinished. Do not publish active metadata in response to a staging reply.

Core now supplies `linux_provisioning_client::transfer` for the privileged
installer. It reads only protected pending identity as UID 0, authenticates the
actual service on the real bus before any key write, and exchanges the descriptor
method call and bounded transfer concurrently. A successful result retains the
source database fence and authenticated bus connection through later commit or
abort; the caller must keep its source lifecycle lock too. The client never starts
or reconnects a service, and does not grant activation/deletion authority. It takes
already-held raw keys and a frozen snapshot; owner-authorized elevation, legacy
source handoff and a packaged privileged round trip remain to be implemented/tested.

The installer must install the service executable and all ancestor directories
as root-owned and unwritable by the desktop user. Its fixed executable path is
`/usr/lib/ekubo-wallet/ekubo-wallet-service`. Install the unit under
`/usr/lib/systemd/system/`, the D-Bus policy under `/usr/share/dbus-1/system.d/`,
and the sysusers/tmpfiles files under `/usr/lib/sysusers.d/ekubo-wallet.conf`
and `/usr/lib/tmpfiles.d/ekubo-wallet.conf`. The existing polkit policy must also
be installed; its service-owner annotation names the same `ekubo-wallet` account.

Provisioning one owner requires a canonical, nonzero numeric owner UID, distinct
from the resolved service UID. Write root-owned, non-writable-by-others public
metadata at `/etc/ekubo-wallet/owners/<uid>.json`, matching core's closed JSON
schema: `{"owner_uid":1000,"service_uid":999,"profile_id":"00000000-0000-0000-0000-000000000001"}`
(values here are illustrative; provision a fresh nonzero profile UUID).
None of these values may come from an untrusted IPC claim. Create new private state at
`/var/lib/ekubo-wallet/<uid>` with mode 0700 and the service UID. Create the runtime
directory `/run/ekubo-wallet/<uid>` with mode 0711 and the service UID; it must be
recreated after reboot by validated provisioning. Clients need directory search
permission to reach `mcp.sock`; the host authenticates every socket peer using
kernel credentials. Do not recursively chown or repair an existing unsafe tree.
The service retains its own no-follow, ownership, mode, and singleton-lock checks.

The template is started as `ekubo-wallet@<uid>.service`. D-Bus name acquisition
marks bootstrap availability after protected storage initializes. The
`org.ekubo.Wallet.Custody1.Unlock` reply succeeds only after authority and its
owner API are ready. The service being up does not start automations: they require a desktop-session
lease. Enabling/activation, boot-time runtime-directory creation, installation
rollback, upgrade coordination, and removal still need installer implementation.
The install target is intentionally omitted until those steps are implemented.

For on-demand startup, substitute the validated canonical owner UID for every
`@OWNER_UID@` in `org.ekubo.Wallet.Owner.service.in` and install it as the
root-owned `/usr/share/dbus-1/system-services/org.ekubo.Wallet.Owner.u<uid>.service`.
The resulting `SystemdService` must be `ekubo-wallet@<uid>.service`. Register
activation only after the matching protected state, metadata, runtime-directory
provisioning, executable, and unit are ready. The `Exec=/usr/bin/false` fallback
deliberately refuses activation without systemd rather than launching the service
outside its unit's sandbox. Do not install the unexpanded template.

Initial Linux owner and MCP connections request `StartServiceByName` on the
pinned system bus if the name is unowned, then resolve and authenticate the
service's unique name, UID, and PID. Activation failure returns an error; it never permits local-custody
fallback for an installed profile. Existing connections do not activate again or
replay interrupted requests. The activation reply is availability only, so the
client still authenticates the endpoint before reading enrollment ciphertext.

The unit deliberately avoids systemd's automatic state-directory ownership
repair. See [systemd's directory semantics](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml).
The D-Bus policy permits only the dedicated account to own the wallet namespace;
core still authenticates each owner call. See [D-Bus bus policy](https://dbus.freedesktop.org/doc/dbus-daemon.1.html).
Native packaged-service tests must verify these assets with polkit, networking,
SQLCipher, and the protected executable before deployment. Windows must provide
its own SCM, ACL, and authenticated-pipe provisioning for the same shared runtime.
