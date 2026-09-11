# Linux authority service assets

These assets are not yet included in release packages or installed by the
application. Do not start this service against real accounts: key enrollment,
transactional migration, and desktop remote startup remain unfinished. Storage
now requires encrypted credentials and starts locked. The host waits for the
authenticated client's enrolled ciphertext before constructing authority.

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

The unit deliberately avoids systemd's automatic state-directory ownership
repair. See [systemd's directory semantics](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml).
The D-Bus policy permits only the dedicated account to own the wallet namespace;
core still authenticates each owner call. See [D-Bus bus policy](https://dbus.freedesktop.org/doc/dbus-daemon.1.html).
Native packaged-service tests must verify these assets with polkit, networking,
SQLCipher, and the protected executable before deployment. Windows must provide
its own SCM, ACL, and authenticated-pipe provisioning for the same shared runtime.
