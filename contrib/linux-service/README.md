# Fresh protected v2 installation

These assets are for the signed privileged v2 package. Do not run installation
while building or testing the repository. No command reads or removes 1.x state.

## Package integration

Build `ekubo-wallet-service` and `ekubo-wallet-v2-enroll` from the service crate
without `test-hooks`. Install both root-owned, mode 0755, under
`/usr/lib/ekubo-wallet-v2/`. Install `install-profile` in that same directory,
root-owned and mode 0755. It requires Python 3 and `pkexec`.

Install:

- `ekubo-wallet-v2@.service` and `ekubo-wallet-v2-provision@.service` into the
  system unit directory;
- both `org.ekubo.Wallet2.*.conf` policies into `/usr/share/dbus-1/system.d/`;
- `org.ekubo.Wallet2.Owner.service.in` into `/usr/lib/ekubo-wallet-v2/`;
- `ekubo-wallet-v2.sysusers` into `/usr/lib/sysusers.d/`;
- `ekubo-wallet-v2.tmpfiles` into `/usr/lib/tmpfiles.d/`;
- the separately maintained v2 polkit owner-authentication policy.

The package postinstall must run systemd-sysusers, systemd-tmpfiles --create for
the package files, daemon-reload, `install-profile --restore-activations`, and
reload the system bus configuration (never restart D-Bus).
Do not recursively chown/chmod existing custody directories during upgrades.
An upgrade replaces compatible signed binaries and restarts existing units;
it must not run fresh enrollment on an existing profile.

Enrollment and resume publish the exact UID-substituted activation file into
`/usr/share/dbus-1/system-services/org.ekubo.Wallet2.Owner.uOWNER_UID.service`.
Publication fsyncs complete bytes before a Linux no-replace rename, then fsyncs the
directory. Exact protected files are idempotent; conflicts, unsafe paths,
malformed metadata and altered templates fail without replacement. The file's
`User` is `ekubo-wallet-v2`, and `SystemdService` is the exact
`ekubo-wallet-v2@OWNER_UID.service` instance. `Exec=/usr/bin/false` deliberately
fails closed when systemd activation is unavailable; it cannot bypass the unit's
sandbox. The generated file is retained outside the package manifest. Postinstall
also regenerates missing files from root-protected `owners/*.json` identities,
without reading custody files or owner proofs. This allows stopped retained
profiles to activate via `StartServiceByName` after reinstall; `try-restart`
alone cannot start a stopped unit.

The login owner runs:

```
/usr/lib/ekubo-wallet-v2/ekubo-wallet-v2-enroll --owner
```

This holds the real owner's authenticated relay endpoint while `pkexec` runs
the fixed installer. The installer creates an unused profile, starts the
provisioning service, receives only ciphertext, delivers it to the actual
owner, stops provisioning, publishes storage/configuration without replacement,
and enables/starts the authority. The owner then authenticates and unlocks the
normal service through the normal owner client.

The native hosts call `mark_setup_complete()` after relay unlock and successful
authority publication. This also captures an immutable, encrypted-database
first-run baseline for an optional explicitly authorized legacy move. Fresh
installation itself never reads the legacy profile or legacy credentials.

## Interrupted fresh setup

Nothing retries key generation over existing records. Before relay confirmation,
an unpublished, unused pending Linux profile can be explicitly discarded:

```
sudo /usr/lib/ekubo-wallet-v2/install-profile --discard-unused OWNER_UID
```

After durable relay confirmation, resume publication with:

```
sudo /usr/lib/ekubo-wallet-v2/install-profile --resume OWNER_UID
```

The normal owner can instead run `ekubo-wallet-v2-enroll --resume-owner`, which
elevates the fixed resume action and reconnects the owner. Missing credentials on an installed profile are an
error, never an invitation to reset. An interruption before protected pending
metadata was created requires privileged inspection of the unused installation
artifacts; the recovery command does not guess their provenance.

## Windows package integration

The signed package installs both `.exe` files in `%ProgramFiles%/Ekubo Wallet 2`
and ships `contrib/install-windows-v2.ps1` and `contrib/recover-windows-v2.ps1`.
The owner starts `ekubo-wallet-v2-enroll.exe --owner` from a normal login session.
The helper now launches the fixed installed script through UAC automatically,
keeps the authenticated owner relay alive, and connects/unlocks the published
service while the elevated installer waits for readiness. The elevation may
belong to a different administrator. Packaged UI can launch this same helper and
wait for its exit status; no SID or endpoint needs to be copied by the user.
The scripts must also be Authenticode signed and deployable under `AllSigned`;
the package must address publisher trust rather than bypass execution policy.

The installer creates `EkuboWalletV2-<profile>` under a distinct virtual account,
protected `ProgramData/EkuboWalletV2` storage and `HKLM/SOFTWARE/EkuboWalletV2`
metadata. It verifies relay receipt before publication and waits for the
service's readiness marker. `recover-windows-v2.ps1 -OwnerSid SID` resumes only
relay-confirmed setup; `-DiscardUnused` explicitly discards an unpublished,
unconfirmed first-install attempt. The initial script supports one fresh owner
profile per machine and refuses existing v2 roots. Package upgrades must preserve
those roots and service registrations rather than invoking this fresh installer.
The normal owner CLI exposes these explicit choices as `--resume-owner` and
`--discard-unused`, with UAC elevation of the fixed recovery script.

Native Windows execution, signed package upgrade behavior, and production
owner-authorization acceptance still require native validation. These scripts
have not been executed on the development host.
