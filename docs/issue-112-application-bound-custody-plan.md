# Issue #112: application-bound custody on Windows and Linux

Status: plan. Nothing here is implemented.

[Issue #112](https://github.com/EkuboProtocol/wallet/issues/112) is the open
critical finding that a same-user process can read both the SQLCipher database
key and every raw account private key out of the platform credential store,
reconstruct a signer outside `ekubo-wallet-core`, and sign anything — with no
debugger, no injection, no administrator, and no wallet IPC capability. This
document plans the fix and the review that gates it.

## 1. The goal, stated as UX before security

The requirement is not "encrypt the key harder". It is: **Windows and Linux
should feel exactly like macOS feels today.**

On macOS the owner installs the wallet, opens it, and it works. There is no
wallet password and no key password. The key is in the login keychain, which
the login already unlocked, and the item's access control names the wallet's
code-signing identity, so the wallet reads it silently and another same-user
program does not. `docs/threat-model.md` records why that is a materially
stronger application boundary: Apple documents that
[the creating application is automatically trusted and item access is tracked by its code-signing requirement](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/AboutCS/AboutCS.html).

So the target is a boundary with these properties, on all three platforms:

- the private key and database key are readable by the wallet application and
  by nothing else the desktop user runs;
- unlocking happens as a consequence of the user's ordinary OS login, not as a
  separate secret;
- unattended policy execution keeps working — a policy-allowed transaction is
  signed with no human present and no prompt.

### UX acceptance criteria

A candidate design is only acceptable if all of these hold:

1. **No new password.** No wallet password, no key password, no passphrase at
   first run or at any launch.
2. **No per-signature prompt.** Signing that the active policy already allows
   stays silent. Windows Hello and polkit remain where they are today — owner
   authorization for widening authority — and do not move onto the signing path.
3. **Unattended execution survives.** Scheduled automations and agent-submitted
   transactions still execute while nobody is at the machine.
4. **Same account, same address.** The upgrade preserves wallet IDs, addresses,
   policies, and history. No re-import, no seed re-entry, no migration UI.
5. **Same install gesture,** or an honestly-disclosed larger one. Where the OS
   demands more (see §5), that cost is named here and decided by the maintainer
   rather than absorbed silently.

## 2. Why the current stores fail

Already documented in-tree, repeated here so the plan is self-contained:

- `crates/ekubo-wallet-core/src/policy_store.rs` keeps the SQLCipher key at the
  fixed service/user pair `org.ekubo.wallet.db` / `default`.
- `crates/ekubo-wallet-core/src/custody.rs` keeps each raw secp256k1 key under
  `org.ekubo.wallet.private-key.instance`, keyed by wallet instance UUID.
- `keyring` 4.1.6's Windows backend writes generic credentials, which Microsoft
  documents as
  [readable and writable by user processes](https://learn.microsoft.com/en-us/windows/win32/secauthn/kinds-of-credentials).
- Its Linux backend uses the Secret Service default collection, whose
  [specification does not mandate access control](https://specifications.freedesktop.org/secret-service/latest/ch10.html),
  and GNOME states that
  [any application with the same user's privileges can read secrets from an unlocked keyring](https://wiki.gnome.org/Projects%282f%29GnomeKeyring%282f%29SecurityFAQ.html).

Renaming the entries, randomising them, or wrapping them in DPAPI under the
same user does not move the boundary. Neither does encrypting the key with
something else stored beside it. The missing ingredient is an OS-enforced
*application identity* that a sibling process cannot forge.

## 3. Linux

### 3.1 There is no Linux equivalent of the Keychain ACL

State this first, because it governs everything after it: **no Linux mechanism
authenticates which program is making a request to a same-UID peer.** macOS can
say "this item is readable by the binary bearing this code-signing identity."
Linux has no such concept. Every mechanism that genuinely keeps a same-UID
attacker out does it by moving the secret to a **different GID or UID**, moving
it **off the host**, or adding a **password**.

The result that settles the design space: an attacker can **exec the genuine
installed wallet binary** under `LD_PRELOAD` with a hostile environment. That
process's `/proc/PID/exe` is genuine, its `SO_PEERCRED` credentials are genuine,
and its `SO_PEERPIDFD` resolves to a real, non-reused PID. So the discriminator
can never be a credential API — it must be **whatever defeats `LD_PRELOAD`**,
and only two things do: set-ID execution (`AT_SECURE`) or a tightly written LSM
profile.

### 3.2 What is theater

Named plainly, because each of these protects against a *different* attacker —
offline disk theft, other users, other machines — and is easily mistaken for
protection against this one:

- **Flatpak's Secret portal.** The per-app master secret is stored by
  gnome-keyring as an ordinary item in the login collection keyed on `app_id`,
  with no ACL in the code path, and the Secret Service specification states that
  it ["does not mandate any form of access control"](https://specifications.freedesktop.org/secret-service/latest/ch10.html).
  An unconfined process reads it out and then decrypts `~/.var/app/<id>`, a
  plain user-owned directory. Flatpak's process isolation is outbound-only.
- **Snap strict confinement.** Same shared Secret Service, and `~/snap` is
  documented as user-accessible from outside the snap. The
  [AppArmor kernel documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html)
  is explicit that unprofiled tasks "run in an unconfined state which is
  equivalent to standard Linux DAC permissions" — AppArmor confines the snap,
  not the snap's attacker.
- **TPM 2.0 sealing without a PIN.** systemd's guarantee is machine-binding —
  sealed credentials "can only be decrypted again by the local machine." Access
  to `/dev/tpmrm0` is an ordinary file permission (`0660`, group `tss`), so the
  enrollment that lets the wallet use the TPM grants every same-UID process the
  same channel. PCR policies are global system state any local process can
  satisfy. Only an authValue/PIN helps, which is the password criterion 1
  forbids.
- **Kernel keyrings.** Permissions are possessor/user/group/other; there is no
  per-binary subject, and the user keyring is shared by all processes with that
  UID. A possessor-only session key is real isolation but dies with the session,
  and whatever re-provisions it is reachable by the attacker.
- **fscrypt** — documented as not hiding plaintext from other users on the same
  system once the key is added. **Landlock** — definitionally self-restriction.
  **AppArmor shipped in our own `.deb`** — cannot confine unprofiled peers.
- **Any daemon that authenticates by checking `/proc/PID/exe`.** systemd
  documents `sd_bus_creds_get_exe()` as a property that "should not be used for
  more than explanatory information, in particular it should not be used for
  security-relevant decisions, because the executable might have been replaced
  or removed by the time the value can be processed"
  ([sd_bus_creds_get_pid(3)](https://man7.org/linux/man-pages/man3/sd_bus_creds_get_pid.3.html)).
  `SO_PEERPIDFD` (Linux 6.5) fixes PID reuse, not identity. There is no
  precedent of a daemon authenticating a specific same-UID binary without an
  LSM: polkit authenticates the *human*, and `ssh-agent`'s own manual says its
  socket "is accessible only to the current user, but is easily abused by root
  or another instance of the same user"
  ([ssh-agent(1)](https://man7.org/linux/man-pages/man1/ssh-agent.1.html)).

The current Secret Service default collection belongs in this list, which is why
issue #112 is right on the diagnosis.

### 3.3 The recommended design: setgid, `.deb` only

Install the wallet binary root-owned and set-group-ID to a dedicated system
group nobody is a member of, with the protected state root under
`/var/lib/ekubo-wallet` traversable only with that group. This is the design in
issue #112's comment, and it holds.

It works because set-ID execution triggers the loader's secure-execution mode:
`AT_SECURE` is set when the real and effective group IDs differ, and
`LD_PRELOAD`, `LD_LIBRARY_PATH`, and `LD_AUDIT` are stripped
([ld.so(8)](https://man7.org/linux/man-pages/man8/ld.so.8.html)).

It also buys something the threat model did not ask for and currently disclaims.
Set-ID exec resets the dumpable flag to `/proc/sys/fs/suid_dumpable`, which
defaults to 0
([PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)),
and [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html) denies
access to a non-dumpable target without `CAP_SYS_PTRACE`.
So same-UID `ptrace`, `process_vm_readv`, and `/proc/PID/mem` are
**kernel-blocked**, and `execve` ignores the set-ID bits when the process is
already traced, closing the attach-before-exec variant. On Linux the wallet
would stop depending on the threat model's ptrace exclusion.

**GUI viability checks out, with one library to watch.** libdbus is reported to
hard-refuse under set-ID — `_dbus_getenv` returning NULL when `rgid != egid`,
and autolaunch failing — with GTK calling `exit(1)` on the same check. Flagged
as *unverified at primary source*: freedesktop's GitLab and cgit both refused
the research pass's connections, so this needs a look at `_dbus_check_setuid`
in `dbus/dbus-sysdeps.c` before anyone relies on it. Neither is fatal here in
any case: GPUI does not link GTK, and **zbus, which the wallet's `keyring` and
polkit paths use, is unaffected** (plain `env::var` with an
`$XDG_RUNTIME_DIR/bus` fallback).
Wayland and X11/xauth work. Mesa and Vulkan ignore env *overrides* under set-ID
but load system drivers normally. NVIDIA disables its shader disk cache for
set-ID binaries, which costs a per-launch recompile.

### 3.4 The gap the issue comment does not address

The comment says same-UID processes "cannot traverse, copy, replace, or roll
back this state." That is correct. But **any same-UID process can execute the
setgid binary itself**, obtaining a process that legitimately holds the group,
under attacker-controlled argv, file descriptors, cwd, and every environment
variable *not* on the loader's strip list — `HOME`, `XDG_*`, `WAYLAND_SOCKET`
(libwayland reads it as a raw fd number), `SPA_PLUGIN_DIR` (PipeWire loads
plugins from it through plain `getenv`), and the bus address.

That does not hand over the key. It does mean the last line of the boundary is
the wallet's own robustness in a hostile execution context rather than the
kernel — the CVE-2021-4034 (PwnKit) and CVE-2023-4911 (Looney Tunables) class.
A Debian maintainer reached exactly this verdict about setgid games: "this use
of setgid is basically security theatre: it's essentially equivalent to making
the high scores world-writeable", because "this game depends on libraries that
make no attempt to avoid privilege escalation from the caller to the games
group" (Simon McVittie, [Bug#1124332](https://bugs.debian.org/1124332),
30 December 2025; same text in [Bug#1124336](https://bugs.debian.org/1124336)).
That is a per-package argument about the games group rather than Debian policy,
but the reasoning transfers exactly.

The difference between our case and theirs is that we would be writing the
hardening deliberately rather than inheriting it. Required, and release-blocking:

- verify `getresuid`/`getresgid` show the expected effective and saved GID at
  the first instruction, and **fail closed** if not — a `nosuid` mount makes
  set-ID exec fail *silently*;
- derive every protected path from the **real UID only** — never from `HOME`,
  `XDG_*`, argv, cwd, or any caller-supplied path;
- treat `WAYLAND_SOCKET`, `SPA_PLUGIN_DIR`, the bus address, and all inherited
  descriptors as untrusted; close every unrecognized inherited fd;
- set `no_new_privs`, disable core dumps explicitly;
- `setresgid(rgid, rgid, rgid)` irreversibly and close protected descriptors
  before spawning the MCP bridge or any other child.

### 3.5 The stronger variant, and why it is a *combination*

A dedicated **system-UID broker** — a socket-activated systemd service running
as its own user, which holds the key and never releases it, signing in-process —
is strictly stronger for key *confidentiality* than §3.3, because a different
UID owns the key and the guarantee stops depending on the wallet's hostile-env
robustness at all.

The trade is that any same-UID caller can *request* a signature, so the policy
engine becomes the entire authorization boundary. That is why it is best as a
**combination** with §3.3 rather than an alternative: setgid keeps arbitrary
callers away from the request path, and the broker keeps the key away from a
wallet process that was started under a hostile environment.

Note the repo already ships `contrib/polkit/com.ekubo.wallet.policy` with
`auth_self`. That remains the right home for owner-only operations precisely
because polkit authenticates the **human**, never the binary.

An AppArmor profile plus `SO_PEERSEC` is the only LSM path that could work, and
only because a tight executable-mmap allowlist blocks the injected `.so` — not
because the label proves identity. Ubuntu/Debian only, with real ongoing
maintenance cost against Mesa and driver updates. Defense in depth at most.

### 3.6 Two packaging blockers

- **`cargo-packager` cannot ship this.** Its `DebianConfig` has exactly six
  fields — `depends`, `desktop_template`, `section`, `priority`, `files`,
  `package_name` — with no maintainer scripts and no file modes or ownership,
  and its `data.tar` is written with deterministic headers
  ([`crates/packager/src/config/mod.rs` L180-L234](https://github.com/crabnebula-dev/cargo-packager/blob/main/crates/packager/src/config/mod.rs#L180-L234),
  read on `main`; the release workflow pins **cargo-packager 0.11.8**, so
  confirm against that tag before acting on it). A setgid or
  system-service design requires switching the Linux `.deb` to **cargo-deb**
  (which has `maintainer-scripts` and `systemd-units`) or post-processing the
  archive. The correct Debian idiom is `addgroup --system` in `postinst` plus
  **`dpkg-statoverride`**, whose database — not the package payload — carries
  the group and mode, and therefore survives upgrade and rollback.
- **AppImage is definitively out**, on three independent grounds: libfuse's
  `fusermount` applies `MS_NOSUID | MS_NODEV` unconditionally; `execve` ignores
  set-ID bits on a `nosuid` mount; and a user-owned file cannot carry a group
  the user is not in, while unprivileged `chown` clears the set-ID bits anyway.
  See §5.2 for what that costs the update channel.

## 4. Windows

### 4.1 The install directory is the root of trust, and ours is not

Before any storage mechanism matters: `cargo-packager` produces a **per-user
NSIS installer**, so the wallet's own executable sits in a directory the desktop
user can write. A same-user process does not need to attack the key store at
all — it overwrites the wallet binary and *becomes* the wallet on next launch.
Every check the real wallet would perform, the replacement performs too, in the
attacker's favour.

So the first requirement on Windows is a tamper-resistant install location.
There are two:

- a **per-machine NSIS install** into `%ProgramFiles%`, which costs one UAC
  prompt at install time and nothing afterwards; or
- **full MSIX**, which installs into `C:\Program Files\WindowsApps` under
  system-controlled ACLs even for a per-user install.

"Package with external location" is *not* a third option for this purpose:
`uap10:AllowExternalContent` deliberately leaves the files where the installer
put them, unvalidated
([grant identity to non-packaged apps](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/grant-identity-to-nonpackaged-apps)).

### 4.2 The CNG-DACL design does not hold

Issue #112's comment proposes a persisted CNG key whose security descriptor
grants use only to the signed package SID. This does not work, for three
independent reasons:

1. **A DACL discriminates between principals, not processes.** The wallet and
   the attacker present the *same user token*. There is no process-identity or
   image-identity ACE type in Windows access control, so any ACE that excludes
   the attacker excludes the wallet.
   ([key storage property identifiers](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers))
2. **`OWNER RIGHTS` does not rescue it.** S-1-3-4 can strip the owner's implicit
   `READ_CONTROL`/`WRITE_DAC`
   ([special identities](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-special-identities-groups)),
   but that is moot given (1): the two processes are the same principal.
3. **The Software KSP keeps user keys as files.** They live under
   `%APPDATA%\Microsoft\Crypto`, DPAPI-protected to the user
   ([key storage and retrieval](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval)),
   so the attacker bypasses NCrypt entirely.

Backing the key with the Platform Crypto Provider or VBS changes only
*extraction*: the blob becomes non-exportable, but any same-user process can
still `NCryptOpenKey` and use it. For a wallet, a signing oracle is theft.

DPAPI and DPAPI-NG fail for the same reason at a different layer.
`CryptProtectData` is documented as protecting data such that "only a user with
the same logon credential… can decrypt"
([CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata));
its optional entropy must itself be stored somewhere the attacker can read, so
it is obfuscation. DPAPI-NG's protection-descriptor grammar is `SID=`, `SDDL=`,
`LOCAL=`, `WEBCREDENTIALS=`
([NCryptCreateProtectionDescriptor](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptcreateprotectiondescriptor))
— every one of which resolves to a principal. **`SID = user` is the finest
grain Windows offers.**

### 4.3 App isolation is preview, and it fails open

Win32 App Isolation requires Windows 11 24H2 (build 26100) and its documentation
still carries the preview warning
([app isolation overview](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-overview)).
The release notes state that packages "run isolated on supported OSes and **fall
back to FullTrust on non-supported ones**"
([release notes](https://learn.microsoft.com/en-us/windows/win32/secauthz/app-isolation-release-notes)).
A security boundary that silently degrades into no boundary is exactly the
fallback §5.3 forbids, so any adoption requires the wallet to inspect its own
token at startup and refuse to touch protected state if it is not genuinely in
an AppContainer.

Note also which direction AppContainer protects: it sandboxes the system *from*
the app. Microsoft states plainly that apps not in an AppContainer "can access
all the user's lockers, including those of AppContainer apps"
([PasswordVault](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.passwordvault)).

The one asset AppContainer genuinely scopes inward is Hello/NGC keys — and that
is conditional. For a **full-trust** caller, an NGC credential is scoped at the
user-account level; only a real AppContainer app gets `[user SID + package
family name]` scoping, where the PFN cannot be forged because it is bound to
the package signing certificate. And `KeyCredential::RequestSignAsync` is
documented as prompting the user
([RequestSignAsync](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredential.requestsignasync)),
which collides with criteria 2 and 3. `UserConsentVerifier` is weaker still: it
returns an enum and releases no key material
([UserConsentVerifier](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier)),
so it authorizes nothing cryptographically. It is right where it already is —
owner authorization — and wrong as a custody mechanism.

### 4.4 What Windows actually enforces: a different principal

Every mechanism above fails on the same sentence — *the two processes are the
same principal* — so the fix is to stop being the same principal.

**Recommended design.** A per-machine install (§4.1) plus a small broker
service running under its own account (`LocalService` or a virtual service
account). The service owns the wrapping key, held either as a service-account
DPAPI blob or as a TPM-backed CNG **machine** key whose DACL grants use only to
the service SID — which is legitimate here precisely because it is
*cross-principal*, the one distinction Windows access control actually enforces.

The wallet reaches it over a named pipe, and the service authenticates each
client by:

1. pipe DACL restricted to the interactive user's SID, with
   `PIPE_REJECT_REMOTE_CLIENTS`;
2. [`GetNamedPipeClientProcessId`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid);
3. **open and hold** a handle to that process before any further check, which
   is what closes the PID-reuse race;
4. `QueryFullProcessImageNameW` on the held handle, requiring a path under
   `%ProgramFiles%\Ekubo` — admin-writable only, so the image cannot be
   swapped underneath the check;
5. `WinVerifyTrust`, pinned to the Ekubo Trusted Signing subject.

This yields the macOS UX: no password, no prompt, key usable only by the
installed wallet binary. Implementation is moderate and conventional in Rust
(`windows-service`, `windows-sys` for pipes and WinTrust, a narrow request
protocol).

### 4.5 The invariant this breaks, and why it is worth breaking

Issue #112's comment states "no new daemon, signing service, or privileged
broker." On Linux that invariant is satisfiable, because `setgid` lets the
kernel grant *the wallet process itself* an extra group at exec, keyed to the
installed image. **Windows has no equivalent**: there is no way to grant a
process an additional SID because of which executable it is. So Windows can
only change principal (a service account) or change packaging (AppContainer —
preview, fails open, GPUI-under-AppContainer untested).

That is a genuine fork, and it is the maintainer's call (§10). What the research
does settle is that the comment's third option — a CNG key DACL'd to a package
SID, with the wallet staying full-trust and same-principal — is not a boundary
at all.

Note the scope of the broker, if chosen: it holds the **wrapping key** and
performs unwrap for an authenticated client. It is not a second signing
service, `ekubo-wallet-core` stays the only thing that signs, and policy
evaluation does not move out of the wallet process. That keeps the invariant's
*intent* — one place that signs, no privileged code doing wallet logic — while
conceding its letter.

### 4.6 Blocked on signing

Any image-identity check rests on Authenticode, and
`AZURE_TRUSTED_SIGNING_ENABLED` is currently `false`. Until it flips, the
Windows backend cannot ship. Unsigned development builds must take an explicit,
loudly-labelled path that the service refuses, rather than a fallback.


## 5. What this costs the packaging, and what it breaks

An OS-enforced application identity is not a library choice. On both platforms
it is a property of *how the program is installed*, so the fix reaches into
release engineering. These consequences are decisions for the maintainer, not
implementation details to be absorbed quietly.

### 5.1 Windows: the per-user installer is part of the problem

`docs/releasing.md` describes a **per-user NSIS installer**. An installation the
desktop user can overwrite cannot host an identity that same user cannot forge:
whatever check the wallet performs at startup, an attacker who can replace the
installed bytes performs it too, in their own code, on their own terms. Any
design that binds custody to the installed executable therefore requires the
executable to live where the user cannot modify it, which means a per-machine
install and an administrator prompt at install time.

That is a real UX regression against criterion 5 — one elevation prompt at
install, none afterwards — and it is the smallest one available. It must be
decided explicitly.

Windows signing is also currently gated off: `AZURE_TRUSTED_SIGNING_ENABLED` is
`false` while public-trust validation is pending, and the workflow proves the
installer stays Authenticode-unsigned. Any identity scheme that rests on a
trusted publisher signature cannot ship before that gate flips. The plan must
not let an unsigned or unsupported configuration silently degrade into the old
behaviour; it fails closed instead.

### 5.2 Linux: AppImage cannot carry this, and AppImage is the update channel

A portable, user-owned, user-writable AppImage cannot hold an identity that
other processes of the same user lack. That conclusion is not
mechanism-specific; it follows from the file being the user's to rewrite.

The consequence is larger than "prefer the .deb", because AppImage is not just
a convenience format here — it is the Linux *updater* format:

- `release.yml` writes `latest.json` with `"linux-x86_64": {… format:"appimage"}`;
- `crates/ekubo-wallet-core/src/update_trust.rs` implements the Linux
  self-update by swapping the running AppImage, and reports that
  "automatic updates are available for the AppImage distribution";
- the `.deb` is published as a release asset but is not an update target.

So making the `.deb` the protected format means Linux loses in-app automatic
updates unless a new mechanism replaces them, because installing a `.deb`
requires authorization the wallet process must not hold. The realistic options
are (a) no in-app update on Linux, only a notification pointing at the package,
(b) a polkit-authorized install action, or (c) an apt repository. Each is
work that this plan must not pretend is free. A narrow precedent for (b)
already ships: Settings → Owner authentication installs the wallet's own
action definition through `pkexec install` under
`org.freedesktop.policykit.exec`, and the `.deb` places that file directly.
Whatever (b) becomes must keep the same shape — content that comes from the
build itself rather than from a file the user can rewrite between check and
use, and nothing running as root but a coreutils copy.

The AppImage does not have to disappear. It has to stop claiming a custody
guarantee it cannot provide: either it refuses to hold keys at all, or it is
labelled unprotected and the threat model says so in the same words the release
notes already use.

### 5.3 What must not happen

No silent fallback. If the platform cannot establish the identity — wrong OS
build, unsigned package, AppImage, missing group, tampered install path — the
wallet fails closed before it touches protected state or opens agent IPC. It
does not quietly reopen the generic credential store, because a fallback that
triggers automatically is the boundary an attacker arranges for.

## 6. Re-custody: an upgrade the owner never sees

Issue #112 requires that legacy entries not be left behind, and the UX
requirement forbids a migration screen. Both hold at once if the upgrade is an
internal storage re-custody rather than a user-facing migration: same wallet,
same address, same policies, no prompt, no re-import.

Before network access, agent IPC, WalletConnect, or any signing path starts,
the first launch of the new version runs one crash-resumable transaction:

1. establish and verify the new platform boundary; abort if it is not real;
2. take the exclusive wallet-state lock (`wallet.lock` already exists);
3. read each legacy SQLCipher key and private-key entry exactly once;
4. write the private keys as encrypted rows into the new SQLCipher store and
   wrap its new database key with the platform-protected wrapping key;
5. reopen it, run SQLCipher and SQLite integrity checks, re-derive every
   address, and exact-match every wallet ID, address, policy, revision, and
   security-sensitive row against the old store;
6. atomically switch the active-store marker, delete every legacy credential
   entry, write a non-secret tombstone that prevents legacy re-import, and
   zeroize all temporary plaintext.

Crash between any two steps must recover to either the old complete store
(before the marker flips) or the new verified complete store. Never an empty
wallet, and never two stores that both consider themselves authoritative.

A design change worth stating on its own: **the private keys stop being
credential-store entries and become encrypted rows inside SQLCipher.** After
this, the only secret outside the database is the platform-protected wrapping
key. That shrinks the platform-specific surface to exactly one object per OS,
which is what makes two new backends tractable at all.

### 6.1 The honest limit

For a wallet that already exists on Windows or Linux, this is **forward
protection only**. If the old credential was already read, moving the same bytes
behind a new boundary proves nothing about who copied them first. The release
notes must say so, and the only complete remediation for a possibly-compromised
existing wallet is a new key — rotation where the protocol allows revocation,
transfer to a new account otherwise.

This is worth saying plainly because it is the one place where "no migration"
and "strict guarantee" genuinely cannot both be true.

## 7. Acceptance gates

These are release-blocking and must be exercised by a **separately built,
same-user hostile executable** — not an in-process mock, which would test the
wallet's own politeness rather than the OS boundary.

- After upgrade, the legacy Credential Manager and Secret Service entries are
  absent.
- Copying the database and the wrapped blob elsewhere does not decrypt them.
- Windows: the sibling cannot enumerate, open, use, export, take ownership of,
  or rewrite the DACL on the wrapping key; cannot open or read the wallet
  process; and a direct, tampered, wrong-identity, or unsupported-OS launch
  fails before touching state or opening IPC. Deletion is tested separately: if
  the OS permits same-user deletion, that is availability loss, and the wallet
  must fail closed rather than mint a replacement authority.
- Linux: the sibling cannot traverse the protected directory or read the
  protected descriptors, and a copied, tampered, or `nosuid`-mounted launch
  fails before touching state or opening IPC.
- A hostile MCP caller still reaches only `AgentApi` and can obtain only
  signatures the active policy authorizes.
- Update and rollback preserve the identity metadata on both platforms; if they
  do not, the wallet fails closed.
- Crash injection covers every re-custody step in §6.
- UX regression tests: first launch after upgrade asks for nothing, an
  automation fires unattended, and no signing path acquired a new prompt.

`ptrace`, debugger attachment, and process injection stay out of scope per
`docs/threat-model.md`. That exclusion is load-bearing for every design
considered here and should be re-affirmed deliberately rather than inherited.

## 8. How the review actually runs

`/code-review ultra` is user-triggered and billed; it cannot be launched on the
maintainer's behalf, and it reviews a **branch bundle or a PR diff** — not a
whole repository. Running it against a clean `main` would review nothing. The
sequence is therefore:

1. **This document** — the design and its costs, agreed before code exists.
2. **Implementation on a branch**, in the order that keeps `main` shippable:
   the SQLCipher key-row refactor and the re-custody transaction first (both
   platform-independent and testable on macOS), then one platform backend, then
   the other.
3. **The ultra review**, run by the maintainer against that branch:

   ```
   /code-review ultra
   ```

   or, once a PR exists,

   ```
   /code-review ultra <PR#>
   ```

   Add `--post` to publish the finished review to the PR as a single comment.

Because the fix touches the security kernel, packaging, and the release
workflow together, the branch should be reviewed before it lands even though
the repo's normal rule is to land straight on `main`. `AGENTS.md` reserves a
long-lived branch for work "genuinely large or risky enough that landing it
half-finished would break the build for someone else"; this qualifies.

For coverage of the existing code *before* the fix exists — which the diff-scoped
ultra review structurally cannot give — the complement is a V12 repository audit
of `EkuboProtocol/wallet`. It is billable, so estimate first:

```
v12_estimate_cost  → v12_audit_github (repoFullName: EkuboProtocol/wallet)
```

Scope it to `crates/ekubo-wallet-core/src` to keep the cost proportionate.

Alongside either, `docs/security-boundary.md`, `docs/threat-model.md`, and
`docs/storage.md` must change in the same commits as the code they describe;
the repo already treats that as a rule for trust-boundary changes.

## 9. The one sentence both platforms produced

The Windows and Linux investigations were run independently and converged:

> The only application boundary these operating systems actually enforce
> against a same-user attacker is a **change of principal**. Everything that
> keeps the wallet as the same principal and tries to distinguish it by
> identity, signature, image path, package SID, or credential-store namespace
> is defeated by the attacker presenting the same credentials.

Linux can satisfy that in-process, because `setgid` lets the kernel grant the
wallet process an extra group at exec keyed to the installed image. Windows
cannot — there is no way to give a process an additional SID because of which
executable it is — so Windows must either run a component under a different
account or adopt AppContainer packaging that is still preview and fails open.

That asymmetry, not a difference of taste, is why the two platform designs in
this document do not look alike.

## 10. Decisions for the maintainer

These are not implementation details and should be settled before code:

1. **Windows: broker service, AppContainer, or narrowed threat model?**
   Issue #112's comment forbids a broker; the research shows the comment's own
   alternative (CNG key DACL'd to a package SID, wallet full-trust and
   same-principal) is not a boundary. *Recommendation:* accept the broker for
   the wrapping key only (§4.5), keeping signing and policy in
   `ekubo-wallet-core`, which preserves the invariant's intent.
2. **Windows: accept a per-machine install and one UAC prompt at install time?**
   Without it there is no tamper-resistant trust anchor and the rest is moot.
3. **Windows: the backend is blocked on `AZURE_TRUSTED_SIGNING_ENABLED`.**
   Confirm the ordering — signing first, then the custody backend.
4. **Linux: setgid alone, or setgid plus a system-UID broker?**
   *Recommendation:* ship setgid first (it meets all three UX constraints and
   blocks ptrace as a bonus), with the broker as a follow-on, since together
   they cover each other's gap (§3.5).
5. **Linux: approve the `cargo-packager` → `cargo-deb` switch** for the `.deb`,
   with `dpkg-statoverride` carrying the mode across upgrades (§3.6).
6. **Linux: what happens to AppImage and to in-app updates?**
   AppImage cannot hold the boundary. Choose between notify-only updates, a
   polkit-authorized install, or an apt repository (§5.2), and choose whether
   AppImage ships at all or ships explicitly labelled unprotected.
7. **Re-affirm or retire the ptrace exclusion.** On Linux, setgid removes the
   need for it. On Windows, a broker design still relies on it. The threat model
   should say so per-platform rather than globally.
8. **Rotation guidance for existing Windows and Linux wallets.** §6.1 — this is
   forward protection only, and the release notes must say it.
9. **Does macOS change too?** Moving private keys into SQLCipher rows (§6) is
   cross-platform. *Recommendation:* yes, for one custody path everywhere, with
   the keychain holding only the wrapping key.

## 11. What was checked to write this

- Issue #112 and its comment; `docs/threat-model.md`,
  `docs/security-boundary.md`, `docs/storage.md`, `docs/releasing.md`.
- `crates/ekubo-wallet-core/src/custody.rs`, `policy_store.rs`,
  `human_presence.rs`, `update_trust.rs`; the `KeyStore` trait's call sites
  across seven non-test files.
- `Cargo.toml` packager metadata, `.github/workflows/build-release-artifacts.yml`,
  `.github/workflows/release.yml`.
- `keyring` 4.1.6 resolves on macOS to `apple-native-keyring-store::keychain`,
  i.e. `SecKeychain::set_generic_password` against the legacy file keychain with
  its default ACL. Worth stating precisely: the macOS boundary is a
  **code-identity-bound consent prompt**, not a hard denial. A Linux or Windows
  design that produces a hard denial therefore exceeds the macOS bar rather than
  merely matching it.
- Primary platform documentation cited inline in §3 and §4.
