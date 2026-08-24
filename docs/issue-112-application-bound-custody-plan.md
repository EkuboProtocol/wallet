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

<!-- SLOT: Linux mechanism, §3 -->
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

That is a genuine fork, and it is the maintainer's call (§9). What the research
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
work that this plan must not pretend is free.

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

<!-- SLOT: open decisions, §9 -->
