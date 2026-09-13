# Windows v2 native owner authentication

## Implemented workflow (2026-09-13)

`windows_service_presence` now scopes core authentication to the last-read owner
pipe token, its session/logon LUID, the exact request digest and a retained live
connection. `--authenticate-owner-sid` runs a separate, per-profile SYSTEM SCM
broker. Its private pipe admits only the installed wallet service SID and SYSTEM;
each request must additionally authenticate as that wallet service SID.

The broker launches the fixed installed `ekubo-wallet-v2-owner-auth.exe` with
`WTSQueryUserToken` / `CreateProcessAsUserW`. It checks the actual owner SID and
logon generation before creation and after completion. Process and primary-thread
objects are SYSTEM-owned; the cloned token's default ACL protects subsequent
threads and suppresses implicit owner `WRITE_DAC`. The helper runs at high
integrity with startup image/extension-point/dynamic-code mitigations, a clean
system-derived environment, and no inherited handles. Only the fixed System32
consent DLL supplies `IUserConsentVerifierInterop` for the helper's own HWND.

The retained process object supplies a one-use, nonzero success exit code. There
is no desktop approval enum, caller-selected executable, enrolled software key,
or process-ID-only result lookup. Timeout, cancellation, disconnect and invalid
bindings fail closed; dropping the process lease terminates an outstanding
helper. Core rechecks the owner connection before granting authorization and
before consuming protected-setting authorization, which also retains the exact
initiating-call binding. A private kill-on-close job ends the collector if its
broker crashes.

Installer, recovery, upgrade, NSIS, and trusted-signing inputs include the helper
and broker registration. Native negative fixtures cover process/thread access,
wrong owner/logon generation, default ACL owner rights, expiry, cancellation,
pipe closure and malformed/replayed receipts. The SYSTEM fixture is explicitly
limited to disposable Windows CI and never resumes its child or invokes Hello.

Validation in this worker: the helper crate passes Windows GNU-target Clippy for
all targets with warnings denied. A read-only probe on the Windows build host
successfully loaded the fixed System32 DLL and queried its HWND interop interface.
That probe invoked no consent method. Full service integration, the SYSTEM CI
fixture and installed human-interaction acceptance are separate gates; no actual
PIN/biometric success or signed package installation is claimed here.

Native contracts checked against Microsoft documentation:
[CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw),
[CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread),
[GetCurrentProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess),
and [RequestVerificationForWindowAsync](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync)
(Windows build 22000 or later).

## Historical pre-implementation investigation (superseded)

2026-09-12 implementation result: **no safe end-to-end Windows owner proof has
been established in this architecture**. `human_presence::windows_owner_auth`
fails closed for every operation. It also refuses before custody activation so
an omitted service bootstrap cannot select local/session-0 Hello as a fallback.
This is a release blocker, not an implementation of Windows authentication.

## First-party API findings

- [Windows Hello guide](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello):
  `KeyCredential.RequestSignAsync` prompts for PIN/biometrics and signs a server
  challenge. The service must already trust an enrolled public key. The guide
  describes ASN.1 publicKeyInfo, RSA/SHA-256/PKCS#1 verification, optional TPM
  attestation and software-backed keys without TPM. It explicitly requires
  registration to establish the application's required identity assurance.
- [CredUIPromptForWindowsCredentialsW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduipromptforwindowscredentialsw):
  creates an interactive credential dialog and returns a credential blob, not a
  service-verifiable consent decision. `CREDUIWIN_SECURE_PROMPT` selects secure
  desktop and cannot be combined with `CREDUIWIN_GENERIC`; the latter returns
  plaintext username/password. Hello can be packed into a smart-card auth buffer,
  but this does not define the wallet's trusted enrollment/operation protocol.
- [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw):
  validates plaintext credentials and returns a token. A future password design
  must validate the resulting token's SID against the protected profile owner,
  not a supplied username or the elevated administrator. `NEW_CREDENTIALS`
  clones local identity for outbound credentials and cannot be used as proof of
  a freshly validated password. A password is reusable; wrapping it in a nonce
  does not prove a fresh gesture or prevent a peer retaining it for new nonces.
- Prior checked native interop evidence is recorded in
  `~/Documents/wallet-windows-presence-notes.md` and
  `~/Documents/wallet-windows-owner-presence-f5ea0f8.md`. Consent enums and HWND
  attachment solve local UI integration, not remote proof verification.

## Exact missing architecture

1. **Trusted enrollment and replacement.** The installed owner SID is an account
   pin, not a public-key pin. There is no protected enrolled authentication key,
   authenticated enrollment protocol, or safe reset/replacement protocol. Taking
   a key from the first same-SID pipe caller would let hostile software enroll
   its own software signing key. A separate administrator's UAC consent must
   not enroll that administrator as the wallet owner. TPM residency alone is
   not established evidence of the intended owner's per-operation consent.
2. **Interactive collector / proof producer.** The session-0 service cannot ask
   its own Hello identity. The current untrusted desktop has no authenticated
   proof producer established by this package. A password flow is allowed by the
   invariant, but needs an explicitly designed input/secret-lifetime boundary,
   owner-SID verification, rate limits/lockout handling, passwordless-account
   behavior and cancellation. Passing reusable secrets through ordinary JSON
   owner RPC or trusting an SSPI handshake using default logon credentials is
   not a substitute. No new password endpoint was exposed.
3. **Challenge exchange and lifecycle.** Current Call RPCs are request/reply,
   not a core-controlled authentication dialogue. A replacement must retain an
   unforgeable service-side operation reservation and bind proof to the service
   instance, protected profile, pinned owner, initiating connection generation,
   canonical exact operation/review digest, fresh nonce and monotonic deadline.
   Submission must atomically consume a challenge once, including invalid
   attempts. Disconnect, cancellation, restart, changed state or key replacement
   must invalidate it; late proofs cannot resume another request. A generic
   signing broker with synthetic nonce tests does not supply the missing trust.
4. **Native evidence.** This Linux worker has no interactive Windows desktop/
   session-0 installation on which to establish unpackaged NSIS compatibility,
   local versus MSA/Entra accounts, medium-integrity owner operation, other-admin
   elevation, negative direct-provider signing, Hello reset, cancellation,
   timeout and replay behavior. No native success is claimed.

These are concrete integration/trust prerequisites, not a claim that Windows
cannot support the feature. Before enabling a backend, choose and validate a
complete trusted-enrollment Hello/WebAuthn design or an explicit protected
password design, then demonstrate it under the actual installer and service
identity. Keep the refusal until that proof exists. No new cryptography,
attestation roots, secret-bearing RPC or credential enrollment was added.
