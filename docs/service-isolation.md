# Service-isolated Wallet 2

Status: native authorization, explicit credential retirement, and installed acceptance harnesses are implemented. Platform execution and actual PIN/biometric release acceptance must be distinguished from source checks. See [Windows native authorization](windows-owner-auth-feasibility-v2.md) and [Linux installed acceptance](native-linux-acceptance.md). The released 1.x application retains its documented credential-store limitation.

## Product boundary

Linux and Windows v2 require an installed service under a distinct OS identity. The service owns SQLCipher, custody, policy evaluation and signing. The desktop and stdio bridge are clients. A missing or damaged installed service never falls back to desktop-user custody. macOS retains its existing platform custody model with a separate v2 identity.

The threat includes an ordinary hostile process running as the desktop user. Matching an IPC caller's UID/SID is admission, not proof that it is the wallet UI. Core must authorize protected owner operations. The owner-RPC classification is documented in [owner-rpc-authorization-v2.md](owner-rpc-authorization-v2.md).

## 1.x coexistence

- Application/package: `Ekubo Wallet 2`, `org.ekubo.wallet.v2`, `ekubo-wallet-v2`.
- Login data: product-scoped `wallet-v2` / `ekubo-wallet-v2` roots and `EKUBO_WALLET_V2_HOME`.
- Linux service: `ekubo-wallet-v2` account, `/etc/ekubo-wallet-v2`, `/var/lib/ekubo-wallet-v2`, `/run/ekubo-wallet-v2`, and `org.ekubo.Wallet2` IPC.
- Windows service: `EkuboWalletV2` machine configuration/storage and product-scoped SCM registrations.
- Agent helper and entry: `ekubo-wallet-v2-mcp-bridge` in the separate helpers directory; `ekubo_wallet_v2`.
- Hosted companion entries: `ekubo_v2` and `ekubo_v2_<protocol>`. Their URLs are unchanged. V2 sync/removal preserves 1.x entries and retains the common external-file lock protocol.
- V2 publication uses a separate signed `v2-channel/latest-v2.json` and never becomes the repository's latest release. Old 1.x binaries follow `releases/latest/download/latest.json` without a major restriction; preserve that channel for them.
- The 1.x line is at 1.8.4 and is preserved on the `release-1.x` branch,
but that branch's two workflows still require builds from `main` (its
verifier pins `head_branch` to `main` and compares against `main`), so they
need a rewrite before a 1.x hotfix can ship. The **Sign and publish release** workflow is v2-only: its tag gate accepts only `v2.*` tags, and it never writes `latest.json` or mutates the 1.x latest release.

Fresh setup, upgrade and uninstall do not read or delete 1.x credentials or authoritative state. An explicit owner-directed move is the only exception.

## Fresh enrollment

The desktop setup window invokes the installed `ekubo-wallet-v2-enroll` coordinator. The ordinary owner remains available through an authenticated relay endpoint while the OS elevates the fixed installer.

The installer establishes protected code, owner binding, native service activation and a new unused profile. The setup-only service generates its wrapping/data/database keys internally, initializes the compiled schema with zero accounts, and publishes records without replacement. No source key or source database is accepted by enrollment.

Only opaque ciphertext reaches the login owner's relay entry. The installer verifies the owner-bound receipt before publishing active metadata. Successful normal custody unlock and authority startup record setup completion. An installed authority with a missing credential is an error, never a request to generate a replacement key.

Explicit resume/discard actions distinguish relay-confirmed publication from unused, unpublished setup. Recovery does not infer provenance for arbitrary abandoned paths. Native installation instructions and limitations are in [contrib/linux-service/README.md](../contrib/linux-service/README.md).

Initial Linux packaging is DEB; Windows packaging is machine-wide NSIS. Service upgrades use signed privileged installers rather than the old portable in-app replacement path. MacOS uses its existing app/DMG delivery. The actual package builders are `contrib/build-v2-packages.py` and `contrib/windows-v2.nsi`.

## Optional first-run move from 1.x

This is an explicit owner flow after fresh v2 enrollment, not automatic installer migration. The Windows transport uses the shared owner stream protocol and service-side native authorization for source reading, destination verification, and completion.

1. Before starting an execution lease or changing v2 onboarding state, offer the move for a fresh destination or an existing pending cleanup.
2. The owner selects the source and explicitly identifies all other custom 1.x profiles to preserve. Unknown inventories are refused.
3. Core authorizes the read, takes the old application/lifecycle locks and opens the source read-only. 1.x must be closed, transactions quiescent and automations disabled. Unsupported schemas and oversized state are refused rather than partially copied.
4. The UI presents exact paths, addresses, instance IDs, table inventory and credentials that must remain shared. A separate explicit confirmation precedes the move.
5. Core imports supported schema data and account material through the authenticated service, preserving identities, policies, revisions, stored history, pending records and settings. It rejects a configured destination. The service reopens/verifies durable state and all keys before source cleanup is possible.
6. After renewed owner authorization and fresh destination verification, publish an encrypted `wallet.db.retired-v2-backup`, then atomically replace the selected source's `wallet.db` with an intentionally invalid database retirement file. Both old locks stay held. Released 1.x fails to open this nonempty database; it need not understand any new marker format. Do not remove/reset the retirement file. Other profiles are not modified.
7. Delete exact verified unshared account-credential entries and confirm their absence. If no preserved profiles need `org.ekubo.wallet.db/default`, delete that exact database credential and confirm absence too. Otherwise retain it. A changed database credential is a hard stop, never permission to delete a newly created authority.
8. The protected pending receipt binds the source ciphertext hash, old database-key hash, destination profile and preserved inventory. An authenticated `Inspect` request freshly verifies destination state and signing keys and returns only nonsecret account identities. Recovery uses that receipt and the exact retirement file/backup even after the source database key has been deleted. It never regenerates an old key or requires decrypting the retired backup. Completion remains pending until cleanup succeeds; execution stays blocked throughout.

**Do not delete the 1.x profile or its directory until the move reports completion.** A pending move with a deleted source permanently locks v2 out: the normal resume path re-opens the exact 1.x source files. If the source is already gone, the owner-authorized `complete-without-source` recovery inspects the pending receipt, proves the bound source's standard `wallet.db` is absent, retires the bound unshared 1.x credentials with the login-owner authority, and only then re-verifies destination state, decrypts every destination key against the sealed store, and atomically clears the pending receipt. The absence gate fails closed: a still-present source (including a dangling symlink, never dereferenced) refuses recovery and names the live profile, only a missing file is acceptance, and any other I/O outcome refuses without proof. Retirement reuses the exact normal-completion deletion routine from the receipt's wallet list — unshared account credentials re-read, compared, deleted and confirmed absent, shared entries kept, the global database credential retired only when no preserved profiles need it — and the UI reports that `CleanupReport` (deleted, already-absent, shared-retained, database-key-retained) rather than the phase-bound receipt. Because retirement precedes completion, a `Complete` status never claims a shared key was deleted that recovery left behind. Recovery requires the same core owner authorization as the move itself, never marks completion on unverified state, and leaves cleanup pending when any destination key is missing or mismatched. A 1.x source below 1.8.2 is refused by the schema gate without modification; upgrade 1.x first and retry.

**First-run-only contract:** the move imports into an empty, unchanged v2 profile only. Any pre-move v2 write — legal acceptance, settings changes, or a schema bump — permanently refuses the move for that profile, and a source that is not exactly the supported schema version is refused without modification. Both gates fail closed with no overwrite or upgrade path. Recovery is a fresh install or reset of the v2 profile.

**Shared-key cases:** preserved profiles require the global 1.x database key, so the encrypted source backup remains readable while that key is retained. Account credentials shared with those profiles remain accessible to 1.x and must not be described as fully isolated. No silent rekeying of preserved profiles occurs. With no preserved profiles, all reviewed source account entries and the global database entry are retired. Histories are not deleted. Keyring APIs have no atomic compare-and-delete against noncooperating same-user software, and no move revokes a previously copied key.

**Windows integration:** `Request::LegacyMove(ServiceCommand)` dispatches to core inside the authenticated owner-call context. The move peer authenticates the installed pipe, unlocks with the opaque owner relay, pins the service instance, and uses shared stream framing. `AuthorizeSource` binds a fresh nonce and exact source selection to native authorization before credential access; phase-specific receipts prevent interchange with import/verify/complete responses. Receipts are bounded to 1 MiB. No presentation-supplied successful receipt is accepted. Retirement file publication uses Windows write-through rename; Linux fsyncs the containing directory. Older receipts missing retirement identity metadata are refused for keyless resume rather than guessed.

## Windows native owner authorization

The per-profile SYSTEM broker accepts only the installed custody service SID. The custody service scopes authorization to kernel-authenticated owner session/logon identity, the exact request digest, and a retained live connection. The broker launches only the installed collector, under the actual interactive owner's token with SYSTEM-owned process/thread security, a restricted token default ACL, high integrity, startup mitigations, a clean environment, and a kill-on-close job. The complete machine image path is pinned and validated through native handles before launch.

Only this protected collector calls `IUserConsentVerifierInterop` from the fixed System32 implementation. The broker consumes its retained process object's result once; arbitrary desktop processes, supplied PIDs, software keys, or approval booleans have no authority. Expiry, disconnect, changed logon identity and cancellation refuse authorization. This requires Windows 11's HWND interop API and Windows Hello configuration. CI's SYSTEM fixture exercises isolation without inventing or automatically approving a biometric gesture.

The old cross-identity migration transfer, snapshot staging, installer commit/cutover and recovery framework has been removed. The smaller optional move is in `legacy_move*` and is separate from fresh installation.

## Runtime contracts

- One shared owner protocol, dispatcher, policy implementation and service runtime.
- Native authenticated service identity is pinned for each connection; failed mutations are never replayed.
- Desktop execution leases control agent sessions, scheduler and dapps. Quick reopen creates a new execution period and cannot revive old work.
- Root client closure closes independent review connections; per-review cancellation does not close unrelated reviews.
- Review inventories and large records/results use bounded paging with exact identity checks. Fetching a completed result never repeats the mutation. Private-key export is excluded from the page store.
- Service loss invalidates stale views and decisions and presents explicit restart/recovery. It does not reconnect and replay a pending decision.
- Neural transaction summaries remain advisory desktop work, outside protected custody.

## Current validation and remaining acceptance

Do not equate feature-enabled tests with native owner authorization: `test-hooks` deliberately substitutes fixture proofs. Production-feature boundary tests and actual native prompts are separate gates.

Required before release:

- Real Windows protected enrollment and interactive owner authorization, including separate-admin elevation, cancellation and replay rejection.
- Actual Linux/Windows install, fresh enrollment, account creation, native approval, reboot and service reconnection.
- Interrupted fresh setup and explicit move cleanup; exact old-key absence and preservation of shared profiles.
- A separate hostile same-user executable probing protected state and owner IPC.
- Populated-profile signed upgrades and repair; simultaneous released 1.x/v2 use with both agent helpers.
- Old 1.x update discovery never selecting v2; macOS regression checks.

The implementation includes native package smoke jobs. Their existence is not evidence they passed. Source-only and unit-test results must be reported separately from installed-product acceptance.

## Development loop

Use one `service-isolation` branch and its dedicated worktree. The former checkpoint branches were all ancestors of the retained tip and have been removed after a verified bundle backup. Historical implementation detail remains in Git.

Coordinate subagents by file ownership. Collect compiler diagnostics together, run relevant tests once after integration, and rerun only failed or behaviorally affected tests. Retain a full final platform/workspace gate. PR source checks are inexpensive; native matrices are explicit milestone dispatches on the same branch, not new checkpoint refs.
