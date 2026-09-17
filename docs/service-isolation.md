# Service-isolated Wallet 2

Status: native authorization and installed acceptance harnesses are implemented. Platform execution and actual PIN/biometric release acceptance must be distinguished from source checks. See [Windows native authorization](windows-owner-auth-feasibility-v2.md) and [Linux installed acceptance](native-linux-acceptance.md). The released 1.x application retains its documented credential-store limitation.

## Product boundary

Linux and Windows v2 require an installed service under a distinct OS identity. The service owns SQLCipher, custody, policy evaluation and signing. The desktop and stdio bridge are clients. A missing or damaged installed service never falls back to desktop-user custody. macOS retains its existing platform custody model with a separate v2 identity.

The threat includes an ordinary hostile process running as the desktop user. Matching an IPC caller's UID/SID is admission, not proof that it is the wallet UI. Core must authorize protected owner operations. The owner-RPC classification is documented in [owner-rpc-authorization-v2.md](owner-rpc-authorization-v2.md).

## 1.x coexistence

- Application/package: `Ekubo Wallet 2`, `org.ekubo.wallet.v2`, `ekubo-wallet-v2`.
- Login data: product-scoped `wallet-v2` / `ekubo-wallet-v2` roots and `EKUBO_WALLET_V2_HOME`.
- Linux service: `ekubo-wallet-v2` account, `/etc/ekubo-wallet-v2`, `/var/lib/ekubo-wallet-v2`, `/run/ekubo-wallet-v2`, and `org.ekubo.Wallet2` IPC.
- Windows service: `EkuboWalletV2` machine configuration/storage and product-scoped SCM registrations.
- Agent helper and entry: `ekubo-wallet-v2-mcp-bridge` in the separate helpers directory; the local `ekubo_wallet` key, taken over from 1.x with the sync preview showing the change.
- Hosted companion entries: `ekubo` and `ekubo_<protocol>`, the same stable keys 1.x writes. Their URLs are unchanged. V2 writes are byte-identical to 1.x writes, so sync preserves 1.x entries; v2 deselect/removal takes the shared entry out, and the common external-file lock protocol is retained.
- V2 publication uses a separate signed `v2-channel/latest-v2.json` and never becomes the repository's latest release. Old 1.x binaries follow `releases/latest/download/latest.json` without a major restriction; preserve that channel for them.
- The 1.x line is at 1.8.4 and is preserved on the `release-1.x` branch,
but that branch's two workflows still require builds from `main` (its
verifier pins `head_branch` to `main` and compares against `main`), so they
need a rewrite before a 1.x hotfix can ship. The **Sign and publish release** workflow is v2-only: its tag gate accepts only `v2.*` tags, and it never writes `latest.json` or mutates the 1.x latest release.

Fresh setup, upgrade and uninstall never read 1.x state. V2 is standalone: users migrate manually on-chain. There is no automated 1.x import.

## Fresh enrollment

The desktop setup window invokes the installed `ekubo-wallet-v2-enroll` coordinator. The ordinary owner remains available through an authenticated relay endpoint while the OS elevates the fixed installer.

The installer establishes protected code, owner binding, native service activation and a new unused profile. The setup-only service generates its wrapping/data/database keys internally, initializes the compiled schema with zero accounts, and publishes records without replacement. No source key or source database is accepted by enrollment.

Only opaque ciphertext reaches the login owner's relay entry. The installer verifies the owner-bound receipt before publishing active metadata. Successful normal custody unlock and authority startup record setup completion. An installed authority with a missing credential is an error, never a request to generate a replacement key.

Explicit resume/discard actions distinguish relay-confirmed publication from unused, unpublished setup. Recovery does not infer provenance for arbitrary abandoned paths. Native installation instructions and limitations are in [contrib/linux-service/README.md](../contrib/linux-service/README.md).

Initial Linux packaging is DEB; Windows packaging is machine-wide NSIS. Service upgrades use signed privileged installers rather than the old portable in-app replacement path. MacOS uses its existing app/DMG delivery. The actual package builders are `contrib/build-v2-packages.py` and `contrib/windows-v2.nsi`.

## Windows native owner authorization

The per-profile SYSTEM broker accepts only the installed custody service SID. The custody service scopes authorization to kernel-authenticated owner session/logon identity, the exact request digest, and a retained live connection. The broker launches only the installed collector, under the actual interactive owner's token with SYSTEM-owned process/thread security, a restricted token default ACL, high integrity, startup mitigations, a clean environment, and a kill-on-close job. The complete machine image path is pinned and validated through native handles before launch.

Only this protected collector calls `IUserConsentVerifierInterop` from the fixed System32 implementation. The broker consumes its retained process object's result once; arbitrary desktop processes, supplied PIDs, software keys, or approval booleans have no authority. Expiry, disconnect, changed logon identity and cancellation refuse authorization. This requires Windows 11's HWND interop API and Windows Hello configuration. CI's SYSTEM fixture exercises isolation without inventing or automatically approving a biometric gesture.

The old cross-identity migration transfer, snapshot staging, installer commit/cutover and recovery framework has been removed.

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
- Interrupted fresh setup recovery.
- A separate hostile same-user executable probing protected state and owner IPC.
- Populated-profile signed upgrades and repair; simultaneous released 1.x/v2 use with both agent helpers.
- Old 1.x update discovery never selecting v2; macOS regression checks.

The implementation includes native package smoke jobs. Their existence is not evidence they passed. Source-only and unit-test results must be reported separately from installed-product acceptance.

## Development loop

Use one `service-isolation` branch and its dedicated worktree. The former checkpoint branches were all ancestors of the retained tip and have been removed after a verified bundle backup. Historical implementation detail remains in Git.

Coordinate subagents by file ownership. Collect compiler diagnostics together, run relevant tests once after integration, and rerun only failed or behaviorally affected tests. Retain a full final platform/workspace gate. PR source checks are inexpensive; native matrices are explicit milestone dispatches on the same branch, not new checkpoint refs.
