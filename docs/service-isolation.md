# Service-isolated Wallet 2

Status: implementation branch, **not release-ready**. Windows native owner authentication and packaged end-to-end acceptance remain blockers. See [Windows authorization feasibility](windows-owner-auth-feasibility-v2.md). The released 1.x application retains its documented credential-store limitation.

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

Fresh setup, upgrade and uninstall do not read or delete 1.x credentials or authoritative state. An explicit owner-directed move is the only exception.

## Fresh enrollment

The desktop setup window invokes the installed `ekubo-wallet-v2-enroll` coordinator. The ordinary owner remains available through an authenticated relay endpoint while the OS elevates the fixed installer.

The installer establishes protected code, owner binding, native service activation and a new unused profile. The setup-only service generates its wrapping/data/database keys internally, initializes the compiled schema with zero accounts, and publishes records without replacement. No source key or source database is accepted by enrollment.

Only opaque ciphertext reaches the login owner's relay entry. The installer verifies the owner-bound receipt before publishing active metadata. Successful normal custody unlock and authority startup record setup completion. An installed authority with a missing credential is an error, never a request to generate a replacement key.

Explicit resume/discard actions distinguish relay-confirmed publication from unused, unpublished setup. Recovery does not infer provenance for arbitrary abandoned paths. Native installation instructions and limitations are in [contrib/linux-service/README.md](../contrib/linux-service/README.md).

Initial Linux packaging is DEB; Windows packaging is machine-wide NSIS. Service upgrades use signed privileged installers rather than the old portable in-app replacement path. MacOS uses its existing app/DMG delivery. The actual package builders are `contrib/build-v2-packages.py` and `contrib/windows-v2.nsi`.

## Optional first-run move from 1.x

This is an explicit Linux owner flow after fresh v2 enrollment, not automatic installer migration. Windows move is disabled until its native authorization and transport are validated.

1. Before starting an execution lease or changing v2 onboarding state, offer the move for a fresh destination or an existing pending cleanup.
2. The owner selects the source and explicitly identifies all other custom 1.x profiles to preserve. Unknown inventories are refused.
3. Core authorizes the read, takes the old application/lifecycle locks and opens the source read-only. 1.x must be closed, transactions quiescent and automations disabled. Unsupported schemas and oversized state are refused rather than partially copied.
4. The UI presents exact paths, addresses, instance IDs, table inventory and credentials that must remain shared. A separate explicit confirmation precedes the move.
5. Core imports supported schema data and account material through the authenticated service, preserving identities, policies, revisions, stored history, pending records and settings. It rejects a configured destination. The service reopens/verifies durable state and all keys before source cleanup is possible.
6. After renewed owner authorization, delete only exact verified unshared account-credential entries and confirm their absence. A durable source-bound pending/complete state controls explicit recovery; a pending cleanup prevents execution leases. It cannot silently adopt a different source or overwrite changed destination state.

**Cleanup limitations:** the shared 1.x database credential and old database are retained. Account credentials needed by preserved profiles are retained as disclosed. Therefore this flow does not provide confidentiality for the retained old database or isolate a key whose legacy copy remains. Keyring APIs do not provide atomic compare-and-delete against noncooperating same-user software. No move can revoke a key copied before the transition. Do not describe this as complete removal of all legacy credentials or as securing previously compromised accounts.

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
