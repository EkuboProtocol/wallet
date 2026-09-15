# v2 owner IPC authorization classification

UID/SID admission identifies an **untrusted process in the owner's account**.
It does not identify the UI or establish a human decision. All payloads remain
untrusted after admission. Review identities bind state, not human presence.
This inventory covers the typed owner protocol including the current paged-read
additions. Newly added RPCs need an explicit classification here and core
enforcement before they can expose protected mutations.

## Protected human decisions

| RPC | Enforcement / exact state |
| --- | --- |
| `BeginPrivateKeyExport` | Core export presence, matching account, bounded reveal lease. |
| `RemoveAccount` | Core presence and lifecycle-locked matching account after authentication. |
| `ReviewTransaction`, `DecideTransactionReview` | Review initiation/choice alone cannot sign. The signing orchestrator must authenticate the exact reviewed envelope and preserve cancellation. Reject/close choices reduce authority. |
| `SignMessage`, `SignTypedData` | Core native authentication, exact reviewed digest, pending-state revalidation. |
| `ApproveDappReview` | Core mints single-use review/account-bound dapp authorization. |
| `InstallPolicy`, `ApplyPolicyProposal` | Core-authenticated widening; only core-proven tightening is an unprompted exception. Exact active revision is re-read. |
| `ResetNetworksToDefaults`, `AcceptNetworkProposal`, `AddNetwork`, `ReplaceNetwork` | Core network authorization and protected-state revalidation. |
| `SetNetworkDisabled` | Enabling requires core authorization. Disabling only an exact reviewed profile is the reduction exception. |
| `AddToken`, `AcceptTokenProposals` | Core authorization before trusting names/decimals; revalidate reviewed proposals. |
| `SetDetailedNotificationPreviews` | Core notification-privacy authorization. |
| `AcceptLegal` | Core validates an acceptable document and its current public digest, authenticates for the specific document class, then rechecks at persistence. Knowing the digest cannot grant acceptance. |
| `ClearActivityHistory` | Core authenticates before opening stores for deletion; terminal-only deletion preserves unsigned/signed/live lifecycle state as defined by each store. Existing three-store deletion is sequential, not an all-stores atomic transaction. |
| `DeleteAutomation` | Core authenticates deletion of evidence, then SQL exact-ID/stopped-state check. The operation also deletes run history, so it is not merely a fail-safe stop. |

The last three operations now terminate in narrow async functions in
`human_presence`. Their raw store mutators are crate-private in production.
Legacy public fixture methods exist only in `cfg(test)` / `test-hooks` builds.
Release binaries must exclude `test-hooks`. No public approval-token constructor
or serialized proof exists in the production protocol.

## Exact fail-safe reductions and refusal paths (unprompted)

| RPC | Why no fresh authorization |
| --- | --- |
| `RemoveToken` | Exact reviewed trusted-token row removal; does not add/replace names. |
| `RejectNetworkProposal`, `RejectTokenProposals`, `RejectPolicyProposal` | Discard pending suggestions, cannot accept them. |
| `RejectMessage`, `RejectTypedData`, `DiscardUnsentTransaction` | Refuse/discard still-unsent work; core refuses signed/broadcast lifecycle states. |
| `AttemptTransactionCancellation` | Core derives a same-nonce self-send from the stored signed envelope and reconciles; no new destination/amount chosen by the caller. |
| `DisableAutomation` | Stops the exact automation without expanding policy or deleting its run history. |
| `DisconnectDappSession`, `RejectDappReview`, `CloseDappReview` | Close a session or refuse its proposal; never authorize a connection. |

An owner-SID/UID peer can request these reductions. UI exclusivity is not a
security property. The documented policy-tightening / network-disabling
exceptions in the previous table also remain unprompted.

## Intended unprompted actions / untrusted informational writes

| RPC | Constraint |
| --- | --- |
| `CreateAccount` | Fresh account only, fixed require-approval-for-everything initial policy in dispatcher. No caller-selected initial authority. |
| `ImportAccount` | Caller supplies the key; core performs explicit import and collision checks. This neither proves provenance nor trusts caller-selected signing permissions. |
| `RebroadcastTransaction` | Exact already-signed bytes after reconciliation; never re-sign or replace. |
| `RelinkAutomation` | Rebinds stored code to the current policy; every emitted batch remains policy-gated. Agent replace-by-key installation already permits that unprompted authority. No new signing permission. |
| `DryRunAutomation` | Simulation only, cannot sign or install permissions. |
| `ImportTokenListForReview` | Fetch/propose only; received labels are untrusted until authenticated acceptance. |
| `BeginDappSession` | Pairing/network setup only; approving a proposal remains separately protected. Requires accepted legal state and desktop lifetime. |
| `SetAppearancePreference`, `SetGuidedSetup`, `SetTestnetMode` | Presentation/checklist state, not network enablement or a signing grant. Same-user peers can change these settings. |
| `SetCompanionServers` | Fixed credential-free companion selection; no wallet signing authority or caller-supplied endpoint. |
| `SetNativeTokenPrice`, `SetTokenPrice` | Explicitly approximate portfolio-ordering/dust hints only. Must not become trusted signing value/amount bounds. |
| `SaveAdvisorySummary` | Untrusted advisory text tied to exact preview evidence; must not be treated as verified signing facts or UI identity. |

## Untrusted reads / observational state refresh

The following may be called by any admitted same-user peer. Data returned to
them is not private from sibling processes. Refreshes may reconcile chain
receipts; caches, watches and read leases do not confer mutation authority.

`Portfolio`, `AccountRemovalDocument`, `TransactionReviewFrame`,
`TransactionInspection`, `RefreshTransaction`, `Transactions`, `Activity`,
`ActivityIndex`, `ActivityRecords`, `ActivityRecord`, `ActivitySources`,
`Transaction`, `Message`, `TypedData`, `Reviews`, `ReviewRecord`, `ReadPage`,
`MessageReviewDocument`, `TypedDataReviewDocument`, `TransactionHeadlines`,
`TransactionPreviewInputs`, `TransactionPreviewPage`, `SavedTransactionSummaries`,
`WaitForEvents`, `Automations`, `AutomationRuns`, `Tokens`, `NativeTokenPrices`,
`TokenProposals`, `DappSessions`, `WaitDappSession`, `DappReviews`, `Snapshot`,
`Accounts`, `Account`, `Policy`, `PolicyHistory`, `Networks`, `NetworkByChainId`,
`NetworkProposals`, `PolicyProposals`, `DetailedNotificationPreviews`,
`AppearancePreference`, `CompanionServers`, `GuidedSetup`, `TestnetMode`,
`LegalStatus`, `LegalDocument`.

## Native enforcement / remaining acceptance gates

- Linux: pinned live system-bus sender, expected profile UID, task-local context,
  fresh `com.ekubo.wallet.v2.human-presence` polkit call, two-minute native
  deadline, unique cancellation ID, best-effort cancellation on future drop,
  post-authentication caller check. Polkit owner annotation is the distinct
  service user `ekubo-wallet-v2`; active owner requires `auth_self`, never a
  retained or administrator authentication. Root-owned policy/rules are trusted.
- Windows: **blocked, fail-closed**; see `windows-owner-auth-feasibility-v2.md`.
  No service or desktop Hello boolean is accepted, even before custody activation.
- Actual packaged cross-identity polkit/PAM and Windows interactive acceptance
  remain required. Private-bus doubles and test-hook success are not that evidence.

## Legacy move and desktop session

| RPC | Enforcement / exact state |
| --- | --- |
| `LegacyMove` (`AuthorizeSource`, `Import`, `Verify`, `Complete`, `CompleteWithoutSource`) | Core native owner authorization per phase inside the authenticated owner call; phase-specific receipts bound to the exact source selection, destination profile, and fresh nonce. `Verify`/`Complete` re-check destination state and every destination key under the lifecycle lock before source cleanup or receipt completion. `CompleteWithoutSource` additionally refuses while the bound source database is present and re-verifies destination custody. Presentation-supplied successful receipts are never accepted; transport validation rejects nonce/phase/binding mismatches. |
| `HoldDesktopSession` / `DesktopSessionReady` | Admission plus a pinned live system-bus sender; the service holds the desktop session only while that sender stays on the bus. Emitting readiness grants no custody or mutation authority; every protected operation still requires its own core authorization. |

| RPC | Constraint |
| --- | --- |
| `LegacyMoveStatus` | Untrusted read: pending-receipt digest and bound source metadata only, no secrets or authorization. Same-user peers may observe it; execution stays blocked while cleanup is pending regardless of what any peer claims. |
