# Audit map

What to read to verify this wallet's security claims, and where each claim
is enforced. Line numbers are deliberately absent — anchors are module and
function names, which `grep` finds after any refactor.

## Scope

The audit scope is **`crates/ekubo-wallet-core`** plus one binary-crate file,
**`src/approve_tui.rs`** (the terminal approval presenter: the reject-default
picker between the review document and the human's decision, in both its
inline rendering and the full-screen review every signing request —
transaction, typed data, message — is read in, where Approve is additionally
refused until the end of the document has been on screen).

Everything else in the binary crate is presentation and adaptation — CLI
argument handling, the MCP tool surface and its DTOs, TUI browsers, tables,
paging — and can change without moving what the wallet is able to sign.
`tests/boundary.rs` trips when that claim erodes: `src/mcp.rs` may never
reference an approval surface, `InteractiveProof::from_terminal` has exactly
one production call site, and the core crate's manifest may not name a
presentation or MCP dependency.

## The two signing paths

Both transaction-signing paths live in `core/src/orchestrator.rs`, each
owning its guard ladder once:

- `orchestrator::execute_automatic` — the automatic path. Admission via
  `orchestrator::validate_send` (plan shape, sender, chain, digest binding,
  no fork results), then policy and simulation verdicts, in-flight
  settlement, signing with `SigningOverrides::none()`, post-sign
  configuration re-reads, and the durable record.
- `orchestrator::approve_transaction` — the human-gated path. Row
  invariants, policy binding at the queued revision, in-flight settlement,
  fresh simulation and preparation, the server-authored review document
  (`orchestrator::transaction_approval_request`), the presenter decision,
  OS owner authentication, the post-authentication re-read ladder, then
  synchronous signing with no further RPC.

The only signing path outside the orchestrator is owner-requested
cancellation (`reconcile::attempt_cancellation` →
`execution::sign_cancellation`): no policy, no approval, compensated by a
fixed envelope shape derived entirely from the stored record and the chain.
`execution::broadcast_signed_cancellation` re-checks that shape at
broadcast.

## Capability boundaries

- `approval::InteractiveProof` — the interactive-terminal capability. Not
  cloneable; `from_terminal()` requires stdin, stdout, and stderr to all be
  terminals; one production call site (the CLI review command).
- `execution::SigningOverrides` — private fields; `none()` or
  `human(&InteractiveProof)`. Signing past a policy denial or failed
  simulation is impossible without the proof.
- `approval::ReviewPresenter` — the UI seam. The orchestrator authors the
  complete review document; a presenter only renders it and returns a
  decision, and never receives key material or store handles. The terminal
  implementation is `src/approve_tui.rs`; a future approval surface is
  another adapter with no core changes.
- `custody::load_matching_signer` — the one place a private key becomes a
  signer, refusing a credential-store entry whose derived address does not
  match the wallet metadata.

## Invariant index

| Claim | Enforced in |
|---|---|
| Fetched plan bytes match the caller-supplied keccak256 digest | `plan_fetch::verify_digest`, sole caller `plan_fetch::fetch_verified_bytes` |
| Fetch admission: https, default port, public pinned addresses, no redirects, 16 MiB cap, no body echo | `plan_fetch::fetch_remote`, `plan_fetch::is_public_ip` |
| Plan shape and size bounds | `core::execution_plan::ExecutionPlan::{parse, validate}` and its `MAX_*` constants |
| Policy evaluation is the sole automatic gate | `core::policy::evaluate_policy`, verdict via `core::policy::policy_allows`; the denial/failure distinction via `core::policy::policy_denies` and `SIMULATION_FAILED_CODE` |
| No policy predicate reads a simulation: every rule is decided from the plan's own bytes | `core::policy::evaluate_policy` takes only the plan and the policy; pinned by `tests/boundary.rs::no_policy_predicate_can_consult_a_simulation` |
| Simulation response is linked to the pinned parent | `fork::validate_replay` (used by both real-state and fork simulation) |
| Gas never comes from an agent or plan | `execution::signing_gas_limit` |
| Post-signature envelope validation (signer, chain, fields, EIP-7702 authority) | `execution::validate_signed_execution`, called from `execution::sign_prepared_execution` |
| Exact bytes and hash persist before first submission; retries rebroadcast only stored bytes | `pending::record_automatic_signed`, `pending::store_signed`, `reconcile::submit_claimed`, `execution::send_exact_bytes` |
| Policy-revision re-binding is layered | `orchestrator` ladders, `pending::store_signed` (SQL transaction), `pending::claim_for_submission`, and the `policy_store` schema CHECK |
| One in-flight transaction per wallet and chain | `pending_transactions_wallet_chain_in_flight` unique index in `policy_store::create_current_schema` |
| Recorded simulations authorize at most one send | `simulation_store::SimulationStore::take` (consume-on-use), revision re-checks in the MCP send path |
| Fork results never authorize anything | `orchestrator::validate_send`, `fork` module docs |
| Typed-data and message requests have no automatic path | `signature_requests::SignatureQueue` (the shared awaiting → rejected/signed state machine), stores in `typed_data` and `message` |
| Signing hash re-derived from stored payload on every read | `typed_data::TypedDataStore::read`, `message::MessageStore::read` |
| Terminal text safety (control chars and bidi overrides) | `sanitize` (the one disallowed-set), re-exported through `render` |
| Descriptor interpretation is display-only and bounded | `clear_signing` (vendored full ERC-7730 registry embedded by `build.rs`; the pinned `clear-signing` crate renders; every output line passes `sanitize` with length and count caps; nothing in the signing path reads a descriptor) |
| Encrypted store configuration and fail-closed startup | `policy_store::PolicyStore::open`, `policy_store::verify_integrity`, `policy_store::load_or_create_database_key` |
| Schema changes underneath a live server refuse requests | `policy_store::PolicyStore::assert_schema_current`, called from the MCP `tool_gate` |
| Legal acceptance gates every tool | MCP `tool_gate` (binary crate) over `legal::require_status_allows_use` (core) |
| Owner authentication call sites | `human_presence::PresenceRequest` variants; platform backends in `human_presence` |
| Key custody: creation, load, export, removal | `custody` (Zeroize, no overwrite, export timestamp before key return) |

## Residual risks the docs accept

Unchanged by the refactor and documented in `threat-model.md`: no
anti-rollback anchor for the encrypted database, a coherently dishonest RPC,
same-user code execution, and external use of the same key invalidating a
chosen nonce.
