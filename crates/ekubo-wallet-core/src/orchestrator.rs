//! The one signing orchestration.
//!
//! Every signature this process produces is minted by a function in this
//! module. Transactions take one of two paths: the automatic path, gated by
//! the active policy and a successful simulation, and the human-gated path,
//! gated by a native review plus OS owner authentication. The two payloads
//! no policy can score — an EIP-191 message and an EIP-712 typed-data
//! payload — take [`sign_reviewed_message`] and [`sign_reviewed_typed_data`],
//! which confirm owner presence themselves.
//!
//! Each owns its guard ladder once, so the MCP server and desktop cannot
//! drift apart on what is checked before key material is touched.
//!
//! That "every signature" is enforced rather than merely intended:
//! [`crate::custody::load_matching_signer`] is crate-private, so no caller
//! outside this crate can obtain a signer to sign anything with. Presentation
//! code passes a [`KeyStore`] and a [`HumanPresence`] in and gets a stored
//! decision back; it never holds the key, and it cannot reach a signature
//! without the presence check that precedes one.

use crate::{
    approval::{
        ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalSectionKind, ReviewDocument,
        ReviewPresenter,
    },
    approval_summary::{
        TokenMetadataMap, interpret_steps, plan_token_targets, render_balance_changes, token_label,
    },
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    core::{execution_plan::ExecutionPlan, policy::FindingSeverity},
    custody::{KeyStore, load_matching_signer},
    execution::{
        PreparedExecution, SigningOverrides, prepare_execution, sign_execution,
        sign_prepared_execution,
    },
    human_presence::{HumanPresence, PresenceRequest},
    message::{MessageStatus, MessageStore, PendingMessage},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::{PolicyStore, StoredPolicy},
    simulation::{SimulationResult, simulate_execution},
    typed_data::{PendingTypedData, TypedDataStatus, TypedDataStore},
};
use alloy::{primitives::B256, signers::SignerSync as _};
use anyhow::{Context, Result, bail, ensure};
use num_bigint::BigUint;
use std::{
    str::FromStr,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

/// Bytes per exact-data row. Fixed so the grouping is a property of the
/// calldata rather than of the window's width.
const CALLDATA_BYTES_PER_ROW: usize = 32;

/// The complete calldata a reviewer is shown, as fixed-width rows.
fn calldata_rows(calldata: &[u8]) -> Vec<String> {
    if calldata.is_empty() {
        return Vec::new();
    }
    calldata
        .chunks(CALLDATA_BYTES_PER_ROW)
        .map(hex::encode)
        .collect()
}

/// A native value in the network's currency with the exact wei in reach —
/// "0.05 ETH (50000000000000000 wei)" — or the raw wei alone when the
/// network does not name its currency or the value is not a number.
fn native_value(wei: &str, network: &NetworkConfig) -> String {
    if BigUint::from_str(wei).is_err() {
        return format!("value {wei}");
    }
    match network.native_currency.as_ref() {
        Some(currency) if wei != "0" => format!(
            "{} {} ({wei} wei)",
            crate::approval_summary::format_fixed_point(wei, currency.decimals),
            currency.symbol
        ),
        Some(currency) => format!("0 {}", currency.symbol),
        None => format!("{wei} wei"),
    }
}

/// What the automatic path did with a simulated plan.
pub enum SendDisposition {
    /// The policy allowed and the simulation succeeded: the exact envelope is
    /// signed and durably recorded, ready for submission.
    Signed(PendingTransaction),
    /// The policy denied or the simulation failed: a pending row now awaits
    /// explicit human approval, and nothing was signed.
    Queued(PendingTransaction),
}

fn lock(pending: &Mutex<PendingStore>) -> Result<std::sync::MutexGuard<'_, PendingStore>> {
    pending
        .lock()
        .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))
}

/// Write down that the owner said no, and be honest about it if that fails.
///
/// By the time this runs the reviewer has already been told the request was
/// refused — the presenter drew that in the native review. The row is what decides
/// whether it is true: `store_signed` accepts anything still
/// `AwaitingApproval`, so a rejection that did not commit leaves a request the
/// owner declined available to a later approval flow, which can sign it.
///
/// Two distinct outcomes were previously reported the same way. `reject`
/// commits and *then* re-reads, so a failure in that read means the rejection
/// did land while the caller hears an error. Asking the row settles which
/// happened: already `Rejected` is a success that reported itself badly, and
/// anything else is a rejection that genuinely is not recorded — which the
/// owner has to be told plainly, because what they saw says otherwise.
fn record_rejection(
    pending: &Mutex<PendingStore>,
    request_id: uuid::Uuid,
) -> Result<PendingTransaction> {
    let error = match lock(pending).and_then(|mut store| store.reject(request_id)) {
        Ok(rejected) => return Ok(rejected),
        Err(error) => error,
    };
    if let Ok(current) = lock(pending).and_then(|store| store.get(request_id))
        && current.status == PendingStatus::Rejected
    {
        return Ok(current);
    }
    Err(error).context(format!(
        "the rejection was not recorded, so request {request_id} is still awaiting approval and \
         can still be signed even though it was refused; open that review in the wallet \
         application and reject it again"
    ))
}

/// The admission ladder every send passes before any decision is made on the
/// simulation verdict: plan shape; sender and chain against this wallet and
/// network; the simulation digest binding the result to this exact plan; and
/// that no fork result — a hypothetical — ever authorizes a send.
pub fn validate_send(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
    simulation: &SimulationResult,
) -> Result<()> {
    plan.validate()?;
    ensure!(
        plan.sender == wallet.address,
        "execution plan sender mismatch"
    );
    ensure!(
        plan.chain_id.as_str() == network.chain_id.to_string(),
        "execution plan chain mismatch"
    );
    // The digest binds the result to this exact plan, and a fork result is
    // hypothetical and can never authorize a send. Signing re-checks the
    // digest too; both are cheap and neither should be reachable.
    ensure!(
        simulation.digest == format!("{:#x}", plan.digest()),
        "simulation does not describe this execution plan"
    );
    ensure!(
        simulation.fork.is_none(),
        "a fork simulation is hypothetical and cannot be sent"
    );
    Ok(())
}

/// The automatic path: from a plan simulated exactly once to either a signed,
/// persisted envelope or a queued approval request. No human is consulted and
/// no override exists here — a plan no rule covers, and a failed simulation,
/// both queue. A plan a `deny` rule matched is the one thing that does
/// neither: it fails outright, below.
///
/// After [`validate_send`], in order: policy and simulation verdicts; the
/// wallet+chain in-flight slot settled against the chain; and, after signing,
/// a re-read of wallet and network configuration so a concurrent
/// configuration change cannot slip a signature into the queue. The final SQL
/// write in `record_automatic_signed` repeats the row-level invariants
/// atomically.
pub async fn execute_automatic(
    config: &ConfigStore,
    pending: &Mutex<PendingStore>,
    keys: &dyn KeyStore,
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    stored_policy: &StoredPolicy,
    plan: &ExecutionPlan,
    plan_source: Option<&str>,
    simulation: &SimulationResult,
) -> Result<SendDisposition> {
    validate_send(wallet, network, plan, simulation)?;
    ensure!(
        stored_policy.wallet_instance_id == wallet.instance_id
            && stored_policy.wallet_id == wallet.id
            && stored_policy.wallet_address == wallet.address,
        "the policy used for this decision belongs to a different wallet identity"
    );

    // Rejected outright: nothing signs and nothing queues. Creating a pending
    // row here would offer the user an approval prompt for something their own
    // policy already refused, and the only honest answer at that prompt is
    // "change the policy", which is not a thing an approval screen can do.
    if let crate::core::policy::PolicyOutcome::Rejected =
        crate::core::policy::policy_outcome(&simulation.policy_findings)
    {
        let reasons = crate::core::policy::denial_reasons(&simulation.policy_findings).join("; ");
        anyhow::bail!(
            "the active wallet policy rejects this plan outright, so nothing was queued or \
             signed: {reasons}. Change the policy if this should be permitted."
        );
    }

    if !simulation.allowed || !simulation.simulation.success {
        let request = lock(pending)?.create_for_instance(
            &wallet.id,
            wallet.instance_id,
            &network.name,
            plan,
            plan_source,
            stored_policy.revision,
        )?;
        return Ok(SendDisposition::Queued(request));
    }

    // A predecessor that already mined, cancelled, or was replaced must
    // never block this send: settle the wallet+chain in-flight slot
    // against the chain before signing a new envelope.
    let in_flight =
        lock(pending)?.in_flight_for_address(wallet.address, &network.chain_id.to_string())?;
    if let Some(previous) = in_flight {
        crate::reconcile::reconcile_record(pending, network, previous, true).await?;
    }
    if let Some(blocker) =
        lock(pending)?.in_flight_for_address(wallet.address, &network.chain_id.to_string())?
    {
        bail!(
            "transaction {} still holds this wallet and chain's signing slot while its outcome reaches {} confirmations",
            blocker.request_id,
            network.finality_confirmations
        );
    }

    let signed = sign_execution(
        wallet,
        network,
        plan,
        simulation,
        keys,
        SigningOverrides::none(),
    )
    .await?;
    ensure!(
        config.wallet(&wallet.id)? == *wallet,
        "wallet configuration changed while the transaction was being signed"
    );
    ensure!(
        config.network_by_chain_id(plan.chain_id.as_str())? == *network,
        "network configuration changed while the transaction was being signed"
    );
    let record = lock(pending)?.record_automatic_signed_for_instance(
        &wallet.id,
        wallet.instance_id,
        &network.name,
        plan,
        plan_source,
        stored_policy.revision,
        &signed.serialized_transaction,
        &signed.transaction_hash,
    )?;
    Ok(SendDisposition::Signed(record))
}

/// What the human-gated path decided.
pub enum ApprovalOutcome {
    /// The reviewer rejected: recorded, nothing signed.
    Rejected(PendingTransaction),
    /// Reviewed, authenticated, signed, and stored for submission.
    Signed(PendingTransaction),
}

/// The human-gated path: from a queued pending row to a recorded decision.
///
/// In order: the row's own invariants (approval required, still awaiting,
/// wallet/network/chain/sender unchanged); the active policy at the exact
/// revision the row was queued under; the wallet+chain in-flight slot settled
/// against the chain; a fresh simulation and preparation; the server-authored
/// review document presented through `presenter`; on approval, OS owner
/// authentication through `presence`; then a full re-read of every mutable
/// input — pending row, wallet, network, policy revision and content, and the
/// review digest — before the key is loaded. Signing is synchronous and
/// performs no RPC after authentication, and the final SQL write in
/// `store_signed` repeats the row and policy checks atomically.
///
/// `read_policy` is called once before review and once after authentication,
/// so the decision and the signature bind the same policy. The
#[allow(clippy::too_many_lines)]
pub async fn approve_transaction(
    config: &ConfigStore,
    pending: PendingStore,
    tokens: crate::token_store::TokenStore,
    read_policy: &(dyn Fn() -> Result<StoredPolicy> + Sync),
    request: PendingTransaction,
    presenter: &dyn ReviewPresenter,
    presence: &dyn HumanPresence,
    keys: &dyn KeyStore,
) -> Result<ApprovalOutcome> {
    ensure!(
        request.approval_required,
        "transaction did not require approval"
    );
    ensure!(
        request.status == PendingStatus::AwaitingApproval,
        "pending request is not awaiting approval"
    );
    let wallet = config.wallet(&request.wallet_id)?;
    let network = config.network(&request.network_name)?;
    ensure!(
        network.chain_id.to_string() == request.chain_id,
        "pending request network chain changed"
    );
    ensure!(
        request.wallet_instance_id == wallet.instance_id
            && request.execution_plan.sender == wallet.address,
        "pending request sender no longer matches wallet"
    );
    let stored_policy = read_policy()?;
    ensure!(
        stored_policy.revision == request.policy_revision,
        "active policy changed while approval was pending"
    );

    let pending = Mutex::new(pending);
    // A predecessor that already mined, cancelled, or was replaced must never
    // block storing this approval's signature: settle the wallet+chain
    // in-flight slot against the chain before the human reads anything.
    let in_flight = lock(&pending)?.in_flight_for_address(wallet.address, &request.chain_id)?;
    if let Some(previous) = in_flight {
        crate::reconcile::reconcile_record(&pending, &network, previous, true).await?;
    }
    if let Some(blocker) =
        lock(&pending)?.in_flight_for_address(wallet.address, &request.chain_id)?
    {
        bail!(
            "transaction {} still holds this wallet and chain's signing slot while its outcome reaches {} confirmations",
            blocker.request_id,
            network.finality_confirmations
        );
    }

    let policy_context = crate::core::predicate::PolicyContext {
        wallet: wallet.address,
    };
    let overrides = SigningOverrides::reviewed();
    let review = TransactionReview {
        wallet: &wallet,
        network: &network,
        request: &request,
        stored_policy: &stored_policy,
        policy_context: &policy_context,
        tokens: Mutex::new(tokens),
        overrides,
        generation: AtomicU64::new(0),
        latest: Mutex::new(None),
    };
    // Authoring can fail on a request that is still perfectly rejectable.
    // The rejection write below happens only after the presenter answers,
    // so the row stayed `awaiting_approval` with no way through this command
    // at all, and whatever queued it waited on a decision nobody could give.
    //
    // The row is not the problem and must not be thrown away: an endpoint that
    // is down comes back, and auto-rejecting here would refuse a request the
    // owner may well want. So the error names the request and the one command
    // that resolves it without needing any of this.
    let (approval, simulation) = review.author().await.with_context(|| {
        format!(
            "this request could not be prepared for review, so it is still awaiting a decision; \
             open review {} in the wallet application to reject it if it should not proceed",
            request.request_id
        )
    })?;
    // Rejecting here is a decision, not an abort: it is recorded, so the
    // agent waiting on this request learns the answer.
    let decision = presenter
        .review_transaction(&approval, &simulation, &review)
        .await?;
    // Recorded before anything else can fail. Rejection needs only the request
    // ID — no simulation, no prepared envelope — and reading that state first
    // meant an unrelated error in it returned early and left the request
    // `AwaitingApproval` after the native UI had told the reviewer it was
    // refused. A decision this function calls a decision has to be written
    // like one.
    if decision != ApprovalDecision::Approved {
        return Ok(ApprovalOutcome::Rejected(record_rejection(
            &pending,
            request.request_id,
        )?));
    }
    // Whatever the reviewer last had in front of them, not what was authored
    // first. A refresh replaces the simulation and the prepared envelope
    // together, and signing the earlier pair would sign numbers nobody
    // approved — the whole point of offering the refresh is that the two can
    // differ.
    let Authored {
        simulation,
        prepared,
    } = review.take_authored()?;

    let review_digest = prepared.review_digest();
    presence
        .confirm(&PresenceRequest::SignTransaction {
            wallet: wallet.id.clone(),
        })
        .await?;

    // Re-read all mutable local authority after the potentially long human
    // review. Signing below is synchronous and performs no RPC requests. The
    // final SQL write repeats the pending/policy checks atomically, so a race
    // cannot put a stale signature into the submission queue.
    let current = lock(&pending)?.get(request.request_id)?;
    ensure!(
        current.status == PendingStatus::AwaitingApproval,
        "pending request changed during approval"
    );
    ensure!(
        current.digest == request.digest,
        "pending request digest changed during approval"
    );
    // The caller supplies both the plan and the digest it claims to be. That
    // pair is checked against the stored record above, but nothing so far
    // checks the pair against itself: a caller could hand over the digest of
    // the record it read and the calldata of something else, and every
    // comparison would pass while the bytes simulated and signed were the
    // other plan's. `PendingRow::parse` binds the two on every durable read,
    // so this closes the same gap at the API boundary.
    ensure!(
        format!("{:#x}", request.execution_plan.digest()) == request.digest,
        "the request's plan does not hash to the digest it carries"
    );
    ensure!(
        current.wallet_instance_id == wallet.instance_id
            && config.wallet(&request.wallet_id)? == wallet,
        "wallet configuration changed during approval"
    );
    ensure!(
        config.network(&request.network_name)? == network,
        "network configuration changed during approval"
    );
    let current_policy = read_policy()?;
    ensure!(
        current_policy.revision == request.policy_revision
            && current_policy.policy == stored_policy.policy,
        "active policy changed during approval"
    );
    ensure!(
        prepared.review_digest() == review_digest,
        "prepared transaction changed during approval"
    );
    let signed = sign_prepared_execution(
        &wallet,
        &network,
        &request.execution_plan,
        &simulation,
        &prepared,
        keys,
        overrides,
    )?;
    let approved = lock(&pending)?.store_signed(
        request.request_id,
        &request.digest,
        &review_digest,
        &signed.serialized_transaction,
        &signed.transaction_hash,
    )?;
    Ok(ApprovalOutcome::Signed(approved))
}

/// Everything one queued transaction's review is authored from, so the first
/// document and every refreshed one are built by the same code from the same
/// inputs.
///
/// The fixed half is what makes a refresh safe: the plan, the policy, and the
/// wallet are borrowed and never replaced, so re-simulating cannot change what
/// is being approved. Only the chain's answer to it can differ.
struct TransactionReview<'a> {
    wallet: &'a WalletMetadata,
    network: &'a NetworkConfig,
    request: &'a PendingTransaction,
    stored_policy: &'a StoredPolicy,
    policy_context: &'a crate::core::predicate::PolicyContext,
    /// Kept behind a mutex because rusqlite connections are Send but not Sync,
    /// while a refresh author must be shareable with the presenter. The lock
    /// is held only for local indexed reads after simulation has completed.
    tokens: Mutex<crate::token_store::TokenStore>,
    overrides: SigningOverrides,
    /// The newest authoring attempt, successful or not. A failed refresh has
    /// to supersede the document before it, and concurrent refreshes must not
    /// let an older success publish after a newer failure.
    generation: AtomicU64,
    /// What the presenter is currently showing. Replaced on every refresh and
    /// read once after the review, because the signature has to be built from
    /// the numbers the reviewer actually decided on.
    latest: Mutex<Option<(u64, Authored)>>,
}

/// One authored review: the simulation and the envelope prepared from it.
/// They travel together because they are one consistent answer about one
/// moment; mixing a simulation from one refresh with a prepared envelope from
/// another would show a reviewer fees and effects that never coexisted. The
/// rendered document itself does not need to travel with them — the caller
/// that triggers a refresh already holds the `ApprovalRequest` `author`
/// returns and hands it straight to the presenter, so nothing ever reads it
/// back out of here.
struct Authored {
    simulation: SimulationResult,
    prepared: crate::execution::PreparedExecution,
}

impl TransactionReview<'_> {
    /// Simulate, prepare, and render. Every call is a complete re-read of the
    /// chain: the simulation is pinned to whatever block is current now, and
    /// the fee fields come from the same moment.
    async fn author(&self) -> Result<(ReviewDocument, SimulationResult)> {
        // Asking for new chain state withdraws the old answer immediately. If
        // anything below fails, approval must fail with it rather than falling
        // back to the nonce, fees, and envelope the reviewer explicitly asked
        // to replace.
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self
            .latest
            .lock()
            .map_err(|_| anyhow::anyhow!("review state lock was poisoned"))? = None;
        let simulation = simulate_execution(
            self.wallet,
            self.network,
            &self.request.execution_plan,
            self.stored_policy,
            self.policy_context,
            None,
        )
        .await?;
        let prepared = prepare_execution(
            self.wallet,
            self.network,
            &self.request.execution_plan,
            &simulation,
            self.overrides,
        )
        .await?;
        // A swap's output token may appear only in the simulation's observed
        // balance changes, not as the target of a standard token call in the
        // plan. Resolve names after every fresh simulation so all displayed
        // token addresses get the owner-confirmed metadata already stored for
        // them. This remains display-only and never consults token contracts.
        let token_targets =
            review_token_targets(&self.request.execution_plan.ordered_steps, &simulation).await;
        let token_metadata = self
            .tokens
            .lock()
            .map_err(|_| anyhow::anyhow!("token database lock was poisoned"))?
            .display_metadata(self.network.chain_id, &token_targets)
            .context("failed to load confirmed token metadata for review")?;
        let approval = transaction_approval_request(
            self.request,
            &simulation,
            &prepared,
            self.network,
            &token_metadata,
        )
        .await?;
        let mut latest = self
            .latest
            .lock()
            .map_err(|_| anyhow::anyhow!("review state lock was poisoned"))?;
        // Check while holding the slot: a newer author can increment without
        // this lock, but it cannot clear the slot until this write finishes.
        // Whichever side wins therefore leaves either its own pair or no pair,
        // never an older pair published after a newer failed attempt.
        ensure!(
            self.generation.load(Ordering::SeqCst) == generation,
            "this review was superseded by a newer refresh"
        );
        *latest = Some((
            generation,
            Authored {
                simulation: simulation.clone(),
                prepared,
            },
        ));
        let mut exact_payloads = vec![serde_json::to_string_pretty(&self.request.execution_plan)?];
        exact_payloads.extend(
            self.request
                .execution_plan
                .ordered_steps
                .iter()
                .map(|step| {
                    let rows = calldata_rows(&step.transaction.data);
                    format!(
                        "Step {} exact calldata\n{}",
                        step.step,
                        if rows.is_empty() {
                            "none".to_owned()
                        } else {
                            format!("0x{}", rows.join("\n"))
                        }
                    )
                }),
        );
        Ok((
            ReviewDocument::from_request(approval, exact_payloads),
            simulation,
        ))
    }

    /// The authored review the presenter finished on.
    fn take_authored(&self) -> Result<Authored> {
        let (generation, authored) = self
            .latest
            .lock()
            .map_err(|_| anyhow::anyhow!("review state lock was poisoned"))?
            .take()
            .context("the review produced no current authored document")?;
        ensure!(
            self.generation.load(Ordering::SeqCst) == generation,
            "the authored review was superseded"
        );
        Ok(authored)
    }
}

async fn review_token_targets(
    steps: &[crate::core::execution_plan::ExecutionStep],
    simulation: &SimulationResult,
) -> Vec<alloy::primitives::Address> {
    let mut targets = plan_token_targets(steps)
        .await
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(changes) = simulation.balance_changes.as_ref() {
        targets.extend(
            changes
                .tokens
                .keys()
                .filter_map(|address| address.parse::<alloy::primitives::Address>().ok()),
        );
    }
    targets.extend(
        simulation
            .token_spends
            .keys()
            .filter_map(|address| address.parse::<alloy::primitives::Address>().ok()),
    );
    targets.into_iter().collect()
}

#[async_trait::async_trait]
impl crate::approval::ReviewRefresh for TransactionReview<'_> {
    async fn resimulate(&self) -> Result<crate::approval::Refreshed> {
        let (document, simulation) = self.author().await?;
        Ok(crate::approval::Refreshed {
            document,
            simulation,
        })
    }
}

/// The complete server-authored review document for one queued transaction:
/// every fact a reviewer decides on, none authored by the presenter.
#[allow(clippy::too_many_lines)]
async fn transaction_approval_request(
    pending: &PendingTransaction,
    simulation: &SimulationResult,
    prepared: &PreparedExecution,
    network: &NetworkConfig,
    token_metadata: &TokenMetadataMap,
) -> Result<ApprovalRequest> {
    let total_native = pending
        .execution_plan
        .ordered_steps
        .iter()
        .map(|step| BigUint::from_str(step.transaction.value.as_str()))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<BigUint>();
    let steps = &pending.execution_plan.ordered_steps;
    let summary = if simulation.simulation.success {
        "The simulation succeeded, but this transaction is outside the wallet's automatic policy. Review the expected wallet changes before approving."
    } else {
        "The simulation failed, so the wallet could not verify this transaction's effects. Approving will still sign the exact transaction shown below."
    };
    let mut request =
        ApprovalRequest::new(ApprovalKind::PolicyException, "Review transaction", summary)
            .fact("Wallet", &pending.wallet_id)
            .fact("Network", network.display_label())
            .fact("Chain ID", &pending.chain_id)
            // The vetted TLS host the plan body was fetched from, "inline data URI"
            // for an agent-held plan, or "a file on this machine" for one read off
            // local disk. A plan this wallet built itself shows that plainly, so a
            // reviewer always knows which producer they are trusting.
            .fact(
                "Plan source",
                pending
                    .plan_source
                    .as_deref()
                    .unwrap_or("constructed locally by this wallet"),
            )
            .fact("Sender", format!("{:#x}", pending.execution_plan.sender))
            .fact(
                "Total native value",
                native_value(&total_native.to_string(), network),
            )
            .fact("Policy revision", pending.policy_revision.to_string())
            .digest(prepared.review_digest());
    request.id = pending.request_id;

    let interpretations = interpret_steps(steps, token_metadata).await;
    request = request.section_kind(
        ApprovalSectionKind::Effects,
        "Expected wallet changes (simulation, excluding live gas)",
    );
    let balance_changes = render_balance_changes(simulation, network, token_metadata);
    if balance_changes.is_empty() {
        request = request.fact(
            "Result",
            if simulation.simulation.success {
                "No asset balance changes were detected."
            } else {
                "Unavailable because the simulation failed."
            },
        );
    } else {
        for (label, value) in balance_changes {
            request = request.fact(label, value);
        }
    }

    for (step, interpretation) in steps.iter().zip(&interpretations) {
        let calldata = step.transaction.data.as_ref();
        let target = token_metadata.get(&step.transaction.to).map_or_else(
            || format!("{:#x}", step.transaction.to),
            |metadata| token_label(step.transaction.to, metadata),
        );
        request = request
            .section_kind(
                ApprovalSectionKind::Action,
                format!("Action {} of {}", step.step, steps.len()),
            )
            // The exact fields here are authoritative; the reading is a
            // supplemental interpretation from a vendored ERC-7730 descriptor
            // or from recognized standard calldata.
            .fact(
                "What it does",
                interpretation.description.clone().unwrap_or_else(|| {
                    "Unrecognized contract call. Verify the target and exact data before approving."
                        .into()
                }),
            )
            .fact("Target", target)
            .fact(
                "Native value",
                native_value(step.transaction.value.as_str(), network),
            )
            .fact("Execution", format!("{:?}", step.kind));
        for detail in &interpretation.details {
            request = request.fact("·", detail);
        }
        let summary = if calldata.is_empty() {
            "none".to_string()
        } else {
            format!(
                "{} bytes; selector 0x{}",
                calldata.len(),
                hex::encode(&calldata[..calldata.len().min(4)])
            )
        };
        request = request.fact("Calldata", summary);
    }

    request = request
        .section_kind(
            ApprovalSectionKind::Fees,
            "Fee ceiling and transaction details",
        )
        .fact(
            "Maximum transaction fee",
            native_value(&prepared.maximum_fee_wei(), network),
        )
        .fact("Type", prepared.transaction_type())
        .fact("Nonce", prepared.nonce().to_string())
        .fact("Gas limit", prepared.gas_limit().to_string())
        .fact(
            "Max fee per gas",
            format!("{} wei", prepared.max_fee_per_gas()),
        )
        .fact(
            "Max priority fee per gas",
            format!("{} wei", prepared.max_priority_fee_per_gas()),
        );
    if let Some(authorization_nonce) = prepared.authorization_nonce() {
        request = request.fact(
            "EIP-7702 authorization",
            format!(
                "implementation={}; nonce={authorization_nonce}",
                simulation.implementation.as_deref().unwrap_or("missing")
            ),
        );
    }
    if let Some(replaced) = &simulation.replaces_delegated_implementation {
        request = request.warning(format!(
            "This replaces the wallet's current EIP-7702 delegation to {replaced}."
        ));
    }
    for warning in interpretations
        .iter()
        .flat_map(|interpretation| &interpretation.warnings)
    {
        request = request.warning(warning);
    }
    for finding in &simulation.policy_findings {
        if finding.severity != FindingSeverity::Info {
            request = request.warning(format!(
                "{}: {}{}",
                finding.code,
                finding.message,
                finding
                    .step
                    .map_or_else(String::new, |step| format!(" (step {step})"))
            ));
        }
    }
    if let Some(failure) = &simulation.simulation.failure {
        request = request.warning(format!(
            "Simulation {:?}: {} Recommended action: {:?}.",
            failure.category,
            crate::sanitize::terminal_safe_line(&failure.message),
            failure.recommended_action
        ));
    }
    Ok(request)
}

/// Refuse a wallet that has no policy, whatever it is being asked to sign.
///
/// "No policy" is the half-provisioned state: `account create` and
/// `account import` write the wallet metadata into encrypted storage and only
/// then initialize its policy, so a failure between the two leaves a wallet whose
/// key exists and whose authority was never described. The desktop tells the owner
/// that state fails closed — "it has no policy, so signing fails closed and the
/// MCP server refuses to start until it has one" — and for transactions it
/// does, because grading a plan needs a policy to grade it against.
///
/// Off-chain signing consulted no policy at all, by design: a policy cannot
/// score what a permit authorizes, so a person reads every payload. But
/// "consults no policy" quietly became "does not need one to exist", and the
/// only enforcement of the invariant was a loop over the wallets present when
/// the server started. A wallet half-provisioned afterwards was invisible to
/// it, and a running server would queue and sign that wallet's EIP-712
/// payloads — a permit, an order, a delegation — for a human who was told the
/// wallet was inert.
///
/// So the check sits on the signature rather than on startup, and it is a
/// separate question from what a policy *says*: this asks only whether the
/// wallet was ever finished. A wallet is either provisioned or it is not, and
/// nothing it holds may be signed until it is.
fn require_provisioned_wallet(
    policies: &PolicyStore,
    wallet: &crate::config::WalletMetadata,
) -> Result<()> {
    ensure!(
        policies
            .get_for_wallet(&wallet.id, wallet.instance_id, wallet.address)?
            .is_some(),
        "wallet {} has no policy bound to its current address, so nothing it holds can be signed. It was created or \
         imported while policy initialization failed. Open Accounts in the wallet application to \
         install a require-approval policy or remove that wallet.",
        wallet.id
    );
    Ok(())
}

/// Confirm owner presence and sign one reviewed EIP-191 message.
///
/// The caller has already drawn the review and taken the reviewer's decision;
/// what remains is everything that must not be skippable, so it lives here
/// rather than at the call site: owner authentication, a re-read of every
/// mutable input the review may have raced, and the signature itself.
///
/// The re-read matters because a review takes as long as a person takes, and
/// nothing is locked while it waits. `request` is what the reviewer actually
/// saw; the stored row and the wallet configuration are compared back against
/// it, so a request edited or a wallet re-pointed mid-review is refused rather
/// than signed under an approval given for something else. The final write
/// repeats the digest and status checks inside its own transaction.
pub async fn sign_reviewed_message(
    config: &ConfigStore,
    policies: &PolicyStore,
    store: &mut MessageStore,
    request: &PendingMessage,
    wallet: &WalletMetadata,
    digest: B256,
    presence: &dyn HumanPresence,
    keys: &dyn KeyStore,
) -> Result<PendingMessage> {
    require_provisioned_wallet(policies, wallet)?;
    ensure!(
        digest == request.digest.parse::<B256>()?,
        "reviewed message digest does not match the stored request"
    );

    presence
        .confirm(&PresenceRequest::SignMessage {
            wallet: wallet.id.clone(),
        })
        .await?;

    // Presence can remain open while the owner changes or removes this
    // account's policy in another window. Re-read provisioning after the OS
    // prompt so the signature cannot cross that configuration boundary.
    require_provisioned_wallet(policies, wallet)?;
    let current = store.get(request.request_id)?;
    ensure!(
        current.status == MessageStatus::AwaitingApproval
            && current.digest == request.digest
            && current.message_hex == request.message_hex
            && current.wallet_instance_id == request.wallet_instance_id
            && current.wallet_id == request.wallet_id
            && current.wallet_address == request.wallet_address,
        "message request changed during approval"
    );
    ensure!(
        current.wallet_instance_id == wallet.instance_id
            && current.wallet_id == wallet.id
            && current.wallet_address == wallet.address,
        "message request belongs to another wallet"
    );
    ensure!(
        config.wallet(&request.wallet_id)? == *wallet,
        "wallet configuration changed during approval"
    );

    let signer = load_matching_signer(keys, wallet)?;
    let signature = signer
        .sign_hash_sync(&digest)
        .context("failed to sign the message")?;
    store.store_signature_for_wallet(
        request.request_id,
        wallet,
        digest,
        &format!("0x{}", hex::encode(signature.as_bytes())),
    )
}

/// Confirm owner presence and sign one reviewed EIP-712 payload.
///
/// The twin of [`sign_reviewed_message`], and it climbs the same ladder for
/// the same reasons; only the queue and the presence reason differ.
pub async fn sign_reviewed_typed_data(
    config: &ConfigStore,
    policies: &PolicyStore,
    store: &mut TypedDataStore,
    request: &PendingTypedData,
    wallet: &WalletMetadata,
    digest: B256,
    presence: &dyn HumanPresence,
    keys: &dyn KeyStore,
) -> Result<PendingTypedData> {
    require_provisioned_wallet(policies, wallet)?;
    ensure!(
        digest == request.digest.parse::<B256>()?,
        "reviewed typed-data digest does not match the stored request"
    );

    presence
        .confirm(&PresenceRequest::SignTypedData {
            wallet: wallet.id.clone(),
        })
        .await?;

    require_provisioned_wallet(policies, wallet)?;
    let current = store.get(request.request_id)?;
    ensure!(
        current.status == TypedDataStatus::AwaitingApproval
            && current.digest == request.digest
            && current.typed_data == request.typed_data
            && current.wallet_instance_id == request.wallet_instance_id
            && current.wallet_id == request.wallet_id
            && current.wallet_address == request.wallet_address,
        "typed-data request changed during approval"
    );
    ensure!(
        current.wallet_instance_id == wallet.instance_id
            && current.wallet_id == wallet.id
            && current.wallet_address == wallet.address,
        "typed-data request belongs to another wallet"
    );
    ensure!(
        config.wallet(&request.wallet_id)? == *wallet,
        "wallet configuration changed during approval"
    );

    let signer = load_matching_signer(keys, wallet)?;
    let signature = signer
        .sign_hash_sync(&digest)
        .context("failed to sign typed data")?;
    store.store_signature_for_wallet(
        request.request_id,
        wallet,
        digest,
        &format!("0x{}", hex::encode(signature.as_bytes())),
    )
}

#[cfg(test)]
#[path = "orchestrator_calldata_display_test.rs"]
mod calldata_display_tests;

#[cfg(test)]
#[path = "orchestrator_rejection_test.rs"]
mod rejection_tests;

#[cfg(test)]
#[path = "orchestrator_provisioning_test.rs"]
mod provisioning_tests;

#[cfg(test)]
#[path = "orchestrator_token_metadata_test.rs"]
mod token_metadata_tests;
