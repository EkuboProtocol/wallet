//! The one signing orchestration.
//!
//! Exactly two paths produce a transaction signature in this process, and
//! both live here: the automatic path, gated by the active policy and a
//! successful simulation, and the human-gated path, gated by a terminal
//! review plus OS owner authentication. Each owns its guard ladder once, so
//! the MCP server and the CLI cannot drift apart on what is checked before
//! key material is touched.

use crate::{
    approval::{
        ApprovalDecision, ApprovalKind, ApprovalRequest, InteractiveProof, ReviewPresenter,
    },
    approval_summary::{
        TokenMetadataMap, interpret_steps, plan_token_targets, render_balance_changes,
    },
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    core::{execution_plan::ExecutionPlan, policy::FindingSeverity},
    custody::KeyStore,
    execution::{
        PreparedExecution, SigningOverrides, prepare_execution, sign_execution,
        sign_prepared_execution,
    },
    human_presence::{HumanPresence, PresenceRequest},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::StoredPolicy,
    simulation::{SimulationResult, simulate_execution},
};
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use std::{str::FromStr, sync::Mutex};

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
/// no override exists — a policy denial or failed simulation always queues.
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

    if !simulation.allowed || !simulation.simulation.success {
        let request = lock(pending)?.create(
            &wallet.id,
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
    let in_flight = lock(pending)?.in_flight(&wallet.id, &network.chain_id.to_string())?;
    if let Some(previous) = in_flight {
        crate::reconcile::reconcile_record(pending, network, previous, true).await?;
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
    let record = lock(pending)?.record_automatic_signed(
        &wallet.id,
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
/// [`InteractiveProof`] is consumed: one proof authorizes one approval.
#[allow(clippy::too_many_lines)]
pub async fn approve_transaction(
    config: &ConfigStore,
    pending: PendingStore,
    tokens: &crate::token_store::TokenStore,
    read_policy: &(dyn Fn() -> Result<StoredPolicy> + Sync),
    request: PendingTransaction,
    proof: InteractiveProof,
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
        request.execution_plan.sender == wallet.address,
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
    let in_flight = lock(&pending)?.in_flight(&wallet.id, &request.chain_id)?;
    if let Some(previous) = in_flight {
        crate::reconcile::reconcile_record(&pending, &network, previous, true).await?;
    }

    let simulation = simulate_execution(
        &wallet,
        &network,
        &request.execution_plan,
        &stored_policy,
        None,
    )
    .await?;
    let overrides = SigningOverrides::human(&proof);
    let prepared = prepare_execution(
        &wallet,
        &network,
        &request.execution_plan,
        &simulation,
        overrides,
    )
    .await?;
    // Display metadata only, and only ever from the owner's token database: a
    // token contract must not get to name itself on the screen where the owner
    // decides. A token with no confirmed row renders by address in base units,
    // which never blocks or alters the approval decision.
    let token_metadata = tokens
        .display_metadata(
            network.chain_id,
            &plan_token_targets(&request.execution_plan.ordered_steps).await,
        )
        .unwrap_or_default();
    let approval =
        transaction_approval_request(&request, &simulation, &prepared, &network, &token_metadata)
            .await?;
    // Rejecting here is a decision, not an abort: it is recorded, so the
    // agent waiting on this request learns the answer.
    if presenter.review_transaction(&approval, &simulation).await? != ApprovalDecision::Approved {
        let rejected = lock(&pending)?.reject(request.request_id)?;
        return Ok(ApprovalOutcome::Rejected(rejected));
    }

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
        config.wallet(&request.wallet_id)? == wallet,
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
    let mut request = ApprovalRequest::new(
        ApprovalKind::PolicyException,
        "Approve policy exception",
        "Review and sign this exact execution plan despite policy or simulation findings.",
    )
    .fact("Wallet", &pending.wallet_id)
    .fact("Network", &pending.network_name)
    .fact("Chain ID", &pending.chain_id)
    // The vetted TLS host the plan body was fetched from, or "inline data
    // URI" for an agent-held plan. A plan this wallet built itself shows
    // that plainly, so a reviewer always knows which producer they are
    // trusting.
    .fact(
        "Plan source",
        pending
            .plan_source
            .as_deref()
            .unwrap_or("constructed locally by this wallet"),
    )
    .fact("Sender", format!("{:#x}", pending.execution_plan.sender))
    .fact(
        "Ordered calls",
        pending.execution_plan.ordered_steps.len().to_string(),
    )
    .fact("Total native value", total_native.to_string())
    .fact("Policy revision", pending.policy_revision.to_string())
    .fact("Plan digest", &pending.digest)
    .fact("Simulation parent block", &simulation.block_number)
    .fact("Transaction type", prepared.transaction_type())
    .fact("Transaction nonce", prepared.nonce().to_string())
    .fact("Gas limit", prepared.gas_limit().to_string())
    .fact(
        "Max fee per gas (wei)",
        prepared.max_fee_per_gas().to_string(),
    )
    .fact(
        "Max priority fee per gas (wei)",
        prepared.max_priority_fee_per_gas().to_string(),
    )
    .fact("Maximum transaction fee (wei)", prepared.maximum_fee_wei())
    .digest(prepared.review_digest());
    request.id = pending.request_id;
    let interpretations =
        interpret_steps(&pending.execution_plan.ordered_steps, token_metadata).await;
    for (step, interpretation) in pending
        .execution_plan
        .ordered_steps
        .iter()
        .zip(&interpretations)
    {
        let calldata = step.transaction.data.as_ref();
        let selector = if calldata.is_empty() {
            "none".into()
        } else {
            format!("0x{}", hex::encode(&calldata[..calldata.len().min(4)]))
        };
        request = request.fact(
            format!("Call {}", step.step),
            format!(
                "kind={:?}; target={:#x}; value={} wei; selector={selector}; calldata={} bytes",
                step.kind,
                step.transaction.to,
                step.transaction.value,
                calldata.len(),
            ),
        );
        // The exact fields above are authoritative; these lines are a
        // supplemental reading from a vendored ERC-7730 descriptor or from
        // recognized standard calldata.
        request = request.fact(
            format!("Call {} reads as", step.step),
            interpretation.description.clone().unwrap_or_else(|| {
                "no matching descriptor or standard token operation; verify the target and selector directly"
                    .into()
            }),
        );
        for detail in &interpretation.details {
            request = request.fact(format!("Call {} ·", step.step), detail);
        }
    }
    let balance_changes = render_balance_changes(simulation, network, token_metadata);
    if balance_changes.is_empty() {
        request = request.fact(
            "Simulated net balance changes",
            if simulation.simulation.success {
                "none detected"
            } else {
                "unavailable because simulation failed"
            },
        );
    } else {
        for (index, line) in balance_changes.iter().enumerate() {
            request = request.fact(
                if index == 0 {
                    "Simulated net balance change (excludes live gas)".to_string()
                } else {
                    format!("Simulated net balance change {}", index + 1)
                },
                line,
            );
        }
    }
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
            failure.category, failure.message, failure.recommended_action
        ));
    }
    Ok(request)
}
