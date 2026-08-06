//! The one signing orchestration.
//!
//! Exactly two paths produce a transaction signature in this process, and
//! both live here: the automatic path, gated by the active policy and a
//! successful simulation, and the human-gated path, gated by a terminal
//! review plus OS owner authentication. Each owns its guard ladder once, so
//! the MCP server and the CLI cannot drift apart on what is checked before
//! key material is touched.

use crate::{
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    core::execution_plan::ExecutionPlan,
    custody::KeyStore,
    execution::{SigningOverrides, sign_execution},
    pending::{PendingStore, PendingTransaction},
    policy_store::StoredPolicy,
    simulation::SimulationResult,
};
use anyhow::{Result, ensure};
use std::sync::Mutex;

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
    simulation: &SimulationResult,
) -> Result<SendDisposition> {
    validate_send(wallet, network, plan, simulation)?;

    if !simulation.allowed || !simulation.simulation.success {
        let request =
            lock(pending)?.create(&wallet.id, &network.name, plan, stored_policy.revision)?;
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
        SigningOverrides::default(),
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
        stored_policy.revision,
        &signed.serialized_transaction,
        &signed.transaction_hash,
    )?;
    Ok(SendDisposition::Signed(record))
}
