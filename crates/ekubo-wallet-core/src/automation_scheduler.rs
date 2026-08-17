//! The in-process cron that runs installed automations.
//!
//! One tick for one automation is the whole of this module's work: settle what
//! the last tick sent, decide whether to run at all, poll the bytecode, and
//! hand any calls it produced to `execute_automatic` — the same guarded path an
//! agent's plan takes. Nothing here evaluates a policy itself, and nothing here
//! signs. It holds an [`AgentExecutionAuthority`], the narrow capability the
//! MCP server also gets, so an audit of what this can sign reads exactly like
//! an audit of what an agent can.
//!
//! Two rules shape everything else.
//!
//! **A tick is skipped, never deferred.** If the wallet and chain's signing
//! slot is held — by this automation's own last transaction or by anything else
//! — the tick is consumed with a recorded reason and the schedule moves on. A
//! deferred tick would execute an intent computed against a chain that has since
//! moved, which is precisely what re-deriving from live state every tick exists
//! to avoid.
//!
//! **Nothing retries.** Every terminal disappointment — a policy that did not
//! allow the batch, a batch that reverted on chain, a transaction that never
//! mined — stops the automation and says why. A blob that emitted a reverting
//! call will emit it again next tick, so stopping is the only response that does
//! not burn gas in a loop.

use crate::{
    agent_authority::AgentExecutionAuthority,
    automation::{self, Automation, PollFailure},
    automation_store::AutomationStore,
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    core::predicate::PolicyContext,
    orchestrator::SendDisposition,
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    simulation::simulate_execution,
    sql::now,
};
use anyhow::{Context as _, Result};
use chrono::{DateTime, TimeDelta, Utc};
use std::sync::Mutex;
use uuid::Uuid;

/// How long a tick's transaction may stay unmined before the automation stops.
///
/// The one wall-clock deadline in this feature, and it is safe to be one
/// because it can only ever *stop* an automation. No clock reading here
/// authorizes anything: a machine whose time is wrong disables an automation
/// early, which is recoverable by relinking, rather than signing something it
/// should not have. The alternative — waiting forever on a transaction the
/// network dropped — leaves the automation permanently skipping with an
/// explanation nobody wrote.
pub const STUCK_TRANSACTION_TIMEOUT: TimeDelta = TimeDelta::minutes(30);

/// What one tick did, for the caller to surface as activity and notifications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TickOutcome {
    /// The wallet and chain's signing slot was busy. Nothing ran.
    Skipped { reason: String },
    /// The blob ran and asked for nothing.
    Idle,
    /// The blob's calls were signed and broadcast.
    Sent { request_id: Uuid, calls: usize },
    /// The automation stopped, and this is what the owner is told.
    Stopped { reason: String },
    /// The tick failed and the automation is still enabled, for now.
    Failed { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickReport {
    pub automation_id: Uuid,
    pub name: String,
    pub outcome: TickOutcome,
}

pub struct AutomationScheduler {
    execution: AgentExecutionAuthority,
}

impl AutomationScheduler {
    #[must_use]
    pub const fn new(execution: AgentExecutionAuthority) -> Self {
        Self { execution }
    }

    /// Run every automation that is due for one wallet on one network.
    ///
    /// Sequential rather than concurrent, because the automations of one wallet
    /// and chain contend for a single signing slot: running them at once would
    /// produce one send and a handful of skips decided by whichever future
    /// happened to be polled first. In order, the first due automation gets the
    /// slot and the rest record honestly that it was taken.
    pub async fn run_due(
        &self,
        config: &ConfigStore,
        automations: &Mutex<AutomationStore>,
        pending: &Mutex<PendingStore>,
        policies: &Mutex<PolicyStore>,
        wallet: &WalletMetadata,
        network: &NetworkConfig,
        at: DateTime<Utc>,
    ) -> Result<Vec<TickReport>> {
        let revision = current_revision(policies, wallet)?;
        let due = lock(automations)?.due(wallet.instance_id, revision, at)?;

        let mut reports: Vec<TickReport> = due
            .unlinked
            .iter()
            .map(|automation| TickReport {
                automation_id: automation.id,
                name: automation.name.clone(),
                outcome: TickOutcome::Stopped {
                    reason: automation
                        .stopped_reason
                        .clone()
                        .unwrap_or_else(|| "the signing policy changed".to_owned()),
                },
            })
            .collect();

        for automation in due.ready {
            if automation.chain_id != network.chain_id {
                continue;
            }
            let report = self
                .run_one(
                    config,
                    automations,
                    pending,
                    policies,
                    wallet,
                    network,
                    &automation,
                    revision,
                    at,
                )
                .await?;
            reports.push(report);
        }
        Ok(reports)
    }

    async fn run_one(
        &self,
        config: &ConfigStore,
        automations: &Mutex<AutomationStore>,
        pending: &Mutex<PendingStore>,
        policies: &Mutex<PolicyStore>,
        wallet: &WalletMetadata,
        network: &NetworkConfig,
        automation: &Automation,
        revision: u64,
        at: DateTime<Utc>,
    ) -> Result<TickReport> {
        // What the previous tick sent decides whether this one may run at all,
        // and a reverted or abandoned batch stops the automation outright.
        if let Some(stop) = self
            .settle_previous_send(pending, network, automation, at)
            .await?
        {
            return stop_automation(automations, automation, &stop);
        }
        if let Some(reason) = slot_holder(pending, wallet, network)? {
            lock(automations)?.record_skip(automation.id, &reason, at)?;
            return Ok(report(automation, TickOutcome::Skipped { reason }));
        }

        // The work list was built against a revision read moments ago, and a
        // policy can be installed in between. Re-reading it here, and using
        // this exact policy for the simulation below, closes that window: the
        // automation is either running under the authority it was bound to or
        // it is not running.
        let stored_policy = current_policy(policies, wallet)?;
        if stored_policy.revision != revision
            || stored_policy.revision != automation.policy_revision
        {
            let unlinked =
                lock(automations)?.due(wallet.instance_id, stored_policy.revision, at)?;
            let reason = unlinked
                .unlinked
                .first()
                .and_then(|automation| automation.stopped_reason.clone())
                .unwrap_or_else(|| "the signing policy changed mid-tick".to_owned());
            return Ok(report(automation, TickOutcome::Stopped { reason }));
        }

        let calls = match self.poll(network, wallet, automation).await? {
            Err(failure) => {
                let reason = failure.to_string();
                let current = lock(automations)?.record_failure(automation.id, &reason, at)?;
                return Ok(report(
                    automation,
                    if current.state == crate::automation::AutomationState::Enabled {
                        TickOutcome::Failed { reason }
                    } else {
                        TickOutcome::Stopped {
                            reason: current.stopped_reason.unwrap_or(reason),
                        }
                    },
                ));
            }
            Ok(outcome) => outcome.calls,
        };
        if calls.is_empty() {
            lock(automations)?.record_tick(automation.id, "no calls", at)?;
            return Ok(report(automation, TickOutcome::Idle));
        }

        let plan = automation::synthesize_plan(wallet.address, automation.chain_id, &calls)?;
        let context = PolicyContext {
            wallet: wallet.address,
        };
        let simulation =
            simulate_execution(wallet, network, &plan, &stored_policy, &context, None).await?;
        let plan_source = format!("automation:{}", automation.id);
        let disposition = self
            .execution
            .execute(
                config,
                pending,
                wallet,
                network,
                &plan,
                Some(plan_source.as_str()),
                &simulation,
            )
            .await?;
        let record = match disposition {
            // Queued means the policy did not allow every call, or the
            // simulation failed. The row it left is the diagnostic; the
            // automation stops so tomorrow's ticks do not queue another
            // hundred of them.
            SendDisposition::Queued(record) => {
                let reason = format!(
                    "the signing policy did not allow this automation's calls; request {} is \
                     waiting for review and shows exactly which call",
                    record.request_id
                );
                return stop_automation(automations, automation, &reason);
            }
            SendDisposition::Signed(record) => record,
        };

        let claimed = lock_pending(pending)?.claim_for_submission(record.request_id)?;
        let (submitted, broadcast) =
            crate::reconcile::submit_claimed(pending, wallet, network, claimed).await?;
        if let Some(error) = broadcast.broadcast_error {
            let reason = format!("broadcasting the automation's transaction failed: {error}");
            let current = lock(automations)?.record_failure(automation.id, &reason, at)?;
            return Ok(report(
                automation,
                if current.state == crate::automation::AutomationState::Enabled {
                    TickOutcome::Failed { reason }
                } else {
                    TickOutcome::Stopped {
                        reason: current.stopped_reason.unwrap_or(reason),
                    }
                },
            ));
        }
        lock(automations)?.record_send(
            automation.id,
            submitted.request_id,
            &format!("sent {} call(s)", calls.len()),
            at,
        )?;
        Ok(report(
            automation,
            TickOutcome::Sent {
                request_id: submitted.request_id,
                calls: calls.len(),
            },
        ))
    }

    async fn poll(
        &self,
        network: &NetworkConfig,
        wallet: &WalletMetadata,
        automation: &Automation,
    ) -> Result<Result<automation::PollOutcome, PollFailure>> {
        let clients = crate::rpc::clients_for(network).await?;
        let mut last = None;
        let mut remaining = clients.len();
        for client in clients {
            remaining -= 1;
            let outcome = automation::poll(
                client.as_ref(),
                wallet.address,
                &automation.bytecode,
                &automation.config,
            )
            .await?;
            // Only an endpoint failure is worth another endpoint. A revert or
            // an undecodable return is a fact about the bytecode, and asking
            // seven more nodes returns the same answer more slowly.
            match outcome {
                Err(PollFailure::Rpc(message)) if remaining > 0 => {
                    last = Some(Err(PollFailure::Rpc(message)));
                }
                settled => return Ok(settled),
            }
        }
        last.context("network has no RPC endpoints to poll against")
    }

    /// Settle whatever the previous tick sent, returning a reason if that
    /// outcome stops the automation.
    async fn settle_previous_send(
        &self,
        pending: &Mutex<PendingStore>,
        network: &NetworkConfig,
        automation: &Automation,
        at: DateTime<Utc>,
    ) -> Result<Option<String>> {
        let Some(request_id) = automation.last_request_id else {
            return Ok(None);
        };
        let record = lock_pending(pending)?.get(request_id);
        // A row that is gone — purged with a wallet, pruned from history —
        // takes its verdict with it. Nothing to settle and nothing to stop.
        let Ok(record) = record else {
            return Ok(None);
        };
        let record = crate::reconcile::reconcile_record(pending, network, record, true).await?;
        match record.status {
            PendingStatus::Reverted => Ok(Some(format!(
                "the transaction this automation sent reverted on chain (request {request_id})"
            ))),
            PendingStatus::Signed | PendingStatus::Submitting | PendingStatus::Broadcast => {
                Ok(stuck_reason(&record, at))
            }
            _ => Ok(None),
        }
    }
}

fn stop_automation(
    automations: &Mutex<AutomationStore>,
    automation: &Automation,
    reason: &str,
) -> Result<TickReport> {
    lock(automations)?.disable(automation.id, reason)?;
    Ok(report(
        automation,
        TickOutcome::Stopped {
            reason: reason.to_owned(),
        },
    ))
}

/// Whether a still-in-flight transaction has been in flight too long to keep
/// waiting on.
fn stuck_reason(record: &PendingTransaction, at: DateTime<Utc>) -> Option<String> {
    let age = at.signed_duration_since(record.updated_at);
    (age > STUCK_TRANSACTION_TIMEOUT).then(|| {
        format!(
            "the transaction this automation sent has not mined in {} minutes (request {}); \
             settle or cancel it, then relink the automation",
            STUCK_TRANSACTION_TIMEOUT.num_minutes(),
            record.request_id
        )
    })
}

/// Why a tick cannot run right now, if it cannot.
///
/// Reads the wallet and chain's in-flight row rather than tracking a slot of
/// its own: one send at a time per wallet and chain is a rule the pending
/// store's unique index already enforces against every sender, and a second
/// notion of the same thing here would be a second thing to keep in agreement.
fn slot_holder(
    pending: &Mutex<PendingStore>,
    wallet: &WalletMetadata,
    network: &NetworkConfig,
) -> Result<Option<String>> {
    let in_flight = lock_pending(pending)?
        .in_flight_for_address(wallet.address, &network.chain_id.to_string())?;
    Ok(in_flight.map(|record| {
        format!(
            "skipped: request {} on this wallet and chain is {}",
            record.request_id,
            record.status.label()
        )
    }))
}

fn current_revision(policies: &Mutex<PolicyStore>, wallet: &WalletMetadata) -> Result<u64> {
    Ok(current_policy(policies, wallet)?.revision)
}

fn current_policy(
    policies: &Mutex<PolicyStore>,
    wallet: &WalletMetadata,
) -> Result<crate::policy_store::StoredPolicy> {
    policies
        .lock()
        .map_err(|_| anyhow::anyhow!("policy database lock was poisoned"))?
        .get_for_wallet(&wallet.id, wallet.instance_id, wallet.address)?
        .context("wallet has no active policy")
}

fn report(automation: &Automation, outcome: TickOutcome) -> TickReport {
    TickReport {
        automation_id: automation.id,
        name: automation.name.clone(),
        outcome,
    }
}

fn lock(
    automations: &Mutex<AutomationStore>,
) -> Result<std::sync::MutexGuard<'_, AutomationStore>> {
    automations
        .lock()
        .map_err(|_| anyhow::anyhow!("automation database lock was poisoned"))
}

fn lock_pending(pending: &Mutex<PendingStore>) -> Result<std::sync::MutexGuard<'_, PendingStore>> {
    pending
        .lock()
        .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))
}

/// The moment a scheduler run uses for every automation it decides.
///
/// One reading per pass, so two automations in the same pass cannot disagree
/// about what time it is and skip each other.
#[must_use]
pub fn tick_moment() -> DateTime<Utc> {
    now()
}

#[cfg(test)]
#[path = "automation_scheduler_test.rs"]
mod tests;
