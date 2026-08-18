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
//! **Sent failures do not retry.** A queued review/unmatched result, a batch
//! that reverted on chain, or a transaction that never mined stops the
//! automation and says why. An explicit policy deny is returned as a scheduler
//! error before a pending row exists and currently leaves the automation
//! enabled. No denied call is signed.

use crate::{
    agent_authority::AgentExecutionAuthority,
    automation::{self, Automation, PollFailure},
    automation_store::{AutomationStore, RunOutcome},
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    core::{policy::ReviewRequest, predicate::PolicyContext},
    orchestrator::SendDisposition,
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    simulation::simulate_execution,
    sql::now,
};
use anyhow::{Context as _, Result};
use chrono::{DateTime, TimeDelta, Utc};
use std::{sync::Mutex, time::Duration};
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
        // An unlink is a run too. It is the moment the automation stopped, and
        // leaving it out of the log would make the history end without saying
        // why.
        for report in &reports {
            log_run(automations, report, at)?;
        }

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
            log_run(automations, &report, at)?;
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
                // An automation runs unattended by definition: there is nobody
                // to ask for a second look, and a tick that queued one would
                // stop the automation rather than getting an answer. What it
                // may sign is the policy's question alone.
                ReviewRequest::PolicyDecides,
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

/// Append one reported tick's outcome to the automation's history.
///
/// Every tick that reaches a [`TickReport`], including the ones that did
/// nothing. An error propagated before `run_one` can return — currently an
/// explicit policy deny is one — has no report to append. Among reported runs,
/// retaining quiet outcomes distinguishes a working automation from a stopped
/// one.
fn log_run(
    automations: &Mutex<AutomationStore>,
    report: &TickReport,
    at: DateTime<Utc>,
) -> Result<()> {
    let (outcome, detail, request_id, calls) = match &report.outcome {
        TickOutcome::Skipped { reason } => (RunOutcome::Skipped, reason.clone(), None, 0),
        TickOutcome::Idle => (
            RunOutcome::Idle,
            "the automation ran and asked for nothing".to_owned(),
            None,
            0,
        ),
        TickOutcome::Sent { request_id, calls } => (
            RunOutcome::Sent,
            format!("sent {calls} call(s)"),
            Some(*request_id),
            u32::try_from(*calls).unwrap_or(u32::MAX),
        ),
        TickOutcome::Stopped { reason } => (RunOutcome::Stopped, reason.clone(), None, 0),
        TickOutcome::Failed { reason } => (RunOutcome::Failed, reason.clone(), None, 0),
    };
    lock(automations)?.record_run(
        report.automation_id,
        outcome,
        &detail,
        request_id,
        calls,
        at,
    )
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

/// The longest the driver sleeps between passes.
///
/// A ceiling rather than a period. The driver normally sleeps until the
/// earliest next fire time it can see, and this bounds how stale that plan may
/// get: an automation installed, relinked, or removed while the driver sleeps
/// changes the answer, and waking every minute regardless means a newly
/// installed hourly job starts within a minute rather than within an hour.
pub const MAX_IDLE_SLEEP: Duration = Duration::from_mins(1);

/// The shortest the driver sleeps between passes.
///
/// A floor on RPC pressure, and the answer to `* * * * * *`: an expression
/// that fires every second gets polled once a second at most and is otherwise
/// left to the serialization rule, which will skip most of those ticks anyway
/// while a send is in flight.
pub const MIN_SLEEP: Duration = Duration::from_secs(1);

/// How long to wait before the next pass, given when the soonest automation is
/// scheduled to fire.
///
/// Separated from the loop so the arithmetic is testable without a clock: the
/// loop is a `sleep` and a call, and every decision worth checking is here.
#[must_use]
pub fn sleep_for(next_fire: Option<DateTime<Utc>>, at: DateTime<Utc>) -> Duration {
    let Some(next) = next_fire else {
        // Nothing scheduled. Wait the ceiling, not forever: an automation
        // installed while the driver sleeps is not something the last plan
        // knew about.
        return MAX_IDLE_SLEEP;
    };
    // A fire time already past means something is due now — a just-installed
    // automation, or a pass that ran long. `to_std` fails on a negative
    // duration, and treating that failure as "nothing to do" would idle for a
    // minute over work that is already late.
    next.signed_duration_since(at)
        .to_std()
        .unwrap_or(Duration::ZERO)
        .clamp(MIN_SLEEP, MAX_IDLE_SLEEP)
}

/// Run every due automation for one wallet and network, forever.
///
/// The loop itself is deliberately thin: sleep, run the due ones, hand the
/// reports to `observe`, repeat. Everything that decides anything is in
/// [`AutomationScheduler::run_due`], which a test can call directly at a moment
/// it names.
///
/// A pass that fails outright — the policy database is locked, the wallet has
/// no policy, the network was disabled — is reported and slept past rather than
/// ending the loop. The alternative is a scheduler that dies quietly on a
/// transient error and leaves every automation stopped with nothing on screen
/// to say so.
///
/// The network is named by chain ID and re-resolved every pass rather than
/// captured once. A long-lived loop holding a `NetworkConfig` from startup
/// would keep polling endpoints the owner has since replaced, and would keep
/// running against a network they have since disabled — the loop would be the
/// one component of the wallet for which editing a network did nothing until
/// restart.
pub async fn drive(
    scheduler: &AutomationScheduler,
    config: &ConfigStore,
    automations: &Mutex<AutomationStore>,
    pending: &Mutex<PendingStore>,
    policies: &Mutex<PolicyStore>,
    mut observe: impl FnMut(Result<Vec<TickReport>>),
) -> ! {
    loop {
        let at = tick_moment();
        let mut soonest: Option<DateTime<Utc>> = None;
        // Wallets and networks are re-read every pass rather than captured
        // once. A loop holding the startup list would keep polling endpoints
        // the owner has since replaced, keep running on a network they have
        // since disabled, and never notice an account they have since added —
        // it would be the one part of the wallet where editing configuration
        // did nothing until restart.
        match config.load() {
            Err(error) => observe(Err(error)),
            Ok(state) => {
                let networks: Vec<_> = state
                    .networks
                    .into_iter()
                    .filter(|network| !network.disabled)
                    .collect();
                for wallet in state.wallets {
                    for network in &networks {
                        let outcome = scheduler
                            .run_due(config, automations, pending, policies, &wallet, network, at)
                            .await;
                        let empty = outcome.as_ref().is_ok_and(Vec::is_empty);
                        if !empty {
                            observe(outcome);
                        }
                    }
                    if let Some(next) = next_fire_time(automations, &wallet, at) {
                        soonest = Some(soonest.map_or(next, |current| current.min(next)));
                    }
                }
            }
        }
        tokio::time::sleep(sleep_for(soonest, at)).await;
    }
}

/// The earliest moment any enabled automation of this wallet is next due.
///
/// A failure to read is not a failure to schedule: the driver falls back to its
/// idle ceiling and tries again, because a database that is briefly busy should
/// cost a wake-up, not the loop.
fn next_fire_time(
    automations: &Mutex<AutomationStore>,
    wallet: &WalletMetadata,
    at: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let installed = lock(automations)
        .ok()?
        .list_for_wallet(wallet.instance_id)
        .ok()?;
    installed
        .iter()
        .filter(|automation| automation.state == crate::automation::AutomationState::Enabled)
        .filter_map(|automation| match automation.last_tick_at {
            None => Some(at),
            Some(last) => automation.schedule.next_after(last),
        })
        .min()
}

#[cfg(test)]
#[path = "automation_scheduler_test.rs"]
mod tests;
