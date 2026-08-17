//! Installed automations, and the bookkeeping one tick leaves behind.
//!
//! Every read that the scheduler acts on goes through here, and every write
//! that stops an automation does too, so "is this thing allowed to run" has one
//! answer in one place. The interesting rule is [`AutomationStore::due`]: it
//! compares each automation's bound policy revision against the wallet's
//! current one and moves any that disagree to
//! [`AutomationState::AwaitingRelink`] rather than returning them. A tick
//! cannot run an automation whose authority the owner has replaced, and it
//! cannot do so by accident either, because the check happens where the work
//! list is produced rather than somewhere a future caller might forget.

use crate::{
    automation::{Automation, AutomationDefinition, AutomationState, CronSchedule},
    config::WalletMetadata,
    policy_store::PolicyStore,
    sql::{Blob, Millis, RowExt, now},
};
use alloy::primitives::{Address, Bytes};
use anyhow::{Context as _, Result, ensure};
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension as _, params};
use std::path::Path;
use uuid::Uuid;

/// How many automations one wallet and chain may hold.
///
/// Each one is an independent RPC conversation on its own schedule, so the
/// ceiling is about what the endpoint and the Automations tab can carry, not
/// about storage. Small enough that the list stays a list a person reads.
pub const MAX_AUTOMATIONS_PER_WALLET_CHAIN: usize = 32;

pub struct AutomationStore {
    database: PolicyStore,
}

/// Whether recording a tick counts as evidence the automation is healthy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClearFailures {
    Yes,
    No,
}

/// What [`AutomationStore::due`] found, kept apart from the automations
/// themselves so a caller cannot mistake "nothing to run" for "nothing
/// happened".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DueAutomations {
    /// Enabled, bound to the current policy revision, and scheduled to have
    /// fired by now.
    pub ready: Vec<Automation>,
    /// Moved to `awaiting_relink` by this call because the policy revision
    /// moved underneath them. Reported so the caller can notify the owner
    /// exactly once, on the transition.
    pub unlinked: Vec<Automation>,
}

impl AutomationStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            database: PolicyStore::production(data_dir)?,
        })
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    /// Install an automation the owner has approved, bound to the policy
    /// revision they approved it under.
    ///
    /// `policy_revision` is a parameter rather than something read here on
    /// purpose: the caller has already shown the owner a review that named a
    /// revision, and re-reading it at this line would bind to whatever is
    /// current now, which is not necessarily what they were shown.
    pub fn install(
        &mut self,
        wallet: &WalletMetadata,
        definition: &AutomationDefinition,
        policy_revision: u64,
    ) -> Result<Automation> {
        ensure!(policy_revision > 0, "policy revision must be positive");
        let existing = self.count_for(wallet.instance_id, definition.chain_id())?;
        ensure!(
            existing < MAX_AUTOMATIONS_PER_WALLET_CHAIN,
            "wallet already has {existing} automations on chain {}, the limit is \
             {MAX_AUTOMATIONS_PER_WALLET_CHAIN}",
            definition.chain_id()
        );
        let id = Uuid::new_v4();
        let created_at = now();
        self.database.connection.execute(
            "INSERT INTO automations (
                 automation_id, wallet_instance_id, wallet_id, wallet_address, chain_id,
                 name, bytecode, config, cron_expression, policy_revision, state,
                 stopped_reason, consecutive_failures, last_tick_at, last_outcome,
                 created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'enabled', NULL, 0, NULL, NULL, ?11, ?11)",
            params![
                Blob(*id.as_bytes()),
                wallet.instance_id.to_string(),
                wallet.id,
                format!("{:#x}", wallet.address),
                i64::try_from(definition.chain_id()).context("chain id out of range")?,
                definition.name(),
                Blob(definition.bytecode().clone()),
                Blob(definition.config().clone()),
                definition.schedule().expression(),
                i64::try_from(policy_revision).context("policy revision out of range")?,
                Millis(created_at),
            ],
        )?;
        self.get(id)?.context("installed automation missing")
    }

    pub fn get(&self, id: Uuid) -> Result<Option<Automation>> {
        self.database
            .connection
            .query_row(
                &format!("SELECT {COLUMNS} FROM automations WHERE automation_id = ?1"),
                params![Blob(*id.as_bytes())],
                read_automation,
            )
            .optional()?
            .transpose()
    }

    /// Every automation belonging to one wallet, newest first.
    pub fn list_for_wallet(&self, wallet_instance_id: Uuid) -> Result<Vec<Automation>> {
        let mut statement = self.database.connection.prepare(&format!(
            "SELECT {COLUMNS} FROM automations WHERE wallet_instance_id = ?1
             ORDER BY created_at DESC"
        ))?;
        let rows = statement
            .query_map(params![wallet_instance_id.to_string()], read_automation)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().collect()
    }

    /// The automations a scheduler should run now, having first unlinked any
    /// whose bound policy revision no longer matches `current_revision`.
    ///
    /// `at` is passed in rather than read from the clock so that a caller
    /// deciding a batch of automations decides all of them against one moment,
    /// and so a test can name the moment it means.
    ///
    /// An automation with no recorded tick is due immediately: it was installed
    /// to run, and making it wait for its first scheduled moment would mean an
    /// hourly job installed at 12:01 does nothing until 13:00 with no
    /// explanation on screen.
    pub fn due(
        &mut self,
        wallet_instance_id: Uuid,
        current_revision: u64,
        at: DateTime<Utc>,
    ) -> Result<DueAutomations> {
        let mut found = DueAutomations::default();
        for automation in self.list_for_wallet(wallet_instance_id)? {
            if automation.state != AutomationState::Enabled {
                continue;
            }
            if automation.policy_revision != current_revision {
                let unlinked = self.mark_awaiting_relink(automation.id, current_revision)?;
                found.unlinked.push(unlinked);
                continue;
            }
            let due = match automation.last_tick_at {
                None => true,
                Some(last) => automation
                    .schedule
                    .next_after(last)
                    .is_some_and(|next| next <= at),
            };
            if due {
                found.ready.push(automation);
            }
        }
        Ok(found)
    }

    /// Record that a tick ran and produced no transaction — the blob returned
    /// an empty list, or its calls were sent.
    ///
    /// Clears the failure count: a tick that ran is evidence the automation and
    /// the endpoint both work, and a count that only ever rose would eventually
    /// disable an automation that had been healthy for a month.
    pub fn record_tick(&mut self, id: Uuid, outcome: &str, at: DateTime<Utc>) -> Result<()> {
        self.write_tick(id, outcome, at, ClearFailures::Yes)
    }

    /// Record a tick that never got as far as running: the wallet and chain's
    /// signing slot was held, so there was nothing to poll against that the
    /// result could be sent from.
    ///
    /// Consumes the tick — the design skips rather than defers, so the schedule
    /// moves on — but deliberately leaves the failure count alone. A skip is not
    /// evidence of health: an automation nine failures deep that happens to land
    /// on one busy slot would otherwise reset to zero and could then fail
    /// forever without ever reaching the limit that stops it.
    pub fn record_skip(&mut self, id: Uuid, reason: &str, at: DateTime<Utc>) -> Result<()> {
        self.write_tick(id, reason, at, ClearFailures::No)
    }

    /// Record that a tick's calls became a transaction, and which one.
    ///
    /// The pointer is how a later tick learns what became of it: whether it
    /// confirmed, reverted, or is still sitting in the mempool holding the
    /// signing slot. Without it an automation would have to guess from the
    /// wallet's in-flight row, which any other sender could also own.
    pub fn record_send(
        &mut self,
        id: Uuid,
        request_id: Uuid,
        outcome: &str,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let changed = self.database.connection.execute(
            "UPDATE automations
             SET last_tick_at = ?2, last_outcome = ?3, last_request_id = ?4,
                 consecutive_failures = 0, updated_at = ?2
             WHERE automation_id = ?1",
            params![
                Blob(*id.as_bytes()),
                Millis(at),
                outcome,
                Blob(*request_id.as_bytes()),
            ],
        )?;
        ensure!(changed == 1, "automation {id} is not installed");
        Ok(())
    }

    fn write_tick(
        &mut self,
        id: Uuid,
        outcome: &str,
        at: DateTime<Utc>,
        clear: ClearFailures,
    ) -> Result<()> {
        let statement = match clear {
            ClearFailures::Yes => {
                "UPDATE automations
                 SET last_tick_at = ?2, last_outcome = ?3, consecutive_failures = 0,
                     updated_at = ?2
                 WHERE automation_id = ?1"
            }
            ClearFailures::No => {
                "UPDATE automations
                 SET last_tick_at = ?2, last_outcome = ?3, updated_at = ?2
                 WHERE automation_id = ?1"
            }
        };
        let changed = self.database.connection.execute(
            statement,
            params![Blob(*id.as_bytes()), Millis(at), outcome],
        )?;
        ensure!(changed == 1, "automation {id} is not installed");
        Ok(())
    }

    /// Record a failed tick, disabling the automation once
    /// [`crate::automation::MAX_CONSECUTIVE_FAILURES`] of them have happened in
    /// a row. Returns the automation as it now stands.
    pub fn record_failure(
        &mut self,
        id: Uuid,
        outcome: &str,
        at: DateTime<Utc>,
    ) -> Result<Automation> {
        let transaction = self.database.connection.unchecked_transaction()?;
        let failures: i64 = transaction
            .query_row(
                "SELECT consecutive_failures FROM automations WHERE automation_id = ?1",
                params![Blob(*id.as_bytes())],
                |row| row.get(0),
            )
            .optional()?
            .with_context(|| format!("automation {id} is not installed"))?;
        let failures = failures.saturating_add(1);
        let limit = i64::from(crate::automation::MAX_CONSECUTIVE_FAILURES);
        if failures >= limit {
            transaction.execute(
                "UPDATE automations
                 SET state = 'disabled', stopped_reason = ?3, consecutive_failures = ?4,
                     last_tick_at = ?2, last_outcome = ?5, updated_at = ?2
                 WHERE automation_id = ?1",
                params![
                    Blob(*id.as_bytes()),
                    Millis(at),
                    format!("stopped after {failures} consecutive failed ticks: {outcome}"),
                    failures,
                    outcome,
                ],
            )?;
        } else {
            transaction.execute(
                "UPDATE automations
                 SET consecutive_failures = ?3, last_tick_at = ?2, last_outcome = ?4,
                     updated_at = ?2
                 WHERE automation_id = ?1",
                params![Blob(*id.as_bytes()), Millis(at), failures, outcome],
            )?;
        }
        transaction.commit()?;
        self.get(id)?.context("automation vanished mid-update")
    }

    /// Stop an automation and say why. The reason is what the Automations tab
    /// shows and the only account the owner gets, so callers pass the specific
    /// failure rather than a category.
    pub fn disable(&mut self, id: Uuid, reason: &str) -> Result<Automation> {
        ensure!(!reason.trim().is_empty(), "a disable needs a reason");
        let changed = self.database.connection.execute(
            "UPDATE automations
             SET state = 'disabled', stopped_reason = ?2, updated_at = ?3
             WHERE automation_id = ?1",
            params![Blob(*id.as_bytes()), reason, Millis(now())],
        )?;
        ensure!(changed == 1, "automation {id} is not installed");
        self.get(id)?.context("automation vanished mid-update")
    }

    /// Rebind an automation to the current policy revision and start it again.
    ///
    /// The only way back to `Enabled`, and it always rebinds — which is why
    /// re-enabling something the owner disabled is the same operation as
    /// relinking something the policy moved out from under. Both are the owner
    /// saying "yes, run this, under what my policy says now".
    pub fn relink(&mut self, id: Uuid, policy_revision: u64) -> Result<Automation> {
        ensure!(policy_revision > 0, "policy revision must be positive");
        let changed = self.database.connection.execute(
            "UPDATE automations
             SET state = 'enabled', stopped_reason = NULL, policy_revision = ?2,
                 consecutive_failures = 0, updated_at = ?3
             WHERE automation_id = ?1",
            params![
                Blob(*id.as_bytes()),
                i64::try_from(policy_revision).context("policy revision out of range")?,
                Millis(now()),
            ],
        )?;
        ensure!(changed == 1, "automation {id} is not installed");
        self.get(id)?.context("automation vanished mid-update")
    }

    pub fn remove(&mut self, id: Uuid) -> Result<bool> {
        let changed = self.database.connection.execute(
            "DELETE FROM automations WHERE automation_id = ?1",
            params![Blob(*id.as_bytes())],
        )?;
        Ok(changed == 1)
    }

    fn mark_awaiting_relink(&mut self, id: Uuid, current_revision: u64) -> Result<Automation> {
        let changed = self.database.connection.execute(
            "UPDATE automations
             SET state = 'awaiting_relink', stopped_reason = ?2, updated_at = ?3
             WHERE automation_id = ?1 AND state = 'enabled'",
            params![
                Blob(*id.as_bytes()),
                format!(
                    "the signing policy changed to revision {current_revision} after this \
                     automation was installed; review it again to run it under the new policy"
                ),
                Millis(now()),
            ],
        )?;
        ensure!(changed == 1, "automation {id} is not installed");
        self.get(id)?.context("automation vanished mid-update")
    }

    fn count_for(&self, wallet_instance_id: Uuid, chain_id: u64) -> Result<usize> {
        let count: i64 = self.database.connection.query_row(
            "SELECT count(*) FROM automations WHERE wallet_instance_id = ?1 AND chain_id = ?2",
            params![
                wallet_instance_id.to_string(),
                i64::try_from(chain_id).context("chain id out of range")?
            ],
            |row| row.get(0),
        )?;
        usize::try_from(count).context("automation count out of range")
    }
}

const COLUMNS: &str = "automation_id, wallet_instance_id, wallet_id, wallet_address, chain_id, \
     name, bytecode, config, cron_expression, policy_revision, state, stopped_reason, \
     consecutive_failures, last_tick_at, last_outcome, last_request_id, created_at, updated_at";

/// Rebuild one row.
///
/// Returns a nested result because a row can be well-formed as SQL and still
/// not describe an automation — a cron expression this build no longer parses,
/// a state name it does not know. Those are corruption or a downgrade, and they
/// deserve the error they get rather than a row silently dropped from a list
/// the owner reads as complete.
fn read_automation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Automation>> {
    let id: [u8; 16] = row.blob(0)?;
    let wallet_instance_id: String = row.get(1)?;
    let wallet_id: String = row.get(2)?;
    let wallet_address: String = row.get(3)?;
    let chain_id: i64 = row.get(4)?;
    let name: String = row.get(5)?;
    let bytecode: Bytes = row.blob(6)?;
    let config: Bytes = row.blob(7)?;
    let cron_expression: String = row.get(8)?;
    let policy_revision: i64 = row.get(9)?;
    let state: String = row.get(10)?;
    let stopped_reason: Option<String> = row.get(11)?;
    let consecutive_failures: i64 = row.get(12)?;
    let last_tick_at = row.time_opt(13)?;
    let last_outcome: Option<String> = row.get(14)?;
    let last_request_id: Option<[u8; 16]> = row.blob_opt(15)?;
    let created_at = row.time(16)?;
    let updated_at = row.time(17)?;
    Ok((|| {
        Ok(Automation {
            id: Uuid::from_bytes(id),
            wallet_instance_id: wallet_instance_id
                .parse()
                .context("stored automation wallet instance id is not a UUID")?,
            wallet_id,
            wallet_address: wallet_address
                .parse::<Address>()
                .context("stored automation wallet address is not an address")?,
            chain_id: u64::try_from(chain_id).context("stored automation chain id is invalid")?,
            name,
            bytecode,
            config,
            schedule: CronSchedule::parse(&cron_expression)?,
            policy_revision: u64::try_from(policy_revision)
                .context("stored automation policy revision is invalid")?,
            state: AutomationState::parse(&state)?,
            stopped_reason,
            consecutive_failures: u32::try_from(consecutive_failures)
                .context("stored automation failure count is invalid")?,
            last_tick_at,
            last_outcome,
            last_request_id: last_request_id.map(Uuid::from_bytes),
            created_at,
            updated_at,
        })
    })())
}

#[cfg(test)]
#[path = "automation_store_test.rs"]
mod tests;
