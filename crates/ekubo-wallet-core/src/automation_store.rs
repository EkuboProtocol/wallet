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

/// The longest caller-chosen key an automation may carry. Long enough for a
/// descriptive name or a UUID, short enough that it stays a label.
pub const MAX_KEY_LEN: usize = 120;

pub struct AutomationStore {
    database: PolicyStore,
}

/// Whether recording a tick counts as evidence the automation is healthy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClearFailures {
    Yes,
    No,
}

/// One tick that ran, and what came of it.
///
/// The automation row carries only the latest outcome, which answers "is it
/// working right now". This answers the question a person actually has about
/// something that runs unattended: what has it been doing, and which
/// transactions did it make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomationRun {
    pub run_id: Uuid,
    pub automation_id: Uuid,
    pub ran_at: DateTime<Utc>,
    pub outcome: RunOutcome,
    /// Owner-facing account of the tick, in the same words the tab shows.
    pub detail: String,
    /// The transaction this tick produced, when it produced one. Its
    /// lifecycle row is hidden rather than deleted when history is cleared, so
    /// this keeps resolving.
    pub request_id: Option<Uuid>,
    pub calls: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    Skipped,
    Idle,
    Sent,
    Stopped,
    Failed,
}

impl RunOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skipped => "skipped",
            Self::Idle => "idle",
            Self::Sent => "sent",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    /// What the tab writes on the row, so every run reads as a sentence
    /// rather than as a status word the reader has to decode.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Skipped => "Skipped",
            Self::Idle => "Nothing to do",
            Self::Sent => "Sent",
            Self::Stopped => "Stopped",
            Self::Failed => "Failed",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "skipped" => Ok(Self::Skipped),
            "idle" => Ok(Self::Idle),
            "sent" => Ok(Self::Sent),
            "stopped" => Ok(Self::Stopped),
            "failed" => Ok(Self::Failed),
            other => anyhow::bail!("unknown automation run outcome {other:?}"),
        }
    }
}

/// How many runs one automation keeps.
///
/// A per-second schedule produces 86,400 rows a day, almost all of them
/// "nothing to do", and an unbounded log would grow without ever being read.
/// The cap is generous enough to cover weeks of a normal schedule and days of
/// an aggressive one, and old rows are dropped oldest-first.
pub const MAX_RUNS_PER_AUTOMATION: usize = 2_000;

/// The result of an install, which is the same operation whether it created
/// something or replaced it.
///
/// `replaced` is what the caller reports back: an agent retrying a timed-out
/// call wants to hear that nothing new happened, and one that meant to install
/// a second automation wants to hear that it just overwrote its first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub automation: Automation,
    pub replaced: Option<Automation>,
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

    /// Install an automation under a caller-chosen key, replacing whatever that
    /// key already named.
    ///
    /// The key is what makes installing idempotent. An agent whose tool call
    /// timed out after the write landed retries with the same key and gets the
    /// same automation back rather than a second one — two identical
    /// automations on one wallet would contend for one signing slot and each
    /// report the other as the reason it skipped, which is a confusing way to
    /// discover you installed something twice.
    ///
    /// Replacement is not an escalation. Every call an automation emits is
    /// evaluated against the installed policy at send time, so swapping the
    /// bytecode under a key buys no authority the policy does not already
    /// grant. What it does do is reset the automation's history — the failure
    /// count, the stopped reason, the pointer to the last transaction — because
    /// those describe the bytecode that was there before, and reporting them
    /// against different bytecode would be a lie.
    ///
    /// `policy_revision` is the revision the caller wrote this automation for.
    /// The caller checks it against the active one; binding it here is what
    /// later ticks compare against.
    pub fn install(
        &mut self,
        wallet: &WalletMetadata,
        key: &str,
        definition: &AutomationDefinition,
        policy_revision: u64,
    ) -> Result<Installed> {
        ensure!(policy_revision > 0, "policy revision must be positive");
        let key = key.trim();
        ensure!(!key.is_empty(), "automation key is empty");
        ensure!(
            key.chars().count() <= MAX_KEY_LEN,
            "automation key exceeds {MAX_KEY_LEN} characters"
        );
        ensure!(
            !key.chars().any(crate::sanitize::is_disallowed),
            "automation key contains a control, bidirectional, or invisible character"
        );
        let replaced = self.by_key(wallet.instance_id, key)?;
        if replaced.is_none() {
            let existing = self.count_for(wallet.instance_id, definition.chain_id())?;
            ensure!(
                existing < MAX_AUTOMATIONS_PER_WALLET_CHAIN,
                "wallet already has {existing} automations on chain {}, the limit is \
                 {MAX_AUTOMATIONS_PER_WALLET_CHAIN}",
                definition.chain_id()
            );
        }
        let id = replaced
            .as_ref()
            .map_or_else(Uuid::new_v4, |existing| existing.id);
        let at = now();
        self.database.connection.execute(
            "INSERT INTO automations (
                 automation_id, wallet_instance_id, wallet_id, wallet_address, chain_id,
                 automation_key, name, bytecode, config, cron_expression, policy_revision,
                 state, stopped_reason, consecutive_failures, last_tick_at, last_outcome,
                 last_request_id, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       'enabled', NULL, 0, NULL, NULL, NULL, ?12, ?12)
             ON CONFLICT(automation_id) DO UPDATE SET
                 chain_id = excluded.chain_id,
                 name = excluded.name,
                 bytecode = excluded.bytecode,
                 config = excluded.config,
                 cron_expression = excluded.cron_expression,
                 policy_revision = excluded.policy_revision,
                 state = 'enabled',
                 stopped_reason = NULL,
                 consecutive_failures = 0,
                 last_tick_at = NULL,
                 last_outcome = NULL,
                 last_request_id = NULL,
                 updated_at = excluded.updated_at",
            params![
                Blob(*id.as_bytes()),
                wallet.instance_id.to_string(),
                wallet.id,
                format!("{:#x}", wallet.address),
                i64::try_from(definition.chain_id()).context("chain id out of range")?,
                key,
                definition.name(),
                Blob(definition.bytecode().clone()),
                Blob(definition.config().clone()),
                definition.schedule().expression(),
                i64::try_from(policy_revision).context("policy revision out of range")?,
                Millis(at),
            ],
        )?;
        let automation = self.get(id)?.context("installed automation missing")?;
        Ok(Installed {
            automation,
            replaced,
        })
    }

    /// Append one tick to an automation's history.
    ///
    /// Every tick is recorded, including the ones that did nothing: "it ran
    /// and there was nothing to do" is the answer to most of the questions
    /// someone asks of an automation, and a log that only kept the
    /// interesting rows could not distinguish a quiet job from a stopped one.
    pub fn record_run(
        &mut self,
        automation_id: Uuid,
        outcome: RunOutcome,
        detail: &str,
        request_id: Option<Uuid>,
        calls: u32,
        at: DateTime<Utc>,
    ) -> Result<()> {
        let transaction = self.database.connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO automation_runs (
                 run_id, automation_id, ran_at, outcome, detail, request_id, calls
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                Blob(*Uuid::new_v4().as_bytes()),
                Blob(*automation_id.as_bytes()),
                Millis(at),
                outcome.as_str(),
                detail,
                request_id.map(|id| Blob(*id.as_bytes())),
                calls,
            ],
        )?;
        // Trimmed on the way in, so the log is bounded by the activity that
        // produces it rather than by a sweep somebody has to remember.
        transaction.execute(
            "DELETE FROM automation_runs
             WHERE run_id IN (
                 SELECT run_id FROM automation_runs
                 WHERE automation_id = ?1
                 ORDER BY ran_at DESC, run_id DESC
                 LIMIT -1 OFFSET ?2
             )",
            params![
                Blob(*automation_id.as_bytes()),
                i64::try_from(MAX_RUNS_PER_AUTOMATION).context("run cap out of range")?
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// One automation's runs, newest first.
    pub fn runs(&self, automation_id: Uuid, limit: usize) -> Result<Vec<AutomationRun>> {
        let mut statement = self.database.connection.prepare(
            "SELECT run_id, automation_id, ran_at, outcome, detail, request_id, calls
             FROM automation_runs WHERE automation_id = ?1
             ORDER BY ran_at DESC, run_id DESC LIMIT ?2",
        )?;
        let rows = statement
            .query_map(
                params![
                    Blob(*automation_id.as_bytes()),
                    i64::try_from(limit).context("run limit out of range")?
                ],
                |row| {
                    let run_id: [u8; 16] = row.blob(0)?;
                    let automation_id: [u8; 16] = row.blob(1)?;
                    let ran_at = row.time(2)?;
                    let outcome: String = row.get(3)?;
                    let detail: String = row.get(4)?;
                    let request_id: Option<[u8; 16]> = row.blob_opt(5)?;
                    let calls: i64 = row.get(6)?;
                    Ok((
                        run_id,
                        automation_id,
                        ran_at,
                        outcome,
                        detail,
                        request_id,
                        calls,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(
                |(run_id, automation_id, ran_at, outcome, detail, request_id, calls)| {
                    Ok(AutomationRun {
                        run_id: Uuid::from_bytes(run_id),
                        automation_id: Uuid::from_bytes(automation_id),
                        ran_at,
                        outcome: RunOutcome::parse(&outcome)?,
                        detail,
                        request_id: request_id.map(Uuid::from_bytes),
                        calls: u32::try_from(calls).context("stored run call count is invalid")?,
                    })
                },
            )
            .collect()
    }

    /// The automation this wallet keeps under `key`, if any.
    pub fn by_key(&self, wallet_instance_id: Uuid, key: &str) -> Result<Option<Automation>> {
        self.database
            .connection
            .query_row(
                &format!(
                    "SELECT {COLUMNS} FROM automations
                     WHERE wallet_instance_id = ?1 AND automation_key = ?2"
                ),
                params![wallet_instance_id.to_string(), key],
                read_automation,
            )
            .optional()?
            .transpose()
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
     automation_key, name, bytecode, config, cron_expression, policy_revision, state, stopped_reason, \
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
    let key: String = row.get(5)?;
    let name: String = row.get(6)?;
    let bytecode: Bytes = row.blob(7)?;
    let config: Bytes = row.blob(8)?;
    let cron_expression: String = row.get(9)?;
    let policy_revision: i64 = row.get(10)?;
    let state: String = row.get(11)?;
    let stopped_reason: Option<String> = row.get(12)?;
    let consecutive_failures: i64 = row.get(13)?;
    let last_tick_at = row.time_opt(14)?;
    let last_outcome: Option<String> = row.get(15)?;
    let last_request_id: Option<[u8; 16]> = row.blob_opt(16)?;
    let created_at = row.time(17)?;
    let updated_at = row.time(18)?;
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
            key,
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
