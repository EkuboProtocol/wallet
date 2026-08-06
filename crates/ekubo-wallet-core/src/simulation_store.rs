//! Simulation results a caller may send instead of simulating again.
//!
//! `eth_simulateV1` is by far the most expensive request this wallet makes, and
//! an agent that simulates a plan to show the user what it does used to pay for
//! that work twice: once for the preview, and once more inside the send, which
//! simulated the identical plan against the identical state seconds later.
//!
//! Recording the first result under an identifier lets the send consume it
//! rather than repeat it. What the send reuses is a complete, already
//! policy-evaluated result for one exact plan — not a promise about the chain.
//! Entries are therefore short-lived, bound to the wallet and chain they were
//! produced for, and consumed on use, so one simulation authorizes at most one
//! send. Anything stale, foreign, or already spent makes the caller simulate
//! again, which is the safe direction.
//!
//! Like forks, this lives only in this process. The approval CLI is a separate
//! process and deliberately re-simulates: a human deciding whether to sign
//! should be reading the chain as it is at that moment, not as it was when the
//! agent queued the request.

use crate::{core::execution_plan::ExecutionPlan, simulation::SimulationResult};
use anyhow::{Context, Result};
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::BTreeMap;
use uuid::Uuid;

/// How long a recorded simulation may still be sent. Short: the whole point of
/// simulating is to describe current state, and a result the chain has moved
/// away from is worth less than the request it saves.
pub const SIMULATION_TTL_SECONDS: i64 = 120;
/// Recorded simulations one wallet may hold.
pub const MAX_RECORDED_PER_WALLET: usize = 16;
/// Recorded simulations this process may hold across every wallet.
pub const MAX_RECORDED_SIMULATIONS: usize = 64;
/// Serialized plan bytes every recorded simulation may retain between them.
///
/// The count caps alone bound entries, not size, and a plan may be up to
/// `MAX_SERIALIZED_PLAN_BYTES` — so sixty-four of them is a gigabyte held in a
/// process that otherwise uses megabytes. Nothing legitimate approaches this:
/// a plan a person would send is kilobytes, and the cache exists to save an
/// RPC round trip rather than to hold a corpus.
pub const MAX_RECORDED_PLAN_BYTES: usize = 64 * 1024 * 1024;

/// One simulation result that has not been sent or expired yet.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordedSimulation {
    pub simulation_id: Uuid,
    pub wallet_id: String,
    pub chain_id: String,
    /// The exact plan that was simulated. The send takes the plan from here
    /// rather than from the caller, so there is no second copy to disagree.
    pub plan: ExecutionPlan,
    /// Where the plan's bytes came from — the vetted https host or
    /// "inline data URI" — carried through to approval-time display. None for
    /// plans this process built itself.
    pub plan_source: Option<String>,
    pub result: SimulationResult,
    pub recorded_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Serialized size of `plan`, measured once when recorded. Kept on the
    /// entry so the byte cap does not re-serialize every plan on every insert.
    pub plan_bytes: usize,
}

/// Recorded simulations, held only in this process.
#[derive(Debug, Default)]
pub struct SimulationStore {
    recorded: BTreeMap<Uuid, RecordedSimulation>,
}

impl SimulationStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a completed simulation and return its identifier.
    ///
    /// The caps evict the oldest entries rather than refusing: this is a cache
    /// of work already done, and failing a simulation the RPC has already
    /// executed because the cache is full would waste exactly what it exists
    /// to save.
    pub fn record(
        &mut self,
        wallet_id: &str,
        chain_id: &str,
        plan: ExecutionPlan,
        plan_source: Option<String>,
        result: SimulationResult,
        now: DateTime<Utc>,
    ) -> RecordedSimulation {
        self.prune(now);
        let plan_bytes = serde_json::to_vec(&plan).map_or(0, |bytes| bytes.len());
        let recorded = RecordedSimulation {
            simulation_id: Uuid::new_v4(),
            wallet_id: wallet_id.to_owned(),
            chain_id: chain_id.to_owned(),
            plan,
            plan_source,
            result,
            recorded_at: now,
            expires_at: now + TimeDelta::seconds(SIMULATION_TTL_SECONDS),
            plan_bytes,
        };
        self.recorded
            .insert(recorded.simulation_id, recorded.clone());
        // The per-wallet cap evicts that wallet's own oldest. Evicting the
        // globally oldest to satisfy a per-wallet limit lets one wallet's
        // traffic delete another wallet's recorded simulation — a cross-wallet
        // effect a per-wallet limit should not have, and one an agent driving
        // a busy wallet would trigger against a quiet one without trying.
        let owner = recorded.wallet_id.clone();
        self.evict_oldest_while(
            |store| {
                store
                    .recorded
                    .values()
                    .filter(|entry| entry.wallet_id == owner)
                    .count()
                    > MAX_RECORDED_PER_WALLET
            },
            Some(&owner),
            recorded.simulation_id,
        );
        self.evict_oldest_while(
            |store| store.recorded.len() > MAX_RECORDED_SIMULATIONS,
            None,
            recorded.simulation_id,
        );
        // Bytes, not just entries. One large plan can be worth thousands of
        // ordinary ones, so a cache bounded only by count is not bounded by
        // memory. The newest entry survives even when it alone exceeds the
        // budget: refusing to record a simulation the RPC has already executed
        // would throw away exactly the work this cache exists to save.
        self.evict_oldest_while(
            |store| store.retained_plan_bytes() > MAX_RECORDED_PLAN_BYTES,
            None,
            recorded.simulation_id,
        );
        recorded
    }

    /// Consume one recorded simulation. A second call for the same identifier
    /// finds nothing, so a result can never authorize two sends.
    pub fn take(&mut self, simulation_id: Uuid, now: DateTime<Utc>) -> Result<RecordedSimulation> {
        self.prune(now);
        self.recorded.remove(&simulation_id).with_context(|| {
            format!(
                "unknown, already sent, or expired simulation {simulation_id}. A recorded \
                 simulation is usable once and for {SIMULATION_TTL_SECONDS} seconds; call \
                 wallet_simulate_execution_plan again and send the new simulation_id."
            )
        })
    }

    /// Drop every expired entry.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.recorded.retain(|_, entry| entry.expires_at > now);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.recorded.len()
    }

    /// Serialized plan bytes currently retained across every entry.
    #[must_use]
    pub fn retained_plan_bytes(&self) -> usize {
        self.recorded
            .values()
            .map(|entry| entry.plan_bytes)
            .sum::<usize>()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recorded.is_empty()
    }

    /// Evict oldest-first until `over_cap` is satisfied.
    ///
    /// `keep` is never evicted. Entries recorded in the same instant tie on
    /// `recorded_at` and fall back to comparing UUIDs, so without this the
    /// row just inserted could be the one removed — and `record` would hand
    /// back a `simulation_id` that no longer exists, which the caller learns
    /// only when sending it fails.
    ///
    /// `wallet_id` scopes the eviction, so a per-wallet cap cannot reach
    /// another wallet's entries.
    fn evict_oldest_while(
        &mut self,
        over_cap: impl Fn(&Self) -> bool,
        wallet_id: Option<&str>,
        keep: Uuid,
    ) {
        while over_cap(self) {
            let Some(oldest) = self
                .recorded
                .values()
                .filter(|entry| entry.simulation_id != keep)
                .filter(|entry| wallet_id.is_none_or(|wallet| entry.wallet_id == wallet))
                .min_by_key(|entry| (entry.recorded_at, entry.simulation_id))
                .map(|entry| entry.simulation_id)
            else {
                return;
            };
            self.recorded.remove(&oldest);
        }
    }
}

#[cfg(test)]
#[path = "simulation_store_test.rs"]
mod tests;
