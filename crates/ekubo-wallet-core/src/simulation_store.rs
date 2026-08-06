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

/// One simulation result that has not been sent or expired yet.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordedSimulation {
    pub simulation_id: Uuid,
    pub wallet_id: String,
    pub chain_id: String,
    /// The exact plan that was simulated. The send takes the plan from here
    /// rather than from the caller, so there is no second copy to disagree.
    pub plan: ExecutionPlan,
    pub result: SimulationResult,
    pub recorded_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
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
        result: SimulationResult,
        now: DateTime<Utc>,
    ) -> RecordedSimulation {
        self.prune(now);
        let recorded = RecordedSimulation {
            simulation_id: Uuid::new_v4(),
            wallet_id: wallet_id.to_owned(),
            chain_id: chain_id.to_owned(),
            plan,
            result,
            recorded_at: now,
            expires_at: now + TimeDelta::seconds(SIMULATION_TTL_SECONDS),
        };
        self.recorded
            .insert(recorded.simulation_id, recorded.clone());
        self.evict_oldest_while(|store| {
            store
                .recorded
                .values()
                .filter(|entry| entry.wallet_id == recorded.wallet_id)
                .count()
                > MAX_RECORDED_PER_WALLET
                || store.recorded.len() > MAX_RECORDED_SIMULATIONS
        });
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

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recorded.is_empty()
    }

    fn evict_oldest_while(&mut self, over_cap: impl Fn(&Self) -> bool) {
        while over_cap(self) {
            let Some(oldest) = self
                .recorded
                .values()
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
mod tests {
    use super::*;
    use crate::{
        config::default_networks,
        core::policy::WalletPolicy,
        policy_store::StoredPolicy,
        simulation::{ExecutionMode, SimulationExecution},
    };
    use serde_json::json;

    fn plan(value: &str) -> ExecutionPlan {
        ExecutionPlan::parse(json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0x",
                    "value": value
                }
            }]
        }))
        .unwrap()
    }

    fn result(plan: &ExecutionPlan) -> SimulationResult {
        SimulationResult {
            simulation_id: None,
            digest: format!("{:#x}", plan.digest()),
            allowed: true,
            policy_findings: Vec::new(),
            policy_revision: 1,
            execution_mode: ExecutionMode::Direct,
            implementation: None,
            will_authorize_delegation: false,
            replaces_delegated_implementation: None,
            simulation: SimulationExecution {
                success: true,
                gas_used: Some("21000".into()),
                block_gas_limit: Some("30000000".into()),
                output: None,
                error: None,
                failure: None,
            },
            token_spends: BTreeMap::new(),
            balance_changes: None,
            block_number: "100".into(),
            fork: None,
        }
    }

    fn record(store: &mut SimulationStore, value: &str, now: DateTime<Utc>) -> RecordedSimulation {
        let plan = plan(value);
        let result = result(&plan);
        store.record("primary", "1", plan, result, now)
    }

    #[test]
    fn a_recorded_simulation_is_returned_once_and_only_once() {
        let now = Utc::now();
        let mut store = SimulationStore::new();
        let recorded = record(&mut store, "1", now);
        let taken = store.take(recorded.simulation_id, now).unwrap();
        assert_eq!(taken.plan, recorded.plan);
        assert!(store.is_empty());
        let error = store
            .take(recorded.simulation_id, now)
            .expect_err("a simulation must not authorize a second send");
        assert!(error.to_string().contains("already sent"));
    }

    #[test]
    fn an_expired_simulation_is_indistinguishable_from_one_that_never_existed() {
        let now = Utc::now();
        let mut store = SimulationStore::new();
        let recorded = record(&mut store, "1", now);
        let later = now + TimeDelta::seconds(SIMULATION_TTL_SECONDS + 1);
        let error = store
            .take(recorded.simulation_id, later)
            .expect_err("an expired simulation must not be sendable");
        assert!(error.to_string().contains("expired"));
        assert!(store.is_empty());
        let unknown = store
            .take(Uuid::new_v4(), now)
            .expect_err("an unknown simulation must not resolve");
        assert!(unknown.to_string().contains("unknown"));
    }

    #[test]
    fn the_cap_evicts_the_oldest_rather_than_refusing_new_work() {
        let mut store = SimulationStore::new();
        let now = Utc::now();
        let first = record(&mut store, "1", now);
        for index in 2..=MAX_RECORDED_PER_WALLET + 1 {
            record(
                &mut store,
                &index.to_string(),
                now + TimeDelta::milliseconds(i64::try_from(index).unwrap()),
            );
        }
        assert_eq!(store.len(), MAX_RECORDED_PER_WALLET);
        assert!(store.take(first.simulation_id, now).is_err());
    }

    /// A simulation carries the policy revision it was evaluated under, which
    /// is what lets the send refuse a result the current policy never saw.
    #[test]
    fn a_recorded_result_names_the_policy_revision_it_was_evaluated_under() {
        let stored = StoredPolicy {
            wallet_id: "primary".into(),
            policy: WalletPolicy::allow_all_with_approval(),
            revision: 7,
            updated_at: Utc::now(),
        };
        let plan = plan("1");
        let mut result = result(&plan);
        result.policy_revision = stored.revision;
        let mut store = SimulationStore::new();
        let now = Utc::now();
        let recorded = store.record("primary", "1", plan, result, now);
        assert_eq!(recorded.result.policy_revision, 7);
        assert_eq!(
            recorded.chain_id,
            default_networks()[0].chain_id.to_string()
        );
    }
}
