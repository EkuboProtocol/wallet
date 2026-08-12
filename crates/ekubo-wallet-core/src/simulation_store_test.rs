//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

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
        policy_outcome: crate::core::policy::PolicyOutcome::Allowed,
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
    store.record("primary", "1", plan, None, result, now)
}

#[test]
fn a_recorded_simulation_id_is_always_usable_when_it_is_returned() {
    // Every entry shares one timestamp, so the oldest-first ordering falls
    // back to comparing UUIDs — which the newest row loses about half the
    // time. Returning an id that eviction just removed hands the caller
    // something that fails only when they try to send it.
    let now = Utc::now();
    let mut store = SimulationStore::new();
    for index in 0..MAX_RECORDED_PER_WALLET * 3 {
        let recorded = record(&mut store, &index.to_string(), now);
        assert!(
            store.take(recorded.simulation_id, now).is_ok(),
            "record returned an id it had already evicted"
        );
        // Put it back so the cap keeps being exercised.
        record(&mut store, &index.to_string(), now);
    }
}

#[test]
fn the_cache_is_bounded_by_bytes_and_not_only_by_count() {
    // Sixteen entries is well under every count cap, so only the byte
    // budget can bound what this retains.
    let now = Utc::now();
    let mut store = SimulationStore::new();
    for index in 1..=MAX_RECORDED_PER_WALLET {
        let plan = plan(&index.to_string());
        let result = result(&plan);
        store.record("primary", "1", plan, None, result, now);
    }
    assert!(store.len() <= MAX_RECORDED_PER_WALLET);
    assert!(
        store.retained_plan_bytes() <= MAX_RECORDED_PLAN_BYTES,
        "retained {} bytes",
        store.retained_plan_bytes()
    );
    // Every entry measured something, so the budget is being computed from
    // real sizes rather than from a zero that would never trip it.
    assert!(store.retained_plan_bytes() > 0);
}

#[test]
fn one_wallet_cannot_evict_another_wallets_simulations() {
    let now = Utc::now();
    let mut store = SimulationStore::new();
    let quiet_plan = plan("1");
    let quiet_result = result(&quiet_plan);
    let quiet = store.record("quiet", "1", quiet_plan, None, quiet_result, now);

    // A busy wallet fills its own per-wallet allowance several times over.
    for index in 2..MAX_RECORDED_PER_WALLET * 2 {
        let plan = plan(&index.to_string());
        let result = result(&plan);
        store.record("busy", "1", plan, None, result, now);
    }

    assert!(
        store.take(quiet.simulation_id, now).is_ok(),
        "a busy wallet evicted a quiet wallet's simulation"
    );
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
        policy: WalletPolicy::allow_anything(),
        revision: 7,
        updated_at: Utc::now(),
    };
    let plan = plan("1");
    let mut result = result(&plan);
    result.policy_revision = stored.revision;
    let mut store = SimulationStore::new();
    let now = Utc::now();
    let recorded = store.record("primary", "1", plan, None, result, now);
    assert_eq!(recorded.result.policy_revision, 7);
    assert_eq!(
        recorded.chain_id,
        default_networks()[0].chain_id.to_string()
    );
}

/// The TTL is wall-clock arithmetic on a value the host can move backwards --
/// an NTP correction, a manual change, a laptop resuming with a stale RTC.
/// Compared against a later wall-clock reading alone, a rollback makes a
/// recorded simulation look younger than it is and keeps it sendable past the
/// window it was given, so an automatic send can sign against chain state the
/// simulation no longer describes.
#[test]
fn a_clock_that_moved_backwards_does_not_refresh_a_simulation() {
    let at = "2026-01-01T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let built = plan("1");
    let outcome = result(&built);

    // Inside the window and moving forward: usable, as before.
    let mut store = SimulationStore::default();
    let recorded = store.record("primary", "1", built.clone(), None, outcome.clone(), at);
    assert!(
        store
            .take(recorded.simulation_id, at + TimeDelta::seconds(60))
            .is_ok()
    );

    // The clock moved behind the moment it was recorded. Elapsed time is no
    // longer knowable, and the safe reading of that is "too long", not "fresh".
    let mut store = SimulationStore::default();
    let recorded = store.record("primary", "1", built, None, outcome, at);
    let error = format!(
        "{:#}",
        store
            .take(recorded.simulation_id, at - TimeDelta::seconds(1))
            .unwrap_err()
    );
    assert!(error.contains("expired simulation"), "{error}");
}

/// And the ordinary boundary is unchanged: the deadline still ends it.
#[test]
fn the_ordinary_expiry_boundary_is_unchanged() {
    let at = "2026-01-01T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
    let built = plan("1");
    let outcome = result(&built);

    let mut store = SimulationStore::default();
    let recorded = store.record("primary", "1", built.clone(), None, outcome.clone(), at);
    assert!(
        store
            .take(
                recorded.simulation_id,
                at + TimeDelta::seconds(SIMULATION_TTL_SECONDS - 1)
            )
            .is_ok()
    );

    let mut store = SimulationStore::default();
    let recorded = store.record("primary", "1", built, None, outcome, at);
    assert!(
        store
            .take(
                recorded.simulation_id,
                at + TimeDelta::seconds(SIMULATION_TTL_SECONDS)
            )
            .is_err()
    );
}
