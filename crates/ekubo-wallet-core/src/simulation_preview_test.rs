use super::*;
fn result(delta: &str) -> crate::simulation::SimulationResult {
    use crate::simulation::{
        BalanceChanges, ExecutionMode, NativeBalanceChange, SimulationExecution, SimulationResult,
    };
    SimulationResult {
        simulation_id: None,
        digest: "0x00".into(),
        allowed: true,
        policy_outcome: crate::core::policy::PolicyOutcome::Allowed,
        policy_findings: Vec::new(),
        policy_revision: 1,
        execution_mode: ExecutionMode::Direct,
        implementation: None,
        will_authorize_delegation: false,
        replaces_delegated_implementation: None,
        prepared_transaction: None,
        prepared_execution: None,
        simulation: SimulationExecution {
            success: true,
            gas_used: None,
            block_gas_limit: None,
            output: None,
            error: None,
            failure: None,
        },
        token_spends: BTreeMap::new(),
        balance_changes: Some(BalanceChanges {
            native: NativeBalanceChange {
                before: "0".into(),
                after: "0".into(),
                delta: delta.into(),
            },
            tokens: BTreeMap::new(),
        }),
        block_number: "1".into(),
        fork: None,
    }
}

#[test]
fn evidence_expires_and_is_bound_to_wallet_chain_and_plan() {
    let mut cache = Cache::default();
    let now = Instant::now();
    let key = (Uuid::new_v4(), 1, "plan".into());
    cache.record(key.clone(), &result("-1"), now);
    assert!(cache.get(&key, now).is_some());
    assert!(
        cache
            .get(&(Uuid::new_v4(), 1, "plan".into()), now)
            .is_none()
    );
    assert!(cache.get(&(key.0, 2, "plan".into()), now).is_none());
    assert!(cache.get(&(key.0, 1, "other".into()), now).is_none());
    assert!(cache.get(&key, now + TTL).is_none());
}
#[test]
fn a_failed_refresh_removes_previous_effects_and_capacity_is_bounded() {
    let mut cache = Cache::default();
    let now = Instant::now();
    let wallet = Uuid::new_v4();
    for index in 0..100 {
        cache.record(
            (wallet, 1, index.to_string()),
            &result("1"),
            now + Duration::from_millis(index),
        );
    }
    assert_eq!(cache.0.len(), CAPACITY);
    assert!(cache.get(&(wallet, 1, "0".into()), now).is_none());
    let key = (wallet, 1, "99".into());
    let mut failed = result("1");
    failed.simulation.success = false;
    cache.record(key.clone(), &failed, now);
    assert!(cache.get(&key, now).is_none());
}
