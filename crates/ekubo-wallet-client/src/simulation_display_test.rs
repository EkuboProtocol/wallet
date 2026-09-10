use super::*;
use ekubo_wallet_core::simulation::SimulationExecution;

fn simulation() -> SimulationResult {
    SimulationResult {
        simulation_id: Some(uuid::Uuid::nil()),
        digest: "0x00".into(),
        allowed: false,
        policy_outcome: PolicyOutcome::RequiresApproval,
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
            gas_used: Some("21000".into()),
            block_gas_limit: Some("30000000".into()),
            output: None,
            error: None,
            failure: None,
        },
        token_spends: BTreeMap::new(),
        balance_changes: None,
        block_number: "1".into(),
        fork: None,
    }
}

#[test]
fn display_preserves_simulation_facts_but_not_consumption_handles() {
    let result = simulation();
    let display = SimulationDisplay::from(&result);
    let wire = serde_json::to_value(&display).unwrap();
    let mut expected = serde_json::to_value(result).unwrap();
    expected.as_object_mut().unwrap().remove("simulation_id");
    assert_eq!(wire, expected);
    let restored: SimulationDisplay = serde_json::from_value(wire).unwrap();
    assert_eq!(restored, display);
}

#[test]
fn display_cannot_deserialize_preparation_authority_or_a_consumption_handle() {
    let wire = serde_json::to_value(SimulationDisplay::from(&simulation())).unwrap();
    for field in ["prepared_execution", "simulation_id", "authorization"] {
        let mut forged = wire.clone();
        forged
            .as_object_mut()
            .unwrap()
            .insert(field.into(), serde_json::json!({"approved":true}));
        assert!(
            serde_json::from_value::<SimulationDisplay>(forged).is_err(),
            "accepted {field}"
        );
    }
}
