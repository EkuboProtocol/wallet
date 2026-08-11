use super::*;
use crate::simulation::{BalanceChanges, NativeBalanceChange, SimulationExecution};
use alloy::primitives::address;
use std::collections::BTreeMap;

#[tokio::test]
async fn review_metadata_includes_tokens_discovered_by_simulation() {
    let circle_token = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
    let ethena_token = address!("4c9edd5852cd905f086c759e8383e09bff1e68b3");
    let mut tokens = BTreeMap::new();
    for token in [circle_token, ethena_token] {
        tokens.insert(
            format!("{token:#x}"),
            crate::simulation::TokenBalanceChange {
                before: Some("0".into()),
                after: Some("1".into()),
                delta: Some("1".into()),
                incoming_transfers: "1".into(),
                outgoing_transfers: "0".into(),
            },
        );
    }
    let simulation = SimulationResult {
        simulation_id: None,
        digest: String::new(),
        allowed: false,
        policy_outcome: crate::core::policy::PolicyOutcome::RequiresApproval,
        policy_findings: Vec::new(),
        policy_revision: 1,
        execution_mode: crate::simulation::ExecutionMode::Direct,
        implementation: None,
        will_authorize_delegation: false,
        replaces_delegated_implementation: None,
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
                delta: "0".into(),
            },
            tokens,
        }),
        block_number: "1".into(),
        fork: None,
    };

    let targets = review_token_targets(&[], &simulation).await;
    assert_eq!(targets, vec![ethena_token, circle_token]);
}
