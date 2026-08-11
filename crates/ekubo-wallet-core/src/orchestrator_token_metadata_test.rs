use super::*;
use crate::simulation::{BalanceChanges, NativeBalanceChange, SimulationExecution};
use crate::{policy_store::DatabaseKey, token_store::ListedToken};
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

    let directory = tempfile::tempdir().unwrap();
    let database = PolicyStore::open(
        &directory.path().join("wallet.db"),
        &DatabaseKey::new([41; 32]),
    )
    .unwrap();
    let mut token_store = crate::token_store::TokenStore::new(database);
    token_store
        .add(
            &ListedToken {
                chain_id: 1,
                address: circle_token,
                symbol: "USDC".into(),
                name: Some("USD Coin".into()),
                decimals: 6,
            },
            "embedded default list",
        )
        .unwrap();
    token_store
        .add(
            &ListedToken {
                chain_id: 1,
                address: ethena_token,
                symbol: "USDe".into(),
                name: Some("Ethena USDe".into()),
                decimals: 18,
            },
            "embedded default list",
        )
        .unwrap();

    let metadata = token_store.display_metadata(1, &targets).unwrap();
    let network = crate::config::default_networks()
        .into_iter()
        .find(|network| network.chain_id == 1)
        .unwrap();
    let rendered = render_balance_changes(&simulation, &network, &metadata);
    assert!(
        rendered
            .iter()
            .any(|(label, value)| { label.starts_with("USDC (") && value.contains("USDC") })
    );
    assert!(
        rendered
            .iter()
            .any(|(label, value)| { label.starts_with("USDe (") && value.contains("USDe") })
    );
}
