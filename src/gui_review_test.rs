use super::*;
use ekubo_wallet_core::{
    approval::{ApprovalKind, ApprovalRequest, NoRefresh},
    core::policy::PolicyOutcome,
    simulation::{ExecutionMode, SimulationExecution},
};
use std::collections::BTreeMap;

fn document() -> ReviewDocument {
    ReviewDocument::from_request(
        ApprovalRequest::new(ApprovalKind::Transaction, "Review", "Exact request"),
        vec!["0x1234".into()],
    )
}

fn simulation() -> SimulationResult {
    SimulationResult {
        simulation_id: None,
        digest: "0x00".into(),
        allowed: false,
        policy_outcome: PolicyOutcome::RequiresApproval,
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
        block_number: "1".into(),
        fork: None,
    }
}

#[tokio::test]
async fn a_closed_review_is_not_a_rejection() {
    let (presenter, mut prompts) = GuiReviewPresenter::channel();
    let task = tokio::spawn(async move {
        presenter
            .review_transaction(&document(), &simulation(), &NoRefresh)
            .await
    });
    prompts
        .recv()
        .await
        .unwrap()
        .response
        .send(GuiReviewCommand::Close)
        .unwrap();
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("closed")
    );
}
