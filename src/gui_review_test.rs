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

struct ChangedRefresh;

#[async_trait::async_trait]
impl ReviewRefresh for ChangedRefresh {
    async fn resimulate(&self) -> anyhow::Result<Refreshed> {
        let mut changed = document();
        changed.request.summary = "Refreshed exact request".into();
        changed = ReviewDocument::from_request(changed.request, vec!["0x5678".into()]);
        Ok(Refreshed {
            document: changed,
            simulation: simulation(),
        })
    }
}

#[tokio::test]
async fn refresh_issues_a_new_single_use_review_frame() {
    let (presenter, mut prompts) = GuiReviewPresenter::channel();
    let task = tokio::spawn(async move {
        presenter
            .review_transaction(&document(), &simulation(), &ChangedRefresh)
            .await
    });
    let first = prompts.recv().await.unwrap();
    let first_identity = first.document.identity;
    first.response.send(GuiReviewCommand::Refresh).unwrap();

    let refreshed = prompts.recv().await.unwrap();
    assert_ne!(refreshed.document.identity, first_identity);
    assert_eq!(refreshed.document.exact_payloads, ["0x5678"]);
    refreshed.response.send(GuiReviewCommand::Reject).unwrap();
    assert_eq!(task.await.unwrap().unwrap(), ApprovalDecision::Rejected);
}
