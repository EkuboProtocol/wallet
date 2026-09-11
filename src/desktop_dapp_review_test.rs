use super::*;
use crate::walletconnect::ProposalChoice;
use ekubo_wallet_core::{
    approval::{ApprovalKind, ApprovalRequest},
    config::{WalletMetadata, WalletSource},
};
use uuid::Uuid;

fn prompt() -> (DesktopDappPrompt, oneshot::Receiver<ProposalCommand>) {
    let account = WalletMetadata {
        id: "primary".into(),
        instance_id: Uuid::new_v4(),
        address: alloy::primitives::Address::from([1; 20]),
        created_at: chrono::Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    };
    let document = |account: &str| {
        ReviewDocument::from_request(
            ApprovalRequest::new(ApprovalKind::PolicyException, "Dapp", "Select an account")
                .fact("Account", account),
            vec![],
        )
    };
    let (response, receiver) = oneshot::channel();
    let prompt = ProposalPrompt {
        session_id: Uuid::new_v4(),
        unselected_document: document(""),
        choices: vec![ProposalChoice {
            document: document(&account.id),
            scope: walletconnect_session::ApprovedScope {
                address: account.address.to_checksum(None),
                chains: vec!["eip155:1".into()],
                methods: vec!["eth_accounts".into()],
                grants: vec![],
                events: vec![],
            },
            account,
        }],
        response,
    };
    (DesktopDappPrompt::local(prompt), receiver)
}

#[tokio::test]
async fn local_approval_uses_the_original_choice_and_returns_no_proof_to_the_ui() {
    let directory = tempfile::tempdir().unwrap();
    let owner = DesktopOwner::from(OwnerApi::for_test(directory.path()).unwrap());
    let (mut prompt, response) = prompt();
    let identity = prompt.choices[0].document.identity.clone();
    let account = prompt.choices[0].account.id.clone();
    // A changed presentation must not change what the single-use handle approves.
    prompt.choices[0].document.identity = "different review".into();
    prompt.choices[0].account.id = "different account".into();
    prompt
        .response
        .respond(&owner, DappDecision::Approve { index: Some(0) })
        .await
        .unwrap();
    let ProposalCommand::Approve {
        index,
        authorization,
    } = response.await.unwrap()
    else {
        panic!("expected an approval delivered directly to the local session");
    };
    assert_eq!(index, 0);
    authorization.verify(&identity, &account).unwrap();
}

#[tokio::test]
async fn absent_or_invalid_account_selection_rejects_without_approving() {
    let directory = tempfile::tempdir().unwrap();
    let owner = DesktopOwner::from(OwnerApi::for_test(directory.path()).unwrap());
    for index in [None, Some(1)] {
        let (prompt, response) = prompt();
        assert!(
            prompt
                .response
                .respond(&owner, DappDecision::Approve { index })
                .await
                .is_err()
        );
        assert!(matches!(response.await.unwrap(), ProposalCommand::Reject));
    }
}

#[tokio::test]
async fn decline_and_close_keep_their_distinct_session_commands() {
    let directory = tempfile::tempdir().unwrap();
    let owner = DesktopOwner::from(OwnerApi::for_test(directory.path()).unwrap());
    let (prompt, response) = prompt();
    prompt
        .response
        .respond(&owner, DappDecision::Reject)
        .await
        .unwrap();
    assert!(matches!(response.await.unwrap(), ProposalCommand::Reject));
    let (prompt, response) = self::prompt();
    prompt
        .response
        .respond(&owner, DappDecision::Close)
        .await
        .unwrap();
    assert!(matches!(response.await.unwrap(), ProposalCommand::Close));
}

#[tokio::test]
async fn ended_session_invalidates_its_unanswered_review() {
    let directory = tempfile::tempdir().unwrap();
    let owner = DesktopOwner::from(OwnerApi::for_test(directory.path()).unwrap());
    let (prompt, receiver) = prompt();
    drop(receiver);
    assert!(prompt.response.is_closed());
    let error = prompt
        .response
        .respond(&owner, DappDecision::Approve { index: Some(0) })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no longer active"));
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[tokio::test]
async fn service_review_never_falls_back_to_local_authority() {
    let directory = tempfile::tempdir().unwrap();
    let owner = DesktopOwner::from(OwnerApi::for_test(directory.path()).unwrap());
    let (local, _response) = prompt();
    let service = DesktopDappPrompt::service(*local.response.review.clone());
    let error = service
        .response
        .respond(&owner, DappDecision::Approve { index: Some(0) })
        .await
        .unwrap_err();
    assert!(error.to_string().contains("authority backend changed"));
}
