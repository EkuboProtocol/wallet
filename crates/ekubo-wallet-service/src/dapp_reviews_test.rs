use super::*;
use crate::walletconnect_review::{ProposalChoice, ProposalPresenter};
use ekubo_wallet_core::{
    approval::{ApprovalKind, ApprovalRequest, ReviewDocument},
    config::WalletSource,
};
use tokio::sync::oneshot;
use walletconnect_session::ApprovedScope;

fn account() -> WalletMetadata {
    WalletMetadata {
        id: "primary".into(),
        instance_id: Uuid::new_v4(),
        address: alloy::primitives::Address::from([1; 20]),
        created_at: chrono::Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    }
}

fn prompt(
    session_id: Uuid,
    account: WalletMetadata,
) -> (ProposalPrompt, oneshot::Receiver<ProposalCommand>) {
    let blank = ReviewDocument::from_request(
        ApprovalRequest::new(ApprovalKind::PolicyException, "Dapp", "Select an account"),
        vec![],
    );
    let selected = ReviewDocument::from_request(
        ApprovalRequest::new(ApprovalKind::PolicyException, "Dapp", "Expose this account")
            .fact("Account", &account.id),
        vec![],
    );
    let scope = ApprovedScope {
        address: account.address.to_checksum(None),
        chains: vec!["eip155:1".into()],
        methods: vec!["eth_accounts".into()],
        grants: vec![],
        events: vec![],
    };
    let (response, receiver) = oneshot::channel();
    (
        ProposalPrompt {
            session_id,
            unselected_document: blank,
            choices: vec![ProposalChoice {
                account,
                scope,
                document: selected,
            }],
            response,
        },
        receiver,
    )
}

#[tokio::test]
async fn approval_uses_the_stored_document_and_keeps_the_proof_inside_the_service() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let account = account();
    owner
        .config()
        .update_for_test(|state| {
            state.wallets.push(account.clone());
            Ok(())
        })
        .unwrap();
    let session_id = Uuid::new_v4();
    let (prompt, response) = prompt(session_id, account.clone());
    let identity = prompt.choices[0].document.identity.clone();
    let queue = DappReviews::default();
    queue.insert(prompt).unwrap();
    assert!(
        queue
            .approve(&owner, session_id, 1, &identity)
            .await
            .is_err()
    );
    assert!(
        queue
            .approve(&owner, session_id, 0, "unreviewed")
            .await
            .is_err()
    );
    assert_eq!(queue.pending().unwrap().len(), 1);
    let request = serde_json::from_value(serde_json::json!({
        "method": "approve_dapp_review",
        "params": { "session_id": session_id, "index": 0, "reviewed_identity": identity }
    }))
    .unwrap();
    // Keep the host alive across approval and replay. Dropping a temporary
    // runtime would close the broker and could mask a broken replay check.
    let receiver = crate::desktop_sessions::DesktopSessions::default();
    let runtime = std::sync::Arc::new(crate::dapp_runtime::DappRuntime::new(
        owner.clone(),
        queue.clone(),
        receiver,
    ));
    let dispatcher = crate::owner_rpc::OwnerDispatcher::new(owner.clone(), runtime);
    let reply = dispatcher.dispatch(request).await.unwrap();
    assert!(
        reply.is_null(),
        "the RPC reply must not contain an authorization proof"
    );
    let ProposalCommand::Approve {
        index,
        authorization,
    } = response.await.unwrap()
    else {
        panic!("expected approval")
    };
    assert_eq!(index, 0);
    authorization.verify(&identity, &account.id).unwrap();
    assert!(
        queue
            .approve(&owner, session_id, 0, &identity)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn reimported_account_cannot_inherit_a_pending_dapp_choice() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let account = account();
    let mut replacement = account.clone();
    replacement.instance_id = Uuid::new_v4();
    owner
        .config()
        .update_for_test(|state| {
            state.wallets.push(replacement);
            Ok(())
        })
        .unwrap();
    let session_id = Uuid::new_v4();
    let (prompt, response) = prompt(session_id, account);
    let identity = prompt.choices[0].document.identity.clone();
    let queue = DappReviews::default();
    queue.insert(prompt).unwrap();
    assert!(
        queue
            .approve(&owner, session_id, 0, &identity)
            .await
            .is_err()
    );
    assert!(matches!(response.await.unwrap(), ProposalCommand::Reject));
    assert!(queue.pending().unwrap().is_empty());
}

#[test]
fn stale_rejection_does_not_consume_the_live_review() {
    let session_id = Uuid::new_v4();
    let (prompt, mut response) = prompt(session_id, account());
    let identity = prompt.unselected_document.identity.clone();
    let queue = DappReviews::default();
    queue.insert(prompt).unwrap();
    assert!(queue.reject(session_id, "old-review").is_err());
    assert_eq!(queue.pending().unwrap().len(), 1);
    queue.reject(session_id, &identity).unwrap();
    assert!(matches!(
        response.try_recv().unwrap(),
        ProposalCommand::Reject
    ));
}

#[test]
fn an_authentication_reservation_prevents_replacement_and_releases_on_cancellation() {
    let session_id = Uuid::new_v4();
    let (first, _response) = prompt(session_id, account());
    let identity = first.choices[0].document.identity.clone();
    let queue = DappReviews::default();
    queue.insert(first).unwrap();
    let (held, reservation) = queue.take(session_id, Some(0), &identity).unwrap();
    let (replacement, _receiver) = prompt(session_id, account());
    assert!(queue.insert(replacement).is_err());
    drop(held);
    drop(reservation);
    let (replacement, _receiver) = prompt(session_id, account());
    queue.insert(replacement).unwrap();
}

#[test]
fn departed_sessions_do_not_leave_live_review_entries() {
    let (prompt, response) = prompt(Uuid::new_v4(), account());
    let queue = DappReviews::default();
    queue.insert(prompt).unwrap();
    drop(response);
    assert!(queue.pending().unwrap().is_empty());
}

#[tokio::test]
async fn an_account_replaced_during_authentication_is_rejected_after_the_challenge() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let account = account();
    owner
        .config()
        .update_for_test(|state| {
            state.wallets.push(account.clone());
            Ok(())
        })
        .unwrap();
    let session_id = Uuid::new_v4();
    let (prompt, response) = prompt(session_id, account);
    let identity = prompt.choices[0].document.identity.clone();
    let queue = DappReviews::default();
    queue.insert(prompt).unwrap();
    // The public approve method always uses native core authentication. This
    // private test callback replaces state at the exact authentication boundary.
    let result = queue
        .approve_with(&owner, session_id, 0, &identity, |document, account| {
            let owner = owner.clone();
            async move {
                let proof = owner.authorize_dapp_connection(&document, &account).await?;
                owner.config().update_for_test(|state| {
                    state.wallets[0].instance_id = Uuid::new_v4();
                    Ok(())
                })?;
                Ok(proof)
            }
        })
        .await;
    assert!(result.is_err());
    assert!(matches!(response.await.unwrap(), ProposalCommand::Reject));
    assert!(queue.pending().unwrap().is_empty());
}

#[tokio::test]
async fn collector_publishes_ready_reviews_and_cancels_pending_decisions_on_shutdown() {
    let queue = DappReviews::default();
    let (presenter, incoming) = ProposalPresenter::channel();
    let events = EventBus::default();
    let mut observed = events.subscribe();
    let collecting = queue.clone();
    let collector = tokio::spawn(async move { collecting.collect(incoming, events).await });

    for cancel in [false, true] {
        let session_id = Uuid::new_v4();
        let (prompt, _unused) = prompt(session_id, account());
        let identity = prompt.unselected_document.identity.clone();
        let presenting = presenter.clone();
        let decision = tokio::spawn(async move {
            presenting
                .review(session_id, prompt.unselected_document, prompt.choices)
                .await
        });
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(event.kind, DomainEventKind::WalletConnectChanged { session_id: ref id } if id == &session_id.to_string())
        );
        assert_eq!(queue.pending().unwrap()[0].session_id, session_id);
        if cancel {
            collector.abort();
            assert!(decision.await.unwrap().is_err());
        } else {
            queue.reject(session_id, &identity).unwrap();
            assert!(matches!(
                decision.await.unwrap().unwrap(),
                ProposalCommand::Reject
            ));
        }
    }
    assert!(collector.await.unwrap_err().is_cancelled());
    assert!(queue.pending().unwrap().is_empty());
    let (late, _response) = prompt(Uuid::new_v4(), account());
    assert!(queue.insert(late).is_err());
}

#[tokio::test]
async fn broker_shutdown_during_authentication_cannot_deliver_approval() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let account = account();
    owner
        .config()
        .update_for_test(|state| {
            state.wallets.push(account.clone());
            Ok(())
        })
        .unwrap();
    let session_id = Uuid::new_v4();
    let (prompt, response) = prompt(session_id, account);
    let identity = prompt.choices[0].document.identity.clone();
    let queue = DappReviews::default();
    queue.insert(prompt).unwrap();
    let result = queue
        .approve_with(&owner, session_id, 0, &identity, |document, account| {
            let owner = owner.clone();
            let queue = queue.clone();
            async move {
                let proof = owner.authorize_dapp_connection(&document, &account).await?;
                queue.shutdown()?;
                Ok(proof)
            }
        })
        .await;
    assert!(result.is_err());
    assert!(
        response.await.is_err(),
        "shutdown must prevent proof delivery to the session"
    );
}

#[test]
fn pending_reviews_preserve_arrival_order_instead_of_sorting_session_ids() {
    let queue = DappReviews::default();
    let first = Uuid::from_u128(30);
    let second = Uuid::from_u128(10);
    let third = Uuid::from_u128(20);
    let (a, _a_response) = prompt(first, account());
    let (b, b_response) = prompt(second, account());
    let (c, _c_response) = prompt(third, account());
    queue.insert(a).unwrap();
    queue.insert(b).unwrap();
    queue.insert(c).unwrap();
    assert_eq!(
        queue
            .pending()
            .unwrap()
            .iter()
            .map(|review| review.session_id)
            .collect::<Vec<_>>(),
        vec![first, second, third]
    );
    drop(b_response);
    assert_eq!(
        queue
            .pending()
            .unwrap()
            .iter()
            .map(|review| review.session_id)
            .collect::<Vec<_>>(),
        vec![first, third]
    );
}
