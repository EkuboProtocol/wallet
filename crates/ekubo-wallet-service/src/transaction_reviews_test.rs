use super::*;
const REVIEW_ID: Uuid = Uuid::from_u128(1);
use ekubo_wallet_core::approval::{
    ApprovalDecision, ApprovalKind, ApprovalRequest, ReviewDocument,
};
use tokio::sync::oneshot;

fn prompt() -> (GuiReviewPrompt, oneshot::Receiver<GuiReviewCommand>) {
    let (response, receive) = oneshot::channel();
    let document = ReviewDocument::from_request(
        ApprovalRequest::new(ApprovalKind::Transaction, "Review", "Exact transaction"),
        vec!["0x1234".into()],
    );
    let simulation = serde_json::from_value(serde_json::json!({
        "digest": "0x00", "allowed": false, "policy_outcome": "requires_approval",
        "policy_findings": [], "policy_revision": 1, "execution_mode": "direct",
        "implementation": null, "will_authorize_delegation": false,
        "replaces_delegated_implementation": null, "prepared_transaction": null,
        "simulation": {"success": true, "gas_used": "21000", "block_gas_limit": "30000000",
            "output": null, "error": null, "failure": null},
        "token_spends": {}, "balance_changes": null, "block_number": "1", "fork": null
    }))
    .unwrap();
    (
        GuiReviewPrompt {
            document,
            simulation,
            response,
        },
        receive,
    )
}

#[tokio::test]
async fn decisions_require_the_exact_frame_and_refresh_retires_it() {
    let broker = TransactionReviews::default();
    let events = EventBus::default();
    let request_id = Uuid::new_v4();
    let _reservation = broker
        .reserve(request_id, REVIEW_ID, events.clone())
        .unwrap();
    let (first, response) = prompt();
    broker.insert(request_id, first).unwrap();
    let frame = broker.frame(request_id, REVIEW_ID).unwrap().unwrap();
    assert!(
        broker
            .decide(
                request_id,
                REVIEW_ID,
                Uuid::new_v4(),
                &frame.document.identity,
                TransactionReviewChoice::Approve,
                &events
            )
            .is_err()
    );
    assert!(
        broker
            .decide(
                request_id,
                REVIEW_ID,
                frame.frame_id,
                "forged",
                TransactionReviewChoice::Approve,
                &events
            )
            .is_err()
    );
    assert_eq!(
        broker
            .frame(request_id, REVIEW_ID)
            .unwrap()
            .unwrap()
            .frame_id,
        frame.frame_id
    );
    broker
        .decide(
            request_id,
            REVIEW_ID,
            frame.frame_id,
            &frame.document.identity,
            TransactionReviewChoice::Refresh,
            &events,
        )
        .unwrap();
    assert_eq!(response.await.unwrap(), GuiReviewCommand::Refresh);
    assert!(broker.frame(request_id, REVIEW_ID).unwrap().is_none());
    let (next, response) = prompt();
    broker.insert(request_id, next).unwrap();
    let refreshed = broker.frame(request_id, REVIEW_ID).unwrap().unwrap();
    // Even an unchanged document after refresh gets a new, single-use frame.
    assert_ne!(refreshed.frame_id, frame.frame_id);
    assert!(
        broker
            .decide(
                request_id,
                REVIEW_ID,
                frame.frame_id,
                &frame.document.identity,
                TransactionReviewChoice::Approve,
                &events
            )
            .is_err()
    );
    broker
        .decide(
            request_id,
            REVIEW_ID,
            refreshed.frame_id,
            &refreshed.document.identity,
            TransactionReviewChoice::Reject,
            &events,
        )
        .unwrap();
    assert_eq!(response.await.unwrap(), GuiReviewCommand::Reject);
    assert!(broker.reserve(request_id, REVIEW_ID, events).is_err());
}

#[test]
fn reservations_are_bounded_and_shutdown_is_terminal() {
    let broker = TransactionReviews::default();
    let events = EventBus::default();
    let mut reservations: Vec<_> = (0..MAX_REVIEWS)
        .map(|_| {
            broker
                .reserve(Uuid::new_v4(), REVIEW_ID, events.clone())
                .unwrap()
        })
        .collect();
    assert!(
        broker
            .reserve(Uuid::new_v4(), REVIEW_ID, events.clone())
            .is_err()
    );
    reservations.pop();
    let last = broker
        .reserve(Uuid::new_v4(), REVIEW_ID, events.clone())
        .unwrap();
    let (frame, mut receiver) = prompt();
    broker.insert(last.request_id, frame).unwrap();
    broker.shutdown().unwrap();
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    ));
    assert!(broker.reserve(Uuid::new_v4(), REVIEW_ID, events).is_err());
    assert!(broker.frame(last.request_id, REVIEW_ID).unwrap().is_none());
}

async fn wait_frame(broker: &TransactionReviews, request_id: Uuid) -> TransactionReviewFrame {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if let Some(frame) = broker.frame(request_id, REVIEW_ID).unwrap() {
                return frame;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn closing_a_review_is_an_abort_and_cancellation_releases_the_request() {
    for choice in [
        TransactionReviewChoice::Close,
        TransactionReviewChoice::Reject,
    ] {
        let broker = TransactionReviews::default();
        let events = EventBus::default();
        let request_id = Uuid::new_v4();
        let (incoming, receive) = mpsc::unbounded_channel();
        let operation = async {
            let (frame, response) = prompt();
            incoming.send(frame).unwrap();
            match response.await? {
                GuiReviewCommand::Reject => Ok(ApprovalDecision::Rejected),
                GuiReviewCommand::Close => bail!("closed without a decision"),
                _ => panic!("unexpected choice"),
            }
        };
        let drive = broker.run(request_id, REVIEW_ID, receive, operation, events.clone());
        let choose = async {
            let frame = wait_frame(&broker, request_id).await;
            broker
                .decide(
                    request_id,
                    REVIEW_ID,
                    frame.frame_id,
                    &frame.document.identity,
                    choice,
                    &events,
                )
                .unwrap();
        };
        let (result, ()) = tokio::join!(drive, choose);
        match choice {
            TransactionReviewChoice::Close => assert!(result.is_err()),
            TransactionReviewChoice::Reject => {
                assert_eq!(result.unwrap(), ApprovalDecision::Rejected);
            }
            _ => unreachable!(),
        }
        assert!(broker.frame(request_id, REVIEW_ID).unwrap().is_none());
        broker.reserve(request_id, REVIEW_ID, events).unwrap();
    }
}

#[tokio::test]
async fn approval_keeps_the_reservation_until_authentication_finishes_or_cancels() {
    let broker = TransactionReviews::default();
    let request_id = Uuid::new_v4();
    let events = EventBus::default();
    let (incoming, receive) = mpsc::unbounded_channel();
    let (auth_started, authenticating) = oneshot::channel();
    let operation = async {
        let (frame, response) = prompt();
        incoming.send(frame).unwrap();
        assert_eq!(response.await?, GuiReviewCommand::Approve);
        auth_started.send(()).unwrap();
        std::future::pending::<Result<()>>().await
    };
    let mut drive = Box::pin(broker.run(request_id, REVIEW_ID, receive, operation, events.clone()));
    let choose = async {
        let frame = wait_frame(&broker, request_id).await;
        broker
            .decide(
                request_id,
                REVIEW_ID,
                frame.frame_id,
                &frame.document.identity,
                TransactionReviewChoice::Approve,
                &events,
            )
            .unwrap();
        authenticating.await.unwrap();
        assert!(
            broker
                .reserve(request_id, REVIEW_ID, events.clone())
                .is_err()
        );
        assert!(broker.frame(request_id, REVIEW_ID).unwrap().is_none());
    };
    tokio::select! {
        result = &mut drive => panic!("review ended before authentication: {result:?}"),
        () = choose => {}
    }
    drop(drive);
    broker.reserve(request_id, REVIEW_ID, events).unwrap();
}

#[tokio::test]
async fn shutdown_cancels_preparation_before_any_frame_exists() {
    let broker = TransactionReviews::default();
    let request_id = Uuid::new_v4();
    let events = EventBus::default();
    let (_incoming, receive) = mpsc::unbounded_channel();
    let (started, ready) = oneshot::channel();
    let operation = async {
        started.send(()).unwrap();
        std::future::pending::<Result<()>>().await
    };
    let stop = async {
        ready.await.unwrap();
        broker.shutdown().unwrap();
    };
    let (result, ()) = tokio::join!(
        broker.run(request_id, REVIEW_ID, receive, operation, events),
        stop
    );
    assert!(result.unwrap_err().to_string().contains("closed"));
    assert!(broker.state().unwrap().is_empty());
}

#[tokio::test]
async fn rpc_failures_release_review_state_and_reject_forged_authority() {
    use crate::{
        dapp_reviews::DappReviews,
        dapp_runtime::DappRuntime,
        owner_rpc::{OwnerDispatcher, Request},
    };
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let activity = crate::desktop_sessions::DesktopSessions::default();
    let dapps = Arc::new(DappRuntime::new(
        owner.clone(),
        DappReviews::default(),
        activity,
    ));
    let dispatcher = OwnerDispatcher::new(owner, dapps);
    let request_id = Uuid::new_v4();
    for _ in 0..2 {
        let request = serde_json::from_value(serde_json::json!({
            "method": "review_transaction", "params": {"request_id": request_id, "review_id": REVIEW_ID}
        }))
        .unwrap();
        let error = dispatcher.dispatch(request).await.unwrap_err();
        assert!(!error.to_string().contains("already has an active review"));
    }
    assert!(
        dispatcher
            .dispatch(Request::TransactionReviewFrame {
                request_id,
                review_id: REVIEW_ID
            })
            .await
            .unwrap()
            .is_null()
    );
    assert!(
        dispatcher
            .dispatch(Request::DecideTransactionReview {
                request_id,
                review_id: REVIEW_ID,
                frame_id: Uuid::new_v4(),
                reviewed_identity: "forged".into(),
                choice: TransactionReviewChoice::Approve,
            })
            .await
            .is_err()
    );
    for field in ["prepared_execution", "authorization", "owner_uid"] {
        let mut request = serde_json::json!({"method": "decide_transaction_review", "params": {
            "request_id": request_id, "review_id": REVIEW_ID, "frame_id": Uuid::new_v4(),
            "reviewed_identity": "forged", "choice": "approve"
        }});
        request["params"][field] = serde_json::json!(true);
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
    dispatcher.shutdown().unwrap();
    dispatcher.shutdown().unwrap();
    let error = dispatcher
        .dispatch(Request::ReviewTransaction {
            request_id,
            review_id: REVIEW_ID,
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("transaction review broker is closed")
    );
}

#[tokio::test]
async fn a_reused_transaction_id_does_not_expose_or_accept_another_review_session() {
    let broker = TransactionReviews::default();
    let events = EventBus::default();
    let request_id = Uuid::new_v4();
    let old = broker
        .reserve(request_id, REVIEW_ID, events.clone())
        .unwrap();
    drop(old);
    let current_id = Uuid::new_v4();
    let _current = broker
        .reserve(request_id, current_id, events.clone())
        .unwrap();
    let (prompt, mut response) = prompt();
    broker.insert(request_id, prompt).unwrap();
    assert!(broker.frame(request_id, REVIEW_ID).unwrap().is_none());
    let frame = broker.frame(request_id, current_id).unwrap().unwrap();
    assert!(
        broker
            .decide(
                request_id,
                REVIEW_ID,
                frame.frame_id,
                &frame.document.identity,
                TransactionReviewChoice::Approve,
                &events
            )
            .is_err()
    );
    assert!(matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    broker
        .decide(
            request_id,
            current_id,
            frame.frame_id,
            &frame.document.identity,
            TransactionReviewChoice::Reject,
            &events,
        )
        .unwrap();
    assert_eq!(response.await.unwrap(), GuiReviewCommand::Reject);
}
