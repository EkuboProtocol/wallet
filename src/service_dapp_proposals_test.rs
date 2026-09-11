use super::*;
use ekubo_wallet_client::dapp_review::DappChoice;
use ekubo_wallet_core::{
    approval::{ApprovalKind, ApprovalRequest, ReviewDocument},
    config::{WalletMetadata, WalletSource},
};
use std::sync::{Arc, Mutex};

fn review() -> DappReview {
    let document = ReviewDocument::from_request(
        ApprovalRequest::new(ApprovalKind::PolicyException, "Dapp", "Select an account"),
        vec![],
    );
    DappReview {
        session_id: Uuid::new_v4(),
        unselected_document: document.clone(),
        choices: vec![DappChoice {
            account: WalletMetadata {
                id: "primary".into(),
                instance_id: Uuid::new_v4(),
                address: alloy::primitives::Address::from([1; 20]),
                created_at: chrono::Utc::now(),
                source: WalletSource::Created,
                exported_at: None,
            },
            document,
        }],
    }
}

#[test]
fn repeated_snapshots_do_not_reopen_reviews_and_changed_choices_invalidate_old_handles() {
    let mut feed = ReviewFeed::default();
    let mut review = review();
    let first = feed
        .reconcile(vec![review.clone()])
        .unwrap()
        .unwrap()
        .pop()
        .unwrap();
    assert!(feed.reconcile(vec![review.clone()]).unwrap().is_none());
    assert!(!first.response.is_closed());
    // Even the same document identity cannot preserve an old account instance.
    review.choices[0].account.instance_id = Uuid::new_v4();
    let replacement = feed
        .reconcile(vec![review])
        .unwrap()
        .unwrap()
        .pop()
        .unwrap();
    assert!(first.response.is_closed());
    assert!(!replacement.response.is_closed());
    assert!(feed.reconcile(vec![]).unwrap().unwrap().is_empty());
    assert!(replacement.response.is_closed());
}

#[test]
fn losing_the_feed_invalidates_every_unanswered_service_review() {
    let mut feed = ReviewFeed::default();
    let prompt = feed
        .reconcile(vec![review()])
        .unwrap()
        .unwrap()
        .pop()
        .unwrap();
    drop(feed);
    assert!(prompt.response.is_closed());
}

#[test]
fn invalid_snapshot_is_rejected_before_any_partial_reconciliation() {
    let mut feed = ReviewFeed::default();
    let original = review();
    let prompt = feed
        .reconcile(vec![original.clone()])
        .unwrap()
        .unwrap()
        .pop()
        .unwrap();
    let duplicate = review();
    assert!(feed.reconcile(vec![duplicate.clone(), duplicate]).is_err());
    assert!(!prompt.response.is_closed());
    assert!(feed.reconcile((0..17).map(|_| review()).collect()).is_err());
    assert!(!prompt.response.is_closed());
    assert!(feed.reconcile(vec![original.clone()]).unwrap().is_none());
    let mut empty = original;
    empty.choices.clear();
    assert!(feed.reconcile(vec![empty]).is_err());
    assert!(!prompt.response.is_closed());
}

struct Source {
    events: tokio::sync::Mutex<mpsc::Receiver<Result<EventBatch>>>,
    reviews: Mutex<Vec<DappReview>>,
    reads: Mutex<Vec<Option<EventCursor>>>,
}

#[async_trait]
impl ReviewSource for Source {
    async fn events(&self, cursor: Option<EventCursor>) -> Result<EventBatch> {
        self.reads.lock().unwrap().push(cursor);
        self.events.lock().await.recv().await.unwrap()
    }
    async fn reviews(&self) -> Result<Vec<DappReview>> {
        assert!(
            !self.reads.lock().unwrap().is_empty(),
            "capture the event cursor before reading state"
        );
        Ok(self.reviews.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn event_gaps_refresh_authoritative_state_and_transport_failure_retires_the_feed() {
    let (events, incoming) = mpsc::channel(4);
    let source = Arc::new(Source {
        events: tokio::sync::Mutex::new(incoming),
        reviews: Mutex::new(vec![review()]),
        reads: Mutex::new(Vec::new()),
    });
    let (updates, mut displayed) = mpsc::channel(4);
    let reader = source.clone();
    let task = tokio::spawn(async move { consume(reader.as_ref(), &updates).await });
    let first_cursor = EventCursor {
        epoch: Uuid::new_v4(),
        sequence: 1,
    };
    events
        .send(Ok(EventBatch {
            mcp_online: None,
            cursor: first_cursor,
            refresh_required: true,
            events: vec![],
        }))
        .await
        .unwrap();
    let DappProposalUpdate::Changed(mut prompts) = displayed.recv().await.unwrap() else {
        panic!("expected a review")
    };
    let original = prompts.pop().unwrap();
    assert!(!original.response.is_closed());
    source.reviews.lock().unwrap()[0].choices[0]
        .document
        .identity = "new authoritative review".into();
    let later = EventCursor {
        sequence: 400,
        ..first_cursor
    };
    events
        .send(Ok(EventBatch {
            mcp_online: None,
            cursor: later,
            refresh_required: true,
            events: vec![],
        }))
        .await
        .unwrap();
    let DappProposalUpdate::Changed(mut prompts) = displayed.recv().await.unwrap() else {
        panic!("expected a replacement")
    };
    let replacement = prompts.pop().unwrap();
    assert!(original.response.is_closed());
    assert!(!replacement.response.is_closed());
    events
        .send(Err(anyhow::anyhow!("transport failed")))
        .await
        .unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(replacement.response.is_closed());
    assert_eq!(
        *source.reads.lock().unwrap(),
        vec![None, Some(first_cursor), Some(later)]
    );
}

#[test]
fn a_batch_reaches_the_ui_in_the_services_arrival_order() {
    let mut first = review();
    let mut second = review();
    first.session_id = Uuid::from_u128(30);
    second.session_id = Uuid::from_u128(10);
    let identities = vec![
        first.unselected_document.identity.clone(),
        second.unselected_document.identity.clone(),
    ];
    let mut feed = ReviewFeed::default();
    let prompts = feed.reconcile(vec![first, second]).unwrap().unwrap();
    assert!(prompts.iter().all(|prompt| !prompt.response.is_closed()));
    assert_eq!(
        prompts
            .into_iter()
            .map(|prompt| prompt.unselected_document.identity)
            .collect::<Vec<_>>(),
        identities
    );
}
