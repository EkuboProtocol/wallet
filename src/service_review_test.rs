use super::*;
use ekubo_wallet_core::approval::{ApprovalKind, ApprovalRequest, ReviewDocument};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::sync::{mpsc, oneshot};

struct Frames {
    pending: Mutex<VecDeque<TransactionReviewFrame>>,
    decisions: mpsc::UnboundedSender<(Uuid, TransactionReviewChoice)>,
    calls: AtomicUsize,
    fail_decision: bool,
}

#[async_trait]
impl ReviewFrames for Frames {
    async fn frame(&self, _: Uuid, _: Uuid) -> Result<Option<TransactionReviewFrame>> {
        Ok(self.pending.lock().unwrap().front().cloned())
    }
    async fn decide(
        &self,
        frame: &TransactionReviewFrame,
        choice: TransactionReviewChoice,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let actual = self.pending.lock().unwrap().pop_front().unwrap();
        assert_eq!(actual.frame_id, frame.frame_id);
        assert_eq!(actual.document.identity, frame.document.identity);
        self.decisions.send((frame.frame_id, choice)).unwrap();
        if self.fail_decision {
            bail!("decision reply lost");
        }
        Ok(())
    }
}

fn frame(request_id: Uuid, review_id: Uuid) -> TransactionReviewFrame {
    TransactionReviewFrame {
        request_id,
        review_id,
        frame_id: Uuid::new_v4(),
        document: ReviewDocument::from_request(
            ApprovalRequest::new(ApprovalKind::Transaction, "Review", "Exact transaction"),
            vec!["0x1234".into()],
        ),
        simulation: serde_json::from_value(serde_json::json!({
            "digest": "0x00", "allowed": false, "policy_outcome": "requires_approval",
            "policy_findings": [], "policy_revision": 1, "execution_mode": "direct",
            "implementation": null, "will_authorize_delegation": false,
            "replaces_delegated_implementation": null, "prepared_transaction": null,
            "simulation": {"success": true, "gas_used": "21000", "block_gas_limit": "30000000",
                "output": null, "error": null, "failure": null},
            "token_spends": {}, "balance_changes": null, "block_number": "1", "fork": null
        }))
        .unwrap(),
    }
}

fn fixture(
    frames: Vec<TransactionReviewFrame>,
) -> (
    Frames,
    mpsc::UnboundedReceiver<(Uuid, TransactionReviewChoice)>,
) {
    let (decisions, received) = mpsc::unbounded_channel();
    (
        Frames {
            pending: Mutex::new(frames.into()),
            decisions,
            calls: AtomicUsize::new(0),
            fail_decision: false,
        },
        received,
    )
}

struct Cancelled(Arc<AtomicBool>);
impl Drop for Cancelled {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn refresh_uses_a_new_exact_frame_and_waits_for_the_service_result() {
    let request_id = Uuid::new_v4();
    let review_id = Uuid::new_v4();
    let first = frame(request_id, review_id);
    let second = frame(request_id, review_id);
    let first_id = first.frame_id;
    let second_id = second.frame_id;
    let identity = first.document.identity.clone();
    let (frames, mut decisions) = fixture(vec![first, second]);
    let (presenter, mut prompts) = GuiReviewPresenter::channel();
    let operation = async {
        let (id, choice) = decisions.recv().await.unwrap();
        assert_eq!(id, first_id);
        assert!(matches!(choice, TransactionReviewChoice::Refresh));
        let (id, choice) = decisions.recv().await.unwrap();
        assert_eq!(id, second_id);
        assert!(matches!(choice, TransactionReviewChoice::Approve));
        Ok(42)
    };
    let ui = async {
        let first = prompts.recv().await.unwrap();
        assert_eq!(first.document.identity, identity);
        first.response.send(GuiReviewCommand::Refresh).unwrap();
        let second = prompts.recv().await.unwrap();
        second.response.send(GuiReviewCommand::Approve).unwrap();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            drive(&frames, request_id, review_id, &presenter, operation),
            ui
        )
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap(), 42);
    assert_eq!(frames.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn ambiguous_decision_failure_is_not_replayed_and_cancels_the_operation() {
    let request_id = Uuid::new_v4();
    let review_id = Uuid::new_v4();
    let (mut frames, _decisions) = fixture(vec![frame(request_id, review_id)]);
    frames.fail_decision = true;
    let (presenter, mut prompts) = GuiReviewPresenter::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let operation = async {
        let _cancelled = Cancelled(cancelled.clone());
        std::future::pending::<Result<()>>().await
    };
    let ui = async {
        prompts
            .recv()
            .await
            .unwrap()
            .response
            .send(GuiReviewCommand::Approve)
            .unwrap();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            drive(&frames, request_id, review_id, &presenter, operation),
            ui
        )
    })
    .await
    .unwrap();
    assert!(result.unwrap_err().to_string().contains("reply lost"));
    assert!(cancelled.load(Ordering::SeqCst));
    assert_eq!(frames.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn service_completion_invalidates_an_unanswered_gui_prompt() {
    let request_id = Uuid::new_v4();
    let review_id = Uuid::new_v4();
    let (frames, _decisions) = fixture(vec![frame(request_id, review_id)]);
    let (presenter, mut prompts) = GuiReviewPresenter::channel();
    let (finish, finished) = oneshot::channel();
    let operation = async {
        finished.await.unwrap();
        Ok(9)
    };
    let ui = async {
        let prompt = prompts.recv().await.unwrap();
        finish.send(()).unwrap();
        prompt
    };
    let (result, prompt) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            drive(&frames, request_id, review_id, &presenter, operation),
            ui
        )
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap(), 9);
    assert!(prompt.response.is_closed());
    assert_eq!(frames.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn another_review_session_is_never_presented_or_decided() {
    let request_id = Uuid::new_v4();
    let (frames, _decisions) = fixture(vec![frame(request_id, Uuid::new_v4())]);
    let (presenter, mut prompts) = GuiReviewPresenter::channel();
    let result = drive(
        &frames,
        request_id,
        Uuid::new_v4(),
        &presenter,
        std::future::pending::<Result<()>>(),
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("session changed"));
    assert!(prompts.try_recv().is_err());
    assert_eq!(frames.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelled_review_still_runs_connection_closure() {
    let (closed, completion) = oneshot::channel();
    let guard = CloseOnDrop::start(async move {
        closed.send(()).unwrap();
        Ok(())
    });
    drop(guard);
    tokio::time::timeout(Duration::from_secs(2), completion)
        .await
        .unwrap()
        .unwrap();
    let guard = CloseOnDrop::start(async { Ok(()) });
    guard.close().await.unwrap();
}
