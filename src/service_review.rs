//! Drive one service-owned review while forwarding only display frames and intent.

use crate::gui_review::{GuiReviewCommand, GuiReviewPresenter};
use anyhow::{Context as _, Result, bail, ensure};
use async_trait::async_trait;
use ekubo_wallet_client::transaction_review::{TransactionReviewChoice, TransactionReviewFrame};
use std::{future::Future, time::Duration};
use uuid::Uuid;

#[async_trait]
trait ReviewFrames: Sync {
    async fn frame(
        &self,
        request_id: Uuid,
        review_id: Uuid,
    ) -> Result<Option<TransactionReviewFrame>>;
    async fn decide(
        &self,
        frame: &TransactionReviewFrame,
        choice: TransactionReviewChoice,
    ) -> Result<()>;
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[async_trait]
impl ReviewFrames for ekubo_wallet_client::OwnerClient {
    async fn frame(
        &self,
        request_id: Uuid,
        review_id: Uuid,
    ) -> Result<Option<TransactionReviewFrame>> {
        self.transaction_review_frame(request_id, review_id).await
    }

    async fn decide(
        &self,
        frame: &TransactionReviewFrame,
        choice: TransactionReviewChoice,
    ) -> Result<()> {
        self.decide_transaction_review(frame, choice).await
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) async fn review(
    owner: &ekubo_wallet_client::OwnerClient,
    request_id: Uuid,
    presenter: &GuiReviewPresenter,
) -> Result<crate::authority::ReviewedTransaction> {
    #[cfg(target_os = "linux")]
    let isolated = owner.independent_connection().await?;
    #[cfg(target_os = "linux")]
    let owner = &isolated;
    #[cfg(target_os = "linux")]
    let closing = {
        let transport = owner.clone();
        CloseOnDrop::start(async move { transport.close().await })
    };
    let review_id = Uuid::new_v4();
    let operation = drive(
        owner,
        request_id,
        review_id,
        presenter,
        owner.review_transaction(request_id, review_id),
    );
    #[cfg(target_os = "linux")]
    {
        let result = operation.await;
        let closed = closing.close().await;
        match (result, closed) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("review connection closure failed: {close_error:#}")))
            }
        }
    }
    #[cfg(target_os = "windows")]
    operation.await
}

async fn drive<T>(
    frames: &impl ReviewFrames,
    request_id: Uuid,
    review_id: Uuid,
    presenter: &GuiReviewPresenter,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    // Dropping either branch cancels the other. In particular, a failed frame
    // read or ambiguous decision reply drops the initiating RPC future. Windows
    // closes its per-call pipe; Linux's outer guard closes the dedicated peer.
    // Neither the decision nor the long-running operation is replayed.
    tokio::select! {
        biased;
        result = operation => result,
        result = present(frames, request_id, review_id, presenter) => {
            result?;
            bail!("transaction review ended without a service result")
        }
    }
}

async fn present(
    frames: &impl ReviewFrames,
    request_id: Uuid,
    review_id: Uuid,
    presenter: &GuiReviewPresenter,
) -> Result<()> {
    let mut previous_frame = None;
    loop {
        let Some(frame) = frames.frame(request_id, review_id).await? else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        ensure!(
            frame.request_id == request_id && frame.review_id == review_id,
            "transaction review session changed; review it again"
        );
        ensure!(
            Some(frame.frame_id) != previous_frame,
            "transaction review reused a consumed frame"
        );
        let command = presenter
            .present_frame(frame.document.clone(), frame.simulation.clone())?
            .await
            .context("the review was closed without a decision")?;
        let choice = match command {
            GuiReviewCommand::Approve => TransactionReviewChoice::Approve,
            GuiReviewCommand::Reject => TransactionReviewChoice::Reject,
            GuiReviewCommand::Refresh => TransactionReviewChoice::Refresh,
            GuiReviewCommand::Close => TransactionReviewChoice::Close,
        };
        frames.decide(&frame, choice).await?;
        if command != GuiReviewCommand::Refresh {
            // Native authentication, signing and submission still belong to
            // the initiating service operation. Wait for its actual result.
            return std::future::pending().await;
        }
        previous_frame = Some(frame.frame_id);
    }
}

// Dropping a D-Bus method future leaves its remote invocation alive. A detached
// supervisor therefore owns the close even when the desktop review task drops.
#[cfg(any(target_os = "linux", test))]
struct CloseOnDrop {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

#[cfg(any(target_os = "linux", test))]
impl CloseOnDrop {
    fn start(close: impl Future<Output = Result<()>> + Send + 'static) -> Self {
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = stopping.await;
            close.await
        });
        Self {
            stop: Some(stop),
            task: Some(task),
        }
    }

    async fn close(mut self) -> Result<()> {
        self.stop.take();
        self.task
            .take()
            .expect("connection closure task is owned")
            .await
            .context("review connection closure task failed")?
    }
}

#[cfg(any(target_os = "linux", test))]
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.stop.take();
    }
}

#[cfg(test)]
#[path = "service_review_test.rs"]
mod tests;
