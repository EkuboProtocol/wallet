//! Bridge between asynchronous signing orchestration and the focused GPUI review.

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use ekubo_wallet_core::{
    approval::{ApprovalDecision, Refreshed, ReviewDocument, ReviewPresenter, ReviewRefresh},
    simulation::SimulationResult,
};
use tokio::sync::{mpsc, oneshot};

/// A generation-scoped action emitted by the native review surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuiReviewCommand {
    Approve,
    Reject,
    Refresh,
    Close,
}

/// One complete review frame. The response channel is deliberately single-use:
/// a refresh produces a new frame and makes every old UI event stale.
pub struct GuiReviewPrompt {
    pub document: ReviewDocument,
    pub simulation: SimulationResult,
    pub response: oneshot::Sender<GuiReviewCommand>,
}

#[derive(Clone)]
pub struct GuiReviewPresenter {
    prompts: mpsc::UnboundedSender<GuiReviewPrompt>,
}

impl GuiReviewPresenter {
    #[must_use]
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<GuiReviewPrompt>) {
        let (prompts, receiver) = mpsc::unbounded_channel();
        (Self { prompts }, receiver)
    }
}

#[async_trait]
impl ReviewPresenter for GuiReviewPresenter {
    async fn review_transaction(
        &self,
        document: &ReviewDocument,
        simulation: &SimulationResult,
        refresh: &dyn ReviewRefresh,
    ) -> Result<ApprovalDecision> {
        let mut document = document.clone();
        let mut simulation = simulation.clone();
        loop {
            let (respond, response) = oneshot::channel();
            self.prompts
                .send(GuiReviewPrompt {
                    document: document.clone(),
                    simulation: simulation.clone(),
                    response: respond,
                })
                .map_err(|_| anyhow::anyhow!("the wallet review window is unavailable"))?;
            match response
                .await
                .context("the review was closed without a decision")?
            {
                GuiReviewCommand::Approve => return Ok(ApprovalDecision::Approved),
                GuiReviewCommand::Reject => return Ok(ApprovalDecision::Rejected),
                GuiReviewCommand::Close => bail!("the review was closed without a decision"),
                GuiReviewCommand::Refresh => {
                    let Refreshed {
                        document: refreshed_document,
                        simulation: refreshed_simulation,
                    } = refresh.resimulate().await?;
                    document = refreshed_document;
                    simulation = refreshed_simulation;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "gui_review_test.rs"]
mod tests;
