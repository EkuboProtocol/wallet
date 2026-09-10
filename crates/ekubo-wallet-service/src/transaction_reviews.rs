//! Shared review broker. The initiating owner RPC runs core orchestration on
//! its authenticated task; only display frames and choices cross the boundary.

use crate::{
    authority::{OwnerApi, ReviewedTransaction},
    events::{DomainEventKind, EventBus},
    gui_review::{GuiReviewCommand, GuiReviewPresenter, GuiReviewPrompt},
};
use anyhow::{Context as _, Result, bail, ensure};
use ekubo_wallet_client::transaction_review::{TransactionReviewChoice, TransactionReviewFrame};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_REVIEWS: usize = 16;

struct PendingFrame {
    frame_id: Uuid,
    prompt: GuiReviewPrompt,
}

#[derive(Clone, Default)]
pub(crate) struct TransactionReviews {
    state: Arc<Mutex<BTreeMap<Uuid, Option<PendingFrame>>>>,
    closed: CancellationToken,
}

struct Reservation {
    broker: TransactionReviews,
    request_id: Uuid,
    events: EventBus,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.broker.state.lock() {
            state.remove(&self.request_id);
        }
        self.events.publish(DomainEventKind::ReviewChanged {
            request_id: self.request_id,
        });
    }
}

impl TransactionReviews {
    fn state(&self) -> Result<MutexGuard<'_, BTreeMap<Uuid, Option<PendingFrame>>>> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("transaction review queue lock was poisoned"))
    }

    fn reserve(&self, request_id: Uuid, events: EventBus) -> Result<Reservation> {
        let mut state = self.state()?;
        ensure!(
            !self.closed.is_cancelled(),
            "transaction review broker is closed"
        );
        ensure!(
            !state.contains_key(&request_id),
            "transaction already has an active review"
        );
        ensure!(state.len() < MAX_REVIEWS, "too many transaction reviews");
        state.insert(request_id, None);
        Ok(Reservation {
            broker: self.clone(),
            request_id,
            events,
        })
    }

    pub(crate) fn shutdown(&self) -> Result<()> {
        let mut state = self.state()?;
        self.closed.cancel();
        state.clear();
        Ok(())
    }

    pub(crate) async fn review(
        &self,
        owner: &OwnerApi,
        request_id: Uuid,
    ) -> Result<ReviewedTransaction> {
        let (presenter, incoming) = GuiReviewPresenter::channel();
        self.run(
            request_id,
            incoming,
            Box::pin(owner.review_transaction(request_id, &presenter)),
            owner.event_bus(),
        )
        .await
    }

    async fn run<T>(
        &self,
        request_id: Uuid,
        incoming: mpsc::UnboundedReceiver<GuiReviewPrompt>,
        operation: impl Future<Output = Result<T>>,
        events: EventBus,
    ) -> Result<T> {
        // This reservation outlives presentation, including native auth and
        // exact-byte submission. Caller cancellation drops the whole scope.
        let _reservation = self.reserve(request_id, events.clone())?;
        tokio::select! {
            biased;
            () = self.closed.cancelled() => bail!("transaction review broker is closed"),
            result = operation => result,
            result = self.collect(request_id, incoming, events) => {
                result?;
                bail!("transaction review presenter closed without a result")
            }
        }
    }

    async fn collect(
        &self,
        request_id: Uuid,
        mut incoming: mpsc::UnboundedReceiver<GuiReviewPrompt>,
        events: EventBus,
    ) -> Result<()> {
        // GuiReviewPresenter waits for each single-use response before it can
        // emit another frame, so this channel cannot build a review backlog.
        while let Some(prompt) = incoming.recv().await {
            self.insert(request_id, prompt)?;
            events.publish(DomainEventKind::ReviewChanged { request_id });
        }
        Ok(())
    }

    fn insert(&self, request_id: Uuid, prompt: GuiReviewPrompt) -> Result<()> {
        let mut state = self.state()?;
        ensure!(
            !self.closed.is_cancelled(),
            "transaction review broker is closed"
        );
        let slot = state
            .get_mut(&request_id)
            .context("transaction review is no longer active")?;
        ensure!(
            slot.is_none(),
            "transaction review already has a pending frame"
        );
        ensure!(
            !prompt.response.is_closed(),
            "transaction review is no longer active"
        );
        *slot = Some(PendingFrame {
            frame_id: Uuid::new_v4(),
            prompt,
        });
        Ok(())
    }

    pub(crate) fn frame(&self, request_id: Uuid) -> Result<Option<TransactionReviewFrame>> {
        let state = self.state()?;
        Ok(state
            .get(&request_id)
            .and_then(Option::as_ref)
            .filter(|pending| !pending.prompt.response.is_closed())
            .map(|pending| TransactionReviewFrame {
                request_id,
                frame_id: pending.frame_id,
                document: pending.prompt.document.clone(),
                simulation: pending.prompt.simulation.clone(),
            }))
    }

    pub(crate) fn decide(
        &self,
        request_id: Uuid,
        frame_id: Uuid,
        reviewed_identity: &str,
        choice: TransactionReviewChoice,
        events: &EventBus,
    ) -> Result<()> {
        let mut state = self.state()?;
        ensure!(
            !self.closed.is_cancelled(),
            "transaction review broker is closed"
        );
        let slot = state
            .get_mut(&request_id)
            .context("transaction review is no longer active")?;
        let pending = slot
            .as_ref()
            .context("transaction review has no pending frame")?;
        ensure!(
            pending.frame_id == frame_id && pending.prompt.document.identity == reviewed_identity,
            "transaction review changed; review it again"
        );
        let command = match choice {
            TransactionReviewChoice::Approve => GuiReviewCommand::Approve,
            TransactionReviewChoice::Reject => GuiReviewCommand::Reject,
            TransactionReviewChoice::Refresh => GuiReviewCommand::Refresh,
            TransactionReviewChoice::Close => GuiReviewCommand::Close,
        };
        // Serialize delivery against shutdown and consume the exact frame once.
        slot.take()
            .expect("checked under the same lock")
            .prompt
            .response
            .send(command)
            .map_err(|_| anyhow::anyhow!("transaction review is no longer active"))?;
        drop(state);
        events.publish(DomainEventKind::ReviewChanged { request_id });
        Ok(())
    }
}

#[cfg(test)]
#[path = "transaction_reviews_test.rs"]
mod tests;
