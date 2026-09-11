//! Reconcile authoritative service proposals into single-use desktop reviews.

use super::DappProposalUpdate;
use crate::desktop_dapp_review::DesktopDappPrompt;
use anyhow::{Result, ensure};
use async_trait::async_trait;
use ekubo_wallet_client::{
    dapp_review::DappReview,
    events::{EventBatch, EventCursor},
};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[async_trait]
trait ReviewSource: Sync {
    async fn events(&self, after: Option<EventCursor>) -> Result<EventBatch>;
    async fn reviews(&self) -> Result<Vec<DappReview>>;
}

#[async_trait]
impl ReviewSource for ekubo_wallet_client::OwnerClient {
    async fn events(&self, after: Option<EventCursor>) -> Result<EventBatch> {
        self.wait_for_events(after).await
    }
    async fn reviews(&self) -> Result<Vec<DappReview>> {
        self.dapp_reviews().await
    }
}

struct TrackedReview {
    review: DappReview,
    active: CancellationToken,
}

#[derive(Default)]
struct ReviewFeed {
    tracked: BTreeMap<Uuid, TrackedReview>,
}

impl Drop for ReviewFeed {
    fn drop(&mut self) {
        for tracked in self.tracked.values() {
            tracked.active.cancel();
        }
    }
}

impl ReviewFeed {
    fn reconcile(&mut self, reviews: Vec<DappReview>) -> Result<Option<Vec<DesktopDappPrompt>>> {
        ensure!(
            reviews.len() <= crate::walletconnect::MAX_WALLETCONNECT_SESSIONS,
            "too many dapp proposals in service snapshot"
        );
        let mut seen = BTreeSet::new();
        // Validate the entire snapshot before changing any live review. The
        // service already bounds its queue, but duplicate IDs are never usable.
        for review in &reviews {
            ensure!(
                seen.insert(review.session_id),
                "duplicate dapp proposal in service snapshot"
            );
            ensure!(
                !review.choices.is_empty(),
                "dapp proposal has no account choices"
            );
        }
        let mut changed = false;
        self.tracked.retain(|id, tracked| {
            if seen.contains(id) {
                return true;
            }
            tracked.active.cancel();
            changed = true;
            false
        });
        let mut prompts = Vec::new();
        for review in reviews {
            if self
                .tracked
                .get(&review.session_id)
                .is_some_and(|tracked| tracked.review == review)
            {
                continue;
            }
            let active = CancellationToken::new();
            prompts.push(DesktopDappPrompt::service(review.clone(), active.clone()));
            if let Some(old) = self
                .tracked
                .insert(review.session_id, TrackedReview { review, active })
            {
                old.active.cancel();
            }
            changed = true;
        }
        Ok(changed.then_some(prompts))
    }
}

pub(super) async fn run(
    owner: &ekubo_wallet_client::OwnerClient,
    updates: &mpsc::Sender<DappProposalUpdate>,
) -> Result<()> {
    consume(owner, updates).await
}

async fn consume(
    source: &impl ReviewSource,
    updates: &mpsc::Sender<DappProposalUpdate>,
) -> Result<()> {
    let mut feed = ReviewFeed::default();
    let mut cursor = None;
    loop {
        // Establish the cursor BEFORE reading state. An event racing the read
        // remains available to the next wait; initial/gap batches refresh too.
        let batch = source.events(cursor).await?;
        cursor = Some(batch.cursor);
        if let Some(prompts) = feed.reconcile(source.reviews().await?)? {
            updates
                .send(DappProposalUpdate::Changed(prompts))
                .await
                .map_err(|_| anyhow::anyhow!("WalletConnect review UI is unavailable"))?;
        }
    }
}

#[cfg(test)]
#[path = "service_dapp_proposals_test.rs"]
mod tests;
