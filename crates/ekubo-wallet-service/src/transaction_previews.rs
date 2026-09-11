//! Bounded background preparation of advisory transaction evidence. This worker
//! never receives caller-authored plans, metadata, signing proofs, or keys.

use crate::authority::OwnerApi;
use anyhow::{Context as _, Result, ensure};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct TransactionPreviews {
    slot: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    transfers: crate::preview_transfer::PreviewTransfers,
}

impl Default for TransactionPreviews {
    fn default() -> Self {
        Self {
            transfers: crate::preview_transfer::PreviewTransfers::default(),
            slot: Arc::new(Semaphore::new(1)),
            requests: Arc::new(Semaphore::new(16)),
        }
    }
}

impl TransactionPreviews {
    pub(crate) fn shutdown(&self) {
        self.transfers.clear();
        self.requests.close();
        self.slot.close();
    }

    pub(crate) fn page(
        &self,
        id: Uuid,
        offset: usize,
    ) -> Result<ekubo_wallet_client::preview_page::PreviewPage> {
        ensure!(!self.requests.is_closed(), "preview worker is stopped");
        self.transfers.read(id, offset)
    }

    pub(crate) async fn begin(
        &self,
        owner: OwnerApi,
        request_ids: Vec<Uuid>,
    ) -> Result<ekubo_wallet_client::preview_page::PreviewPage> {
        let text = self.generate(owner, request_ids).await?;
        ensure!(!self.requests.is_closed(), "preview worker is stopped");
        self.transfers.begin(text)
    }

    pub(crate) async fn generate(&self, owner: OwnerApi, request_ids: Vec<Uuid>) -> Result<String> {
        // Match the existing desktop batch size without making the transport
        // allocate or decode an unbounded collection of execution plans.
        ensure!(
            request_ids.len() <= 8,
            "at most 8 transaction previews can be generated at once"
        );
        self.run(move || {
            let records = request_ids
                .into_iter()
                .map(|id| owner.transaction(id))
                .collect::<Result<Vec<_>>>()?;
            Ok(serde_json::to_string(&owner.transaction_preview_inputs(
                &records.iter().collect::<Vec<_>>(),
            )?)?)
        })
        .await
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let request = self
            .requests
            .clone()
            .try_acquire_owned()
            .context("transaction preview queue is full or stopped")?;
        let slot = self
            .slot
            .clone()
            .acquire_owned()
            .await
            .context("transaction preview worker is stopped")?;
        tokio::task::spawn_blocking(move || {
            // A blocking evidence read cannot be interrupted safely. Keep the slot
            // in the worker even if its RPC future is dropped. No native owner
            // authentication context is inherited by this advisory-only work.
            let _slot = slot;
            let _request = request;
            work()
        })
        .await
        .context("transaction preview worker failed")?
    }
}

#[cfg(test)]
#[path = "transaction_previews_test.rs"]
mod tests;
