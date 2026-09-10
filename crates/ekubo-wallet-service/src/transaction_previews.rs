//! Bounded background generation of advisory transaction text. This worker
//! never receives caller-authored plans, metadata, signing proofs, or keys.

use crate::authority::OwnerApi;
use anyhow::{Context as _, Result, ensure};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct TransactionPreviews {
    slot: Arc<Semaphore>,
    requests: Arc<Semaphore>,
}

impl Default for TransactionPreviews {
    fn default() -> Self {
        Self {
            slot: Arc::new(Semaphore::new(1)),
            requests: Arc::new(Semaphore::new(16)),
        }
    }
}

impl TransactionPreviews {
    pub(crate) fn shutdown(&self) {
        self.requests.close();
        self.slot.close();
    }

    pub(crate) async fn generate(
        &self,
        owner: OwnerApi,
        request_ids: Vec<Uuid>,
    ) -> Result<BTreeMap<Uuid, String>> {
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
            owner.transaction_previews(&records.iter().collect::<Vec<_>>())
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
            // A blocking inference cannot be interrupted safely. Keep the slot
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
