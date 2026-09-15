//! Local compatibility reader while desktop authority moves to the service.
//! Each database read stays on a blocking worker; the capture algorithm is shared.

use crate::authority::OwnerApi;
use anyhow::Result;
use ekubo_wallet_client::activity::{OwnerActivityRecord, OwnerReviewQueues};
use ekubo_wallet_client::desktop_snapshot::{ACTIVITY_LIMIT, AUTOMATION_RUN_LIMIT, SnapshotReader};
use ekubo_wallet_core::{
    approval::ReviewDocument,
    automation::Automation,
    automation_store::AutomationRun,
    config::{NetworkConfig, WalletMetadata},
    legal::LegalStatus,
    policy_store::StoredPolicy,
};
use std::collections::BTreeMap;
use uuid::Uuid;

impl SnapshotReader for OwnerApi {
    async fn reviews(&self) -> Result<OwnerReviewQueues> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.reviews(None)).await?
    }
    async fn automations(&self) -> Result<Vec<Automation>> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.automations()).await?
    }
    async fn automation_runs(&self, automation_id: Uuid) -> Result<Vec<AutomationRun>> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || {
            owner.automation_runs(automation_id, AUTOMATION_RUN_LIMIT)
        })
        .await?
    }
    async fn activity(&self) -> Result<Vec<OwnerActivityRecord>> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.activity(None, ACTIVITY_LIMIT)).await?
    }
    async fn activity_sources(&self) -> Result<BTreeMap<Uuid, String>> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.activity_sources()).await?
    }
    async fn accounts(&self) -> Result<Vec<WalletMetadata>> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.accounts()).await?
    }
    async fn legal_status(&self) -> Result<LegalStatus> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.legal_status()).await?
    }
    async fn networks(&self) -> Result<Vec<NetworkConfig>> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.networks()).await?
    }
    async fn policy(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        let owner = self.clone();
        let wallet_id = wallet_id.to_owned();
        tokio::task::spawn_blocking(move || owner.policy(&wallet_id)).await?
    }
    async fn message_review_document(&self, request_id: Uuid) -> Result<ReviewDocument> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.message_review_document(request_id)).await?
    }
    async fn typed_data_review_document(&self, request_id: Uuid) -> Result<ReviewDocument> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.typed_data_review_document(request_id)).await?
    }
    async fn saved_transaction_summaries(
        &self,
        request_ids: &[Uuid],
    ) -> Result<BTreeMap<Uuid, String>> {
        let owner = self.clone();
        let request_ids = request_ids.to_vec();
        tokio::task::spawn_blocking(move || {
            let records = request_ids
                .into_iter()
                .map(|id| owner.transaction(id))
                .collect::<Result<Vec<_>>>()?;
            owner.saved_transaction_summaries(&records.iter().collect::<Vec<_>>())
        })
        .await?
    }
    async fn transaction_headlines(&self, request_ids: &[Uuid]) -> Result<BTreeMap<Uuid, String>> {
        let owner = self.clone();
        let request_ids = request_ids.to_vec();
        tokio::task::spawn_blocking(move || {
            let records = request_ids
                .into_iter()
                .map(|id| owner.transaction(id))
                .collect::<Result<Vec<_>>>()?;
            owner.transaction_headlines(&records.iter().collect::<Vec<_>>())
        })
        .await?
    }
    async fn native_token_prices(&self) -> Result<BTreeMap<u64, f64>> {
        let owner = self.clone();

        tokio::task::spawn_blocking(move || owner.native_token_prices()).await?
    }
}
