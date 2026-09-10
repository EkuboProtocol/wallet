//! Async capture of cached desktop display data, independent of GPUI and storage.

use crate::activity::{OwnerActivityRecord, OwnerReviewQueues};
use anyhow::Result;
use ekubo_wallet_core::{
    approval::ReviewDocument,
    automation::Automation,
    automation_store::AutomationRun,
    config::{NetworkConfig, WalletMetadata},
    legal::LegalStatus,
    policy_store::StoredPolicy,
};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

/// How many of an automation's runs the tab shows.
///
/// The store keeps thousands; this screen answers "what has it been doing
/// lately", and a page rendering a per-second automation's whole history is a
/// page nobody scrolls to the end of.
pub const AUTOMATION_RUN_LIMIT: usize = 20;

/// Recent activity rows loaded for the desktop snapshot.
pub const ACTIVITY_LIMIT: u16 = 200;

/// Read-only inputs for desktop capture. Implementations must keep blocking
/// database and decoding work off the async executor. No mutation or signing
/// capability is included in this interface.
pub trait SnapshotReader: Sync {
    fn reviews(&self) -> impl std::future::Future<Output = Result<OwnerReviewQueues>> + Send;
    fn automations(&self) -> impl std::future::Future<Output = Result<Vec<Automation>>> + Send;
    fn automation_runs(
        &self,
        automation_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<AutomationRun>>> + Send;
    fn activity(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<OwnerActivityRecord>>> + Send;
    fn activity_sources(
        &self,
    ) -> impl std::future::Future<Output = Result<BTreeMap<Uuid, String>>> + Send;
    fn accounts(&self) -> impl std::future::Future<Output = Result<Vec<WalletMetadata>>> + Send;
    fn legal_status(&self) -> impl std::future::Future<Output = Result<LegalStatus>> + Send;
    fn networks(&self) -> impl std::future::Future<Output = Result<Vec<NetworkConfig>>> + Send;
    fn policy(
        &self,
        wallet_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoredPolicy>>> + Send;
    fn message_review_document(
        &self,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<ReviewDocument>> + Send;
    fn typed_data_review_document(
        &self,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<ReviewDocument>> + Send;
    fn saved_transaction_summaries(
        &self,
        request_ids: &[Uuid],
    ) -> impl std::future::Future<Output = Result<BTreeMap<Uuid, String>>> + Send;
    fn transaction_headlines(
        &self,
        request_ids: &[Uuid],
    ) -> impl std::future::Future<Output = Result<BTreeMap<Uuid, String>>> + Send;
    fn native_token_prices(
        &self,
    ) -> impl std::future::Future<Output = Result<BTreeMap<u64, f64>>> + Send;
}

#[derive(Clone)]
pub struct DesktopSnapshot {
    pub reviews: std::result::Result<OwnerReviewQueues, String>,
    pub activity: std::result::Result<Arc<[OwnerActivityRecord]>, String>,
    /// Which agent asked for each record, where one did. Empty rather than an
    /// error when the lookup fails: a row still names its source from the plan
    /// it carries, and a history list is not worth failing to draw over the
    /// attribution it could not read.
    pub activity_sources: BTreeMap<uuid::Uuid, String>,
    /// What each transaction record's plan does, in one line, for the rows
    /// that name a request before anybody opens it. Decoded here for the same
    /// reason everything else is: the drawing path may not open the database,
    /// and it certainly may not run the descriptor engine over a history list
    /// once a frame.
    ///
    /// Absent for a plan nothing recognized, which is what leaves such a row
    /// titled by its kind alone.
    pub transaction_headlines: BTreeMap<uuid::Uuid, String>,
    /// Persisted, call-data-only AI summaries for pending and past transactions.
    pub transaction_previews: BTreeMap<uuid::Uuid, String>,
    pub accounts: std::result::Result<Vec<WalletMetadata>, String>,
    pub policies: BTreeMap<String, std::result::Result<Option<StoredPolicy>, String>>,
    pub legal_status: std::result::Result<LegalStatus, String>,
    pub networks: std::result::Result<Vec<NetworkConfig>, String>,
    pub automations: std::result::Result<Vec<Automation>, String>,
    /// The recent runs of each automation. Captured with the automations
    /// themselves so the tab draws a complete row in one pass rather than
    /// fetching per card while the reader watches.
    pub automation_runs: BTreeMap<uuid::Uuid, Vec<AutomationRun>>,
    pub message_documents: BTreeMap<uuid::Uuid, std::result::Result<ReviewDocument, String>>,
    pub typed_data_documents: BTreeMap<uuid::Uuid, std::result::Result<ReviewDocument, String>>,
    /// What the owner says each chain's own currency is worth. Read here
    /// rather than at render time, like everything else the portfolio draws:
    /// nothing on the drawing path may open the database.
    pub native_token_prices: BTreeMap<u64, f64>,
}

#[cfg(target_os = "linux")]
impl SnapshotReader for crate::OwnerClient {
    async fn reviews(&self) -> Result<OwnerReviewQueues> {
        crate::OwnerClient::reviews(self, None).await
    }
    async fn automations(&self) -> Result<Vec<Automation>> {
        crate::OwnerClient::automations(self).await
    }
    async fn automation_runs(&self, automation_id: Uuid) -> Result<Vec<AutomationRun>> {
        crate::OwnerClient::automation_runs(self, automation_id, AUTOMATION_RUN_LIMIT).await
    }
    async fn activity(&self) -> Result<Vec<OwnerActivityRecord>> {
        crate::OwnerClient::activity(self, None, ACTIVITY_LIMIT).await
    }
    async fn activity_sources(&self) -> Result<BTreeMap<Uuid, String>> {
        crate::OwnerClient::activity_sources(self).await
    }
    async fn accounts(&self) -> Result<Vec<WalletMetadata>> {
        crate::OwnerClient::accounts(self).await
    }
    async fn legal_status(&self) -> Result<LegalStatus> {
        crate::OwnerClient::legal_status(self).await
    }
    async fn networks(&self) -> Result<Vec<NetworkConfig>> {
        crate::OwnerClient::networks(self).await
    }
    async fn policy(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        crate::OwnerClient::policy(self, wallet_id).await
    }
    async fn message_review_document(&self, request_id: Uuid) -> Result<ReviewDocument> {
        crate::OwnerClient::message_review_document(self, request_id).await
    }
    async fn typed_data_review_document(&self, request_id: Uuid) -> Result<ReviewDocument> {
        crate::OwnerClient::typed_data_review_document(self, request_id).await
    }
    async fn saved_transaction_summaries(
        &self,
        request_ids: &[Uuid],
    ) -> Result<BTreeMap<Uuid, String>> {
        crate::OwnerClient::saved_transaction_summaries(self, request_ids).await
    }
    async fn transaction_headlines(&self, request_ids: &[Uuid]) -> Result<BTreeMap<Uuid, String>> {
        crate::OwnerClient::transaction_headlines(self, request_ids).await
    }
    async fn native_token_prices(&self) -> Result<BTreeMap<u64, f64>> {
        crate::OwnerClient::native_token_prices(self).await
    }
}

impl DesktopSnapshot {
    pub async fn capture(reader: &impl SnapshotReader) -> Self {
        let reviews = cache_result(reader.reviews().await);
        let automations = cache_result(reader.automations().await);
        let mut automation_runs = BTreeMap::new();
        if let Ok(automations) = &automations {
            for automation in automations {
                if let Ok(runs) = reader.automation_runs(automation.id).await {
                    automation_runs.insert(automation.id, runs);
                }
            }
        }
        let activity =
            cache_result(reader.activity().await).map(Arc::<[OwnerActivityRecord]>::from);
        let activity_sources = reader
            .activity_sources()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(id, name)| (id, ekubo_wallet_core::sanitize::stripped_capped(&name, 64)))
            .collect();
        let accounts = cache_result(reader.accounts().await);
        let legal_status = cache_result(reader.legal_status().await);
        let networks = cache_result(reader.networks().await);
        let mut policies = BTreeMap::new();
        if let Ok(accounts) = &accounts {
            for account in accounts {
                policies.insert(
                    account.id.clone(),
                    cache_result(reader.policy(&account.id).await),
                );
            }
        }
        let mut message_documents = BTreeMap::new();
        let mut typed_data_documents = BTreeMap::new();
        if let Ok(activity) = &activity {
            for record in activity.iter() {
                match record {
                    OwnerActivityRecord::Message(record) => {
                        message_documents.insert(
                            record.request_id,
                            cache_result(reader.message_review_document(record.request_id).await),
                        );
                    }
                    OwnerActivityRecord::TypedData(record) => {
                        typed_data_documents.insert(
                            record.request_id,
                            cache_result(
                                reader.typed_data_review_document(record.request_id).await,
                            ),
                        );
                    }
                    OwnerActivityRecord::Transaction(_) => {}
                }
            }
        }
        let ids = transaction_ids(&reviews, &activity);
        let transaction_previews = read_summaries(reader, &ids).await.unwrap_or_default();
        let missing = ids
            .into_iter()
            .filter(|id| !transaction_previews.contains_key(id))
            .collect::<Vec<_>>();
        let transaction_headlines = read_headlines(reader, &missing).await.unwrap_or_default();
        Self {
            reviews,
            activity,
            activity_sources,
            transaction_headlines,
            transaction_previews,
            accounts,
            policies,
            legal_status,
            networks,
            automations,
            automation_runs,
            message_documents,
            typed_data_documents,
            native_token_prices: reader.native_token_prices().await.unwrap_or_default(),
        }
    }
}

fn cache_result<T>(result: Result<T>) -> std::result::Result<T, String> {
    result.map_err(|error| format!("{error:#}"))
}

fn transaction_ids(
    reviews: &std::result::Result<OwnerReviewQueues, String>,
    activity: &std::result::Result<Arc<[OwnerActivityRecord]>, String>,
) -> Vec<Uuid> {
    let mut ids = Vec::new();
    if let Ok(reviews) = reviews {
        ids.extend(reviews.transactions.iter().map(|record| record.request_id));
    }
    if let Ok(activity) = activity {
        ids.extend(activity.iter().filter_map(|record| match record {
            OwnerActivityRecord::Transaction(record) => Some(record.request_id),
            _ => None,
        }));
    }
    let mut seen = std::collections::BTreeSet::new();
    ids.retain(|id| seen.insert(*id));
    ids
}

// Split large review inventories at the RPC bound without truncating them.
async fn read_summaries(
    reader: &impl SnapshotReader,
    ids: &[Uuid],
) -> Result<BTreeMap<Uuid, String>> {
    let mut summaries = BTreeMap::new();
    for batch in ids.chunks(1000) {
        summaries.extend(reader.saved_transaction_summaries(batch).await?);
    }
    Ok(summaries)
}
async fn read_headlines(
    reader: &impl SnapshotReader,
    ids: &[Uuid],
) -> Result<BTreeMap<Uuid, String>> {
    let mut headlines = BTreeMap::new();
    for batch in ids.chunks(1000) {
        headlines.extend(reader.transaction_headlines(batch).await?);
    }
    Ok(headlines)
}

#[cfg(test)]
#[path = "desktop_snapshot_test.rs"]
mod tests;
