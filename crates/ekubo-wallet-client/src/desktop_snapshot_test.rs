use super::*;
use std::sync::Mutex;

#[derive(Default)]
struct Reader {
    batches: Mutex<Vec<usize>>,
}
// Suspend each fake read to exercise capture across asynchronous boundaries.
impl SnapshotReader for Reader {
    async fn reviews(&self) -> Result<OwnerReviewQueues> {
        tokio::task::yield_now().await;
        Ok(OwnerReviewQueues {
            transactions: Vec::new(),
            messages: Vec::new(),
            typed_data: Vec::new(),
            policy_proposals: Vec::new(),
            network_proposals: Vec::new(),
            token_proposals: Vec::new(),
        })
    }
    async fn automations(&self) -> Result<Vec<Automation>> {
        tokio::task::yield_now().await;
        Ok(Vec::new())
    }
    async fn automation_runs(&self, _automation_id: Uuid) -> Result<Vec<AutomationRun>> {
        tokio::task::yield_now().await;
        anyhow::bail!("synthetic read failure")
    }
    async fn activity(&self) -> Result<Vec<OwnerActivityRecord>> {
        tokio::task::yield_now().await;
        anyhow::bail!("synthetic read failure")
    }
    async fn activity_sources(&self) -> Result<BTreeMap<Uuid, String>> {
        tokio::task::yield_now().await;
        anyhow::bail!("synthetic read failure")
    }
    async fn accounts(&self) -> Result<Vec<WalletMetadata>> {
        tokio::task::yield_now().await;
        Ok(Vec::new())
    }
    async fn legal_status(&self) -> Result<LegalStatus> {
        tokio::task::yield_now().await;
        anyhow::bail!("synthetic read failure")
    }
    async fn networks(&self) -> Result<Vec<NetworkConfig>> {
        tokio::task::yield_now().await;
        Ok(Vec::new())
    }
    async fn policy(&self, _wallet_id: &str) -> Result<Option<StoredPolicy>> {
        tokio::task::yield_now().await;
        anyhow::bail!("synthetic read failure")
    }
    async fn message_review_document(&self, _request_id: Uuid) -> Result<ReviewDocument> {
        tokio::task::yield_now().await;
        anyhow::bail!("synthetic read failure")
    }
    async fn typed_data_review_document(&self, _request_id: Uuid) -> Result<ReviewDocument> {
        tokio::task::yield_now().await;
        anyhow::bail!("synthetic read failure")
    }
    async fn saved_transaction_summaries(
        &self,
        request_ids: &[Uuid],
    ) -> Result<BTreeMap<Uuid, String>> {
        tokio::task::yield_now().await;
        self.batches.lock().unwrap().push(request_ids.len());
        Ok(request_ids.iter().map(|id| (*id, id.to_string())).collect())
    }
    async fn transaction_headlines(&self, request_ids: &[Uuid]) -> Result<BTreeMap<Uuid, String>> {
        tokio::task::yield_now().await;
        self.batches.lock().unwrap().push(request_ids.len());
        Ok(request_ids.iter().map(|id| (*id, id.to_string())).collect())
    }
    async fn native_token_prices(&self) -> Result<BTreeMap<u64, f64>> {
        tokio::task::yield_now().await;
        Ok([(1, 2.0)].into_iter().collect())
    }
}

#[tokio::test]
async fn partial_read_failure_keeps_independent_snapshot_data() {
    let snapshot = DesktopSnapshot::capture(&Reader::default()).await;
    assert!(snapshot.reviews.is_ok());
    assert!(snapshot.accounts.unwrap().is_empty());
    assert!(snapshot.networks.unwrap().is_empty());
    assert!(
        snapshot
            .activity
            .unwrap_err()
            .contains("synthetic read failure")
    );
    assert!(snapshot.legal_status.is_err());
    assert!(snapshot.activity_sources.is_empty());
    assert!(snapshot.message_documents.is_empty());
    assert_eq!(snapshot.native_token_prices.get(&1), Some(&2.0));
}

#[tokio::test]
async fn large_summary_inventories_are_chunked_without_truncation() {
    let reader = Reader::default();
    let ids = (1..=2001).map(Uuid::from_u128).collect::<Vec<_>>();
    let saved = read_summaries(&reader, &ids).await.unwrap();
    let headlines = read_headlines(&reader, &ids).await.unwrap();
    assert_eq!(saved.len(), ids.len());
    assert_eq!(headlines, saved);
    assert_eq!(
        *reader.batches.lock().unwrap(),
        [1000, 1000, 1, 1000, 1000, 1]
    );
}
