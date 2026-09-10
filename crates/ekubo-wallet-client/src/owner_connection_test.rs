use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone)]
struct Transport {
    calls: Arc<AtomicUsize>,
    response: Option<String>,
}

impl sealed::Sealed for Transport {}

impl OwnerTransport for Transport {
    fn exchange(
        &self,
        _: &str,
    ) -> impl std::future::Future<Output = Result<Zeroizing<String>>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(
            self.response
                .clone()
                .map(Zeroizing::new)
                .ok_or_else(|| anyhow::anyhow!("reply lost after dispatch")),
        )
    }
    async fn hold(&self) -> Result<()> {
        std::future::pending().await
    }
    fn close(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        std::future::ready(Ok(()))
    }
}

fn client(response: Option<String>) -> OwnerConnection<Transport> {
    OwnerConnection::from_transport(Transport {
        calls: Arc::new(AtomicUsize::new(0)),
        response,
    })
}

#[tokio::test]
async fn ambiguous_mutation_failure_is_never_replayed() {
    let client = client(None);
    assert!(client.create_account("test").await.is_err());
    assert_eq!(client.transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn oversized_request_is_rejected_before_transport_dispatch() {
    let client = client(None);
    let wallet_id = "x".repeat(crate::framing::MAX_FRAME_BYTES);
    let error = client.create_account(&wallet_id).await.unwrap_err();
    assert!(error.to_string().contains("request exceeds"));
    assert_eq!(client.transport.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn oversized_reply_is_rejected_before_deserialization() {
    // Valid JSON with extra whitespace must still respect the wire bound.
    let client = client(Some(format!(
        "[]{}",
        " ".repeat(crate::framing::MAX_FRAME_BYTES)
    )));
    let error = client.accounts().await.unwrap_err();
    assert!(error.to_string().contains("response exceeds"));
    assert_eq!(client.transport.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn typed_owner_and_snapshot_reads_share_the_same_transport() {
    let client = client(Some("[]".into()));
    assert!(client.accounts().await.unwrap().is_empty());
    assert!(
        crate::desktop_snapshot::SnapshotReader::accounts(&client)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(client.transport.calls.load(Ordering::SeqCst), 2);
}
