use super::*;

#[tokio::test]
async fn no_desktop_or_legal_acceptance_means_no_session_worker() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let (active, receiver) = watch::channel(0);
    let runtime = DappRuntime::new(owner, DappReviews::default(), receiver);
    assert!(runtime.begin("not-a-pairing").is_err());
    active.send_replace(1);
    assert!(runtime.begin("not-a-pairing").is_err());
    assert!(runtime.sessions().unwrap().is_empty());
    assert!(runtime.jobs.lock().unwrap().workers.is_empty());
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn session_results_survive_worker_completion_until_read() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let (_active, receiver) = watch::channel(1);
    let runtime = DappRuntime::new(owner, DappReviews::default(), receiver);
    let id = Uuid::new_v4();
    let (complete, result) = watch::channel(None);
    runtime.jobs.lock().unwrap().results.insert(id, result);
    complete.send_replace(Some(Err("synthetic relay failure".into())));
    assert_eq!(
        runtime.wait(id).await.unwrap_err().to_string(),
        "synthetic relay failure"
    );
    assert!(runtime.wait(Uuid::new_v4()).await.is_err());
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn last_desktop_departure_cancels_the_session_worker() {
    use crate::config::{WalletMetadata, WalletSource};
    use ekubo_wallet_core::legal::LegalDocument;
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    owner
        .config()
        .update_for_test(|state| {
            state.wallets.push(WalletMetadata {
                id: "primary".into(),
                instance_id: Uuid::new_v4(),
                address: alloy::primitives::Address::from([1; 20]),
                created_at: chrono::Utc::now(),
                source: WalletSource::Created,
                exported_at: None,
            });
            Ok(())
        })
        .unwrap();
    for document in [LegalDocument::TermsOfService, LegalDocument::PrivacyPolicy] {
        let (_, digest) = owner.legal_document(document);
        owner.accept_legal(document, &digest).unwrap();
    }
    let (active, receiver) = watch::channel(1);
    let runtime = Arc::new(DappRuntime::new(owner, DappReviews::default(), receiver));
    let supervised = runtime.clone();
    let supervisor = tokio::spawn(async move { supervised.supervise().await });
    let uri = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}",
        "11".repeat(32),
        "22".repeat(32)
    );
    let handle = tokio::runtime::Handle::current();
    // Exercise worker registration and cancellation without opening a relay.
    let summary = runtime
        .begin_with(&uri, move |worker| {
            handle.block_on(async move {
                worker.start.shutdown.cancelled().await;
                Ok(())
            })
        })
        .unwrap();
    assert_eq!(runtime.sessions().unwrap().len(), 1);
    active.send_replace(0);
    tokio::time::timeout(Duration::from_secs(1), runtime.wait(summary.id))
        .await
        .unwrap()
        .unwrap();
    assert!(runtime.sessions().unwrap().is_empty());
    runtime.shutdown().await.unwrap();
    supervisor.abort();
    assert!(supervisor.await.unwrap_err().is_cancelled());
    assert!(runtime.begin(&uri).is_err());
}
