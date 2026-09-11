use super::*;

#[tokio::test]
async fn no_desktop_or_legal_acceptance_means_no_session_worker() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let desktops = crate::desktop_sessions::DesktopSessions::default();
    let receiver = desktops.clone();
    let runtime = DappRuntime::new(owner, DappReviews::default(), receiver);
    assert!(runtime.begin("not-a-pairing").is_err());
    let _active = desktops.reserve().unwrap().activate();
    assert!(runtime.begin("not-a-pairing").is_err());
    assert!(runtime.sessions().unwrap().is_empty());
    assert!(runtime.jobs.lock().unwrap().workers.is_empty());
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn session_results_survive_worker_completion_until_read() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let receiver = crate::desktop_sessions::DesktopSessions::default();
    let _active = receiver.reserve().unwrap().activate();
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
async fn quick_desktop_reopen_cancels_old_workers_without_cancelling_new_sessions() {
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
    let receiver = crate::desktop_sessions::DesktopSessions::default();
    let active = receiver.reserve().unwrap().activate();
    let runtime = Arc::new(DappRuntime::new(
        owner,
        DappReviews::default(),
        receiver.clone(),
    ));
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
        .begin_with(&uri, {
            let handle = handle.clone();
            move |worker| {
                handle.block_on(async move {
                    worker.start.shutdown.cancelled().await;
                    Ok(())
                })
            }
        })
        .unwrap();
    assert_eq!(runtime.sessions().unwrap().len(), 1);
    drop(active);
    let reopened = receiver.reserve().unwrap().activate();
    let next = runtime
        .begin_with(&uri, move |worker| {
            handle.block_on(async move {
                worker.start.shutdown.cancelled().await;
                Ok(())
            })
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), runtime.wait(summary.id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime
            .sessions()
            .unwrap()
            .iter()
            .map(|session| session.id)
            .collect::<Vec<_>>(),
        vec![next.id]
    );
    assert!(
        runtime.jobs.lock().unwrap().results[&next.id]
            .borrow()
            .is_none()
    );
    drop(reopened);
    tokio::time::timeout(Duration::from_secs(1), runtime.wait(next.id))
        .await
        .unwrap()
        .unwrap();
    assert!(runtime.sessions().unwrap().is_empty());
    runtime.shutdown().await.unwrap();
    supervisor.abort();
    assert!(supervisor.await.unwrap_err().is_cancelled());
    assert!(runtime.begin(&uri).is_err());
}
