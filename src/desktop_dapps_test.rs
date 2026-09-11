use super::*;
use crate::{events::DomainEventKind, walletconnect::SessionStatus};

fn fixture() -> (
    tempfile::TempDir,
    OwnerApi,
    DesktopDapps,
    Arc<Mutex<WalletConnectManager>>,
) {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let (presenter, _incoming) = ProposalPresenter::channel();
    let manager = Arc::new(Mutex::new(WalletConnectManager::default()));
    let dapps = DesktopDapps::local(owner.clone(), manager.clone(), presenter);
    (directory, owner, dapps, manager)
}

fn uri() -> String {
    format!(
        "wc:{}@2?relay-protocol=irn&symKey={}",
        "11".repeat(32),
        "22".repeat(32)
    )
}

#[tokio::test]
async fn snapshots_and_disconnect_reach_the_same_local_session() {
    let (_directory, owner, dapps, manager) = fixture();
    let mut events = owner.event_bus().subscribe();
    let (start, summary) = manager.lock().unwrap().begin_uri(&uri()).unwrap();
    manager.lock().unwrap().update(
        summary.id,
        SessionStatus::Connected,
        Some("Dapp".into()),
        2,
        Some(100),
    );
    let snapshot = dapps.sessions().await.unwrap();
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].settled);
    assert_eq!(snapshot[0].active_requests, 2);
    assert_eq!(snapshot[0].dapp_name.as_deref(), Some("Dapp"));
    assert_eq!(dapps.disconnect(summary.id).await.unwrap().id, summary.id);
    assert!(start.shutdown.is_cancelled());
    assert!(dapps.sessions().await.unwrap().is_empty());
    assert!(
        matches!(events.try_recv().unwrap().kind, DomainEventKind::WalletConnectChanged { session_id } if session_id == summary.id.to_string())
    );
    assert!(dapps.disconnect(summary.id).await.is_err());
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn cancellation_before_registration_does_not_consume_or_parse_the_link() {
    let (_directory, _owner, dapps, manager) = fixture();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(
        dapps
            .begin("not even a pairing URI", &cancel)
            .await
            .unwrap()
            .is_none()
    );
    assert!(manager.lock().unwrap().sessions().is_empty());
}

#[tokio::test]
async fn malformed_link_fails_without_creating_a_session() {
    let (_directory, _owner, dapps, manager) = fixture();
    assert!(dapps.begin("wc:", &CancellationToken::new()).await.is_err());
    assert!(manager.lock().unwrap().sessions().is_empty());
}

#[tokio::test]
async fn cancellation_after_registration_disconnects_the_returned_session() {
    let (_directory, _owner, dapps, manager) = fixture();
    // Register entirely in memory: no relay, credentials, or network worker.
    let (start, summary) = manager.lock().unwrap().begin_uri(&uri()).unwrap();
    let started = StartedDappSession {
        summary,
        completion: Completion::Local(tokio::spawn(async { Ok(()) })),
    };
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(
        dapps
            .finish_start(started, &cancel)
            .await
            .unwrap()
            .is_none()
    );
    assert!(start.shutdown.is_cancelled());
    assert!(dapps.sessions().await.unwrap().is_empty());
}

#[tokio::test]
async fn waiting_returns_the_session_failure_instead_of_restarting_it() {
    let (_directory, _owner, dapps, manager) = fixture();
    let (_start, summary) = manager.lock().unwrap().begin_uri(&uri()).unwrap();
    let started = StartedDappSession {
        summary,
        completion: Completion::Local(tokio::spawn(async {
            anyhow::bail!("relay session failed")
        })),
    };
    let started = dapps
        .finish_start(started, &CancellationToken::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        started.wait().await.unwrap_err().to_string(),
        "relay session failed"
    );
    assert_eq!(manager.lock().unwrap().sessions().len(), 1);
}

#[tokio::test]
async fn shutdown_closes_all_clones_before_another_registration_can_start() {
    let (_directory, _owner, dapps, manager) = fixture();
    let another = dapps.clone();
    let (start, _summary) = manager.lock().unwrap().begin_uri(&uri()).unwrap();
    dapps.shutdown().await.unwrap();
    assert!(start.shutdown.is_cancelled());
    assert!(
        another
            .begin(&uri(), &CancellationToken::new())
            .await
            .unwrap()
            .is_none()
    );
    assert!(another.sessions().await.unwrap().is_empty());
    // Direct registration, after a caller's early closed check, must also fail.
    assert!(another.start(&uri()).await.is_err());
    dapps.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_waits_for_settled_session_farewells() {
    let (_directory, _owner, dapps, manager) = fixture();
    let (start, summary) = manager.lock().unwrap().begin_uri(&uri()).unwrap();
    manager.lock().unwrap().update(
        summary.id,
        SessionStatus::Connected,
        Some("Dapp".into()),
        0,
        None,
    );
    let closing = tokio::spawn(async move { dapps.shutdown().await });
    start.shutdown.cancelled().await;
    assert!(!closing.is_finished());
    assert!(manager.lock().unwrap().sessions().is_empty());
    start.farewell.cancel();
    closing.await.unwrap().unwrap();
}
