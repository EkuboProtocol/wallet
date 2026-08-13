use super::*;

#[test]
fn malformed_and_expired_uris_never_create_sessions() {
    let mut manager = WalletConnectManager::default();
    assert!(manager.begin_uri("not-walletconnect").is_err());
    assert!(manager.sessions().is_empty());
    let expired = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}&expiryTimestamp=1",
        "11".repeat(32),
        "22".repeat(32)
    );
    assert!(manager.begin_uri(&expired).is_err());
    assert!(manager.sessions().is_empty());
}

#[test]
fn manager_keeps_multiple_sessions_only_in_memory() {
    let mut manager = WalletConnectManager::default();
    for byte in ["11", "33"] {
        let uri = format!(
            "wc:{}@2?relay-protocol=irn&symKey={}",
            byte.repeat(32),
            "22".repeat(32)
        );
        manager.begin_uri(&uri).unwrap();
    }
    assert_eq!(manager.sessions().len(), 2);
    manager.disconnect_all();
    assert!(manager.sessions().is_empty());
}

#[test]
fn disconnect_cancels_the_live_session() {
    let mut manager = WalletConnectManager::default();
    let uri = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}",
        "44".repeat(32),
        "55".repeat(32)
    );
    let (start, summary) = manager.begin_uri(&uri).unwrap();
    assert!(!start.shutdown.is_cancelled());
    let removed = manager.disconnect(summary.id).unwrap();
    assert_eq!(removed.id, summary.id);
    assert!(start.shutdown.is_cancelled());
    assert!(manager.sessions().is_empty());
}

#[test]
fn live_status_updates_preserve_the_dapp_name() {
    let mut manager = WalletConnectManager::default();
    let uri = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}",
        "66".repeat(32),
        "77".repeat(32)
    );
    let (_, summary) = manager.begin_uri(&uri).unwrap();
    manager.update(
        summary.id,
        SessionStatus::Connected,
        Some("Example".into()),
        1,
        Some(1_900_000_000),
    );
    manager.update(summary.id, SessionStatus::Connected, None, 0, None);
    let current = manager.sessions().pop().unwrap();
    assert_eq!(current.dapp_name.as_deref(), Some("Example"));
    assert_eq!(current.active_requests, 0);
    assert_eq!(current.expires_at, Some(1_900_000_000));
}
