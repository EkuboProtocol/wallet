use super::*;

#[test]
fn malformed_and_expired_uris_never_create_sessions() {
    let mut manager = WalletConnectManager::default();
    assert!(manager.add_uri("not-walletconnect").is_err());
    assert!(manager.sessions().is_empty());
    let expired = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}&expiryTimestamp=1",
        "11".repeat(32),
        "22".repeat(32)
    );
    assert!(manager.add_uri(&expired).is_err());
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
        manager.add_uri(&uri).unwrap();
    }
    assert_eq!(manager.sessions().len(), 2);
    manager.disconnect_all();
    assert!(manager.sessions().is_empty());
}
