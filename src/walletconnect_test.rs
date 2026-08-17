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

fn paired(manager: &mut WalletConnectManager, byte: &str) -> Uuid {
    let uri = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}",
        byte.repeat(32),
        "22".repeat(32)
    );
    manager.begin_uri(&uri).unwrap().1.id
}

#[test]
fn a_pairing_becomes_a_connection_only_once_it_settles() {
    let mut manager = WalletConnectManager::default();
    let id = paired(&mut manager, "11");
    // Paired, then waiting on the dapp: nothing about this has been shown to
    // the owner, let alone approved by them.
    assert!(!manager.sessions()[0].settled);
    manager.update(id, SessionStatus::AwaitingProposal, None, 0, None);
    assert!(!manager.sessions()[0].settled);

    manager.update(
        id,
        SessionStatus::Connected,
        Some("Example".into()),
        0,
        None,
    );
    assert!(manager.sessions()[0].settled);

    // A dapp that walks away does not un-approve itself. The row stays so the
    // owner can see what happened to something they did let in.
    manager.update(id, SessionStatus::Disconnecting, None, 0, None);
    assert!(manager.sessions()[0].settled);
}

#[test]
fn a_pairing_that_fails_before_settling_frees_its_slot() {
    let mut manager = WalletConnectManager::default();
    let unsettled = paired(&mut manager, "33");
    let connected = paired(&mut manager, "44");
    manager.update(connected, SessionStatus::Connected, None, 0, None);

    // Nothing draws an unsettled pairing, so an error left on one would be
    // invisible — and the entry would hold a slot against the session cap
    // that no button on screen could ever free. The connect panel reports
    // that failure instead.
    manager.fail(unsettled, "relay refused the subscription".into());
    let sessions = manager.sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, connected);

    // A settled one keeps its row, because there the error belongs beside a
    // dapp the owner recognizes.
    manager.fail(connected, "the relay dropped".into());
    let sessions = manager.sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].last_error.as_deref(), Some("the relay dropped"));
    assert_eq!(sessions[0].status, SessionStatus::Disconnecting);
}
