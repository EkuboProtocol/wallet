use super::*;
use ekubo_wallet_core::policy_store::register_test_database_key;
use std::time::Duration;

#[test]
fn pending_connections_are_bounded_without_starting_jobs() {
    let sessions = DesktopSessions::default();
    let mut reserved = (0..32)
        .map(|_| sessions.reserve().unwrap())
        .collect::<Vec<_>>();
    assert!(sessions.reserve().is_err());
    assert_eq!(*sessions.activity().borrow(), 0);
    let active = reserved.pop().unwrap().activate();
    assert_eq!(*sessions.activity().borrow(), 1);
    assert!(sessions.reserve().is_err());
    drop(reserved);
    assert_eq!(*sessions.activity().borrow(), 1);
    assert_eq!(sessions.slots.available_permits(), 31);
    drop(active);
    assert_eq!(*sessions.activity().borrow(), 0);
    assert_eq!(sessions.slots.available_permits(), 32);
}

#[tokio::test]
async fn cancelling_one_connection_preserves_other_desktop_sessions() {
    let sessions = DesktopSessions::default();
    let other = sessions.reserve().unwrap().activate();
    let reservation = sessions.reserve().unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _active = reservation.activate();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    started.await.unwrap();
    assert_eq!(*sessions.activity().borrow(), 2);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(*sessions.activity().borrow(), 1);
    assert_eq!(sessions.slots.available_permits(), 31);
    drop(other);
    assert_eq!(*sessions.activity().borrow(), 0);
    assert_eq!(sessions.slots.available_permits(), 32);
}

#[tokio::test]
async fn supervisor_opens_storage_only_when_a_desktop_is_active() {
    let file = tempfile::NamedTempFile::new().unwrap();
    register_test_database_key(file.path(), [0x43; 32]).unwrap();
    let config = ConfigStore::new(file.path());
    let sessions = DesktopSessions::default();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            sessions.supervise(config.clone(), EventBus::default())
        )
        .await
        .is_err()
    );
    let active = sessions.reserve().unwrap().activate();
    assert!(
        sessions
            .supervise(config, EventBus::default())
            .await
            .is_err()
    );
    drop(active);
    assert_eq!(*sessions.active.borrow(), 0);
}
