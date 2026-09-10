use super::*;
use ekubo_wallet_core::policy_store::register_test_database_key;
use std::time::Duration;

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
    let slot = sessions.slots.clone().try_acquire_owned().unwrap();
    let active = ActiveSession::new(sessions.active.clone(), slot);
    assert!(
        sessions
            .supervise(config, EventBus::default())
            .await
            .is_err()
    );
    drop(active);
    assert_eq!(*sessions.active.borrow(), 0);
}

/// This exercises connection lifetime on a private bus. Owner UID authorization
/// is a separate core check at the real interface, before `hold` is invoked.
#[tokio::test]
#[ignore = "requires dbus-daemon; launches an isolated test bus"]
async fn desktop_disconnect_releases_its_execution_session() {
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};
    struct Bus(std::process::Child);
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut daemon = Bus(Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap());
    let mut address = String::new();
    BufReader::new(daemon.0.stdout.take().unwrap())
        .read_line(&mut address)
        .unwrap();
    let service = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let desktop = zbus::connection::Builder::address(address.trim())
        .unwrap()
        .build()
        .await
        .unwrap();
    let sender = desktop.unique_name().unwrap().clone();
    let sessions = DesktopSessions::default();
    let mut activity = sessions.active.subscribe();
    let holder = sessions.clone();
    let lease = tokio::spawn(async move { holder.hold(&service, &sender).await });
    tokio::time::timeout(Duration::from_secs(5), activity.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*activity.borrow_and_update(), 1);
    desktop.close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), lease)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(*sessions.active.borrow(), 0);
    assert_eq!(sessions.slots.available_permits(), 32);
}
