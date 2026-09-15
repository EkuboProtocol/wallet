use super::*;
use ekubo_wallet_core::policy_store::{DatabaseKey, register_test_database_key};

#[tokio::test]
async fn empty_profile_runs_until_cancelled_without_publishing_idle_events() {
    let directory = tempfile::tempdir().unwrap();
    register_test_database_key(directory.path(), [0x53; 32]).unwrap();
    let config = ConfigStore::open(directory.path(), DatabaseKey::new([0x53; 32]));
    assert!(config.load().unwrap().wallets.is_empty());
    let events = EventBus::default();
    let mut received = events.subscribe();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), run(config, events),)
            .await
            .is_err()
    );
    assert!(received.try_recv().is_err());
}

#[tokio::test]
async fn invalid_storage_fails_before_entering_the_driver() {
    let file = tempfile::NamedTempFile::new().unwrap();
    // Register a fake key even for this invalid path so no production open can
    // reach the machine credential store while testing the initialization error.
    register_test_database_key(file.path(), [0x54; 32]).unwrap();
    let outcome = run(ConfigStore::new(file.path()), EventBus::default()).await;
    assert!(outcome.is_err());
    assert_eq!(std::fs::metadata(file.path()).unwrap().len(), 0);
}
