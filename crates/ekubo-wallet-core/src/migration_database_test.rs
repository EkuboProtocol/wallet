use super::*;
use crate::policy_store::PolicyStore;
use rusqlite::{Error, ErrorCode};
use std::{fs, io, time::Duration};

const KEY: [u8; 32] = [0x43; 32];
fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("wallet.db");
    let store = PolicyStore::open(&path, &DatabaseKey::new(KEY)).unwrap();
    store
        .connection
        .execute_batch(
            "CREATE TABLE migration_probe(id INTEGER PRIMARY KEY, value TEXT NOT NULL);
        CREATE INDEX migration_probe_value ON migration_probe(value);
        INSERT INTO migration_probe VALUES(1,'snapshot');
        PRAGMA user_version=37; PRAGMA application_id=42;",
        )
        .unwrap();
    drop(store);
    (dir, path)
}
fn observer(path: &Path) -> Connection {
    let connection = open_existing(path, &DatabaseKey::new(KEY)).unwrap();
    connection.busy_timeout(Duration::ZERO).unwrap();
    connection
}
fn assert_fenced(connection: &Connection) {
    let result = connection.execute("INSERT INTO migration_probe VALUES(2,'late mutation')", []);
    assert!(matches!(result, Err(Error::SqliteFailure(e, _)) if e.code == ErrorCode::DatabaseBusy));
}

#[test]
fn encrypted_snapshot_preserves_schema_data_and_header_while_source_remains_fenced() {
    let (dir, source) = fixture();
    let before = fs::read(&source).unwrap();
    let observer = observer(&source);
    let mut snapshot = MigrationDatabaseSnapshot::freeze(&source, Zeroizing::new(KEY)).unwrap();
    assert!(snapshot.wallet_inventory().unwrap().is_empty());
    assert_fenced(&observer);
    let transfer = snapshot.transfer().unwrap();
    let mut bytes = Vec::new();
    assert_eq!(snapshot.write_to(&mut bytes).unwrap(), bytes.len() as u64);
    assert_eq!(
        crate::database_staging::DatabaseTransfer::describe(&mut bytes.as_slice()).unwrap(),
        transfer
    );
    assert_ne!(&bytes[..16], b"SQLite format 3\0");
    let target = dir.path().canonicalize().unwrap().join("received.db");
    fs::write(&target, &bytes).unwrap();
    let copied = open_existing(&target, &DatabaseKey::new(KEY)).unwrap();
    verify_integrity(&copied).unwrap();
    assert_eq!(schema_version(&copied).unwrap(), Some(SCHEMA_VERSION));
    assert_eq!(
        copied
            .query_row("SELECT value FROM migration_probe", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        "snapshot"
    );
    assert_eq!(
        copied
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        37
    );
    assert_eq!(
        copied
            .pragma_query_value(None, "application_id", |r| r.get::<_, i64>(0))
            .unwrap(),
        42
    );
    assert_eq!(
        copied
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='migration_probe_value'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    let wrong_key = open_existing(&target, &DatabaseKey::new([0x66; 32])).unwrap();
    assert!(verify_integrity(&wrong_key).is_err());
    assert_fenced(&observer);
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "policy_store::migration_database::tests::independent_process_observes_source_fence", "--nocapture"])
        .env("EKUBO_TEST_MIGRATION_FENCE_SOURCE", &source)
        .status().unwrap().success());
    drop(snapshot);
    assert_eq!(fs::read(&source).unwrap(), before);
    observer
        .execute("INSERT INTO migration_probe VALUES(2,'after release')", [])
        .unwrap();
    assert_eq!(
        copied
            .query_row("SELECT count(*) FROM migration_probe", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

struct FailedReceiver;
impl Write for FailedReceiver {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("synthetic transfer failure"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn failed_transfer_keeps_source_fenced_and_retry_restarts_at_zero() {
    let (_dir, source) = fixture();
    let observer = observer(&source);
    let mut snapshot = MigrationDatabaseSnapshot::freeze(&source, Zeroizing::new(KEY)).unwrap();
    assert!(snapshot.write_to(&mut FailedReceiver).is_err());
    assert_fenced(&observer);
    let mut first = Vec::new();
    snapshot.write_to(&mut first).unwrap();
    let mut second = Vec::new();
    snapshot.write_to(&mut second).unwrap();
    assert_eq!(first, second);
}

#[test]
fn missing_wrong_key_and_old_schema_sources_fail_without_creation_or_upgrade() {
    let (dir, source) = fixture();
    let missing = dir.path().canonicalize().unwrap().join("absent.db");
    assert!(MigrationDatabaseSnapshot::freeze(&missing, Zeroizing::new(KEY)).is_err());
    assert!(!missing.exists());
    let before = fs::read(&source).unwrap();
    assert!(MigrationDatabaseSnapshot::freeze(&source, Zeroizing::new([0x66; 32])).is_err());
    assert_eq!(fs::read(&source).unwrap(), before);
    let connection = observer(&source);
    connection
        .execute("UPDATE schema_metadata SET version=12", [])
        .unwrap();
    drop(connection);
    let before = fs::read(&source).unwrap();
    assert!(MigrationDatabaseSnapshot::freeze(&source, Zeroizing::new(KEY)).is_err());
    assert_eq!(fs::read(&source).unwrap(), before);
    // A failure after taking the fence must release it too.
    observer(&source)
        .execute("UPDATE schema_metadata SET version=13", [])
        .unwrap();
}

#[test]
fn wal_source_is_rejected_instead_of_changing_its_journal_mode() {
    let (_dir, source) = fixture();
    let connection = observer(&source);
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    assert!(MigrationDatabaseSnapshot::freeze(&source, Zeroizing::new(KEY)).is_err());
    assert_eq!(
        connection
            .pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
}

#[test]
fn independent_process_observes_source_fence() {
    let Some(path) = std::env::var_os("EKUBO_TEST_MIGRATION_FENCE_SOURCE") else {
        return;
    };
    assert_fenced(&observer(Path::new(&path)));
}

fn inventory_wallet() -> crate::config::WalletMetadata {
    crate::config::WalletMetadata {
        instance_id: uuid::Uuid::new_v4(),
        id: "migration-source".into(),
        address: alloy::primitives::Address::repeat_byte(0x11),
        created_at: chrono::DateTime::from_timestamp_millis(1000).unwrap(),
        source: crate::config::WalletSource::Imported,
        exported_at: None,
    }
}

#[test]
fn source_inventory_reads_existing_metadata_without_changing_bytes_or_releasing_the_fence() {
    let (dir, source) = fixture();
    let wallet = inventory_wallet();
    crate::config::ConfigStore::open(dir.path(), DatabaseKey::new(KEY))
        .update_for_test(|config| {
            config.wallets = vec![wallet.clone()];
            Ok(())
        })
        .unwrap();
    PolicyStore::open(&source, &DatabaseKey::new(KEY))
        .unwrap()
        .register_wallet_without_policy(&wallet)
        .unwrap();
    let before = fs::read(&source).unwrap();
    let snapshot = MigrationDatabaseSnapshot::freeze(&source, Zeroizing::new(KEY)).unwrap();
    assert_eq!(snapshot.wallet_inventory().unwrap(), vec![wallet]);
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "policy_store::migration_database::tests::independent_process_observes_source_fence",
        ])
        .env("EKUBO_TEST_MIGRATION_FENCE_SOURCE", &source)
        .status()
        .unwrap()
        .success());
    drop(snapshot);
    assert_eq!(fs::read(&source).unwrap(), before);
}

#[test]
fn source_inventory_refuses_orphan_signing_identity_without_initializing_configuration() {
    let (_dir, source) = fixture();
    PolicyStore::open(&source, &DatabaseKey::new(KEY))
        .unwrap()
        .register_wallet_without_policy(&inventory_wallet())
        .unwrap();
    let before = fs::read(&source).unwrap();
    let snapshot = MigrationDatabaseSnapshot::freeze(&source, Zeroizing::new(KEY)).unwrap();
    assert!(snapshot.wallet_inventory().is_err());
    let configured: i64 = snapshot
        .source
        .query_row(
            "SELECT count(*) FROM application_settings WHERE key=?1",
            [crate::config::WALLET_CONFIGURATION_SETTING],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(configured, 0);
    drop(snapshot);
    assert_eq!(fs::read(&source).unwrap(), before);
}
