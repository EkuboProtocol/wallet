use super::*;
use crate::policy_store::{
    DatabaseKey, PolicyStore, migration_database::MigrationDatabaseSnapshot,
};
use zeroize::Zeroizing;

#[test]
fn fresh_exports_have_stable_logical_identity_and_mutations_change_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().canonicalize().unwrap().join("wallet.db");
    let key = [0x43; 32];
    drop(PolicyStore::open(&path, &DatabaseKey::new(key)).unwrap());
    let mut first = MigrationDatabaseSnapshot::freeze(&path, Zeroizing::new(key)).unwrap();
    let initial = first.source_fingerprint().unwrap();
    let ciphertext = first.transfer().unwrap();
    drop(first);
    let mut second = MigrationDatabaseSnapshot::freeze(&path, Zeroizing::new(key)).unwrap();
    assert_eq!(initial, second.source_fingerprint().unwrap());
    assert_ne!(ciphertext, second.transfer().unwrap());
    drop(second);
    let store = PolicyStore::open(&path, &DatabaseKey::new(key)).unwrap();
    store
        .connection
        .execute("INSERT INTO application_settings VALUES('probe','1',1)", [])
        .unwrap();
    drop(store);
    let changed = MigrationDatabaseSnapshot::freeze(&path, Zeroizing::new(key)).unwrap();
    assert_ne!(initial, changed.source_fingerprint().unwrap());
}

#[test]
fn schema_headers_rowids_and_value_types_are_part_of_identity() {
    let source = Connection::open_in_memory().unwrap();
    create_current_schema(&source).unwrap();
    let mut previous = describe(&source).unwrap();
    for sql in [
        "PRAGMA user_version=17",
        "PRAGMA application_id=42",
        "INSERT INTO application_settings VALUES('probe','1',1)",
        "UPDATE application_settings SET rowid=41",
        "UPDATE application_settings SET value_json='2'",
        "CREATE INDEX fingerprint_probe ON application_settings(updated_at)",
    ] {
        source.execute_batch(sql).unwrap();
        let next = describe(&source).unwrap();
        assert_ne!(previous, next, "{sql}");
        previous = next;
    }
    let mut integer = Sha256::new();
    let mut text = Sha256::new();
    hash_query(&source, "SELECT 1", &mut integer).unwrap();
    hash_query(&source, "SELECT '1'", &mut text).unwrap();
    assert_ne!(integer.finalize(), text.finalize());
    source
        .execute_batch("CREATE VIEW forbidden AS SELECT 1")
        .unwrap();
    assert!(describe(&source).is_err());
}
