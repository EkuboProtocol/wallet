use super::*;
use crate::policy_store::PolicyStore;

const KEY: [u8; 32] = [0x43; 32];
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.db");
    let target = dir.path().join("target.db");
    let store = PolicyStore::open(&source, &DatabaseKey::new(KEY)).unwrap();
    store.connection.execute_batch("INSERT INTO application_settings(rowid,key,value_json,updated_at) VALUES(41,'retained','{\"value\":true}',17); PRAGMA user_version=37; PRAGMA application_id=42").unwrap();
    drop(store);
    std::fs::File::create(&target).unwrap();
    (dir, source, target)
}
fn run(source: &Path, target: &Path) -> Result<()> {
    rebuild(source, target, &DatabaseKey::new(KEY), &BTreeMap::new())
}

#[test]
fn canonical_copy_preserves_data_rowids_and_headers_without_changing_source() {
    let (_dir, source, target) = fixture();
    let before = std::fs::read(&source).unwrap();
    run(&source, &target).unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), before);
    let copied = open_existing(&target, &DatabaseKey::new(KEY)).unwrap();
    let row: (i64, String, i64) = copied
        .query_row(
            "SELECT rowid,value_json,updated_at FROM application_settings WHERE key='retained'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(row, (41, "{\"value\":true}".into(), 17));
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
    assert_ne!(&std::fs::read(&target).unwrap()[..16], b"SQLite format 3\0");
}

#[test]
fn missing_source_constraints_are_recreated_from_compiled_schema() {
    let (_dir, source, target) = fixture();
    let input = open_existing(&source, &DatabaseKey::new(KEY)).unwrap();
    input
        .execute_batch("DROP INDEX wallet_instances_active_name")
        .unwrap();
    drop(input);
    run(&source, &target).unwrap();
    let copied = open_existing(&target, &DatabaseKey::new(KEY)).unwrap();
    copied.execute_batch("INSERT INTO wallet_instances VALUES('00000000-0000-0000-0000-000000000001','same','0x0000000000000000000000000000000000000001',1,NULL)").unwrap();
    assert!(copied.execute_batch("INSERT INTO wallet_instances VALUES('00000000-0000-0000-0000-000000000002','same','0x0000000000000000000000000000000000000002',2,NULL)").is_err());
}

#[test]
fn rows_accepted_by_weakened_source_checks_cannot_enter_canonical_database() {
    let (_dir, source, target) = fixture();
    let input = open_existing(&source, &DatabaseKey::new(KEY)).unwrap();
    input.execute_batch("DROP TABLE legal_acceptance; CREATE TABLE legal_acceptance(document TEXT PRIMARY KEY NOT NULL,digest BLOB NOT NULL,accepted_at INTEGER NOT NULL) STRICT; INSERT INTO legal_acceptance VALUES('unreviewed',zeroblob(32),1)").unwrap();
    drop(input);
    assert!(run(&source, &target).is_err());
    let copied = open_existing(&target, &DatabaseKey::new(KEY)).unwrap();
    assert_eq!(
        copied
            .query_row("SELECT count(*) FROM application_settings", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0,
        "partial data copy must roll back"
    );
}

#[test]
fn column_order_differences_are_preserved_by_name_but_unknown_state_is_rejected() {
    let (_dir, source, target) = fixture();
    let input = open_existing(&source, &DatabaseKey::new(KEY)).unwrap();
    input.execute_batch("ALTER TABLE application_settings RENAME TO old_settings; CREATE TABLE application_settings(updated_at INTEGER NOT NULL,key TEXT PRIMARY KEY NOT NULL,value_json TEXT NOT NULL) STRICT; INSERT INTO application_settings(rowid,updated_at,key,value_json) SELECT rowid,updated_at,key,value_json FROM old_settings; DROP TABLE old_settings").unwrap();
    drop(input);
    run(&source, &target).unwrap();
    let copied = open_existing(&target, &DatabaseKey::new(KEY)).unwrap();
    assert_eq!(
        copied
            .query_row(
                "SELECT rowid FROM application_settings WHERE key='retained'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        41
    );
    for sql in [
        "CREATE TABLE unknown_state(value TEXT)",
        "ALTER TABLE application_settings ADD COLUMN unknown_value TEXT",
    ] {
        let (_dir, source, target) = fixture();
        let input = open_existing(&source, &DatabaseKey::new(KEY)).unwrap();
        input.execute_batch(sql).unwrap();
        drop(input);
        assert!(run(&source, &target).is_err());
    }
}
