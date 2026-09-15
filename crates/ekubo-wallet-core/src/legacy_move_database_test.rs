use super::*;

fn fixture(key: [u8; 32]) -> (tempfile::TempDir, PolicyStore) {
    let directory = tempfile::tempdir().unwrap();
    crate::policy_store::register_test_database_key(directory.path(), key).unwrap();
    crate::config::ConfigStore::open(directory.path(), DatabaseKey::new(key))
        .load()
        .unwrap();
    let store =
        PolicyStore::open(&directory.path().join("wallet.db"), &DatabaseKey::new(key)).unwrap();
    (directory, store)
}

#[test]
fn source_is_read_only_and_unknown_state_is_not_silently_dropped() {
    let (directory, store) = fixture([0x31; 32]);
    store
        .connection
        .execute(
            "INSERT INTO application_settings VALUES('move-test',?1,0)",
            ["{\"secret\":\"preserve me\"}"],
        )
        .unwrap();
    drop(store);
    let source = open_source(
        &directory.path().join("wallet.db"),
        &DatabaseKey::new([0x31; 32]),
    )
    .unwrap();
    assert!(
        source
            .execute("DELETE FROM application_settings", [])
            .is_err()
    );
    assert!(capture(&source, false).is_ok());
    drop(source);
    let store = PolicyStore::open(
        &directory.path().join("wallet.db"),
        &DatabaseKey::new([0x31; 32]),
    )
    .unwrap();
    store
        .connection
        .execute("CREATE TABLE unknown_user_state(value TEXT)", [])
        .unwrap();
    assert!(capture(&store.connection, false).is_err());
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT value_json FROM application_settings WHERE key='move-test'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "{\"secret\":\"preserve me\"}"
    );
}

#[test]
fn whole_state_import_is_atomic_verified_and_bound_to_unchanged_first_run() {
    let (_source_dir, source) = fixture([0x32; 32]);
    source
        .connection
        .execute(
            "INSERT INTO application_settings VALUES('move-test',?1,0)",
            ["{\"history\":[1,2],\"settings\":true}"],
        )
        .unwrap();
    let snapshot = capture(&source.connection, false).unwrap();
    let expected = snapshot.digest().unwrap();
    let (target_dir, target) = fixture([0x33; 32]);
    drop(target);
    initialize_baseline(target_dir.path()).unwrap();
    let before = PolicyStore::production(target_dir.path()).unwrap();
    let baseline = capture(&before.connection, true).unwrap().digest().unwrap();
    drop(before);
    assert!(
        import(target_dir.path(), &snapshot, |_| anyhow::bail!(
            "interrupted key preparation"
        ))
        .is_err()
    );
    let after = PolicyStore::production(target_dir.path()).unwrap();
    assert_eq!(
        capture(&after.connection, true).unwrap().digest().unwrap(),
        baseline
    );
    drop(after);
    assert_eq!(
        import(target_dir.path(), &snapshot, |_| Ok(())).unwrap(),
        expected
    );
    assert!(verify(target_dir.path(), expected).unwrap().is_empty());
    assert_eq!(
        import(target_dir.path(), &snapshot, |_| Ok(())).unwrap(),
        expected
    );
    let changed = PolicyStore::production(target_dir.path()).unwrap();
    changed
        .connection
        .execute(
            "UPDATE application_settings SET value_json='{}' WHERE key='move-test'",
            [],
        )
        .unwrap();
    drop(changed);
    assert!(verify(target_dir.path(), expected).is_err());
    assert!(import(target_dir.path(), &snapshot, |_| Ok(())).is_err());
    assert!(finish_cleanup(target_dir.path(), expected, "test-only-unbound-source").is_err());
    assert!(!move_state(target_dir.path()).unwrap().complete);
}

#[test]
fn first_run_owner_changes_and_oversized_snapshots_refuse_without_import() {
    let (_source_dir, source) = fixture([0x34; 32]);
    let snapshot = capture(&source.connection, false).unwrap();
    let (directory, target) = fixture([0x35; 32]);
    drop(target);
    initialize_baseline(directory.path()).unwrap();
    let changed = PolicyStore::production(directory.path()).unwrap();
    changed
        .connection
        .execute(
            "INSERT INTO application_settings VALUES('new-v2-choice','true',0)",
            [],
        )
        .unwrap();
    drop(changed);
    assert!(
        import(directory.path(), &snapshot, |_| panic!(
            "must not import any keys"
        ))
        .is_err()
    );
    let snapshot = Snapshot {
        tables: vec![Table {
            name: "oversized".into(),
            columns: vec!["value".into()],
            rows: vec![vec![Cell::Text("x".repeat(MAX_BYTES + 1))]],
        }],
    };
    assert!(snapshot.digest().is_err());
}

#[test]
fn predated_source_schema_fails_with_upgrade_hint() {
    let (_directory, older) = fixture([0x38; 32]);
    older
        .connection
        .execute(
            "UPDATE schema_metadata SET version=version-1 WHERE singleton=1",
            [],
        )
        .unwrap();
    let error = capture(&older.connection, false).map(|_| ()).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("predates the supported move schema"));
    assert!(message.contains("1.8.2"));
    assert!(message.contains("left unchanged"));
    assert!(crate::legacy_move::is_predates_supported_schema(&error));
    let (_directory, newer) = fixture([0x39; 32]);
    newer
        .connection
        .execute(
            "UPDATE schema_metadata SET version=version+1 WHERE singleton=1",
            [],
        )
        .unwrap();
    let error = capture(&newer.connection, false).map(|_| ()).unwrap_err();
    assert!(!crate::legacy_move::is_predates_supported_schema(&error));
}

#[test]
fn account_identity_policy_revisions_and_configuration_are_preserved() {
    let (source_dir, mut source) = fixture([0x36; 32]);
    let wallet = crate::config::WalletMetadata {
        instance_id: uuid::Uuid::from_u128(73),
        id: "preserved-account".into(),
        address: alloy::signers::local::PrivateKeySigner::from_slice(&[7; 32])
            .unwrap()
            .address(),
        created_at: chrono::DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
        source: crate::config::WalletSource::Created,
        exported_at: None,
    };
    let config = crate::config::ConfigStore::open(source_dir.path(), DatabaseKey::new([0x36; 32]));
    config
        .update(|config| {
            config.wallets.push(wallet.clone());
            Ok(())
        })
        .unwrap();
    let policy = crate::core::policy::WalletPolicy::require_approval_for_everything();
    source.put_for_instance(&wallet, &policy, None).unwrap();
    source
        .put_for_instance(
            &wallet,
            &crate::core::policy::WalletPolicy::allow_anything(),
            Some(1),
        )
        .unwrap();
    let history = source.policy_history_count(&wallet.id).unwrap();
    let snapshot = capture(&source.connection, false).unwrap();
    let (target_dir, target) = fixture([0x37; 32]);
    drop(target);
    initialize_baseline(target_dir.path()).unwrap();
    let digest = import(target_dir.path(), &snapshot, |inventory| {
        assert_eq!(inventory, std::slice::from_ref(&wallet));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        verify(target_dir.path(), digest).unwrap(),
        vec![wallet.clone()]
    );
    let target = PolicyStore::production(target_dir.path()).unwrap();
    assert_eq!(target.policy_history_count(&wallet.id).unwrap(), history);
    assert_eq!(
        capture(&target.connection, true).unwrap().digest().unwrap(),
        snapshot.digest().unwrap()
    );
}
