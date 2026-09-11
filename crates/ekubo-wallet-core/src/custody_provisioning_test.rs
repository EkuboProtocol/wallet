use super::*;
use crate::{config::WalletSource, service_custody::ServiceCustody};

fn account(name: &str, instance: Uuid) -> MigrationAccount {
    let key = Zeroizing::new([0x11; 32]);
    MigrationAccount {
        wallet: WalletMetadata {
            id: name.into(),
            instance_id: instance,
            address: PrivateKeySigner::from_slice(key.as_slice())
                .unwrap()
                .address(),
            created_at: chrono::Utc::now(),
            source: WalletSource::Imported,
            exported_at: None,
        },
        key,
    }
}

fn records(
    prepared: &PreparedServiceCredentials,
) -> BTreeMap<ServiceCredentialRecord, Zeroizing<Vec<u8>>> {
    let mut records = BTreeMap::new();
    prepared
        .visit_service_records(|record, bytes| {
            records.insert(record, Zeroizing::new(bytes.to_vec()));
            Ok(())
        })
        .unwrap();
    records
}

#[test]
fn prepared_records_unlock_through_actual_service_custody_with_platform_identity_bindings() {
    for (owner, service) in [
        ("linux:uid:1000", "linux:uid:999"),
        ("windows:sid:S-1-5-21-1000", "windows:sid:S-1-5-80-999"),
    ] {
        let profile = Uuid::new_v4();
        let instance = Uuid::new_v4();
        let prepared = prepare(
            owner,
            service,
            profile,
            Zeroizing::new([0x42; 32]),
            vec![account("primary", instance)],
        )
        .unwrap();
        let records = records(&prepared);
        assert_eq!(
            records
                .keys()
                .map(|record| record.file_name())
                .collect::<Vec<_>>(),
            vec![
                "wrapping.key".to_owned(),
                "custody.json".to_owned(),
                "key-database".to_owned(),
                format!("key-account-{instance}")
            ]
        );
        assert!(
            records
                .values()
                .all(|bytes| bytes.as_slice() != prepared.relay().as_bytes())
        );
        let custody = ServiceCustody::default();
        custody
            .unlock(
                records[&ServiceCredentialRecord::Enrollment].as_slice(),
                records[&ServiceCredentialRecord::WrappingKey].as_slice(),
                owner,
                service,
                profile,
                prepared.relay(),
            )
            .unwrap();
        let cipher = custody.cipher().unwrap();
        assert_eq!(
            *cipher
                .open_database_key(&records[&ServiceCredentialRecord::DatabaseKey])
                .unwrap(),
            [0x42; 32]
        );
        assert_eq!(
            *cipher
                .open_account_key(
                    instance,
                    &records[&ServiceCredentialRecord::AccountKey(instance)]
                )
                .unwrap(),
            [0x11; 32]
        );
        assert!(
            cipher
                .open_account_key(
                    Uuid::new_v4(),
                    &records[&ServiceCredentialRecord::AccountKey(instance)]
                )
                .is_err()
        );
        let other = ServiceCustody::default();
        assert!(
            other
                .unlock(
                    records[&ServiceCredentialRecord::Enrollment].as_slice(),
                    records[&ServiceCredentialRecord::WrappingKey].as_slice(),
                    owner,
                    service,
                    Uuid::new_v4(),
                    prepared.relay()
                )
                .is_err()
        );
    }
}

#[test]
fn inconsistent_or_duplicate_account_identity_is_rejected_before_output() {
    let prepare = |accounts| {
        prepare(
            "owner",
            "service",
            Uuid::new_v4(),
            Zeroizing::new([0x42; 32]),
            accounts,
        )
    };
    let instance = Uuid::new_v4();
    assert!(
        prepare(vec![
            account("primary", instance),
            account("other", instance)
        ])
        .is_err()
    );
    assert!(
        prepare(vec![
            account("primary", instance),
            account("primary", Uuid::new_v4())
        ])
        .is_err()
    );
    assert!(prepare(vec![account("primary", Uuid::nil())]).is_err());
    let mut invalid = account("primary", instance);
    invalid.key = Zeroizing::new([0; 32]);
    assert!(prepare(vec![invalid]).is_err());
    let mut wrong = account("primary", instance);
    wrong.wallet.address = alloy::primitives::Address::ZERO;
    assert!(prepare(vec![wrong]).is_err());
}

#[test]
fn output_failure_stops_visiting_and_enrollment_is_fresh_on_each_preparation() {
    let profile = Uuid::new_v4();
    let prepare = || {
        prepare(
            "owner",
            "service",
            profile,
            Zeroizing::new([0x42; 32]),
            vec![],
        )
        .unwrap()
    };
    let first = prepare();
    let second = prepare();
    assert_ne!(first.relay().digest(), second.relay().digest());
    let mut seen = Vec::new();
    assert!(
        first
            .visit_service_records(|record, _| {
                seen.push(record);
                anyhow::bail!("synthetic staging failure")
            })
            .is_err()
    );
    assert_eq!(seen, vec![ServiceCredentialRecord::WrappingKey]);
}

fn prepare(
    owner: &str,
    service: &str,
    profile: Uuid,
    database: Zeroizing<[u8; 32]>,
    accounts: Vec<MigrationAccount>,
) -> Result<PreparedServiceCredentials> {
    let expected = accounts
        .iter()
        .map(|account| account.wallet.clone())
        .collect::<Vec<_>>();
    PreparedServiceCredentials::prepare(owner, service, profile, database, &expected, accounts)
}

#[test]
fn missing_keys_and_changed_metadata_cannot_prepare_a_partial_inventory() {
    let first = account("primary", Uuid::new_v4());
    let other = account("other", Uuid::new_v4());
    let expected = vec![first.wallet.clone(), other.wallet.clone()];
    let database = Zeroizing::new([0x42; 32]);
    assert!(
        PreparedServiceCredentials::prepare(
            "owner",
            "service",
            Uuid::new_v4(),
            database.clone(),
            &expected,
            vec![first]
        )
        .is_err()
    );
    let mut changed = account("primary", expected[0].instance_id);
    changed.wallet.exported_at = Some(chrono::Utc::now());
    assert!(
        PreparedServiceCredentials::prepare(
            "owner",
            "service",
            Uuid::new_v4(),
            database.clone(),
            &expected,
            vec![changed, other]
        )
        .is_err()
    );
}

struct StageStore {
    profile: Uuid,
    files: std::cell::RefCell<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    fail_at: Option<usize>,
    corrupt_read: bool,
    database: tempfile::TempDir,
}
impl CredentialStagingStore for StageStore {
    fn identity(&self) -> (String, String, Uuid) {
        ("owner".into(), "service".into(), self.profile)
    }
    fn create_new(&self, stage: Uuid, record: StagedRecord, bytes: &[u8]) -> Result<()> {
        let mut files = self.files.borrow_mut();
        anyhow::ensure!(self.fail_at != Some(files.len()), "synthetic write failure");
        let name = record.file_name(stage)?;
        anyhow::ensure!(!files.contains_key(&name), "record already exists");
        files.insert(name, Zeroizing::new(bytes.to_vec()));
        Ok(())
    }
    fn read(&self, stage: Uuid, record: StagedRecord) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = self
            .files
            .borrow()
            .get(&record.file_name(stage)?)
            .cloned()
            .context("missing staged record")?;
        if self.corrupt_read {
            bytes[0] ^= 1;
        }
        Ok(bytes)
    }
}
fn stage_fixture(
    fail_at: Option<usize>,
    corrupt_read: bool,
) -> (PreparedServiceCredentials, StageStore) {
    let profile = Uuid::new_v4();
    let prepared = prepare(
        "owner",
        "service",
        profile,
        Zeroizing::new([0x42; 32]),
        vec![],
    )
    .unwrap();
    (
        prepared,
        StageStore {
            profile,
            files: std::cell::RefCell::default(),
            fail_at,
            corrupt_read,
            database: tempfile::tempdir().unwrap(),
        },
    )
}

#[test]
fn staging_publishes_a_completion_marker_last_without_using_active_names_or_relay_bytes() {
    let (prepared, store) = stage_fixture(None, false);
    let first = prepared.stage(&store).unwrap();
    let files = store.files.borrow();
    assert_eq!(files.len(), 4);
    assert!(
        files
            .keys()
            .all(|name| name.starts_with(&format!("custody-stage-{}-", first.id())))
    );
    assert!(
        files
            .values()
            .all(|bytes| bytes.as_slice() != prepared.relay().as_bytes())
    );
    let marker = &files[&StagedRecord::Complete.file_name(first.id()).unwrap()];
    assert_eq!(marker.as_slice(), serde_json::to_vec(&first).unwrap());
    drop(files);
    let second = prepared.stage(&store).unwrap();
    assert_ne!(first.id(), second.id());
    assert_eq!(store.files.borrow().len(), 8);
}

#[test]
fn interrupted_or_corrupt_staging_never_publishes_completion() {
    for fail_at in 0..4 {
        let (prepared, store) = stage_fixture(Some(fail_at), false);
        assert!(prepared.stage(&store).is_err());
        assert!(
            !store
                .files
                .borrow()
                .keys()
                .any(|name| name.ends_with("complete.json"))
        );
    }
    let (prepared, store) = stage_fixture(None, true);
    assert!(prepared.stage(&store).is_err());
    assert_eq!(store.files.borrow().len(), 1);
}

#[test]
fn staging_refuses_the_wrong_protected_profile_before_writing() {
    let (prepared, mut store) = stage_fixture(None, false);
    store.profile = Uuid::new_v4();
    assert!(prepared.stage(&store).is_err());
    assert!(store.files.borrow().is_empty());
}

impl crate::database_staging::DatabaseStagingStore for StageStore {
    fn receive_database(
        &self,
        _: Uuid,
        _: &crate::database_staging::DatabaseTransfer,
        _: &mut dyn std::io::Read,
    ) -> Result<()> {
        anyhow::bail!("this fixture supplies a database directly")
    }
    fn open_staged_database(&self, _: Uuid) -> Result<std::fs::File> {
        Ok(std::fs::File::open(self.database.path().join("wallet.db"))?)
    }
    fn staged_database(&self, stage: Uuid) -> Result<crate::database_staging::StagedDatabase<'_>> {
        Ok(crate::database_staging::StagedDatabase::new(
            self.database.path().join("wallet.db"),
            self.open_staged_database(stage)?,
            self,
        ))
    }
}

fn verification_fixture() -> (
    PreparedServiceCredentials,
    StageStore,
    CredentialStage,
    WalletMetadata,
) {
    use crate::{
        config::WalletConfig,
        policy_store::{DatabaseKey, PolicyStore},
    };
    let (_, store) = stage_fixture(None, false);
    let migration = account("primary", Uuid::new_v4());
    let wallet = migration.wallet.clone();
    let prepared = prepare(
        "owner",
        "service",
        store.profile,
        Zeroizing::new([0x42; 32]),
        vec![migration],
    )
    .unwrap();
    let mut db = PolicyStore::open(
        &store.database.path().join("wallet.db"),
        &DatabaseKey::new([0x42; 32]),
    )
    .unwrap();
    db.register_wallet_without_policy(&wallet).unwrap();
    let config = WalletConfig {
        version: 3,
        wallets: vec![wallet.clone()],
        networks: vec![],
    };
    db.connection
        .execute(
            "INSERT INTO application_settings(key,value_json,updated_at) VALUES(?1,?2,0)",
            rusqlite::params![
                crate::config::WALLET_CONFIGURATION_SETTING,
                serde_json::to_string(&config).unwrap()
            ],
        )
        .unwrap();
    drop(db);
    let stage = prepared.stage(&store).unwrap();
    (prepared, store, stage, wallet)
}

#[test]
fn staged_database_verification_matches_credentials_and_both_account_inventories_without_writes() {
    let (prepared, store, stage, _) = verification_fixture();
    let path = store.database.path().join("wallet.db");
    let before = std::fs::read(&path).unwrap();
    prepared.verify_staged_inventory(&store, &stage).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn staged_database_rejects_missing_metadata_changed_signing_rows_and_extra_active_accounts() {
    use crate::policy_store::{DatabaseKey, PolicyStore};
    for sql in [
        "DELETE FROM application_settings WHERE key='wallet_configuration'",
        "UPDATE application_settings SET value_json=json_set(value_json,'$.wallets[0].exported_at','2024-01-01T00:00:00Z') WHERE key='wallet_configuration'",
        "UPDATE wallet_instances SET wallet_id='changed'",
        "UPDATE wallet_instances SET retired_at=1",
        "INSERT INTO wallet_instances VALUES('00000000-0000-0000-0000-000000000099','extra','0x0000000000000000000000000000000000000001',1,NULL)",
        "UPDATE schema_metadata SET version=12",
        "CREATE VIEW migration_view AS SELECT * FROM wallet_instances",
        "CREATE TRIGGER migration_trigger AFTER UPDATE ON application_settings BEGIN UPDATE wallet_instances SET wallet_id='changed'; END",
    ] {
        let (prepared, store, stage, _) = verification_fixture();
        let path = store.database.path().join("wallet.db");
        let db = PolicyStore::open(&path, &DatabaseKey::new([0x42; 32])).unwrap();
        db.connection.execute_batch(sql).unwrap();
        drop(db);
        let before = std::fs::read(&path).unwrap();
        assert!(
            prepared.verify_staged_inventory(&store, &stage).is_err(),
            "accepted {sql}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn staged_database_rejects_changed_enrollment_or_credentials_before_acceptance() {
    let (prepared, mut store, stage, _) = verification_fixture();
    store.profile = Uuid::new_v4();
    assert!(prepared.verify_staged_inventory(&store, &stage).is_err());
    let (prepared, store, stage, _) = verification_fixture();
    let name = StagedRecord::Credential(ServiceCredentialRecord::DatabaseKey)
        .file_name(stage.id())
        .unwrap();
    store.files.borrow_mut().get_mut(&name).unwrap()[0] ^= 1;
    assert!(prepared.verify_staged_inventory(&store, &stage).is_err());
    let (prepared, store, stage, _) = verification_fixture();
    store
        .files
        .borrow_mut()
        .remove(&StagedRecord::Complete.file_name(stage.id()).unwrap());
    assert!(prepared.verify_staged_inventory(&store, &stage).is_err());
}

#[test]
fn staged_database_preserves_retired_history_but_rejects_broken_references() {
    use crate::policy_store::{DatabaseKey, PolicyStore};
    let (prepared, store, stage, _) = verification_fixture();
    let path = store.database.path().join("wallet.db");
    let db = PolicyStore::open(&path, &DatabaseKey::new([0x42; 32])).unwrap();
    db.connection.execute_batch("INSERT INTO wallet_instances VALUES('00000000-0000-0000-0000-000000000099','retired','0x0000000000000000000000000000000000000001',1,2)").unwrap();
    drop(db);
    prepared.verify_staged_inventory(&store, &stage).unwrap();
    let db = PolicyStore::open(&path, &DatabaseKey::new([0x42; 32])).unwrap();
    db.connection.execute_batch("PRAGMA foreign_keys=OFF; CREATE TABLE migration_parent(id INTEGER PRIMARY KEY); CREATE TABLE migration_child(parent INTEGER REFERENCES migration_parent(id)); INSERT INTO migration_child VALUES(99)").unwrap();
    drop(db);
    assert!(prepared.verify_staged_inventory(&store, &stage).is_err());
}

#[test]
fn staged_database_under_another_key_is_rejected_without_rekeying_it() {
    use crate::policy_store::{DatabaseKey, PolicyStore};
    let (prepared, store, stage, _) = verification_fixture();
    let path = store.database.path().join("wallet.db");
    std::fs::remove_file(&path).unwrap();
    drop(PolicyStore::open(&path, &DatabaseKey::new([0x99; 32])).unwrap());
    let before = std::fs::read(&path).unwrap();
    assert!(prepared.verify_staged_inventory(&store, &stage).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
