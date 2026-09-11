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
        let mut bytes = self.files.borrow()[&record.file_name(stage)?].clone();
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
