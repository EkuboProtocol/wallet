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
