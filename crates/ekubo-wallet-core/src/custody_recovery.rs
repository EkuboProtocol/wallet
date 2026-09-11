//! Rehydrate only inside core. Returning a preparation publicly would expose its
//! raw-record visitor; the public recovery result must remain an opaque candidate.
use super::*;
use crate::database_staging::{DatabaseStagingStore, DatabaseTransfer};

impl PreparedServiceCredentials {
    pub(crate) fn restore(
        store: &(impl CredentialStagingStore + DatabaseStagingStore),
        stage: &CredentialStage,
        relay: WrappedDataKey,
        expected: &[WalletMetadata],
        canonical: &DatabaseTransfer,
    ) -> Result<Self> {
        ensure!(
            stage.version == 1 && !stage.id().is_nil(),
            "invalid recovery stage"
        );
        let wrapping = Zeroizing::new(read_record::<32>(
            store,
            stage,
            ServiceCredentialRecord::WrappingKey,
        )?);
        let enrollment = store
            .read(
                stage.id(),
                StagedRecord::Credential(ServiceCredentialRecord::Enrollment),
            )?
            .to_vec();
        let (owner, service, profile) = store.identity();
        let cipher = CustodyEnrollment::from_bytes(&enrollment)?.unlock(
            &WrappingKey::from_material(wrapping.clone()),
            &owner,
            &service,
            profile,
            &relay,
        )?;
        let database = read_record(store, stage, ServiceCredentialRecord::DatabaseKey)?;
        let mut accounts = BTreeMap::new();
        let mut plaintext = Vec::new();
        for wallet in expected {
            let sealed = read_record(
                store,
                stage,
                ServiceCredentialRecord::AccountKey(wallet.instance_id),
            )?;
            plaintext.push(MigrationAccount {
                wallet: wallet.clone(),
                key: cipher.open_account_key(wallet.instance_id, &sealed)?,
            });
            accounts.insert(wallet.instance_id, sealed);
        }
        validate_accounts(expected, &plaintext)?;
        drop(plaintext);
        let prepared = Self {
            wrapping,
            enrollment,
            database,
            accounts,
            relay,
            wallets: expected
                .iter()
                .map(|wallet| (wallet.instance_id, wallet.clone()))
                .collect(),
        };
        let mut digest = Sha256::new();
        prepared
            .visit_service_records(|record, bytes| digest_record(&mut digest, record, bytes))?;
        ensure!(
            stage.records
                == u64::try_from(prepared.accounts.len())?
                    .checked_add(3)
                    .context("recovery inventory overflow")?
                && stage.digest == <[u8; 32]>::from(digest.finalize()),
            "recovery credential inventory changed"
        );
        prepared.verify_staged_inventory(store, stage)?;
        let database = store.canonical_database(stage.id())?;
        ensure!(
            database.transfer()? == *canonical,
            "recovery canonical database changed"
        );
        let key = cipher.open_database_key(&prepared.database)?;
        crate::policy_store::migration_database::verify_received(
            database.path(),
            &crate::policy_store::DatabaseKey::new(*key),
            &prepared.wallets,
        )?;
        Ok(prepared)
    }
}

fn read_record<const N: usize>(
    store: &impl CredentialStagingStore,
    stage: &CredentialStage,
    record: ServiceCredentialRecord,
) -> Result<[u8; N]> {
    store
        .read(stage.id(), StagedRecord::Credential(record))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid recovery credential length"))
}
