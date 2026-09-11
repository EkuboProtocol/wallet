//! Prepare the exact encrypted credential records consumed by both service stores.
//! This is pure preparation over keys already held by the caller, not an owner
//! authorization, keyring reader, filesystem installer, or migration commit.
//! The privileged installer must stage records in validated service-only storage,
//! persist the relay separately in the login keyring, verify the imported database,
//! and commit activation before removing any legacy credential. No deletion proof
//! or authority to change an existing enrollment is produced here.

use crate::custody_staging::{CredentialStage, CredentialStagingStore, StagedRecord};
use crate::{
    config::{WalletMetadata, validate_wallet_id},
    custody_envelope::{
        CustodyBinding, CustodyEnrollment, SEALED_KEY_BYTES, WrappedDataKey, WrappingKey,
    },
};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context as _, Result, ensure};
use rand::TryRng as _;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use zeroize::Zeroizing;

#[path = "custody_recovery.rs"]
mod recovery;

/// A supplied key and the existing metadata whose identity must remain unchanged.
/// Preparation consumes and zeroizes supplied bytes. Opaque core key types cannot
/// be passed here, and no existing credential is retrieved or exported.
pub struct MigrationAccount {
    pub wallet: WalletMetadata,
    pub key: Zeroizing<[u8; 32]>,
}

pub use crate::custody_staging::ServiceCredentialRecord;

/// Not serializable or Debug: the service wrapping key must never be included
/// in a desktop relay, diagnostic dump, or ordinary migration manifest.
pub struct PreparedServiceCredentials {
    wrapping: Zeroizing<[u8; 32]>,
    enrollment: Vec<u8>,
    database: [u8; SEALED_KEY_BYTES],
    accounts: BTreeMap<Uuid, [u8; SEALED_KEY_BYTES]>,
    relay: WrappedDataKey,
    wallets: BTreeMap<Uuid, WalletMetadata>,
}

impl PreparedServiceCredentials {
    /// Identities/profile must come from protected installer state. This method
    /// validates their cryptographic binding, not their operating-system provenance.
    pub fn prepare(
        owner: &str,
        service: &str,
        profile: Uuid,
        database: Zeroizing<[u8; 32]>,
        expected: &[WalletMetadata],
        accounts: Vec<MigrationAccount>,
    ) -> Result<Self> {
        validate_accounts(expected, &accounts)?;
        let generation = Uuid::new_v4();
        let binding = CustodyBinding::new(owner, service, profile, generation)?;
        let mut wrapping = Zeroizing::new([0; 32]);
        rand::rngs::SysRng
            .try_fill_bytes(wrapping.as_mut())
            .map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))?;
        let key = WrappingKey::from_material(wrapping.clone());
        let (cipher, relay) = key.enroll(binding)?;
        let enrollment = serde_json::to_vec(&CustodyEnrollment::new(generation, &relay)?)?;
        let sealed_database = cipher.seal_database_key(&database)?;
        drop(database);
        let database = sealed_database;
        let mut sealed = BTreeMap::new();
        let mut wallets = BTreeMap::new();
        for account in accounts {
            sealed.insert(
                account.wallet.instance_id,
                cipher.seal_account_key(account.wallet.instance_id, &account.key)?,
            );
            wallets.insert(account.wallet.instance_id, account.wallet);
        }
        Ok(Self {
            wrapping,
            enrollment,
            database,
            accounts: sealed,
            relay,
            wallets,
        })
    }

    /// Stage under a new identity without replacing active records. The native
    /// store must provide durable create-new writes and validated handle reads.
    /// This marker is not activation or legacy-credential deletion authority.
    pub fn stage(
        &self,
        store: &impl crate::custody_staging::CredentialStagingStore,
    ) -> Result<crate::custody_staging::CredentialStage> {
        let (owner, service, profile) = store.identity();
        CustodyEnrollment::from_bytes(&self.enrollment)?.unlock(
            &WrappingKey::from_material(self.wrapping.clone()),
            &owner,
            &service,
            profile,
            &self.relay,
        )?;
        let mut stage = StageWriter::new(store);
        self.visit_service_records(|record, bytes| stage.record(record, bytes))?;
        stage.finish()
    }

    /// Verify the received database against this preparation and its immutable
    /// staged records. No schema writes, activation, owner proof, or deletion
    /// receipt result from this check. Recovery must revalidate the source too.
    /// Schema constraints/indexes still need trusted validation or reconstruction
    /// before activation; a schema-version number is not structural attestation.
    pub fn verify_staged_inventory(
        &self,
        store: &(impl CredentialStagingStore + crate::database_staging::DatabaseStagingStore),
        stage: &CredentialStage,
    ) -> Result<()> {
        ensure!(
            store.read(stage.id(), StagedRecord::Complete)?.as_slice()
                == serde_json::to_vec(stage)?,
            "credential stage completion changed"
        );
        self.visit_service_records(|record, bytes| {
            ensure!(
                store
                    .read(stage.id(), StagedRecord::Credential(record))?
                    .as_slice()
                    == bytes,
                "staged credential changed"
            );
            Ok(())
        })?;
        let (owner, service, profile) = store.identity();
        let cipher = CustodyEnrollment::from_bytes(&self.enrollment)?.unlock(
            &WrappingKey::from_material(self.wrapping.clone()),
            &owner,
            &service,
            profile,
            &self.relay,
        )?;
        let key = cipher.open_database_key(&self.database)?;
        let database = store.staged_database(stage.id())?;
        crate::policy_store::migration_database::verify_received(
            database.path(),
            &crate::policy_store::DatabaseKey::new(*key),
            &self.wallets,
        )
    }

    /// Build a fresh candidate using only compiled DDL and the received data.
    /// Successful publication is still not activation or legacy-deletion authority.
    pub fn rebuild_staged_database(
        &self,
        store: &(impl CredentialStagingStore + crate::database_staging::DatabaseStagingStore),
        stage: &CredentialStage,
    ) -> Result<crate::database_staging::DatabaseTransfer> {
        self.verify_staged_inventory(store, stage)?;
        let (owner, service, profile) = store.identity();
        let cipher = CustodyEnrollment::from_bytes(&self.enrollment)?.unlock(
            &WrappingKey::from_material(self.wrapping.clone()),
            &owner,
            &service,
            profile,
            &self.relay,
        )?;
        let key = cipher.open_database_key(&self.database)?;
        let database_key = crate::policy_store::DatabaseKey::new(*key);
        let source = store.staged_database(stage.id())?;
        let candidate = store.create_canonical_database(stage.id())?;
        crate::policy_store::migration_rebuild::rebuild(
            source.path(),
            candidate.path(),
            &database_key,
            &self.wallets,
        )?;
        candidate.publish()?;
        let canonical = store.canonical_database(stage.id())?;
        crate::policy_store::migration_database::verify_received(
            canonical.path(),
            &database_key,
            &self.wallets,
        )?;
        canonical.transfer()
    }

    /// Ciphertext for the desktop login keyring only. Never store these bytes
    /// beside the service wrapping key. This is not an activation/cleanup receipt.
    #[must_use]
    pub const fn relay(&self) -> &WrappedDataKey {
        &self.relay
    }

    /// Visit service-only records, including the secret wrapping key. The callback
    /// must use protected staging handles and provide its own durable transaction.
    /// A callback error stops preparation output; it does not roll back its writes.
    /// The desktop relay is deliberately absent from this record set.
    pub fn visit_service_records(
        &self,
        mut visit: impl FnMut(ServiceCredentialRecord, &[u8]) -> Result<()>,
    ) -> Result<()> {
        visit(
            ServiceCredentialRecord::WrappingKey,
            self.wrapping.as_slice(),
        )?;
        visit(ServiceCredentialRecord::Enrollment, &self.enrollment)?;
        visit(ServiceCredentialRecord::DatabaseKey, &self.database)?;
        for (instance, sealed) in &self.accounts {
            visit(ServiceCredentialRecord::AccountKey(*instance), sealed)?;
        }
        Ok(())
    }
}

pub(crate) fn validate_accounts(
    expected: &[WalletMetadata],
    accounts: &[MigrationAccount],
) -> Result<()> {
    ensure!(
        expected.len() == accounts.len(),
        "migration account inventory is incomplete"
    );
    let inventory: BTreeMap<_, _> = expected
        .iter()
        .map(|wallet| (wallet.instance_id, wallet))
        .collect();
    ensure!(
        inventory.len() == expected.len(),
        "duplicate expected account instance"
    );
    let mut names = BTreeSet::new();
    let mut instances = BTreeSet::new();
    for account in accounts {
        ensure!(
            inventory.get(&account.wallet.instance_id).copied() == Some(&account.wallet),
            "migration account metadata changed"
        );
        validate_wallet_id(&account.wallet.id)?;
        ensure!(
            !account.wallet.instance_id.is_nil(),
            "migration account has no instance identity"
        );
        ensure!(
            names.insert(&account.wallet.id) && instances.insert(account.wallet.instance_id),
            "duplicate migration account identity"
        );
        ensure!(
            PrivateKeySigner::from_slice(account.key.as_slice())
                .context("invalid migration account key")?
                .address()
                == account.wallet.address,
            "migration key does not match account metadata"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "custody_provisioning_test.rs"]
mod tests;

pub(crate) struct StageWriter<'a, S> {
    store: &'a S,
    id: Uuid,
    count: u64,
    digest: Sha256,
}
impl<'a, S: CredentialStagingStore> StageWriter<'a, S> {
    pub(crate) fn new(store: &'a S) -> Self {
        Self {
            store,
            id: Uuid::new_v4(),
            count: 0,
            digest: Sha256::new(),
        }
    }
    pub(crate) fn record(&mut self, record: ServiceCredentialRecord, bytes: &[u8]) -> Result<()> {
        let staged = StagedRecord::Credential(record);
        self.store.create_new(self.id, staged, bytes)?;
        let read = self.store.read(self.id, staged)?;
        ensure!(
            read.as_slice() == bytes,
            "staged credential readback mismatch"
        );
        digest_record(&mut self.digest, record, bytes)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("too many staged records"))?;
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<CredentialStage> {
        let stage = CredentialStage {
            version: 1,
            stage: self.id,
            records: self.count,
            digest: self.digest.finalize().into(),
        };
        let marker = serde_json::to_vec(&stage)?;
        self.store
            .create_new(self.id, StagedRecord::Complete, &marker)?;
        ensure!(
            self.store.read(self.id, StagedRecord::Complete)?.as_slice() == marker,
            "staging completion readback mismatch"
        );
        Ok(stage)
    }
}

fn digest_record(digest: &mut Sha256, record: ServiceCredentialRecord, bytes: &[u8]) -> Result<()> {
    let name = record.file_name();
    digest.update(u64::try_from(name.len())?.to_le_bytes());
    digest.update(name.as_bytes());
    digest.update(u64::try_from(bytes.len())?.to_le_bytes());
    digest.update(bytes);
    Ok(())
}
