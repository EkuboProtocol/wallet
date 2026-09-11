//! Prepare the exact encrypted credential records consumed by both service stores.
//! This is pure preparation over keys already held by the caller, not an owner
//! authorization, keyring reader, filesystem installer, or migration commit.
//! The privileged installer must stage records in validated service-only storage,
//! persist the relay separately in the login keyring, verify the imported database,
//! and commit activation before removing any legacy credential. No deletion proof
//! or authority to change an existing enrollment is produced here.

use crate::{
    config::{WalletMetadata, validate_wallet_id},
    custody_envelope::{
        CustodyBinding, CustodyEnrollment, SEALED_KEY_BYTES, WrappedDataKey, WrappingKey,
    },
};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context as _, Result, ensure};
use rand::TryRng as _;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A supplied key and the existing metadata whose identity must remain unchanged.
/// Preparation consumes and zeroizes supplied bytes. Opaque core key types cannot
/// be passed here, and no existing credential is retrieved or exported.
pub struct MigrationAccount {
    pub wallet: WalletMetadata,
    pub key: Zeroizing<[u8; 32]>,
}

/// Closed record names shared by Linux and Windows service custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceCredentialRecord {
    WrappingKey,
    Enrollment,
    DatabaseKey,
    AccountKey(Uuid),
}

impl ServiceCredentialRecord {
    #[must_use]
    pub fn file_name(self) -> String {
        match self {
            Self::WrappingKey => "wrapping.key".into(),
            Self::Enrollment => "custody.json".into(),
            Self::DatabaseKey => "key-database".into(),
            Self::AccountKey(instance) => format!("key-account-{instance}"),
        }
    }
}

/// Not serializable or Debug: the service wrapping key must never be included
/// in a desktop relay, diagnostic dump, or ordinary migration manifest.
pub struct PreparedServiceCredentials {
    wrapping: Zeroizing<[u8; 32]>,
    enrollment: Vec<u8>,
    database: [u8; SEALED_KEY_BYTES],
    accounts: BTreeMap<Uuid, [u8; SEALED_KEY_BYTES]>,
    relay: WrappedDataKey,
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
        for account in accounts {
            sealed.insert(
                account.wallet.instance_id,
                cipher.seal_account_key(account.wallet.instance_id, &account.key)?,
            );
        }
        Ok(Self {
            wrapping,
            enrollment,
            database,
            accounts: sealed,
            relay,
        })
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

fn validate_accounts(expected: &[WalletMetadata], accounts: &[MigrationAccount]) -> Result<()> {
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
