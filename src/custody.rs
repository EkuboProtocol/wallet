use crate::{
    config::{ConfigStore, WalletMetadata, WalletSource, validate_wallet_id},
    human_presence::{HumanPresence, PresenceRequest},
};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use keyring::{Entry, Error as KeyringError};
use std::{fmt, sync::Arc};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEYRING_SERVICE: &str = "org.ekubo.wallet.private-key.v1";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeyMaterial([u8; 32]);

impl PrivateKeyMaterial {
    pub fn from_hex(value: &str) -> Result<Self> {
        let value = value.strip_prefix("0x").unwrap_or(value);
        ensure!(
            value.len() == 64,
            "private key must contain exactly 32 bytes"
        );
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(value, &mut bytes).context("private key must be hexadecimal")?;
        PrivateKeySigner::from_slice(&bytes)
            .context("private key is not a valid secp256k1 scalar")?;
        Ok(Self(bytes))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == 32, "stored private key is not 32 bytes");
        let mut material = [0_u8; 32];
        material.copy_from_slice(bytes);
        PrivateKeySigner::from_slice(&material)
            .context("stored private key is not a valid secp256k1 scalar")?;
        Ok(Self(material))
    }

    #[must_use]
    pub fn signer(&self) -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&self.0).expect("validated private key")
    }

    #[must_use]
    pub fn expose_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("0x{}", hex::encode(self.0)))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PrivateKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateKeyMaterial([REDACTED])")
    }
}

/// Loads the wallet's private key and refuses a credential-store entry whose
/// derived address does not match the wallet metadata: a row swapped
/// underneath the wallet must never produce a signature. Every signing path
/// in the process obtains its signer here.
pub fn load_matching_signer<K: KeyStore + ?Sized>(
    keys: &K,
    wallet: &WalletMetadata,
) -> Result<PrivateKeySigner> {
    let material = keys.load(&wallet.id)?;
    let signer = material.signer();
    ensure!(
        signer.address() == wallet.address,
        "credential-store private key does not match wallet metadata"
    );
    Ok(signer)
}

pub trait KeyStore: Send + Sync {
    fn insert_new(&self, wallet_id: &str, key: &PrivateKeyMaterial) -> Result<()>;
    fn load(&self, wallet_id: &str) -> Result<PrivateKeyMaterial>;
    fn delete(&self, wallet_id: &str) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OsKeyStore;

impl OsKeyStore {
    fn entry(wallet_id: &str) -> Result<Entry> {
        validate_wallet_id(wallet_id)?;
        Entry::new(KEYRING_SERVICE, wallet_id).context("platform credential store is unavailable")
    }
}

impl KeyStore for OsKeyStore {
    fn insert_new(&self, wallet_id: &str, key: &PrivateKeyMaterial) -> Result<()> {
        let entry = Self::entry(wallet_id)?;
        match entry.get_secret() {
            Ok(mut existing) => {
                existing.zeroize();
                bail!("credential store already contains wallet {wallet_id}");
            }
            Err(KeyringError::NoEntry) => {}
            Err(error) => {
                return Err(error).context("failed to inspect platform credential store");
            }
        }
        entry
            .set_secret(key.as_bytes())
            .context("failed to save private key in platform credential store")
    }

    fn load(&self, wallet_id: &str) -> Result<PrivateKeyMaterial> {
        let mut bytes = Self::entry(wallet_id)?
            .get_secret()
            .with_context(|| format!("failed to load private key for wallet {wallet_id}"))?;
        let result = PrivateKeyMaterial::from_bytes(&bytes);
        bytes.zeroize();
        result
    }

    fn delete(&self, wallet_id: &str) -> Result<()> {
        match Self::entry(wallet_id)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(error).context("failed to delete private key from credential store"),
        }
    }
}

pub struct CustodyService<K: KeyStore, H: HumanPresence> {
    config: ConfigStore,
    keys: Arc<K>,
    presence: Arc<H>,
}

impl<K: KeyStore, H: HumanPresence> CustodyService<K, H> {
    #[must_use]
    pub fn new(config: ConfigStore, keys: Arc<K>, presence: Arc<H>) -> Self {
        Self {
            config,
            keys,
            presence,
        }
    }

    pub fn create(&self, wallet_id: &str) -> Result<WalletMetadata> {
        let signer = PrivateKeySigner::random();
        let key = PrivateKeyMaterial::from_bytes(signer.to_bytes().as_slice())?;
        self.add(wallet_id, &key, WalletSource::Created)
    }

    pub fn import(&self, wallet_id: &str, key: PrivateKeyMaterial) -> Result<WalletMetadata> {
        let result = self.add(wallet_id, &key, WalletSource::Imported);
        drop(key);
        result
    }

    fn add(
        &self,
        wallet_id: &str,
        key: &PrivateKeyMaterial,
        source: WalletSource,
    ) -> Result<WalletMetadata> {
        validate_wallet_id(wallet_id)?;
        let address = key.signer().address();
        let metadata = WalletMetadata {
            id: wallet_id.into(),
            address,
            created_at: Utc::now(),
            source,
            exported_at: None,
        };

        self.keys.insert_new(wallet_id, key)?;
        let update = self.config.update(|config| {
            ensure!(
                !config.wallets.iter().any(|wallet| wallet.id == wallet_id),
                "wallet {wallet_id} already exists"
            );
            ensure!(
                !config
                    .wallets
                    .iter()
                    .any(|wallet| wallet.address == address),
                "address {address} is already configured"
            );
            config.wallets.push(metadata.clone());
            Ok(())
        });
        if let Err(error) = update {
            if let Err(rollback) = self.keys.delete(wallet_id) {
                return Err(error).context(format!(
                    "configuration update failed and credential rollback also failed: {rollback:#}"
                ));
            }
            return Err(error);
        }
        Ok(metadata)
    }

    pub async fn export(&self, wallet_id: &str) -> Result<Zeroizing<String>> {
        let metadata = self.config.wallet(wallet_id)?;
        self.presence
            .confirm(&PresenceRequest::ExportPrivateKey {
                wallet: wallet_id.into(),
            })
            .await?;
        let key = self.keys.load(wallet_id)?;
        ensure!(
            key.signer().address() == metadata.address,
            "credential address does not match wallet metadata"
        );

        // Record that a copy left through this tool before returning key
        // material, so a failed metadata write never leaks a key unrecorded.
        // The first timestamp stands: a second export reveals nothing the
        // first did not, and moving the mark forward would misdate the moment
        // the key stopped being held only here.
        self.config.update(|config| {
            let wallet = config
                .wallets
                .iter_mut()
                .find(|wallet| wallet.id == wallet_id)
                .with_context(|| format!("unknown wallet {wallet_id}"))?;
            wallet.exported_at.get_or_insert_with(Utc::now);
            Ok(())
        })?;
        Ok(key.expose_hex())
    }

    pub async fn remove(&self, wallet_id: &str) -> Result<WalletMetadata> {
        let metadata = self.config.wallet(wallet_id)?;
        self.presence
            .confirm(&PresenceRequest::RemoveWallet {
                wallet: wallet_id.into(),
            })
            .await?;

        // Remove metadata first. If key deletion fails, reinsert the metadata
        // so a reachable credential is not orphaned without an inventory row.
        self.config.update(|config| {
            let index = config
                .wallets
                .iter()
                .position(|wallet| wallet.id == wallet_id)
                .with_context(|| format!("unknown wallet {wallet_id}"))?;
            config.wallets.remove(index);
            Ok(())
        })?;
        if let Err(error) = self.keys.delete(wallet_id) {
            let rollback = self.config.update(|config| {
                config.wallets.push(metadata.clone());
                Ok(())
            });
            if let Err(rollback) = rollback {
                return Err(error).context(format!(
                    "credential deletion failed and metadata rollback also failed: {rollback:#}"
                ));
            }
            return Err(error);
        }
        Ok(metadata)
    }
}

/// In-memory key store for tests: the same trait surface as the OS store,
/// no credential-store side effects.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryKeyStore(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

#[cfg(test)]
impl KeyStore for MemoryKeyStore {
    fn insert_new(&self, wallet_id: &str, key: &PrivateKeyMaterial) -> Result<()> {
        let mut keys = self.0.lock().unwrap();
        ensure!(!keys.contains_key(wallet_id), "duplicate key");
        keys.insert(wallet_id.into(), key.as_bytes().to_vec());
        Ok(())
    }

    fn load(&self, wallet_id: &str) -> Result<PrivateKeyMaterial> {
        let keys = self.0.lock().unwrap();
        PrivateKeyMaterial::from_bytes(keys.get(wallet_id).context("missing test key")?)
    }

    fn delete(&self, wallet_id: &str) -> Result<()> {
        self.0.lock().unwrap().remove(wallet_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::human_presence::TestHumanPresence;

    fn service(
        allow: bool,
    ) -> (
        tempfile::TempDir,
        CustodyService<MemoryKeyStore, TestHumanPresence>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let service = CustodyService::new(
            ConfigStore::new(directory.path()),
            Arc::new(MemoryKeyStore::default()),
            Arc::new(TestHumanPresence { allow }),
        );
        (directory, service)
    }

    #[tokio::test]
    async fn export_records_a_timestamp() {
        let (_directory, service) = service(true);
        let wallet = service.create("primary").unwrap();
        assert!(wallet.exported_at.is_none());
        let exported = service.export("primary").await.unwrap();
        assert_eq!(exported.len(), 66);
        assert!(
            service
                .config
                .wallet("primary")
                .unwrap()
                .exported_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn re_export_keeps_the_first_timestamp() {
        let (_directory, service) = service(true);
        service.create("primary").unwrap();
        service.export("primary").await.unwrap();
        let first = service.config.wallet("primary").unwrap().exported_at;
        service.export("primary").await.unwrap();
        assert_eq!(service.config.wallet("primary").unwrap().exported_at, first);
    }

    #[tokio::test]
    async fn denial_does_not_record_an_export() {
        let (_directory, service) = service(false);
        service.create("primary").unwrap();
        assert!(service.export("primary").await.is_err());
        assert!(
            service
                .config
                .wallet("primary")
                .unwrap()
                .exported_at
                .is_none()
        );
    }

    #[test]
    fn imports_record_their_external_origin() {
        let (_directory, service) = service(true);
        let key = PrivateKeyMaterial::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let wallet = service.import("imported", key).unwrap();
        assert_eq!(wallet.source, WalletSource::Imported);
        // An import is externally known from the start, but that is `source`'s
        // job to say. `exported_at` records only this tool's own disclosures.
        assert!(wallet.exported_at.is_none());
    }
}
