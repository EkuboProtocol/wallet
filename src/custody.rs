use crate::{
    config::{ConfigStore, CustodyStatus, WalletMetadata, WalletSource, validate_wallet_id},
    human_presence::{HumanPresence, PresenceAction, PresenceRequest},
};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use keyring::{Entry, Error as KeyringError};
use std::{fmt, sync::Arc};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEYRING_SERVICE: &str = "org.ekubo.secure-wallet-mcp.private-key.v1";

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
        self.add(
            wallet_id,
            &key,
            WalletSource::Created,
            CustodyStatus::Sealed,
        )
    }

    pub fn import(&self, wallet_id: &str, key: PrivateKeyMaterial) -> Result<WalletMetadata> {
        let result = self.add(
            wallet_id,
            &key,
            WalletSource::Imported,
            CustodyStatus::ExternallyKnown,
        );
        drop(key);
        result
    }

    fn add(
        &self,
        wallet_id: &str,
        key: &PrivateKeyMaterial,
        source: WalletSource,
        custody: CustodyStatus,
    ) -> Result<WalletMetadata> {
        validate_wallet_id(wallet_id)?;
        let address = key.signer().address();
        let metadata = WalletMetadata {
            id: wallet_id.into(),
            address,
            created_at: Utc::now(),
            source,
            custody,
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
            .confirm(&PresenceRequest {
                action: PresenceAction::ExportPrivateKey,
                wallet_id: wallet_id.into(),
                operation_digest: None,
            })
            .await?;
        let key = self.keys.load(wallet_id)?;
        ensure!(
            key.signer().address() == metadata.address,
            "credential address does not match wallet metadata"
        );

        // Record the irreversible loss of exclusive custody before returning
        // key material. A failed metadata write therefore never leaks a key.
        self.config.update(|config| {
            let wallet = config
                .wallets
                .iter_mut()
                .find(|wallet| wallet.id == wallet_id)
                .with_context(|| format!("unknown wallet {wallet_id}"))?;
            wallet.custody = CustodyStatus::Exported;
            wallet.exported_at.get_or_insert_with(Utc::now);
            Ok(())
        })?;
        Ok(key.expose_hex())
    }

    pub async fn remove(&self, wallet_id: &str) -> Result<WalletMetadata> {
        let metadata = self.config.wallet(wallet_id)?;
        self.presence
            .confirm(&PresenceRequest {
                action: PresenceAction::RemoveWallet,
                wallet_id: wallet_id.into(),
                operation_digest: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::human_presence::TestHumanPresence;
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Default)]
    struct MemoryKeyStore(Mutex<BTreeMap<String, Vec<u8>>>);

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
    async fn created_wallet_transitions_to_exported() {
        let (_directory, service) = service(true);
        let wallet = service.create("primary").unwrap();
        assert_eq!(wallet.custody, CustodyStatus::Sealed);
        let exported = service.export("primary").await.unwrap();
        assert_eq!(exported.len(), 66);
        let wallet = service.config.wallet("primary").unwrap();
        assert_eq!(wallet.custody, CustodyStatus::Exported);
        assert!(wallet.exported_at.is_some());
    }

    #[tokio::test]
    async fn denial_does_not_reclassify_key() {
        let (_directory, service) = service(false);
        service.create("primary").unwrap();
        assert!(service.export("primary").await.is_err());
        assert_eq!(
            service.config.wallet("primary").unwrap().custody,
            CustodyStatus::Sealed
        );
    }

    #[test]
    fn imports_are_never_marked_sealed() {
        let (_directory, service) = service(true);
        let key = PrivateKeyMaterial::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let wallet = service.import("imported", key).unwrap();
        assert_eq!(wallet.custody, CustodyStatus::ExternallyKnown);
    }
}
