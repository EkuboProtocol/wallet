use crate::{
    config::{ConfigStore, KeyStorage, WalletMetadata, WalletSource, validate_wallet_id},
    human_presence::{HumanPresence, PresenceRequest},
};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use keyring::Entry;
use keyring_core::Error as KeyringError;
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

pub trait KeyStore: Send + Sync {
    fn insert_new(
        &self,
        wallet_id: &str,
        storage: KeyStorage,
        key: &PrivateKeyMaterial,
    ) -> Result<()>;
    fn load(&self, wallet_id: &str, storage: KeyStorage) -> Result<PrivateKeyMaterial>;
    fn delete(&self, wallet_id: &str, storage: KeyStorage) -> Result<()>;
}

/// Build an entry in the iCloud-synchronized keychain.
///
/// Synchronized items live in the protected-data keychain, which the OS only
/// opens to processes carrying an application identifier and the iCloud
/// keychain entitlement. A plain developer build or an unsigned binary is
/// refused with `errSecMissingEntitlement (-34018)`, so that requirement is
/// spelled out wherever an operation on one of these entries fails.
#[cfg(target_os = "macos")]
fn cloud_entry(wallet_id: &str) -> Result<keyring_core::Entry> {
    use keyring_core::api::CredentialStoreApi;
    let store = apple_native_keyring_store::protected::Store::new_with_configuration(
        &std::collections::HashMap::from([("cloud-sync", "true")]),
    )
    .context("iCloud-synchronized keychain is unavailable")?;
    store
        .build(KEYRING_SERVICE, wallet_id, None)
        .context("failed to reference the iCloud-synchronized keychain entry")
}

#[cfg(not(target_os = "macos"))]
fn cloud_entry(_wallet_id: &str) -> Result<keyring_core::Entry> {
    bail!(
        "cloud-synced key storage is only available on macOS, where it uses the iCloud \
         Keychain; this platform's credential store does not replicate secrets across devices"
    )
}

/// The requirement most likely behind a failed cloud-store operation, stated
/// once so every failure path repeats it consistently.
const CLOUD_ENTITLEMENT_HINT: &str = "if the underlying error is errSecMissingEntitlement \
    (-34018), this binary is not signed with the iCloud keychain entitlement that \
    synchronized items require";

#[derive(Clone, Copy, Debug, Default)]
pub struct OsKeyStore;

impl OsKeyStore {
    fn entry(wallet_id: &str, storage: KeyStorage) -> Result<keyring_core::Entry> {
        validate_wallet_id(wallet_id)?;
        match storage {
            KeyStorage::Local => Ok(Entry::new(KEYRING_SERVICE, wallet_id)
                .context("platform credential store is unavailable")?
                .inner),
            KeyStorage::CloudSynced => cloud_entry(wallet_id),
        }
    }

    fn operation_context(storage: KeyStorage, operation: &str) -> String {
        match storage {
            KeyStorage::Local => format!("failed to {operation} the platform credential store"),
            KeyStorage::CloudSynced => format!(
                "failed to {operation} the iCloud-synchronized keychain; {CLOUD_ENTITLEMENT_HINT}"
            ),
        }
    }
}

impl KeyStore for OsKeyStore {
    fn insert_new(
        &self,
        wallet_id: &str,
        storage: KeyStorage,
        key: &PrivateKeyMaterial,
    ) -> Result<()> {
        let entry = Self::entry(wallet_id, storage)?;
        match entry.get_secret() {
            Ok(mut existing) => {
                existing.zeroize();
                bail!("{} already contains wallet {wallet_id}", storage.describe());
            }
            Err(KeyringError::NoEntry) => {}
            Err(error) => {
                return Err(error).context(Self::operation_context(storage, "inspect"));
            }
        }
        entry
            .set_secret(key.as_bytes())
            .context(Self::operation_context(storage, "save the private key in"))
    }

    fn load(&self, wallet_id: &str, storage: KeyStorage) -> Result<PrivateKeyMaterial> {
        let mut bytes = Self::entry(wallet_id, storage)?
            .get_secret()
            .with_context(|| {
                format!(
                    "failed to load the private key for wallet {wallet_id} from the {}",
                    storage.describe()
                )
            })?;
        let result = PrivateKeyMaterial::from_bytes(&bytes);
        bytes.zeroize();
        result
    }

    fn delete(&self, wallet_id: &str, storage: KeyStorage) -> Result<()> {
        match Self::entry(wallet_id, storage)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(error).context(Self::operation_context(
                storage,
                "delete the private key from",
            )),
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

    pub fn create(&self, wallet_id: &str, storage: KeyStorage) -> Result<WalletMetadata> {
        let signer = PrivateKeySigner::random();
        let key = PrivateKeyMaterial::from_bytes(signer.to_bytes().as_slice())?;
        self.add(wallet_id, &key, WalletSource::Created, storage)
    }

    pub fn import(
        &self,
        wallet_id: &str,
        key: PrivateKeyMaterial,
        storage: KeyStorage,
    ) -> Result<WalletMetadata> {
        let result = self.add(wallet_id, &key, WalletSource::Imported, storage);
        drop(key);
        result
    }

    /// Adopt a key that another device already placed in the cloud-synced
    /// store, recording it in this machine's wallet list without the key ever
    /// appearing outside the credential store.
    ///
    /// The key arrives here already known outside this machine, which is
    /// exactly what `WalletSource::Imported` records, and callers treat it
    /// the same way: nothing signs until a policy is deliberately installed.
    pub fn attach(&self, wallet_id: &str) -> Result<WalletMetadata> {
        validate_wallet_id(wallet_id)?;
        let key = self.keys.load(wallet_id, KeyStorage::CloudSynced)?;
        let metadata = WalletMetadata {
            id: wallet_id.into(),
            address: key.signer().address(),
            created_at: Utc::now(),
            source: WalletSource::Imported,
            exported_at: None,
            key_storage: KeyStorage::CloudSynced,
        };
        self.record(&metadata)?;
        Ok(metadata)
    }

    fn add(
        &self,
        wallet_id: &str,
        key: &PrivateKeyMaterial,
        source: WalletSource,
        storage: KeyStorage,
    ) -> Result<WalletMetadata> {
        validate_wallet_id(wallet_id)?;
        let metadata = WalletMetadata {
            id: wallet_id.into(),
            address: key.signer().address(),
            created_at: Utc::now(),
            source,
            exported_at: None,
            key_storage: storage,
        };

        self.keys.insert_new(wallet_id, storage, key)?;
        if let Err(error) = self.record(&metadata) {
            if let Err(rollback) = self.keys.delete(wallet_id, storage) {
                return Err(error).context(format!(
                    "configuration update failed and credential rollback also failed: {rollback:#}"
                ));
            }
            return Err(error);
        }
        Ok(metadata)
    }

    fn record(&self, metadata: &WalletMetadata) -> Result<()> {
        self.config.update(|config| {
            ensure!(
                !config.wallets.iter().any(|wallet| wallet.id == metadata.id),
                "wallet {} already exists",
                metadata.id
            );
            ensure!(
                !config
                    .wallets
                    .iter()
                    .any(|wallet| wallet.address == metadata.address),
                "address {} is already configured",
                metadata.address
            );
            config.wallets.push(metadata.clone());
            Ok(())
        })
    }

    pub async fn export(&self, wallet_id: &str) -> Result<Zeroizing<String>> {
        let metadata = self.config.wallet(wallet_id)?;
        self.presence
            .confirm(&PresenceRequest::ExportPrivateKey {
                wallet: wallet_id.into(),
            })
            .await?;
        let key = self.keys.load(wallet_id, metadata.key_storage)?;
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
        if let Err(error) = self.keys.delete(wallet_id, metadata.key_storage) {
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

    impl MemoryKeyStore {
        /// The two storages are distinct namespaces in the real stores, so the
        /// test store keys by both to catch code that saves in one store and
        /// loads or deletes from the other.
        fn slot(wallet_id: &str, storage: KeyStorage) -> String {
            format!("{storage:?}/{wallet_id}")
        }
    }

    impl KeyStore for MemoryKeyStore {
        fn insert_new(
            &self,
            wallet_id: &str,
            storage: KeyStorage,
            key: &PrivateKeyMaterial,
        ) -> Result<()> {
            let mut keys = self.0.lock().unwrap();
            let slot = Self::slot(wallet_id, storage);
            ensure!(!keys.contains_key(&slot), "duplicate key");
            keys.insert(slot, key.as_bytes().to_vec());
            Ok(())
        }

        fn load(&self, wallet_id: &str, storage: KeyStorage) -> Result<PrivateKeyMaterial> {
            let keys = self.0.lock().unwrap();
            PrivateKeyMaterial::from_bytes(
                keys.get(&Self::slot(wallet_id, storage))
                    .context("missing test key")?,
            )
        }

        fn delete(&self, wallet_id: &str, storage: KeyStorage) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .remove(&Self::slot(wallet_id, storage));
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
    async fn export_records_a_timestamp() {
        let (_directory, service) = service(true);
        let wallet = service.create("primary", KeyStorage::Local).unwrap();
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
        service.create("primary", KeyStorage::Local).unwrap();
        service.export("primary").await.unwrap();
        let first = service.config.wallet("primary").unwrap().exported_at;
        service.export("primary").await.unwrap();
        assert_eq!(service.config.wallet("primary").unwrap().exported_at, first);
    }

    #[tokio::test]
    async fn denial_does_not_record_an_export() {
        let (_directory, service) = service(false);
        service.create("primary", KeyStorage::Local).unwrap();
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

    #[tokio::test]
    async fn cloud_synced_wallets_use_the_cloud_store_for_their_whole_lifecycle() {
        let (_directory, service) = service(true);
        let wallet = service.create("roaming", KeyStorage::CloudSynced).unwrap();
        assert_eq!(wallet.key_storage, KeyStorage::CloudSynced);
        assert_eq!(
            service.config.wallet("roaming").unwrap().key_storage,
            KeyStorage::CloudSynced
        );

        // The key must be reachable through the cloud slot and only there:
        // exporting goes through metadata, and the local slot stays empty.
        assert_eq!(service.export("roaming").await.unwrap().len(), 66);
        assert!(service.keys.load("roaming", KeyStorage::Local).is_err());

        service.remove("roaming").await.unwrap();
        assert!(
            service
                .keys
                .load("roaming", KeyStorage::CloudSynced)
                .is_err(),
            "removal must delete from the store the key lives in"
        );
    }

    #[test]
    fn attach_adopts_a_synced_key_without_touching_it() {
        let (_directory, service) = service(true);
        // Another device's create is indistinguishable from a locally stored
        // cloud key: the credential exists but this machine has no metadata.
        let key = PrivateKeyMaterial::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let address = key.signer().address();
        service
            .keys
            .insert_new("roaming", KeyStorage::CloudSynced, &key)
            .unwrap();

        let wallet = service.attach("roaming").unwrap();
        assert_eq!(wallet.address, address);
        assert_eq!(wallet.source, WalletSource::Imported);
        assert_eq!(wallet.key_storage, KeyStorage::CloudSynced);
        assert!(wallet.exported_at.is_none());
        assert_eq!(service.config.wallet("roaming").unwrap(), wallet);
    }

    #[test]
    fn attach_requires_the_synced_credential_and_a_free_wallet_id() {
        let (_directory, service) = service(true);
        assert!(
            service.attach("absent").is_err(),
            "no synced credential to adopt"
        );

        service.create("primary", KeyStorage::CloudSynced).unwrap();
        assert!(
            service.attach("primary").is_err(),
            "wallet is already configured on this machine"
        );
    }

    #[test]
    fn imports_record_their_external_origin() {
        let (_directory, service) = service(true);
        let key = PrivateKeyMaterial::from_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let wallet = service.import("imported", key, KeyStorage::Local).unwrap();
        assert_eq!(wallet.source, WalletSource::Imported);
        // An import is externally known from the start, but that is `source`'s
        // job to say. `exported_at` records only this tool's own disclosures.
        assert!(wallet.exported_at.is_none());
    }
}
