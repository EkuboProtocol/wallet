use crate::{
    config::{ConfigStore, WalletMetadata, WalletSource, validate_wallet_id},
    human_presence::{HumanPresence, PresenceRequest},
};
use alloy::{primitives::Address, signers::local::PrivateKeySigner};
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

    /// The address this key controls.
    ///
    /// Public in both senses: an address is derived from the public key and is
    /// written into every transaction the wallet sends, so handing one out
    /// discloses nothing. It is the only thing about a key that leaves this
    /// crate, which is what lets [`Self::signer`] and [`Self::expose_hex`]
    /// below stay crate-private without the presentation layer losing anything
    /// it can legitimately show.
    #[must_use]
    pub fn address(&self) -> Address {
        self.signer().address()
    }

    /// Crate-private, and the reason is the whole point of the crate split.
    ///
    /// A `PrivateKeySigner` signs any 32 bytes put in front of it, with no
    /// policy, no simulation, and no owner authentication — so a caller holding
    /// one has the wallet. Keeping it inside the kernel means the only way for
    /// presentation code to obtain a signature is to call one of the
    /// orchestrator entry points, each of which confirms human presence first.
    /// Widening this to `pub` restores the bypass regardless of what those
    /// entry points check.
    #[must_use]
    pub(crate) fn signer(&self) -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&self.0).expect("validated private key")
    }

    /// Crate-private for the same reason as [`Self::signer`], and more
    /// bluntly: this renders the secret itself. The single caller is
    /// [`CustodyService::export`], which confirms owner presence and records
    /// the disclosure before calling it.
    #[must_use]
    pub(crate) fn expose_hex(&self) -> Zeroizing<String> {
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
///
/// Crate-private, so "every signing path" is a fact about this crate rather
/// than a convention the presentation layer is trusted to keep. The address
/// check below is worth having, but it is not an authorization check: it
/// establishes that the key is the right key, never that anyone asked for it
/// to be used. Callers outside the kernel therefore get no route to a signer
/// at all — they hand a [`KeyStore`] to an orchestrator entry point, which
/// confirms presence and then calls this.
pub(crate) fn load_matching_signer<K: KeyStore + ?Sized>(
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
            // An error is not proof that nothing was written. The metadata
            // write commits when the replacement file lands, and steps after
            // that can still report failure — so rolling back on the error
            // alone can delete the only copy of a key the wallet it belongs to
            // is still listed under, which nothing can undo.
            //
            // Ask instead of assuming, and ask precisely: a row naming this
            // wallet at this address can only be the row this call just wrote,
            // because the update refuses a duplicate address. An id that is
            // taken by some *other* address means the write never happened, so
            // the credential inserted a moment ago is still garbage to clear.
            if self
                .config
                .wallet(wallet_id)
                .is_ok_and(|existing| existing.address == address)
            {
                return Err(error).context(format!(
                    "wallet {wallet_id} was created and its key is stored, but the write reported \
                     an error; verify with `ekubo-wallet account list` before retrying"
                ));
            }
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
        //
        // Owner authentication above can take arbitrarily long, and no
        // configuration lock is held while it waits. A concurrent process can
        // remove this wallet and create another under the same name in that
        // window, so the row is matched on the address the owner actually
        // reviewed rather than on the name alone: removing by name would
        // delete a replacement wallet's row — and then its key — on the
        // strength of an approval given for its predecessor.
        if let Err(error) = self.config.update(|config| {
            let index = config
                .wallets
                .iter()
                .position(|wallet| wallet.id == wallet_id)
                .with_context(|| format!("unknown wallet {wallet_id}"))?;
            ensure!(
                config.wallets[index].address == metadata.address,
                "wallet {wallet_id} now holds address {} rather than the {} that was reviewed; \
                 it was replaced while this removal was being authorized",
                config.wallets[index].address,
                metadata.address
            );
            config.wallets.remove(index);
            Ok(())
        }) {
            // The mirror of `add`: an error here need not mean the row
            // survived, and returning on it would leave a reachable
            // credential with no inventory row naming it. But deleting a
            // credential cannot be undone, so it proceeds only on positive
            // proof that no row bears this name — and a failed re-read is not
            // that proof. `wallet` reports an unreadable configuration and an
            // absent row the same way, so testing it with `is_ok` treated
            // "cannot tell" as "already removed" and destroyed the only key of
            // a wallet that was still listed.
            match self.config.load() {
                Ok(config) if !config.wallets.iter().any(|wallet| wallet.id == wallet_id) => {}
                Ok(_) => return Err(error),
                Err(unreadable) => {
                    return Err(error).context(format!(
                        "the configuration could not be re-read to establish whether the metadata \
                         row for {wallet_id} survived, so its private key was left in place; \
                         resolve that and retry: {unreadable:#}"
                    ));
                }
            }
        }
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
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Default)]
pub struct MemoryKeyStore(std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>);

#[cfg(any(test, feature = "test-hooks"))]
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
#[path = "custody_test.rs"]
mod tests;
