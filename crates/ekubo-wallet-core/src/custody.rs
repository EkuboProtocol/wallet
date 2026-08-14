use crate::core::policy::WalletPolicy;
use crate::{
    config::{ConfigStore, WalletMetadata, WalletSource, validate_wallet_id},
    human_presence::{HumanPresence, PresenceRequest},
};
use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use keyring::{Entry, Error as KeyringError};
use rand::TryRng as _;
use std::{fmt, sync::Arc};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const KEYRING_SERVICE: &str = "org.ekubo.wallet.private-key.instance";

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeyMaterial([u8; 32]);

impl PrivateKeyMaterial {
    fn random() -> Result<Self> {
        let mut material = Self([0_u8; 32]);
        rand::rng()
            .try_fill_bytes(&mut material.0)
            .context("operating system randomness is unavailable")?;
        PrivateKeySigner::from_slice(&material.0)
            .context("operating system randomness produced an invalid secp256k1 scalar")?;
        Ok(material)
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        let value = value.strip_prefix("0x").unwrap_or(value);
        ensure!(
            value.len() == 64,
            "private key must contain exactly 32 bytes"
        );
        let mut material = Self([0_u8; 32]);
        hex::decode_to_slice(value, &mut material.0).context("private key must be hexadecimal")?;
        PrivateKeySigner::from_slice(&material.0)
            .context("private key is not a valid secp256k1 scalar")?;
        Ok(material)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == 32, "stored private key is not 32 bytes");
        let mut material = Self([0_u8; 32]);
        material.0.copy_from_slice(bytes);
        PrivateKeySigner::from_slice(&material.0)
            .context("stored private key is not a valid secp256k1 scalar")?;
        Ok(material)
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
    let material = keys.load(wallet.instance_id)?;
    let signer = material.signer();
    ensure!(
        signer.address() == wallet.address,
        "credential-store private key does not match wallet metadata"
    );
    Ok(signer)
}

/// Where a wallet's private key lives.
///
/// Sealed: implementing this requires [`crate::sealed::SealedKeyStore`], which
/// is private to the kernel, so the only key stores are the two below. A store
/// decides whether `insert_new` really persisted the key it was handed and
/// whether `delete` really removed one, which is not a decision presentation
/// code gets to make. See [`crate::sealed`] for the full reasoning.
pub trait KeyStore: crate::sealed::SealedKeyStore + Send + Sync {
    fn insert_new(&self, instance_id: Uuid, key: &PrivateKeyMaterial) -> Result<()>;
    fn load(&self, instance_id: Uuid) -> Result<PrivateKeyMaterial>;

    /// Which address the stored credential controls, or `None` when this id
    /// names no credential.
    ///
    /// An `Err` means the store could not answer. It never means "empty":
    /// conflating the two is how a removal that could not read the credential
    /// store concluded the key was already gone.
    fn address_of(&self, instance_id: Uuid) -> Result<Option<Address>>;

    /// Delete the credential under `instance_id`, but only if it controls
    /// `expected`.
    ///
    /// There is deliberately no `delete(wallet_id)`. A wallet id is reusable,
    /// so a deletion addressed by id alone is a deletion of whatever happens
    /// to be there when it lands — which is how an authorization to remove one
    /// wallet destroyed the key of the wallet that replaced it, and how a
    /// creation that lost a race deleted the winner's key. Requiring the
    /// UUID makes that sentence impossible to write; the address check is a
    /// second integrity guard that refuses corrupted or swapped key material.
    fn delete_matching(&self, instance_id: Uuid, expected: Address) -> Result<Deletion>;
}

/// What a credential-store write that reported an error actually did.
///
/// Separate from the code that produces it so the four answers can be tested
/// without a platform credential store: the whole defect was a flow that only
/// ever considered one of them.
#[derive(Debug)]
pub(crate) enum FailedWrite {
    /// The secret is there and is the one that was being written. The error
    /// was reported after the write committed.
    Committed,
    /// Nothing is there. The write really did fail.
    NotWritten,
    /// Something else is there under this name.
    Conflicting,
    /// The store could not be re-read, so nothing is known.
    Unknown(anyhow::Error),
}

/// Decide what a failed write did from a readback: `Ok(None)` for no entry,
/// `Ok(Some(matches))` for an entry that does or does not hold the intended
/// secret, `Err` when the store could not answer.
pub(crate) fn classify_failed_write(readback: Result<Option<bool>>) -> FailedWrite {
    match readback {
        Ok(Some(true)) => FailedWrite::Committed,
        Ok(Some(false)) => FailedWrite::Conflicting,
        Ok(None) => FailedWrite::NotWritten,
        Err(unreadable) => FailedWrite::Unknown(unreadable),
    }
}

/// What [`KeyStore::delete_matching`] found when it looked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deletion {
    /// The expected credential was there and is now gone.
    Removed,
    /// There was no credential under this id.
    Absent,
    /// A credential is there, but it controls a different address, so it
    /// belongs to some other wallet and was left alone.
    Mismatched(Address),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OsKeyStore;

impl crate::sealed::SealedKeyStore for OsKeyStore {}

impl OsKeyStore {
    fn entry(instance_id: Uuid) -> Result<Entry> {
        // The credential store is machine-wide, so an account created in a
        // scratch directory would outlive the `rm -rf` that discards it — a
        // private key with no wallet left to name it. Refusing is honest about
        // what an ephemeral session is for: starting the server and exercising
        // the read paths, not holding keys.
        #[cfg(debug_assertions)]
        ensure!(
            !crate::ephemeral::is_enabled(),
            "this is an ephemeral session, which never touches the platform credential store; \
account operations need an ordinary session, so drop --ephemeral"
        );
        Entry::new(KEYRING_SERVICE, &instance_id.to_string())
            .context("platform credential store is unavailable")
    }
}

impl KeyStore for OsKeyStore {
    // `block_in_place` in every method below, not a direct call: see
    // `policy_store::load_or_create_database_key`'s doc comment for why a
    // synchronous credential-store touch from inside our own Tokio runtime
    // needs it -- `keyring`'s Linux backend starts a second, nested runtime
    // on first use, which Tokio otherwise refuses unconditionally.

    fn insert_new(&self, instance_id: Uuid, key: &PrivateKeyMaterial) -> Result<()> {
        tokio::task::block_in_place(|| {
            let entry = Self::entry(instance_id)?;
            match entry.get_secret() {
                Ok(mut existing) => {
                    existing.zeroize();
                    bail!("credential store already contains wallet instance {instance_id}");
                }
                Err(KeyringError::NoEntry) => {}
                Err(error) => {
                    return Err(error).context("failed to inspect platform credential store");
                }
            }
            let Err(error) = entry.set_secret(key.as_bytes()) else {
                return Ok(());
            };
            // An error from `set_secret` is not proof that nothing was
            // written, and treating it as proof is how a key ended up in the
            // credential store with no configuration row naming it: `add`
            // returned here, before it could write the metadata or run any
            // rollback, and the next attempt to create the same wallet was
            // refused as a duplicate by the very credential it had orphaned.
            //
            // The same readback `load_or_create_database_key` uses, for the
            // same reason — the store itself is the only honest witness to
            // what it did.
            let readback = match entry.get_secret() {
                Ok(mut stored) => {
                    let outcome = Ok(Some(stored == key.as_bytes()));
                    stored.zeroize();
                    outcome
                }
                Err(KeyringError::NoEntry) => Ok(None),
                Err(unreadable) => Err(anyhow::Error::new(unreadable)),
            };
            match classify_failed_write(readback) {
                // It landed. Reporting the error would strand it.
                FailedWrite::Committed => Ok(()),
                FailedWrite::NotWritten => {
                    Err(error).context("failed to save private key in platform credential store")
                }
                FailedWrite::Conflicting => Err(error).context(format!(
                    "failed to save the private key for wallet instance {instance_id}, and the credential \
                     store now holds a different secret under that name; resolve it there before \
                     retrying"
                )),
                FailedWrite::Unknown(unreadable) => Err(error).context(format!(
                    "failed to save the private key for wallet instance {instance_id}, and the credential \
                     store could not be re-read to establish whether it was written anyway; \
                     check for an entry named {instance_id} before retrying: {unreadable:#}"
                )),
            }
        })
    }

    fn load(&self, instance_id: Uuid) -> Result<PrivateKeyMaterial> {
        tokio::task::block_in_place(|| {
            let mut bytes = Self::entry(instance_id)?.get_secret().with_context(|| {
                format!("failed to load private key for wallet instance {instance_id}")
            })?;
            let result = PrivateKeyMaterial::from_bytes(&bytes);
            bytes.zeroize();
            result
        })
    }

    fn address_of(&self, instance_id: Uuid) -> Result<Option<Address>> {
        tokio::task::block_in_place(|| match Self::entry(instance_id)?.get_secret() {
            Ok(mut bytes) => {
                let material = PrivateKeyMaterial::from_bytes(&bytes);
                bytes.zeroize();
                Ok(Some(material?.address()))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(error).context("failed to inspect platform credential store"),
        })
    }

    fn delete_matching(&self, instance_id: Uuid, expected: Address) -> Result<Deletion> {
        tokio::task::block_in_place(|| {
            let entry = Self::entry(instance_id)?;
            let mut bytes = match entry.get_secret() {
                Ok(bytes) => bytes,
                Err(KeyringError::NoEntry) => return Ok(Deletion::Absent),
                Err(error) => {
                    return Err(error).context("failed to inspect platform credential store");
                }
            };
            let material = PrivateKeyMaterial::from_bytes(&bytes);
            bytes.zeroize();
            let actual = material?.address();
            if actual != expected {
                return Ok(Deletion::Mismatched(actual));
            }
            match entry.delete_credential() {
                Ok(()) | Err(KeyringError::NoEntry) => Ok(Deletion::Removed),
                Err(error) => {
                    Err(error).context("failed to delete private key from credential store")
                }
            }
        })
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
        let key = PrivateKeyMaterial::random()?;
        self.add(wallet_id, &key, WalletSource::Created, None)
    }

    /// Create and publish a wallet only after its address-bound fail-closed
    /// policy exists, all under the lifecycle lock.
    pub fn create_with_policy(
        &self,
        wallet_id: &str,
        policy: &WalletPolicy,
    ) -> Result<WalletMetadata> {
        let key = PrivateKeyMaterial::random()?;
        self.add(wallet_id, &key, WalletSource::Created, Some(policy))
    }

    pub fn import(&self, wallet_id: &str, key: PrivateKeyMaterial) -> Result<WalletMetadata> {
        let result = self.add(wallet_id, &key, WalletSource::Imported, None);
        drop(key);
        result
    }

    pub fn import_with_policy(
        &self,
        wallet_id: &str,
        key: PrivateKeyMaterial,
        policy: &WalletPolicy,
    ) -> Result<WalletMetadata> {
        let result = self.add(wallet_id, &key, WalletSource::Imported, Some(policy));
        drop(key);
        result
    }

    fn add(
        &self,
        wallet_id: &str,
        key: &PrivateKeyMaterial,
        source: WalletSource,
        policy: Option<&WalletPolicy>,
    ) -> Result<WalletMetadata> {
        validate_wallet_id(wallet_id)?;
        let address = key.signer().address();
        let metadata = WalletMetadata {
            instance_id: Uuid::new_v4(),
            id: wallet_id.into(),
            address,
            created_at: Utc::now(),
            source,
            exported_at: None,
        };

        // The credential write and the configuration write are one operation.
        // Held apart, two creations of the same id both passed the
        // "credential store already contains wallet" check, both wrote, and
        // the loser's rollback deleted the winner's key.
        self.config.with_lifecycle_lock(|| {
            let current = self.config.load()?;
            ensure!(
                !current.wallets.iter().any(|wallet| wallet.id == wallet_id),
                "wallet {wallet_id} already exists"
            );
            ensure!(
                !current
                    .wallets
                    .iter()
                    .any(|wallet| wallet.address == address),
                "address {address} is already configured"
            );
            self.keys.insert_new(metadata.instance_id, key)?;
            let update = (|| {
                let fail_closed;
                let initial_policy = if let Some(policy) = policy {
                    policy
                } else {
                    fail_closed = WalletPolicy::require_approval_for_everything();
                    &fail_closed
                };
                let mut policies = self.config.policy_store()?;
                policies.initialize_policy(&metadata, initial_policy)?;
                self.config.update(|config| {
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
                })
            })();
            if let Err(error) = update {
                // An error is not proof that nothing was written. The metadata
                // write commits when the replacement file lands, and steps
                // after that can still report failure — so rolling back on the
                // error alone can delete the only copy of a key the wallet it
                // belongs to is still listed under, which nothing can undo.
                //
                // Ask instead of assuming, and ask precisely: a row naming this
                // wallet at this address can only be the row this call just
                // wrote, because the update refuses a duplicate address. An id
                // that is taken by some *other* address means the write never
                // happened, so the credential inserted a moment ago is still
                // garbage to clear.
                if self
                    .config
                    .wallet(wallet_id)
                    .is_ok_and(|existing| existing.address == address)
                {
                    return Err(error).context(format!(
                        "wallet {wallet_id} was created and its key is stored, but the write \
                         reported an error; verify it in the Accounts screen before retrying"
                    ));
                }
                if let Err(cleanup) = self
                    .config
                    .policy_store()
                    .and_then(|mut policies| policies.abandon_unpublished(metadata.instance_id))
                {
                    return Err(error).context(format!(
                        "wallet publication failed and policy rollback also failed: {cleanup:#}"
                    ));
                }
                // Addressed by the key this call inserted, never by the id
                // alone: if anything else now occupies the id, that credential
                // belongs to another wallet and this rollback is not entitled
                // to it.
                match self.keys.delete_matching(metadata.instance_id, address) {
                    Ok(Deletion::Removed | Deletion::Absent) => {}
                    Ok(Deletion::Mismatched(other)) => {
                        return Err(error).context(format!(
                            "wallet {wallet_id} now holds a credential for {other} rather than \
                             the {address} this call inserted, so that credential was left in \
                             place"
                        ));
                    }
                    Err(rollback) => {
                        return Err(error).context(format!(
                            "configuration update failed and credential rollback also failed: \
                             {rollback:#}"
                        ));
                    }
                }
                return Err(error);
            }
            Ok(metadata.clone())
        })
    }

    /// Reveal the raw private key of the wallet at `expected`, and record that
    /// it left.
    ///
    /// `expected` is the address the owner was shown, and it is required for
    /// the same reason `delete_matching` requires one: a wallet id is
    /// reusable, so an export addressed by name alone is an export of whatever
    /// holds that name when it lands. This used to check the loaded credential
    /// against the loaded metadata, which is a real check of a different
    /// thing — both are read after the review, so a replacement that happened
    /// before this was called produces two values that agree with each other
    /// and with nothing the owner saw. An owner approving "reveal the key for
    /// 0xabc…" could be handed the key for a wallet that address was never
    /// part of.
    ///
    /// So the reviewed address is compared at each place the id is resolved:
    /// before owner authentication, so a doomed export does not put a prompt
    /// on their screen; after it, because authentication takes as long as a
    /// person takes; against the credential itself; and against the row the
    /// disclosure is recorded on, so the mark cannot land on a successor while
    /// the predecessor's key is what was returned.
    ///
    /// The lifecycle lock covers everything after the prompt, so a create or a
    /// remove cannot interleave with the read at all. The comparisons remain
    /// because the lock is not held across the prompt: it is the answer to
    /// concurrency, not to time.
    pub async fn export(&self, wallet_id: &str, expected: Address) -> Result<Zeroizing<String>> {
        let reviewed = self.config.wallet(wallet_id)?;
        Self::ensure_reviewed(&reviewed, &reviewed, wallet_id, expected)?;
        self.presence
            .confirm(&PresenceRequest::ExportPrivateKey {
                wallet: wallet_id.into(),
            })
            .await?;
        self.config
            .with_lifecycle_lock(|| self.export_locked(wallet_id, expected, &reviewed))
    }

    fn export_locked(
        &self,
        wallet_id: &str,
        expected: Address,
        reviewed: &WalletMetadata,
    ) -> Result<Zeroizing<String>> {
        let metadata = self.config.wallet(wallet_id)?;
        Self::ensure_reviewed(&metadata, reviewed, wallet_id, expected)?;
        let key = self.keys.load(metadata.instance_id)?;
        ensure!(
            key.signer().address() == expected,
            "the credential stored under {wallet_id} controls {} rather than the {expected} that \
             was reviewed; nothing was revealed",
            key.signer().address()
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
                .find(|wallet| {
                    wallet.instance_id == reviewed.instance_id
                        && wallet.id == wallet_id
                        && wallet.address == expected
                })
                .with_context(|| {
                    format!("no wallet {wallet_id} holds the reviewed address {expected}")
                })?;
            wallet.exported_at.get_or_insert_with(Utc::now);
            Ok(())
        })?;
        Ok(key.expose_hex())
    }

    /// Refuse a wallet that is no longer the one the owner reviewed.
    fn ensure_reviewed(
        current: &WalletMetadata,
        reviewed: &WalletMetadata,
        wallet_id: &str,
        expected: Address,
    ) -> Result<()> {
        ensure!(
            current.instance_id == reviewed.instance_id && current.address == expected,
            "wallet {wallet_id} is no longer instance {} at {expected}; it was replaced while \
             this export was being authorized",
            reviewed.instance_id
        );
        Ok(())
    }

    pub async fn remove(&self, wallet_id: &str) -> Result<WalletMetadata> {
        let metadata = self.config.wallet(wallet_id)?;
        self.remove_reviewed(&metadata).await
    }

    /// Remove exactly the wallet instance whose address and identity were
    /// shown to the owner before this core operation began.
    pub async fn remove_reviewed(&self, metadata: &WalletMetadata) -> Result<WalletMetadata> {
        let wallet_id = &metadata.id;
        self.presence
            .confirm(&PresenceRequest::RemoveWallet {
                wallet: wallet_id.clone(),
            })
            .await?;

        // The lock is taken *after* authentication, not before: owner
        // authentication can take arbitrarily long, and blocking every other
        // process for as long as a human takes to answer a prompt is its own
        // defect. What it must cover is the pair of writes below — removing
        // the row and deleting the key it named — because a wallet created in
        // the gap between them inherits the id and had its brand-new key
        // deleted by this call's approval.
        //
        // Removing the row first is still right: if key deletion fails, the
        // metadata goes back, so a reachable credential is never orphaned
        // without an inventory row naming it.
        //
        // The row is matched on the address the owner actually reviewed rather
        // than on the name alone: removing by name would delete a replacement
        // wallet's row on the strength of an approval given for its
        // predecessor.
        self.config
            .with_lifecycle_lock(|| self.remove_locked(wallet_id, metadata))
    }

    fn remove_locked(&self, wallet_id: &str, metadata: &WalletMetadata) -> Result<WalletMetadata> {
        if let Err(error) = self.config.update(|config| {
            let index = config
                .wallets
                .iter()
                .position(|wallet| wallet.id == wallet_id)
                .with_context(|| format!("unknown wallet {wallet_id}"))?;
            ensure!(
                config.wallets[index].instance_id == metadata.instance_id
                    && config.wallets[index].address == metadata.address,
                "wallet {wallet_id} is no longer instance {} at {}; it was replaced while this \
                 removal was being authorized",
                metadata.instance_id,
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
        let removed = match self
            .keys
            .delete_matching(metadata.instance_id, metadata.address)
        {
            Ok(Deletion::Removed | Deletion::Absent) => Ok(metadata.clone()),
            // Something else holds this id now. The approval was for
            // `metadata.address`, so that credential is not this call's to
            // delete, and the row that names it is not this call's to restore.
            Ok(Deletion::Mismatched(other)) => Err(anyhow::anyhow!(
                "wallet {wallet_id} now holds a credential for {other} rather than the {} that \
                 was reviewed, so it was replaced while this removal ran; the replacement's key \
                 was left in place",
                metadata.address
            )),
            Err(error) => {
                // A deletion that reports failure has not said whether it
                // failed before or after removing the credential, so the
                // pre-operation metadata is not a state that is known to be
                // recoverable. Restoring it unconditionally is what listed a
                // wallet whose only key was already destroyed — an inventory
                // row that looks available and can never sign.
                //
                // Ask the store what is actually there, and restore only on a
                // positive answer that the reviewed key survived.
                match self.keys.address_of(metadata.instance_id) {
                    Ok(Some(surviving)) if surviving == metadata.address => {
                        let rollback = self.config.update(|config| {
                            ensure!(
                                !config.wallets.iter().any(|wallet| wallet.id == wallet_id),
                                "wallet {wallet_id} was recreated while this removal was failing"
                            );
                            config.wallets.push(metadata.clone());
                            Ok(())
                        });
                        if let Err(rollback) = rollback {
                            return Err(error).context(format!(
                                "credential deletion failed and metadata rollback also failed: \
                                 {rollback:#}"
                            ));
                        }
                        Err(error)
                    }
                    // The key is gone. The removal the owner asked for
                    // happened; putting the row back would list a wallet that
                    // cannot sign and cannot be exported.
                    Ok(None) => Ok(metadata.clone()),
                    Ok(Some(other)) => Err(error).context(format!(
                        "wallet {wallet_id} now holds a credential for {other} rather than the {} \
                         that was reviewed, so its metadata was not restored",
                        metadata.address
                    )),
                    Err(unreadable) => Err(error).context(format!(
                        "the credential store could not be re-read to establish whether the \
                         private key for {wallet_id} survived, so its metadata was not restored; \
                         check the Accounts screen before recreating it: \
                         {unreadable:#}"
                    )),
                }
            }
        }?;
        // Still inside the lifecycle lock: retire this immutable instance but
        // retain its policies and activity as history. A re-import receives a
        // new UUID and cannot inherit any of it.
        self.config.policy_store()?.retire_wallet(metadata)?;
        Ok(removed)
    }
}

/// In-memory key store for tests: the same trait surface as the OS store,
/// no credential-store side effects.
#[cfg(any(test, feature = "test-hooks"))]
#[derive(Default)]
pub struct MemoryKeyStore(std::sync::Mutex<std::collections::BTreeMap<Uuid, Vec<u8>>>);

#[cfg(any(test, feature = "test-hooks"))]
impl crate::sealed::SealedKeyStore for MemoryKeyStore {}

#[cfg(any(test, feature = "test-hooks"))]
impl KeyStore for MemoryKeyStore {
    fn insert_new(&self, instance_id: Uuid, key: &PrivateKeyMaterial) -> Result<()> {
        let mut keys = self.0.lock().unwrap();
        ensure!(!keys.contains_key(&instance_id), "duplicate key");
        keys.insert(instance_id, key.as_bytes().to_vec());
        Ok(())
    }

    fn load(&self, instance_id: Uuid) -> Result<PrivateKeyMaterial> {
        let keys = self.0.lock().unwrap();
        PrivateKeyMaterial::from_bytes(keys.get(&instance_id).context("missing test key")?)
    }

    fn address_of(&self, instance_id: Uuid) -> Result<Option<Address>> {
        let keys = self.0.lock().unwrap();
        match keys.get(&instance_id) {
            None => Ok(None),
            Some(bytes) => Ok(Some(PrivateKeyMaterial::from_bytes(bytes)?.address())),
        }
    }

    fn delete_matching(&self, instance_id: Uuid, expected: Address) -> Result<Deletion> {
        let mut keys = self.0.lock().unwrap();
        let Some(bytes) = keys.get(&instance_id) else {
            return Ok(Deletion::Absent);
        };
        let actual = PrivateKeyMaterial::from_bytes(bytes)?.address();
        if actual != expected {
            return Ok(Deletion::Mismatched(actual));
        }
        keys.remove(&instance_id);
        Ok(Deletion::Removed)
    }
}

#[cfg(test)]
#[path = "custody_test.rs"]
mod tests;
