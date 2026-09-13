//! Non-secret retirement evidence lives in the protected destination binding.
//! A source marker is only checked against that evidence, never trusted alone.
use super::*;
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Seek as _, Write as _};

const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub database_key_hash: [u8; 32],
    pub source_file_hash: [u8; 32],
}

pub(super) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(super) fn file_hash(file: &File) -> Result<[u8; 32]> {
    ensure!(
        file.metadata()?.len() <= MAX_SOURCE_BYTES,
        "legacy source exceeds bounded file size"
    );
    // Closing a duplicate descriptor would release this process's POSIX SQLite
    // locks for the inode. Borrow the already-held pin instead.
    let mut reader = file;
    reader.rewind()?;
    let mut reader = reader.take(MAX_SOURCE_BYTES + 1);
    let mut digest = Sha256::new();
    let mut buffer = [0; 8192];
    let mut total = 0_u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        ensure!(
            total <= MAX_SOURCE_BYTES,
            "legacy source grew past bounded file size"
        );
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

fn marker(binding: &MoveBinding) -> Result<Vec<u8>> {
    let mut bytes = b"EKUBO WALLET 1.X PROFILE RETIRED TO V2\nThis is intentionally not a SQLite database. Do not remove or reset it.\nEncrypted history: wallet.db.retired-v2-backup\n".to_vec();
    bytes.extend(serde_json::to_vec(binding)?);
    Ok(bytes)
}

fn read_database_key() -> Result<Option<Zeroizing<Vec<u8>>>> {
    // All production callers run in blocking_phase (review/resume or cleanup).
    match crate::credential_store::legacy_entry("org.ekubo.wallet.db", "default")
        .context("open legacy global database credential store")?
        .get_secret()
    {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => {
            Err(anyhow::Error::from(error).context("read legacy global database credential"))
        }
    }
}

pub(super) fn check_database_key(identity: &Identity, required: bool) -> Result<()> {
    check_key(
        identity,
        required,
        read_database_key()?.as_deref().map(Vec::as_slice),
    )
}

fn check_key(identity: &Identity, preserved: bool, key: Option<&[u8]>) -> Result<()> {
    if let Some(key) = key {
        ensure!(
            key.len() == 32 && hash(key) == identity.database_key_hash,
            "legacy global database credential changed; stop without deleting new authority"
        );
    } else {
        ensure!(
            !preserved,
            "legacy global database credential is absent but preserved profiles require it"
        );
    }
    Ok(())
}

pub(super) fn retire_database_key(identity: &Identity, preserved: bool) -> Result<bool> {
    retire_key_with(identity, preserved, read_database_key, || {
        match crate::credential_store::legacy_entry("org.ekubo.wallet.db", "default")
            .context("open legacy global database credential for deletion")?
            .delete_credential()
        {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => {
                Err(anyhow::Error::from(error).context("delete legacy global database credential"))
            }
        }
    })
}

fn retire_key_with(
    identity: &Identity,
    preserved: bool,
    mut read: impl FnMut() -> Result<Option<Zeroizing<Vec<u8>>>>,
    mut remove: impl FnMut() -> Result<()>,
) -> Result<bool> {
    let key = read()?;
    check_key(identity, preserved, key.as_deref().map(Vec::as_slice))?;
    if preserved {
        return Ok(true);
    }
    if key.is_some() {
        let current = read()?;
        check_key(identity, false, current.as_deref().map(Vec::as_slice))?;
        if current.is_some() {
            remove()?;
        }
    }
    ensure!(
        read()?.is_none(),
        "legacy database credential deletion was not confirmed; cleanup remains pending"
    );
    Ok(false)
}

fn sync_directory(root: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    File::open(root)?.sync_all()?;
    #[cfg(target_os = "windows")]
    let _ = root; // Windows publishes with MOVEFILE_WRITE_THROUGH below.
    Ok(())
}

fn publish(temp: tempfile::NamedTempFile, path: &Path, replace: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    if replace {
        temp.persist(path)?;
    } else {
        temp.persist_noclobber(path)?;
    }
    #[cfg(target_os = "windows")]
    {
        let temporary = temp.into_temp_path();
        super::native::publish(&temporary, path, replace)?;
    }
    Ok(())
}

fn backup(root: &Path, pin: &File, identity: &Identity) -> Result<File> {
    let path = root.join("wallet.db.retired-v2-backup");
    if !path.try_exists()? {
        let mut temp = tempfile::NamedTempFile::new_in(root)?;
        let mut source = pin;
        source.rewind()?;
        let copied = std::io::copy(&mut source.take(MAX_SOURCE_BYTES + 1), temp.as_file_mut())?;
        ensure!(
            copied <= MAX_SOURCE_BYTES,
            "legacy source grew past bounded backup size"
        );
        ensure!(
            file_hash(temp.as_file())? == identity.source_file_hash,
            "legacy source changed while copying backup"
        );
        temp.as_file().sync_all()?;
        publish(temp, &path, false)?;
        sync_directory(root)?;
    }
    let file = open_legacy_file(&path, false)?;
    ensure!(
        file_hash(&file)? == identity.source_file_hash,
        "encrypted legacy backup identity mismatch"
    );
    sync_directory(root)?;
    Ok(file)
}

impl Frozen {
    pub(super) fn retire(&mut self, binding: &MoveBinding) -> Result<()> {
        self.revalidate()?;
        let identity = binding
            .retirement
            .as_ref()
            .context("missing retirement identity")?;
        let marker = marker(binding)?;
        if file_hash(&self.pin)? == hash(&marker) {
            let backup = open_legacy_file(&self.root.join("wallet.db.retired-v2-backup"), false)?;
            ensure!(
                file_hash(&backup)? == identity.source_file_hash,
                "encrypted legacy backup identity mismatch"
            );
            sync_directory(&self.root)?;
            return Ok(());
        }
        ensure!(
            file_hash(&self.pin)? == identity.source_file_hash,
            "legacy source changed before retirement"
        );
        let backup = backup(&self.root, &self.pin, identity)?;
        // Release database handles (Windows disallows replacing an open source),
        // but keep both old application locks until cleanup and receipt completion.
        drop(self.connection.take());
        self.pin = backup;
        let mut temp = tempfile::NamedTempFile::new_in(&self.root)?;
        temp.write_all(&marker)?;
        temp.as_file().sync_all()?;
        publish(temp, &self.root.join("wallet.db"), true)?;
        sync_directory(&self.root)?;
        self.pin = open_legacy_file(&self.root.join("wallet.db"), false)?;
        ensure!(
            file_hash(&self.pin)? == hash(&marker),
            "legacy retirement marker did not persist"
        );
        Ok(())
    }

    fn retired(root: PathBuf, binding: &MoveBinding) -> Result<Self> {
        let mut locks = Vec::new();
        for name in ["application.lock", "lifecycle.lock"] {
            let file = open_legacy_file(&root.join(name), true)?;
            fs2::FileExt::try_lock_exclusive(&file)
                .context("close 1.x before resuming retirement")?;
            locks.push(file);
        }
        let pin = open_legacy_file(&root.join("wallet.db"), false)?;
        ensure!(
            file_hash(&pin)? == hash(&marker(binding)?),
            "source is not the destination-bound retirement tombstone"
        );
        let result = Self {
            connection: None,
            pin,
            _locks: locks,
            root,
            digest: [0; 32],
        };
        result.revalidate()?;
        Ok(result)
    }
}

impl LegacySource {
    pub(super) fn resume(receipt: Receipt) -> Result<Self> {
        require_legacy_owner()?;
        Self::resume_with_key(
            receipt,
            read_database_key().context("read old database credential during cleanup recovery")?,
        )
    }

    fn resume_with_key(receipt: Receipt, key: Option<Zeroizing<Vec<u8>>>) -> Result<Self> {
        let binding = receipt
            .binding
            .context("missing destination-bound move identity")?;
        let identity = binding.retirement.clone().context("pending receipt predates resumable source retirement; source must be recovered explicitly")?;
        check_key(
            &identity,
            !binding.preserved_profiles.is_empty(),
            key.as_deref().map(Vec::as_slice),
        )?;
        let marker_hash = hash(&marker(&binding)?);
        let source_file = open_legacy_file(&binding.source.join("wallet.db"), false)?;
        let retired = file_hash(&source_file)? == marker_hash;
        drop(source_file);
        let database_key = key
            .as_ref()
            .map(|key| {
                Ok::<_, anyhow::Error>(DatabaseKey::new(
                    key.as_slice()
                        .try_into()
                        .context("invalid legacy database key")?,
                ))
            })
            .transpose()?;
        let source = if retired {
            Frozen::retired(binding.source.clone(), &binding)?
        } else {
            let source = Frozen::open(
                binding.source.clone(),
                database_key
                    .as_ref()
                    .context("old database key absent before source retirement; stop")?,
            )?;
            ensure!(
                source.digest == receipt.digest
                    && file_hash(&source.pin)? == identity.source_file_hash,
                "legacy source differs from committed destination"
            );
            source
        };
        let mut frozen = vec![source];
        let mut preserved_wallets = Vec::new();
        for path in &binding.preserved_profiles {
            let other = Frozen::open(
                path.clone(),
                database_key
                    .as_ref()
                    .context("preserved profile key absent")?,
            )?;
            preserved_wallets.extend(database::wallets(
                other.connection.as_ref().expect("open preserved profile"),
            )?);
            frozen.push(other);
        }
        ensure!(
            shared_accounts(&receipt.wallets, &preserved_wallets)
                == binding.retained_shared_accounts,
            "preserved profile sharing changed; cleanup remains pending"
        );
        // Erase the raw platform credential before returning the reviewed source.
        drop(key);
        Ok(Self {
            authorized_profile: binding.profile,
            frozen,
            summary: MoveSummary {
                source: binding.source,
                accounts: receipt.wallets,
                tables: vec![],
                retained_shared_accounts: binding.retained_shared_accounts,
                preserved_profiles: binding.preserved_profiles,
            },
            snapshot: None,
            digest: receipt.digest,
            retirement: identity,
        })
    }
}

#[cfg(test)]
#[path = "legacy_move_retirement_test.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "legacy_move_secret_service_test.rs"]
mod secret_service_tests;
