//! Process-wide Windows service storage routing. Activation requires the
//! installer-provisioned virtual account and profile; it never migrates or
//! repairs desktop state. Once activated, no operation falls back to keyring.

use crate::{
    custody_envelope::WrappedDataKey,
    windows_service_storage::{DatabaseFile, PrivateStorageRoot},
};
use anyhow::{Context as _, Result, ensure};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::OnceLock,
};

static STORAGE: OnceLock<PrivateStorageRoot> = OnceLock::new();

/// Activate locked custody before constructing any application authority.
/// Existing installer state and the actual primary process token are verified.
pub fn initialize(owner_sid: &str) -> Result<PathBuf> {
    let root = PrivateStorageRoot::open(owner_sid)?;
    let path = root.data_dir().to_owned();
    STORAGE
        .set(root)
        .map_err(|_| anyhow::anyhow!("service custody is already initialized"))?;
    Ok(path)
}

/// The transport must first authenticate the desktop peer. The ciphertext
/// supplies no identity, paths, owner approval, or enrollment metadata.
pub fn unlock(wrapped: &WrappedDataKey) -> Result<()> {
    STORAGE
        .get()
        .context("service custody is not initialized")?
        .unlock(wrapped)
}

pub(crate) fn data_dir() -> Option<&'static Path> {
    STORAGE.get().map(PrivateStorageRoot::data_dir)
}

pub(crate) fn require_data_dir(path: &Path) -> Result<()> {
    if let Some(root) = data_dir() {
        ensure!(
            path == root,
            "wallet authority requested a directory outside its service profile"
        );
    }
    Ok(())
}

fn database_file(root: &Path, path: &Path) -> Result<DatabaseFile> {
    for (name, file) in [
        ("wallet.db", DatabaseFile::Database),
        ("wallet.lock", DatabaseFile::Lock),
        ("config.lock", DatabaseFile::ConfigurationLock),
        ("lifecycle.lock", DatabaseFile::LifecycleLock),
    ] {
        if path == root.join(name) {
            return Ok(file);
        }
    }
    anyhow::bail!("wallet authority requested an unsupported service file")
}

pub(crate) fn open_file(path: &Path) -> Option<Result<File>> {
    STORAGE
        .get()
        .map(|root| root.open_database_file(database_file(root.data_dir(), path)?))
}

pub(crate) fn pin_database(path: &Path) -> Result<Option<File>> {
    STORAGE
        .get()
        .map(|root| {
            ensure!(
                matches!(
                    database_file(root.data_dir(), path)?,
                    DatabaseFile::Database
                ),
                "SQLite requested a non-database service file"
            );
            root.open_database_file(DatabaseFile::Database)
        })
        .transpose()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Credential {
    Database,
    Account(uuid::Uuid),
}

impl Credential {
    fn parse(service: &str, user: &str) -> Result<Self> {
        match (service, user) {
            ("org.ekubo.wallet.db", "default") => Ok(Self::Database),
            ("org.ekubo.wallet.private-key.instance", id) => {
                let id = uuid::Uuid::parse_str(id).context("invalid wallet instance identifier")?;
                ensure!(!id.is_nil(), "invalid wallet instance identifier");
                Ok(Self::Account(id))
            }
            _ => anyhow::bail!("unsupported service credential namespace"),
        }
    }
}

pub(crate) struct Entry {
    root: &'static PrivateStorageRoot,
    credential: Credential,
}

pub(crate) fn entry(service: &str, user: &str) -> Option<Result<Entry>> {
    STORAGE.get().map(|root| {
        Ok(Entry {
            root,
            credential: Credential::parse(service, user)?,
        })
    })
}

impl Entry {
    pub(crate) fn get_secret(&self) -> Result<Vec<u8>> {
        let material = match self.credential {
            Credential::Database => self.root.read_database_key()?,
            Credential::Account(id) => self.root.read_account_key(id)?,
        };
        Ok(material.to_vec())
    }

    pub(crate) fn set_secret(&self, bytes: &[u8]) -> Result<()> {
        let material: &[u8; 32] = bytes
            .try_into()
            .context("invalid service credential length")?;
        match self.credential {
            Credential::Database => self.root.create_database_key(material),
            Credential::Account(id) => self.root.create_account_key(id, material),
        }
    }

    pub(crate) fn delete_credential(&self) -> Result<()> {
        self.root.delete_key(match self.credential {
            Credential::Database => None,
            Credential::Account(id) => Some(id),
        })
    }
}

pub(crate) fn is_missing_credential(error: &anyhow::Error) -> bool {
    // Only a missing final credential name means first use. Access errors,
    // corrupt files, and missing profile paths must never mint a replacement.
    error
        .downcast_ref::<windows::core::Error>()
        .is_some_and(|error| {
            error.code() == windows::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND.to_hresult()
        })
}

#[cfg(test)]
#[path = "windows_service_custody_test.rs"]
mod tests;
