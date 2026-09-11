//! Linux service-owned custody. No desktop credentials are read by this store.
//!
//! The installer provisions root-owned configuration and a directory owned by
//! a distinct, unprivileged service UID. Bootstrap pins directory descriptors
//! before opening keys. This module does not install anything or migrate keys.

use std::{
    fs::File,
    io::{Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use anyhow::{Context as _, Result, ensure};
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, openat};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::custody_envelope::{DataCipher, SEALED_KEY_BYTES, WrappedDataKey};
use crate::service_custody::ServiceCustody;
use crate::service_profile_lock::ProfileLock;

static STORAGE: OnceLock<Storage> = OnceLock::new();
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_CONFIG_BYTES: u64 = 4096;
const KEY_BYTES: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerConfiguration {
    owner_uid: u32,
    service_uid: u32,
    profile_id: uuid::Uuid,
}

/// Installer-attested identity for the current desktop user's service.
/// Construction is restricted to the root-owned configuration reader.
pub struct InstalledServiceIdentity {
    owner_uid: u32,
    service_uid: u32,
    profile_id: uuid::Uuid,
}

impl InstalledServiceIdentity {
    #[must_use]
    pub const fn profile_id(&self) -> uuid::Uuid {
        self.profile_id
    }
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    #[must_use]
    pub const fn service_uid(&self) -> u32 {
        self.service_uid
    }
}

/// Read only public installer configuration, without activating custody or
/// touching credentials. Clients cannot choose another owner or a config path.
pub fn installed_service_identity() -> Result<InstalledServiceIdentity> {
    let owner_uid = rustix::process::geteuid().as_raw();
    ensure!(
        rustix::process::getuid().as_raw() == owner_uid,
        "wallet client cannot run as a set-user-ID process"
    );
    let configured = owner_configuration(&root_directory()?, owner_uid)?;
    Ok(InstalledServiceIdentity {
        owner_uid,
        service_uid: configured.service_uid,
        profile_id: configured.profile_id,
    })
}

fn root_directory() -> Result<File> {
    let root = File::from(rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    validate_directory(&root, 0, false)?;
    Ok(root)
}

fn owner_configuration(root: &File, owner_uid: u32) -> Result<OwnerConfiguration> {
    let etc = directory(root, "etc", 0, false)?;
    let config_root = directory(&etc, "ekubo-wallet", 0, false)?;
    let owners = directory(&config_root, "owners", 0, false)?;
    let config = open_regular(&owners, &format!("{owner_uid}.json"), 0, false)?;
    ensure!(
        config.metadata()?.len() <= MAX_CONFIG_BYTES,
        "service configuration is oversized"
    );
    let mut bytes = Vec::new();
    config.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    decode_configuration(&bytes, owner_uid)
}

fn decode_configuration(bytes: &[u8], owner_uid: u32) -> Result<OwnerConfiguration> {
    ensure!(
        bytes.len() as u64 <= MAX_CONFIG_BYTES,
        "service configuration is oversized"
    );
    let configured: OwnerConfiguration = serde_json::from_slice(bytes)?;
    ensure!(
        configured.owner_uid == owner_uid
            && owner_uid != 0
            && configured.service_uid != 0
            && configured.service_uid != owner_uid
            && !configured.profile_id.is_nil(),
        "wallet service identity does not match installer configuration"
    );
    Ok(configured)
}

struct Storage {
    _lock: ProfileLock,
    owner_uid: u32,
    directory: Arc<File>,
    data_dir: PathBuf,
    service_uid: u32,
    profile_id: uuid::Uuid,
    custody: ServiceCustody,
}

/// Activate only after the installer has provisioned this owner's root-owned
/// configuration. The supplied UID selects a configuration, not an authority:
/// its content and the running process identity must agree. There is no
/// environment-variable override or caller-selected storage path.
///
/// One service process serves one owner. Activation is single-use; subsequent
/// attempts cannot replace the active custody store. The host must exit if
/// activation fails, before accepting any IPC connection. Custody remains
/// locked until `unlock` validates the enrolled keyring ciphertext; the host
/// must not construct wallet authority before then.
pub fn initialize(owner_uid: u32) -> Result<PathBuf> {
    let service_uid = rustix::process::geteuid().as_raw();
    ensure!(
        service_uid != 0 && owner_uid != 0 && service_uid != owner_uid,
        "wallet service requires a distinct, unprivileged OS identity"
    );
    ensure!(
        rustix::process::getuid().as_raw() == service_uid,
        "wallet service cannot run as a set-user-ID process"
    );
    let root = root_directory()?;
    let configured = owner_configuration(&root, owner_uid)?;
    ensure!(
        configured.owner_uid == owner_uid && configured.service_uid == service_uid,
        "wallet service identity does not match installer configuration"
    );
    let var = directory(&root, "var", 0, false)?;
    let lib = directory(&var, "lib", 0, false)?;
    let parent = directory(&lib, "ekubo-wallet", 0, false)?;
    let directory = Arc::new(directory(
        &parent,
        &owner_uid.to_string(),
        service_uid,
        true,
    )?);
    let data_dir = PathBuf::from(format!("/var/lib/ekubo-wallet/{owner_uid}"));
    let lock = lock_profile(&directory, service_uid)?;
    STORAGE
        .set(Storage {
            _lock: lock,
            owner_uid,
            directory,
            data_dir: data_dir.clone(),
            service_uid,
            profile_id: configured.profile_id,
            custody: ServiceCustody::default(),
        })
        .map_err(|_| anyhow::anyhow!("wallet service storage was already initialized"))?;
    Ok(data_dir)
}

/// Connect only through the root-controlled system bus directory. Environment
/// overrides could select a hostile bus that lies about peer UIDs, so they are
/// deliberately not consulted by either side of the service boundary.
pub async fn system_bus_stream() -> Result<tokio::net::UnixStream> {
    use std::os::{fd::AsRawFd as _, unix::fs::FileTypeExt as _};

    let run = directory(&root_directory()?, "run", 0, false)?;
    let bus = directory(&run, "dbus", 0, false)?;
    let path = format!("/proc/self/fd/{}/system_bus_socket", bus.as_raw_fd());
    ensure!(
        std::fs::symlink_metadata(&path)?.file_type().is_socket(),
        "system bus endpoint is not a socket"
    );
    // Keep the pinned parent descriptor alive until connect has finished.
    let stream = tokio::net::UnixStream::connect(path).await?;
    drop(bus);
    Ok(stream)
}

/// Pinned runtime directory provisioned by the installer, accessible to clients
/// but writable only by the service. The host binds sockets relative to this
/// descriptor, never through a desktop-controlled path.
pub fn runtime_directory() -> Result<File> {
    let storage = STORAGE
        .get()
        .context("service storage is not initialized")?;
    let run = File::from(rustix::fs::open(
        "/run",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    validate_directory(&run, 0, false)?;
    let parent = directory(&run, "ekubo-wallet", 0, false)?;
    directory(
        &parent,
        &storage.owner_uid.to_string(),
        storage.service_uid,
        false,
    )
}

fn lock_profile(parent: &File, uid: u32) -> Result<ProfileLock> {
    let lock = File::from(openat(
        parent,
        "service.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_raw_mode(PRIVATE_FILE_MODE),
    )?);
    validate_file(&lock, uid, true)?;
    ProfileLock::acquire(lock)
}

pub(crate) fn owner_uid() -> Option<u32> {
    STORAGE.get().map(|storage| storage.owner_uid)
}

pub(crate) fn data_dir() -> Option<&'static Path> {
    STORAGE.get().map(|storage| storage.data_dir.as_path())
}

pub(crate) fn require_data_dir(data_dir: &Path) -> Result<()> {
    if let Some(storage) = STORAGE.get() {
        ensure!(
            data_dir == storage.data_dir,
            "wallet authority requested a directory outside its service profile"
        );
    }
    Ok(())
}

pub(crate) fn entry(service: &str, user: &str) -> Option<Result<Entry>> {
    STORAGE.get().map(|storage| storage.entry(service, user))
}

/// The host must authenticate the desktop OS peer before calling this bootstrap
/// operation. Only ciphertext crosses that transport; metadata and the wrapping
/// key are read through the service's pinned private directory.
pub fn unlock(wrapped: &WrappedDataKey) -> Result<()> {
    STORAGE
        .get()
        .context("service storage is not initialized")?
        .unlock(wrapped)
}

impl Storage {
    fn unlock(&self, wrapped: &WrappedDataKey) -> Result<()> {
        self.custody.unlock(
            open_regular(&self.directory, "custody.json", self.service_uid, true)?,
            open_regular(&self.directory, "wrapping.key", self.service_uid, true)?,
            &format!("linux:uid:{}", self.owner_uid),
            &format!("linux:uid:{}", self.service_uid),
            self.profile_id,
            wrapped,
        )
    }

    fn entry(&self, service: &str, user: &str) -> Result<Entry> {
        let cipher = self.custody.cipher()?;
        let (name, instance) = match (service, user) {
            ("org.ekubo.wallet.db", "default") => ("key-database".to_owned(), None),
            ("org.ekubo.wallet.private-key.instance", id) => {
                let id = uuid::Uuid::parse_str(id).context("invalid wallet instance identifier")?;
                ensure!(!id.is_nil(), "invalid wallet instance identifier");
                (format!("key-account-{id}"), Some(id))
            }
            _ => anyhow::bail!("unsupported service credential namespace"),
        };
        Ok(Entry {
            directory: self.directory.clone(),
            service_uid: self.service_uid,
            name,
            cipher,
            instance,
        })
    }
}

pub(crate) struct Entry {
    directory: Arc<File>,
    service_uid: u32,
    name: String,
    cipher: Arc<DataCipher>,
    instance: Option<uuid::Uuid>,
}

fn read_fixed<const N: usize>(parent: &File, name: &str, uid: u32) -> Result<Zeroizing<[u8; N]>> {
    crate::service_custody::read_fixed(open_regular(parent, name, uid, true)?)
}

impl Entry {
    pub(crate) fn get_secret(&self) -> Result<Vec<u8>> {
        let bytes = read_fixed::<SEALED_KEY_BYTES>(&self.directory, &self.name, self.service_uid)?;
        let material = match self.instance {
            Some(instance) => self.cipher.open_account_key(instance, bytes.as_slice())?,
            None => self.cipher.open_database_key(bytes.as_slice())?,
        };
        Ok(material.to_vec())
    }

    /// Keys are immutable. Publish a fully synced inode without replacing any
    /// existing key, including when another service process races creation.
    pub(crate) fn set_secret(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() == KEY_BYTES,
            "invalid service credential length"
        );
        let material: &[u8; KEY_BYTES] = bytes.try_into().expect("validated key length");
        let sealed = match self.instance {
            Some(instance) => self.cipher.seal_account_key(instance, material)?,
            None => self.cipher.seal_database_key(material)?,
        };
        let temporary = format!(".key-stage-{}", uuid::Uuid::new_v4());
        let mut file = File::from(openat(
            &self.directory,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(PRIVATE_FILE_MODE),
        )?);
        let result = (|| {
            file.write_all(&sealed)?;
            file.sync_all()?;
            rustix::fs::renameat_with(
                &self.directory,
                &temporary,
                &self.directory,
                &self.name,
                RenameFlags::NOREPLACE,
            )?;
            self.directory.sync_all()?;
            Ok(())
        })();
        // If publication succeeded, this name no longer exists. If it failed,
        // remove only the exact temporary entry created by this operation.
        let _ = rustix::fs::unlinkat(&self.directory, &temporary, AtFlags::empty());
        result
    }

    pub(crate) fn delete_credential(&self) -> Result<()> {
        // Refuse symlinks, hard links, wrong ownership, and permissive ACL masks
        // before deleting. The protected parent excludes desktop-user races.
        let _file = open_regular(&self.directory, &self.name, self.service_uid, true)?;
        rustix::fs::unlinkat(&self.directory, &self.name, AtFlags::empty())?;
        self.directory.sync_all()?;
        Ok(())
    }
}

fn directory(parent: &File, name: &str, uid: u32, private: bool) -> Result<File> {
    let directory = File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    validate_directory(&directory, uid, private)?;
    Ok(directory)
}

fn validate_directory(directory: &File, uid: u32, private: bool) -> Result<()> {
    let metadata = directory.metadata()?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid,
        "service directory has incorrect ownership or type"
    );
    let permissions = metadata.mode() & 0o7777;
    ensure!(
        if private {
            permissions == PRIVATE_DIRECTORY_MODE
        } else {
            permissions & 0o7022 == 0
        },
        "service directory has unsafe permissions"
    );
    Ok(())
}

fn open_regular(parent: &File, name: &str, uid: u32, private: bool) -> Result<File> {
    // NONBLOCK prevents a substituted FIFO from blocking before the type check.
    let file = File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    validate_file(&file, uid, private)?;
    Ok(file)
}

fn validate_file(file: &File, uid: u32, private: bool) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == uid && metadata.nlink() == 1,
        "service file has incorrect ownership, type, or link count"
    );
    let permissions = metadata.mode() & 0o7777;
    ensure!(
        if private {
            permissions == PRIVATE_FILE_MODE
        } else {
            permissions & 0o7133 == 0
        },
        "service file has unsafe permissions"
    );
    Ok(())
}

#[cfg(test)]
#[path = "service_storage_test.rs"]
mod tests;

#[cfg(test)]
#[path = "service_storage_unlock_test.rs"]
mod unlock_tests;
