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
}

struct Storage {
    _lock: File,
    owner_uid: u32,
    directory: Arc<File>,
    data_dir: PathBuf,
    service_uid: u32,
}

/// Activate only after the installer has provisioned this owner's root-owned
/// configuration. The supplied UID selects a configuration, not an authority:
/// its content and the running process identity must agree. There is no
/// environment-variable override or caller-selected storage path.
///
/// One service process serves one owner. Activation is single-use; subsequent
/// attempts cannot replace the active custody store. The host must exit if
/// activation fails, before accepting any IPC connection.
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
    let root = File::from(rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?);
    validate_directory(&root, 0, false)?;
    let etc = directory(&root, "etc", 0, false)?;
    let config_root = directory(&etc, "ekubo-wallet", 0, false)?;
    let owners = directory(&config_root, "owners", 0, false)?;
    let config = open_regular(&owners, &format!("{owner_uid}.json"), 0, false)?;
    ensure!(
        config.metadata()?.len() <= MAX_CONFIG_BYTES,
        "service configuration is oversized"
    );
    let mut bytes = Vec::new();
    config.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_CONFIG_BYTES,
        "service configuration is oversized"
    );
    let configured: OwnerConfiguration = serde_json::from_slice(&bytes)?;
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
        })
        .map_err(|_| anyhow::anyhow!("wallet service storage was already initialized"))?;
    Ok(data_dir)
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

fn lock_profile(parent: &File, uid: u32) -> Result<File> {
    let lock = File::from(openat(
        parent,
        "service.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_raw_mode(PRIVATE_FILE_MODE),
    )?);
    validate_file(&lock, uid, true)?;
    fs2::FileExt::try_lock_exclusive(&lock).context("wallet service profile is already running")?;
    Ok(lock)
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
    STORAGE.get().map(|storage| {
        let name = match (service, user) {
            ("org.ekubo.wallet.db", "default") => "key-database".to_owned(),
            ("org.ekubo.wallet.private-key.instance", id) => {
                let id = uuid::Uuid::parse_str(id).context("invalid wallet instance identifier")?;
                format!("key-account-{id}")
            }
            _ => anyhow::bail!("unsupported service credential namespace"),
        };
        Ok(Entry {
            directory: storage.directory.clone(),
            service_uid: storage.service_uid,
            name,
        })
    })
}

pub(crate) struct Entry {
    directory: Arc<File>,
    service_uid: u32,
    name: String,
}

impl Entry {
    pub(crate) fn get_secret(&self) -> Result<Vec<u8>> {
        let mut file = open_regular(&self.directory, &self.name, self.service_uid, true)?;
        ensure!(
            file.metadata()?.len() == KEY_BYTES as u64,
            "invalid service credential length"
        );
        let mut bytes = Zeroizing::new(vec![0; KEY_BYTES]);
        file.read_exact(&mut bytes)?;
        ensure!(
            file.read(&mut [0_u8; 1])? == 0,
            "service credential grew while being read"
        );
        Ok(bytes.to_vec())
    }

    /// Keys are immutable. Publish a fully synced inode without replacing any
    /// existing key, including when another service process races creation.
    pub(crate) fn set_secret(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() == KEY_BYTES,
            "invalid service credential length"
        );
        let temporary = format!(".key-stage-{}", uuid::Uuid::new_v4());
        let mut file = File::from(openat(
            &self.directory,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(PRIVATE_FILE_MODE),
        )?);
        let result = (|| {
            file.write_all(bytes)?;
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
