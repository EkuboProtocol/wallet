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

/// Public pending identity read by the privileged installer. Distinct from
/// active desktop discovery, and constructed only from protected configuration.
pub struct PendingInstallerIdentity {
    configured: OwnerConfiguration,
}

impl PendingInstallerIdentity {
    #[must_use]
    pub const fn owner_uid(&self) -> u32 {
        self.configured.owner_uid
    }
    #[must_use]
    pub const fn service_uid(&self) -> u32 {
        self.configured.service_uid
    }
    #[must_use]
    pub const fn profile_id(&self) -> uuid::Uuid {
        self.configured.profile_id
    }
}

/// Read pending public metadata without accessing either service or legacy keys.
/// This cannot activate custody or fall back from an active/damaged installation.
pub fn pending_installer_identity(owner_uid: u32) -> Result<PendingInstallerIdentity> {
    ensure!(
        rustix::process::getuid().as_raw() == 0 && rustix::process::geteuid().as_raw() == 0,
        "pending identity lookup requires the privileged installer"
    );
    read_pending_installer_identity(&root_directory()?, owner_uid, 0)
}

fn read_pending_installer_identity(
    root: &File,
    owner_uid: u32,
    system_uid: u32,
) -> Result<PendingInstallerIdentity> {
    Ok(PendingInstallerIdentity {
        configured: pending_configuration(root, owner_uid, system_uid)?,
    })
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
    find_installed_service_identity()?.context("wallet service is not installed")
}

/// Absence permits pre-installation behavior. Unsafe or unreadable paths and
/// malformed configuration never count as an absent installation.
pub fn find_installed_service_identity() -> Result<Option<InstalledServiceIdentity>> {
    let owner_uid = client_uid()?;
    let Some(configured) = find_owner_configuration(&root_directory()?, owner_uid, 0)? else {
        return Ok(None);
    };
    Ok(Some(InstalledServiceIdentity {
        owner_uid,
        service_uid: configured.service_uid,
        profile_id: configured.profile_id,
    }))
}

fn client_uid() -> Result<u32> {
    let owner_uid = rustix::process::geteuid().as_raw();
    ensure!(
        rustix::process::getuid().as_raw() == owner_uid,
        "wallet client cannot run as a set-user-ID process"
    );
    Ok(owner_uid)
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
    find_owner_configuration(root, owner_uid, 0)?.context("wallet service is not installed")
}

fn find_owner_configuration(
    root: &File,
    owner_uid: u32,
    system_uid: u32,
) -> Result<Option<OwnerConfiguration>> {
    find_configuration_at(root, owner_uid, system_uid, "owners")
}

fn find_configuration_at(
    root: &File,
    owner_uid: u32,
    system_uid: u32,
    collection: &str,
) -> Result<Option<OwnerConfiguration>> {
    let mut parent = directory(root, "etc", system_uid, false)?;
    for name in ["ekubo-wallet", collection] {
        let Some(next) = open_optional(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        )?
        else {
            return Ok(None);
        };
        validate_directory(&next, system_uid, false)?;
        parent = next;
    }
    let Some(config) = open_optional(
        &parent,
        &format!("{owner_uid}.json"),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
    )?
    else {
        return Ok(None);
    };
    validate_file(&config, system_uid, false)?;
    ensure!(
        config.metadata()?.len() <= MAX_CONFIG_BYTES,
        "service configuration is oversized"
    );
    let mut bytes = Vec::new();
    config.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(Some(decode_configuration(&bytes, owner_uid)?))
}

fn open_optional(parent: &File, name: &str, flags: OFlags) -> Result<Option<File>> {
    match openat(parent, name, flags, Mode::empty()) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(error.into()),
    }
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

/// Connect only to the installed owner's protected MCP socket. The expected
/// process comes from the authenticated system-bus peer that unlocked custody;
/// it supplements, and cannot replace, the installed service UID check.
pub async fn agent_stream(
    identity: &InstalledServiceIdentity,
    expected_pid: u32,
) -> Result<tokio::net::UnixStream> {
    ensure!(
        client_uid()? == identity.owner_uid,
        "MCP client belongs to another owner"
    );
    connect_agent_under(&root_directory()?, identity, expected_pid, 0).await
}

async fn connect_agent_under(
    root: &File,
    identity: &InstalledServiceIdentity,
    expected_pid: u32,
    system_uid: u32,
) -> Result<tokio::net::UnixStream> {
    use std::os::{fd::AsRawFd as _, unix::fs::FileTypeExt as _};
    let run = client_directory(root, "run", system_uid)?;
    let parent = client_directory(&run, "ekubo-wallet", system_uid)?;
    let runtime = client_directory(
        &parent,
        &identity.owner_uid.to_string(),
        identity.service_uid,
    )?;
    let path = format!("/proc/self/fd/{}/mcp.sock", runtime.as_raw_fd());
    ensure!(
        std::fs::symlink_metadata(&path)?.file_type().is_socket(),
        "service MCP endpoint is not a socket"
    );
    let stream = tokio::net::UnixStream::connect(path).await?;
    validate_agent_peer(&stream, identity.service_uid, expected_pid)?;
    drop(runtime);
    Ok(stream)
}

fn client_directory(parent: &File, name: &str, uid: u32) -> Result<File> {
    // O_PATH pins an execute-only runtime directory without requiring a client
    // to list its contents. Metadata and connection checks still fail closed.
    let directory = File::from(openat(
        parent,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    validate_directory(&directory, uid, false)?;
    Ok(directory)
}

fn validate_agent_peer(
    stream: &tokio::net::UnixStream,
    service_uid: u32,
    expected_pid: u32,
) -> Result<()> {
    let peer = stream.peer_cred()?;
    ensure!(
        peer.uid() == service_uid,
        "MCP endpoint does not belong to the installed service"
    );
    ensure!(
        peer.pid().and_then(|pid| u32::try_from(pid).ok()) == Some(expected_pid),
        "MCP endpoint is not the authenticated custody process"
    );
    Ok(())
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

pub struct CredentialStagingRoot {
    directory: Arc<File>,
    owner_uid: u32,
    service_uid: u32,
    profile_id: uuid::Uuid,
    _lock: Option<ProfileLock>,
}

pub fn credential_staging_root() -> Result<CredentialStagingRoot> {
    let storage = STORAGE
        .get()
        .context("service storage is not initialized")?;
    Ok(CredentialStagingRoot {
        directory: storage.directory.clone(),
        owner_uid: storage.owner_uid,
        service_uid: storage.service_uid,
        profile_id: storage.profile_id,
        _lock: None,
    })
}

/// Open only pending installer storage, without initializing global custody or
/// publishing an installed identity. No owner or agent endpoint is activated.
pub fn pending_credential_staging_root(owner_uid: u32) -> Result<PendingCredentialStorage> {
    let service_uid = rustix::process::geteuid().as_raw();
    ensure!(
        service_uid != 0
            && service_uid != owner_uid
            && rustix::process::getuid().as_raw() == service_uid,
        "pending storage requires a distinct unprivileged service process"
    );
    let root = root_directory()?;
    open_pending_storage(&root, owner_uid, 0)
}

fn open_pending_storage(
    root: &File,
    owner_uid: u32,
    system_uid: u32,
) -> Result<PendingCredentialStorage> {
    let service_uid = rustix::process::geteuid().as_raw();
    let configured = pending_configuration(root, owner_uid, system_uid)?;
    ensure!(
        configured.service_uid == service_uid,
        "pending service identity mismatch"
    );
    let var = directory(root, "var", system_uid, false)?;
    let lib = directory(&var, "lib", system_uid, false)?;
    let parent = directory(&lib, "ekubo-wallet", system_uid, false)?;
    let pending = directory(&parent, "pending", system_uid, false)?;
    let directory = Arc::new(directory(
        &pending,
        &configured.profile_id.to_string(),
        service_uid,
        true,
    )?);
    let lock = lock_profile(&directory, service_uid)?;
    Ok(PendingCredentialStorage(CredentialStagingRoot {
        directory,
        owner_uid,
        service_uid,
        profile_id: configured.profile_id,
        _lock: Some(lock),
    }))
}

fn pending_configuration(
    root: &File,
    owner_uid: u32,
    system_uid: u32,
) -> Result<OwnerConfiguration> {
    ensure!(
        find_owner_configuration(root, owner_uid, system_uid)?.is_none(),
        "pending bootstrap cannot replace an active service profile"
    );
    find_configuration_at(root, owner_uid, system_uid, "pending")?
        .context("pending service profile is missing")
}

impl crate::custody_staging::CredentialStagingStore for CredentialStagingRoot {
    fn identity(&self) -> (String, String, uuid::Uuid) {
        (
            format!("linux:uid:{}", self.owner_uid),
            format!("linux:uid:{}", self.service_uid),
            self.profile_id,
        )
    }
    fn create_new(
        &self,
        stage: uuid::Uuid,
        record: crate::custody_staging::StagedRecord,
        bytes: &[u8],
    ) -> Result<()> {
        ensure!(
            rustix::process::geteuid().as_raw() == self.service_uid,
            "service process identity changed"
        );
        publish_stage_record(
            &self.directory,
            self.service_uid,
            &record.file_name(stage)?,
            bytes,
        )
    }
    fn read(
        &self,
        stage: uuid::Uuid,
        record: crate::custody_staging::StagedRecord,
    ) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            rustix::process::geteuid().as_raw() == self.service_uid,
            "service process identity changed"
        );
        read_stage_record(&self.directory, self.service_uid, &record.file_name(stage)?)
    }
}

fn publish_stage_record(parent: &File, uid: u32, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 4096, "custody staging record is oversized");
    validate_directory(parent, uid, true)?;
    publish_private_record(parent, name, bytes)
}

fn read_stage_record(parent: &File, uid: u32, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    validate_directory(parent, uid, true)?;
    let file = open_regular(parent, name, uid, true)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "custody staging record is oversized");
    Ok(bytes)
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
        publish_private_record(&self.directory, &self.name, &sealed)
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

fn publish_private_record(parent: &File, name: &str, bytes: &[u8]) -> Result<()> {
    publish_private_with(parent, name, |file| Ok(file.write_all(bytes)?))
}

fn publish_private_with(
    parent: &File,
    name: &str,
    populate: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    let temporary = format!(".key-stage-{}", uuid::Uuid::new_v4());
    let mut file = File::from(openat(
        parent,
        &temporary,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(PRIVATE_FILE_MODE),
    )?);
    let result = (|| {
        populate(&mut file)?;
        file.sync_all()?;
        rustix::fs::renameat_with(parent, &temporary, parent, name, RenameFlags::NOREPLACE)?;
        parent.sync_all()?;
        Ok(())
    })();
    // If publication succeeded, this name no longer exists. If it failed,
    // remove only the exact temporary entry created by this operation.
    let _ = rustix::fs::unlinkat(parent, &temporary, AtFlags::empty());
    result
}

/// Pending storage cannot initialize active custody or owner/agent endpoints.
pub struct PendingCredentialStorage(CredentialStagingRoot);
impl crate::custody_staging::CredentialStagingStore for PendingCredentialStorage {
    fn identity(&self) -> (String, String, uuid::Uuid) {
        self.0.identity()
    }
    fn create_new(
        &self,
        stage: uuid::Uuid,
        record: crate::custody_staging::StagedRecord,
        bytes: &[u8],
    ) -> Result<()> {
        self.0.create_new(stage, record, bytes)
    }
    fn read(
        &self,
        stage: uuid::Uuid,
        record: crate::custody_staging::StagedRecord,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.0.read(stage, record)
    }
}
impl crate::database_staging::DatabaseStagingStore for PendingCredentialStorage {
    fn create_canonical_database(
        &self,
        stage: uuid::Uuid,
    ) -> Result<crate::database_staging::CanonicalDatabase<'_>> {
        self.validate_process()?;
        let destination = crate::database_staging::canonical_file_name(stage)?;
        let temporary = format!(".database-build-{}", uuid::Uuid::new_v4());
        let path = self.directory_path()?.join(&temporary);
        let parent: &File = &self.0.directory;
        let file = File::from(openat(
            parent,
            &temporary,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(PRIVATE_FILE_MODE),
        )?);
        let discarded = temporary.clone();
        let candidate = crate::database_staging::CanonicalDatabase::new(
            path,
            file,
            move |_, published| {
                rustix::fs::renameat_with(
                    parent,
                    &temporary,
                    parent,
                    &destination,
                    RenameFlags::NOREPLACE,
                )?;
                *published = true;
                parent.sync_all()?;
                Ok(())
            },
            move |_| {
                rustix::fs::unlinkat(parent, &discarded, AtFlags::empty())?;
                Ok(())
            },
            self,
        );
        validate_file(candidate.file(), self.0.service_uid, true)?;
        Ok(candidate)
    }
    fn canonical_database(
        &self,
        stage: uuid::Uuid,
    ) -> Result<crate::database_staging::StagedDatabase<'_>> {
        self.validate_process()?;
        let name = crate::database_staging::canonical_file_name(stage)?;
        let file = open_regular(&self.0.directory, &name, self.0.service_uid, true)?;
        Ok(crate::database_staging::StagedDatabase::new(
            self.directory_path()?.join(name),
            file,
            self,
        ))
    }

    fn receive_database(
        &self,
        stage: uuid::Uuid,
        transfer: &crate::database_staging::DatabaseTransfer,
        input: &mut dyn std::io::Read,
    ) -> Result<()> {
        self.validate_process()?;
        publish_private_with(
            &self.0.directory,
            &crate::database_staging::file_name(stage)?,
            |file| crate::database_staging::receive(transfer, input, file),
        )
    }
    fn open_staged_database(&self, stage: uuid::Uuid) -> Result<File> {
        self.validate_process()?;
        open_regular(
            &self.0.directory,
            &crate::database_staging::file_name(stage)?,
            self.0.service_uid,
            true,
        )
    }
    fn staged_database(
        &self,
        stage: uuid::Uuid,
    ) -> Result<crate::database_staging::StagedDatabase<'_>> {
        let file = self.open_staged_database(stage)?;
        // Resolve only our kernel-owned directory descriptor, never an IPC path.
        // Its root-owned parent prevents service/desktop renames; stage records
        // are immutable while this pending profile's singleton lock is held.
        let directory = self.directory_path()?;
        Ok(crate::database_staging::StagedDatabase::new(
            directory.join(crate::database_staging::file_name(stage)?),
            file,
            self,
        ))
    }
}
impl PendingCredentialStorage {
    fn directory_path(&self) -> Result<PathBuf> {
        use std::os::fd::AsRawFd as _;
        let path = std::fs::read_link(format!("/proc/self/fd/{}", self.0.directory.as_raw_fd()))?;
        ensure!(path.is_absolute(), "pending directory path is not absolute");
        Ok(path)
    }

    fn validate_process(&self) -> Result<()> {
        ensure!(
            rustix::process::geteuid().as_raw() == self.0.service_uid,
            "service process identity changed"
        );
        validate_directory(&self.0.directory, self.0.service_uid, true)
    }
}
