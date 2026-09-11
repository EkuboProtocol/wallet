//! Inspect the already-open object, never a second path lookup.
// Windows handle metadata and security descriptors require native FFI.
#![allow(unsafe_code)]

use super::{
    DatabaseFile, StorageKind, machine_path, validate_component, validate_directory_inheritance,
    validate_machine_security, validate_metadata, validate_security,
};
use crate::service_profile_lock::ProfileLock;
use crate::windows_service_config::InstalledServiceIdentity;
use anyhow::{Context as _, Result, ensure};
use std::{
    fs::File,
    mem::size_of,
    os::windows::io::{AsHandle as _, AsRawHandle as _, BorrowedHandle, FromRawHandle as _},
    path::{Path, PathBuf},
};
use windows::Win32::{
    Foundation::{
        HANDLE, HLOCAL, LocalFree, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING,
    },
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_TRAVERSE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
        GetFinalPathNameByHandleW, READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_GUID,
    },
    System::IO::IO_STATUS_BLOCK,
};
use windows::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
            FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
        },
    },
    core::PWSTR,
};

#[path = "windows_service_storage_write.rs"]
mod write;

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocates the owned descriptor with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

/// An existing installer-provisioned profile and every pinned ancestor. This
/// object starts locked; encrypted credential access requires its protected
/// enrollment to unlock. It grants no owner-operation authorization.
pub struct PrivateStorageRoot {
    directory: File,
    data_dir: PathBuf,
    _ancestors: Vec<File>,
    identity: InstalledServiceIdentity,
    _lock: ProfileLock,
    custody: crate::service_custody::ServiceCustody,
}

impl PrivateStorageRoot {
    /// The owner SID selects protected machine configuration. Actual service
    /// identity must match before any filesystem bootstrap occurs. No caller
    /// path, environment override, provisioning, or permission repair is used.
    pub fn open(owner_sid: &str) -> Result<Self> {
        let identity = crate::windows_service_config::service_identity(owner_sid)?;
        Self::open_identity(identity, "Owners")
    }

    fn open_identity(identity: InstalledServiceIdentity, collection: &str) -> Result<Self> {
        let trusted = crate::windows_service_config::machine_trustees()?;
        let mut ancestors = program_data_ancestors(&trusted)?;
        for component in ["EkuboWallet", collection] {
            let parent = ancestors.last().expect("drive root is pinned");
            let child = open_relative(parent.as_handle(), component, StorageKind::Directory)?;
            validate_machine_handle(child.as_handle(), &trusted, false)?;
            ancestors.push(child);
        }
        let parent = ancestors.last().expect("owners directory is pinned");
        let directory = open_relative(
            parent.as_handle(),
            &identity.profile_id().simple().to_string(),
            StorageKind::Directory,
        )?;
        validate_private_handle(directory.as_handle(), &identity, StorageKind::Directory)?;
        let lock_file = open_private_child(
            directory.as_handle(),
            "service.lock",
            &identity,
            StorageKind::File,
        )?;
        let lock = ProfileLock::acquire(lock_file)?;
        // Only now is every ancestor guaranteed to have a retained child.
        // Those child handles deny deletion, preventing the empty-directory
        // prerequisite for setting a reparse point via FILE_WRITE_ATTRIBUTES.
        // Reject any reparse point introduced during initial traversal. The
        // relative opens themselves also prohibit following reparse points.
        for ancestor in &ancestors {
            read_security(ancestor.as_handle(), StorageKind::Directory)?;
        }
        let data_dir = pinned_directory_path(directory.as_handle())?;
        Ok(Self {
            directory,
            data_dir,
            _ancestors: ancestors,
            identity,
            _lock: lock,
            custody: crate::service_custody::ServiceCustody::default(),
        })
    }

    /// OS-resolved volume path for this retained profile. Use only while the
    /// root remains alive; all ancestors are pinned against replacement.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn open_file(&self, component: &str) -> Result<File> {
        open_private_child(
            self.directory.as_handle(),
            component,
            &self.identity,
            StorageKind::File,
        )
    }

    /// Open the fixed `SQLCipher` database or its lock relative to this pinned
    /// profile. New files start private; existing files must already be safe.
    /// Keep the returned handle alive while SQLite uses its pathname so the
    /// database cannot be replaced. This does not open a SQLite connection.
    pub fn open_database_file(&self, file: DatabaseFile) -> Result<File> {
        crate::windows_service_identity::verify_service_process(self.identity.service_sid())?;
        validate_private_handle(
            self.directory.as_handle(),
            &self.identity,
            StorageKind::Directory,
        )?;
        write::open_database_file(
            self.directory.as_handle(),
            match file {
                DatabaseFile::Database => "wallet.db",
                DatabaseFile::Lock => "wallet.lock",
                DatabaseFile::ConfigurationLock => "config.lock",
                DatabaseFile::LifecycleLock => "lifecycle.lock",
            },
            self.identity.service_sid(),
            |file| validate_private_handle(file.as_handle(), &self.identity, StorageKind::File),
        )
    }

    /// The host authenticates the desktop peer before relaying its ciphertext.
    /// Bindings, enrollment, and wrapping material come only from this verified
    /// profile. Repeated unlock cannot replace an active cipher.
    pub fn unlock(&self, wrapped: &crate::custody_envelope::WrappedDataKey) -> Result<()> {
        self.custody.unlock(
            self.open_file("custody.json")?,
            self.open_file("wrapping.key")?,
            &format!("windows:sid:{}", self.identity.owner_sid()),
            &format!("windows:sid:{}", self.identity.service_sid()),
            self.identity.profile_id(),
            wrapped,
        )
    }

    /// Service-internal database credential. Never return this material in IPC.
    pub fn read_database_key(&self) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let cipher = self.custody.cipher()?;
        let sealed = self.read_encrypted_key("key-database")?;
        cipher.open_database_key(sealed.as_slice())
    }

    /// Service-internal account credential. Core's export and signing entry
    /// points must still enforce their normal owner/policy checks.
    pub fn read_account_key(&self, instance: uuid::Uuid) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        ensure!(!instance.is_nil(), "invalid wallet instance identifier");
        let cipher = self.custody.cipher()?;
        let sealed = self.read_encrypted_key(&format!("key-account-{instance}"))?;
        cipher.open_account_key(instance, sealed.as_slice())
    }

    fn read_encrypted_key(
        &self,
        component: &str,
    ) -> Result<zeroize::Zeroizing<[u8; crate::custody_envelope::SEALED_KEY_BYTES]>> {
        crate::service_custody::read_fixed(self.open_file(component)?)
    }

    /// Service-internal database-key creation. Only ciphertext is written, and
    /// an existing credential is never replaced, including corrupt plaintext.
    pub fn create_database_key(&self, material: &[u8; 32]) -> Result<()> {
        let sealed = self.custody.cipher()?.seal_database_key(material)?;
        self.create_encrypted_key("key-database", &sealed)
    }

    /// Account import/creation must already have passed core's owner checks.
    /// This protected storage capability only creates an immutable instance key;
    /// it does not add an account, change policy, or authorize signing.
    pub fn create_account_key(&self, instance: uuid::Uuid, material: &[u8; 32]) -> Result<()> {
        let sealed = self
            .custody
            .cipher()?
            .seal_account_key(instance, material)?;
        self.create_encrypted_key(&format!("key-account-{instance}"), &sealed)
    }

    /// Service-internal removal after core has authorized account lifecycle
    /// changes. Authenticate the exact encrypted object before deleting it.
    pub(crate) fn delete_key(&self, instance: Option<uuid::Uuid>) -> Result<()> {
        let cipher = self.custody.cipher()?;
        crate::windows_service_identity::verify_service_process(self.identity.service_sid())?;
        validate_private_handle(
            self.directory.as_handle(),
            &self.identity,
            StorageKind::Directory,
        )?;
        let name = instance.map_or_else(
            || "key-database".to_owned(),
            |id| format!("key-account-{id}"),
        );
        write::remove_credential(
            self.directory.as_handle(),
            &name,
            self.identity.service_sid(),
            |file| {
                validate_private_handle(file.as_handle(), &self.identity, StorageKind::File)?;
                let sealed = crate::service_custody::read_fixed::<
                    { crate::custody_envelope::SEALED_KEY_BYTES },
                >(file)?;
                let _material = match instance {
                    Some(id) => cipher.open_account_key(id, sealed.as_slice())?,
                    None => cipher.open_database_key(sealed.as_slice())?,
                };
                Ok(())
            },
        )
    }

    fn create_encrypted_key(
        &self,
        component: &str,
        sealed: &[u8; crate::custody_envelope::SEALED_KEY_BYTES],
    ) -> Result<()> {
        crate::windows_service_identity::verify_service_process(self.identity.service_sid())?;
        validate_private_handle(
            self.directory.as_handle(),
            &self.identity,
            StorageKind::Directory,
        )?;
        write::publish(
            &self.directory,
            component,
            self.identity.service_sid(),
            sealed,
            |file| validate_private_handle(file.as_handle(), &self.identity, StorageKind::File),
        )
    }
}

fn program_data_path() -> Result<String> {
    use windows::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    };
    struct PathText(PWSTR);
    impl Drop for PathText {
        fn drop(&mut self) {
            // SAFETY: SHGetKnownFolderPath allocates its path with CoTaskMemAlloc.
            unsafe { CoTaskMemFree(Some(self.0.0.cast())) };
        }
    }
    // SAFETY: fixed known-folder ID and current verified service process context.
    let folder = FOLDERID_ProgramData;
    let text = PathText(unsafe { SHGetKnownFolderPath(&raw const folder, KF_FLAG_DEFAULT, None) }?);
    // SAFETY: successful known-folder lookup returns a NUL-terminated allocation.
    Ok(unsafe { text.0.to_string() }?)
}

fn program_data_ancestors(trusted: &[String]) -> Result<Vec<File>> {
    use windows::{
        Win32::{Storage::FileSystem::GetDriveTypeW, System::WindowsProgramming::DRIVE_FIXED},
        core::PCWSTR,
    };
    let path = program_data_path()?;
    let (drive, components) = machine_path(&path)?;
    let drive_wide: Vec<u16> = drive.encode_utf16().chain(Some(0)).collect();
    // SAFETY: drive_wide is a live NUL-terminated absolute drive root.
    ensure!(
        unsafe { GetDriveTypeW(PCWSTR(drive_wide.as_ptr())) } == DRIVE_FIXED,
        "machine storage is not on a fixed local drive"
    );
    let root = open_native(None, &format!("\\??\\{drive}"), StorageKind::Directory)?;
    validate_machine_handle(root.as_handle(), trusted, true)
        .with_context(|| format!("unsafe machine storage drive root {drive}"))?;
    let mut ancestors = vec![root];
    for component in components {
        let parent = ancestors.last().expect("drive root is pinned");
        // machine_path validated this OS-provided component, including Unicode.
        let child = open_native(Some(parent.as_handle()), component, StorageKind::Directory)?;
        validate_machine_handle(child.as_handle(), trusted, true)
            .with_context(|| format!("unsafe machine storage ancestor {component} in {path}"))?;
        ancestors.push(child);
    }
    Ok(ancestors)
}

fn validate_machine_handle(
    handle: BorrowedHandle<'_>,
    trusted: &[String],
    shared_os_ancestor: bool,
) -> Result<()> {
    let (owner, entries) = read_security(handle, StorageKind::Directory)?;
    validate_machine_security(&owner, &entries, trusted, shared_os_ancestor)
}

/// Validate one object held open by the service. The caller must first traverse
/// protected ancestors without following reparse points and retain the handle
/// for subsequent I/O. This does not prove path provenance or authorize a read.
/// A handle opened after following a link cannot establish that the path was safe.
pub fn validate_private_handle(
    handle: BorrowedHandle<'_>,
    identity: &InstalledServiceIdentity,
    kind: StorageKind,
) -> Result<()> {
    validate_handle(handle, identity.service_sid(), kind)
}

/// Open an existing child for read-only I/O under a protected private directory.
/// The service must have established the root's protected path provenance and
/// retain its ancestor handles. No path supplied by an IPC request belongs here.
/// The exact returned handle is validated and must be used for subsequent I/O.
/// No file is created, repaired, truncated, or reopened by path.
pub fn open_private_child(
    parent: BorrowedHandle<'_>,
    component: &str,
    identity: &InstalledServiceIdentity,
    kind: StorageKind,
) -> Result<File> {
    crate::windows_service_identity::verify_service_process(identity.service_sid())?;
    validate_private_handle(parent, identity, StorageKind::Directory)?;
    let child = open_relative(parent, component, kind)?;
    validate_private_handle(child.as_handle(), identity, kind)?;
    Ok(child)
}

fn open_relative(parent: BorrowedHandle<'_>, component: &str, kind: StorageKind) -> Result<File> {
    validate_component(component)?;
    open_native(Some(parent), component, kind)
}

fn open_native(parent: Option<BorrowedHandle<'_>>, name: &str, kind: StorageKind) -> Result<File> {
    let mut wide_name: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(wide_name.len() * size_of::<u16>())?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: PWSTR(wide_name.as_mut_ptr()),
    };
    // The initial DOS drive lookup needs its OS object-manager mapping. Once
    // that root is pinned, never follow a reparse during a relative lookup,
    // including a parent changed by an attribute-only writer during traversal.
    let mut flags = OBJ_CASE_INSENSITIVE;
    if parent.is_some() {
        flags |= OBJ_DONT_REPARSE;
    }
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())?,
        RootDirectory: parent.map_or(HANDLE::default(), |parent| HANDLE(parent.as_raw_handle())),
        ObjectName: &raw const name,
        Attributes: flags,
        ..Default::default()
    };
    let (access, file_type) = match kind {
        StorageKind::Directory => (
            READ_CONTROL | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
            FILE_DIRECTORY_FILE,
        ),
        StorageKind::File => (FILE_GENERIC_READ, FILE_NON_DIRECTORY_FILE),
    };
    let mut handle = HANDLE::default();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: parent and every pointer-backed argument remain live through
    // this synchronous open. Callers supply either a validated component or a
    // validated local drive root. FILE_OPEN never creates or
    // truncates; FILE_OPEN_REPARSE_POINT opens the link itself for rejection.
    unsafe {
        NtCreateFile(
            &raw mut handle,
            access,
            &raw const attributes,
            &raw mut status,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OPEN,
            file_type | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        )
    }
    .ok()?;
    ensure!(
        !handle.is_invalid(),
        "private storage open returned an invalid handle"
    );
    // SAFETY: NtCreateFile returned a new owned synchronous file handle; no
    // other guard owns it. File closes it on every subsequent error path.
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

fn pinned_directory_path(handle: BorrowedHandle<'_>) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: the handle and the writable buffer remain live for this query.
    // Use the volume GUID, not a drive-letter mapping or an NT device path
    // which SQLite would interpret as a relative Windows path.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            HANDLE(handle.as_raw_handle()),
            &mut buffer,
            VOLUME_NAME_GUID,
        )
    };
    if length == 0 {
        return Err(std::io::Error::last_os_error()).context("cannot resolve pinned profile path");
    }
    let length = usize::try_from(length)?;
    ensure!(length < buffer.len(), "pinned profile path is too long");
    let path = String::from_utf16(&buffer[..length])?;
    ensure!(
        path.starts_with(r"\\?\Volume{"),
        "profile has no local volume GUID path"
    );
    Ok(PathBuf::from(path))
}

fn validate_handle(handle: BorrowedHandle<'_>, service_sid: &str, kind: StorageKind) -> Result<()> {
    let (owner, entries) = read_security(handle, kind)?;
    validate_security(&owner, &entries, service_sid)?;
    if matches!(kind, StorageKind::Directory) {
        validate_directory_inheritance(&entries, service_sid)?;
    }
    Ok(())
}

fn read_security(
    handle: BorrowedHandle<'_>,
    kind: StorageKind,
) -> Result<(String, Vec<crate::windows_security::AccessEntry>)> {
    let handle = HANDLE(handle.as_raw_handle());
    // SAFETY: BorrowedHandle guarantees a live handle for the entire call.
    ensure!(
        unsafe { GetFileType(handle) } == FILE_TYPE_DISK,
        "private storage is not a disk object"
    );
    let mut metadata = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is live and metadata points to writable initialized storage.
    unsafe { GetFileInformationByHandle(handle, &raw mut metadata) }?;
    validate_metadata(metadata.dwFileAttributes, metadata.nNumberOfLinks, kind)?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the handle is live and the descriptor output is writable. No
    // borrowed pointers escape the Descriptor guard below.
    unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    }
    .ok()?;
    let descriptor = Descriptor(descriptor);
    // SAFETY: GetSecurityInfo returned a complete live OS-allocated descriptor.
    unsafe { crate::windows_security::read_descriptor(descriptor.0) }
}

#[cfg(test)]
#[path = "windows_service_storage_native_test.rs"]
mod tests;

impl crate::custody_staging::CredentialStagingStore for PrivateStorageRoot {
    fn identity(&self) -> (String, String, uuid::Uuid) {
        (
            format!("windows:sid:{}", self.identity.owner_sid()),
            format!("windows:sid:{}", self.identity.service_sid()),
            self.identity.profile_id(),
        )
    }
    fn create_new(
        &self,
        stage: uuid::Uuid,
        record: crate::custody_staging::StagedRecord,
        bytes: &[u8],
    ) -> Result<()> {
        crate::windows_service_identity::verify_service_process(self.identity.service_sid())?;
        validate_private_handle(
            self.directory.as_handle(),
            &self.identity,
            StorageKind::Directory,
        )?;
        write::publish(
            &self.directory,
            &record.file_name(stage)?,
            self.identity.service_sid(),
            bytes,
            |file| validate_private_handle(file.as_handle(), &self.identity, StorageKind::File),
        )
    }
    fn read(
        &self,
        stage: uuid::Uuid,
        record: crate::custody_staging::StagedRecord,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        use std::io::Read as _;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        self.open_file(&record.file_name(stage)?)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4096, "custody staging record is oversized");
        Ok(bytes)
    }
}

/// Pending storage exposes credential staging only. It cannot be used as a
/// desktop installed identity, active custody backend, or owner authorization.
pub struct PendingCredentialStorage(PrivateStorageRoot);
impl PendingCredentialStorage {
    pub fn open(owner_sid: &str) -> Result<Self> {
        let identity = crate::windows_service_config::pending_service_identity(owner_sid)?;
        Ok(Self(PrivateStorageRoot::open_identity(
            identity, "Pending",
        )?))
    }
}
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
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.0.read(stage, record)
    }
}

impl crate::database_staging::DatabaseStagingStore for PendingCredentialStorage {
    fn receive_database(
        &self,
        stage: uuid::Uuid,
        transfer: &crate::database_staging::DatabaseTransfer,
        input: &mut dyn std::io::Read,
    ) -> Result<()> {
        crate::windows_service_identity::verify_service_process(self.0.identity.service_sid())?;
        validate_private_handle(
            self.0.directory.as_handle(),
            &self.0.identity,
            StorageKind::Directory,
        )?;
        write::publish_with(
            &self.0.directory,
            &crate::database_staging::file_name(stage)?,
            self.0.identity.service_sid(),
            |file| validate_private_handle(file.as_handle(), &self.0.identity, StorageKind::File),
            |file| crate::database_staging::receive(transfer, input, file),
        )
    }
    fn staged_database(
        &self,
        stage: uuid::Uuid,
    ) -> Result<crate::database_staging::StagedDatabase<'_>> {
        let file = self.open_staged_database(stage)?;
        Ok(crate::database_staging::StagedDatabase::new(
            self.0
                .data_dir
                .join(crate::database_staging::file_name(stage)?),
            file,
            self,
        ))
    }
    fn open_staged_database(&self, stage: uuid::Uuid) -> Result<File> {
        self.0
            .open_file(&crate::database_staging::file_name(stage)?)
    }
}
