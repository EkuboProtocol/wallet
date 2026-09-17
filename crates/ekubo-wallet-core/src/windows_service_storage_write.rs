//! Immutable credential publication under a pinned Windows service directory.
//! The parent module establishes service identity and validates the root before
//! entering here. Neither temporary nor destination names come from IPC.

use super::*;
use std::io::Write as _;
use windows::{
    Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_OPEN_IF, FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0,
        FILE_WRITE_THROUGH, FileRenameInformation, NtSetInformationFile,
    },
    Win32::{
        Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        },
        Storage::FileSystem::{
            DELETE, FILE_DISPOSITION_INFO, FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_WRITE,
            FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_WRITE, FileDispositionInfo, ReOpenFile,
            SetFileInformationByHandle,
        },
    },
    core::PCWSTR,
};

pub(super) fn publish(
    parent: &File,
    destination: &str,
    owner_sid: &str,
    sealed: &[u8],
    validate: impl FnOnce(&File) -> Result<()>,
) -> Result<()> {
    ensure!(sealed.len() <= 4096, "private publication is oversized");
    publish_with(parent, destination, owner_sid, validate, |file| {
        Ok(file.write_all(sealed)?)
    })
}

pub(super) fn publish_with(
    parent: &File,
    destination: &str,
    owner_sid: &str,
    validate: impl FnOnce(&File) -> Result<()>,
    populate: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
    validate_component(destination)?;
    let temporary = format!(".key-stage-{}", uuid::Uuid::new_v4());
    let mut file = create(parent.as_handle(), &temporary, owner_sid)
        .context("cannot create encrypted credential temporary file")?;
    let mut published = false;
    let result = (|| {
        validate(&file)?;
        populate(&mut file)?;
        file.sync_all()?;
        rename_new(&file, destination).context("cannot publish encrypted credential name")?;
        published = true;
        // Flush again after publication. If this fails, report ambiguity: the
        // key may already be committed and must be read back, never overwritten.
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() && !published {
        discard(&file).context("cannot remove unpublished encrypted credential")?;
    }
    result
}

fn descriptor(owner_sid: &str) -> Result<Descriptor> {
    // Identity comes from protected configuration. Validate the alphabet too,
    // so even internal misuse cannot inject another SDDL clause.
    ensure!(
        owner_sid.starts_with("S-1-")
            && owner_sid.len() <= 184
            && owner_sid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'S' | b'-')),
        "invalid private file owner SID"
    );
    // An elevated installer must be able to verify prepared service records
    // after stopping the service. Administrators are already trusted machine
    // principals; grant read only, and only for virtual-service-owned records.
    // Ordinary/filtered tokens do not gain a grant for their user SID here.
    let installer = if crate::windows_service_identity::is_virtual_service_sid(owner_sid) {
        "(A;;GR;;;BA)"
    } else {
        ""
    };
    let sddl: Vec<u16> = format!("O:{owner_sid}D:P(A;;FA;;;{owner_sid})(A;;FA;;;SY){installer}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: a validated SID is embedded in a fixed SDDL template; the input
    // is NUL terminated and the output is owned by the LocalFree guard.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }?;
    Ok(Descriptor(descriptor))
}

// Keep immutable credential publication exclusive. Database and lock handles
// must permit SQLite/other service connections to write. Temporary database
// build pins additionally share deletion for later same-object publication.
#[derive(Clone, Copy)]
enum OpenMode {
    NewCredential,
    DatabaseBuild,
    DeleteCredential,
    Database,
}

fn create(parent: BorrowedHandle<'_>, component: &str, owner_sid: &str) -> Result<File> {
    open_handle(parent, component, owner_sid, OpenMode::NewCredential)
}

pub(super) fn create_database_stage(
    parent: BorrowedHandle<'_>,
    component: &str,
    owner_sid: &str,
) -> Result<File> {
    open_handle(parent, component, owner_sid, OpenMode::DatabaseBuild)
}

// Acquire DELETE access to the same pinned object only after SQLite closes.
// The build pin shares deletion, but requests no DELETE access itself, allowing
// SQLite's ordinary READ|WRITE sharing mode. Private ACLs and the pending root's
// singleton lock prevent outside writers from renaming the temporary name.
pub(super) fn database_publication_handle(file: &File) -> Result<File> {
    // SAFETY: the original file stays live. ReOpenFile addresses its object,
    // never a pathname; OS sharing checks reject any remaining SQLite handle.
    let handle = unsafe {
        ReOpenFile(
            HANDLE(file.as_raw_handle()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_WRITE_THROUGH,
        )
    }?;
    ensure!(
        !handle.is_invalid(),
        "database reopen returned an invalid handle"
    );
    // SAFETY: transfer ownership of the newly opened handle exactly once.
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

pub(super) fn open_database_file(
    parent: BorrowedHandle<'_>,
    component: &str,
    owner_sid: &str,
    validate: impl FnOnce(&File) -> Result<()>,
) -> Result<File> {
    ensure!(
        matches!(
            component,
            "wallet.db" | "wallet.lock" | "config.lock" | "lifecycle.lock"
        ),
        "invalid database file name"
    );
    let file = open_handle(parent, component, owner_sid, OpenMode::Database)?;
    // FILE_OPEN_IF never truncates or repairs existing state. Validate its
    // actual handle before exposing write access to the rest of core.
    validate(&file)?;
    Ok(file)
}

/// Fixed administrative rendezvous file. `FILE_OPEN_IF` never truncates/repairs an
/// existing object; the installer validates its actual owner/DACL before locking.
pub(super) fn open_installer_lock(parent: BorrowedHandle<'_>, owner: &str) -> Result<File> {
    open_handle(parent, "installer.lock", owner, OpenMode::Database)
}

pub(super) fn remove_credential(
    parent: BorrowedHandle<'_>,
    component: &str,
    owner_sid: &str,
    validate: impl FnOnce(&File) -> Result<()>,
) -> Result<()> {
    let file = open_handle(parent, component, owner_sid, OpenMode::DeleteCredential)?;
    validate(&file)?;
    discard(&file)
}

fn open_handle(
    parent: BorrowedHandle<'_>,
    component: &str,
    owner_sid: &str,
    mode: OpenMode,
) -> Result<File> {
    validate_component(component)?;
    let descriptor = descriptor(owner_sid)?;
    let mut wide: Vec<u16> = component.encode_utf16().collect();
    let length = u16::try_from(wide.len() * size_of::<u16>())?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: PWSTR(wide.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())?,
        RootDirectory: HANDLE(parent.as_raw_handle()),
        ObjectName: &raw const name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: descriptor.0.0.cast(),
        ..Default::default()
    };
    let mut handle = HANDLE::default();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: all input allocations and the borrowed parent outlive the call.
    // No mode truncates an existing file. A protected DACL is applied on
    // creation, before bytes exist. Database mode validates existing objects
    // before returning; deletion also validates its exclusive handle before use.
    unsafe {
        NtCreateFile(
            &raw mut handle,
            match mode {
                OpenMode::NewCredential => FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                OpenMode::DeleteCredential => FILE_GENERIC_READ | DELETE,
                OpenMode::Database | OpenMode::DatabaseBuild => {
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE
                }
            },
            &raw const attributes,
            &raw mut status,
            None,
            FILE_ATTRIBUTE_NORMAL,
            match mode {
                OpenMode::NewCredential | OpenMode::DeleteCredential => FILE_SHARE_MODE(0),
                OpenMode::Database => FILE_SHARE_READ | FILE_SHARE_WRITE,
                OpenMode::DatabaseBuild => FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            },
            match mode {
                OpenMode::NewCredential | OpenMode::DatabaseBuild => FILE_CREATE,
                OpenMode::DeleteCredential => FILE_OPEN,
                OpenMode::Database => FILE_OPEN_IF,
            },
            FILE_NON_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_WRITE_THROUGH,
            None,
            0,
        )
    }
    .ok()?;
    ensure!(
        !handle.is_invalid(),
        "private creation returned an invalid handle"
    );
    // SAFETY: ownership of the successful native handle is transferred to File.
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

pub(super) fn rename_new(file: &File, destination: &str) -> Result<()> {
    // repr(C) preserves the native header's alignment and flexible-name offset.
    // Our validated names fit this fixed allocation; no unaligned cast is used.
    #[repr(C)]
    struct Rename {
        info: FILE_RENAME_INFORMATION,
        tail: [u16; 128],
    }
    validate_component(destination)?;
    let name: Vec<u16> = destination.encode_utf16().collect();
    let mut rename = Rename {
        info: FILE_RENAME_INFORMATION {
            Anonymous: FILE_RENAME_INFORMATION_0 {
                ReplaceIfExists: false,
            },
            // A simple name with NULL RootDirectory renames inside the source
            // file's existing directory. Supplying its parent handle instead
            // makes Windows reopen a write handle to that directory, which
            // conflicts with our deliberate no-write-sharing ancestor pins.
            RootDirectory: HANDLE::default(),
            FileNameLength: u32::try_from(name.len() * 2)?,
            ..Default::default()
        },
        tail: [0; 128],
    };
    // SAFETY: the enclosing repr(C) allocation has room for 129 UTF-16 units
    // starting at FileName (including the native header's possible tail padding).
    // validate_component limits input to at most 128 ASCII bytes.
    unsafe {
        let output = (&raw mut rename)
            .cast::<u16>()
            .add(std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName) / size_of::<u16>());
        std::ptr::copy_nonoverlapping(name.as_ptr(), output, name.len());
    }
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: the aligned structure and source handle remain live. The name is
    // a validated single component, so NULL RootDirectory uses the file's own
    // directory, never cwd. Its parent is pinned and private; replacement and
    // cross-directory moves are disabled.
    unsafe {
        NtSetInformationFile(
            HANDLE(file.as_raw_handle()),
            &raw mut status,
            (&raw const rename).cast(),
            u32::try_from(size_of::<Rename>())?,
            FileRenameInformation,
        )
    }
    .ok()?;
    Ok(())
}

pub(super) fn discard(file: &File) -> Result<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the owned handle has DELETE access; only this open object is
    // marked for deletion. No path is reopened and no replacement is followed.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>())?,
        )
    }?;
    Ok(())
}

#[cfg(test)]
#[path = "windows_service_storage_write_test.rs"]
mod tests;
