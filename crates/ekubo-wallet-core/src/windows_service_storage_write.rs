//! Immutable credential publication under a pinned Windows service directory.
//! The parent module establishes service identity and validates the root before
//! entering here. Neither temporary nor destination names come from IPC.

use super::*;
use std::io::Write as _;
use windows::{
    Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0, FILE_WRITE_THROUGH,
        FileRenameInformation, NtSetInformationFile,
    },
    Win32::{
        Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        },
        Storage::FileSystem::{
            DELETE, FILE_DISPOSITION_INFO, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
            FileDispositionInfo, SetFileInformationByHandle,
        },
    },
    core::PCWSTR,
};

pub(super) fn publish(
    parent: &File,
    destination: &str,
    owner_sid: &str,
    sealed: &[u8; crate::custody_envelope::SEALED_KEY_BYTES],
    validate: impl FnOnce(&File) -> Result<()>,
) -> Result<()> {
    validate_component(destination)?;
    let temporary = format!(".key-stage-{}", uuid::Uuid::new_v4());
    let mut file = create(parent.as_handle(), &temporary, owner_sid)?;
    let mut published = false;
    let result = (|| {
        validate(&file)?;
        file.write_all(sealed)?;
        file.sync_all()?;
        rename_new(&file, parent.as_handle(), destination)?;
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
    let sddl: Vec<u16> = format!("O:{owner_sid}D:P(A;;FA;;;{owner_sid})(A;;FA;;;SY)")
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

fn create(parent: BorrowedHandle<'_>, component: &str, owner_sid: &str) -> Result<File> {
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
    // FILE_CREATE cannot open or truncate a preexisting name. A protected DACL
    // is applied at creation, before bytes exist. No sharing is granted.
    unsafe {
        NtCreateFile(
            &raw mut handle,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            &raw const attributes,
            &raw mut status,
            None,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_MODE(0),
            FILE_CREATE,
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

fn rename_new(file: &File, parent: BorrowedHandle<'_>, destination: &str) -> Result<()> {
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
            RootDirectory: HANDLE(parent.as_raw_handle()),
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
    // SAFETY: the aligned structure and both handles remain live. A simple
    // relative name resolves under the pinned parent; replacement is disabled.
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

fn discard(file: &File) -> Result<()> {
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
