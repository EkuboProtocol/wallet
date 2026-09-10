//! Inspect the already-open object, never a second path lookup.
// Windows handle metadata and security descriptors require native FFI.
#![allow(unsafe_code)]

use super::{StorageKind, validate_component, validate_metadata, validate_security};
use crate::windows_service_config::InstalledServiceIdentity;
use anyhow::{Result, ensure};
use std::{
    fs::File,
    mem::size_of,
    os::windows::io::{AsHandle as _, AsRawHandle as _, BorrowedHandle, FromRawHandle as _},
};
use windows::Win32::{
    Foundation::{HANDLE, HLOCAL, LocalFree, OBJ_CASE_INSENSITIVE, UNICODE_STRING},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_TRAVERSE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
        READ_CONTROL, SYNCHRONIZE,
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

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: GetSecurityInfo allocates the owned descriptor with LocalAlloc.
        unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
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
    let mut wide_name: Vec<u16> = component.encode_utf16().collect();
    let length = u16::try_from(wide_name.len() * size_of::<u16>())?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: PWSTR(wide_name.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())?,
        RootDirectory: HANDLE(parent.as_raw_handle()),
        ObjectName: &raw const name,
        Attributes: OBJ_CASE_INSENSITIVE,
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
    // this synchronous open. The single validated component cannot escape the
    // parent or select an alternate data stream. FILE_OPEN never creates or
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

fn validate_handle(handle: BorrowedHandle<'_>, service_sid: &str, kind: StorageKind) -> Result<()> {
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
    let (owner, entries) = unsafe { crate::windows_security::read_descriptor(descriptor.0) }?;
    validate_security(&owner, &entries, service_sid)
}

#[cfg(test)]
#[path = "windows_service_storage_native_test.rs"]
mod tests;
