//! Inspect the already-open object, never a second path lookup.
// Windows handle metadata and security descriptors require native FFI.
#![allow(unsafe_code)]

use super::{StorageKind, validate_metadata, validate_security};
use crate::windows_service_config::InstalledServiceIdentity;
use anyhow::{Result, ensure};
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};
use windows::Win32::{
    Foundation::{HANDLE, HLOCAL, LocalFree},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
    },
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
