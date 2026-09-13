//! Windows file identity proof for a legacy read-only pin.
#![allow(unsafe_code)]
use anyhow::{Result, ensure};
use std::{fs::File, os::windows::io::AsRawHandle as _};
use windows::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
};

pub(super) fn publish(
    source: &std::path::Path,
    destination: &std::path::Path,
    replace: bool,
) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows::{
        Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        },
        core::PCWSTR,
    };
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let flags = if replace {
        MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING
    } else {
        MOVEFILE_WRITE_THROUGH
    };
    // Both NUL-terminated buffers live through the call; no source handles remain.
    unsafe { MoveFileExW(PCWSTR(source.as_ptr()), PCWSTR(destination.as_ptr()), flags) }?;
    Ok(())
}

pub(super) fn identity(file: &File) -> Result<(u32, u64)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // The File owns a live handle and info is a correctly sized writable output.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut info) }?;
    ensure!(
        info.dwFileAttributes & 0x400 == 0 && info.nNumberOfLinks == 1,
        "legacy file is a reparse point or hard link"
    );
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}
