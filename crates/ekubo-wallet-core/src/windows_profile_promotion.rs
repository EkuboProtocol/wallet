//! Privileged no-replace move between pinned, protected machine directories.
//! Profile handles are retired before the move; installer exclusion survives it.
use super::super::{
    StorageKind, open_native_shared, pinned_directory_path, read_security, validate_component,
    validate_machine_handle,
};
use super::{QuiescentProfile, load_checkpoint};
use crate::migration_ready::Location;
use anyhow::{Context as _, Result, ensure};
use std::{
    fs::File,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt as _,
        io::{AsHandle as _, AsRawHandle as _},
    },
    path::Path,
};
use windows::{
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            FILE_ID_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo,
            GetFileInformationByHandleEx, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        },
    },
    core::PCWSTR,
};

pub(super) fn promote(profile: QuiescentProfile<'_>) -> Result<QuiescentProfile<'_>> {
    let identity = crate::windows_service_config::committed_installer_identity(&profile.owner_sid)?;
    ensure!(
        profile.location == Location::Pending
            && identity.profile_id() == profile.checkpoint.destination.profile,
        "promotion requires the committed pending profile"
    );
    profile.require_checkpoint(
        &load_checkpoint(&profile.owner_sid)?.context("promotion checkpoint is missing")?,
    )?;
    let QuiescentProfile {
        _installer: installer,
        _lock: lock,
        _directory: directory,
        _ancestors: ancestors,
        owner_sid,
        checkpoint: _,
        location: _,
    } = profile;
    let wallet = ancestors
        .get(
            ancestors
                .len()
                .checked_sub(2)
                .context("missing wallet ancestor")?,
        )
        .context("missing wallet ancestor")?;
    let parent = ancestors.last().context("missing pending ancestor")?;
    let trusted = crate::windows_service_config::machine_trustees()?;
    // Only this wallet-owned parent allows write sharing, needed by the move's
    // target open. Its checked ACL disallows all untrusted mutation; deletion
    // sharing stays disabled. Broader OS ancestors retain their original pins.
    let target = open_native_shared(
        Some(wallet.as_handle()),
        "Owners",
        StorageKind::Directory,
        false,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?;
    validate_machine_handle(target.as_handle(), &trusted, false)?;
    let original = file_id(&directory)?;
    let name = identity.profile_id().simple().to_string();
    drop(directory);
    drop(lock);
    move_new(parent, &name, &target, &name)?;
    for ancestor in &ancestors {
        read_security(ancestor.as_handle(), StorageKind::Directory)?;
    }
    read_security(target.as_handle(), StorageKind::Directory)?;
    let promoted = installer.verify_promoted(&owner_sid)?;
    let QuiescentProfile {
        _directory: directory,
        ..
    } = &promoted;
    ensure!(
        file_id(directory)? == original,
        "promoted directory identity changed"
    );
    Ok(promoted)
}

fn file_id(file: &File) -> Result<(u64, [u8; 16])> {
    let mut information = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&raw mut information).cast(),
            u32::try_from(size_of::<FILE_ID_INFO>())?,
        )
    }?;
    Ok((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}

fn path_wide(path: &Path) -> Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    ensure!(
        !value.contains(&0) && value.len() < 32_767,
        "invalid promotion path"
    );
    value.push(0);
    Ok(value)
}

fn move_new(source: &File, source_name: &str, target: &File, target_name: &str) -> Result<()> {
    validate_component(source_name)?;
    validate_component(target_name)?;
    ensure!(
        file_id(source)?.0 == file_id(target)?.0,
        "promotion cannot cross volumes"
    );
    // Only kernel-resolved volume GUID paths under retained protected parents.
    // No environment, drive-letter mapping, caller path, replacement, copy/delete
    // fallback, or reboot scheduling is accepted. Failure remains recoverable.
    let source_path = path_wide(&pinned_directory_path(source.as_handle())?.join(source_name))?;
    let target_path = path_wide(&pinned_directory_path(target.as_handle())?.join(target_name))?;
    unsafe {
        MoveFileExW(
            PCWSTR(source_path.as_ptr()),
            PCWSTR(target_path.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }?;
    Ok(())
}

#[cfg(test)]
#[path = "windows_profile_promotion_test.rs"]
mod tests;
