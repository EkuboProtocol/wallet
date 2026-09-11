//! Administrative checkpoint publication; no service-custody authorization.
use super::*;
use crate::installer_checkpoint::{Destination, RecoveryCheckpoint};
use crate::windows_security::AccessEntry;
use std::io::Read as _;

const ADMINISTRATORS: &str = "S-1-5-32-544";

/// Publish immutable evidence under the fixed machine pending directory. Actual
/// elevated installer identity is required. No relay or key belongs in this file.
pub fn save_checkpoint(owner_sid: &str, checkpoint: &RecoveryCheckpoint) -> Result<()> {
    let (ancestors, destination) = journal_parent(owner_sid)?;
    let parent = ancestors.last().context("journal parent is missing")?;
    let bytes = checkpoint.journal_bytes(&destination)?;
    if let Some(existing) = read(parent, &destination)? {
        ensure!(
            existing.journal_bytes(&destination)? == bytes,
            "installer checkpoint conflicts with existing evidence"
        );
        return Ok(());
    }
    write::publish(
        parent,
        &name(&destination),
        ADMINISTRATORS,
        &bytes,
        |file| validate_journal(file.as_handle()),
    )?;
    let stored = read(parent, &destination)?.context("published checkpoint is missing")?;
    ensure!(
        stored.journal_bytes(&destination)? == bytes,
        "installer checkpoint readback mismatch"
    );
    Ok(())
}

/// Load bounded evidence for the protected pending identity. Absence never
/// authorizes stage deletion, activation, or fallback from an active profile.
pub fn load_checkpoint(owner_sid: &str) -> Result<Option<RecoveryCheckpoint>> {
    let (ancestors, destination) = journal_parent(owner_sid)?;
    read(
        ancestors.last().context("journal parent is missing")?,
        &destination,
    )
}

fn journal_parent(owner_sid: &str) -> Result<(Vec<File>, Destination)> {
    let identity = crate::windows_service_config::pending_installer_identity(owner_sid)?;
    let trusted = crate::windows_service_config::machine_trustees()?;
    let mut ancestors = program_data_ancestors(&trusted)?;
    for component in ["EkuboWallet", "Pending"] {
        let parent = ancestors.last().context("machine parent is missing")?;
        let child = open_relative(parent.as_handle(), component, StorageKind::Directory)?;
        validate_machine_handle(child.as_handle(), &trusted, false)?;
        ancestors.push(child);
    }
    Ok((
        ancestors,
        Destination {
            owner: format!("windows:sid:{}", identity.owner_sid()),
            service: format!("windows:sid:{}", identity.service_sid()),
            profile: identity.profile_id(),
        },
    ))
}

fn name(destination: &Destination) -> String {
    format!("{}.checkpoint.json", destination.profile.simple())
}

fn validate_journal(handle: BorrowedHandle<'_>) -> Result<()> {
    // read_security validates regular file type, reparse attributes and link count.
    let (owner, entries) = read_security(handle, StorageKind::File)?;
    validate_journal_entries(&owner, &entries)
}

fn validate_journal_entries(owner: &str, entries: &[AccessEntry]) -> Result<()> {
    ensure!(
        owner == ADMINISTRATORS,
        "installer checkpoint has an unexpected owner"
    );
    for entry in entries {
        match entry {
            AccessEntry::Allow { sid, mask, .. } => ensure!(
                *mask == 0 || sid == ADMINISTRATORS || sid == "S-1-5-18",
                "installer checkpoint grants access to an untrusted principal"
            ),
            AccessEntry::Deny => {}
            AccessEntry::Unsupported => {
                anyhow::bail!("installer checkpoint uses an unsupported access entry")
            }
        }
    }
    Ok(())
}

fn read(parent: &File, destination: &Destination) -> Result<Option<RecoveryCheckpoint>> {
    let file = match open_native_access(
        Some(parent.as_handle()),
        &name(destination),
        StorageKind::File,
        true,
    ) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<windows::core::Error>()
                .is_some_and(|error| {
                    error.code()
                        == windows::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND.to_hresult()
                }) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    validate_journal(file.as_handle())?;
    ensure!(
        file.metadata()?.len() <= 4096,
        "installer checkpoint is oversized"
    );
    let mut bytes = Vec::new();
    (&file).take(4097).read_to_end(&mut bytes)?;
    let checkpoint = RecoveryCheckpoint::from_journal(&bytes, destination)?;
    // This exact handle was opened for write as well as read so Windows can
    // flush it. No path reopen, truncation or checkpoint mutation occurs.
    file.sync_all()?;
    Ok(Some(checkpoint))
}

#[cfg(test)]
#[path = "windows_installer_journal_test.rs"]
mod tests;
