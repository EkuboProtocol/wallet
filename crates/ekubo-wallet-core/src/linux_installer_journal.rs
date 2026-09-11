//! Root-owned pending checkpoint, separate from custody and login relay storage.
use super::*;
use crate::migration_transfer::{Destination, RecoveryCheckpoint, TransferIntent};

/// Record an attempt before forwarding its header or keys. Existing conflicting
/// intent requires explicit recovery/abort; it is never overwritten here.
pub fn save_intent(owner_uid: u32, intent: &TransferIntent) -> Result<()> {
    require_installer()?;
    save_intent_under(&root_directory()?, owner_uid, 0, intent)
}

pub fn load_intent(owner_uid: u32) -> Result<Option<TransferIntent>> {
    require_installer()?;
    let (parent, destination) = journal_parent(&root_directory()?, owner_uid, 0)?;
    read_intent(&parent, owner_uid, 0, &destination)
}

/// Persist immutable recovery evidence for the currently configured pending
/// profile. Requires the actual privileged installer; never activates a profile.
pub fn save_checkpoint(owner_uid: u32, checkpoint: &RecoveryCheckpoint) -> Result<()> {
    require_installer()?;
    save_under(&root_directory()?, owner_uid, 0, checkpoint)
}

/// Load bounded recovery evidence from the fixed root-owned pending directory.
/// Absence means no checkpoint, not permission to discard or activate a stage.
pub fn load_checkpoint(owner_uid: u32) -> Result<Option<RecoveryCheckpoint>> {
    require_installer()?;
    let (parent, destination) = journal_parent(&root_directory()?, owner_uid, 0)?;
    read(&parent, owner_uid, 0, &destination)
}

fn require_installer() -> Result<()> {
    ensure!(
        rustix::process::getuid().as_raw() == 0 && rustix::process::geteuid().as_raw() == 0,
        "checkpoint access requires the privileged installer"
    );
    Ok(())
}

fn journal_parent(root: &File, owner: u32, system_uid: u32) -> Result<(File, Destination)> {
    let configured = pending_configuration(root, owner, system_uid)?;
    let mut parent = directory(root, "etc", system_uid, false)?;
    for component in ["ekubo-wallet", "pending"] {
        parent = directory(&parent, component, system_uid, false)?;
    }
    Ok((
        parent,
        Destination {
            owner: format!("linux:uid:{}", configured.owner_uid),
            service: format!("linux:uid:{}", configured.service_uid),
            profile: configured.profile_id,
        },
    ))
}

fn read(
    parent: &File,
    owner: u32,
    system_uid: u32,
    destination: &Destination,
) -> Result<Option<RecoveryCheckpoint>> {
    let checkpoint = read_record(parent, &format!("{owner}.checkpoint.json"), system_uid)?
        .map(|bytes| RecoveryCheckpoint::from_journal(&bytes, destination))
        .transpose()?;
    if let (Some(checkpoint), Some(intent)) = (
        &checkpoint,
        read_intent(parent, owner, system_uid, destination)?,
    ) {
        intent.validate_checkpoint(checkpoint)?;
    }
    Ok(checkpoint)
}

fn read_intent(
    parent: &File,
    owner: u32,
    system_uid: u32,
    destination: &Destination,
) -> Result<Option<TransferIntent>> {
    read_record(parent, &format!("{owner}.intent.json"), system_uid)?
        .map(|bytes| TransferIntent::from_journal(&bytes, destination))
        .transpose()
}

fn read_record(parent: &File, name: &str, system_uid: u32) -> Result<Option<Vec<u8>>> {
    let Some(file) = open_optional(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
    )?
    else {
        return Ok(None);
    };
    validate_file(&file, system_uid, true)?;
    ensure!(
        file.metadata()?.len() <= MAX_CONFIG_BYTES,
        "installer checkpoint is oversized"
    );
    let mut bytes = Vec::new();
    (&file).take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    // A retry after interrupted publication also completes the durability work.
    file.sync_all()?;
    parent.sync_all()?;
    Ok(Some(bytes))
}

fn save_under(
    root: &File,
    owner: u32,
    system_uid: u32,
    checkpoint: &RecoveryCheckpoint,
) -> Result<()> {
    let (parent, destination) = journal_parent(root, owner, system_uid)?;
    let bytes = checkpoint.journal_bytes(&destination)?;
    if let Some(intent) = read_intent(&parent, owner, system_uid, &destination)? {
        intent.validate_checkpoint(checkpoint)?;
    }
    save_record(
        &parent,
        &format!("{owner}.checkpoint.json"),
        system_uid,
        &bytes,
    )
}

fn save_intent_under(
    root: &File,
    owner: u32,
    system_uid: u32,
    intent: &TransferIntent,
) -> Result<()> {
    let (parent, destination) = journal_parent(root, owner, system_uid)?;
    let bytes = intent.journal_bytes(&destination)?;
    if let Some(checkpoint) = read(&parent, owner, system_uid, &destination)? {
        intent.validate_checkpoint(&checkpoint)?;
    }
    save_record(&parent, &format!("{owner}.intent.json"), system_uid, &bytes)
}

fn save_record(parent: &File, name: &str, system_uid: u32, bytes: &[u8]) -> Result<()> {
    if let Some(existing) = read_record(parent, name, system_uid)? {
        ensure!(
            existing == bytes,
            "installer checkpoint conflicts with existing evidence"
        );
        return Ok(());
    }
    publish_private_record(parent, name, bytes)?;
    let stored =
        read_record(parent, name, system_uid)?.context("published checkpoint is missing")?;
    ensure!(stored == bytes, "installer checkpoint readback mismatch");
    Ok(())
}

#[cfg(test)]
#[path = "linux_installer_journal_test.rs"]
mod tests;
