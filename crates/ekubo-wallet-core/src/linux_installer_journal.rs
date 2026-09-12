//! Root-owned pending checkpoint, separate from custody and login relay storage.
use super::*;
use crate::migration_transfer::{Destination, RecoveryCheckpoint, TransferIntent};

/// Serializes privileged installer operations across profiles. The file is a
/// permanent rendezvous point, never a PID record to remove after a crash.
/// Holding this guard does not establish source validity or authorize cutover.
pub struct InstallerLease {
    _lock: ProfileLock,
    _parent: File,
}

/// Verified pending files with the service's singleton lock retained. This is
/// not activation authority: the live source and durable decision remain separate.
pub struct QuiescentProfile<'a> {
    _installer: &'a InstallerLease,
    _lock: ProfileLock,
    _directory: File,
    _parent: File,
    configured: OwnerConfiguration,
    checkpoint: RecoveryCheckpoint,
}

impl QuiescentProfile<'_> {
    /// Record the durable decision while retaining installer and service locks.
    /// The coordinator must separately retain/revalidate the live source. This
    /// blocks legacy fallback; it neither promotes files nor permits deletion.
    pub fn begin_cutover(&self) -> Result<()> {
        require_installer()?;
        self.require_checkpoint(
            &load_checkpoint(self.configured.owner_uid)?
                .context("cutover checkpoint is missing")?,
        )?;
        record_cutover_under(&root_directory()?, &self.configured, 0)
    }

    pub(crate) fn require_checkpoint(&self, checkpoint: &RecoveryCheckpoint) -> Result<()> {
        ensure!(
            self.checkpoint
                .journal_bytes(&self.checkpoint.destination)?
                == checkpoint.journal_bytes(&self.checkpoint.destination)?,
            "quiescent profile checkpoint changed"
        );
        Ok(())
    }
}

pub(crate) fn require_uncommitted(owner_uid: u32) -> Result<()> {
    require_installer()?;
    super::require_uncommitted(&root_directory()?, owner_uid, 0)
}

impl InstallerLease {
    pub fn verify_prepared(&self, owner_uid: u32) -> Result<QuiescentProfile<'_>> {
        use std::os::fd::AsRawFd as _;
        require_installer()?;
        let root = root_directory()?;
        let configured = pending_configuration(&root, owner_uid, 0)?;
        let checkpoint =
            load_checkpoint(owner_uid)?.context("prepared verification requires a checkpoint")?;
        let mut parent = directory(&root, "var", 0, false)?;
        for component in ["lib", "ekubo-wallet", "pending"] {
            parent = directory(&parent, component, 0, false)?;
        }
        let directory = directory(
            &parent,
            &configured.profile_id.to_string(),
            configured.service_uid,
            true,
        )?;
        // Never create a missing service lock: this must be an existing prepared
        // profile. A running/cooperating service prevents verification here.
        let lock = ProfileLock::acquire(open_regular(
            &directory,
            "service.lock",
            configured.service_uid,
            true,
        )?)?;
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))?;
        let accounts =
            crate::migration_ready::account_instances(entries.map(|entry| Ok(entry?.file_name())))?;
        crate::migration_ready::verify_ready(&checkpoint, &accounts, |name| {
            open_regular(&directory, name, configured.service_uid, true)
        })?;
        Ok(QuiescentProfile {
            _installer: self,
            _lock: lock,
            _directory: directory,
            _parent: parent,
            configured,
            checkpoint,
        })
    }
}

fn record_cutover_under(
    root: &File,
    configured: &OwnerConfiguration,
    system_uid: u32,
) -> Result<()> {
    ensure!(
        pending_configuration(root, configured.owner_uid, system_uid)? == *configured,
        "cutover pending identity changed"
    );
    let etc = directory(root, "etc", system_uid, false)?;
    let wallet = directory(&etc, "ekubo-wallet", system_uid, false)?;
    match rustix::fs::mkdirat(&wallet, "committed", Mode::from_raw_mode(0o755)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let parent = directory(&wallet, "committed", system_uid, false)?;
    let name = format!("{}.json", configured.owner_uid);
    let bytes = serde_json::to_vec(configured)?;
    let existing = open_optional(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
    )?;
    if let Some(file) = existing {
        validate_file(&file, system_uid, false)?;
        let mut stored = Vec::new();
        (&file)
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut stored)?;
        ensure!(
            stored == bytes,
            "cutover decision conflicts with existing evidence"
        );
        file.sync_all()?;
        parent.sync_all()?;
    } else {
        publish_private_with(&parent, &name, |file| {
            rustix::fs::fchmod(&*file, Mode::from_raw_mode(0o644))?;
            std::io::Write::write_all(file, &bytes)?;
            Ok(())
        })?;
    }
    wallet.sync_all()?;
    ensure!(
        find_configuration_at(root, configured.owner_uid, system_uid, "committed")?
            == Some(configured.clone()),
        "cutover decision readback mismatch"
    );
    Ok(())
}

pub fn acquire_installer() -> Result<InstallerLease> {
    require_installer()?;
    acquire_under(&root_directory()?, 0)
}

fn acquire_under(root: &File, system_uid: u32) -> Result<InstallerLease> {
    let mut parent = directory(root, "etc", system_uid, false)?;
    for component in ["ekubo-wallet", "pending"] {
        parent = directory(&parent, component, system_uid, false)?;
    }
    let file = File::from(openat(
        &parent,
        "installer.lock",
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_raw_mode(PRIVATE_FILE_MODE),
    )?);
    validate_file(&file, system_uid, true)?;
    ensure!(file.metadata()?.len() == 0, "installer lock is not empty");
    let lock = ProfileLock::acquire(file).context("another wallet installer may be running")?;
    parent.sync_all()?;
    Ok(InstallerLease {
        _lock: lock,
        _parent: parent,
    })
}

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
