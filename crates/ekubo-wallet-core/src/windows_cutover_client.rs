//! Reconnect to a committed source without restarting the pending service.
use super::{Result, SourceStream, migration_transfer, provisioning_io, windows_service_config};
use std::io::Write as _;

/// Retains the refrozen owner source and installer exclusion. Confirmation is
/// temporary, not activation or cleanup authority; drop aborts retention.
pub struct RecoveredCutover {
    _source: SourceStream,
    _cancel: provisioning_io::CancelTransfer,
    installer: crate::windows_service_storage::installer_journal::InstallerLease,
    checkpoint: migration_transfer::RecoveryCheckpoint,
    owner: String,
}

impl RecoveredCutover {
    pub fn verify_prepared(
        &self,
    ) -> Result<crate::windows_service_storage::installer_journal::QuiescentProfile<'_>> {
        let prepared = self.installer.verify_prepared(&self.owner)?;
        prepared.require_checkpoint(&self.checkpoint)?;
        Ok(prepared)
    }
    #[must_use]
    pub const fn checkpoint(&self) -> &migration_transfer::RecoveryCheckpoint {
        &self.checkpoint
    }
}

/// Requires actual installer authority, an existing committed decision, and its
/// protected checkpoint. No caller checkpoint, source path, key, or relay is accepted.
pub async fn recover_cutover_from_owner(
    owner: &str,
    endpoint: uuid::Uuid,
) -> Result<RecoveredCutover> {
    let installer = crate::windows_service_storage::installer_journal::acquire_installer()?;
    let identity = windows_service_config::committed_installer_identity(owner)?;
    let checkpoint = crate::windows_service_storage::installer_journal::load_checkpoint(owner)?
        .ok_or_else(|| anyhow::anyhow!("committed source checkpoint is missing"))?;
    let pipe = crate::windows_relay_pipe::connect_source(&identity, endpoint).await?;
    let (mut source, cancel) = provisioning_io::bridge(pipe, migration_transfer::INSTALLER_TIMEOUT);
    let owner = owner.to_owned();
    // Keep cancellation in the awaiting task; the worker holds both locks until
    // native I/O actually finishes, including when that task is cancelled.
    let (source, installer, checkpoint, owner) = tokio::task::spawn_blocking(move || {
        let prepared = installer.verify_prepared(&owner)?;
        prepared.require_checkpoint(&checkpoint)?;
        windows_service_config::committed_installer_identity(&owner)?;
        source.write_all(crate::windows_relay_pipe::SOURCE_PREFACE)?;
        crate::migration_source::request_cutover(&mut source, &checkpoint)?;
        drop(prepared);
        Ok::<_, anyhow::Error>((source, installer, checkpoint, owner))
    })
    .await??;
    Ok(RecoveredCutover {
        _source: source,
        _cancel: cancel,
        installer,
        checkpoint,
        owner,
    })
}
