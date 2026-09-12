//! Reconnect to a committed source without restarting the pending service.
use super::{OwnedUniqueName, Result, migration_transfer, service_storage};

/// Retains the refrozen owner source and installer exclusion. Confirmation is
/// temporary, not activation or cleanup authority; drop aborts retention.
pub struct RecoveredCutover {
    _source: crate::linux_source_handoff::OwnerChannel,
    _cancel: crate::linux_provisioning_io::CancelStream,
    installer: service_storage::installer_journal::InstallerLease,
    checkpoint: migration_transfer::RecoveryCheckpoint,
    owner: u32,
}

impl RecoveredCutover {
    pub fn verify_prepared(
        &self,
    ) -> Result<service_storage::installer_journal::QuiescentProfile<'_>> {
        let prepared = self.installer.verify_prepared(self.owner)?;
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
    owner: u32,
    endpoint: OwnedUniqueName,
) -> Result<RecoveredCutover> {
    let installer = service_storage::installer_journal::acquire_installer()?;
    service_storage::committed_installer_identity(owner)?;
    let checkpoint = service_storage::installer_journal::load_checkpoint(owner)?
        .ok_or_else(|| anyhow::anyhow!("committed source checkpoint is missing"))?;
    let (mut source, cancel) = crate::linux_source_handoff::connect(owner, endpoint).await?;
    // Keep cancellation in the awaiting task; the worker holds both locks until
    // native I/O actually finishes, including when that task is cancelled.
    let (source, installer, checkpoint, owner) = tokio::task::spawn_blocking(move || {
        let prepared = installer.verify_prepared(owner)?;
        prepared.require_checkpoint(&checkpoint)?;
        service_storage::committed_installer_identity(owner)?;

        crate::migration_source::request_cutover(&mut source.stream, &checkpoint)?;
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
