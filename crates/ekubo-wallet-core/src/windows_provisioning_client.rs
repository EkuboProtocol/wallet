//! Privileged Windows installer transfer. No elevation, credential lookup,
//! service activation, or legacy deletion occurs here.
use crate::{
    config::WalletMetadata,
    custody_provisioning::MigrationAccount,
    migration_transfer::{self, Destination, StagingReply},
    policy_store::migration_database::MigrationDatabaseSnapshot,
    provisioning_io, windows_provisioning_pipe, windows_service_config,
};
use anyhow::{Result, ensure};
use std::io::Write as _;
use zeroize::Zeroizing;

/// Retains the source database fence through the installer's later commit/abort.
/// The caller must retain its lifecycle lock too. A staging reply grants no
/// activation or legacy deletion authority and is not a durable commit receipt.
pub struct StagedSource {
    snapshot: MigrationDatabaseSnapshot,
    reply: StagingReply,
    destination: Destination,
    checkpoint: Option<migration_transfer::RecoveryCheckpoint>,
}

impl StagedSource {
    /// Capture journal evidence while retaining the source fence. The caller
    /// must durably persist it in protected storage and the relay separately.
    pub fn checkpoint(&mut self) -> Result<migration_transfer::RecoveryCheckpoint> {
        if let Some(checkpoint) = &self.checkpoint {
            return Ok(checkpoint.clone());
        }
        let checkpoint = migration_transfer::RecoveryCheckpoint::capture(
            self.destination.clone(),
            &self.reply,
            &mut self.snapshot,
        )?;
        self.checkpoint = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    #[must_use]
    pub const fn reply(&self) -> &StagingReply {
        &self.reply
    }

    /// Explicitly reconnect and revalidate this same stage without releasing the
    /// source fence. Keep the caller's lifecycle lock held too. Failure aborts
    /// retention; it never activates custody or retries the original transfer.
    pub async fn recover(self, owner_sid: &str, expected: Vec<WalletMetadata>) -> Result<Self> {
        let identity = windows_service_config::pending_installer_identity(owner_sid)?;
        ensure!(
            destination(&identity) == self.destination,
            "pending recovery profile changed"
        );
        let (mut source, reply) = exchange(&identity, self, move |stream, destination, source| {
            if let Some(checkpoint) = &source.checkpoint {
                return checkpoint.exchange(
                    stream,
                    destination,
                    &source.snapshot,
                    source.reply.relay().clone(),
                    &expected,
                );
            }
            migration_transfer::recover_exchange(
                stream,
                destination,
                &source.reply,
                &mut source.snapshot,
                &expected,
            )
        })
        .await?;
        source.reply = reply;
        Ok(source)
    }
}

fn destination(identity: &windows_service_config::PendingInstallerIdentity) -> Destination {
    Destination {
        owner: format!("windows:sid:{}", identity.owner_sid()),
        service: format!("windows:sid:{}", identity.service_sid()),
        profile: identity.profile_id(),
    }
}

/// Transfer keys already supplied to the privileged installer. Protected
/// pending metadata and the connected native pipe are checked before writing
/// even the nonsecret preface. Errors never reconnect or replay the transfer.
pub async fn transfer(
    owner_sid: &str,
    database_key: Zeroizing<[u8; 32]>,
    expected: Vec<WalletMetadata>,
    accounts: Vec<MigrationAccount>,
    snapshot: MigrationDatabaseSnapshot,
) -> Result<StagedSource> {
    let identity = windows_service_config::pending_installer_identity(owner_sid)?;
    let destination = destination(&identity);
    let (snapshot, reply) = exchange(&identity, snapshot, move |stream, destination, snapshot| {
        let session = migration_transfer::send(
            stream,
            destination,
            database_key,
            &expected,
            accounts,
            snapshot,
            migration_transfer::INSTALLER_LIMITS,
        )?;
        migration_transfer::read_reply(stream, session)
    })
    .await?;
    Ok(StagedSource {
        snapshot,
        reply,
        destination,
        checkpoint: None,
    })
}

/// Resume from protected journal evidence after re-quiescing and freezing the
/// legacy source. The caller retains lifecycle exclusion through commit/abort.
/// The relay must come from the actual owner's separate login credential store.
pub async fn resume(
    owner_sid: &str,
    checkpoint: migration_transfer::RecoveryCheckpoint,
    snapshot: MigrationDatabaseSnapshot,
    relay: crate::custody_envelope::WrappedDataKey,
    expected: Vec<WalletMetadata>,
) -> Result<StagedSource> {
    let identity = windows_service_config::pending_installer_identity(owner_sid)?;
    let destination = destination(&identity);
    let evidence = checkpoint.clone();
    let (snapshot, reply) = exchange(&identity, snapshot, move |stream, destination, snapshot| {
        checkpoint.exchange(stream, destination, snapshot, relay, &expected)
    })
    .await?;
    Ok(StagedSource {
        snapshot,
        reply,
        destination,
        checkpoint: Some(evidence),
    })
}

type InstallerStream = tokio_util::io::SyncIoBridge<
    provisioning_io::DeadlineStream<tokio::net::windows::named_pipe::NamedPipeClient>,
>;

// Match Linux's source-state retention contract. This private transport helper
// does not collect credentials or expose a writer to presentation/MCP callers.
async fn exchange<S: Send + 'static>(
    identity: &windows_service_config::PendingInstallerIdentity,
    mut source: S,
    operation: impl FnOnce(&mut InstallerStream, Destination, &mut S) -> Result<StagingReply>
    + Send
    + 'static,
) -> Result<(S, StagingReply)> {
    let pipe = windows_provisioning_pipe::connect(identity).await?;
    let destination = destination(identity);
    let (mut stream, _cancel) =
        provisioning_io::bridge(pipe, migration_transfer::INSTALLER_TIMEOUT);
    // Cancellation stays with the awaiting task. Source state remains with the
    // blocking worker until its native I/O exits, even if the task is dropped.
    tokio::task::spawn_blocking(move || {
        stream.write_all(windows_provisioning_pipe::PREFACE)?;
        let reply = operation(&mut stream, destination, &mut source)?;
        Ok((source, reply))
    })
    .await?
}
