//! Privileged installer client for the pending Linux service. No keyring lookup,
//! elevation, service activation or legacy deletion happens in this module.
use crate::{
    config::WalletMetadata,
    custody_provisioning::MigrationAccount,
    linux_provisioning_io::InstallerStream,
    migration_transfer::{self, Destination, StagingReply},
    policy_store::migration_database::MigrationDatabaseSnapshot,
    service_storage::{self, PendingInstallerIdentity},
};
use anyhow::{Context as _, Result, ensure};
use futures::StreamExt as _;
use std::time::Duration;
use zbus::{Connection, fdo::DBusProxy, names::OwnedUniqueName};
use zeroize::Zeroizing;

/// A staged remote source, with its authenticated owner stream retained. The
/// source fence is temporary and may be lost on disconnect/deadline: this type
/// deliberately has no activation method. Drop aborts retention, not staging.
pub struct ForwardedSource {
    _owner: crate::linux_source_handoff::OwnerChannel,
    _cancel: crate::linux_provisioning_io::CancelStream,
    _service: Connection,
    reply: StagingReply,
    checkpoint: migration_transfer::RecoveryCheckpoint,
}
impl ForwardedSource {
    #[must_use]
    pub const fn reply(&self) -> &StagingReply {
        &self.reply
    }
    #[must_use]
    pub const fn checkpoint(&self) -> &migration_transfer::RecoveryCheckpoint {
        &self.checkpoint
    }
}

/// Root installer staging from the exact owner endpoint learned during launch.
/// Both peers and protected pending metadata are checked before forwarding keys.
/// No source path, raw key or generic writer is accepted or exposed by this API.
/// Intent is persisted before forwarding; a completed checkpoint is persisted
/// before returning. Neither record authorizes activation or an automatic replay.
pub async fn forward_from_owner(
    owner_uid: u32,
    recipient: OwnedUniqueName,
) -> Result<ForwardedSource> {
    handoff_from_owner(owner_uid, recipient, None).await
}

/// Recover only the completed checkpoint in protected installer storage. The
/// owner refreezes its existing source and supplies its separately stored relay.
/// Missing/incomplete evidence fails; this never retries a transfer or activates.
pub async fn recover_from_owner(
    owner_uid: u32,
    recipient: OwnedUniqueName,
) -> Result<ForwardedSource> {
    let checkpoint = service_storage::installer_journal::load_checkpoint(owner_uid)?
        .context("source recovery requires a completed installer checkpoint")?;
    handoff_from_owner(owner_uid, recipient, Some(checkpoint)).await
}

async fn handoff_from_owner(
    owner_uid: u32,
    recipient: OwnedUniqueName,
    previous: Option<migration_transfer::RecoveryCheckpoint>,
) -> Result<ForwardedSource> {
    let (identity, bus) = connect(owner_uid).await?;
    let (owner, cancel) = crate::linux_source_handoff::connect(owner_uid, recipient).await?;
    let result = exchange(
        &bus,
        &identity,
        (owner, None),
        move |stream, destination, source| {
            crate::migration_source::request(&mut source.0.stream, previous.as_ref())?;
            let request = if let Some(checkpoint) = &previous {
                migration_transfer::relay_recovery_request(
                    &mut source.0.stream,
                    stream,
                    &destination,
                    checkpoint,
                    migration_transfer::INSTALLER_LIMITS,
                )?
            } else {
                migration_transfer::relay_request_with_intent(
                    &mut source.0.stream,
                    stream,
                    &destination,
                    migration_transfer::INSTALLER_LIMITS,
                    |intent| service_storage::installer_journal::save_intent(owner_uid, intent),
                )?
            };
            let (reply, checkpoint) = request.finish(stream, &mut source.0.stream)?;
            if let Some(previous) = &previous {
                ensure!(
                    checkpoint.journal_bytes(&destination)?
                        == previous.journal_bytes(&destination)?,
                    "owner recovery checkpoint changed"
                );
            }
            service_storage::installer_journal::save_checkpoint(owner_uid, &checkpoint)?;
            source.1 = Some(checkpoint);
            Ok(reply)
        },
    )
    .await;
    match result {
        Ok(((owner, checkpoint), reply)) => Ok(ForwardedSource {
            _owner: owner,
            _cancel: cancel,
            _service: bus,
            reply,
            checkpoint: checkpoint.context("source checkpoint is missing")?,
        }),
        Err(error) => {
            let _ = bus.close().await;
            Err(error)
        }
    }
}

/// Successful staging keeps the source fence and exact service connection alive
/// through the installer's later commit/abort. Keep the source lifecycle lock
/// alive too. Dropping this object aborts retention; it cannot undo staged files.
/// No method authorizes activation or deletion of legacy credentials.
pub struct StagedSource {
    snapshot: MigrationDatabaseSnapshot,
    _bus: Connection,
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

    /// Explicitly reconnect to the same protected profile while retaining the
    /// source fence. The caller retains its lifecycle lock. This does not replay
    /// the transfer, activate custody or recover an installer-crash journal.
    pub async fn recover(self, owner_uid: u32, expected: Vec<WalletMetadata>) -> Result<Self> {
        let (identity, bus) = connect(owner_uid).await?;
        let destination = destination(&identity);
        if destination != self.destination {
            let _ = bus.close().await;
            anyhow::bail!("pending recovery profile changed");
        }
        let Self {
            snapshot,
            _bus: old_bus,
            reply: previous,
            checkpoint,
            ..
        } = self;
        let recovery_checkpoint = checkpoint.clone();
        let result = exchange(
            &bus,
            &identity,
            snapshot,
            move |stream, destination, snapshot| {
                if let Some(checkpoint) = recovery_checkpoint {
                    return checkpoint.exchange(
                        stream,
                        destination,
                        snapshot,
                        previous.relay().clone(),
                        &expected,
                    );
                }
                migration_transfer::recover_exchange(
                    stream,
                    destination,
                    &previous,
                    snapshot,
                    &expected,
                )
            },
        )
        .await;
        let _ = old_bus.close().await;
        match result {
            Ok((snapshot, reply)) => Ok(Self {
                snapshot,
                _bus: bus,
                reply,
                destination,
                checkpoint,
            }),
            Err(error) => {
                let _ = bus.close().await;
                Err(error)
            }
        }
    }
}

/// Transfer only keys already supplied to the privileged installer. Authenticate
/// protected pending metadata and the real system-bus recipient before any key
/// write. The owner UID identifies an installer-selected profile, not authority
/// to elevate an ordinary process. Failures never reconnect or replay a transfer.
pub async fn transfer(
    owner_uid: u32,
    database_key: Zeroizing<[u8; 32]>,
    expected: Vec<WalletMetadata>,
    accounts: Vec<MigrationAccount>,
    snapshot: MigrationDatabaseSnapshot,
) -> Result<StagedSource> {
    let (identity, bus) = connect(owner_uid).await?;
    let destination = destination(&identity);
    let result = exchange(
        &bus,
        &identity,
        snapshot,
        move |stream, destination, snapshot| {
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
        },
    )
    .await;
    match result {
        Ok((snapshot, reply)) => Ok(StagedSource {
            snapshot,
            _bus: bus,
            reply,
            destination,
            checkpoint: None,
        }),
        Err(error) => {
            let _ = bus.close().await;
            Err(error)
        }
    }
}

async fn connect(owner_uid: u32) -> Result<(PendingInstallerIdentity, Connection)> {
    let identity = service_storage::pending_installer_identity(owner_uid)?;
    let bus = tokio::time::timeout(Duration::from_secs(10), async {
        zbus::connection::Builder::unix_stream(service_storage::system_bus_stream().await?)
            .build()
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    .context("provisioning bus connection timed out")??;
    Ok((identity, bus))
}

fn destination(identity: &PendingInstallerIdentity) -> Destination {
    Destination {
        owner: format!("linux:uid:{}", identity.owner_uid()),
        service: format!("linux:uid:{}", identity.service_uid()),
        profile: identity.profile_id(),
    }
}

async fn authenticate(
    registry: &DBusProxy<'_>,
    name: &str,
    expected_uid: u32,
) -> Result<OwnedUniqueName> {
    let service = registry.get_name_owner(name.try_into()?).await?;
    ensure!(
        registry
            .get_connection_unix_user(service.clone().into())
            .await?
            == expected_uid,
        "pending endpoint does not belong to the configured service"
    );
    ensure!(
        registry
            .get_connection_unix_process_id(service.clone().into())
            .await?
            != 0,
        "pending endpoint has no live service process"
    );
    Ok(service)
}

// Transport retains the supplied source state without requiring a database
// snapshot in this process. The local-source adapters above supply a snapshot;
// an owner-channel adapter must instead retain its authenticated connection.
async fn exchange<S: Send + 'static>(
    bus: &Connection,
    identity: &PendingInstallerIdentity,
    mut source: S,
    operation: impl FnOnce(&mut InstallerStream, Destination, &mut S) -> Result<StagingReply>
    + Send
    + 'static,
) -> Result<(S, StagingReply)> {
    let registry = DBusProxy::new(bus).await?;
    let name = format!("org.ekubo.Wallet.Provision.u{}", identity.owner_uid());
    // Resolve exactly once. Calls address the authenticated unique owner, not
    // the replaceable well-known name; no activation/reconnection is attempted.
    let service = tokio::time::timeout(
        Duration::from_secs(10),
        authenticate(&registry, &name, identity.service_uid()),
    )
    .await??;
    let mut departed = tokio::time::timeout(
        Duration::from_secs(10),
        registry.receive_name_owner_changed_with_args(&[(0, service.as_str())]),
    )
    .await??;
    // Recheck that exact unique owner after installing the disconnection watch.
    let checked = tokio::time::timeout(
        Duration::from_secs(10),
        authenticate(&registry, service.as_str(), identity.service_uid()),
    )
    .await??;
    ensure!(checked == service, "pending service identity changed");
    let (mut stream, remote, _cancel) =
        InstallerStream::pair(migration_transfer::INSTALLER_TIMEOUT)?;
    let remote = zbus::zvariant::OwnedFd::from(remote);
    let destination = destination(identity);
    let worker = tokio::task::spawn_blocking(move || {
        let reply = operation(&mut stream, destination, &mut source)?;
        Ok::<_, anyhow::Error>((source, reply))
    });
    let call = async {
        let reply = bus
            .call_method(
                Some(service.as_str()),
                "/org/ekubo/Wallet/Provision",
                Some("org.ekubo.Wallet.Provision1"),
                "Transfer",
                &(remote,),
            )
            .await?;
        ensure!(
            reply.header().sender() == Some(service.inner()),
            "provisioning reply provenance changed"
        );
        reply.body().deserialize::<()>()?;
        Ok::<_, anyhow::Error>(())
    };
    // The method completes only after stream exchange. Run both concurrently;
    // awaiting the method before sending data would deadlock. Cancellation
    // shuts the shared socket; the worker retains the source state until exit.
    tokio::select! {
        result = async { let (transfer, ()) = tokio::try_join!(async { worker.await? }, call)?; Ok(transfer) } => result,
        _ = departed.next() => Err(anyhow::anyhow!("pending service disconnected")),
        () = bus.closed() => Err(anyhow::anyhow!("provisioning bus disconnected")),
        () = tokio::time::sleep(migration_transfer::INSTALLER_TIMEOUT) => Err(anyhow::anyhow!("provisioning timed out")),
    }
}

/// Resume from protected journal evidence after re-quiescing and freezing the
/// legacy source. The caller retains lifecycle exclusion through commit/abort.
/// The relay must come from the actual owner's separate login credential store.
pub async fn resume(
    owner_uid: u32,
    checkpoint: migration_transfer::RecoveryCheckpoint,
    snapshot: MigrationDatabaseSnapshot,
    relay: crate::custody_envelope::WrappedDataKey,
    expected: Vec<WalletMetadata>,
) -> Result<StagedSource> {
    let (identity, bus) = connect(owner_uid).await?;
    let destination = destination(&identity);
    let evidence = checkpoint.clone();
    let result = exchange(
        &bus,
        &identity,
        snapshot,
        move |stream, destination, snapshot| {
            evidence.exchange(stream, destination, snapshot, relay, &expected)
        },
    )
    .await;
    match result {
        Ok((snapshot, reply)) => Ok(StagedSource {
            snapshot,
            _bus: bus,
            reply,
            destination,
            checkpoint: Some(checkpoint),
        }),
        Err(error) => {
            let _ = bus.close().await;
            Err(error)
        }
    }
}

#[cfg(test)]
#[path = "linux_provisioning_client_test.rs"]
mod tests;
