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

/// Successful staging keeps the source fence and exact service connection alive
/// through the installer's later commit/abort. Keep the source lifecycle lock
/// alive too. Dropping this object aborts retention; it cannot undo staged files.
/// No method authorizes activation or deletion of legacy credentials.
pub struct StagedSource {
    _snapshot: MigrationDatabaseSnapshot,
    _bus: Connection,
    reply: StagingReply,
}

impl StagedSource {
    #[must_use]
    pub const fn reply(&self) -> &StagingReply {
        &self.reply
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
    let identity = service_storage::pending_installer_identity(owner_uid)?;
    let bus = tokio::time::timeout(Duration::from_secs(10), async {
        zbus::connection::Builder::unix_stream(service_storage::system_bus_stream().await?)
            .build()
            .await
            .map_err(anyhow::Error::from)
    })
    .await
    .context("provisioning bus connection timed out")??;
    let result = exchange(&bus, &identity, database_key, expected, accounts, snapshot).await;
    match result {
        Ok((snapshot, reply)) => Ok(StagedSource {
            _snapshot: snapshot,
            _bus: bus,
            reply,
        }),
        Err(error) => {
            let _ = bus.close().await;
            Err(error)
        }
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

async fn exchange(
    bus: &Connection,
    identity: &PendingInstallerIdentity,
    database_key: Zeroizing<[u8; 32]>,
    expected: Vec<WalletMetadata>,
    accounts: Vec<MigrationAccount>,
    mut snapshot: MigrationDatabaseSnapshot,
) -> Result<(MigrationDatabaseSnapshot, StagingReply)> {
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
    let destination = Destination {
        owner: format!("linux:uid:{}", identity.owner_uid()),
        service: format!("linux:uid:{}", identity.service_uid()),
        profile: identity.profile_id(),
    };
    let worker = tokio::task::spawn_blocking(move || {
        let session = migration_transfer::send(
            &mut stream,
            destination,
            database_key,
            &expected,
            accounts,
            &mut snapshot,
            migration_transfer::INSTALLER_LIMITS,
        )?;
        let reply = migration_transfer::read_reply(&mut stream, session)?;
        Ok::<_, anyhow::Error>((snapshot, reply))
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
    // shuts the shared socket; the worker retains the source fence until exit.
    tokio::select! {
        result = async { let (transfer, ()) = tokio::try_join!(async { worker.await? }, call)?; Ok(transfer) } => result,
        _ = departed.next() => Err(anyhow::anyhow!("pending service disconnected")),
        () = bus.closed() => Err(anyhow::anyhow!("provisioning bus disconnected")),
        () = tokio::time::sleep(migration_transfer::INSTALLER_TIMEOUT) => Err(anyhow::anyhow!("provisioning timed out")),
    }
}

#[cfg(test)]
#[path = "linux_provisioning_client_test.rs"]
mod tests;
