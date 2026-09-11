//! Installer-only pending host. No authority, owner RPC, scheduler or MCP starts.
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::{migration_transfer, service_storage};
use futures::StreamExt as _;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use zbus::{Connection, fdo::DBusProxy, message::Header, zvariant::OwnedFd};

#[path = "linux_provisioning_io.rs"]
mod io;

const OBJECT_PATH: &str = "/org/ekubo/Wallet/Provision";

pub async fn run(owner_uid: u32) -> Result<()> {
    // Actual service UID, root-owned pending metadata, private storage and
    // profile lock are checked before advertising any provisioning endpoint.
    let pending = service_storage::pending_credential_staging_root(owner_uid)?;
    let bus = zbus::connection::Builder::unix_stream(service_storage::system_bus_stream().await?)
        .name(format!("org.ekubo.Wallet.Provision.u{owner_uid}"))?
        .serve_at(
            OBJECT_PATH,
            ProvisioningInterface {
                pending: Arc::new(Mutex::new(pending)),
            },
        )?
        .build()
        .await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = tokio::select! {
        () = bus.closed() => Err(anyhow::anyhow!("provisioning system bus disconnected")),
        _ = terminate.recv() => Ok(()),
        signal = tokio::signal::ctrl_c() => signal.map_err(anyhow::Error::from),
    };
    bus.close().await?;
    result
}

struct ProvisioningInterface {
    pending: Arc<Mutex<service_storage::PendingCredentialStorage>>,
}

#[zbus::interface(name = "org.ekubo.Wallet.Provision1")]
impl ProvisioningInterface {
    /// The installer creates a socketpair, retains one end and sends the other
    /// over this authenticated system-bus call. Transfer/reply use that stream.
    async fn transfer(
        &self,
        stream: OwnedFd,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<()> {
        // Protected paths, credentials and detailed database errors never enter
        // bus replies. The caller must treat failure as an ambiguous pending stage.
        self.receive(stream, header, connection)
            .await
            .map_err(|_| zbus::fdo::Error::Failed("wallet provisioning transfer failed".into()))
    }
}

impl ProvisioningInterface {
    async fn receive(
        &self,
        stream: OwnedFd,
        header: Header<'_>,
        connection: &Connection,
    ) -> Result<()> {
        let sender = header
            .sender()
            .context("provisioning has no authenticated sender")?
            .to_owned();
        let registry = DBusProxy::new(connection).await?;
        // Subscribe before checking credentials, so disconnection between the
        // identity lookup and worker admission cannot strand a privileged task.
        let mut departed = tokio::time::timeout(
            Duration::from_secs(10),
            registry.receive_name_owner_changed_with_args(&[(0, sender.as_str())]),
        )
        .await??;
        let pid = installer_process(&registry, &sender).await?;
        let (mut stream, _cancel) =
            io::InstallerStream::new(stream.into(), pid, migration_transfer::INSTALLER_TIMEOUT)?;
        let pending = self
            .pending
            .clone()
            .try_lock_owned()
            .context("provisioning is busy")?;
        let worker = tokio::task::spawn_blocking(move || {
            let candidate = migration_transfer::receive(
                &*pending,
                &mut stream,
                migration_transfer::INSTALLER_LIMITS,
            )?;
            candidate.write_reply(&mut stream)
        });
        // A service stop or caller disconnect drops the cancellation guard and
        // shuts down native I/O. The worker retains the profile lock until its
        // current database operation finishes; no retry can overlap it.
        tokio::select! {
            result = worker => result?,
            _ = departed.next() => Err(anyhow::anyhow!("installer disconnected")),
            () = connection.closed() => Err(anyhow::anyhow!("provisioning bus disconnected")),
            () = tokio::time::sleep(migration_transfer::INSTALLER_TIMEOUT) => Err(anyhow::anyhow!("provisioning timed out")),
        }
    }
}

async fn installer_process(
    registry: &DBusProxy<'_>,
    sender: &zbus::names::UniqueName<'_>,
) -> Result<u32> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let uid = registry
            .get_connection_unix_user(sender.clone().into())
            .await?;
        ensure!(uid == 0, "provisioning requires the privileged installer");
        Ok(registry
            .get_connection_unix_process_id(sender.clone().into())
            .await?)
    })
    .await?
}

#[cfg(test)]
#[path = "linux_provisioning_test.rs"]
mod tests;
