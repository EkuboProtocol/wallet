//! Owner-side source lifetime and root-authenticated migration transport.
//! This is staging only; it has no service activation or legacy deletion command.
use crate::{
    linux_provisioning_io::{CancelStream, InstallerStream},
    migration_transfer,
};
use anyhow::{Context as _, Result, ensure};
use futures::StreamExt as _;
use std::sync::Arc;
use tokio::sync::Semaphore;
use zbus::{Connection, fdo::DBusProxy, names::OwnedUniqueName};

const PATH: &str = "/org/ekubo/Wallet/InstallerSource";
const INTERFACE: &str = "org.ekubo.Wallet.InstallerSource1";
const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bind before starting local wallet workers. Give the exact unique name to the
/// privileged launch handoff. Binding alone reads no configuration or credential.
pub struct OwnerSourceEndpoint(Connection);
impl OwnerSourceEndpoint {
    pub async fn bind() -> Result<Self> {
        let owner = rustix::process::getuid().as_raw();
        ensure!(
            owner != 0 && owner == rustix::process::geteuid().as_raw(),
            "source endpoint requires the ordinary desktop owner"
        );
        let bus = zbus::connection::Builder::unix_stream(
            crate::service_storage::system_bus_stream().await?,
        )
        .serve_at(
            PATH,
            SourceInterface {
                slots: Arc::new(Semaphore::new(1)),
            },
        )?
        .build()
        .await?;
        Ok(Self(bus))
    }

    pub fn unique_name(&self) -> Result<OwnedUniqueName> {
        Ok(self
            .0
            .unique_name()
            .context("source bus has no unique name")?
            .to_owned())
    }

    pub async fn close(self) -> Result<()> {
        Ok(self.0.close().await?)
    }
}

struct SourceInterface {
    slots: Arc<Semaphore>,
}

#[zbus::interface(name = "org.ekubo.Wallet.InstallerSource1")]
impl SourceInterface {
    async fn start(
        &self,
        channel: zbus::zvariant::OwnedFd,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] bus: &Connection,
    ) -> zbus::fdo::Result<()> {
        let sender: OwnedUniqueName = header
            .sender()
            .ok_or_else(|| zbus::fdo::Error::AccessDenied("missing installer identity".into()))?
            .to_owned()
            .into();
        let registry = DBusProxy::new(bus).await?;
        let admitted = tokio::time::timeout(AUTH_TIMEOUT, async {
            let process = authenticate(&registry, &sender, 0).await?;
            let departed = registry
                .receive_name_owner_changed_with_args(&[(0, sender.as_str())])
                .await?;
            ensure!(
                authenticate(&registry, &sender, 0).await? == process,
                "installer changed"
            );
            let (stream, cancel) = InstallerStream::new(
                channel.into(),
                process,
                migration_transfer::INSTALLER_TIMEOUT,
            )?;
            Ok::<_, anyhow::Error>((stream, cancel, departed))
        })
        .await
        .map_err(|_| zbus::fdo::Error::AccessDenied("installer admission timed out".into()))?
        .map_err(|_| {
            zbus::fdo::Error::AccessDenied(
                "source requires the authenticated installer stream".into(),
            )
        })?;
        let slot = self.slots.clone().try_acquire_owned().map_err(|_| {
            zbus::fdo::Error::LimitsExceeded("source handoff already in progress".into())
        })?;
        let (mut stream, cancel, mut departed) = admitted;
        let bus = bus.clone();
        // Return admission promptly: the worker keeps its fence until abort.
        // Cancellation belongs to the watcher, while admission belongs to the
        // blocking worker even if a credential backend is slow to return.
        tokio::spawn(async move {
            let _cancel = cancel;
            let worker = tokio::task::spawn_blocking(move || {
                let _slot = slot;
                crate::migration_source::serve(&mut stream)
            });
            tokio::select! {
                _ = worker => {},
                _ = departed.next() => {},
                () = bus.closed() => {},
                () = tokio::time::sleep(migration_transfer::INSTALLER_TIMEOUT) => {},
            }
        });
        Ok(())
    }
}

async fn authenticate(registry: &DBusProxy<'_>, peer: &OwnedUniqueName, uid: u32) -> Result<u32> {
    ensure!(
        registry
            .get_connection_unix_user(peer.clone().into())
            .await?
            == uid,
        "source peer UID mismatch"
    );
    let pid = registry
        .get_connection_unix_process_id(peer.clone().into())
        .await?;
    ensure!(pid != 0, "source peer is not live");
    Ok(pid)
}

// Only the native provisioning adapter receives this authenticated stream. No
// public stream getter can redirect core-collected credentials to an agent.
pub(crate) struct OwnerChannel {
    pub(crate) stream: InstallerStream,
    _bus: Connection,
}

pub(crate) async fn connect(
    owner: u32,
    recipient: OwnedUniqueName,
) -> Result<(OwnerChannel, CancelStream)> {
    tokio::time::timeout(AUTH_TIMEOUT, async {
        let bus = zbus::connection::Builder::unix_stream(
            crate::service_storage::system_bus_stream().await?,
        )
        .build()
        .await?;
        let registry = DBusProxy::new(&bus).await?;
        authenticate(&registry, &recipient, owner).await?;
        let (stream, remote, cancel) =
            InstallerStream::pair(migration_transfer::INSTALLER_TIMEOUT)?;
        let reply = bus
            .call_method(
                Some(recipient.as_str()),
                PATH,
                Some(INTERFACE),
                "Start",
                &(zbus::zvariant::OwnedFd::from(remote),),
            )
            .await?;
        ensure!(
            reply.header().sender() == Some(recipient.inner()),
            "source reply provenance changed"
        );
        reply.body().deserialize::<()>()?;
        authenticate(&registry, &recipient, owner).await?;
        Ok((OwnerChannel { stream, _bus: bus }, cancel))
    })
    .await
    .context("source connection timed out")?
}

#[cfg(test)]
#[path = "linux_source_handoff_test.rs"]
mod tests;
