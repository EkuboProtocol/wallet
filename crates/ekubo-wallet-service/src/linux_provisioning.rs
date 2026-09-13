//! Root-authenticated fresh enrollment under the protected service identity.
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::{custody_provisioning, service_storage};
use std::sync::Arc;
use tokio::sync::Mutex;
use zbus::{Connection, fdo::DBusProxy, message::Header};

pub async fn run(owner_uid: u32) -> Result<()> {
    let pending = service_storage::pending_credential_staging_root(owner_uid)?;
    let bus = zbus::connection::Builder::unix_stream(service_storage::system_bus_stream().await?)
        .name(format!("org.ekubo.Wallet2.Provision.u{owner_uid}"))?
        .serve_at(
            "/org/ekubo/Wallet2/Provision",
            ProvisioningInterface {
                pending: Arc::new(Mutex::new(pending)),
            },
        )?
        .build()
        .await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        () = bus.closed() => anyhow::bail!("provisioning system bus disconnected"),
        _ = terminate.recv() => {},
        signal = tokio::signal::ctrl_c() => signal?,
    }
    bus.close().await?;
    Ok(())
}

struct ProvisioningInterface {
    pending: Arc<Mutex<service_storage::PendingCredentialStorage>>,
}

#[zbus::interface(name = "org.ekubo.Wallet2.Provision1")]
impl ProvisioningInterface {
    async fn enroll(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<Vec<u8>> {
        self.fresh(header, connection).await.map_err(|_| {
            zbus::fdo::Error::Failed("fresh enrollment failed; inspect pending setup".into())
        })
    }
}

impl ProvisioningInterface {
    async fn fresh(&self, header: Header<'_>, connection: &Connection) -> Result<Vec<u8>> {
        let sender = header.sender().context("missing installer identity")?;
        let registry = DBusProxy::new(connection).await?;
        ensure!(
            registry
                .get_connection_unix_user(sender.clone().into())
                .await?
                == 0,
            "fresh enrollment requires the privileged installer"
        );
        let pending = self
            .pending
            .clone()
            .try_lock_owned()
            .context("enrollment busy")?;
        tokio::task::spawn_blocking(move || {
            Ok(custody_provisioning::enroll(&*pending)?.as_bytes().to_vec())
        })
        .await?
    }
}
