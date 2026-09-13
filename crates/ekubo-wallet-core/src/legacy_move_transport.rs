//! Authentication stays in core: presentation cannot forge a cleanup receipt.
use super::{Receipt, ServiceCommand};
use anyhow::{Result, ensure};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

pub(super) fn require_supported() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "legacy move is disabled on Windows pending native authorization and existing owner-protocol integration; no legacy credentials were read or deleted"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) struct Peer {
    bus: zbus::Connection,
    service: zbus::names::OwnedUniqueName,
    profile: uuid::Uuid,
}
#[cfg(target_os = "linux")]
impl Peer {
    pub(super) const fn profile(&self) -> uuid::Uuid {
        self.profile
    }
    pub(super) async fn connect() -> Result<Self> {
        let identity = crate::service_storage::installed_service_identity()?;
        let bus = zbus::connection::Builder::unix_stream(
            crate::service_storage::system_bus_stream().await?,
        )
        .build()
        .await?;
        let registry = zbus::fdo::DBusProxy::new(&bus).await?;
        let name = format!("org.ekubo.Wallet2.Owner.u{}", identity.owner_uid());
        let peer = registry.get_name_owner(name.as_str().try_into()?).await?;
        ensure!(
            registry
                .get_connection_unix_user(peer.clone().into())
                .await?
                == identity.service_uid(),
            "move endpoint is not the installed protected service"
        );
        drop(registry);
        Ok(Self {
            bus,
            service: peer,
            profile: identity.profile_id(),
        })
    }
    pub(super) async fn call(&mut self, command: &ServiceCommand) -> Result<Receipt> {
        let request = Zeroizing::new(serde_json::to_string(command)?);
        let proxy = zbus::Proxy::new(
            &self.bus,
            self.service.as_str(),
            "/org/ekubo/Wallet2/Owner",
            "org.ekubo.Wallet2.Owner1",
        )
        .await?;
        let response: String = tokio::time::timeout(
            std::time::Duration::from_secs(180),
            proxy.call("LegacyMove", &(request.as_str(),)),
        )
        .await??;
        ensure!(response.len() <= 64 * 1024, "move receipt is oversized");
        let receipt: Receipt = serde_json::from_str(&response)?;
        ensure!(
            receipt.profile == self.profile,
            "move receipt belongs to another protected profile"
        );
        Ok(receipt)
    }
}

// Deliberately no duplicate Windows framing implementation. Neither public
// source admission nor service import can reach this disabled transport.
#[cfg(target_os = "windows")]
pub(super) struct Peer;
#[cfg(target_os = "windows")]
impl Peer {
    pub(super) fn profile(&self) -> uuid::Uuid {
        uuid::Uuid::nil()
    }
    pub(super) async fn connect() -> Result<Self> {
        require_supported()?;
        Ok(Self)
    }
    pub(super) async fn call(&mut self, _command: &ServiceCommand) -> Result<Receipt> {
        anyhow::bail!("Windows legacy move is disabled")
    }
}
