//! Desktop-side Linux owner transport. This never opens wallet storage.

use crate::owner_connection::{OwnerConnection, OwnerTransport};
use crate::owner_protocol::OBJECT_PATH;
use anyhow::{Context as _, Result, ensure};
use std::time::Duration;
use zbus::{Connection, Proxy, fdo::DBusProxy, names::OwnedUniqueName};

#[derive(Clone)]
pub struct LinuxOwnerTransport {
    proxy: Proxy<'static>,
    service: OwnedUniqueName,
    process: u32,
}

impl OwnerConnection<LinuxOwnerTransport> {
    /// Authenticate the installed service using protected installer metadata
    /// and the real system bus. No caller-provided UID, bus address, or service
    /// name is accepted at this boundary.
    pub async fn connect() -> Result<Self> {
        let identity = ekubo_wallet_core::service_storage::installed_service_identity()?;
        tokio::time::timeout(Duration::from_secs(10), async {
            Ok(Self::from_transport(connect_custody(&identity).await?))
        })
        .await
        .context("wallet service connection timed out")?
    }

    #[cfg(test)]
    async fn on_bus(bus: Connection, name: &str, expected_uid: u32) -> Result<Self> {
        Ok(Self::from_transport(
            LinuxOwnerTransport::authenticate(bus, name, expected_uid).await?,
        ))
    }
}

impl LinuxOwnerTransport {
    async fn activate(bus: Connection, name: &str, expected_uid: u32) -> Result<Self> {
        let registry = DBusProxy::new(&bus).await?;
        if !registry.name_has_owner(name.try_into()?).await? {
            let reply = registry.start_service_by_name(name.try_into()?, 0).await?;
            let _ = zbus::fdo::StartServiceReply::try_from(reply)?;
        }
        // Activation only establishes availability. Resolve and authenticate
        // the actual unique owner before touching the login keyring. Existing
        // transports never activate again after an interrupted operation.
        Self::authenticate(bus, name, expected_uid).await
    }

    async fn authenticate(bus: Connection, name: &str, expected_uid: u32) -> Result<Self> {
        let registry = DBusProxy::new(&bus).await?;
        let service = registry.get_name_owner(name.try_into()?).await?;
        let actual_uid = registry
            .get_connection_unix_user(service.clone().into())
            .await?;
        ensure!(
            actual_uid == expected_uid,
            "wallet endpoint does not belong to the installed service"
        );
        // Address the verified unique name, never the replaceable well-known
        // name. A restart requires a new explicitly authenticated connection.
        let process = registry
            .get_connection_unix_process_id(service.clone().into())
            .await?;
        let proxy =
            Proxy::new_owned(bus, service.clone(), OBJECT_PATH, "org.ekubo.Wallet.Owner1").await?;
        Ok(Self {
            proxy,
            service,
            process,
        })
    }

    async fn unlock(
        &self,
        wrapped: &ekubo_wallet_core::custody_envelope::WrappedDataKey,
    ) -> Result<()> {
        let proxy = Proxy::new(
            self.proxy.connection(),
            self.service.as_str(),
            crate::owner_protocol::CUSTODY_OBJECT_PATH,
            "org.ekubo.Wallet.Custody1",
        )
        .await?;
        let reply = proxy.call_method("Unlock", &(wrapped.as_bytes(),)).await?;
        ensure!(
            reply.header().sender() == Some(self.service.inner()),
            "custody reply came from an unexpected service"
        );
        Ok(reply.body().deserialize::<()>()?)
    }
}

impl crate::owner_connection::sealed::Sealed for LinuxOwnerTransport {}

impl OwnerTransport for LinuxOwnerTransport {
    async fn exchange(&self, request: &str) -> Result<zeroize::Zeroizing<String>> {
        let message = self.proxy.call_method("Call", &(request,)).await?;
        ensure!(
            message.header().sender() == Some(self.service.inner()),
            "owner response came from an unexpected service"
        );
        Ok(zeroize::Zeroizing::new(
            message.body().deserialize::<String>()?,
        ))
    }

    /// Keep automatic execution active for this desktop connection. Spawn this
    /// once for the application lifetime; closing the connection ends the lease.
    /// Cancelling just this method's future does not disconnect a D-Bus peer.
    async fn hold(&self) -> Result<()> {
        let response = self.proxy.call_method("HoldDesktopSession", &()).await?;
        ensure!(
            response.header().sender() == Some(self.service.inner()),
            "desktop session response came from an unexpected service"
        );
        Ok(response.body().deserialize()?)
    }

    /// Close this connection, including all clones and pending owner requests.
    /// The application must do this on Quit to release its desktop session.
    async fn close(&self) -> Result<()> {
        Ok(self.proxy.connection().clone().close().await?)
    }
}

async fn connect_custody(
    identity: &ekubo_wallet_core::service_storage::InstalledServiceIdentity,
) -> Result<LinuxOwnerTransport> {
    let bus = zbus::connection::Builder::unix_stream(
        ekubo_wallet_core::service_storage::system_bus_stream().await?,
    )
    .build()
    .await?;
    let transport = LinuxOwnerTransport::activate(
        bus,
        &format!("org.ekubo.Wallet.Owner.u{}", identity.owner_uid()),
        identity.service_uid(),
    )
    .await?;
    // The login keyring is not touched until the service identity is pinned.
    let profile = identity.profile_id();
    let wrapped =
        tokio::task::spawn_blocking(move || ekubo_wallet_core::custody_relay::load(profile))
            .await??;
    transport.unlock(&wrapped).await?;
    Ok(transport)
}

/// An installed service failure never falls back to the desktop's local socket.
/// The agent receives an MCP stream, without an owner client or desktop lease.
pub async fn try_connect_agent_stream() -> Result<Option<tokio::net::UnixStream>> {
    let Some(identity) = ekubo_wallet_core::service_storage::find_installed_service_identity()?
    else {
        return Ok(None);
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let custody = connect_custody(&identity).await?;
        let stream =
            ekubo_wallet_core::service_storage::agent_stream(&identity, custody.process).await?;
        custody.close().await?;
        Ok(Some(stream))
    })
    .await
    .context("MCP service connection timed out")?
}

pub type OwnerClient = OwnerConnection<LinuxOwnerTransport>;

#[cfg(test)]
#[path = "owner_client_test.rs"]
mod tests;
