//! Linux D-Bus adapter for the shared owner dispatcher.

use crate::runtime::ServiceRuntime;
use ekubo_wallet_client::owner_protocol::Request;
use futures::StreamExt as _;
use std::sync::Arc;

/// Serialize as the same D-Bus string while erasing our owned reply on drop.
/// zbus owns separate encoded buffers; this does not erase those copies.
#[derive(zbus::zvariant::Type)]
#[zvariant(signature = "s")]
pub(crate) struct OwnerResponse(zeroize::Zeroizing<String>);

impl serde::Serialize for OwnerResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

pub(crate) struct LinuxOwnerInterface {
    runtime: Arc<ServiceRuntime>,
}

impl LinuxOwnerInterface {
    pub(crate) fn new(runtime: Arc<ServiceRuntime>) -> Self {
        Self { runtime }
    }
}

/// Called within core's authenticated owner context. `sender` is taken from
/// the message header. The session guard never crosses IPC to the desktop.
async fn hold_desktop(
    reservation: crate::runtime::ReservedDesktopSession,
    bus: &zbus::Connection,
    sender: &zbus::names::OwnedUniqueName,
) -> anyhow::Result<()> {
    let registry = zbus::fdo::DBusProxy::new(bus).await?;
    // Subscribe before checking liveness so a departure cannot be missed.
    let mut departed = registry
        .receive_name_owner_changed_with_args(&[(0, sender.as_str())])
        .await?;
    registry
        .get_connection_unix_user(sender.clone().into())
        .await?;
    let _session = reservation.activate();
    while let Some(signal) = departed.next().await {
        let args = signal.args()?;
        if args.name().as_str() == sender.as_str() && args.new_owner().as_ref().is_none() {
            return Ok(());
        }
    }
    anyhow::bail!("desktop session lost its system bus connection")
}

#[zbus::interface(name = "org.ekubo.Wallet.Owner1")]
impl LinuxOwnerInterface {
    async fn hold_desktop_session(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        let sender = header
            .sender()
            .ok_or_else(|| zbus::fdo::Error::AccessDenied("missing caller identity".into()))?
            .to_owned()
            .into();
        ekubo_wallet_core::service_presence::with_owner_call(
            connection,
            &header,
            Box::pin(async {
                hold_desktop(self.runtime.reserve_desktop()?, connection, &sender).await
            }),
        )
        .await
        .map_err(|error| zbus::fdo::Error::AccessDenied(error.to_string()))?
        .map_err(|error| {
            zbus::fdo::Error::Failed(ekubo_wallet_core::sanitize::stripped_capped(
                &error.to_string(),
                2048,
            ))
        })
    }

    async fn call(
        &self,
        request: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> zbus::fdo::Result<OwnerResponse> {
        if request.len() > crate::framing::MAX_FRAME_BYTES {
            return Err(zbus::fdo::Error::InvalidArgs(
                "owner request exceeds its size limit".into(),
            ));
        }
        let request: Request = serde_json::from_str(request)
            .map_err(|_| zbus::fdo::Error::InvalidArgs("invalid owner operation".into()))?;
        let result = ekubo_wallet_core::service_presence::with_owner_call(
            connection,
            &header,
            Box::pin(self.runtime.owner.encode(request)),
        )
        .await
        .map_err(|error| zbus::fdo::Error::AccessDenied(error.to_string()))?
        .map_err(|error| {
            zbus::fdo::Error::Failed(ekubo_wallet_core::sanitize::stripped_capped(
                &format!("{error:#}"),
                2048,
            ))
        })?;
        if result.len() > crate::framing::MAX_FRAME_BYTES {
            return Err(zbus::fdo::Error::Failed(
                "owner response exceeds its size limit".into(),
            ));
        }
        Ok(OwnerResponse(result))
    }
}

#[cfg(test)]
#[path = "linux_owner_rpc_test.rs"]
mod tests;
