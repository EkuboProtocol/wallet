//! Linux D-Bus adapter for the shared owner dispatcher.

use crate::{authority::OwnerApi, dapp_runtime::DappRuntime, owner_rpc::OwnerDispatcher};
use ekubo_wallet_client::owner_protocol::Request;
use std::sync::Arc;

pub(crate) struct LinuxOwnerInterface {
    dispatcher: OwnerDispatcher,
    sessions: crate::desktop_sessions::DesktopSessions,
}

impl LinuxOwnerInterface {
    pub(crate) fn new(
        owner: OwnerApi,
        sessions: crate::desktop_sessions::DesktopSessions,
        dapps: Arc<DappRuntime>,
    ) -> Self {
        Self {
            dispatcher: OwnerDispatcher::new(owner, dapps),
            sessions,
        }
    }
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
            self.sessions.hold(connection, &sender),
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
    ) -> zbus::fdo::Result<String> {
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
            self.dispatcher.dispatch(request),
        )
        .await
        .map_err(|error| zbus::fdo::Error::AccessDenied(error.to_string()))?
        .map_err(|error| {
            zbus::fdo::Error::Failed(ekubo_wallet_core::sanitize::stripped_capped(
                &format!("{error:#}"),
                2048,
            ))
        })?;
        let response = serde_json::to_string(&result)
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        if response.len() > crate::framing::MAX_FRAME_BYTES {
            return Err(zbus::fdo::Error::Failed(
                "owner response exceeds its size limit".into(),
            ));
        }
        Ok(response)
    }
}
