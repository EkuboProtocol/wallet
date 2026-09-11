//! Windows desktop adapter. The core pipe connector authenticates the connected
//! service object before this client relays ciphertext or any owner request.

use crate::{
    owner_connection::{OwnerConnection, OwnerTransport},
    stream_owner_client::{Connector, StreamOwnerClient},
};
use anyhow::Result;
use std::sync::Arc;
use tokio::net::windows::named_pipe::NamedPipeClient;

#[derive(Clone)]
struct WindowsConnector(Arc<ekubo_wallet_core::windows_service_config::InstalledServiceIdentity>);

impl Connector for WindowsConnector {
    type Stream = NamedPipeClient;
    async fn connect(&self) -> Result<Self::Stream> {
        ekubo_wallet_core::windows_owner_pipe::connect(&self.0).await
    }
}

#[derive(Clone)]
pub struct WindowsOwnerTransport(StreamOwnerClient<WindowsConnector>);
impl crate::owner_connection::sealed::Sealed for WindowsOwnerTransport {}

impl OwnerTransport for WindowsOwnerTransport {
    async fn exchange(&self, request: &str) -> Result<zeroize::Zeroizing<String>> {
        self.0.exchange(request).await
    }
    async fn hold(&self) -> Result<()> {
        self.0.hold().await
    }
    async fn close(&self) -> Result<()> {
        self.0.close().await
    }
}

impl OwnerConnection<WindowsOwnerTransport> {
    pub async fn connect() -> Result<Self> {
        let identity =
            Arc::new(ekubo_wallet_core::windows_service_config::installed_service_identity()?);
        let profile = identity.profile_id();
        let client = StreamOwnerClient::connect(WindowsConnector(identity), move || {
            Box::pin(async move {
                tokio::task::spawn_blocking(move || ekubo_wallet_core::custody_relay::load(profile))
                    .await?
            })
        })
        .await?;
        Ok(Self::from_transport(WindowsOwnerTransport(client)))
    }
}

pub type OwnerClient = OwnerConnection<WindowsOwnerTransport>;
