//! Windows owner-pipe listener and bounded connection admission. SCM startup,
//! protected custody activation, and owner-presence proofs remain host duties.

use crate::{
    custody_bootstrap::Startup,
    owner_stream_rpc::{OwnerStreamService, Peer},
    runtime::ServiceRuntime,
};
use anyhow::Result;
use ekubo_wallet_core::{
    windows_owner_pipe::{ConnectedOwnerPipe, OwnerPipeListener},
    windows_service_config::InstalledServiceIdentity,
};
use std::sync::Arc;
use tokio::{net::windows::named_pipe::NamedPipeServer, sync::Semaphore, task::JoinSet};

pub struct WindowsOwnerEndpoint {
    identity: Arc<InstalledServiceIdentity>,
    listener: OwnerPipeListener,
    service: Arc<OwnerStreamService>,
}

pub struct WindowsOwnerPublisher(Arc<OwnerStreamService>);

impl WindowsOwnerPublisher {
    /// Publish authority after validated custody unlock, then signal `Startup::ready`.
    pub fn publish(&self, runtime: Arc<ServiceRuntime>) -> Result<()> {
        self.0.publish(runtime)
    }
}

impl WindowsOwnerEndpoint {
    /// Activate locked protected custody before publishing the first endpoint.
    /// The returned publisher remains usable while run owns the listener.
    pub fn bind(owner_sid: &str) -> Result<(Self, WindowsOwnerPublisher, Startup)> {
        ekubo_wallet_core::windows_service_custody::initialize(owner_sid)?;
        let identity = Arc::new(ekubo_wallet_core::windows_service_config::service_identity(
            owner_sid,
        )?);
        let listener = OwnerPipeListener::bind(identity.clone(), true)?;
        let (service, startup) = OwnerStreamService::new();
        let service = Arc::new(service);
        let publisher = WindowsOwnerPublisher(service.clone());
        Ok((
            Self {
                identity,
                listener,
                service,
            },
            publisher,
            startup,
        ))
    }

    /// Cancellation drops every connection and therefore every desktop lease.
    /// Keep this future alive alongside startup and the runtime supervisor.
    pub async fn run(self) -> Result<()> {
        let slots = Arc::new(Semaphore::new(32));
        let mut connections = JoinSet::new();
        let mut accepting = Box::pin(self.listener.accept());
        loop {
            tokio::select! {
                accepted = &mut accepting => {
                    let peer = accepted?;
                    // The accepted instance keeps the namespace alive while
                    // its successor is created; there is no rebind gap.
                    let next = OwnerPipeListener::bind(self.identity.clone(), false)?;
                    accepting = Box::pin(next.accept());
                    let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                    let service = self.service.clone();
                    connections.spawn(async move {
                        let _slot = slot;
                        if let Err(error) = service.serve(peer, ekubo_wallet_core::windows_service_custody::unlock).await {
                            tracing::debug!(%error, "Windows owner connection ended");
                        }
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }
}

impl Peer for ConnectedOwnerPipe {
    type Stream = NamedPipeServer;
    fn stream(&mut self) -> &mut Self::Stream {
        self.stream()
    }
    fn authenticate(&self) -> Result<()> {
        self.authenticate_request()
    }
}
