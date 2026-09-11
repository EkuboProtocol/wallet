//! Shared owner dispatch over a stream whose OS adapter authenticates each read.

use crate::{
    authority::AgentApi,
    custody_bootstrap::{CustodyBootstrap, Startup},
    runtime::ServiceRuntime,
};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_client::{
    owner_protocol::Request,
    owner_stream_protocol::{self as wire, Frame, Kind},
};
use ekubo_wallet_core::custody_envelope::WrappedDataKey;
use std::sync::{Arc, OnceLock, atomic::AtomicUsize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

pub(crate) trait Peer: Send {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn stream(&mut self) -> &mut Self::Stream;
    fn authenticate(&self) -> Result<()>;
    fn into_stream(self) -> Self::Stream;
}

pub(crate) struct OwnerStreamService {
    instance: uuid::Uuid,
    bootstrap: CustodyBootstrap,
    runtime: OnceLock<Arc<ServiceRuntime>>,
    mcp_active: Arc<AtomicUsize>,
}

enum Next {
    Finished,
    Mcp(AgentApi),
}

impl OwnerStreamService {
    pub(crate) fn new() -> (Self, Startup) {
        let (bootstrap, startup) = CustodyBootstrap::new();
        (
            Self {
                instance: uuid::Uuid::new_v4(),
                bootstrap,
                runtime: OnceLock::new(),
                mcp_active: Arc::new(AtomicUsize::new(0)),
            },
            startup,
        )
    }

    pub(crate) fn publish(&self, runtime: Arc<ServiceRuntime>) -> Result<()> {
        self.runtime
            .set(runtime)
            .map_err(|_| anyhow::anyhow!("owner runtime is already published"))
    }

    fn runtime(&self) -> Result<&ServiceRuntime> {
        self.runtime
            .get()
            .map(Arc::as_ref)
            .context("owner runtime is not ready")
    }

    pub(crate) async fn serve(
        &self,
        mut peer: impl Peer,
        unlock: impl FnOnce(&WrappedDataKey) -> Result<()> + Send,
    ) -> Result<()> {
        wire::write(peer.stream(), Kind::Hello, self.instance.as_bytes()).await?;
        let first =
            tokio::time::timeout(std::time::Duration::from_secs(10), read_request(&mut peer))
                .await
                .context("owner handshake timed out")??;
        match self.dispatch(&mut peer, first, unlock).await {
            Ok(Next::Finished) => Ok(()),
            Ok(Next::Mcp(agent)) => {
                // After the empty acknowledgement, this stream is exclusively
                // MCP. Never write owner frames into it or accept owner calls.
                crate::mcp_transport::serve_connection(
                    peer.into_stream(),
                    agent,
                    self.mcp_active.clone(),
                    self.runtime()?.events(),
                )
                .await
            }
            Err(error) => {
                let message =
                    ekubo_wallet_core::sanitize::stripped_capped(&error.to_string(), 2048);
                wire::write(peer.stream(), Kind::Error, message.as_bytes()).await
            }
        }
    }

    async fn dispatch(
        &self,
        peer: &mut impl Peer,
        frame: Frame,
        unlock: impl FnOnce(&WrappedDataKey) -> Result<()> + Send,
    ) -> Result<Next> {
        let frame = self.prepare(peer, frame, unlock).await?;
        match frame.kind {
            Kind::Hold => self.hold(peer, &frame).await?,
            Kind::Call => self.call(peer, &frame).await?,
            Kind::Agent => {
                ensure!(frame.body().is_empty(), "MCP handoff request has a payload");
                let agent = self.runtime()?.agent_api();
                wire::write(peer.stream(), Kind::Ok, &[]).await?;
                return Ok(Next::Mcp(agent));
            }
            _ => anyhow::bail!("unexpected owner request kind"),
        }
        Ok(Next::Finished)
    }

    async fn prepare(
        &self,
        peer: &mut impl Peer,
        frame: Frame,
        unlock: impl FnOnce(&WrappedDataKey) -> Result<()> + Send,
    ) -> Result<Frame> {
        if frame.kind != Kind::Unlock {
            return Ok(frame);
        }
        // A one-byte read is cancellation-safe. Never cancel a partial frame
        // reader and then reuse the connection for the next protocol phase.
        tokio::select! {
            result = self.bootstrap.unlock(frame.body(), unlock) => result?,
            departed = wait_for_departure(peer.stream()) => return Err(departed),
        }
        wire::write(peer.stream(), Kind::Ok, &[]).await?;
        let next = read_request(peer).await?;
        ensure!(
            matches!(next.kind, Kind::Hold | Kind::Agent),
            "expected desktop lifetime or MCP handoff request"
        );
        Ok(next)
    }

    async fn hold(&self, peer: &mut impl Peer, frame: &Frame) -> Result<()> {
        ensure!(
            frame.body().is_empty(),
            "desktop lifetime request has a payload"
        );
        let reservation = self.runtime()?.reserve_desktop()?;
        let _active = reservation.activate();
        wire::write(peer.stream(), Kind::Ok, &[]).await?;
        match wire::read(peer.stream()).await? {
            None => Ok(()),
            Some(_) => anyhow::bail!("unexpected traffic on desktop lifetime connection"),
        }
    }

    async fn call(&self, peer: &mut impl Peer, frame: &Frame) -> Result<()> {
        let runtime = self.runtime()?;
        let request: Request = serde_json::from_slice(frame.body())
            .map_err(|_| anyhow::anyhow!("invalid owner operation"))?;
        let response = tokio::select! {
            response = runtime.owner.encode(request) => response?,
            departed = wait_for_departure(peer.stream()) => return Err(departed),
        };
        wire::write(peer.stream(), Kind::Ok, response.as_bytes()).await
    }
}

async fn read_request(peer: &mut impl Peer) -> Result<Frame> {
    let frame = wire::read(peer.stream())
        .await?
        .context("owner connection closed")?;
    // No await or dispatch occurs between the last read and the OS identity
    // check. The Windows implementation also reverts impersonation here.
    peer.authenticate()?;
    Ok(frame)
}

async fn wait_for_departure(stream: &mut (impl AsyncRead + Unpin)) -> anyhow::Error {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => anyhow::anyhow!("owner connection closed"),
        Ok(_) => anyhow::anyhow!("unexpected traffic on owner connection"),
        Err(error) => error.into(),
    }
}

#[cfg(test)]
#[path = "owner_stream_rpc_test.rs"]
mod tests;

#[cfg(test)]
#[path = "owner_stream_mcp_test.rs"]
mod mcp_tests;
