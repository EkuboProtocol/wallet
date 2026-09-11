//! Shared owner dispatch over a stream whose OS adapter authenticates each read.

use crate::{
    custody_bootstrap::{CustodyBootstrap, Startup},
    runtime::ServiceRuntime,
};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_client::{
    owner_protocol::Request,
    owner_stream_protocol::{self as wire, Frame, Kind},
};
use ekubo_wallet_core::custody_envelope::WrappedDataKey;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

pub(crate) trait Peer: Send {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;
    fn stream(&mut self) -> &mut Self::Stream;
    fn authenticate(&self) -> Result<()>;
}

pub(crate) struct OwnerStreamService {
    instance: uuid::Uuid,
    bootstrap: CustodyBootstrap,
    runtime: OnceLock<Arc<ServiceRuntime>>,
}

impl OwnerStreamService {
    pub(crate) fn new() -> (Self, Startup) {
        let (bootstrap, startup) = CustodyBootstrap::new();
        (
            Self {
                instance: uuid::Uuid::new_v4(),
                bootstrap,
                runtime: OnceLock::new(),
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
        let result = self.dispatch(&mut peer, first, unlock).await;
        if let Err(error) = result {
            let message = ekubo_wallet_core::sanitize::stripped_capped(&error.to_string(), 2048);
            wire::write(peer.stream(), Kind::Error, message.as_bytes()).await?;
        }
        Ok(())
    }

    async fn dispatch(
        &self,
        peer: &mut impl Peer,
        frame: Frame,
        unlock: impl FnOnce(&WrappedDataKey) -> Result<()> + Send,
    ) -> Result<()> {
        match frame.kind {
            Kind::Unlock => {
                // A one-byte read is cancellation-safe. Never cancel a partial
                // frame reader and then reuse the connection for the next phase.
                tokio::select! {
                    result = self.bootstrap.unlock(frame.body(), unlock) => result?,
                    departed = wait_for_departure(peer.stream()) => return departed,
                }
                wire::write(peer.stream(), Kind::Ok, &[]).await?;
                let hold = read_request(peer).await?;
                ensure!(hold.kind == Kind::Hold, "expected desktop lifetime request");
                self.hold(peer, &hold).await
            }
            Kind::Hold => self.hold(peer, &frame).await,
            Kind::Call => self.call(peer, &frame).await,
            _ => anyhow::bail!("unexpected owner request kind"),
        }
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
            departed = wait_for_departure(peer.stream()) => return departed,
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

async fn wait_for_departure(stream: &mut (impl AsyncRead + Unpin)) -> Result<()> {
    let mut byte = [0];
    let count = stream.read(&mut byte).await?;
    ensure!(count == 0, "unexpected traffic on owner connection");
    anyhow::bail!("owner connection closed")
}

#[cfg(test)]
#[path = "owner_stream_rpc_test.rs"]
mod tests;
