//! Shared stream client state. Only authenticated OS adapters construct it.

use crate::owner_stream_protocol::{self as wire, Kind};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::custody_envelope::WrappedDataKey;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite},
    sync::{Semaphore, watch},
};
use zeroize::Zeroizing;

pub(crate) trait Connector: Clone + Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn connect(&self) -> impl std::future::Future<Output = Result<Self::Stream>> + Send;
}

struct State {
    stop: watch::Sender<bool>,
    hold: watch::Sender<bool>,
    ready: watch::Receiver<bool>,
    closed: watch::Receiver<Option<String>>,
    calls: Semaphore,
}

impl Drop for State {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[derive(Clone)]
pub(crate) struct StreamOwnerClient<C> {
    connector: C,
    instance: uuid::Uuid,
    state: Arc<State>,
}

impl<C: Connector> StreamOwnerClient<C> {
    pub(crate) async fn connect<F>(connector: C, load: impl FnOnce() -> F) -> Result<Self>
    where
        F: std::future::Future<Output = Result<WrappedDataKey>> + Send,
    {
        let (mut stream, instance) =
            tokio::time::timeout(Duration::from_secs(10), connect_unlocked(&connector, load))
                .await
                .context("owner service connection timed out")??;
        let (stop, mut stopping) = watch::channel(false);
        let (hold, mut holding) = watch::channel(false);
        let (closed, status) = watch::channel(None);
        let (ready, readiness) = watch::channel(false);
        tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                _ = stopping.wait_for(|stop| *stop) => Ok(()),
                result = supervise(&mut stream, &mut holding, &ready) => result,
            };
            // A close acknowledgement means the actual lifetime pipe is gone.
            drop(stream);
            closed.send_replace(Some(result.err().map_or_else(
                || "owner connection closed".into(),
                |error| error.to_string(),
            )));
        });
        Ok(Self {
            connector,
            instance,
            state: Arc::new(State {
                stop,
                hold,
                ready: readiness,
                closed: status,
                calls: Semaphore::new(32),
            }),
        })
    }

    pub(crate) async fn exchange(&self, request: &str) -> Result<Zeroizing<String>> {
        ensure!(
            request.len() < crate::framing::MAX_FRAME_BYTES,
            "owner request exceeds its size limit"
        );
        let _slot = self
            .state
            .calls
            .try_acquire()
            .context("owner client is busy")?;
        let mut stop = self.state.stop.subscribe();
        let mut closed = self.state.closed.clone();
        tokio::select! {
            biased;
            _ = stop.wait_for(|stop| *stop) => anyhow::bail!("owner connection closed"),
            _ = closed.wait_for(Option::is_some) => anyhow::bail!("owner connection lost"),
            result = self.exchange_once(request) => result,
        }
    }

    async fn exchange_once(&self, request: &str) -> Result<Zeroizing<String>> {
        let mut stream = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = self.connector.connect().await?;
            let instance = wire::read_hello(&mut stream).await?;
            if instance != self.instance {
                self.state.stop.send_replace(true);
                anyhow::bail!("owner service instance changed");
            }
            Ok::<_, anyhow::Error>(stream)
        })
        .await
        .context("owner call connection timed out")??;
        // Exactly one dispatch. Any error after this point is potentially
        // ambiguous; this transport never resends the request.
        wire::write(&mut stream, Kind::Call, request.as_bytes()).await?;
        let response = reply(&mut stream).await?;
        Ok(Zeroizing::new(
            std::str::from_utf8(response.body())?.to_owned(),
        ))
    }

    pub(crate) async fn hold(&self, ready: tokio::sync::oneshot::Sender<()>) -> Result<()> {
        self.state.hold.send_replace(true);
        let mut closed = self.state.closed.clone();
        let mut acknowledged = self.state.ready.clone();
        tokio::select! {
            biased;
            reason = closed.wait_for(Option::is_some) => {
                let reason = reason.context("owner lifetime task stopped")?;
                anyhow::bail!("{}", reason.as_deref().unwrap_or("owner connection closed"));
            },
            result = acknowledged.wait_for(|ready| *ready) => {
                result.context("desktop readiness monitor stopped")?;
                let _ = ready.send(());
            }
        }

        let reason = closed
            .wait_for(Option::is_some)
            .await
            .context("owner lifetime task stopped")?;
        anyhow::bail!("{}", reason.as_deref().unwrap_or("owner connection closed"))
    }

    pub(crate) async fn close(&self) -> Result<()> {
        self.state.stop.send_replace(true);
        self.state
            .closed
            .clone()
            .wait_for(Option::is_some)
            .await
            .context("owner lifetime task stopped")?;
        Ok(())
    }
}

async fn connect_unlocked<C: Connector, F>(
    connector: &C,
    load: impl FnOnce() -> F,
) -> Result<(C::Stream, uuid::Uuid)>
where
    F: std::future::Future<Output = Result<WrappedDataKey>> + Send,
{
    let mut stream = connector.connect().await?;
    let instance = wire::read_hello(&mut stream).await?;
    // Never invoke the ciphertext loader before OS endpoint authentication
    // and greeting validation. Callers bound the complete startup duration.
    let wrapped = load().await?;
    wire::write(&mut stream, Kind::Unlock, wrapped.as_bytes()).await?;
    unit_reply(&mut stream).await?;
    Ok((stream, instance))
}

/// Retain the same authenticated kernel connection through relay and handoff.
/// No desktop lease, owner-call client, or raw key is returned to the agent.
pub(crate) async fn connect_agent<C: Connector, F>(
    connector: C,
    load: impl FnOnce() -> F,
) -> Result<C::Stream>
where
    F: std::future::Future<Output = Result<WrappedDataKey>> + Send,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut stream, _) = connect_unlocked(&connector, load).await?;
        wire::write(&mut stream, Kind::Agent, &[]).await?;
        unit_reply(&mut stream).await?;
        Ok(stream)
    })
    .await
    .context("MCP service connection timed out")?
}

async fn supervise(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    holding: &mut watch::Receiver<bool>,
    ready: &watch::Sender<bool>,
) -> Result<()> {
    let mut byte = [0];
    tokio::select! {
        ready = holding.wait_for(|hold| *hold) => { ready.context("owner lifetime was dropped")?; }
        count = stream.read(&mut byte) => {
            ensure!(count? == 0, "unexpected owner lifetime traffic");
            anyhow::bail!("owner service disconnected");
        }
    }
    wire::write(stream, Kind::Hold, &[]).await?;
    unit_reply(stream).await?;
    ready.send_replace(true);
    let count = stream.read(&mut byte).await?;
    ensure!(count == 0, "unexpected owner lifetime traffic");
    anyhow::bail!("owner service disconnected")
}

async fn reply(stream: &mut (impl AsyncRead + Unpin)) -> Result<wire::Frame> {
    let response = wire::read(stream)
        .await?
        .context("owner service closed without a reply")?;
    match response.kind {
        Kind::Ok => Ok(response),
        Kind::Error => {
            ensure!(response.body().len() <= 2048, "oversized owner error");
            anyhow::bail!("{}", std::str::from_utf8(response.body())?);
        }
        _ => anyhow::bail!("unexpected owner response"),
    }
}

async fn unit_reply(stream: &mut (impl AsyncRead + Unpin)) -> Result<()> {
    ensure!(
        reply(stream).await?.body().is_empty(),
        "unexpected owner acknowledgement payload"
    );
    Ok(())
}

#[cfg(test)]
#[path = "stream_owner_client_test.rs"]
mod tests;

#[cfg(test)]
#[path = "stream_agent_client_test.rs"]
mod agent_tests;
