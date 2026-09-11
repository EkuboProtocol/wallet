//! Desktop session lifetime, independent of Linux/Windows transport details.
//! Concrete transports authenticate peers; this supervisor grants no authority.

use anyhow::{Context as _, Result};
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
};

/// A previously authenticated owner connection. Closing must invalidate all
/// clones and pending requests, releasing the service's desktop-session lease.
pub trait SessionTransport: Send + Sync + 'static {
    fn hold(
        &self,
        ready: oneshot::Sender<()>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn close(&self) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// The authenticated connection is supervised, but its lease is not yet acknowledged.
    Starting,
    /// The service has acknowledged this connection's active desktop lease.
    /// This is readiness, never an owner-authorization proof.
    Connected,
    Closing,
    Closed,
    Failed(String),
}

/// Keep this for the application lifetime. Await `close` before shutting down
/// the async runtime. Drop also requests closure, but cannot wait for it.
pub struct DesktopSession {
    stop: watch::Sender<bool>,
    state: watch::Receiver<SessionState>,
    task: Option<JoinHandle<Result<()>>>,
}

impl DesktopSession {
    /// Start inside a Tokio runtime with an already authenticated transport.
    /// No native owner-authentication context is needed or inherited here.
    pub fn start(transport: impl SessionTransport) -> Self {
        Self::start_with_timeout(transport, std::time::Duration::from_secs(10))
    }

    fn start_with_timeout(
        transport: impl SessionTransport,
        startup_timeout: std::time::Duration,
    ) -> Self {
        let (stop, stopping) = watch::channel(false);
        let (state, status) = watch::channel(SessionState::Starting);
        let task = tokio::spawn(supervise(transport, stopping, state, startup_timeout));
        Self {
            stop,
            state: status,
            task: Some(task),
        }
    }

    #[must_use]
    pub fn state(&self) -> watch::Receiver<SessionState> {
        self.state.clone()
    }

    /// Wait until the authenticated service has accepted the execution lease.
    /// The supervisor closes the actual connection if startup fails or times out.
    pub async fn ready(&self) -> Result<()> {
        let mut state = self.state.clone();
        loop {
            match state.borrow_and_update().clone() {
                SessionState::Starting | SessionState::Closing => {}
                SessionState::Connected => return Ok(()),
                SessionState::Closed => {
                    anyhow::bail!("desktop session closed before becoming ready")
                }
                SessionState::Failed(error) => anyhow::bail!("{error}"),
            }
            state
                .changed()
                .await
                .context("desktop session supervisor stopped")?;
        }
    }

    pub async fn close(mut self) -> Result<()> {
        self.stop.send_replace(true);
        self.task
            .take()
            .expect("desktop session owns its supervisor")
            .await
            .context("desktop session supervisor failed")?
    }
}

impl Drop for DesktopSession {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        // Dropping a JoinHandle detaches it. Do not abort: the supervisor still
        // needs to close the actual connection while the runtime remains alive.
    }
}

async fn supervise(
    transport: impl SessionTransport,
    mut stop: watch::Receiver<bool>,
    state: watch::Sender<SessionState>,
    startup_timeout: std::time::Duration,
) -> Result<()> {
    let result = await_lease(&transport, &mut stop, &state, startup_timeout).await;
    state.send_replace(SessionState::Closing);
    // Even an unexpected successful return ends the connection: merely dropping
    // the hold future can leave the service's session active through a clone.
    let closed = transport.close().await;
    let result = match (result, closed) {
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("connection closure also failed: {close_error:#}")))
        }
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    };
    state.send_replace(match &result {
        Ok(()) => SessionState::Closed,
        Err(error) => SessionState::Failed(format!("{error:#}")),
    });
    result
}

async fn await_lease(
    transport: &impl SessionTransport,
    stop: &mut watch::Receiver<bool>,
    state: &watch::Sender<SessionState>,
    startup_timeout: std::time::Duration,
) -> Result<()> {
    let (ready, acknowledged) = oneshot::channel();
    let hold = transport.hold(ready);
    let timeout = tokio::time::sleep(startup_timeout);
    tokio::pin!(hold, acknowledged, timeout);
    let mut starting = true;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => return Ok(()),
            result = &mut hold => return match result {
                Ok(()) => Err(anyhow::anyhow!("desktop session ended unexpectedly")),
                Err(error) => Err(error.context("desktop session was lost")),
            },
            ready = &mut acknowledged, if starting => {
                ready.context("desktop session ended without a readiness acknowledgement")?;
                starting = false;
                state.send_replace(SessionState::Connected);
            }
            () = &mut timeout, if starting => anyhow::bail!("desktop session readiness timed out"),
        }
    }
}

impl<T: crate::owner_connection::OwnerTransport> SessionTransport
    for crate::owner_connection::OwnerConnection<T>
{
    async fn hold(&self, ready: oneshot::Sender<()>) -> Result<()> {
        self.hold_desktop_session(ready).await
    }
    async fn close(&self) -> Result<()> {
        crate::owner_connection::OwnerConnection::close(self).await
    }
}

#[cfg(test)]
#[path = "desktop_session_test.rs"]
mod tests;
