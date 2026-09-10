//! Desktop session lifetime, independent of Linux/Windows transport details.
//! Concrete transports authenticate peers; this supervisor grants no authority.

use anyhow::{Context as _, Result};
use tokio::{sync::watch, task::JoinHandle};

/// A previously authenticated owner connection. Closing must invalidate all
/// clones and pending requests, releasing the service's desktop-session lease.
pub trait SessionTransport: Send + Sync + 'static {
    fn hold(&self) -> impl std::future::Future<Output = Result<()>> + Send;
    fn close(&self) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// The authenticated connection is supervised. This is not an acknowledgement
    /// that the service has accepted the long-running lease call yet.
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
        let (stop, stopping) = watch::channel(false);
        let (state, status) = watch::channel(SessionState::Connected);
        let task = tokio::spawn(supervise(transport, stopping, state));
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
) -> Result<()> {
    let result = tokio::select! {
        biased;
        _ = stop.changed() => Ok(()),
        result = transport.hold() => match result {
            Ok(()) => Err(anyhow::anyhow!("desktop session ended unexpectedly")),
            Err(error) => Err(error.context("desktop session was lost")),
        },
    };
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

impl<T: crate::owner_connection::OwnerTransport> SessionTransport
    for crate::owner_connection::OwnerConnection<T>
{
    async fn hold(&self) -> Result<()> {
        self.hold_desktop_session().await
    }
    async fn close(&self) -> Result<()> {
        crate::owner_connection::OwnerConnection::close(self).await
    }
}

#[cfg(test)]
#[path = "desktop_session_test.rs"]
mod tests;
