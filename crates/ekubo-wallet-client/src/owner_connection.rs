//! Shared owner operations over a previously authenticated platform connection.

use anyhow::{Result, ensure};
use zeroize::Zeroizing;

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Implemented only by this crate's authenticated platform adapters. An adapter
/// must pin the service identity, validate reply provenance, dispatch exactly
/// once, and invalidate all clones and pending operations when closed.
pub trait OwnerTransport: sealed::Sealed + Clone + Send + Sync + 'static {
    fn exchange(
        &self,
        request: &str,
    ) -> impl std::future::Future<Output = Result<Zeroizing<String>>> + Send;
    fn hold(
        &self,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn close(&self) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Contains no local authority or storage fallback. Construction is restricted
/// to adapters after platform-specific service authentication succeeds.
#[derive(Clone)]
pub struct OwnerConnection<T: OwnerTransport> {
    pub(crate) transport: T,
}

impl<T: OwnerTransport> OwnerConnection<T> {
    #[cfg(any(target_os = "linux", target_os = "windows", test))]
    pub(crate) fn from_transport(transport: T) -> Self {
        Self { transport }
    }

    /// Await `ready` before starting service-backed desktop work. Keep this
    /// lifetime in application state and await close on Quit.
    #[must_use]
    pub fn start_desktop_session(&self) -> crate::desktop_session::DesktopSession {
        crate::desktop_session::DesktopSession::start(self.clone())
    }

    /// Cancelling this future alone does not close the authenticated connection.
    pub async fn hold_desktop_session(
        &self,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<()> {
        self.transport.hold(ready).await
    }

    /// Close all connection clones and pending requests without reconnecting.
    pub async fn close(&self) -> Result<()> {
        self.transport.close().await
    }

    /// A lost reply never justifies replaying a mutation. Refresh authoritative
    /// state after an ambiguous failure. Secret-bearing JSON stays zeroizing.
    pub(crate) async fn call<R: serde::de::DeserializeOwned>(
        &self,
        request: &crate::owner_protocol::Request,
    ) -> Result<R> {
        let request = Zeroizing::new(serde_json::to_string(request)?);
        ensure!(
            request.len() <= crate::framing::MAX_FRAME_BYTES,
            "owner request exceeds its size limit"
        );
        let response = self.transport.exchange(&request).await?;
        ensure!(
            response.len() <= crate::framing::MAX_FRAME_BYTES,
            "owner response exceeds its size limit"
        );
        Ok(serde_json::from_str(&response)?)
    }
}

#[cfg(test)]
#[path = "owner_connection_test.rs"]
mod tests;
