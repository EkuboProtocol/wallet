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
        let response = self.exchange(request).await?;
        if let Ok(reply) =
            serde_json::from_str::<crate::preview_page::RecordTransferReply>(&response)
        {
            return self.read_pages(reply.owner_record_transfer).await;
        }
        Ok(serde_json::from_str(&response)?)
    }

    async fn exchange(
        &self,
        request: &crate::owner_protocol::Request,
    ) -> Result<Zeroizing<String>> {
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
        Ok(response)
    }

    /// Read a complete record/document using the same bounded transfer as
    /// advisory previews. Never expose a partial document to a decision UI.
    pub(crate) async fn read<R: serde::de::DeserializeOwned>(
        &self,
        request: &crate::owner_protocol::Request,
    ) -> Result<R> {
        let page = self.call(request).await?;
        self.read_pages(page).await
    }

    async fn read_pages<R: serde::de::DeserializeOwned>(
        &self,
        mut page: crate::preview_page::PreviewPage,
    ) -> Result<R> {
        use crate::preview_page::{MAX_EVIDENCE_BYTES, PAGE_BYTES};
        let identity = page.transfer_id;
        let total = page.total_bytes;
        ensure!(
            !identity.is_nil() && total > 0 && total <= MAX_EVIDENCE_BYTES,
            "invalid record transfer size or identity"
        );
        let mut text = Zeroizing::new(String::new());
        loop {
            ensure!(
                page.transfer_id == identity
                    && page.total_bytes == total
                    && page.offset == text.len()
                    && !page.text.is_empty()
                    && page.text.len() <= PAGE_BYTES
                    && page.text.len() <= total.saturating_sub(text.len()),
                "invalid record transfer page"
            );
            text.push_str(&page.text);
            if text.len() == total {
                break;
            }
            let response = self
                .exchange(&crate::owner_protocol::Request::ReadPage {
                    transfer_id: identity,
                    offset: text.len(),
                })
                .await?;
            page = serde_json::from_str(&response)?;
        }
        Ok(serde_json::from_str(&text)?)
    }
}

#[cfg(test)]
#[path = "owner_connection_test.rs"]
mod tests;
