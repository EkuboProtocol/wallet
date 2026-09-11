//! Shared service lifecycle. Platform hosts establish protected custody and
//! authenticated transports before using it; this is not an OS boundary itself.

use crate::{
    authority::{AgentApi, ApplicationAuthority},
    dapp_reviews::DappReviews,
    dapp_runtime::DappRuntime,
    desktop_sessions::DesktopSessions,
    events::EventBus,
    owner_rpc::OwnerDispatcher,
};
use anyhow::Result;
use std::sync::Arc;

pub use crate::desktop_sessions::{
    ActiveSession as ActiveDesktopSession, ReservedSession as ReservedDesktopSession,
};

pub struct ServiceRuntime {
    authority: ApplicationAuthority,
    sessions: DesktopSessions,
    pub(crate) owner: OwnerDispatcher,
    dapps: Arc<DappRuntime>,
}

pub(crate) struct ServiceAgentConnection {
    agent: AgentApi,
    events: EventBus,
    stopped: tokio_util::sync::CancellationToken,
}

impl ServiceAgentConnection {
    pub(crate) async fn serve<S>(
        self,
        stream: S,
        active: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        crate::mcp_transport::serve_connection(
            stream,
            self.agent,
            active,
            self.events,
            self.stopped,
        )
        .await
    }
}

impl ServiceRuntime {
    /// Accept only authority opened after the platform's identity and custody
    /// bootstrap. No local-store fallback or platform selection occurs here.
    #[must_use]
    pub fn new(authority: ApplicationAuthority) -> Self {
        let sessions = DesktopSessions::default();
        let dapps = Arc::new(DappRuntime::new(
            authority.owner_api(),
            DappReviews::default(),
            sessions.activity(),
        ));
        let owner = OwnerDispatcher::new(authority.owner_api(), dapps.clone());
        Self {
            authority,
            sessions,
            owner,
            dapps,
        }
    }

    #[cfg(test)]
    pub(crate) fn agent_api(&self) -> AgentApi {
        self.authority.agent_api()
    }

    pub(crate) fn agent_connection(&self) -> Result<ServiceAgentConnection> {
        Ok(ServiceAgentConnection {
            stopped: self.sessions.agent_period()?,
            agent: self.authority.agent_api(),
            events: self.events(),
        })
    }

    #[must_use]
    pub fn events(&self) -> EventBus {
        self.authority.events()
    }

    /// Reserve bounded capacity without activating jobs. An OS adapter must
    /// authenticate its caller and monitor disconnection before activation.
    pub fn reserve_desktop(&self) -> Result<ReservedDesktopSession> {
        self.sessions.reserve()
    }

    /// Run one scheduler and dapp supervisor, gated by the same desktop leases.
    /// Host shutdown must drop this future before closing endpoints and jobs.
    pub async fn supervise(&self) -> Result<()> {
        let owner = self.authority.owner_api();
        tokio::select! {
            finished = self.sessions.supervise(owner.config().clone(), self.events()) => {
                Err(finished.err().unwrap_or_else(|| {
                    anyhow::anyhow!("automation supervisor unexpectedly stopped")
                }))
            }
            finished = self.dapps.supervise() => {
                Err(finished.err().unwrap_or_else(|| {
                    anyhow::anyhow!("dapp supervisor unexpectedly stopped")
                }))
            }
        }
    }

    /// Close reviews before the platform tears down its authenticated endpoint.
    pub fn close_owner_reviews(&self) -> Result<()> {
        self.owner.shutdown()
    }

    /// Called after supervisor cancellation and transport/request drainage.
    pub async fn shutdown_dapps(&self) -> Result<()> {
        self.dapps.shutdown().await
    }
}

#[cfg(test)]
#[path = "runtime_test.rs"]
mod tests;
