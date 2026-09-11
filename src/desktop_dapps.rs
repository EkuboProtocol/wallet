//! `WalletConnect` sessions through one selected desktop backend. Service-backed
//! instances contain no local manager, session worker, or dapp authority.

use crate::{
    authority::OwnerApi,
    desktop_dapp_review::DesktopDappPrompt,
    walletconnect::{
        ProposalPresenter, ProposalPrompt, SessionSummary, WalletConnectManager, run_session,
    },
};
use anyhow::{Context as _, Result, ensure};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub enum DappProposalUpdate {
    Changed(Vec<DesktopDappPrompt>),
    Failed(String),
}

#[derive(Clone)]
pub struct DesktopDapps {
    backend: Backend,
    closed: Arc<AtomicBool>,
}

#[derive(Clone)]
enum Backend {
    Local {
        owner: OwnerApi,
        manager: Arc<Mutex<WalletConnectManager>>,
        presenter: ProposalPresenter,
    },
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    Service(ekubo_wallet_client::OwnerClient),
}

pub struct StartedDappSession {
    pub summary: SessionSummary,
    completion: Completion,
}

enum Completion {
    Local(tokio::task::JoinHandle<Result<()>>),
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    Service(ekubo_wallet_client::OwnerClient),
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "windows")),
    allow(
        clippy::match_single_binding,
        reason = "only the local backend exists on this platform"
    )
)]
impl DesktopDapps {
    #[must_use]
    pub fn local(
        owner: OwnerApi,
        manager: Arc<Mutex<WalletConnectManager>>,
        presenter: ProposalPresenter,
    ) -> Self {
        Self {
            backend: Backend::Local {
                owner,
                manager,
                presenter,
            },
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[must_use]
    pub fn service(owner: ekubo_wallet_client::OwnerClient) -> Self {
        Self {
            backend: Backend::Service(owner),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Stop new local registrations before draining the same manager. For a
    /// service, close the owner transport and its desktop lease; the resident
    /// service then cancels its sessions and can finish relay farewells after
    /// the desktop has exited.
    pub async fn shutdown(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        match &self.backend {
            Backend::Local { manager, .. } => {
                let farewells = manager
                    .lock()
                    .map_err(|_| anyhow::anyhow!("WalletConnect session state is unavailable"))?
                    .disconnect_all();
                futures::future::join_all(farewells.iter().map(CancellationToken::cancelled)).await;
                Ok(())
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Backend::Service(owner) => owner.close().await,
        }
    }

    /// One application-lifetime feed. The service path never consumes a local
    /// proposal channel or receives a native authorization capability.
    pub async fn run_proposals(
        &self,
        local: tokio::sync::mpsc::UnboundedReceiver<ProposalPrompt>,
        updates: tokio::sync::mpsc::Sender<DappProposalUpdate>,
    ) {
        let result = match &self.backend {
            Backend::Local { owner, .. } => {
                local_proposals(local, owner.event_bus(), &updates).await
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Backend::Service(owner) => {
                drop(local);
                service_dapp_proposals::run(owner, &updates).await
            }
        };
        if let Err(error) = result {
            let update = if self.closed.load(Ordering::SeqCst) {
                DappProposalUpdate::Changed(Vec::new())
            } else {
                DappProposalUpdate::Failed(format!("WalletConnect reviews unavailable: {error:#}"))
            };
            let _ = updates.send(update).await;
        }
    }

    pub async fn sessions(&self) -> Result<Vec<SessionSummary>> {
        match &self.backend {
            Backend::Local { manager, .. } => Ok(manager
                .lock()
                .map_err(|_| anyhow::anyhow!("WalletConnect session state is unavailable"))?
                .sessions()),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Backend::Service(owner) => owner.dapp_sessions().await,
        }
    }

    pub async fn disconnect(&self, session_id: Uuid) -> Result<SessionSummary> {
        match &self.backend {
            Backend::Local { manager, owner, .. } => {
                let summary = manager
                    .lock()
                    .map_err(|_| anyhow::anyhow!("WalletConnect session state is unavailable"))?
                    .disconnect(session_id)?;
                owner
                    .event_bus()
                    .publish(crate::events::DomainEventKind::WalletConnectChanged {
                        session_id: session_id.to_string(),
                    });
                Ok(summary)
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Backend::Service(owner) => owner.disconnect_dapp_session(session_id).await,
        }
    }

    /// Cancellation before registration spends no link. Once registration is
    /// in flight, await its result and disconnect a canceled session by its
    /// returned ID. Never replay a start after an ambiguous transport error.
    pub async fn begin(
        &self,
        uri: &str,
        cancel: &CancellationToken,
    ) -> Result<Option<StartedDappSession>> {
        if cancel.is_cancelled() || self.closed.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let started = self.start(uri).await?;
        self.finish_start(started, cancel).await
    }

    async fn finish_start(
        &self,
        started: StartedDappSession,
        cancel: &CancellationToken,
    ) -> Result<Option<StartedDappSession>> {
        if self.closed.load(Ordering::SeqCst) {
            // Local shutdown already removed all registered sessions. A remote
            // desktop lease is closing, so its service owns cancellation.
            return Ok(None);
        }
        if cancel.is_cancelled() {
            self.disconnect(started.summary.id).await?;
            Ok(None)
        } else {
            Ok(Some(started))
        }
    }

    async fn start(&self, uri: &str) -> Result<StartedDappSession> {
        match &self.backend {
            Backend::Local {
                owner,
                manager,
                presenter,
            } => {
                let runtime = tokio::runtime::Handle::try_current()
                    .context("WalletConnect runtime is unavailable")?;
                let (start, summary) = {
                    let mut manager = manager.lock().map_err(|_| {
                        anyhow::anyhow!("WalletConnect session state is unavailable")
                    })?;
                    ensure!(
                        !self.closed.load(Ordering::SeqCst),
                        "WalletConnect is shutting down"
                    );
                    manager.begin_uri(uri)?
                };
                let events = owner.event_bus();
                events.publish(crate::events::DomainEventKind::WalletConnectChanged {
                    session_id: start.id.to_string(),
                });
                let dapp = owner.dapp_api();
                let manager = manager.clone();
                let presenter = presenter.clone();
                let completion = tokio::task::spawn_blocking(move || {
                    runtime.block_on(run_session(start, dapp, presenter, manager, events))
                });
                Ok(StartedDappSession {
                    summary,
                    completion: Completion::Local(completion),
                })
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Backend::Service(owner) => Ok(StartedDappSession {
                summary: owner.begin_dapp_session(uri).await?,
                completion: Completion::Service(owner.clone()),
            }),
        }
    }
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "windows")),
    allow(
        clippy::match_single_binding,
        reason = "only the local backend exists on this platform"
    )
)]
impl StartedDappSession {
    pub async fn wait(self) -> Result<()> {
        match self.completion {
            Completion::Local(task) => task.await.context("WalletConnect session task failed")?,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Completion::Service(owner) => owner.wait_dapp_session(self.summary.id).await,
        }
    }
}

async fn local_proposals(
    mut incoming: tokio::sync::mpsc::UnboundedReceiver<ProposalPrompt>,
    events: crate::events::EventBus,
    updates: &tokio::sync::mpsc::Sender<DappProposalUpdate>,
) -> Result<()> {
    let mut events = events.subscribe();
    loop {
        let prompts = tokio::select! {
            prompt = incoming.recv() => {
                let Some(prompt) = prompt else { return Ok(()); };
                vec![DesktopDappPrompt::local(prompt)]
            }
            event = events.recv() => {
                match event {
                    Ok(event) if matches!(event.kind, crate::events::DomainEventKind::WalletConnectChanged { .. }) => {},
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                    _ => continue,
                }
                Vec::new()
            }
        };
        updates
            .send(DappProposalUpdate::Changed(prompts))
            .await
            .map_err(|_| anyhow::anyhow!("WalletConnect review UI is unavailable"))?;
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
#[path = "service_dapp_proposals.rs"]
mod service_dapp_proposals;

#[cfg(test)]
#[path = "desktop_dapps_test.rs"]
mod tests;
