//! `WalletConnect` execution under service authority. Session workers receive
//! only `DappApi`; owner authentication remains in the review broker/RPC task.

use crate::{
    authority::{DappApi, OwnerApi},
    dapp_reviews::DappReviews,
    events::{DomainEventKind, EventBus},
    walletconnect::{SessionStart, SessionSummary, WalletConnectManager, run_session},
    walletconnect_review::{ProposalPresenter, ProposalPrompt},
};
use anyhow::{Context as _, Result, ensure};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type Outcome = std::result::Result<(), String>;

struct SessionWorker {
    start: SessionStart,
    dapp: DappApi,
    presenter: ProposalPresenter,
    manager: Arc<Mutex<WalletConnectManager>>,
    events: EventBus,
}

#[derive(Default)]
struct Jobs {
    closed: bool,
    results: BTreeMap<Uuid, watch::Receiver<Option<Outcome>>>,
    workers: JoinSet<()>,
}

pub struct DappRuntime {
    owner: OwnerApi,
    reviews: DappReviews,
    manager: Arc<Mutex<WalletConnectManager>>,
    presenter: ProposalPresenter,
    incoming: Mutex<Option<mpsc::UnboundedReceiver<ProposalPrompt>>>,
    active: watch::Receiver<usize>,
    jobs: Mutex<Jobs>,
}

impl DappRuntime {
    #[must_use]
    pub fn new(owner: OwnerApi, reviews: DappReviews, active: watch::Receiver<usize>) -> Self {
        let (presenter, incoming) = ProposalPresenter::channel();
        Self {
            owner,
            reviews,
            active,
            presenter,
            manager: Arc::new(Mutex::new(WalletConnectManager::default())),
            incoming: Mutex::new(Some(incoming)),
            jobs: Mutex::new(Jobs::default()),
        }
    }

    #[must_use]
    pub const fn reviews(&self) -> &DappReviews {
        &self.reviews
    }

    pub fn sessions(&self) -> Result<Vec<SessionSummary>> {
        Ok(self
            .manager
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp manager lock was poisoned"))?
            .sessions())
    }

    pub fn begin(&self, uri: &str) -> Result<SessionSummary> {
        let handle =
            tokio::runtime::Handle::try_current().context("dapp runtime is unavailable")?;
        self.begin_with(uri, move |worker| {
            handle.block_on(run_session(
                worker.start,
                worker.dapp,
                worker.presenter,
                worker.manager,
                worker.events,
            ))
        })
    }

    fn begin_with(
        &self,
        uri: &str,
        run: impl FnOnce(SessionWorker) -> Result<()> + Send + 'static,
    ) -> Result<SessionSummary> {
        ensure!(*self.active.borrow() > 0, "no desktop session is active");
        let dapp = self.owner.dapp_api();
        dapp.require_legal_acceptance()?;
        ensure!(
            !dapp.accounts()?.is_empty(),
            "create an account before connecting a dapp"
        );
        let mut jobs = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp worker lock was poisoned"))?;
        ensure!(!jobs.closed, "dapp runtime is closed");
        while let Some(result) = jobs.workers.try_join_next() {
            if let Err(error) = result {
                tracing::warn!(%error, "dapp worker stopped unexpectedly");
            }
        }
        if jobs.results.len() >= 64 {
            jobs.results.retain(|_, result| result.borrow().is_none());
        }
        ensure!(
            jobs.results.len() < 64,
            "too many outstanding dapp session results"
        );
        let (start, summary) = self
            .manager
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp manager lock was poisoned"))?
            .begin_uri(uri)?;
        // Close the race with the last desktop departing during registration.
        if *self.active.borrow() == 0 {
            self.manager
                .lock()
                .map_err(|_| anyhow::anyhow!("dapp manager lock was poisoned"))?
                .disconnect(start.id)?;
            anyhow::bail!("no desktop session is active");
        }
        let id = start.id;
        let (complete, result) = watch::channel(None);
        jobs.results.insert(id, result);
        let manager = self.manager.clone();
        let presenter = self.presenter.clone();
        let events = self.owner.event_bus();
        jobs.workers.spawn_blocking(move || {
            let result = run(SessionWorker {
                start,
                dapp,
                presenter,
                manager: manager.clone(),
                events: events.clone(),
            });
            if let Ok(mut manager) = manager.lock() {
                match &result {
                    Ok(()) => manager.finish(id),
                    Err(error) => manager.fail(
                        id,
                        crate::sanitize::terminal_safe_line(&format!("{error:#}")),
                    ),
                }
            }
            events.publish(DomainEventKind::WalletConnectChanged {
                session_id: id.to_string(),
            });
            let _ = complete.send(Some(result.map_err(|error| format!("{error:#}"))));
        });
        self.owner
            .event_bus()
            .publish(DomainEventKind::WalletConnectChanged {
                session_id: id.to_string(),
            });
        Ok(summary)
    }

    pub async fn wait(&self, id: Uuid) -> Result<()> {
        let mut result = self
            .jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp worker lock was poisoned"))?
            .results
            .get(&id)
            .cloned()
            .context("unknown or expired dapp session result")?;
        loop {
            if let Some(outcome) = result.borrow_and_update().clone() {
                return outcome.map_err(anyhow::Error::msg);
            }
            result
                .changed()
                .await
                .context("dapp worker ended without a result")?;
        }
    }

    pub fn disconnect(&self, id: Uuid) -> Result<SessionSummary> {
        let summary = self
            .manager
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp manager lock was poisoned"))?
            .disconnect(id)?;
        self.owner
            .event_bus()
            .publish(DomainEventKind::WalletConnectChanged {
                session_id: id.to_string(),
            });
        Ok(summary)
    }

    fn cancel_sessions(&self) -> Result<Vec<CancellationToken>> {
        let mut manager = self
            .manager
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp manager lock was poisoned"))?;
        let ids: Vec<_> = manager
            .sessions()
            .into_iter()
            .map(|session| session.id)
            .collect();
        let farewells = manager.disconnect_all();
        for id in ids {
            self.owner
                .event_bus()
                .publish(DomainEventKind::WalletConnectChanged {
                    session_id: id.to_string(),
                });
        }
        Ok(farewells)
    }

    pub async fn supervise(&self) -> Result<()> {
        let incoming = self
            .incoming
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp review channel lock was poisoned"))?
            .take()
            .context("dapp review collector already started")?;
        let collector = self.reviews.collect(incoming, self.owner.event_bus());
        tokio::pin!(collector);
        let mut active = self.active.clone();
        loop {
            if *active.borrow_and_update() == 0 {
                self.cancel_sessions()?;
            }
            tokio::select! {
                () = &mut collector => anyhow::bail!("dapp review collector stopped"),
                change = active.changed() => change.context("desktop session monitor stopped")?,
            }
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.jobs
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp worker lock was poisoned"))?
            .closed = true;
        let farewells = self.cancel_sessions()?;
        self.reviews.shutdown()?;
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            futures::future::join_all(farewells.iter().map(CancellationToken::cancelled)),
        )
        .await;
        let mut workers = std::mem::take(
            &mut self
                .jobs
                .lock()
                .map_err(|_| anyhow::anyhow!("dapp worker lock was poisoned"))?
                .workers,
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(result) = workers.join_next().await {
                result.context("dapp worker failed")?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("dapp workers did not stop")??;
        Ok(())
    }
}

impl Drop for DappRuntime {
    fn drop(&mut self) {
        let _ = self.cancel_sessions();
        let _ = self.reviews.shutdown();
    }
}

#[cfg(test)]
#[path = "dapp_runtime_test.rs"]
mod tests;
