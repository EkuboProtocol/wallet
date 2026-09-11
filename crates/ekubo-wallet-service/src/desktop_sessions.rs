//! Tie automatic execution to live, authenticated desktop connections.
//! A running OS service alone must not start the user's automations.

use crate::{config::ConfigStore, events::EventBus};
use anyhow::{Context as _, Result};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(crate) struct DesktopSessions {
    active: watch::Sender<usize>,
    slots: Arc<Semaphore>,
    period: Arc<Mutex<Option<CancellationToken>>>,
}

impl Default for DesktopSessions {
    fn default() -> Self {
        let (active, _) = watch::channel(0);
        Self {
            active,
            slots: Arc::new(Semaphore::new(32)),
            period: Arc::default(),
        }
    }
}

/// Bounded admission before the adapter finishes authenticating its connection.
#[must_use = "dropping the reservation releases admission capacity"]
pub struct ReservedSession {
    active: watch::Sender<usize>,
    slot: OwnedSemaphorePermit,
    period: Arc<Mutex<Option<CancellationToken>>>,
}

impl ReservedSession {
    /// The platform adapter must establish caller identity and subscribe to
    /// disconnect before activating. Keeping a reservation does not run jobs.
    pub fn activate(self) -> ActiveSession {
        let mut period = self.period.lock().expect("desktop period poisoned");
        if period.is_none() {
            *period = Some(CancellationToken::new());
        }
        self.active.send_modify(|count| *count += 1);
        drop(period);
        ActiveSession {
            active: self.active,
            _slot: self.slot,
            period: self.period,
        }
    }
}

/// An authenticated desktop lifetime. Drop it when the connection ends, the
/// request is cancelled, or the platform host shuts down.
#[must_use = "dropping the session stops its contribution to desktop activity"]
pub struct ActiveSession {
    active: watch::Sender<usize>,
    _slot: OwnedSemaphorePermit,
    period: Arc<Mutex<Option<CancellationToken>>>,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        let mut period = self.period.lock().expect("desktop period poisoned");
        self.active.send_modify(|count| {
            *count -= 1;
            if *count == 0
                && let Some(ended) = period.take()
            {
                ended.cancel();
            }
        });
    }
}

impl DesktopSessions {
    /// A child of this exact active period. A zero-to-one transition creates a
    /// new parent; quick reopen cannot revive connections from the prior run.
    pub(crate) fn agent_period(&self) -> Result<CancellationToken> {
        self.period
            .lock()
            .expect("desktop period poisoned")
            .as_ref()
            .map(CancellationToken::child_token)
            .context("no desktop session is active")
    }

    pub(crate) fn activity(&self) -> watch::Receiver<usize> {
        self.active.subscribe()
    }

    pub(crate) fn reserve(&self) -> Result<ReservedSession> {
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .context("too many desktop sessions")?;
        Ok(ReservedSession {
            active: self.active.clone(),
            slot,
            period: self.period.clone(),
        })
    }

    pub(crate) async fn supervise(&self, config: ConfigStore, events: EventBus) -> Result<()> {
        let mut active = self.active.subscribe();
        loop {
            if *active.borrow_and_update() == 0 {
                active
                    .changed()
                    .await
                    .context("desktop session monitor stopped")?;
                continue;
            }
            let execution = crate::automation_runtime::run(config.clone(), events.clone());
            tokio::pin!(execution);
            loop {
                tokio::select! {
                    result = &mut execution => return result,
                    change = active.changed() => {
                        change.context("desktop session monitor stopped")?;
                        if *active.borrow_and_update() == 0 {
                            break;
                        }
                    }
                }
            }
            // Last desktop disconnected: drop the driver before waiting for
            // another session. The next session reopens current protected state.
        }
    }
}

#[cfg(test)]
#[path = "desktop_sessions_test.rs"]
mod tests;
