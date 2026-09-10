//! Tie automatic execution to live, authenticated desktop bus connections.
//! A running OS service alone must not start the user's automations.

use crate::{config::ConfigStore, events::EventBus};
use anyhow::{Context as _, Result};
use futures::StreamExt as _;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use zbus::{Connection, fdo::DBusProxy, names::OwnedUniqueName};

#[derive(Clone)]
pub(crate) struct DesktopSessions {
    active: watch::Sender<usize>,
    slots: Arc<Semaphore>,
}

impl Default for DesktopSessions {
    fn default() -> Self {
        let (active, _) = watch::channel(0);
        Self {
            active,
            slots: Arc::new(Semaphore::new(32)),
        }
    }
}

struct ActiveSession {
    active: watch::Sender<usize>,
    _slot: OwnedSemaphorePermit,
}

impl ActiveSession {
    fn new(active: watch::Sender<usize>, slot: OwnedSemaphorePermit) -> Self {
        active.send_modify(|count| *count += 1);
        Self {
            active,
            _slot: slot,
        }
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.active.send_modify(|count| *count -= 1);
    }
}

impl DesktopSessions {
    pub(crate) fn activity(&self) -> watch::Receiver<usize> {
        self.active.subscribe()
    }

    /// Called only inside core's authenticated owner-call context. `sender`
    /// comes from the real message header, never from request parameters.
    pub(crate) async fn hold(&self, bus: &Connection, sender: &OwnedUniqueName) -> Result<()> {
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .context("too many desktop sessions")?;
        let registry = DBusProxy::new(bus).await?;
        // Subscribe before checking liveness, so a departure cannot be lost
        // between accepting the session and beginning to watch it.
        let mut departed = registry
            .receive_name_owner_changed_with_args(&[(0, sender.as_str())])
            .await?;
        registry
            .get_connection_unix_user(sender.clone().into())
            .await?;
        let _session = ActiveSession::new(self.active.clone(), slot);
        while let Some(signal) = departed.next().await {
            let args = signal.args()?;
            if args.name().as_str() == sender.as_str() && args.new_owner().as_ref().is_none() {
                return Ok(());
            }
        }
        anyhow::bail!("desktop session lost its system bus connection")
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
