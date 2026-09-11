//! Desktop event subscriptions over the selected authority backend.
//! History loss requests fresh reads; it never invents notification events.

use crate::{desktop_owner::DesktopOwner, events::DomainEvent};
#[cfg(any(target_os = "linux", target_os = "windows", test))]
use anyhow::Context as _;
use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "windows", test))]
use ekubo_wallet_client::events::{EventBatch, EventCursor};
#[cfg(any(target_os = "linux", target_os = "windows", test))]
use std::collections::VecDeque;
use tokio::sync::broadcast;
#[cfg(any(target_os = "linux", target_os = "windows", test))]
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum DesktopEvent {
    Event(DomainEvent),
    Refresh { mcp_online: Option<bool> },
}

pub struct DesktopEvents {
    source: Subscription,
}

enum Subscription {
    Local(broadcast::Receiver<DomainEvent>),
    #[cfg(any(target_os = "linux", target_os = "windows", test))]
    Remote(RemoteEvents),
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
struct RemoteEvents {
    batches: mpsc::Receiver<Result<EventBatch>>,
    pending: VecDeque<DomainEvent>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
impl Drop for RemoteEvents {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DesktopEvents {
    #[must_use]
    pub fn subscribe(owner: &DesktopOwner, runtime: &tokio::runtime::Handle) -> Self {
        let source = match owner {
            DesktopOwner::Local(owner) => Subscription::Local(owner.event_bus().subscribe()),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            DesktopOwner::Service(owner) => {
                Subscription::Remote(RemoteEvents::start(owner.clone(), runtime))
            }
        };
        // macOS has only the local backend, which needs no runtime.
        let _ = runtime;
        Self { source }
    }

    /// May be awaited on GPUI: remote I/O runs exclusively on the supplied Tokio runtime.
    pub async fn recv(&mut self) -> Result<DesktopEvent> {
        match &mut self.source {
            Subscription::Local(events) => match events.recv().await {
                Ok(event) => Ok(DesktopEvent::Event(event)),
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    Ok(DesktopEvent::Refresh { mcp_online: None })
                }
                Err(broadcast::error::RecvError::Closed) => {
                    anyhow::bail!("desktop event stream closed")
                }
            },
            #[cfg(any(target_os = "linux", target_os = "windows", test))]
            Subscription::Remote(events) => events.recv().await,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
trait EventSource: Send + 'static {
    fn wait(
        &self,
        after: Option<EventCursor>,
    ) -> impl std::future::Future<Output = Result<EventBatch>> + Send;
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl EventSource for ekubo_wallet_client::OwnerClient {
    async fn wait(&self, after: Option<EventCursor>) -> Result<EventBatch> {
        self.wait_for_events(after).await
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
impl RemoteEvents {
    fn start(source: impl EventSource, runtime: &tokio::runtime::Handle) -> Self {
        // One queued batch bounds memory and allows history loss to be detected by
        // the service journal when a consumer falls behind. No unbounded relay.
        let (sender, batches) = mpsc::channel(1);
        let task = runtime.spawn(async move {
            let mut cursor = None;
            loop {
                let batch = source.wait(cursor).await;
                let failed = batch.is_err();
                if let Ok(batch) = &batch {
                    cursor = Some(batch.cursor);
                }
                if sender.send(batch).await.is_err() || failed {
                    return;
                }
            }
        });
        Self {
            batches,
            pending: VecDeque::new(),
            task,
        }
    }

    async fn recv(&mut self) -> Result<DesktopEvent> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(DesktopEvent::Event(event));
            }
            let batch = self
                .batches
                .recv()
                .await
                .context("service event stream closed")??;
            if batch.refresh_required {
                anyhow::ensure!(
                    batch.events.is_empty(),
                    "event reset contained historical notifications"
                );
                return Ok(DesktopEvent::Refresh {
                    mcp_online: batch.mcp_online,
                });
            }
            self.pending = batch.events.into();
        }
    }
}

#[cfg(test)]
#[path = "desktop_events_test.rs"]
mod tests;
