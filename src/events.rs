use anyhow::{Context as _, Result};
use chrono::Utc;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Semaphore, broadcast, watch};
use uuid::Uuid;

pub use ekubo_wallet_client::events::{
    DomainEvent, DomainEventKind, EventBatch, EventCursor, SignatureKind, SignatureStage,
    TransactionStage,
};

const MAX_EVENTS: usize = 512;
const MAX_JOURNAL_BYTES: usize = 1024 * 1024;
const MAX_BATCH_EVENTS: usize = 128;
const POLL_TIMEOUT: Duration = Duration::from_secs(10);

struct Journal {
    cursor: EventCursor,
    entries: VecDeque<(u64, DomainEvent, usize)>,
    bytes: usize,
}

impl Journal {
    fn publish(&mut self, event: &DomainEvent) {
        if self.cursor.sequence == u64::MAX {
            self.cursor = EventCursor {
                epoch: Uuid::new_v4(),
                sequence: 0,
            };
            self.entries.clear();
            self.bytes = 0;
        }
        self.cursor.sequence += 1;
        // Oversized events are still delivered locally as before. Remote
        // consumers must refresh instead of silently missing the invalidation.
        let size = serde_json::to_vec(event).map_or(usize::MAX, |bytes| bytes.len());
        if size > MAX_JOURNAL_BYTES {
            self.entries.clear();
            self.bytes = 0;
            return;
        }
        self.entries
            .push_back((self.cursor.sequence, event.clone(), size));
        self.bytes += size;
        while self.entries.len() > MAX_EVENTS || self.bytes > MAX_JOURNAL_BYTES {
            let (_, _, removed) = self.entries.pop_front().expect("nonempty journal");
            self.bytes -= removed;
        }
    }

    fn batch(&self, after: Option<EventCursor>) -> EventBatch {
        let oldest = self
            .entries
            .front()
            .map_or(self.cursor.sequence, |(sequence, _, _)| sequence - 1);
        let Some(after) = after.filter(|after| {
            after.epoch == self.cursor.epoch
                && after.sequence >= oldest
                && after.sequence <= self.cursor.sequence
        }) else {
            return EventBatch {
                cursor: self.cursor,
                refresh_required: true,
                events: Vec::new(),
            };
        };
        let mut cursor = after;
        let events = self
            .entries
            .iter()
            .filter(|(sequence, _, _)| *sequence > after.sequence)
            .take(MAX_BATCH_EVENTS)
            .map(|(sequence, event, _)| {
                cursor.sequence = *sequence;
                event.clone()
            })
            .collect();
        EventBatch {
            cursor,
            refresh_required: false,
            events,
        }
    }
}

struct Shared {
    journal: Mutex<Journal>,
    changed: watch::Sender<EventCursor>,
    sender: broadcast::Sender<DomainEvent>,
    waiters: Semaphore,
}

#[derive(Clone)]
pub struct EventBus {
    shared: Arc<Shared>,
}

impl Default for EventBus {
    fn default() -> Self {
        let cursor = EventCursor {
            epoch: Uuid::new_v4(),
            sequence: 0,
        };
        let (changed, _) = watch::channel(cursor);
        let (sender, _) = broadcast::channel(MAX_EVENTS);
        Self {
            shared: Arc::new(Shared {
                journal: Mutex::new(Journal {
                    cursor,
                    entries: VecDeque::new(),
                    bytes: 0,
                }),
                changed,
                sender,
                waiters: Semaphore::new(64),
            }),
        }
    }
}

impl EventBus {
    pub fn publish(&self, kind: DomainEventKind) {
        let event = DomainEvent {
            occurred_at: Utc::now(),
            kind,
        };
        let mut journal = self.shared.journal.lock().expect("event journal poisoned");
        journal.publish(&event);
        self.shared.changed.send_replace(journal.cursor);
        // Keep journal and local subscriber order identical under concurrent
        // publishers. No receiver or external code runs under this lock.
        let _ = self.shared.sender.send(event);
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<DomainEvent> {
        self.shared.sender.subscribe()
    }

    fn batch(&self, after: Option<EventCursor>) -> EventBatch {
        self.shared
            .journal
            .lock()
            .expect("event journal poisoned")
            .batch(after)
    }

    /// Bounded long poll for authenticated owner IPC. Capture a snapshot after
    /// an initial/reset batch, then resume from that batch's cursor so changes
    /// made during the capture are retained. Cancellation holds no server cursor.
    pub async fn wait_since(&self, after: Option<EventCursor>) -> Result<EventBatch> {
        let _permit = self
            .shared
            .waiters
            .try_acquire()
            .context("too many event waiters")?;
        // Subscribe before reading: a publisher between the read and wait must
        // wake this call, even if nobody was subscribed when it published.
        let mut changed = self.shared.changed.subscribe();
        let initial = self.batch(after);
        if initial.refresh_required || !initial.events.is_empty() {
            return Ok(initial);
        }
        let _ = tokio::time::timeout(POLL_TIMEOUT, changed.changed()).await;
        Ok(self.batch(after))
    }
}

#[cfg(test)]
#[path = "events_test.rs"]
mod tests;
