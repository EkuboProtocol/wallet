use super::*;
use crate::events::{DomainEventKind, EventBus};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

struct Source {
    replies: Mutex<VecDeque<Result<EventBatch>>>,
    cursors: Arc<Mutex<Vec<Option<EventCursor>>>>,
    dropped: Option<oneshot::Sender<()>>,
}
impl Drop for Source {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}
impl EventSource for Source {
    async fn wait(&self, after: Option<EventCursor>) -> Result<EventBatch> {
        self.cursors.lock().unwrap().push(after);
        let reply = self.replies.lock().unwrap().pop_front();
        match reply {
            Some(reply) => reply,
            None => std::future::pending().await,
        }
    }
}
fn batch(sequence: u64, refresh_required: bool, events: Vec<DomainEvent>) -> EventBatch {
    EventBatch {
        cursor: EventCursor {
            epoch: uuid::Uuid::nil(),
            sequence,
        },
        refresh_required,
        mcp_online: refresh_required.then_some(true),
        events,
    }
}
fn event() -> DomainEvent {
    DomainEvent {
        occurred_at: chrono::DateTime::from_timestamp(1, 0).unwrap(),
        kind: DomainEventKind::ConfigurationChanged,
    }
}

#[tokio::test]
async fn service_resets_refresh_without_replaying_and_preserve_event_order_and_time() {
    let expected = event();
    let cursors = Arc::new(Mutex::new(Vec::new()));
    let mut events = RemoteEvents::start(
        Source {
            replies: Mutex::new(VecDeque::from([
                Ok(batch(10, true, vec![])),
                Ok(batch(11, false, vec![expected.clone()])),
                Ok(batch(20, true, vec![])),
                Err(anyhow::anyhow!("synthetic disconnect")),
            ])),
            cursors: cursors.clone(),
            dropped: None,
        },
        &tokio::runtime::Handle::current(),
    );
    assert!(matches!(
        events.recv().await.unwrap(),
        DesktopEvent::Refresh {
            mcp_online: Some(true)
        }
    ));
    let DesktopEvent::Event(received) = events.recv().await.unwrap() else {
        panic!("expected event")
    };
    assert_eq!(received, expected);
    assert!(matches!(
        events.recv().await.unwrap(),
        DesktopEvent::Refresh {
            mcp_online: Some(true)
        }
    ));
    assert!(
        events
            .recv()
            .await
            .unwrap_err()
            .to_string()
            .contains("synthetic disconnect")
    );
    assert!(events.recv().await.is_err());
    assert_eq!(
        *cursors.lock().unwrap(),
        vec![
            None,
            Some(batch(10, true, vec![]).cursor),
            Some(batch(11, false, vec![]).cursor),
            Some(batch(20, true, vec![]).cursor)
        ]
    );
}

#[tokio::test]
async fn dropping_the_subscription_cancels_its_pending_remote_read() {
    let (dropped, finished) = oneshot::channel();
    let events = DesktopEvents {
        source: Subscription::Remote(RemoteEvents::start(
            Source {
                replies: Mutex::new(VecDeque::new()),
                cursors: Arc::default(),
                dropped: Some(dropped),
            },
            &tokio::runtime::Handle::current(),
        )),
    };
    tokio::task::yield_now().await;
    drop(events);
    tokio::time::timeout(std::time::Duration::from_secs(1), finished)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn local_lag_requests_a_refresh_and_subsequent_events_remain_usable() {
    let bus = EventBus::default();
    let mut events = DesktopEvents {
        source: Subscription::Local(bus.subscribe()),
    };
    for _ in 0..2048 {
        bus.publish(DomainEventKind::ConfigurationChanged);
    }
    assert!(matches!(
        events.recv().await.unwrap(),
        DesktopEvent::Refresh { .. }
    ));
    assert!(matches!(
        events.recv().await.unwrap(),
        DesktopEvent::Event(_)
    ));
}

#[tokio::test]
async fn reset_batches_cannot_inject_historical_notifications() {
    let mut events = RemoteEvents::start(
        Source {
            replies: Mutex::new(VecDeque::from([Ok(batch(1, true, vec![event()]))])),
            cursors: Arc::default(),
            dropped: None,
        },
        &tokio::runtime::Handle::current(),
    );
    assert!(events.recv().await.is_err());
}
