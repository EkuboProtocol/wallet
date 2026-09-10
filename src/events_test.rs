use super::*;

fn change(index: usize) -> DomainEventKind {
    DomainEventKind::AgentConnectionChanged {
        active_connections: index,
    }
}

#[tokio::test]
async fn initial_cursor_keeps_changes_made_during_snapshot_capture() {
    let bus = EventBus::default();
    bus.publish(change(1));
    let initial = bus.wait_since(None).await.unwrap();
    assert!(initial.refresh_required);
    assert!(initial.events.is_empty());
    bus.publish(change(2));
    let batch = bus.wait_since(Some(initial.cursor)).await.unwrap();
    assert!(!batch.refresh_required);
    assert_eq!(batch.events.len(), 1);
    assert_eq!(batch.events[0].kind, change(2));
    // A second desktop can read the same cursor independently; one consumer
    // cannot drain another's notifications.
    assert_eq!(bus.wait_since(Some(initial.cursor)).await.unwrap(), batch);
}

#[tokio::test]
async fn long_poll_wakes_on_publish_and_cancellation_releases_capacity() {
    let bus = EventBus::default();
    let initial = bus.wait_since(None).await.unwrap();
    let waiting = bus.clone();
    let task = tokio::spawn(async move { waiting.wait_since(Some(initial.cursor)).await });
    tokio::task::yield_now().await;
    assert_eq!(bus.shared.waiters.available_permits(), 63);
    bus.publish(change(3));
    let batch = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(batch.events[0].kind, change(3));
    let waiting = bus.clone();
    let task = tokio::spawn(async move { waiting.wait_since(Some(batch.cursor)).await });
    tokio::task::yield_now().await;
    assert_eq!(bus.shared.waiters.available_permits(), 63);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(bus.shared.waiters.available_permits(), 64);
    let capacity = bus.shared.waiters.acquire_many(64).await.unwrap();
    assert!(bus.wait_since(None).await.is_err());
    drop(capacity);
    assert!(bus.wait_since(None).await.is_ok());
}

#[tokio::test]
async fn evicted_foreign_and_future_cursors_require_a_refresh() {
    let bus = EventBus::default();
    let old = bus.wait_since(None).await.unwrap().cursor;
    for index in 0..=MAX_EVENTS {
        bus.publish(change(index));
    }
    assert!(bus.wait_since(Some(old)).await.unwrap().refresh_required);
    let foreign = EventCursor {
        epoch: Uuid::new_v4(),
        sequence: 1,
    };
    assert!(
        bus.wait_since(Some(foreign))
            .await
            .unwrap()
            .refresh_required
    );
    let future = EventCursor {
        epoch: old.epoch,
        sequence: u64::MAX,
    };
    assert!(bus.wait_since(Some(future)).await.unwrap().refresh_required);
    let restarted = EventBus::default();
    assert!(
        restarted
            .wait_since(Some(old))
            .await
            .unwrap()
            .refresh_required
    );
}

#[tokio::test]
async fn bounded_batches_keep_order_and_do_not_skip_the_unreturned_tail() {
    let bus = EventBus::default();
    let start = bus.wait_since(None).await.unwrap().cursor;
    let mut local = bus.subscribe();
    for index in 0..(MAX_BATCH_EVENTS + 3) {
        bus.publish(change(index));
    }
    let first = bus.wait_since(Some(start)).await.unwrap();
    assert_eq!(first.events.len(), MAX_BATCH_EVENTS);
    let second = bus.wait_since(Some(first.cursor)).await.unwrap();
    assert_eq!(second.events.len(), 3);
    for (index, event) in first.events.iter().chain(&second.events).enumerate() {
        assert_eq!(event.kind, change(index));
        assert_eq!(local.recv().await.unwrap(), *event);
    }
    assert_eq!(second.cursor.sequence, (MAX_BATCH_EVENTS + 3) as u64);
}

#[tokio::test]
async fn oversized_notifications_and_sequence_rollover_cannot_hide_a_gap() {
    let bus = EventBus::default();
    let before = bus.wait_since(None).await.unwrap().cursor;
    bus.publish(DomainEventKind::WalletConnectProposed {
        session_id: "test".into(),
        dapp: "x".repeat(MAX_JOURNAL_BYTES + 1),
    });
    assert!(bus.wait_since(Some(before)).await.unwrap().refresh_required);
    assert_eq!(bus.shared.journal.lock().unwrap().bytes, 0);
    let reset = bus.wait_since(None).await.unwrap().cursor;
    bus.publish(change(1));
    assert_eq!(bus.wait_since(Some(reset)).await.unwrap().events.len(), 1);
    bus.shared.journal.lock().unwrap().cursor.sequence = u64::MAX;
    bus.publish(change(2));
    let rollover = bus.wait_since(Some(reset)).await.unwrap();
    assert!(rollover.refresh_required);
    assert_ne!(rollover.cursor.epoch, reset.epoch);
    assert_eq!(rollover.cursor.sequence, 1);
}

#[tokio::test]
async fn byte_budget_evicts_history_before_the_event_count_limit() {
    let bus = EventBus::default();
    let before = bus.wait_since(None).await.unwrap().cursor;
    for index in 0..4 {
        bus.publish(DomainEventKind::WalletConnectProposed {
            session_id: index.to_string(),
            dapp: "x".repeat(MAX_JOURNAL_BYTES / 3),
        });
    }
    assert!(bus.wait_since(Some(before)).await.unwrap().refresh_required);
    let journal = bus.shared.journal.lock().unwrap();
    assert!(journal.bytes <= MAX_JOURNAL_BYTES);
    assert!(journal.entries.len() < 4);
}
