use super::*;
use tokio::io::AsyncWriteExt as _;

#[tokio::test]
async fn buffered_traffic_wins_over_a_ready_operation_and_cannot_be_replayed() {
    let (mut peer, reader) = tokio::io::duplex(16);
    peer.write_all(b"x").await.unwrap();
    let mut monitor = OwnerCallMonitor::new(reader);
    let binding = monitor.binding();
    let polled = AtomicBool::new(false);
    for _ in 0..2 {
        assert!(
            monitor
                .run(async {
                    polled.store(true, Ordering::Release);
                    Ok(())
                })
                .await
                .is_err()
        );
    }
    assert!(!polled.load(Ordering::Acquire));
    assert!(binding.ensure_live().is_err());
}

#[tokio::test]
async fn operation_completion_rechecks_transport_before_response_phase() {
    let (mut peer, reader) = tokio::io::duplex(16);
    let mut monitor = OwnerCallMonitor::new(reader);
    let result = monitor
        .run(async {
            peer.write_all(b"x").await?;
            Ok(())
        })
        .await;
    assert!(result.is_err());
    assert!(monitor.binding().ensure_live().is_err());
}

struct PendingOperation {
    binding: OwnerCallBinding,
    revoked_on_drop: Arc<AtomicBool>,
}
impl Future for PendingOperation {
    type Output = Result<()>;
    fn poll(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
impl Drop for PendingOperation {
    fn drop(&mut self) {
        self.revoked_on_drop
            .store(self.binding.ensure_live().is_err(), Ordering::Release);
    }
}

#[tokio::test]
async fn cancelling_a_phase_revokes_before_dropping_the_operation() {
    let (_peer, reader) = tokio::io::duplex(16);
    let mut monitor = OwnerCallMonitor::new(reader);
    let binding = monitor.binding();
    let revoked = Arc::new(AtomicBool::new(false));
    let mut phase = Box::pin(monitor.run(PendingOperation {
        binding: binding.clone(),
        revoked_on_drop: revoked.clone(),
    }));
    assert!(futures::poll!(&mut phase).is_pending());
    drop(phase);
    assert!(revoked.load(Ordering::Acquire));
    assert!(binding.ensure_live().is_err());
    assert!(monitor.run(async { Ok(()) }).await.is_err());
}

#[tokio::test]
async fn eof_and_monitor_drop_invalidate_retained_bindings() {
    let (peer, reader) = tokio::io::duplex(16);
    let mut monitor = OwnerCallMonitor::new(reader);
    let binding = monitor.binding();
    drop(peer);
    assert!(monitor.run(async { Ok(()) }).await.is_err());
    assert!(binding.ensure_live().is_err());
    let (_other_peer, reader) = tokio::io::duplex(16);
    let mut other = OwnerCallMonitor::new(reader);
    let other_binding = other.binding();
    assert!(!binding.same_call(&other_binding));
    other.run(async { Ok(()) }).await.unwrap();
    other_binding.ensure_live().unwrap();
    drop(other);
    assert!(other_binding.ensure_live().is_err());
}
