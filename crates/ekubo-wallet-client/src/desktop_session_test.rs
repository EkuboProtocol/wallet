use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Transport {
    entered: watch::Sender<bool>,
    acknowledged: watch::Receiver<bool>,
    release: watch::Receiver<bool>,
    closed: Arc<AtomicUsize>,
    fail_hold: bool,
    fail_close: bool,
}
impl SessionTransport for Transport {
    async fn hold(&self, ready: oneshot::Sender<()>) -> Result<()> {
        self.entered.send_replace(true);
        self.acknowledged.clone().wait_for(|ready| *ready).await?;
        let _ = ready.send(());
        let mut release = self.release.clone();
        release.changed().await?;
        anyhow::ensure!(!self.fail_hold, "synthetic lease failure");
        Ok(())
    }
    async fn close(&self) -> Result<()> {
        tokio::task::yield_now().await;
        self.closed.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(!self.fail_close, "synthetic close failure");
        Ok(())
    }
}

fn transport(
    fail_hold: bool,
    fail_close: bool,
) -> (
    Transport,
    watch::Receiver<bool>,
    watch::Sender<bool>,
    Arc<AtomicUsize>,
    watch::Sender<bool>,
) {
    let (entered, waiting) = watch::channel(false);
    let (release, held) = watch::channel(false);
    let (acknowledge, acknowledged) = watch::channel(true);
    let closed = Arc::new(AtomicUsize::new(0));
    (
        Transport {
            entered,
            acknowledged,
            release: held,
            closed: closed.clone(),
            fail_hold,
            fail_close,
        },
        waiting,
        release,
        closed,
        acknowledge,
    )
}

async fn ended(state: &mut watch::Receiver<SessionState>) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if matches!(
                *state.borrow_and_update(),
                SessionState::Closed | SessionState::Failed(_)
            ) {
                break;
            }
            state.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_quit_and_drop_both_close_the_transport() {
    for explicit in [true, false] {
        let (transport, mut entered, _release, closed, _ready) = transport(false, false);
        let session = DesktopSession::start(transport);
        let mut state = session.state();
        entered.changed().await.unwrap();
        if explicit {
            session.close().await.unwrap();
        } else {
            drop(session);
        }
        ended(&mut state).await;
        assert_eq!(*state.borrow(), SessionState::Closed);
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn unexpected_lease_completion_closes_and_reports_failure_without_restart() {
    for fail_hold in [false, true] {
        let (transport, mut entered, release, closed, _ready) = transport(fail_hold, false);
        let session = DesktopSession::start(transport);
        let mut state = session.state();
        entered.changed().await.unwrap();
        release.send_replace(true);
        ended(&mut state).await;
        assert!(matches!(*state.borrow(), SessionState::Failed(_)));
        assert!(session.close().await.is_err());
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn close_failure_is_reported_instead_of_claiming_a_released_session() {
    let (transport, mut entered, _release, closed, _ready) = transport(false, true);
    let session = DesktopSession::start(transport);
    let state = session.state();
    entered.changed().await.unwrap();
    assert!(
        session
            .close()
            .await
            .unwrap_err()
            .to_string()
            .contains("synthetic close failure")
    );
    assert!(matches!(*state.borrow(), SessionState::Failed(_)));
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn starting_is_not_ready_until_the_service_acknowledges_its_lease() {
    let (transport, mut entered, _release, closed, acknowledge) = transport(false, false);
    acknowledge.send_replace(false);
    let session = DesktopSession::start(transport);
    assert_eq!(*session.state().borrow(), SessionState::Starting);
    entered.changed().await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), session.ready())
            .await
            .is_err()
    );
    assert_eq!(closed.load(Ordering::SeqCst), 0);
    acknowledge.send_replace(true);
    session.ready().await.unwrap();
    assert_eq!(*session.state().borrow(), SessionState::Connected);
    session.close().await.unwrap();
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn missing_readiness_times_out_and_closes_the_real_transport() {
    let (transport, _entered, _release, closed, acknowledge) = transport(false, false);
    acknowledge.send_replace(false);
    let session =
        DesktopSession::start_with_timeout(transport, std::time::Duration::from_millis(20));
    assert!(session.ready().await.is_err());
    let error = session.close().await.unwrap_err();
    assert!(error.to_string().contains("readiness timed out"));
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failed_readiness_handshake_never_claims_the_session_is_connected() {
    let (transport, _entered, _release, closed, acknowledge) = transport(false, false);
    acknowledge.send_replace(false);
    drop(acknowledge);
    let session = DesktopSession::start(transport);
    assert!(session.ready().await.is_err());
    assert!(session.close().await.is_err());
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}
