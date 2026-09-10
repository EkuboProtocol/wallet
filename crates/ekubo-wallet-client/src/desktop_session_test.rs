use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Transport {
    entered: watch::Sender<bool>,
    release: watch::Receiver<bool>,
    closed: Arc<AtomicUsize>,
    fail_hold: bool,
    fail_close: bool,
}
impl SessionTransport for Transport {
    async fn hold(&self) -> Result<()> {
        self.entered.send_replace(true);
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
) {
    let (entered, waiting) = watch::channel(false);
    let (release, held) = watch::channel(false);
    let closed = Arc::new(AtomicUsize::new(0));
    (
        Transport {
            entered,
            release: held,
            closed: closed.clone(),
            fail_hold,
            fail_close,
        },
        waiting,
        release,
        closed,
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
        let (transport, mut entered, _release, closed) = transport(false, false);
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
        let (transport, mut entered, release, closed) = transport(fail_hold, false);
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
    let (transport, mut entered, _release, closed) = transport(false, true);
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
