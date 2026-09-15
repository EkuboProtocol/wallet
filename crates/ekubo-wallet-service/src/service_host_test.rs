use super::*;
use crate::{
    authority::{ApplicationAuthority, OwnerApi},
    custody_bootstrap::CustodyBootstrap,
};
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn stop_while_locked_drains_endpoint_without_opening_authority() {
    let (bootstrap, startup) = CustodyBootstrap::new();
    let (endpoint_stop, mut stopping) = watch::channel(false);
    let (_stop, stopped) = watch::channel(true);
    let drained = Arc::new(AtomicBool::new(false));
    let finished = drained.clone();
    ServiceHost {
        startup,
        endpoint_stop,
        endpoint: async move {
            let _bootstrap = bootstrap;
            stopping.wait_for(|stop| *stop).await.unwrap();
            tokio::task::yield_now().await;
            finished.store(true, Ordering::SeqCst);
            Ok(())
        },
        open: || panic!("authority opened while locked"),
        publish: |_| panic!("authority published while locked"),
    }
    .run(stopped)
    .await
    .unwrap();
    assert!(drained.load(Ordering::SeqCst));
}

#[tokio::test]
async fn endpoint_failure_is_preserved_without_opening_authority() {
    let (_bootstrap, startup) = CustodyBootstrap::new();
    let (endpoint_stop, _stopping) = watch::channel(false);
    let (_stop, stopped) = watch::channel(false);
    let error = ServiceHost {
        startup,
        endpoint_stop,
        endpoint: async { anyhow::bail!("test endpoint failure") },
        open: || panic!("authority opened without endpoint"),
        publish: |_| panic!("authority published without endpoint"),
    }
    .run(stopped)
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "test endpoint failure");
}

fn envelope() -> ekubo_wallet_core::custody_envelope::WrappedDataKey {
    use ekubo_wallet_core::custody_envelope::{CustodyBinding, WrappingKey};
    WrappingKey::from_material(zeroize::Zeroizing::new([0x32; 32]))
        .enroll(
            CustodyBinding::new(
                "owner",
                "service",
                uuid::Uuid::new_v4(),
                uuid::Uuid::new_v4(),
            )
            .unwrap(),
        )
        .unwrap()
        .1
}

async fn startup_case(fail_open: bool, fail_publish: bool) {
    let directory = tempfile::tempdir().unwrap();
    let (bootstrap, startup) = CustodyBootstrap::new();
    let (endpoint_stop, mut stopping) = watch::channel(false);
    let (stop, stopped) = watch::channel(false);
    let observed = std::cell::RefCell::new(None);
    let opened = AtomicBool::new(false);
    let published = AtomicBool::new(false);
    let drained = AtomicBool::new(false);
    let result = ServiceHost {
        startup,
        endpoint_stop,
        endpoint: async {
            let unlocked = bootstrap.unlock(envelope().as_bytes(), |_| Ok(())).await;
            assert_eq!(unlocked.is_ok(), !fail_open && !fail_publish);
            if unlocked.is_ok() {
                assert!(published.load(Ordering::SeqCst));
            }
            stop.send_replace(true);
            stopping.wait_for(|stop| *stop).await.unwrap();
            // An asynchronous cleanup must finish before the host returns.
            tokio::task::yield_now().await;
            drained.store(true, Ordering::SeqCst);
            Ok(())
        },
        open: || {
            opened.store(true, Ordering::SeqCst);
            anyhow::ensure!(!fail_open, "test open failure");
            let owner = OwnerApi::for_test(directory.path())?;
            let service = Arc::new(ServiceRuntime::new(ApplicationAuthority::open(
                owner.config().clone(),
            )?));
            *observed.borrow_mut() = Some(service.events().subscribe());
            Ok(service)
        },
        publish: |_| {
            anyhow::ensure!(!fail_publish, "test publish failure");
            published.store(true, Ordering::SeqCst);
            Ok(())
        },
    }
    .run(stopped)
    .await;
    assert!(opened.load(Ordering::SeqCst));
    assert!(drained.load(Ordering::SeqCst));
    if let Some(mut events) = observed.into_inner() {
        let mut online = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let crate::events::DomainEventKind::McpStatusChanged { online: value } = event.kind {
                online.push(value);
            }
        }
        assert_eq!(
            online,
            if fail_publish {
                vec![false]
            } else {
                vec![true, false]
            }
        );
    }
    if fail_open {
        assert_eq!(result.unwrap_err().to_string(), "test open failure");
    } else if fail_publish {
        assert_eq!(result.unwrap_err().to_string(), "test publish failure");
    } else {
        result.unwrap();
    }
}

#[tokio::test]
async fn open_failure_rejects_unlock_and_drains_endpoint() {
    startup_case(true, false).await;
}

#[tokio::test]
async fn publication_failure_rejects_unlock_and_drains_endpoint() {
    startup_case(false, true).await;
}

#[tokio::test]
async fn readiness_follows_publication_and_stop_drains_endpoint() {
    startup_case(false, false).await;
}
