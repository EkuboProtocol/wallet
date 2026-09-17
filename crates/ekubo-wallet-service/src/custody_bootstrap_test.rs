use super::*;
use ekubo_wallet_core::custody_envelope::{CustodyBinding, CustodyEnrollment, WrappingKey};
use futures::poll;
use uuid::Uuid;

fn enrollment() -> (WrappingKey, CustodyEnrollment, WrappedDataKey) {
    let wrapping = WrappingKey::from_material(zeroize::Zeroizing::new([0x11; 32]));
    let binding = CustodyBinding::new(
        "linux:uid:1000",
        "linux:uid:2000",
        Uuid::from_u128(1),
        Uuid::from_u128(2),
    )
    .unwrap();
    let (_, wrapped) = wrapping.enroll(binding).unwrap();
    let enrolled = CustodyEnrollment::new(Uuid::from_u128(2), &wrapped).unwrap();
    (wrapping, enrolled, wrapped)
}

#[tokio::test]
async fn rejected_envelopes_do_not_start_authority_and_unlock_waits_for_readiness() {
    let (bootstrap, mut startup) = CustodyBootstrap::new();
    let (wrapping, enrolled, wrapped) = enrollment();
    assert!(
        bootstrap
            .unlock(&[0x22; 32], |_| panic!("malformed input reached custody"))
            .await
            .is_err()
    );
    let unlock = |wrapped: &WrappedDataKey| {
        enrolled
            .unlock(
                &wrapping,
                "linux:uid:1000",
                "linux:uid:2000",
                Uuid::from_u128(1),
                wrapped,
            )
            .map(|_| ())
    };
    let (_, _, wrong) = enrollment();
    assert!(bootstrap.unlock(wrong.as_bytes(), unlock).await.is_err());
    assert!(poll!(Box::pin(startup.wait_for_unlock())).is_pending());
    let mut request = Box::pin(bootstrap.unlock(wrapped.as_bytes(), unlock));
    assert!(poll!(request.as_mut()).is_pending());
    startup.wait_for_unlock().await.unwrap();
    assert!(poll!(request.as_mut()).is_pending());
    startup.ready();
    request.await.unwrap();
    bootstrap.unlock(wrapped.as_bytes(), unlock).await.unwrap();
}

#[tokio::test]
async fn failed_host_startup_never_returns_a_successful_unlock_reply() {
    let (bootstrap, mut startup) = CustodyBootstrap::new();
    let (_, _, wrapped) = enrollment();
    let mut request = Box::pin(bootstrap.unlock(wrapped.as_bytes(), |_| Ok(())));
    assert!(poll!(request.as_mut()).is_pending());
    startup.wait_for_unlock().await.unwrap();
    drop(startup);
    assert!(request.await.is_err());
}

#[tokio::test]
async fn cancelling_a_relay_releases_capacity_without_relocking_custody() {
    let (bootstrap, mut startup) = CustodyBootstrap::new();
    let (_, _, wrapped) = enrollment();
    let mut request = Box::pin(bootstrap.unlock(wrapped.as_bytes(), |_| Ok(())));
    assert!(poll!(request.as_mut()).is_pending());
    assert_eq!(bootstrap.slots.available_permits(), 31);
    drop(request);
    assert_eq!(bootstrap.slots.available_permits(), 32);
    startup.wait_for_unlock().await.unwrap();
    startup.ready();
    bootstrap
        .unlock(wrapped.as_bytes(), |_| Ok(()))
        .await
        .unwrap();
}

#[tokio::test]
async fn pending_bootstrap_requests_are_bounded_and_cancellation_allows_recovery() {
    let (bootstrap, startup) = CustodyBootstrap::new();
    let (_, _, wrapped) = enrollment();
    let mut requests = Vec::new();
    for _ in 0..32 {
        let mut request = Box::pin(bootstrap.unlock(wrapped.as_bytes(), |_| Ok(())));
        assert!(poll!(request.as_mut()).is_pending());
        requests.push(request);
    }
    assert!(
        bootstrap
            .unlock(wrapped.as_bytes(), |_| panic!(
                "capacity must be checked first"
            ))
            .await
            .is_err()
    );
    requests.pop();
    let mut recovery = Box::pin(bootstrap.unlock(wrapped.as_bytes(), |_| Ok(())));
    assert!(poll!(recovery.as_mut()).is_pending());
    startup.ready();
    recovery.await.unwrap();
    for request in requests {
        request.await.unwrap();
    }
    assert_eq!(bootstrap.slots.available_permits(), 32);
}
