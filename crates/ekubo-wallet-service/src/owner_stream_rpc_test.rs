use super::*;
use crate::authority::{ApplicationAuthority, OwnerApi};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::DuplexStream;

pub(super) struct TestPeer {
    stream: DuplexStream,
    allowed: bool,
    checked: Arc<AtomicUsize>,
}
impl Peer for TestPeer {
    type Stream = DuplexStream;
    fn stream(&mut self) -> &mut DuplexStream {
        &mut self.stream
    }
    fn into_stream(self) -> Self::Stream {
        self.stream
    }
    fn authenticate(&self) -> Result<()> {
        self.checked.fetch_add(1, Ordering::SeqCst);
        ensure!(self.allowed, "untrusted test peer");
        Ok(())
    }
}

pub(super) fn pair(allowed: bool) -> (TestPeer, DuplexStream, Arc<AtomicUsize>) {
    let (stream, client) = tokio::io::duplex(8192);
    let checked = Arc::new(AtomicUsize::new(0));
    (
        TestPeer {
            stream,
            allowed,
            checked: checked.clone(),
        },
        client,
        checked,
    )
}

pub(super) fn runtime(path: &std::path::Path) -> Arc<ServiceRuntime> {
    let owner = OwnerApi::for_test(path).unwrap();
    for document in [
        crate::legal::LegalDocument::TermsOfService,
        crate::legal::LegalDocument::PrivacyPolicy,
    ] {
        let (_, digest) = owner.legal_document(document);
        owner.accept_legal(document, &digest).unwrap();
    }
    Arc::new(ServiceRuntime::new(
        ApplicationAuthority::open(owner.config().clone()).unwrap(),
    ))
}

pub(super) fn envelope() -> WrappedDataKey {
    use ekubo_wallet_core::custody_envelope::{CustodyBinding, WrappingKey};
    WrappingKey::from_material(zeroize::Zeroizing::new([0x22; 32]))
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

#[tokio::test]
async fn untrusted_peer_cannot_unlock_or_dispatch() {
    let (service, mut startup) = OwnerStreamService::new();
    let (peer, mut client, checked) = pair(false);
    let task = tokio::spawn(async move {
        service
            .serve(peer, |_| panic!("unauthenticated unlock"))
            .await
    });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(&mut client, Kind::Unlock, envelope().as_bytes())
        .await
        .unwrap();
    assert!(task.await.unwrap().is_err());
    assert_eq!(checked.load(Ordering::SeqCst), 1);
    assert!(startup.wait_for_unlock().await.is_err());
}

#[tokio::test]
async fn authenticated_calls_use_the_shared_dispatcher_and_do_not_accept_a_second_call() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _) = OwnerStreamService::new();
    service.publish(runtime(dir.path())).unwrap();
    let (peer, mut client, checked) = pair(true);
    let task = tokio::spawn(async move {
        service
            .serve(peer, |_| panic!("call attempted unlock"))
            .await
    });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(
        &mut client,
        Kind::Call,
        &serde_json::to_vec(&Request::Networks).unwrap(),
    )
    .await
    .unwrap();
    let reply = wire::read(&mut client).await.unwrap().unwrap();
    assert_eq!(reply.kind, Kind::Ok);
    let networks: Vec<crate::config::NetworkConfig> = serde_json::from_slice(reply.body()).unwrap();
    assert!(!networks.is_empty());
    task.await.unwrap().unwrap();
    assert_eq!(checked.load(Ordering::SeqCst), 1);
    assert!(wire::read(&mut client).await.unwrap().is_none());
}

#[tokio::test]
async fn unlock_waits_for_runtime_and_desktop_lease_ends_on_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let (service, mut startup) = OwnerStreamService::new();
    let service = Arc::new(service);
    let (peer, mut client, checked) = pair(true);
    let serving = service.clone();
    let task = tokio::spawn(async move { serving.serve(peer, |_| Ok(())).await });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(&mut client, Kind::Unlock, envelope().as_bytes())
        .await
        .unwrap();
    startup.wait_for_unlock().await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            wire::read(&mut client)
        )
        .await
        .is_err(),
        "unlock acknowledged before runtime readiness"
    );
    let runtime = runtime(dir.path());
    let reservations: Vec<_> = (0..31)
        .map(|_| runtime.reserve_desktop().unwrap())
        .collect();
    service.publish(runtime.clone()).unwrap();
    startup.ready();
    assert_eq!(
        wire::read(&mut client).await.unwrap().unwrap().kind,
        Kind::Ok
    );
    assert!(
        runtime.reserve_desktop().is_ok(),
        "unlock must not activate or reserve a desktop"
    );
    assert!(
        runtime
            .owner
            .encode(Request::BeginDappSession {
                uri: "not-a-pairing".into()
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("no desktop session is active")
    );
    wire::write(&mut client, Kind::Hold, &[]).await.unwrap();
    assert_eq!(
        wire::read(&mut client).await.unwrap().unwrap().kind,
        Kind::Ok
    );
    assert!(runtime.reserve_desktop().is_err());
    assert!(
        runtime
            .owner
            .encode(Request::BeginDappSession {
                uri: "not-a-pairing".into()
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("create an account before connecting a dapp")
    );
    assert_eq!(checked.load(Ordering::SeqCst), 2);
    drop(client);
    task.await.unwrap().unwrap();
    assert!(runtime.reserve_desktop().is_ok());
    assert!(
        runtime
            .owner
            .encode(Request::BeginDappSession {
                uri: "not-a-pairing".into()
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("no desktop session is active")
    );
    drop(reservations);
}

#[tokio::test]
async fn disconnect_during_unlock_releases_the_bootstrap_wait() {
    let (service, mut startup) = OwnerStreamService::new();
    let service = Arc::new(service);
    let (peer, mut client, _) = pair(true);
    let serving = service.clone();
    let task = tokio::spawn(async move { serving.serve(peer, |_| Ok(())).await });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(&mut client, Kind::Unlock, envelope().as_bytes())
        .await
        .unwrap();
    startup.wait_for_unlock().await.unwrap();
    drop(client);
    assert!(task.await.unwrap().is_err());
    // Admission is reusable and the cipher is intentionally not relocked by
    // cancellation. A later authenticated desktop may finish startup.
    let (peer, mut client, _) = pair(true);
    let task = tokio::spawn(async move { service.serve(peer, |_| Ok(())).await });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(&mut client, Kind::Unlock, envelope().as_bytes())
        .await
        .unwrap();
    startup.ready();
    assert_eq!(
        wire::read(&mut client).await.unwrap().unwrap().kind,
        Kind::Ok
    );
    drop(client);
    let _ = task.await.unwrap();
}
