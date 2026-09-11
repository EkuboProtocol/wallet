use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{io::DuplexStream, sync::mpsc};

#[derive(Clone)]
pub(super) struct Factory {
    pub(super) incoming: mpsc::UnboundedSender<DuplexStream>,
    pub(super) opened: Arc<AtomicUsize>,
}
impl Connector for Factory {
    type Stream = DuplexStream;
    fn connect(&self) -> impl std::future::Future<Output = Result<Self::Stream>> + Send {
        self.opened.fetch_add(1, Ordering::SeqCst);
        let (client, service) = tokio::io::duplex(8192);
        std::future::ready(
            self.incoming
                .send(service)
                .map(|()| client)
                .map_err(|_| anyhow::anyhow!("endpoint unavailable")),
        )
    }
}

pub(super) fn envelope() -> WrappedDataKey {
    use ekubo_wallet_core::custody_envelope::{CustodyBinding, WrappingKey};
    WrappingKey::from_material(Zeroizing::new([0x44; 32]))
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

struct Fixture {
    client: StreamOwnerClient<Factory>,
    control: DuplexStream,
    incoming: mpsc::UnboundedReceiver<DuplexStream>,
    instance: uuid::Uuid,
}
impl Fixture {
    async fn new() -> Self {
        let (incoming, mut receiver) = mpsc::unbounded_channel();
        let factory = Factory {
            incoming,
            opened: Arc::new(AtomicUsize::new(0)),
        };
        let pending = tokio::spawn(StreamOwnerClient::connect(factory, || {
            Box::pin(async { Ok(envelope()) })
        }));
        let instance = uuid::Uuid::new_v4();
        let mut control = receiver.recv().await.unwrap();
        wire::write(&mut control, Kind::Hello, instance.as_bytes())
            .await
            .unwrap();
        let unlock = wire::read(&mut control).await.unwrap().unwrap();
        assert_eq!(unlock.kind, Kind::Unlock);
        WrappedDataKey::from_bytes(unlock.body()).unwrap();
        wire::write(&mut control, Kind::Ok, &[]).await.unwrap();
        let client = pending.await.unwrap().unwrap();
        Self {
            client,
            control,
            incoming: receiver,
            instance,
        }
    }

    fn call(&self) -> tokio::task::JoinHandle<Result<Zeroizing<String>>> {
        let client = self.client.clone();
        tokio::spawn(async move { client.exchange(r#"{"method":"networks"}"#).await })
    }

    async fn accepted_call(&mut self) -> DuplexStream {
        let mut stream = self.incoming.recv().await.unwrap();
        wire::write(&mut stream, Kind::Hello, self.instance.as_bytes())
            .await
            .unwrap();
        let call = wire::read(&mut stream).await.unwrap().unwrap();
        assert_eq!(call.kind, Kind::Call);
        assert_eq!(call.body(), br#"{"method":"networks"}"#);
        stream
    }
}

#[tokio::test]
async fn invalid_service_greeting_never_invokes_the_ciphertext_loader() {
    let (incoming, mut receiver) = mpsc::unbounded_channel();
    let loads = Arc::new(AtomicUsize::new(0));
    let counted = loads.clone();
    let pending = tokio::spawn(StreamOwnerClient::connect(
        Factory {
            incoming,
            opened: Arc::new(AtomicUsize::new(0)),
        },
        move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(envelope()) })
        },
    ));
    let mut service = receiver.recv().await.unwrap();
    wire::write(&mut service, Kind::Ok, &[]).await.unwrap();
    assert!(pending.await.unwrap().is_err());
    assert_eq!(loads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn service_replacement_closes_all_clones_before_sending_the_call() {
    let mut fixture = Fixture::new().await;
    let pending = fixture.call();
    let mut replacement = fixture.incoming.recv().await.unwrap();
    wire::write(
        &mut replacement,
        Kind::Hello,
        uuid::Uuid::new_v4().as_bytes(),
    )
    .await
    .unwrap();
    assert!(pending.await.unwrap().is_err());
    assert!(wire::read(&mut replacement).await.unwrap().is_none());
    fixture.client.close().await.unwrap();
    assert!(fixture.client.exchange("{}").await.is_err());
    assert_eq!(fixture.client.connector.opened.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn lost_reply_is_not_replayed_and_success_preserves_exact_response_bytes() {
    let mut fixture = Fixture::new().await;
    let pending = fixture.call();
    let stream = fixture.accepted_call().await;
    drop(stream);
    assert!(pending.await.unwrap().is_err());
    assert!(fixture.incoming.try_recv().is_err());
    assert_eq!(fixture.client.connector.opened.load(Ordering::SeqCst), 2);
    let fresh = fixture.call();
    let mut stream = fixture.accepted_call().await;
    wire::write(&mut stream, Kind::Ok, b"[1, 2]").await.unwrap();
    assert_eq!(&*fresh.await.unwrap().unwrap(), "[1, 2]");
    fixture.client.close().await.unwrap();
}

#[tokio::test]
async fn canceling_hold_does_not_close_the_lease_but_explicit_close_does() {
    let mut fixture = Fixture::new().await;
    // Connecting/unlocking alone emits no lifetime request.
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.control.read(&mut byte))
            .await
            .is_err()
    );
    let clone = fixture.client.clone();
    let (ready, mut acknowledged) = tokio::sync::oneshot::channel();
    let hold = tokio::spawn(async move { clone.hold(ready).await });
    assert_eq!(
        wire::read(&mut fixture.control)
            .await
            .unwrap()
            .unwrap()
            .kind,
        Kind::Hold
    );
    assert!(matches!(
        acknowledged.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    wire::write(&mut fixture.control, Kind::Ok, &[])
        .await
        .unwrap();
    acknowledged.await.unwrap();
    hold.abort();
    assert!(hold.await.unwrap_err().is_cancelled());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.control.read(&mut byte))
            .await
            .is_err()
    );
    fixture.client.close().await.unwrap();
    assert_eq!(fixture.control.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn closing_the_client_cancels_pending_calls_and_refuses_new_connections() {
    let mut fixture = Fixture::new().await;
    let pending = fixture.call();
    let mut service = fixture.accepted_call().await;
    fixture.client.close().await.unwrap();
    assert!(pending.await.unwrap().is_err());
    assert!(wire::read(&mut service).await.unwrap().is_none());
    assert!(fixture.client.exchange("{}").await.is_err());
    assert_eq!(fixture.client.connector.opened.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn service_lifetime_disconnect_invalidates_calls_even_before_hold() {
    let fixture = Fixture::new().await;
    drop(fixture.control);
    let (ready, acknowledged) = tokio::sync::oneshot::channel();
    assert!(fixture.client.hold(ready).await.is_err());
    assert!(acknowledged.await.is_err());
    assert!(fixture.client.exchange("{}").await.is_err());
    assert_eq!(fixture.client.connector.opened.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropping_the_last_clone_closes_the_lifetime_driver() {
    let mut fixture = Fixture::new().await;
    let last = fixture.client.clone();
    drop(fixture.client);
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.control.read(&mut byte))
            .await
            .is_err()
    );
    drop(last);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), fixture.control.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn malformed_hold_acknowledgement_never_reports_readiness() {
    let mut fixture = Fixture::new().await;
    let clone = fixture.client.clone();
    let (ready, acknowledged) = tokio::sync::oneshot::channel();
    let hold = tokio::spawn(async move { clone.hold(ready).await });
    assert_eq!(
        wire::read(&mut fixture.control)
            .await
            .unwrap()
            .unwrap()
            .kind,
        Kind::Hold
    );
    wire::write(&mut fixture.control, Kind::Ok, b"unexpected payload")
        .await
        .unwrap();
    assert!(
        hold.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("unexpected owner acknowledgement payload")
    );
    assert!(acknowledged.await.is_err());
    assert!(fixture.client.exchange("{}").await.is_err());
    assert_eq!(fixture.client.connector.opened.load(Ordering::SeqCst), 1);
}
