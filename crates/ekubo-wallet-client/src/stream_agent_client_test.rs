use super::{
    tests::{Factory, envelope},
    *,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    sync::mpsc,
};

fn factory() -> (Factory, mpsc::UnboundedReceiver<tokio::io::DuplexStream>) {
    let (incoming, receiver) = mpsc::unbounded_channel();
    (
        Factory {
            incoming,
            opened: Arc::new(AtomicUsize::new(0)),
        },
        receiver,
    )
}

#[tokio::test]
async fn invalid_greeting_never_loads_an_envelope_for_mcp() {
    let (factory, mut incoming) = factory();
    let task = tokio::spawn(connect_agent(factory, || async {
        panic!("ciphertext loaded before service greeting validation");
    }));
    let mut server = incoming.recv().await.unwrap();
    wire::write(&mut server, Kind::Ok, &[]).await.unwrap();
    assert!(task.await.unwrap().is_err());
}

async fn accept_relay(server: &mut tokio::io::DuplexStream) {
    wire::write(server, Kind::Hello, uuid::Uuid::new_v4().as_bytes())
        .await
        .unwrap();
    let frame = wire::read(server).await.unwrap().unwrap();
    assert_eq!(frame.kind, Kind::Unlock);
    WrappedDataKey::from_bytes(frame.body()).unwrap();
    wire::write(server, Kind::Ok, &[]).await.unwrap();
    let frame = wire::read(server).await.unwrap().unwrap();
    assert_eq!(
        frame.kind,
        Kind::Agent,
        "MCP must never request a desktop lease"
    );
    assert!(frame.body().is_empty());
}

#[tokio::test]
async fn mcp_uses_one_connection_and_waits_for_the_handoff_acknowledgement() {
    let (factory, mut incoming) = factory();
    let opened = factory.opened.clone();
    let mut task = tokio::spawn(connect_agent(factory, || async { Ok(envelope()) }));
    let mut server = incoming.recv().await.unwrap();
    accept_relay(&mut server).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut task)
            .await
            .is_err()
    );
    wire::write(&mut server, Kind::Ok, &[]).await.unwrap();
    server.write_all(b"preserved MCP bytes\n").await.unwrap();
    let mut client = BufReader::new(task.await.unwrap().unwrap());
    let mut line = String::new();
    client.read_line(&mut line).await.unwrap();
    assert_eq!(line, "preserved MCP bytes\n");
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    drop(client);
    let mut byte = [0];
    assert_eq!(server.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn handoff_rejection_closes_the_connection_without_retrying() {
    let (factory, mut incoming) = factory();
    let opened = factory.opened.clone();
    let task = tokio::spawn(connect_agent(factory, || async { Ok(envelope()) }));
    let mut server = incoming.recv().await.unwrap();
    accept_relay(&mut server).await;
    wire::write(&mut server, Kind::Error, b"not ready")
        .await
        .unwrap();
    assert_eq!(task.await.unwrap().unwrap_err().to_string(), "not ready");
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    let mut byte = [0];
    assert_eq!(server.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn cancelled_handoff_drops_the_actual_connection() {
    let (factory, mut incoming) = factory();
    let task = tokio::spawn(connect_agent(factory, || async { Ok(envelope()) }));
    let mut server = incoming.recv().await.unwrap();
    accept_relay(&mut server).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let mut byte = [0];
    assert_eq!(server.read(&mut byte).await.unwrap(), 0);
}
