use super::*;
use std::io::{Read as _, Write as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn blocking_codec_exchanges_bytes_with_async_transport() {
    let (stream, mut peer) = tokio::io::duplex(64);
    let (mut stream, _cancel) = bridge(stream, Duration::from_secs(10));
    let worker = tokio::task::spawn_blocking(move || {
        let mut bytes = [0; 3];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"abc");
        stream.write_all(b"xyz").unwrap();
        stream.flush().unwrap();
    });
    peer.write_all(b"abc").await.unwrap();
    let mut reply = [0; 3];
    peer.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"xyz");
    worker.await.unwrap();
}

#[tokio::test]
async fn cancellation_wakes_blocking_codec_before_its_deadline() {
    let (stream, _peer) = tokio::io::duplex(64);
    let (mut stream, cancel) = bridge(stream, Duration::from_secs(60));
    let (started, ready) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        stream.read_exact(&mut [0; 1]).unwrap_err().kind()
    });
    ready.await.unwrap();
    drop(cancel);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap(),
        io::ErrorKind::ConnectionAborted
    );
}

#[tokio::test]
async fn deadline_ends_stalled_codec_io() {
    let (stream, _peer) = tokio::io::duplex(64);
    let (mut stream, _cancel) = bridge(stream, Duration::from_millis(20));
    let worker =
        tokio::task::spawn_blocking(move || stream.read_exact(&mut [0; 1]).unwrap_err().kind());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap(),
        io::ErrorKind::TimedOut
    );
}
