use super::*;
use tokio::io::AsyncWriteExt as _;

#[tokio::test]
async fn completion_racing_extra_input_never_starts_an_owner_response() {
    let (mut server, mut client) = tokio::io::duplex(64);
    let result = run_call(&mut server, |_| async {
        client.write_all(b"unexpected").await?;
        Ok(zeroize::Zeroizing::new("null".into()))
    })
    .await;
    assert!(result.is_err());
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.is_empty());
}

#[tokio::test]
async fn extra_input_during_response_backpressure_revokes_the_call() {
    let (mut server, mut client) = tokio::io::duplex(16);
    let (started, binding) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        run_call(&mut server, |binding| async move {
            assert!(started.send(binding).is_ok());
            Ok(zeroize::Zeroizing::new(serde_json::to_string(
                &"x".repeat(1024),
            )?))
        })
        .await
    });
    let binding = binding.await.unwrap();
    // Observe a real response write, then stop draining it. The write cannot
    // finish in this bounded channel; incoming protocol violations must wake it.
    let mut first = [0];
    client.read_exact(&mut first).await.unwrap();
    client.write_all(b"extra").await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(binding.ensure_live().is_err());
    let mut remainder = Vec::new();
    client.read_to_end(&mut remainder).await.unwrap();
    assert!(
        remainder.len() + 1 < 1024,
        "full owner response escaped cancellation"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn native_prefetched_input_is_rejected_before_owner_dispatch_or_response() {
    use tokio::{
        io::AsyncBufReadExt as _,
        net::windows::named_pipe::{ClientOptions, ServerOptions},
    };
    let name = format!(
        r"\\.\pipe\EkuboWallet-owner-monitor-test-{}",
        uuid::Uuid::new_v4()
    );
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .unwrap();
    let mut client = ClientOptions::new().open(&name).unwrap();
    server.connect().await.unwrap();
    client.write_all(b"extra").await.unwrap();
    let mut server = tokio::io::BufReader::new(server);
    assert_eq!(server.fill_buf().await.unwrap(), b"extra");
    let mut dispatched = false;
    assert!(
        run_call(&mut server, |_| async {
            dispatched = true;
            Ok(zeroize::Zeroizing::new("null".into()))
        })
        .await
        .is_err()
    );
    assert!(!dispatched);
    drop(server);
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response).await;
    assert!(response.is_empty());
}
