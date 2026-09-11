use super::{
    tests::{envelope, pair, runtime},
    *,
};
use serde_json::{Value, json};
use std::{sync::atomic::Ordering, time::Duration};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream};

async fn rpc(
    stream: &mut BufReader<DuplexStream>,
    id: u32,
    method: &str,
    mut params: Value,
) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{}
    });
    let message = json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params});
    stream
        .get_mut()
        .write_all(&serde_json::to_vec(&message).unwrap())
        .await
        .unwrap();
    stream.get_mut().write_all(b"\n").await.unwrap();
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["id"], id, "{reply}");
    reply
}

#[tokio::test]
async fn relayed_mcp_preserves_discovery_and_calls_without_acquiring_an_extra_desktop_lease() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime(dir.path());
    let _desktop = runtime.reserve_desktop().unwrap().activate();
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
    service.publish(runtime.clone()).unwrap();
    startup.ready();
    assert_eq!(
        wire::read(&mut client).await.unwrap().unwrap().kind,
        Kind::Ok
    );
    wire::write(&mut client, Kind::Agent, &[]).await.unwrap();
    assert_eq!(
        wire::read(&mut client).await.unwrap().unwrap().kind,
        Kind::Ok
    );
    client.write_all(b"{\"client\":\"codex\"}\n").await.unwrap();
    let mut client = BufReader::new(client);

    // Compare the actual existing MCP transport with the service handoff, not
    // a second catalog or a list of guessed tool names.
    let (mut baseline, server) = tokio::io::duplex(1024 * 1024);
    let agent = runtime.agent_api();
    let events = runtime.events();
    let original = tokio::spawn(crate::mcp_transport::serve_connection(
        server,
        agent,
        Arc::new(AtomicUsize::new(0)),
        events,
        tokio_util::sync::CancellationToken::new(),
    ));
    baseline
        .write_all(b"{\"client\":\"codex\"}\n")
        .await
        .unwrap();
    let mut baseline = BufReader::new(baseline);
    for (id, method, params) in [
        (1, "server/discover", json!({})),
        (2, "tools/list", json!({})),
        (
            3,
            "tools/call",
            json!({"name":"wallet_list", "arguments":{}}),
        ),
        (
            4,
            "tools/call",
            json!({"name":"wallet_export_private_key", "arguments":{}}),
        ),
        (5, "networks", json!({})),
    ] {
        let actual = rpc(&mut client, id, method, params.clone()).await;
        let expected = rpc(&mut baseline, id, method, params).await;
        assert_eq!(actual, expected);
        if id == 2 {
            assert!(!actual["result"]["tools"].as_array().unwrap().is_empty());
        } else if id >= 4 {
            assert!(
                actual.get("error").is_some(),
                "MCP must not expose raw key export or owner dispatch: {actual}"
            );
        }
    }
    assert_eq!(checked.load(Ordering::SeqCst), 2);
    assert_eq!(service.mcp_active.load(Ordering::SeqCst), 1);
    let reservations: Vec<_> = (0..31)
        .map(|_| runtime.reserve_desktop().unwrap())
        .collect();
    assert!(runtime.reserve_desktop().is_err());
    drop(reservations);
    drop(client);
    drop(baseline);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), original)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(service.mcp_active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn untrusted_mcp_handoff_is_rejected_before_entering_the_protocol() {
    let (service, _startup) = OwnerStreamService::new();
    let (peer, mut client, checked) = pair(false);
    let task = tokio::spawn(async move {
        service
            .serve(peer, |_| panic!("MCP handoff cannot unlock custody"))
            .await
    });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(&mut client, Kind::Agent, &[]).await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert_eq!(checked.load(Ordering::SeqCst), 1);
    assert!(wire::read(&mut client).await.unwrap().is_none());
}

#[tokio::test]
async fn locked_or_malformed_handoff_never_switches_to_mcp() {
    for payload in [&[][..], &b"untrusted body"[..]] {
        let (service, _startup) = OwnerStreamService::new();
        let (peer, mut client, _) = pair(true);
        let task =
            tokio::spawn(async move { service.serve(peer, |_| panic!("unexpected unlock")).await });
        wire::read_hello(&mut client).await.unwrap();
        wire::write(&mut client, Kind::Agent, payload)
            .await
            .unwrap();
        let reply = wire::read(&mut client).await.unwrap().unwrap();
        assert_eq!(reply.kind, Kind::Error);
        assert!(
            !reply
                .body()
                .windows(b"untrusted body".len())
                .any(|part| part == b"untrusted body")
        );
        task.await.unwrap().unwrap();
        assert!(wire::read(&mut client).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn cancelling_the_service_task_closes_mcp_and_releases_its_active_count() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _startup) = OwnerStreamService::new();
    let runtime = runtime(dir.path());
    let _desktop = runtime.reserve_desktop().unwrap().activate();
    service.publish(runtime).unwrap();
    let service = Arc::new(service);
    let (peer, mut client, _) = pair(true);
    let serving = service.clone();
    let task =
        tokio::spawn(async move { serving.serve(peer, |_| panic!("unexpected unlock")).await });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(&mut client, Kind::Agent, &[]).await.unwrap();
    assert_eq!(
        wire::read(&mut client).await.unwrap().unwrap().kind,
        Kind::Ok
    );
    client.write_all(b"{\"client\":\"codex\"}\n").await.unwrap();
    let mut client = BufReader::new(client);
    let reply = rpc(&mut client, 1, "tools/list", json!({})).await;
    assert!(!reply["result"]["tools"].as_array().unwrap().is_empty());
    assert_eq!(service.mcp_active.load(Ordering::SeqCst), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(service.mcp_active.load(Ordering::SeqCst), 0);
    let mut line = String::new();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), client.read_line(&mut line))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn an_unlocked_service_without_a_desktop_rejects_mcp_before_acknowledgement() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _startup) = OwnerStreamService::new();
    service.publish(runtime(dir.path())).unwrap();
    let (peer, mut client, _) = pair(true);
    let task =
        tokio::spawn(async move { service.serve(peer, |_| panic!("unexpected unlock")).await });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(&mut client, Kind::Agent, &[]).await.unwrap();
    let reply = wire::read(&mut client).await.unwrap().unwrap();
    assert_eq!(reply.kind, Kind::Error);
    assert!(
        std::str::from_utf8(reply.body())
            .unwrap()
            .contains("no desktop session is active")
    );
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn quitting_then_reopening_closes_old_mcp_streams_and_allows_new_connections() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime(dir.path());
    let desktop = runtime.reserve_desktop().unwrap().activate();
    let (service, _startup) = OwnerStreamService::new();
    service.publish(runtime.clone()).unwrap();
    let service = Arc::new(service);
    let (peer, mut client, _) = pair(true);
    let serving = service.clone();
    let task =
        tokio::spawn(async move { serving.serve(peer, |_| panic!("unexpected unlock")).await });
    wire::read_hello(&mut client).await.unwrap();
    wire::write(&mut client, Kind::Agent, &[]).await.unwrap();
    assert_eq!(
        wire::read(&mut client).await.unwrap().unwrap().kind,
        Kind::Ok
    );
    client.write_all(b"{\"client\":\"codex\"}\n").await.unwrap();
    let mut client = BufReader::new(client);
    assert!(rpc(&mut client, 1, "tools/list", json!({})).await["result"]["tools"].is_array());
    drop(desktop);
    let _reopened = runtime.reserve_desktop().unwrap().activate();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(service.mcp_active.load(Ordering::SeqCst), 0);
    let mut line = String::new();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), client.read_line(&mut line))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(runtime.agent_connection().is_ok());
}
