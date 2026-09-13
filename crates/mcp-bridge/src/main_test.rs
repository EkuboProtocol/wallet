use super::*;

#[test]
fn missing_service_is_an_actionable_setup_failure() {
    let error = require_service::<()>(None).unwrap_err().to_string();
    assert!(error.contains("Ekubo Wallet 2"));
    assert!(error.contains("signed Ekubo Wallet 2 installer"));
    assert_eq!(require_service(Some(42)).unwrap(), 42);
}

// Inject transport at the existing generic handshake boundary. These tests
// run on service-only platforms without adding any production routing bypass.
#[tokio::test]
async fn incompatible_peer_gets_no_catalog_or_business_requests() {
    let (bridge, peer) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut peer = BufReader::new(peer);
        assert!(read_frame(&mut peer).await.unwrap().is_some());
        peer.get_mut()
            .write_all(b"{\"id\":1,\"result\":{\"serverInfo\":{\"version\":\"0.0.0\"}}}\n")
            .await
            .unwrap();
        assert!(read_frame(&mut peer).await.unwrap().is_none());
    });
    let result = handshake(bridge, b"{\"id\":1,\"method\":\"initialize\"}\n", None).await;
    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .downcast_ref::<VersionMismatch>()
            .is_some()
    );
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_hung_injected_handshake_can_be_cancelled_and_closes_its_transport() {
    let (bridge, peer) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let mut peer = BufReader::new(peer);
        assert!(read_frame(&mut peer).await.unwrap().is_some());
        // Never answer initialize. Cancellation must release the stream.
        assert!(read_frame(&mut peer).await.unwrap().is_none());
    });
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            handshake(bridge, b"{\"id\":1,\"method\":\"initialize\"}\n", None),
        )
        .await
        .is_err()
    );
    tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn partial_injected_frames_survive_read_cancellation() {
    let (bridge, mut peer) = tokio::io::duplex(4096);
    let mut reader = BufReader::new(bridge);
    let mut partial = Vec::new();
    peer.write_all(b"{\"id\":1,").await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            read_frame_into(&mut reader, &mut partial),
        )
        .await
        .is_err()
    );
    assert_eq!(partial, b"{\"id\":1,");
    peer.write_all(b"\"result\":{}}\n").await.unwrap();
    let frame = read_frame_into(&mut reader, &mut partial)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&frame).unwrap(),
        json!({"id":1,"result":{}})
    );
    assert!(partial.is_empty());
}
