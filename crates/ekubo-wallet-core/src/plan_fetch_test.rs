use super::*;

#[tokio::test]
async fn compressed_reference_integrity_is_over_decompressed_json() {
    use flate2::{Compression, write::GzEncoder};
    use std::io::{Read as _, Write as _};

    let body = br#"{"chain_id":"1","calls":[{"to":"0x1111111111111111111111111111111111111111","data":"0x"}]}"#;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    let compressed = encoder.finish().unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4_096];
        let read = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..read]).to_ascii_lowercase();
        assert!(request.contains("accept-encoding:"));
        assert!(request.contains("gzip"));
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            compressed.len()
        )
        .unwrap();
        stream.write_all(&compressed).unwrap();
    });

    let reference = ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ArtifactType::ReadCalls,
        url: format!("http://{address}/artifact/test"),
        integrity: Some(ArtifactIntegrity {
            algorithm: "keccak256".into(),
            value: format!("0x{:x}", keccak256(body)),
        }),
        bytes: Some(body.len() as u64),
        instruction: None,
    };
    let fetched = fetch_reference(
        &reference,
        ArtifactType::ReadCalls,
        FetchPolicy {
            allow_insecure: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(fetched.bytes, body);
    server.join().unwrap();
}

#[tokio::test]
async fn file_references_are_never_accepted() {
    let reference = ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ArtifactType::ExecutionPlan,
        url: "file:///tmp/plan.json".into(),
        integrity: Some(ArtifactIntegrity {
            algorithm: "keccak256".into(),
            value: format!("0x{}", "00".repeat(32)),
        }),
        bytes: Some(0),
        instruction: None,
    };
    let error = fetch_reference(
        &reference,
        ArtifactType::ExecutionPlan,
        FetchPolicy::production(),
    )
    .await
    .unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("https") || message.contains("unsupported"),
        "{message}"
    );
}
