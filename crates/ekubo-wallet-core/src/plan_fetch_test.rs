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
async fn file_reference_resolves_when_integrity_matches() {
    let body = br#"{"chain_id":"1","calls":[]}"#;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plan.json");
    std::fs::write(&path, body).unwrap();
    let reference = ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ArtifactType::ReadCalls,
        url: format!("file://{}", path.display()),
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
        FetchPolicy::production(),
    )
    .await
    .unwrap();
    assert_eq!(fetched.bytes, body);
    assert_eq!(fetched.source, ArtifactSource::LocalFile);
}

#[tokio::test]
async fn file_reference_with_localhost_host_resolves() {
    let body = br#"{"chain_id":"1","calls":[]}"#;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plan.json");
    std::fs::write(&path, body).unwrap();
    let reference = ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ArtifactType::ReadCalls,
        url: format!("file://localhost{}", path.display()),
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
        FetchPolicy::production(),
    )
    .await
    .unwrap();
    assert_eq!(fetched.bytes, body);
}

/// Missing, mismatched, oversized, and unreadable files fail
/// indistinguishably and without file contents: each envelope would
/// otherwise be a yes-or-no question about the host's files.
#[tokio::test]
async fn file_failures_are_indistinguishable_and_content_free() {
    let body = br#"{"chain_id":"1","marker":"distinctive-body-marker"}"#;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plan.json");
    std::fs::write(&path, body).unwrap();
    let envelope = |url: String, value: String, bytes: Option<u64>| -> ArtifactReference {
        ArtifactReference {
            kind: "artifact_reference".into(),
            artifact_type: ArtifactType::ReadCalls,
            url,
            integrity: Some(ArtifactIntegrity {
                algorithm: "keccak256".into(),
                value,
            }),
            bytes,
            instruction: None,
        }
    };
    let digest = format!("0x{:x}", keccak256(body));
    let missing = envelope(
        format!("file://{}", directory.path().join("absent.json").display()),
        digest.clone(),
        Some(body.len() as u64),
    );
    let mismatched = envelope(
        format!("file://{}", path.display()),
        format!("0x{}", "00".repeat(32)),
        Some(body.len() as u64),
    );
    let oversized = envelope(
        format!("file://{}", path.display()),
        digest.clone(),
        Some(body.len() as u64 + 1),
    );
    let mut failures = Vec::new();
    for reference in [missing, mismatched, oversized] {
        let error = fetch_reference(
            &reference,
            ArtifactType::ReadCalls,
            FetchPolicy::production(),
        )
        .await
        .unwrap_err();
        failures.push(error.to_string());
    }
    assert_eq!(failures[0], failures[1]);
    assert_eq!(failures[1], failures[2]);
    for failure in &failures {
        assert!(failure.contains("could not be resolved"), "{failure}");
        assert!(!failure.contains("plan.json"), "{failure}");
        assert!(!failure.contains("distinctive-body-marker"), "{failure}");
    }
}

#[tokio::test]
async fn file_reference_without_integrity_is_rejected_before_any_read() {
    let reference = ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ArtifactType::ExecutionPlan,
        url: "file:///tmp/plan.json".into(),
        integrity: None,
        bytes: None,
        instruction: None,
    };
    let error = fetch_reference(
        &reference,
        ArtifactType::ExecutionPlan,
        FetchPolicy::production(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("integrity block"), "{error}");
}

#[tokio::test]
async fn file_reference_to_a_remote_host_is_rejected() {
    let body = br#"{"chain_id":"1","calls":[]}"#;
    let reference = ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ArtifactType::ReadCalls,
        url: "file://example.com/tmp/plan.json".into(),
        integrity: Some(ArtifactIntegrity {
            algorithm: "keccak256".into(),
            value: format!("0x{:x}", keccak256(body)),
        }),
        bytes: Some(body.len() as u64),
        instruction: None,
    };
    let error = fetch_reference(
        &reference,
        ArtifactType::ReadCalls,
        FetchPolicy::production(),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("could not be resolved"),
        "{error}"
    );
}
