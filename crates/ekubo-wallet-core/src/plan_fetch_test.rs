use super::*;

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
