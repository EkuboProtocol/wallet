//! `ekubo-wallet reference` and the wallet's `file:` reader are two halves of
//! one agreement: the command says what a file hashes to, and the wallet
//! refuses the file unless it still hashes to that. Nothing else checks that
//! they agree on the digest, the byte count, or the URL spelling, and a
//! disagreement would surface only as a tool call that refuses every plan an
//! agent assembles.

use assert_cmd::Command;
use ekubo_wallet::plan_fetch::{
    ArtifactReference, ArtifactSource, FetchPolicy, resolve_execution_plan_reference,
};
use std::fs;

fn plan_json(recipient: &str) -> String {
    serde_json::json!({
        "schema_version": "1",
        "chain_id": "1",
        "caip2_chain_id": "eip155:1",
        "sender": "0x1111111111111111111111111111111111111111",
        "ordered_steps": [{
            "step": 1,
            "kind": "execution",
            "transaction": {
                "chain_id": "1",
                "from": "0x1111111111111111111111111111111111111111",
                "to": recipient,
                "data": "0xd0e30db0",
                "value": "0",
            },
        }],
    })
    .to_string()
}

fn envelope_for(path: &std::path::Path) -> ArtifactReference {
    let output = Command::cargo_bin("ekubo-wallet")
        .expect("ekubo-wallet binary builds")
        .arg("reference")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "reference exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the printed envelope is an artifact_reference")
}

#[tokio::test]
async fn the_printed_envelope_resolves_the_file_it_describes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("combined-plan.json");
    fs::write(
        &path,
        plan_json("0x2222222222222222222222222222222222222222"),
    )
    .unwrap();

    let reference = envelope_for(&path);
    assert_eq!(reference.kind, "artifact_reference");
    assert!(reference.integrity.is_some(), "no integrity block printed");
    assert!(reference.bytes.is_some(), "no byte count printed");

    let (plan, source) = resolve_execution_plan_reference(&reference, FetchPolicy::production())
        .await
        .unwrap();
    assert_eq!(plan.ordered_steps.len(), 1);
    assert_eq!(source, ArtifactSource::LocalFile);
}

#[tokio::test]
async fn an_envelope_stops_describing_a_file_that_changed_under_it() {
    // The whole point of the digest on a path: what is simulated and what is
    // sent are two reads of the same file, and only this catches the file
    // moving between them.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("combined-plan.json");
    fs::write(
        &path,
        plan_json("0x2222222222222222222222222222222222222222"),
    )
    .unwrap();
    let reference = envelope_for(&path);

    fs::write(
        &path,
        plan_json("0x3333333333333333333333333333333333333333"),
    )
    .unwrap();
    let error = resolve_execution_plan_reference(&reference, FetchPolicy::production())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("must not be simulated or signed"), "{error}");
}
