//! Live conformance for resolving execution plans by producer reference.
//!
//! Exercises `plan_fetch` under the production admission policy against the
//! real Ekubo MCP deployment: public-host vetting over real DNS, TLS, the
//! `/artifact/<id>` route's semantics, integrity verification over live
//! bytes, and the full parse/validate path on a plan an actual producer
//! stored. The unit tests cover the same logic against local fixtures; what
//! needs the network is the deployed end of the contract.
//!
//! These tests require the producer deployment that emits `artifact_reference`
//! envelopes (post unified-artifact-references); against an older deployment
//! they fail rather than skip.
//!
//! Skipped unless `EKUBO_WALLET_LIVE_PLAN_FETCH_TESTS=1`. The happy-path test
//! additionally needs a fresh reference (they expire): pass the whole
//! `execution_plan_reference` envelope JSON via
//! `EKUBO_WALLET_LIVE_PLAN_REFERENCE`, e.g. copied verbatim from any Ekubo
//! MCP preparation tool's result.

use ekubo_wallet::plan_fetch::{
    ArtifactReference, ArtifactSummary, ArtifactType, FetchPolicy, resolve_execution_plan_reference,
};

fn live_enabled() -> bool {
    std::env::var_os("EKUBO_WALLET_LIVE_PLAN_FETCH_TESTS").is_some_and(|value| value == "1")
}

#[tokio::test]
async fn an_unknown_reference_reports_expiry_without_leaking_the_response() {
    if !live_enabled() {
        eprintln!("skipped: set EKUBO_WALLET_LIVE_PLAN_FETCH_TESTS=1");
        return;
    }
    let reference = ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ArtifactType::ExecutionPlan,
        url: "https://mcp.ekubo.org/artifact/00000000-0000-4000-8000-000000000000".into(),
        integrity: Some(ekubo_wallet::plan_fetch::ArtifactIntegrity {
            algorithm: "keccak256".into(),
            value: format!("0x{}", "11".repeat(32)),
        }),
        bytes: Some(2),
        summary: ArtifactSummary::default(),
        instruction: None,
    };
    let error = resolve_execution_plan_reference(&reference, FetchPolicy::production())
        .await
        .expect_err("a never-stored reference must not resolve");
    let message = error.to_string();
    assert!(message.contains("expired or never existed"), "{message}");
}

#[tokio::test]
async fn a_fresh_reference_resolves_and_verifies_under_production_policy() {
    if !live_enabled() {
        eprintln!("skipped: set EKUBO_WALLET_LIVE_PLAN_FETCH_TESTS=1");
        return;
    }
    let Ok(envelope) = std::env::var("EKUBO_WALLET_LIVE_PLAN_REFERENCE") else {
        eprintln!(
            "skipped: supply EKUBO_WALLET_LIVE_PLAN_REFERENCE with a fresh \
             execution_plan_reference envelope JSON"
        );
        return;
    };
    let reference: ArtifactReference =
        serde_json::from_str(&envelope).expect("envelope JSON parses as an artifact_reference");
    let (plan, source) = resolve_execution_plan_reference(&reference, FetchPolicy::production())
        .await
        .expect("a fresh live reference resolves");
    assert!(!plan.ordered_steps.is_empty());
    assert!(matches!(
        source,
        ekubo_wallet::plan_fetch::ArtifactSource::Https { .. }
    ));

    let mut tampered = reference;
    if let Some(integrity) = &mut tampered.integrity {
        integrity.value = format!("0x{}", "11".repeat(32));
    }
    let error = resolve_execution_plan_reference(&tampered, FetchPolicy::production())
        .await
        .expect_err("a tampered digest must refuse the same live plan");
    assert!(
        error
            .to_string()
            .contains("must not be simulated or signed"),
        "{error}"
    );
}
