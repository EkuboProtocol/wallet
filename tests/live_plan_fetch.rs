//! Live conformance for resolving execution plans by reference URL.
//!
//! Exercises `plan_fetch` under the production admission policy against the
//! real Ekubo MCP deployment: public-host vetting over real DNS, TLS, the
//! `/plan/<id>` route's semantics, digest verification over live bytes, and
//! the full parse/validate path on a plan an actual producer stored. The unit
//! tests cover the same logic against local fixtures; what needs the network
//! is the deployed end of the contract.
//!
//! Skipped unless `EKUBO_WALLET_LIVE_PLAN_FETCH_TESTS=1`. The happy-path test
//! additionally needs a fresh reference (they expire in minutes): pass its
//! URL and digest via `EKUBO_WALLET_LIVE_PLAN_URL` and
//! `EKUBO_WALLET_LIVE_PLAN_DIGEST`, e.g. from any Ekubo MCP preparation
//! tool's `execution_plan_reference`.

use ekubo_wallet::plan_fetch::{FetchPolicy, resolve_execution_plan};

fn live_enabled() -> bool {
    std::env::var_os("EKUBO_WALLET_LIVE_PLAN_FETCH_TESTS").is_some_and(|value| value == "1")
}

#[tokio::test]
async fn an_unknown_reference_reports_expiry_without_leaking_the_response() {
    if !live_enabled() {
        eprintln!("skipped: set EKUBO_WALLET_LIVE_PLAN_FETCH_TESTS=1");
        return;
    }
    let error = resolve_execution_plan(
        "https://mcp.ekubo.org/plan/00000000-0000-4000-8000-000000000000",
        None,
        FetchPolicy::production(),
    )
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
    let (Ok(url), Ok(digest)) = (
        std::env::var("EKUBO_WALLET_LIVE_PLAN_URL"),
        std::env::var("EKUBO_WALLET_LIVE_PLAN_DIGEST"),
    ) else {
        eprintln!("skipped: supply EKUBO_WALLET_LIVE_PLAN_URL and EKUBO_WALLET_LIVE_PLAN_DIGEST");
        return;
    };
    let plan = resolve_execution_plan(&url, Some(&digest), FetchPolicy::production())
        .await
        .expect("a fresh live reference resolves");
    assert!(!plan.ordered_steps.is_empty());

    let wrong = format!("0x{}", "11".repeat(32));
    let error = resolve_execution_plan(&url, Some(&wrong), FetchPolicy::production())
        .await
        .expect_err("a tampered digest must refuse the same live plan");
    assert!(
        error
            .to_string()
            .contains("must not be simulated or signed"),
        "{error}"
    );
}
