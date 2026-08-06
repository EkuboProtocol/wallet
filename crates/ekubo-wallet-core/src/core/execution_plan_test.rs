//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

fn plan() -> Value {
    json!({
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
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0x",
                "value": "0"
            }
        }]
    })
}

#[test]
fn parses_and_hashes_canonical_plan() {
    let parsed = ExecutionPlan::parse(plan()).unwrap();
    assert_eq!(
        format!("{:#x}", parsed.digest()),
        "0x93aeec006e55dfe0f54041d53c94387e08c504d4f3b3826cd3426dbc7da38ea5"
    );
}

#[test]
fn rejects_mismatched_chain_and_unknown_fields() {
    let mut input = plan();
    input["caip2_chain_id"] = json!("eip155:2");
    assert!(ExecutionPlan::parse(input).is_err());
    let mut input = plan();
    input["surprise"] = json!(true);
    assert!(ExecutionPlan::parse(input).is_err());
}

#[test]
fn accepts_only_bounded_error_result_decode_hints() {
    let mut input = plan();
    input["ordered_steps"][0]["revert_decode"] = json!({
        "kind": "error_result",
        "abi": [{
            "type": "error",
            "name": "Slippage",
            "inputs": [{"name": "minimum", "type": "uint256"}]
        }],
        "required": false
    });
    assert!(ExecutionPlan::parse(input).is_ok());

    let mut input = plan();
    input["ordered_steps"][0]["revert_decode"] = json!({
        "kind": "error_result",
        "abi": []
    });
    assert!(ExecutionPlan::parse(input).is_err());
}

#[test]
fn rejects_execution_plans_over_the_step_limit() {
    let mut parsed = ExecutionPlan::parse(plan()).unwrap();
    let template = parsed.ordered_steps[0].clone();
    parsed.ordered_steps = (1..=MAX_EXECUTION_STEPS + 1)
        .map(|step| ExecutionStep {
            step: u32::try_from(step).unwrap(),
            ..template.clone()
        })
        .collect();

    let error = parsed.validate().unwrap_err().to_string();
    assert!(error.contains("exceeds 4096 steps"));
}
