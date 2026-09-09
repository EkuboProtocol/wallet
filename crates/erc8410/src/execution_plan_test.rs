//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use alloc::string::ToString;
use serde_json::json;

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

#[test]
fn json_entry_point_validates_and_bounds_input() {
    let input = serde_json::to_string(&plan()).unwrap();
    assert_eq!(
        ExecutionPlan::from_json(&input).unwrap(),
        ExecutionPlan::parse(plan()).unwrap()
    );
    assert!(ExecutionPlan::from_json("{}").is_err());
    assert!(ExecutionPlan::from_json(&" ".repeat(MAX_SERIALIZED_PLAN_BYTES + 1)).is_err());
}

#[test]
fn quantities_preserve_full_precision() {
    let maximum = U256::MAX.to_string();
    let mut input = plan();
    input["ordered_steps"][0]["transaction"]["value"] = json!(maximum);
    let parsed = ExecutionPlan::from_json(&serde_json::to_string(&input).unwrap()).unwrap();
    assert_eq!(parsed.ordered_steps[0].transaction.value.value(), U256::MAX);
    for invalid in [
        "01",
        "-1",
        "1.0",
        "",
        "0x1",
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    ] {
        assert!(DecimalU256::new(invalid).is_err());
    }
}

#[test]
fn digest_excludes_metadata_but_binds_transaction() {
    let mut parsed = ExecutionPlan::parse(plan()).unwrap();
    let original = parsed.digest();
    parsed.ordered_steps[0].transaction.gas = Some(DecimalU256::new("21000").unwrap());
    parsed.required_capabilities.push("atomic_batch".into());
    parsed.extensions.insert("producer".into(), json!("test"));
    parsed.validate().unwrap();
    assert_eq!(parsed.digest(), original);
    parsed.ordered_steps[0].transaction.value = DecimalU256::new("1").unwrap();
    assert_ne!(parsed.digest(), original);
}
