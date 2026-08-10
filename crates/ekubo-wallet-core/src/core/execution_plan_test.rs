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

/// The door the check used to miss.
///
/// `wallet_send_execution_plan` hands `send_new_plan` a plan any producer
/// authored. It never passes through `transfer_plan`, which is where the
/// zero-address refusal lived, and `validate` checked calldata bounds, step
/// ordering, chain, and sender -- everything about the shape of the request
/// except where the value was going. An agent that wanted a plan targeting
/// `0x0` routed it through a producer MCP and was untouched.
///
/// There is no screen to disclose this on rather than refuse it:
/// `execute_automatic` signs a policy-covered plan with nobody watching, and
/// an ordinary token allowlist authorizes one. The owner's consent on that
/// path is the policy they wrote, and a policy permitting transfers of a token
/// is not consent to destroy it.
#[test]
fn a_producer_supplied_plan_cannot_send_to_the_zero_address() {
    let plan = |to: &str| {
        ExecutionPlan::parse(serde_json::json!({
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
                    "to": to,
                    "data": "0x",
                    "value": "1000000000000000000"
                }
            }]
        }))
    };

    let error = format!(
        "{:#}",
        plan("0x0000000000000000000000000000000000000000")
            .expect_err("a plan that destroys native value is not a plan this wallet signs")
    );
    assert!(error.contains("zero address"), "{error}");
    assert!(error.contains("cannot be undone"), "{error}");

    plan("0x2222222222222222222222222222222222222222")
        .expect("an ordinary recipient is unaffected");
}

/// And a later step is checked too: refusing only the first would let a batch
/// carry the destruction behind an innocuous opener.
#[test]
fn a_zero_recipient_in_any_step_refuses_the_plan() {
    let error = format!(
        "{:#}",
        ExecutionPlan::parse(serde_json::json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [
                {
                    "step": 1,
                    "kind": "execution",
                    "transaction": {
                        "chain_id": "1",
                        "from": "0x1111111111111111111111111111111111111111",
                        "to": "0x2222222222222222222222222222222222222222",
                        "data": "0x",
                        "value": "1"
                    }
                },
                {
                    "step": 2,
                    "kind": "execution",
                    "transaction": {
                        "chain_id": "1",
                        "from": "0x1111111111111111111111111111111111111111",
                        "to": "0x0000000000000000000000000000000000000000",
                        "data": "0x",
                        "value": "1"
                    }
                }
            ]
        }))
        .expect_err("the plan is signed as a unit")
    );
    assert!(
        error.contains("step 2"),
        "the refusal names which step: {error}"
    );
}
