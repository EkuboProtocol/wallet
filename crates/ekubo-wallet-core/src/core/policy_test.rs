//! Tests for the ordered policy document in [`super`].

use super::*;
use crate::core::predicate::PolicyContext;
use alloy::primitives::{Address, address};
use serde_json::json;

const WALLET: Address = address!("1111111111111111111111111111111111111111");
const TOKEN: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
const ROUTER: Address = address!("2222222222222222222222222222222222222222");

fn context() -> PolicyContext {
    PolicyContext { wallet: WALLET }
}

fn plan(chain_id: u64, calls: &[(Address, &str, &str)]) -> ExecutionPlan {
    ExecutionPlan::parse(json!({
        "schema_version": "1",
        "chain_id": chain_id.to_string(),
        "caip2_chain_id": format!("eip155:{chain_id}"),
        "sender": format!("{WALLET:#x}"),
        "ordered_steps": calls.iter().enumerate().map(|(index, (to, data, value))| json!({
            "step": index + 1,
            "kind": "execution",
            "transaction": {
                "chain_id": chain_id.to_string(),
                "from": format!("{WALLET:#x}"),
                "to": format!("{to:#x}"),
                "data": data,
                "value": value
            }
        })).collect::<Vec<_>>()
    }))
    .expect("plan parses")
}

fn one_call(to: Address, data: &str, value: &str) -> ExecutionPlan {
    plan(1, &[(to, data, value)])
}

fn policy(value: serde_json::Value) -> WalletPolicy {
    WalletPolicy::parse(value).expect("policy parses")
}

fn findings(subject: &WalletPolicy, plan: &ExecutionPlan) -> Vec<PolicyFinding> {
    evaluate_policy(plan, subject, &context())
}

fn outcome(subject: &WalletPolicy, plan: &ExecutionPlan) -> PolicyOutcome {
    policy_outcome(&findings(subject, plan))
}

fn approve(spender: Address, amount: u64) -> String {
    format!("0x095ea7b3{:0>64}{amount:064x}", format!("{spender:x}"))
}

#[test]
fn empty_policy_is_the_safe_default_and_requests_approval() {
    let subject = WalletPolicy::require_approval_for_everything();
    assert_eq!(subject.rules, []);
    assert_eq!(
        outcome(&subject, &one_call(ROUTER, "0x", "0")),
        PolicyOutcome::RequiresApproval
    );
    assert_eq!(
        findings(&subject, &one_call(ROUTER, "0x", "0"))[0].code,
        CALL_NOT_ALLOWED_CODE
    );
}

#[test]
fn matcherless_deny_disables_transaction_signing() {
    let subject = WalletPolicy::deny_all();
    for candidate in [
        one_call(ROUTER, "0x", "0"),
        one_call(ROUTER, "0xdeadbeef", "1000"),
        one_call(TOKEN, &approve(ROUTER, u64::MAX), "0"),
    ] {
        assert_eq!(outcome(&subject, &candidate), PolicyOutcome::Rejected);
    }
}

#[test]
fn matcherless_allow_permits_every_transaction_call() {
    let subject = WalletPolicy::allow_anything();
    assert_eq!(
        outcome(&subject, &one_call(ROUTER, "0xdeadbeef", "1000")),
        PolicyOutcome::Allowed
    );
}

#[test]
fn tightening_classifier_accepts_only_structurally_proven_reductions() {
    let approval = WalletPolicy::require_approval_for_everything();
    let allow_all = WalletPolicy::allow_anything();
    let deny_all = WalletPolicy::deny_all();
    assert!(is_tightening(&approval, &deny_all));
    assert!(!is_tightening(&approval, &allow_all));
    assert!(is_tightening(&allow_all, &approval));
    assert!(!is_tightening(&deny_all, &approval));

    let broad_allow = policy(json!({"version": 1, "rules": [{
        "effect": "allow", "chain_id": {"eq": "1"}
    }]}));
    let narrow_allow = policy(json!({"version": 1, "rules": [{
        "effect": "allow", "chain_id": {"eq": "1"},
        "to": {"eq": format!("{TOKEN:#x}")}
    }]}));
    assert!(is_tightening(&broad_allow, &narrow_allow));
    assert!(!is_tightening(&narrow_allow, &broad_allow));
}

#[test]
fn inserting_denies_and_deleting_allows_are_prompt_free_tightenings() {
    let current = policy(json!({"version": 1, "rules": [
        {"effect": "allow", "chain_id": {"eq": "1"}},
        {"effect": "allow", "chain_id": {"eq": "10"}}
    ]}));
    let proposed = policy(json!({"version": 1, "rules": [
        {"effect": "deny", "to": {"eq": format!("{TOKEN:#x}")}},
        {"effect": "allow", "chain_id": {"eq": "10"}}
    ]}));
    assert!(is_tightening(&current, &proposed));
    assert!(!is_tightening(&proposed, &current));
}

#[test]
fn first_matching_rule_wins() {
    let allow_chain_first = policy(json!({"version": 1, "rules": [
        {"effect": "allow", "chain_id": {"eq": "1"}},
        {"effect": "deny", "to": {"eq": format!("{TOKEN:#x}")}}
    ]}));
    let deny_token_first = policy(json!({"version": 1, "rules": [
        {"effect": "deny", "to": {"eq": format!("{TOKEN:#x}")}},
        {"effect": "allow", "chain_id": {"eq": "1"}}
    ]}));
    let call = one_call(TOKEN, "0x", "0");
    assert_eq!(outcome(&allow_chain_first, &call), PolicyOutcome::Allowed);
    assert_eq!(outcome(&deny_token_first, &call), PolicyOutcome::Rejected);
}

#[test]
fn present_matchers_are_anded_and_omitted_matchers_are_wildcards() {
    let subject = policy(json!({"version": 1, "rules": [{
        "effect": "allow",
        "chain_id": {"eq": "1"},
        "to": {"eq": format!("{TOKEN:#x}")},
        "native_value": {"eq": "0"}
    }]}));
    assert_eq!(
        outcome(&subject, &one_call(TOKEN, "0xdeadbeef", "0")),
        PolicyOutcome::Allowed
    );
    assert_eq!(
        outcome(&subject, &one_call(ROUTER, "0x", "0")),
        PolicyOutcome::RequiresApproval
    );
    assert_eq!(
        outcome(&subject, &one_call(TOKEN, "0x", "1")),
        PolicyOutcome::RequiresApproval
    );
    assert_eq!(
        outcome(&subject, &plan(8453, &[(TOKEN, "0x", "0")])),
        PolicyOutcome::RequiresApproval
    );
}

#[test]
fn every_call_in_a_batch_must_be_allowed() {
    let subject = policy(json!({"version": 1, "rules": [{
        "effect": "allow", "to": {"eq": format!("{TOKEN:#x}")}
    }]}));
    let result = findings(
        &subject,
        &plan(1, &[(TOKEN, "0x", "0"), (ROUTER, "0x", "0")]),
    );
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].step, Some(2));
    assert_eq!(policy_outcome(&result), PolicyOutcome::RequiresApproval);
}

#[test]
fn any_denied_call_rejects_the_whole_batch() {
    let subject = policy(json!({"version": 1, "rules": [
        {"effect": "deny", "to": {"eq": format!("{ROUTER:#x}")}},
        {"effect": "allow"}
    ]}));
    let result = findings(
        &subject,
        &plan(1, &[(TOKEN, "0x", "0"), (ROUTER, "0x", "0")]),
    );
    assert_eq!(policy_outcome(&result), PolicyOutcome::Rejected);
    assert_eq!(denial_reasons(&result).len(), 1);
}

#[test]
fn selector_arguments_and_integer_comparisons_are_enforced() {
    let subject = policy(json!({"version": 1, "rules": [{
        "effect": "allow",
        "to": {"eq": format!("{TOKEN:#x}")},
        "calldata": {"selector": {
            "abi": "approve(address spender, uint256 amount)",
            "args": {
                "spender": {"eq": format!("{ROUTER:#x}")},
                "amount": {"lte": "100"}
            }
        }}
    }]}));
    assert_eq!(
        outcome(&subject, &one_call(TOKEN, &approve(ROUTER, 100), "0")),
        PolicyOutcome::Allowed
    );
    assert_eq!(
        outcome(&subject, &one_call(TOKEN, &approve(ROUTER, 101), "0")),
        PolicyOutcome::RequiresApproval
    );
    assert_eq!(
        outcome(&subject, &one_call(TOKEN, &approve(WALLET, 1), "0")),
        PolicyOutcome::RequiresApproval
    );
}

#[test]
fn selector_matching_refuses_policy_unchecked_trailing_calldata() {
    let subject = policy(json!({"version": 1, "rules": [{
        "effect": "allow",
        "calldata": {"selector": {"abi": "approve(address spender, uint256 amount)"}}
    }]}));
    let data = format!("{}00", approve(ROUTER, 1));
    assert_eq!(
        outcome(&subject, &one_call(TOKEN, &data, "0")),
        PolicyOutcome::RequiresApproval
    );
}

#[test]
fn malformed_selector_data_falls_through_to_a_later_rule() {
    let subject = policy(json!({"version": 1, "rules": [
        {"effect": "deny", "calldata": {"selector": {
            "abi": "approve(address spender, uint256 amount)",
            "args": {"amount": {"gt": "0"}}
        }}},
        {"effect": "allow", "to": {"eq": format!("{TOKEN:#x}")}}
    ]}));
    assert_eq!(
        outcome(&subject, &one_call(TOKEN, "0x095ea7b3", "0")),
        PolicyOutcome::Allowed
    );
}

#[test]
fn provably_shadowed_rules_are_rejected() {
    let error = WalletPolicy::parse(json!({"version": 1, "rules": [
        {"effect": "allow", "chain_id": {"eq": "1"}},
        {"effect": "deny", "chain_id": {"eq": "1"}, "to": {"eq": format!("{TOKEN:#x}")}}
    ]}))
    .unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("rule 2 is unreachable"), "{error}");
}

#[test]
fn equivalent_typed_literals_cannot_hide_a_shadowed_rule() {
    let error = WalletPolicy::parse(serde_json::json!({
        "version": 1,
        "rules": [
            {"effect": "allow", "chain_id": {"eq": "0x10"}},
            {"effect": "deny", "chain_id": {"eq": "16"}}
        ]
    }))
    .unwrap_err();
    assert!(format!("{error:#}").contains("rule 2 is unreachable"));
}

#[test]
fn old_policy_vocabulary_is_rejected() {
    for document in [
        json!({"version": 1, "chains": {}}),
        json!({"version": 1, "rules": [], "max_calls_per_batch": 1}),
        json!({"version": 1, "rules": [{"effect": "allow", "from": {"eq": "$self"}}]}),
        json!({"version": 1, "rules": [{"effect": "allow", "value": {"eq": "0"}}]}),
        json!({"version": 1, "rules": [{"effect": "allow", "delegation": {"in": ["0"]}}]}),
    ] {
        assert!(WalletPolicy::parse(document).is_err());
    }
}

#[test]
fn version_and_rules_are_required_and_unknown_fields_are_rejected() {
    assert!(WalletPolicy::parse(json!({"rules": []})).is_err());
    assert!(WalletPolicy::parse(json!({"version": 1})).is_err());
    assert!(WalletPolicy::parse(json!({"version": 2, "rules": []})).is_err());
    assert!(WalletPolicy::parse(json!({"version": 1, "rules": [], "extra": true})).is_err());
    assert!(WalletPolicy::parse(json!({"version": 1, "rules": []})).is_ok());
}

#[test]
fn rule_count_is_bounded_before_shadow_analysis() {
    let rules = (0..257)
        .map(|index| json!({"effect": "allow", "chain_id": {"eq": index.to_string()}}))
        .collect::<Vec<_>>();
    let error = WalletPolicy::parse(json!({"version": 1, "rules": rules})).unwrap_err();
    assert!(format!("{error:#}").contains("at most 256 rules"));
}

#[test]
fn predicates_are_checked_against_their_slots() {
    assert!(
        WalletPolicy::parse(json!({"version": 1, "rules": [{
            "effect": "allow", "native_value": {"eq": "$self"}
        }]}))
        .is_err()
    );
    assert!(
        WalletPolicy::parse(json!({"version": 1, "rules": [{
            "effect": "allow", "chain_id": {"selector": {"abi": "x()"}}
        }]}))
        .is_err()
    );
}

#[test]
fn direct_deserialization_uses_the_same_admission_boundary() {
    let document = json!({
        "$schema": "https://example.invalid/policy.schema.json",
        "version": 1,
        "rules": [{
            "effect": "deny",
            "label": "No calls to this address",
            "chain_id": {"in": ["1", "8453"]},
            "to": {"eq": format!("{ROUTER:#x}")},
            "native_value": {"eq": "0"},
            "calldata": {"eq": "0x"}
        }]
    });
    let parsed: WalletPolicy = serde_json::from_value(document.clone()).expect("admissible");
    assert_eq!(serde_json::to_value(parsed).unwrap(), document);
}

#[test]
fn labels_are_bounded_and_sanitized_at_the_policy_boundary() {
    assert!(
        WalletPolicy::parse(json!({"version": 1, "rules": [{
            "effect": "allow", "label": "", "to": {"eq": format!("{TOKEN:#x}")}
        }]}))
        .is_err()
    );
    assert!(
        WalletPolicy::parse(json!({"version": 1, "rules": [{
            "effect": "allow", "label": "x".repeat(161), "to": {"eq": format!("{TOKEN:#x}")}
        }]}))
        .is_err()
    );
}

#[test]
fn named_addresses_are_filtered_by_chain_matchers() {
    let subject = policy(json!({"version": 1, "rules": [
        {"effect": "allow", "chain_id": {"eq": "1"}, "to": {"eq": format!("{TOKEN:#x}")}},
        {"effect": "allow", "chain_id": {"eq": "8453"}, "to": {"eq": format!("{ROUTER:#x}")}}
    ]}));
    assert_eq!(subject.named_addresses(U256::from(1)), vec![TOKEN]);
    assert_eq!(subject.named_addresses(U256::from(8453)), vec![ROUTER]);
}

#[test]
fn diffs_are_position_aware_because_order_is_authority() {
    let current = policy(json!({"version": 1, "rules": [
        {"effect": "allow", "chain_id": {"eq": "1"}},
        {"effect": "deny", "to": {"eq": format!("{TOKEN:#x}")}}
    ]}));
    let proposed = policy(json!({"version": 1, "rules": [
        {"effect": "deny", "to": {"eq": format!("{TOKEN:#x}")}},
        {"effect": "allow", "chain_id": {"eq": "1"}}
    ]}));
    let diff = diff_policies(&current, &proposed);
    assert_eq!(diff.len(), 2);
    assert!(diff[0].contains("rule 1 changed"));
    assert!(diff[1].contains("rule 2 changed"));
}

#[test]
fn schema_describes_the_ordered_v1_surface() {
    let schema = json_schema().to_string();
    assert!(schema.contains("First matching rule wins"));
    assert!(schema.contains("native_value"));
    assert!(schema.contains("chain_id"));
    assert!(schema.contains("tuple"));
    assert!(!schema.contains("max_calls_per_batch"));
    assert!(!schema.contains("ChainPolicy"));
}
