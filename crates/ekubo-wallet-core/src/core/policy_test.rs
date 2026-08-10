//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.

use super::*;
use crate::core::predicate::PolicyContext;
use alloy::primitives::{Address, address};
use proptest::prelude::*;
use serde_json::json;

const WALLET: Address = address!("1111111111111111111111111111111111111111");
const TOKEN: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
const ROUTER: Address = address!("2222222222222222222222222222222222222222");

fn context() -> PolicyContext {
    PolicyContext { wallet: WALLET }
}

/// A one-step plan calling `to` with `data` and `value` wei.
fn plan_with(to: Address, data: &str, value: &str) -> ExecutionPlan {
    ExecutionPlan::parse(json!({
        "schema_version": "1",
        "chain_id": "1",
        "caip2_chain_id": "eip155:1",
        "sender": format!("{WALLET:#x}"),
        "ordered_steps": [{
            "step": 1,
            "kind": "execution",
            "transaction": {
                "chain_id": "1",
                "from": format!("{WALLET:#x}"),
                "to": format!("{to:#x}"),
                "data": data,
                "value": value
            }
        }]
    }))
    .expect("plan parses")
}

fn two_step_plan(first: Address, second: Address) -> ExecutionPlan {
    ExecutionPlan::parse(json!({
        "schema_version": "1",
        "chain_id": "1",
        "caip2_chain_id": "eip155:1",
        "sender": format!("{WALLET:#x}"),
        "ordered_steps": [
            { "step": 1, "kind": "execution", "transaction": {
                "chain_id": "1", "from": format!("{WALLET:#x}"),
                "to": format!("{first:#x}"), "data": "0xaabbccdd", "value": "0" }},
            { "step": 2, "kind": "execution", "transaction": {
                "chain_id": "1", "from": format!("{WALLET:#x}"),
                "to": format!("{second:#x}"), "data": "0xaabbccdd", "value": "0" }}
        ]
    }))
    .expect("plan parses")
}

fn approve_calldata(spender: Address, amount: u64) -> String {
    format!("0x095ea7b3{:0>64}{amount:064x}", format!("{spender:x}"))
}

fn policy(value: serde_json::Value) -> WalletPolicy {
    WalletPolicy::parse(value).expect("policy parses")
}

fn allows(subject: &WalletPolicy, plan: &ExecutionPlan) -> bool {
    policy_allows(&evaluate_policy(plan, subject, &context()))
}

fn codes(subject: &WalletPolicy, plan: &ExecutionPlan) -> Vec<String> {
    evaluate_policy(plan, subject, &context())
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

fn generated(rules: &Vec<serde_json::Value>) -> WalletPolicy {
    WalletPolicy::parse(json!({
        "version": 1,
        "chains": { "1": { "native_value": "any_value", "rules": rules } }
    }))
    .expect("generated policy parses")
}

// ------------------------------------------------------------- the defaults

#[test]
fn a_policy_with_no_rules_denies_everything() {
    let empty = policy(json!({ "version": 1, "chains": { "1": {} } }));
    assert_eq!(
        codes(&empty, &plan_with(ROUTER, "0x12345678", "0")),
        ["call_not_allowed"]
    );
}

#[test]
fn the_shipped_deny_all_profile_denies_every_shape_of_call() {
    let deny_all = WalletPolicy::require_approval_for_everything();
    for (to, data, value) in [
        (ROUTER, "0x".to_string(), "0"),
        (ROUTER, "0x".to_string(), "1000"),
        (TOKEN, approve_calldata(ROUTER, 1), "0"),
        (ROUTER, "0xdeadbeef".to_string(), "0"),
    ] {
        assert!(
            !allows(&deny_all, &plan_with(to, &data, value)),
            "{to:#x} {data} {value} was allowed"
        );
    }
}

#[test]
fn the_shipped_allow_all_profile_permits_every_shape_of_call() {
    let allow_all = WalletPolicy::allow_all_with_approval();
    for (to, data, value) in [
        (ROUTER, "0x".to_string(), "0"),
        (ROUTER, "0x".to_string(), "1000000000000000000"),
        (TOKEN, approve_calldata(ROUTER, u64::MAX), "0"),
        (ROUTER, "0xdeadbeef".to_string(), "5"),
    ] {
        assert!(
            allows(&allow_all, &plan_with(to, &data, value)),
            "{to:#x} {data} {value} was denied"
        );
    }
}

#[test]
fn omitting_native_value_denies_native_value() {
    // The rule permits the call; the chain guard is what refuses the wei.
    let guarded = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [{ "effect": "allow" }] } }
    }));
    assert!(allows(&guarded, &plan_with(ROUTER, "0x", "0")));
    assert_eq!(
        codes(&guarded, &plan_with(ROUTER, "0x", "1")),
        ["native_value_not_allowed"]
    );
}

#[test]
fn no_rule_can_widen_the_native_value_guard() {
    let guarded = policy(json!({
        "version": 1,
        "chains": { "1": {
            "native_value": { "eq": "0" },
            "rules": [{ "effect": "allow", "value": { "eq": "1000" } }]
        }}
    }));
    assert_eq!(
        codes(&guarded, &plan_with(ROUTER, "0x", "1000")),
        ["native_value_not_allowed"],
        "the guard is a conjunction, not a default a rule overrides"
    );
}

// ------------------------------------------------------------- rule effects

#[test]
fn deny_beats_allow_however_the_rules_are_ordered() {
    let allow_rule = json!({ "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } });
    let deny_rule = json!({
        "effect": "deny",
        "calldata": { "selector": { "abi": "approve(address spender, uint256 amount)" } }
    });
    let plan = plan_with(TOKEN, &approve_calldata(ROUTER, 5), "0");
    for rules in [
        json!([allow_rule, deny_rule]),
        json!([deny_rule, allow_rule]),
    ] {
        let subject = policy(json!({ "version": 1, "chains": { "1": { "rules": rules } } }));
        assert_eq!(codes(&subject, &plan), ["call_denied"]);
    }
}

#[test]
fn a_rule_constrains_only_the_slots_it_names() {
    let subject = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [{
            "effect": "allow",
            "to": { "eq": format!("{TOKEN:#x}") }
        }]}}
    }));
    // Same target, wildly different calldata: still allowed, because the rule
    // says nothing about calldata. This is what `describe` warns about.
    assert!(allows(&subject, &plan_with(TOKEN, "0xdeadbeef", "0")));
    assert!(!allows(&subject, &plan_with(ROUTER, "0xdeadbeef", "0")));
}

#[test]
fn an_argument_predicate_decides_between_two_otherwise_identical_calls() {
    let subject = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [{
            "effect": "allow",
            "to": { "eq": format!("{TOKEN:#x}") },
            "calldata": { "selector": {
                "abi": "approve(address spender, uint256 amount)",
                "args": { "spender": { "in": ["0x2222222222222222222222222222222222222222"] } }
            }}
        }]}}
    }));
    assert!(allows(
        &subject,
        &plan_with(TOKEN, &approve_calldata(ROUTER, 1), "0")
    ));
    assert!(!allows(
        &subject,
        &plan_with(TOKEN, &approve_calldata(WALLET, 1), "0")
    ));
}

#[test]
fn a_familiar_selector_does_not_excuse_an_unnamed_target() {
    // The document a maintainer would actually write: one router it may call,
    // and small transfers of one token to a cold wallet. The predecessor to
    // this engine picked which half of the document graded a step from the
    // first four calldata bytes, so calldata beginning `transfer(address,
    // uint256)` was judged by the token rules alone and never consulted the
    // target allowlist — and four bytes are trivially brute-forced, so they
    // are no evidence the callee is a token at all.
    let cold = address!("3333333333333333333333333333333333333333");
    let attacker = address!("4444444444444444444444444444444444444444");
    let subject = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            {
                "effect": "allow",
                "to": { "eq": format!("{ROUTER:#x}") },
                "calldata": { "selector": { "abi": "swap(address token, uint256 amount)" } }
            },
            {
                "effect": "allow",
                "to": { "eq": format!("{TOKEN:#x}") },
                "calldata": { "selector": {
                    "abi": "transfer(address to, uint256 amount)",
                    "args": { "to": { "eq": format!("{cold:#x}") } }
                }}
            }
        ]}}
    }));
    let transfer_to_cold = format!("0xa9059cbb{:0>64}{:064x}", format!("{cold:x}"), 1_u64);
    assert!(allows(&subject, &plan_with(TOKEN, &transfer_to_cold, "0")));
    // Byte-identical calldata, a target the policy never named. Whatever this
    // contract does with the wallet's standing allowances, its delegation, or
    // its operator grants, no rule says the wallet may call it.
    assert_eq!(
        codes(&subject, &plan_with(attacker, &transfer_to_cold, "0")),
        vec![CALL_NOT_ALLOWED_CODE.to_string()]
    );
}

#[test]
fn every_step_of_a_batch_is_graded_independently() {
    let subject = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } }
        ]}}
    }));
    let findings = evaluate_policy(&two_step_plan(TOKEN, ROUTER), &subject, &context());
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].step,
        Some(2),
        "the second call is the unmatched one"
    );
}

// ------------------------------------------------------------------ chains

#[test]
fn an_exact_chain_entry_replaces_the_wildcard_rather_than_extending_it() {
    let subject = policy(json!({
        "version": 1,
        "chains": {
            "*": { "rules": [{ "effect": "allow" }] },
            "1": { "rules": [] }
        }
    }));
    assert!(
        !allows(&subject, &plan_with(ROUTER, "0x", "0")),
        "chain 1 has its own empty rule set"
    );
    assert!(
        subject.chain("8453").is_some(),
        "a chain with no entry still falls back to the wildcard"
    );
}

#[test]
fn a_chain_with_no_policy_at_all_is_refused() {
    let subject = policy(json!({ "version": 1, "chains": { "8453": { "rules": [] } } }));
    assert_eq!(
        codes(&subject, &plan_with(ROUTER, "0x", "0")),
        ["chain_not_allowed"]
    );
}

#[test]
fn batches_larger_than_the_chain_limit_are_refused() {
    let subject = policy(json!({
        "version": 1,
        "chains": { "1": { "max_calls_per_batch": 1, "rules": [{ "effect": "allow" }] } }
    }));
    assert!(
        codes(&subject, &two_step_plan(ROUTER, ROUTER)).contains(&"too_many_calls".to_string())
    );
}

// ------------------------------------------------------------------ parsing

#[test]
fn only_version_one_parses() {
    assert!(WalletPolicy::parse(json!({ "version": 2, "chains": {} })).is_err());
    assert!(WalletPolicy::parse(json!({ "version": 1, "chains": {} })).is_ok());
}

#[test]
fn unknown_fields_are_refused_rather_than_ignored() {
    // The retired v2 vocabulary must not be silently accepted and ignored.
    assert!(
        WalletPolicy::parse(json!({
            "version": 1,
            "chains": { "1": { "rules": [], "tokens": {} } }
        }))
        .is_err()
    );
}

#[test]
fn a_rule_predicate_is_type_checked_against_its_slot_at_parse_time() {
    // an address predicate on the value slot could never match a uint.
    assert!(
        WalletPolicy::parse(json!({
            "version": 1,
            "chains": { "1": { "rules": [{ "effect": "allow", "value": { "eq": "$self" } }] } }
        }))
        .is_err()
    );
    // A bare-hex address literal is refused at install time, not at signing.
    assert!(
        WalletPolicy::parse(json!({
            "version": 1,
            "chains": { "1": { "rules": [{
                "effect": "allow",
                "to": { "eq": "1111111111111111111111111111111111111111" }
            }]}}
        }))
        .is_err()
    );
}

#[test]
fn chain_keys_must_be_canonical_decimal_or_the_wildcard() {
    for key in ["01", "0x1", "one", ""] {
        assert!(
            WalletPolicy::parse(json!({ "version": 1, "chains": { key: { "rules": [] } } }))
                .is_err(),
            "{key} should be refused"
        );
    }
    for key in ["1", "0", "8453", "*"] {
        assert!(
            WalletPolicy::parse(json!({ "version": 1, "chains": { key: { "rules": [] } } }))
                .is_ok(),
            "{key} should parse"
        );
    }
}

#[test]
fn the_digest_is_stable_across_equivalent_spellings() {
    let one = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [{
            "effect": "allow",
            "calldata": { "selector": { "abi": "approve(address spender,uint256 amount)" } }
        }]}}
    }));
    let two = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [{
            "effect": "allow",
            "calldata": { "selector": { "abi": "approve(address spender, uint256 amount)" } }
        }]}}
    }));
    assert_eq!(one.digest().unwrap(), two.digest().unwrap());
}

// -------------------------------------------------------------------- diffs

#[test]
fn a_removed_rule_still_covered_by_another_reads_as_covered_not_as_a_loss() {
    let current = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } },
            { "effect": "allow" }
        ]}}
    }));
    let proposed = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [{ "effect": "allow" }] }}
    }));
    let diff = diff_policies(&current, &proposed);
    assert!(
        diff.iter().any(|line| line.contains("still covered by")),
        "{diff:?}"
    );
    assert!(
        !diff.iter().any(|line| line.starts_with("- ")),
        "a widening must never render as a removal: {diff:?}"
    );
}

#[test]
fn a_genuinely_removed_rule_reads_as_a_loss() {
    let current = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } }
        ]}}
    }));
    let proposed = policy(json!({ "version": 1, "chains": { "1": { "rules": [] }}}));
    let diff = diff_policies(&current, &proposed);
    assert!(diff.iter().any(|line| line.starts_with("- ")), "{diff:?}");
}

#[test]
fn an_unconstrained_calldata_slot_is_called_out_in_the_diff() {
    let current = policy(json!({ "version": 1, "chains": { "1": { "rules": [] }}}));
    let proposed = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "to": { "eq": format!("{ROUTER:#x}") } }
        ]}}
    }));
    let diff = diff_policies(&current, &proposed);
    assert!(
        diff.iter()
            .any(|line| line.contains("any calldata, including batched calls")),
        "a reviewer must be told the payload is unbounded: {diff:?}"
    );
}

#[test]
fn an_identical_policy_reports_no_change() {
    let subject = WalletPolicy::allow_all_with_approval();
    assert_eq!(
        diff_policies(&subject, &subject),
        ["No permission changes: the proposed policy is identical."]
    );
}

// ----------------------------------------------------------------- fuzzing

fn rule_strategy() -> impl Strategy<Value = serde_json::Value> {
    let targets = prop::sample::select(vec![
        format!("{TOKEN:#x}"),
        format!("{ROUTER:#x}"),
        format!("{WALLET:#x}"),
    ]);
    (
        prop::sample::select(vec!["allow", "deny"]),
        prop::option::of(targets),
        prop::option::of(prop::sample::select(vec!["0", "1", "1000"])),
    )
        .prop_map(|(effect, to, value)| {
            let mut rule = serde_json::Map::new();
            rule.insert("effect".into(), json!(effect));
            if let Some(to) = to {
                rule.insert("to".into(), json!({ "eq": to }));
            }
            if let Some(value) = value {
                rule.insert("value".into(), json!({ "eq": value }));
            }
            serde_json::Value::Object(rule)
        })
}

fn call_strategy() -> impl Strategy<Value = (Address, String, String)> {
    (
        prop::sample::select(vec![TOKEN, ROUTER, WALLET, Address::ZERO]),
        prop::sample::select(vec!["0x", "0xdeadbeef"]),
        prop::sample::select(vec!["0", "1", "1000"]),
    )
        .prop_map(|(to, data, value)| (to, data.to_string(), value.to_string()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(768))]

    /// Rules form a set, so permuting them can never change a decision. This
    /// is what lets the permission diff be a diff of the document rather than
    /// a simulation of it.
    #[test]
    fn shuffling_the_rules_never_changes_the_decision(
        rules in prop::collection::vec(rule_strategy(), 0..6),
        call in call_strategy(),
        rotation in 0usize..6,
    ) {
        let (to, data, value) = call;
        let plan = plan_with(to, &data, &value);
        let mut rotated = rules.clone();
        let count = rotated.len();
        if count > 0 {
            rotated.rotate_left(rotation % count);
        }
        prop_assert_eq!(
            allows(&generated(&rules), &plan),
            allows(&generated(&rotated), &plan)
        );
    }

    /// Adding a deny rule can only ever remove authority, never add it.
    #[test]
    fn adding_a_deny_rule_never_grants_anything(
        rules in prop::collection::vec(rule_strategy(), 0..5),
        extra in rule_strategy(),
        call in call_strategy(),
    ) {
        let (to, data, value) = call;
        let plan = plan_with(to, &data, &value);
        let mut denial = extra;
        denial["effect"] = json!("deny");
        let before = allows(&generated(&rules), &plan);
        let mut widened = rules.clone();
        widened.push(denial);
        let after = allows(&generated(&widened), &plan);
        prop_assert!(before || !after, "a deny rule granted authority");
    }

    /// Removing an allow rule can only ever remove authority.
    #[test]
    fn dropping_an_allow_rule_never_grants_anything(
        rules in prop::collection::vec(rule_strategy(), 1..6),
        index in 0usize..6,
        call in call_strategy(),
    ) {
        let (to, data, value) = call;
        let plan = plan_with(to, &data, &value);
        let allow_positions = rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule["effect"] == json!("allow"))
            .map(|(position, _)| position)
            .collect::<Vec<_>>();
        if allow_positions.is_empty() {
            return Ok(());
        }
        let position = allow_positions[index % allow_positions.len()];
        let before = allows(&generated(&rules), &plan);
        let mut narrowed = rules.clone();
        narrowed.remove(position);
        let after = allows(&generated(&narrowed), &plan);
        prop_assert!(
            before || !after,
            "dropping an allow rule granted authority"
        );
    }

    /// The decision is total: an allowed call carries no error finding, and a
    /// denied one always names why rather than falling through silently.
    #[test]
    fn every_call_is_decided_and_the_default_is_deny(
        rules in prop::collection::vec(rule_strategy(), 0..5),
        call in call_strategy(),
    ) {
        let (to, data, value) = call;
        let plan = plan_with(to, &data, &value);
        let findings = evaluate_policy(&plan, &generated(&rules), &context());
        if policy_allows(&findings) {
            prop_assert!(findings.is_empty());
        } else {
            let named = findings
                .iter()
                .any(|finding| finding.code == "call_denied" || finding.code == "call_not_allowed");
            prop_assert!(named, "a denial must name why it denied");
        }
    }

    /// Whatever the call looks like, the deny-all profile denies it.
    #[test]
    fn the_deny_all_profile_has_no_hole(call in call_strategy()) {
        let (to, data, value) = call;
        let plan = plan_with(to, &data, &value);
        prop_assert!(!allows(&WalletPolicy::require_approval_for_everything(), &plan));
    }
}

// --------------------------------------------- unreadable encodings

#[test]
fn a_denied_call_cannot_escape_by_being_encoded_unreadably() {
    // The carve-out shape: a broad allow with a narrow deny over it. Appending
    // one byte to the calldata used to un-match the deny — a target contract's
    // decoder ignores trailing bytes and performs the approve regardless —
    // while leaving the broad allow matching, so the call signed automatically.
    let subject = policy(json!({
        "version": 1,
        "chains": { "1": {
            "max_calls_per_batch": 4,
            "native_value": { "eq": "0" },
            "rules": [
                { "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } },
                { "effect": "deny",
                  "to": { "eq": format!("{TOKEN:#x}") },
                  "calldata": { "selector": {
                      "abi": "approve(address spender, uint256 amount)" } } }
            ]
        }}
    }));

    let honest = approve_calldata(ROUTER, 1);
    assert!(
        codes(&subject, &plan_with(TOKEN, &honest, "0")).contains(&CALL_DENIED_CODE.to_owned())
    );
    assert!(
        codes(&subject, &plan_with(TOKEN, &format!("{honest}00"), "0"))
            .contains(&CALL_DENIED_CODE.to_owned()),
        "a trailing byte must not buy the approve this deny rule names"
    );
    assert!(!allows(
        &subject,
        &plan_with(TOKEN, &format!("{honest}00"), "0")
    ));
}

#[test]
fn a_negated_selector_does_not_admit_an_unreadable_call() {
    // "Allow anything that is not an approve." Reported as a plain non-match,
    // an unreadable approve satisfied the negation and was the one call the
    // rule existed to exclude.
    let subject = policy(json!({
        "version": 1,
        "chains": { "1": {
            "max_calls_per_batch": 4,
            "native_value": { "eq": "0" },
            "rules": [
                { "effect": "allow",
                  "to": { "eq": format!("{TOKEN:#x}") },
                  "calldata": { "not": { "selector": {
                      "abi": "approve(address spender, uint256 amount)" } } } }
            ]
        }}
    }));

    assert!(
        allows(&subject, &plan_with(TOKEN, "0xaabbccdd", "0")),
        "an unrelated call is still allowed"
    );
    let honest = approve_calldata(ROUTER, 1);
    assert!(!allows(&subject, &plan_with(TOKEN, &honest, "0")));
    assert!(
        !allows(&subject, &plan_with(TOKEN, &format!("{honest}00"), "0")),
        "a trailing byte must not invert the negation"
    );
}

// ------------------------------------------------ diff direction

#[test]
fn removing_a_deny_rule_reads_as_a_widening() {
    // The marker states the direction of the change, not which document the
    // rule sits in. Dropping a deny hands authority back, so it must not be
    // shown under the same sign as dropping an allow.
    let current = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } },
            { "effect": "deny", "label": "no router", "to": { "eq": format!("{ROUTER:#x}") } }
        ]}}
    }));
    let proposed = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } }
        ]}}
    }));

    let diff = diff_policies(&current, &proposed);
    let line = diff
        .iter()
        .find(|line| line.contains("no router"))
        .unwrap_or_else(|| panic!("the dropped deny must be reported: {diff:?}"));
    assert!(
        line.starts_with("+ ") && line.contains("stops denying"),
        "dropping a deny grants authority and must read that way: {line}"
    );
    assert!(
        !diff.iter().any(|line| line.starts_with("- ")),
        "nothing here takes authority away: {diff:?}"
    );
}

#[test]
fn adding_a_deny_rule_reads_as_a_narrowing() {
    let current = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } }
        ]}}
    }));
    let proposed = policy(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "to": { "eq": format!("{TOKEN:#x}") } },
            { "effect": "deny", "label": "no router", "to": { "eq": format!("{ROUTER:#x}") } }
        ]}}
    }));

    let diff = diff_policies(&current, &proposed);
    let line = diff
        .iter()
        .find(|line| line.contains("no router"))
        .unwrap_or_else(|| panic!("the added deny must be reported: {diff:?}"));
    assert!(
        line.starts_with("- ") && line.contains("starts denying"),
        "adding a deny takes authority away and must read that way: {line}"
    );
}

#[test]
fn a_chain_taking_its_own_rules_is_diffed_against_the_fallback_it_leaves() {
    // The chain was already governed, by (*), so "now governed" would be a
    // false description — and the authority it actually gains is only what
    // its own rules add over the fallback's.
    let shared =
        json!({ "effect": "allow", "label": "token", "to": { "eq": format!("{TOKEN:#x}") } });
    let current = policy(json!({
        "version": 1,
        "chains": { "*": { "rules": [shared] }}
    }));
    let proposed = policy(json!({
        "version": 1,
        "chains": {
            "*": { "rules": [shared] },
            "1": { "rules": [
                shared,
                { "effect": "allow", "label": "router", "to": { "eq": format!("{ROUTER:#x}") } }
            ]}
        }
    }));

    let diff = diff_policies(&current, &proposed);
    assert!(
        diff.iter()
            .any(|line| line.contains("stops following every chain (*)")),
        "the fallback it leaves must be named: {diff:?}"
    );
    assert!(
        !diff.iter().any(|line| line.contains("now governed")),
        "the chain was already governed by the fallback: {diff:?}"
    );
    let granted: Vec<_> = diff.iter().filter(|line| line.starts_with("+ ")).collect();
    assert_eq!(
        granted.len(),
        1,
        "only the rule the fallback did not already carry is new authority: {diff:?}"
    );
    assert!(granted[0].contains("router"), "{diff:?}");
}

#[test]
fn replacing_a_delegation_asks_a_person_rather_than_being_denied_or_allowed() {
    // The three outcomes mean three different things, and this finding has to
    // land on the middle one. `Allowed` would sign the authorization with
    // nobody told; `Rejected` would need the owner to edit a policy that has
    // no way to speak about delegations at all, and would refuse a
    // replacement they may well want.
    let finding = PolicyFinding {
        severity: FindingSeverity::Error,
        code: DELEGATION_REPLACED_CODE.into(),
        message: "would replace the delegation".into(),
        step: None,
    };
    assert!(!policy_allows(std::slice::from_ref(&finding)));
    assert_eq!(
        policy_outcome(std::slice::from_ref(&finding)),
        PolicyOutcome::RequiresApproval
    );
    assert!(denial_reasons(std::slice::from_ref(&finding)).is_empty());
}

#[test]
fn authorizing_a_first_delegation_is_disclosed_without_blocking_the_batch() {
    // The companion to the finding above, and the reason it exists: whether
    // `delegation_replaced` fires at all is decided by a single `get_code_at`
    // answer. An endpoint reporting empty code for an account that is really
    // delegated elsewhere produced no delegation finding whatsoever, while the
    // wallet went on to sign the authorization -- so the replacement happened
    // on chain with the document silent about delegations entirely.
    //
    // This one is therefore not conditional on that answer being honest. It
    // must stay a warning: every account's first batch authorizes a
    // delegation, and making that `RequiresApproval` would mean no unattended
    // batch could ever run.
    let finding = PolicyFinding {
        severity: FindingSeverity::Warning,
        code: DELEGATION_AUTHORIZED_CODE.into(),
        message: "would authorize a delegation".into(),
        step: None,
    };
    assert!(policy_allows(std::slice::from_ref(&finding)));
    assert_eq!(
        policy_outcome(std::slice::from_ref(&finding)),
        PolicyOutcome::Allowed,
        "disclosure must not turn every first batch into an approval prompt"
    );

    // And it never displaces the stronger finding when both could apply.
    let replaced = PolicyFinding {
        severity: FindingSeverity::Error,
        code: DELEGATION_REPLACED_CODE.into(),
        message: "would replace the delegation".into(),
        step: None,
    };
    let both = [finding, replaced];
    assert_eq!(policy_outcome(&both), PolicyOutcome::RequiresApproval);
}

#[test]
fn an_unreadable_token_balance_stops_the_automatic_path() {
    // Deliberately an error rather than a warning, unlike
    // `delegation_authorized` above. The two are different questions: a first
    // delegation is a thing the wallet knows it is doing and discloses, while
    // this is the wallet saying it does not know how much of a limited token
    // moved. Enforcing a spending limit against a number nobody has is not
    // something an unattended signature should do.
    let finding = PolicyFinding {
        severity: FindingSeverity::Error,
        code: TOKEN_BALANCE_UNVERIFIED_CODE.into(),
        message: "balance of 0xaa.. could not be read".into(),
        step: None,
    };
    assert!(!policy_allows(std::slice::from_ref(&finding)));
    assert_eq!(
        policy_outcome(std::slice::from_ref(&finding)),
        PolicyOutcome::RequiresApproval,
        "a human can still override it; the policy has no rule to edit that would help"
    );
    // Not a denial: `denial_reasons` names rules the owner could change, and
    // there is no rule that makes an unreadable token readable.
    assert!(denial_reasons(std::slice::from_ref(&finding)).is_empty());
}

mod admission_tests_belong_to_the_types {
    //! Deserializing any policy type is admission, not just
    //! `WalletPolicy::parse`.
    //!
    //! The checks used to hang off `parse` alone, so `from_value` was a second
    //! door into the same authority-bearing types that skipped every one of
    //! them. `evaluate_policy` then read `max_calls_per_batch` from whatever it
    //! was handed, so a policy that never passed admission decided what signed
    //! automatically.

    use crate::core::policy::{ChainPolicy, Rule, WalletPolicy};
    use serde_json::json;

    /// The finding's own repro, at the type it names. Deserialization is the
    /// only way an out-of-crate caller can build one of these at all, so
    /// refusing here is refusing everywhere.
    #[test]
    fn a_directly_deserialized_policy_cannot_exceed_the_batch_ceiling() {
        let document = json!({
            "version": 1,
            "chains": {"1": {"max_calls_per_batch": 5000, "rules": []}}
        });

        let direct = serde_json::from_value::<WalletPolicy>(document.clone())
            .expect_err("4096 is the ceiling however the policy was built");
        assert!(
            direct.to_string().contains("max_calls_per_batch"),
            "{direct}"
        );

        // And `parse` still says the same thing, because it is now the same
        // door rather than the only checked one.
        assert!(WalletPolicy::parse(document).is_err());
    }

    /// One level down: a chain policy lifted out of a fragment on its own is
    /// checked by the code that checks one reached through a document. Left
    /// unchecked, the same value arrives at `evaluate_policy` inside a
    /// `WalletPolicy` a caller assembled around it.
    #[test]
    fn a_chain_policy_deserialized_on_its_own_is_checked_too() {
        assert!(
            serde_json::from_value::<ChainPolicy>(json!({"max_calls_per_batch": 5000})).is_err()
        );
        assert!(serde_json::from_value::<ChainPolicy>(json!({"max_calls_per_batch": 0})).is_err());
        assert!(serde_json::from_value::<ChainPolicy>(json!({"label": ""})).is_err());
        assert!(
            serde_json::from_value::<ChainPolicy>(json!({"max_calls_per_batch": 4096})).is_ok(),
            "the ceiling itself is admissible"
        );
    }

    /// And a rule, whose invariant is that each predicate is applicable to the
    /// slot holding it. A `length` predicate over an address decides nothing;
    /// admitted, it silently never matches, so a rule the owner reviewed as a
    /// restriction restricts nothing.
    #[test]
    fn a_rule_deserialized_on_its_own_has_its_slots_checked() {
        let inapplicable = json!({"effect": "allow", "to": {"length": {"eq": "20"}}});
        let error = serde_json::from_value::<Rule>(inapplicable.clone())
            .expect_err("a predicate must be applicable to the slot it sits in");
        assert!(error.to_string().contains("applicable"), "{error}");

        // The same rule inside a document is refused by the same code, so the
        // two paths cannot disagree about what a valid rule is.
        assert!(
            serde_json::from_value::<WalletPolicy>(json!({
                "version": 1,
                "chains": {"1": {"rules": [inapplicable]}}
            }))
            .is_err()
        );
    }

    /// Version and chain keys are `WalletPolicy`'s own, and they travel with
    /// the type rather than with one constructor.
    #[test]
    fn the_document_level_checks_travel_with_the_type() {
        assert!(
            serde_json::from_value::<WalletPolicy>(json!({"version": 2, "chains": {}})).is_err()
        );
        assert!(
            serde_json::from_value::<WalletPolicy>(json!({"chains": {"01": {}}})).is_err(),
            "a non-canonical chain key governs nothing and must not be admitted"
        );
        assert!(
            serde_json::from_value::<WalletPolicy>(json!({"chains": {}})).is_ok(),
            "and an empty document is still a policy: it governs nothing automatically"
        );
    }

    /// The guard on the private mirrors this fix introduced. A field added to
    /// a public type and forgotten in its mirror would be rejected by the
    /// mirror's `deny_unknown_fields` rather than quietly skipping validation
    /// — this is the test that notices, by round-tripping a document that
    /// names every field there is.
    #[test]
    fn every_field_survives_a_round_trip_through_the_validating_deserializer() {
        let document = json!({
            "$schema": "https://example.invalid/policy.schema.json",
            "version": 1,
            "chains": {
                "*": {
                    "label": "every chain",
                    "max_calls_per_batch": 32,
                    "native_value": {"eq": "0"},
                    "rules": [{
                        "effect": "deny",
                        "label": "no calls to the stranger",
                        "to": {"eq": "0x3333333333333333333333333333333333333333"},
                        "from": {"eq": "$self"},
                        "value": {"eq": "0"},
                        "calldata": {"eq": "0x"}
                    }]
                }
            }
        });
        let policy: WalletPolicy = serde_json::from_value(document.clone()).expect("admissible");
        assert_eq!(
            serde_json::to_value(&policy).expect("serializes"),
            document,
            "a field dropped by a mirror would vanish here"
        );
        // Every shipped example is likewise admissible through `from_value`
        // and not only through `parse`.
        assert_eq!(policy.chains.len(), 1);
    }
}

mod admission_bounds_tests {
    //! Admission does bounded work, and the bound belongs to the policy
    //! language rather than to whichever parser delivered the document.

    use crate::core::{
        policy::WalletPolicy,
        predicate::{MAX_PREDICATE_DEPTH, MAX_PREDICATE_NODES},
    };
    use serde_json::{Value, json};

    /// `{"not": {"not": {... }}}`, `depth` levels of it.
    fn nested(depth: usize) -> Value {
        let mut predicate = json!("any_value");
        for _ in 0..depth {
            predicate = json!({ "not": predicate });
        }
        predicate
    }

    fn policy_with(calldata: &Value) -> Value {
        json!({
            "version": 1,
            "chains": {"1": {"rules": [{"effect": "allow", "calldata": calldata}]}}
        })
    }

    /// The stack was never actually unbounded -- `serde_json` refuses past 128
    /// levels while parsing -- but that is a constant inside a dependency's
    /// parser, not a fact about this type. It says nothing about a `Predicate`
    /// reached any other way, and this crate would not notice it changing.
    #[test]
    fn a_predicate_nested_past_the_limit_is_refused() {
        let error = format!(
            "{:#}",
            WalletPolicy::parse(policy_with(&nested(MAX_PREDICATE_DEPTH + 4)))
                .expect_err("a tree nobody can review is not admissible")
        );
        assert!(error.contains("nests deeper"), "{error}");
    }

    /// And the limit is far enough above real documents that reaching it means
    /// something is wrong. The deepest shipped example nests four.
    #[test]
    fn an_ordinarily_nested_predicate_is_admitted() {
        WalletPolicy::parse(policy_with(&nested(4))).expect("four levels is an ordinary policy");
    }

    /// Depth alone would miss this: one level, enormous sideways. The node
    /// budget is what bounds the work rather than the stack.
    #[test]
    fn a_predicate_that_is_wide_rather_than_deep_is_refused() {
        let literals: Vec<String> = (0..=MAX_PREDICATE_NODES)
            .map(|index| format!("{index}"))
            .collect();
        let error = format!(
            "{:#}",
            WalletPolicy::parse(policy_with(&json!({ "in": literals })))
                .expect_err("a million-entry set is not a reviewable rule")
        );
        assert!(error.contains("more than"), "{error}");
    }

    /// The counts around the rules are bounded too, so admission cannot be
    /// made expensive by repetition instead of by nesting.
    #[test]
    fn a_document_with_too_many_rules_is_refused() {
        let rules: Vec<Value> = (0..2_000)
            .map(|_| json!({"effect": "allow", "calldata": "any_value"}))
            .collect();
        assert!(
            WalletPolicy::parse(json!({
                "version": 1,
                "chains": {"1": {"rules": rules}}
            }))
            .is_err()
        );

        let chains: serde_json::Map<String, Value> = (1..=300)
            .map(|index| (index.to_string(), json!({"rules": []})))
            .collect();
        assert!(WalletPolicy::parse(json!({"version": 1, "chains": chains})).is_err());
    }
}
