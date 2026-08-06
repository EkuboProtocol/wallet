//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::core::execution_plan::ExecutionPlan;
use serde_json::json;

fn transfer_plan() -> ExecutionPlan {
    transfer_plan_of(U256::from(1_u8))
}

fn transfer_plan_of(amount: U256) -> ExecutionPlan {
    let data = format!(
        "0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333{amount:064x}"
    );
    ExecutionPlan::parse(json!({
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
                "data": data,
                "value": "0"
            }
        }]
    }))
    .unwrap()
}

fn wildcard_token_policy(limit: &str) -> WalletPolicy {
    WalletPolicy::parse(json!({
        "chains": {
            "1": {
                "targets": { "*": { "allow_any_calldata": true } },
                "tokens": {
                    "*": {
                        "max_spend_per_transaction": limit,
                        "transfer_recipients": { "*": {} }
                    }
                }
            }
        }
    }))
    .unwrap()
}

#[test]
fn removing_a_rule_under_a_wildcard_reads_as_widening_not_narrowing() {
    // Dropping the exact entry for a target while `*` survives does not
    // take the permission away — `exact_or_wildcard` hands the target to
    // the wildcard, which here allows any calldata rather than one
    // selector. A `-` line would tell the reviewer they were tightening
    // the policy while they approved the opposite.
    let current = WalletPolicy::parse(json!({
        "chains": {
            "1": {
                "targets": {
                    "0x2222222222222222222222222222222222222222": {
                        "allowed_selectors": { "0xa9059cbb": {} }
                    },
                    "*": { "allow_any_calldata": true }
                }
            }
        }
    }))
    .unwrap();
    let proposed = WalletPolicy::parse(json!({
        "chains": {
            "1": { "targets": { "*": { "allow_any_calldata": true } } }
        }
    }))
    .unwrap();

    let diff = diff_policies(&current, &proposed);
    assert!(
        diff.iter().any(|line| line.contains("falls back to (*)")),
        "{diff:?}"
    );
    assert!(
        !diff
            .iter()
            .any(|line| line.starts_with("- chain 1: target 0x2222")),
        "a widening was rendered as a removal: {diff:?}"
    );
}

#[test]
fn every_level_that_falls_back_says_so() {
    // Approval spenders, the tokens under them, and transfer recipients
    // all resolve through the same wildcard fallback, so all three have
    // to describe a removal that widens as a widening.
    let current = WalletPolicy::parse(json!({
            "chains": { "1": {
                "approval_spenders": {
                    "0x3333333333333333333333333333333333333333": {
                        "tokens": { "0x4444444444444444444444444444444444444444": { "max_amount": "5" } }
                    },
                    "*": { "tokens": { "*": { "max_amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935" } } }
                },
                "tokens": { "0x5555555555555555555555555555555555555555": {
                    "max_spend_per_transaction": "10",
                    "transfer_recipients": {
                        "0x6666666666666666666666666666666666666666": {},
                        "*": {}
                    }
                } }
            } }
        }))
        .unwrap();
    let proposed = WalletPolicy::parse(json!({
            "chains": { "1": {
                "approval_spenders": {
                    "*": { "tokens": { "*": { "max_amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935" } } }
                },
                "tokens": { "0x5555555555555555555555555555555555555555": {
                    "max_spend_per_transaction": "10",
                    "transfer_recipients": { "*": {} }
                } }
            } }
        }))
        .unwrap();

    let diff = diff_policies(&current, &proposed);
    let widenings = diff
        .iter()
        .filter(|line| line.contains("falls back"))
        .count();
    assert_eq!(widenings, 2, "{diff:?}");
    assert!(
        !diff.iter().any(|line| line.starts_with("- chain 1:")),
        "a widening was rendered as a removal: {diff:?}"
    );
}

#[test]
fn removing_a_rule_with_no_wildcard_is_still_a_removal() {
    let current = WalletPolicy::parse(json!({
        "chains": {
            "1": {
                "targets": {
                    "0x2222222222222222222222222222222222222222": {
                        "allow_any_calldata": true
                    }
                }
            }
        }
    }))
    .unwrap();
    let proposed = WalletPolicy::parse(json!({ "chains": { "1": {} } })).unwrap();
    let diff = diff_policies(&current, &proposed);
    assert!(
        diff.iter().any(|line| line.starts_with("- chain 1:")),
        "{diff:?}"
    );
}

#[test]
fn a_wildcard_token_rule_bounds_what_a_transfer_declares() {
    // A token whose Transfer event is not the canonical three-topic shape
    // produces no observed spend, and `*` is excluded from the balance
    // probes, so there was nothing for the limit to be measured against.
    // That made naming a token strictly stronger than covering it with a
    // wildcard — the opposite of what writing `*` reads like.
    let policy = wildcard_token_policy("1000000");
    let findings = evaluate_policy(
        &transfer_plan_of(U256::from(2_000_000_u64)),
        &policy,
        Some(&BTreeMap::new()),
    );
    assert!(!policy_allows(&findings), "{findings:?}");
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "token_spend_limit"),
        "{findings:?}"
    );
}

#[test]
fn a_transfer_within_the_wildcard_limit_still_passes() {
    let policy = wildcard_token_policy("1000000");
    let findings = evaluate_policy(
        &transfer_plan_of(U256::from(1_000_000_u64)),
        &policy,
        Some(&BTreeMap::new()),
    );
    assert!(policy_allows(&findings), "{findings:?}");
}

#[test]
fn default_policy_allows_transfer_and_normalizes_keys() {
    let policy = WalletPolicy::allow_all_with_approval();
    let spends = BTreeMap::from([(
        "0x2222222222222222222222222222222222222222".into(),
        BigUint::from(1_u8),
    )]);
    assert!(policy_allows(&evaluate_policy(
        &transfer_plan(),
        &policy,
        Some(&spends)
    )));
}

#[test]
fn exact_chain_replaces_wildcard() {
    let policy = WalletPolicy::parse(json!({
        "chains": {
            "*": { "targets": { "*": { "allow_any_calldata": true } } },
            "1": {}
        }
    }))
    .unwrap();
    assert!(!policy_allows(&evaluate_policy(
        &transfer_plan(),
        &policy,
        Some(&BTreeMap::new())
    )));
}

#[test]
fn a_policy_written_against_the_retired_simulation_switch_still_opens() {
    // Simulation is unconditional now. A stored policy that still carries
    // the old field must keep parsing — failing here would lock the owner
    // out of their own wallet — and the field must not survive the parse
    // in either direction.
    for setting in [true, false] {
        let policy = WalletPolicy::parse(json!({
            "chains": { "1": { "tokens": { "*": {} } } },
            "require_simulation": setting
        }))
        .expect("a retired setting is discarded, not rejected");
        let round_trip = serde_json::to_value(&policy).unwrap();
        assert!(round_trip.get("require_simulation").is_none());
    }
}

#[test]
fn a_policy_written_against_the_retired_approval_expiry_still_opens() {
    // Queued requests no longer expire, and no policy setting can give
    // them a deadline again. A stored policy that still carries the old
    // field — top level, per chain, or both — must keep parsing, because
    // failing here would lock the owner out of their own wallet, and the
    // field must not survive the parse in either direction.
    let policy = WalletPolicy::parse(json!({
        "chains": {
            "1": { "tokens": { "*": {} }, "approval_expiry_seconds": 300 },
            "*": { "approval_expiry_seconds": 60 }
        },
        "approval_expiry_seconds": 600
    }))
    .expect("a retired setting is discarded, not rejected");
    let round_trip = serde_json::to_value(&policy).unwrap();
    assert!(round_trip.get("approval_expiry_seconds").is_none());
    for chain in round_trip["chains"].as_object().unwrap().values() {
        assert!(chain.get("approval_expiry_seconds").is_none());
    }
}

#[test]
fn policy_diff_is_minimized_and_permission_level() {
    let current = WalletPolicy::require_approval_for_everything();
    let proposed = WalletPolicy::parse(json!({
        "chains": {
            "*": {
                "max_calls_per_batch": 1,
                "native": { "max_value_per_transaction": "0" }
            },
            "1": {
                "max_calls_per_batch": 4,
                "native": { "max_value_per_transaction": "1000000000000000000" },
                "approval_spenders": {
                    "0x000000000022d473030f116ddee9f6b43ac78ba3": {
                        "tokens": {
                            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {
                                "max_amount": "5000000"
                            }
                        }
                    }
                },
                "tokens": {
                    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {
                        "max_spend_per_transaction": "5000000",
                        "transfer_recipients": {
                            "0x3333333333333333333333333333333333333333": {}
                        }
                    }
                }
            }
        }
    }))
    .unwrap();

    let diff = diff_policies(&current, &proposed);
    assert!(
        diff.iter()
            .any(|line| line.starts_with("+ chain 1:") && line.contains("native value up to"))
    );
    assert!(diff.iter().any(|line| {
        line.contains("approvals to spender 0x000000000022d473030f116ddee9f6b43ac78ba3")
            && line.contains("up to 5000000")
    }));
    assert!(diff.iter().any(|line| line.contains("transfer recipients")
        && line.contains("0x3333333333333333333333333333333333333333")));
    // The unchanged wildcard chain contributes nothing.
    assert!(!diff.iter().any(|line| line.contains("every chain (*)")));

    // Identical documents diff to an explicit no-change line.
    let unchanged = diff_policies(&current, &current);
    assert_eq!(unchanged.len(), 1);
    assert!(unchanged[0].contains("identical"));

    // Removing a grant shows as a removal, and unlimited reads as a word.
    let allow_all = WalletPolicy::allow_all_with_approval();
    let shrink = diff_policies(&allow_all, &current);
    assert!(
        shrink
            .iter()
            .any(|line| line.starts_with("- chain every chain (*)") || line.starts_with("- chain"))
    );
    assert!(shrink.iter().any(|line| line.contains("unlimited")));
}

#[test]
fn a_decimal_quantity_is_bounded_by_length_before_it_is_parsed() {
    // The largest canonical uint256 is 78 digits, so anything longer is
    // refused either way. What changes is the cost: `BigUint::from_str` is
    // superlinear in radix 10, and a policy carries one of these per token,
    // per spender-token, and per chain.
    assert!(validate_decimal(MAX_UINT256).is_ok());
    assert!(validate_decimal("0").is_ok());
    assert!(validate_decimal(&"9".repeat(MAX_UINT256.len() + 1)).is_err());
    // A value of the maximum length that is still above the ceiling is
    // caught by the comparison, as before.
    let over = "9".repeat(MAX_UINT256.len());
    assert!(validate_decimal(&over).is_err());
}

#[test]
fn rejects_removed_stateful_daily_limits() {
    assert!(
        WalletPolicy::parse(json!({
            "chains": { "1": { "native": { "max_value_per_day": "1" } } }
        }))
        .is_err()
    );
    assert!(
        WalletPolicy::parse(json!({
            "chains": { "1": { "tokens": { "*": { "max_spend_per_day": "1" } } } }
        }))
        .is_err()
    );
}
