use super::*;
use crate::RiskBand;

fn call(action: &str, fields: &[&str]) -> CallSummary {
    CallSummary {
        description: Some(action.into()),
        details: fields.iter().map(|s| (*s).into()).collect(),
        ..CallSummary::default()
    }
}
fn summary(calls: Vec<CallSummary>) -> String {
    let predictions = calls
        .iter()
        .map(|_| TransactionPreview {
            class: TransactionClass::Swap,
            risk: RiskBand::Routine,
            summary: String::new(),
        })
        .collect::<Vec<_>>();
    summarize(&PlanDocument { calls }, &predictions)
}
fn swap() -> CallSummary {
    let mut result = call(
        "Uniswap — Swap",
        &[
            "Amount in: 250 USDC",
            "Token out: ETH",
            "Minimum output: 0.1 ETH",
        ],
    );
    result.target = "router".into();
    result
}

#[test]
fn exact_approval_and_swap_fit_the_card() {
    assert_eq!(
        summary(vec![
            call("approve spender router for 250 USDC", &[]),
            swap()
        ]),
        "Approve and swap 250 USDC for ETH"
    );
}
#[test]
fn unlimited_approval_stays_explicit() {
    let mut approval = call("approve spender router for unlimited USDC", &[]);
    approval.warnings.push("Unlimited allowance".into());
    assert_eq!(
        summary(vec![approval, swap()]),
        "Unlimited approve USDC and swap 250 USDC for ETH"
    );
}
#[test]
fn revocation_stays_after_the_swap() {
    assert_eq!(
        summary(vec![
            swap(),
            call("revoke USDC allowance for spender router", &[])
        ]),
        "Swap 250 USDC for ETH, then revoke approval"
    );
}
#[test]
fn minimum_output_is_never_the_swap_amount() {
    assert_eq!(
        summary(vec![call(
            "Uniswap — Swap",
            &["Minimum output: 0.1 ETH", "Token out: ETH"]
        )]),
        "Swap for ETH"
    );
}
#[test]
fn cooldown_does_not_promise_an_immediate_withdrawal() {
    assert_eq!(
        summary(vec![call(
            "Ethena — Cooldown shares",
            &["Amount: 12 sUSDe"]
        )]),
        "Start cooldown 12 sUSDe"
    );
}
#[test]
fn liquidity_minimum_is_not_a_withdrawal_quantity() {
    assert_eq!(
        summary(vec![call(
            "Uniswap — Remove liquidity",
            &[
                "Liquidity: 50",
                "Minimum token 0: 10 USDC",
                "Minimum token 1: 0.01 ETH"
            ]
        )]),
        "Remove liquidity on Uniswap"
    );
}
#[test]
fn conflicting_amount_fields_are_not_arbitrarily_resolved() {
    assert_eq!(
        summary(vec![call(
            "Aave — Supply",
            &["Amount: 250 USDC", "Amount: 500 USDC"]
        )]),
        "Deposit on Aave"
    );
}
#[test]
fn an_unknown_tail_is_not_lost() {
    let mut calls = vec![swap(); 63];
    calls.push(CallSummary::default());
    let text = summary(calls);
    assert!(text.contains("unknown call"), "{text}");
    assert!(text.chars().count() <= MAX_CHARS);
}
#[test]
fn all_fallbacks_obey_the_character_budget() {
    for count in [1, 2, 64, 512] {
        let calls = (0..count)
            .map(|i| call(&format!("{} {i}", "批准".repeat(200)), &[]))
            .collect();
        let text = summary(calls);
        assert!(text.chars().count() <= MAX_CHARS, "{text}");
        assert!(!text.ends_with('…'));
    }
}
#[test]
fn address_annotations_are_removed_without_erasing_caveats() {
    assert_eq!(
        compact("USDC (0x1111111111111111111111111111111111111111)"),
        "USDC"
    );
    assert_eq!(compact("USDC (minimum)"), "USDC (minimum)");
}

#[test]
fn a_larger_allowance_is_not_called_an_exact_approval() {
    assert_eq!(
        summary(vec![
            call("approve spender router for 1000 USDC", &[]),
            swap()
        ]),
        "Approve 1000 USDC and swap 250 USDC for ETH"
    );
}

#[test]
fn a_separate_spender_is_not_hidden_in_approve_and_swap() {
    let text = summary(vec![
        call(
            "approve spender 0x2222222222222222222222222222222222222222 for unlimited USDC",
            &[],
        ),
        swap(),
    ]);
    assert!(
        text.to_lowercase()
            .contains("unlimited approve usdc to 0x222222…222222"),
        "{text}"
    );
    assert!(text.contains("swap 250 USDC for ETH"), "{text}");
}

#[test]
fn a_distinct_swap_recipient_is_preserved() {
    let mut call = swap();
    call.details
        .push("Recipient: 0x2222222222222222222222222222222222222222".into());
    let text = summary(vec![call]);
    assert!(text.contains("to 0x222222…222222"), "{text}");
}

#[test]
fn a_raw_unlimited_approval_stays_explicit_without_a_text_warning() {
    let mut approval = call("approve spender router for 250 USDC", &[]);
    approval.evidence = Some(crate::slots::CallEvidence {
        calldata: format!(
            "0x095ea7b3{}{}{}",
            "0".repeat(24),
            "1".repeat(40),
            "f".repeat(64)
        ),
        ..crate::slots::CallEvidence::default()
    });
    let text = summary(vec![approval, swap()]);
    assert!(text.starts_with("Unlimited approve"), "{text}");
}

#[test]
fn tentative_abi_hints_never_become_verified_actions() {
    let opaque = CallSummary {
        evidence: Some(crate::slots::CallEvidence {
            abi: vec![crate::slots::AbiCandidate {
                signature: "swapExactInput(uint256)".into(),
                contract_match: false,
                arguments: vec![],
            }],
            ..crate::slots::CallEvidence::default()
        }),
        ..CallSummary::default()
    };
    assert_eq!(summary(vec![opaque]), "Unknown call (possible swap)");
}

#[test]
fn overview_keeps_both_unlimited_permissions_and_unknown_calls() {
    let mut calls: Vec<_> = (0..50)
        .map(|i| {
            call(
                &format!("approve spender router{i} for unlimited USDC"),
                &[],
            )
        })
        .collect();
    calls.push(CallSummary::default());
    let text = summary(calls);
    assert!(text.contains("unlimited approvals"), "{text}");
    assert!(text.contains("unknown calls"), "{text}");
    assert!(text.chars().count() <= MAX_CHARS);
}

#[test]
fn same_router_on_another_chain_does_not_bind_approval() {
    let mut approval = call("approve spender router for 250 USDC", &[]);
    approval.evidence = Some(crate::slots::CallEvidence {
        chain_id: "1".into(),
        ..Default::default()
    });
    let mut action = swap();
    action.evidence = Some(crate::slots::CallEvidence {
        chain_id: "10".into(),
        to: "router".into(),
        ..Default::default()
    });
    assert_eq!(
        summary(vec![approval, action]),
        "Approve 250 USDC to router and swap 250 USDC for ETH"
    );
}

#[test]
fn same_symbol_different_asset_does_not_omit_approval_amount() {
    let mut approval = call("approve spender router for 250 USDC", &[]);
    approval.target = "0x1111111111111111111111111111111111111111".into();
    let mut action = swap();
    action
        .details
        .push("Token in: USDC (0x2222222222222222222222222222222222222222)".into());
    assert_eq!(
        summary(vec![approval, action]),
        "Approve 250 USDC and swap 250 USDC for ETH"
    );
}
