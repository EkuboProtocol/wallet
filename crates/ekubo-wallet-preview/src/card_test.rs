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
            basis: crate::SummaryBasis::Interpretation,
            class: TransactionClass::Swap,
            risk: RiskBand::Routine,
            summary: String::new(),
        })
        .collect::<Vec<_>>();
    summarize(
        &PlanDocument {
            simulation: None,
            calls,
        },
        &predictions,
    )
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

fn simulated_plan() -> PlanDocument {
    PlanDocument {
        calls: vec![CallSummary {
            native_value: "1 ETH".into(),
            ..CallSummary::default()
        }],
        simulation: Some(crate::slots::SimulatedFlows {
            sent: vec!["1 ETH".into()],
            received: vec!["2400 USDG".into()],
            from_logs: false,
        }),
    }
}

#[test]
fn opaque_calls_describe_simulated_receipts_without_claiming_a_swap() {
    let mut plan = simulated_plan();
    assert_eq!(summarize(&plan, &[]), "Send 1 ETH and receive 2400 USDG");
    plan.simulation.as_mut().unwrap().from_logs = true;
    assert_eq!(summarize(&plan, &[]), "Send 1 ETH and receive 2400 USDG");
    plan.simulation = None;
    assert_eq!(summarize(&plan, &[]), "Unknown call sending 1 ETH");
}

#[test]
fn simulation_does_not_override_decoded_intent_or_hide_permissions() {
    let mut plan = simulated_plan();
    plan.calls[0].description = Some("deposit".into());
    assert_eq!(compose(&plan, &[]).basis, SummaryBasis::Interpretation);
    plan.calls[0].description = None;
    let mut approval = call("approve spender router for 250 USDC", &[]);
    approval.warnings.push("Unlimited approval".into());
    plan.calls.insert(0, approval);
    let text = summarize(&plan, &[]);
    assert!(text.starts_with("Unlimited approve"), "{text}");
    assert!(text.contains("receive 2400 USDG"), "{text}");
    plan.calls.push(CallSummary::default());
    assert!(
        compose(&plan, &[]).basis == SummaryBasis::Interpretation,
        "global effects cannot be assigned to either unknown call"
    );
}

#[test]
fn long_simulated_outcomes_respect_the_card_limit_without_cutting_amounts() {
    let mut plan = simulated_plan();
    plan.simulation.as_mut().unwrap().received =
        vec!["123456789012345678901234567890 VERY_LONG_TOKEN_SYMBOL".into(); 8];
    let text = summarize(&plan, &[]);
    assert!(text.chars().count() <= MAX_CHARS);
    assert_eq!(text, "Unknown call sending 1 ETH");
}

#[test]
fn inferred_intent_requires_candidate_agreement_and_compatible_effects() {
    let mut plan = simulated_plan();
    let candidate = |signature: &str| crate::slots::AbiCandidate {
        signature: signature.into(),
        contract_match: false,
        arguments: vec![],
    };
    plan.calls[0].evidence = Some(crate::slots::CallEvidence {
        abi: vec![candidate("swapExactInput(uint256)")],
        ..Default::default()
    });
    let result = compose(&plan, &[]);
    assert_eq!(result.text, "Swap 1 ETH for 2400 USDG");
    assert_eq!(result.basis, SummaryBasis::InferredIntent);
    assert_eq!(result.inferred_class, Some(TransactionClass::Swap));
    plan.calls[0]
        .evidence
        .as_mut()
        .unwrap()
        .abi
        .push(candidate("deposit(uint256)"));
    assert_eq!(compose(&plan, &[]).inferred_class, None);
    assert_eq!(summarize(&plan, &[]), "Send 1 ETH and receive 2400 USDG");
    plan.calls[0].evidence.as_mut().unwrap().abi = vec![candidate("deposit(uint256)")];
    assert_eq!(summarize(&plan, &[]), "Deposit 1 ETH");
    plan.calls[0].evidence.as_mut().unwrap().abi = vec![candidate("repay(uint256)")];
    assert_eq!(
        compose(&plan, &[]).inferred_class,
        None,
        "repayment cannot explain an unrelated receipt"
    );
    plan.simulation.as_mut().unwrap().received.clear();
    assert_eq!(summarize(&plan, &[]), "Repay 1 ETH");
    plan.calls[0].evidence.as_mut().unwrap().abi = vec![candidate("swapExactInput(uint256)")];
    assert_eq!(
        compose(&plan, &[]).inferred_class,
        None,
        "a swap needs an observed receipt"
    );
}

#[test]
fn compound_function_names_do_not_hide_their_final_action() {
    assert_eq!(candidate_action("swapAndDeposit(uint256)"), None);
    assert_eq!(candidate_action("depositAndStake(uint256)"), None);
    assert_eq!(
        candidate_action("unwrapWETH9(uint256,address)"),
        Some("unwrap")
    );
}
