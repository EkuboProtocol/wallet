use super::*;
use crate::slots::CallSummary;

type TestBackend = burn::backend::NdArray;

const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const SPENDER: &str = "0x1111111254EEB25477B68fb85Ed929f73A960582";

fn engine() -> PreviewEngine<TestBackend> {
    let device = burn::backend::ndarray::NdArrayDevice::default();
    PreviewEngine::new(PreviewModel::new(&device), device)
}

fn plan(description: &str) -> PlanDocument {
    PlanDocument {
        calls: vec![CallSummary {
            description: Some(description.to_owned()),
            ..CallSummary::default()
        }],
    }
}

/// A plan nothing decoded never reaches the model. There is no signal in it to
/// classify, and a confident category over calldata nobody read is the failure
/// this surface exists to avoid.
#[test]
fn an_opaque_plan_is_unrecognized_without_a_forward_pass() {
    let opaque = PlanDocument {
        calls: vec![CallSummary {
            target: SPENDER.to_owned(),
            ..CallSummary::default()
        }],
    };
    let preview = engine().legacy_preview(&opaque);
    assert_eq!(preview.class, TransactionClass::Unrecognized);
    assert_eq!(preview.risk, RiskBand::Critical);
    assert!(preview.summary.is_empty());
}

/// Untrained weights answer nonsense, which is the point: whatever they
/// answer must be *inside the enums*, never an index the UI cannot render.
#[test]
fn an_answer_is_always_a_member_of_the_closed_enums() {
    let preview = engine().legacy_preview(&plan(&format!(
        "approve spender {SPENDER} for 5.5 USDC ({USDC})"
    )));
    assert!(crate::taxonomy::CLASSES.contains(&preview.class));
    assert!(crate::taxonomy::RISKS.contains(&preview.risk));
}

#[test]
fn a_batch_answers_one_preview_per_plan_in_order() {
    let documents = vec![
        plan("swap tokens"),
        PlanDocument {
            calls: vec![CallSummary::default()],
        },
        plan(&format!("transfer 1.5 USDC ({USDC}) to {SPENDER}")),
    ];
    let previews = engine().legacy_preview_all(&documents);
    assert_eq!(previews.len(), 3);
    // The middle plan decoded to nothing, so it keeps the honest answer even
    // though its neighbours went through the model.
    assert_eq!(previews[1].class, TransactionClass::Unrecognized);
    assert!(previews[1].summary.is_empty());
}

#[test]
fn an_empty_batch_is_not_a_forward_pass() {
    assert!(engine().legacy_preview_all(&[]).is_empty());
}

/// The last line of defense. Slotization already makes this unreachable, but
/// the check is what stands between a future refactor and a reviewer reading a
/// value the plan does not contain.
#[test]
fn a_summary_naming_a_value_the_plan_lacks_is_refused() {
    let slotized = crate::slots::slotize(&plan(&format!("transfer 1.5 USDC ({USDC})")));
    assert!(values_are_all_from("transfer 1.5 USDC", &slotized));
    assert!(
        !values_are_all_from("transfer 9999.75 USDC", &slotized),
        "an amount nothing lifted must be refused"
    );
    assert!(
        !values_are_all_from(&format!("send to {SPENDER}"), &slotized),
        "an address nothing lifted must be refused"
    );
}

#[test]
fn a_summary_of_words_alone_is_always_accepted() {
    let slotized = crate::slots::slotize(&plan("wrap ether"));
    assert!(values_are_all_from("wrap ether then stake", &slotized));
    assert!(values_are_all_from("", &slotized));
}

/// Decoding is greedy, not sampled: a reviewer who refreshes a request must
/// see the same sentence, or they cannot tell a reworded summary from a
/// changed plan.
#[test]
fn the_same_plan_produces_the_same_summary_every_time() {
    let engine = engine();
    let document = plan(&format!("swap 2.5 USDC ({USDC}) for 1.0 WETH ({SPENDER})"));
    let first = engine.legacy_preview(&document);
    let second = engine.legacy_preview(&document);
    assert_eq!(first.summary, second.summary);
    assert_eq!(first.class, second.class);
}

/// Reading indices back must produce one per row, never an empty vector.
///
/// This test cannot fail on the backend it runs on. `NdArray`'s integer
/// element is already `i64`, so a raw `to_vec::<i64>()` would pass here too --
/// which is exactly why the bug this guards reached a GPU before anything
/// noticed. What the test is for is the count: every caller of `indices`
/// treats a missing entry as a default, so a silent shortfall is indistinguishable
/// from a confident wrong answer, and this at least pins the contract that
/// there is one index per row.
#[test]
fn reading_indices_back_yields_one_per_row() {
    let device = burn::backend::ndarray::NdArrayDevice::default();
    let scores = Tensor::<TestBackend, 2>::from_data(
        burn::tensor::TensorData::new(vec![0.1_f32, 0.9, 0.2, 0.7, 0.1, 0.1], [2, 3]),
        &device,
    );
    let read = indices(scores.argmax(1));
    assert_eq!(read.len(), 2, "one index per row, never an empty vector");
    assert_eq!(read, [1, 0]);
}

/// The value check must not refuse a summary over the punctuation the
/// renderer attached.
///
/// It did. Stripping only `,` and `.` meant a trailing colon stayed on the
/// word, so "0xabc…:" was compared against a slot text that has no colon and
/// never matched. Every summary naming a protocol reads "Aave DAO: …", so the
/// effect was that protocol-led summaries were silently refused and rendered
/// as nothing -- which looked like the model failing to produce one.
#[test]
fn punctuation_does_not_make_a_real_value_look_invented() {
    let slotized =
        crate::slots::slotize(&plan(&format!("transfer 1.5 USDC ({USDC}) to {SPENDER}")));
    for rendered in [
        format!("send 1.5 USDC to {SPENDER}"),
        format!("send to {SPENDER}, then wait"),
        format!("{SPENDER}: send 1.5 USDC"),
        format!("send to {SPENDER}."),
        format!("send to ({SPENDER})"),
    ] {
        assert!(
            values_are_all_from(&rendered, &slotized),
            "refused a summary whose values are all in the plan: {rendered}"
        );
    }
}

/// And it must still refuse a value the plan does not contain, punctuation or
/// not.
#[test]
fn punctuation_does_not_let_an_invented_value_through() {
    let slotized = crate::slots::slotize(&plan(&format!("transfer 1.5 USDC ({USDC})")));
    for rendered in [
        "send 9999.75 USDC".to_owned(),
        format!("send to {SPENDER}:"),
        format!("{SPENDER}: send"),
    ] {
        assert!(
            !values_are_all_from(&rendered, &slotized),
            "accepted a value nothing lifted: {rendered}"
        );
    }
}

/// A plan nobody decoded keeps the class we know, even when it is worth
/// writing a sentence about.
///
/// Letting the value through the model so it can name the amount is right;
/// letting the model also pick the *class* is not. "Nothing decoded this" is a
/// fact, and an unreadable call moving ether previewing as "Claim" is the
/// confident noise this surface exists to avoid.
#[test]
fn an_undecoded_call_that_sends_value_is_still_unrecognized() {
    let sending = PlanDocument {
        calls: vec![CallSummary {
            target: SPENDER.to_owned(),
            native_value: "2.5 ETH".to_owned(),
            ..CallSummary::default()
        }],
    };
    assert!(sending.nothing_decoded());
    assert!(!sending.is_opaque());
    let preview = engine().legacy_preview(&sending);
    assert_eq!(preview.class, TransactionClass::Unrecognized);
    assert_eq!(preview.risk, RiskBand::Critical);
}

#[test]
fn a_suffix_or_prefix_of_a_value_is_not_the_value() {
    let slots = slotize(&plan(&format!("transfer 1000.5 USDC ({USDC})")));
    for summary in [
        "transfer 100 USDC",
        "transfer 0.5 USDC",
        "send to 0xA0b86991",
    ] {
        assert!(!values_are_all_from(summary, &slots), "accepted {summary}");
    }
}

#[test]
fn an_overlong_single_call_is_not_summarized_from_its_prefix() {
    let mut document = plan(&"swap ".repeat(600));
    document.calls[0].warnings.push("unlimited approval".into());
    let preview = engine().legacy_preview(&document);
    assert_eq!(preview.class, TransactionClass::Unrecognized);
    assert_eq!(preview.risk, RiskBand::Critical);
    assert!(preview.summary.contains("exceeds preview limits"));
}

#[test]
fn a_late_opaque_call_survives_long_plan_preparation() {
    let mut document = PlanDocument {
        calls: vec![plan("swap tokens").calls.remove(0); 200],
    };
    document.calls.push(CallSummary {
        target: SPENDER.into(),
        native_value: "2.5 ETH".into(),
        ..CallSummary::default()
    });
    let mut prepared = Prepared::default();
    prepared.push(&document);
    assert_eq!(prepared.previews.len(), 201);
    assert_eq!(prepared.pending.len(), 200);
    let mut parts = vec![
        TransactionPreview {
            class: TransactionClass::Swap,
            risk: RiskBand::Routine,
            summary: "swap tokens".into()
        };
        200
    ];
    parts.push(prepared.previews[200].clone());
    let preview = aggregate(&parts);
    assert_eq!(preview.risk, RiskBand::Critical);
    assert!(preview.summary.contains("201 calls; call 201:"));
    assert!(preview.summary.contains("2.5 ETH"));
}

#[test]
fn a_decoded_warning_cannot_be_downgraded_by_the_model() {
    let mut document = plan("swap tokens");
    document.calls[0]
        .warnings
        .push("unlimited spending allowance".into());
    assert_eq!(engine().legacy_preview(&document).risk, RiskBand::Critical);
}

#[test]
fn generation_cannot_substitute_an_unsupported_action_or_asset_word() {
    let slots = slotize(&plan("CoreDAO Earn Contract — withdraw core"));
    assert!(grounded_word(vocab::token_of("withdraw"), &slots));
    assert!(grounded_word(vocab::token_of("core"), &slots));
    for word in ["celo", "stake", "dca"] {
        assert_ne!(
            vocab::token_of(word),
            vocab::UNK,
            "fixture must exercise a real output word"
        );
        assert!(
            !grounded_word(vocab::token_of(word), &slots),
            "allowed unsupported {word}"
        );
    }
}

#[test]
fn action_phrases_are_preserved_even_with_untrained_weights() {
    let description = "Ethena — Cooldown shares";
    let preview = engine().legacy_preview(&plan(description));
    assert!(
        preview.summary.contains("Ethena: Cooldown shares"),
        "{}",
        preview.summary
    );
}

#[test]
fn a_transfer_from_never_names_the_sender_as_the_destination() {
    let description = format!("transferFrom {SPENDER} to {USDC} for 5 ETH");
    let preview = engine().legacy_preview(&plan(&description));
    assert_eq!(preview.class, TransactionClass::Transfer);
    assert_eq!(preview.risk, RiskBand::Caution);
    assert_eq!(preview.summary, description);
}

#[test]
fn omitted_or_reordered_actions_trigger_the_extractive_fallback() {
    let slots = slotize(&PlanDocument {
        calls: vec![
            plan("Ethena — Cooldown shares").calls.remove(0),
            plan("CoreDAO — Withdraw CORE").calls.remove(0),
        ],
    });
    let reading: Vec<_> = slots
        .slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| {
            matches!(
                slot.kind,
                crate::slots::SlotKind::Action | crate::slots::SlotKind::Protocol
            )
        })
        .map(|(i, _)| vocab::slot_token(i).unwrap())
        .collect();
    assert!(preserves_actions(&reading, &slots));
    assert!(!preserves_actions(&reading[..2], &slots));
    assert!(!preserves_actions(
        &reading.into_iter().rev().collect::<Vec<_>>(),
        &slots
    ));
    assert_eq!(
        action_fallback(&slots),
        "Ethena: Cooldown shares; then CoreDAO: Withdraw CORE"
    );
}

#[test]
fn long_inputs_reduce_the_dispatch_size() {
    assert_eq!(batch_size_for(32), 8);
    assert_eq!(batch_size_for(128), 8);
    assert_eq!(batch_size_for(256), 2);
    assert_eq!(batch_size_for(512), 1);
}

#[test]
fn selected_values_keep_their_field_roles_and_ignore_contract_targets() {
    let slots = slotize(&PlanDocument {
        calls: vec![crate::CallSummary {
            evidence: None,
            description: Some("Uniswap — Remove liquidity".into()),
            details: vec!["Liquidity: 50".into(), "Minimum output: 0.01 ETH".into()],
            target: "0x1111111111111111111111111111111111111111".into(),
            native_value: "0 ETH".into(),
            warnings: vec![],
        }],
    });
    let selected: Vec<_> = slots
        .slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.text == "0.01 ETH" || slot.kind == crate::slots::SlotKind::Address)
        .map(|(index, _)| vocab::slot_token(index).unwrap())
        .collect();
    assert_eq!(
        render_summary(&slots, &selected),
        "Uniswap: Remove liquidity — Minimum output: 0.01 ETH"
    );
}

#[test]
fn equal_values_in_different_fields_do_not_lose_their_roles() {
    let slots = slotize(&PlanDocument {
        calls: vec![crate::CallSummary {
            evidence: None,
            description: Some("Protocol — Swap".into()),
            details: vec![
                "Maximum input: 10 ETH".into(),
                "Minimum output: 10 ETH".into(),
            ],
            target: "contract".into(),
            native_value: "0 ETH".into(),
            warnings: vec![],
        }],
    });
    let second = slots
        .slots
        .iter()
        .position(|slot| slot.field == Some(1))
        .unwrap();
    assert_eq!(
        render_summary(&slots, &[vocab::slot_token(second).unwrap()]),
        "Protocol: Swap — Minimum output: 10 ETH"
    );
}

#[test]
fn a_selected_native_value_is_labeled_as_native_value() {
    let slots = slotize(&PlanDocument {
        calls: vec![crate::CallSummary {
            evidence: None,
            description: Some("Lido — Stake ETH".into()),
            details: vec![],
            target: "contract".into(),
            native_value: "0.5 ETH".into(),
            warnings: vec![],
        }],
    });
    let amount = slots
        .slots
        .iter()
        .position(|slot| slot.text == "0.5 ETH")
        .unwrap();
    assert_eq!(
        render_summary(&slots, &[vocab::slot_token(amount).unwrap()]),
        "Lido: Stake ETH — Native value: 0.5 ETH"
    );
}

#[test]
fn explicit_operator_grants_and_revocations_do_not_need_a_prediction() {
    for (description, class, risk) in [
        (
            "setApprovalForAll: grant operator 0x1234 control of all NFT tokens",
            TransactionClass::Approval,
            RiskBand::Critical,
        ),
        (
            "setApprovalForAll: revoke operator 0x1234 for NFT",
            TransactionClass::Revocation,
            RiskBand::Routine,
        ),
        (
            "setApprovalForAll operator 0x1234 approved false",
            TransactionClass::Revocation,
            RiskBand::Routine,
        ),
    ] {
        let mut prepared = Prepared::default();
        prepared.push(&PlanDocument {
            calls: vec![crate::CallSummary {
                description: Some(description.into()),
                ..Default::default()
            }],
        });
        assert!(prepared.pending.is_empty());
        assert_eq!(prepared.previews[0].class, class);
        assert_eq!(prepared.previews[0].risk, risk);
        assert_eq!(prepared.previews[0].summary, description);
    }
}

#[test]
fn card_results_do_not_depend_on_other_queued_requests() {
    let engine = crate::cpu::load().unwrap();
    let mut long = plan("Ethena — Cooldown shares");
    long.calls[0].details.push("additional ".repeat(440));
    let ordinary = plan("Aave — Supply");
    let expected = engine.preview_all(&[long.clone(), ordinary.clone()]);
    let mut queue = vec![long; 8];
    queue.push(ordinary);
    let actual = engine.preview_all(&queue);
    assert_eq!(actual[0], expected[0]);
    assert_eq!(actual[8], expected[1]);
}

#[test]
fn card_operator_risk_does_not_depend_on_model_output_or_optional_warnings() {
    let engine = engine();
    let grant = engine.preview(&plan(
        "setApprovalForAll operator 0x2222222222222222222222222222222222222222 approved true",
    ));
    assert_eq!(grant.risk, RiskBand::Critical);
    let revoke = engine.preview(&plan(
        "setApprovalForAll operator 0x2222222222222222222222222222222222222222 approved false",
    ));
    assert_eq!(revoke.risk, RiskBand::Routine);
}
