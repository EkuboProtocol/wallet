use super::*;

const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const SPENDER: &str = "0x1111111254EEB25477B68fb85Ed929f73A960582";

/// A call whose target lifts no slot of its own, so a test naming slot
/// indices is reading only what its description put there.
fn call(description: &str) -> CallSummary {
    CallSummary {
        description: Some(description.to_owned()),
        native_value: "0".to_owned(),
        ..CallSummary::default()
    }
}

fn plan(description: &str) -> PlanDocument {
    PlanDocument {
        calls: vec![call(description)],
    }
}

fn kinds(slotized: &Slotized) -> Vec<SlotKind> {
    slotized.slots.iter().map(|slot| slot.kind).collect()
}

fn texts(slotized: &Slotized) -> Vec<&str> {
    slotized
        .slots
        .iter()
        .map(|slot| slot.text.as_str())
        .collect()
}

#[test]
fn an_amount_with_a_bound_symbol_lifts_whole() {
    let slotized = slotize(&plan(&format!(
        "approve spender {SPENDER} for 1000.5 USDC ({USDC})"
    )));
    assert_eq!(kinds(&slotized), [SlotKind::Address, SlotKind::Amount]);
    assert_eq!(texts(&slotized)[1], format!("1000.5 USDC ({USDC})"));
}

#[test]
fn a_bare_uppercase_ticker_is_a_unit_but_an_ordinary_word_is_not() {
    let slotized = slotize(&plan("wrap 2.5 ETH and 1 more call"));
    let lifted = texts(&slotized);
    assert!(lifted.contains(&"2.5 ETH"), "{lifted:?}");
    assert!(
        !lifted.iter().any(|text| text.contains("more")),
        "a count must not swallow the word after it: {lifted:?}"
    );
}

#[test]
fn an_own_account_annotation_stays_bound_to_its_address() {
    let slotized = slotize(&plan(&format!(
        "transfer to {SPENDER} (your account savings)"
    )));
    assert_eq!(
        texts(&slotized)[0],
        format!("{SPENDER} (your account savings)"),
        "splitting these would let a summary name the address without the fact that it is the owner's"
    );
}

#[test]
fn a_hex_blob_that_is_not_twenty_bytes_is_data_not_an_address() {
    let slotized = slotize(&plan("permit 0xdeadbeef then 0x00"));
    assert_eq!(kinds(&slotized), [SlotKind::Data, SlotKind::Data]);
}

#[test]
fn a_bare_integer_is_a_number_and_a_fraction_is_an_amount() {
    let slotized = slotize(&plan("tick 887272 ratio 0.3"));
    assert_eq!(kinds(&slotized), [SlotKind::Number, SlotKind::Amount]);
}

#[test]
fn base_unit_rendering_lifts_as_one_amount() {
    let slotized = slotize(&plan(&format!("transfer 12345 base units of {USDC}")));
    assert_eq!(kinds(&slotized), [SlotKind::Amount]);
    assert_eq!(texts(&slotized)[0], format!("12345 base units of {USDC}"));
}

/// The property the whole design rests on: no digit of a value ever reaches
/// the model, so no forward pass can alter one.
#[test]
fn no_input_token_carries_a_digit_from_a_lifted_value() {
    let slotized = slotize(&plan(&format!(
        "swap 1000.5 USDC ({USDC}) for 0.318 WETH ({SPENDER}) before 1893456000"
    )));
    for token in &slotized.tokens {
        let piece = vocab::text_of(*token).unwrap_or("");
        assert!(
            !piece.contains("1000") && !piece.contains("318") && !piece.contains("1893456000"),
            "the value {piece:?} reached the model's input"
        );
    }
}

#[test]
fn rendering_substitutes_slot_references_verbatim() {
    let slotized = slotize(&plan(&format!(
        "approve spender {SPENDER} for 1000.5 USDC ({USDC})"
    )));
    let summary = [
        vocab::token_of("approve"),
        vocab::slot_token(1).unwrap(),
        vocab::token_of("for"),
        vocab::slot_token(0).unwrap(),
    ];
    assert_eq!(
        slotized.render(&summary),
        format!("approve 1000.5 USDC ({USDC}) for {SPENDER}")
    );
}

/// A reference the plan has no slot for is dropped. Printing it would put
/// `<s7>` in front of a human, which reads as a value.
#[test]
fn a_reference_past_the_slot_table_is_dropped_not_printed() {
    let slotized = slotize(&plan("wrap"));
    let summary = [
        vocab::token_of("wrap"),
        vocab::slot_token(40).unwrap(),
        vocab::token_of("now"),
    ];
    let rendered = slotized.render(&summary);
    assert_eq!(rendered, "wrap now");
    assert!(!rendered.contains('<'));
}

#[test]
fn punctuation_joins_the_word_before_it() {
    let slotized = slotize(&plan("wrap"));
    let summary = [
        vocab::token_of("wrap"),
        vocab::token_of("ether"),
        vocab::token_of(","),
        vocab::token_of("then"),
        vocab::token_of("stake"),
        vocab::token_of("."),
    ];
    assert_eq!(slotized.render(&summary), "wrap ether, then stake.");
}

/// Past the cap a value is still announced by kind, so the model knows one was
/// there, but it gets no reference -- and a value it cannot name is a value it
/// cannot misrender.
#[test]
fn values_past_the_cap_lose_their_reference_not_their_kind() {
    let details: Vec<String> = (0..MAX_SLOTS + 10)
        .map(|index| format!("n {index}"))
        .collect();
    let document = PlanDocument {
        calls: vec![CallSummary {
            description: Some("batch".to_owned()),
            details,
            ..CallSummary::default()
        }],
    };
    let slotized = slotize(&document);
    assert_eq!(slotized.slots.len(), MAX_SLOTS);
    assert!(
        slotized
            .tokens
            .iter()
            .filter_map(|t| vocab::slot_index(*t))
            .all(|i| i < MAX_SLOTS)
    );
}

#[test]
fn a_long_plan_is_truncated_rather_than_growing_without_bound() {
    let calls = (0..400).map(|_| call("swap tokens for tokens")).collect();
    let slotized = slotize(&PlanDocument { calls });
    assert!(slotized.tokens.len() <= MAX_INPUT_TOKENS);
}

#[test]
fn a_plan_that_decoded_to_nothing_is_opaque() {
    let opaque = PlanDocument {
        calls: vec![CallSummary {
            target: SPENDER.to_owned(),
            ..CallSummary::default()
        }],
    };
    assert!(opaque.is_opaque());
    assert!(!plan("swap").is_opaque());
}

#[test]
fn a_zero_native_value_is_left_out_of_the_input() {
    for zero in ["0", "0 ETH", "0.0 ETH", " "] {
        let document = PlanDocument {
            calls: vec![CallSummary {
                description: Some("call".to_owned()),
                native_value: zero.to_owned(),
                ..CallSummary::default()
            }],
        };
        let slotized = slotize(&document);
        assert!(
            !slotized.tokens.contains(&vocab::token_of("<value>")),
            "{zero:?} should not be announced as a value"
        );
    }
    let document = PlanDocument {
        calls: vec![CallSummary {
            description: Some("call".to_owned()),
            native_value: "1.5 ETH".to_owned(),
            ..CallSummary::default()
        }],
    };
    assert!(
        slotize(&document)
            .tokens
            .contains(&vocab::token_of("<value>"))
    );
}

/// A call's target is lifted like any other value, so a summary can name the
/// contract it is talking to.
#[test]
fn the_target_is_lifted_too() {
    let document = PlanDocument {
        calls: vec![CallSummary {
            description: Some("swap".to_owned()),
            target: format!("USDC ({USDC})"),
            ..CallSummary::default()
        }],
    };
    let slotized = slotize(&document);
    assert_eq!(kinds(&slotized), [SlotKind::Token]);
    assert_eq!(texts(&slotized)[0], format!("USDC ({USDC})"));
}
