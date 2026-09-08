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
    let preview = engine().preview(&opaque);
    assert_eq!(preview.class, TransactionClass::Unrecognized);
    assert_eq!(preview.risk, RiskBand::Critical);
    assert!(preview.summary.is_empty());
}

/// Untrained weights answer nonsense, which is the point: whatever they
/// answer must be *inside the enums*, never an index the UI cannot render.
#[test]
fn an_answer_is_always_a_member_of_the_closed_enums() {
    let preview = engine().preview(&plan(&format!(
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
    let previews = engine().preview_all(&documents);
    assert_eq!(previews.len(), 3);
    // The middle plan decoded to nothing, so it keeps the honest answer even
    // though its neighbours went through the model.
    assert_eq!(previews[1].class, TransactionClass::Unrecognized);
    assert!(previews[1].summary.is_empty());
}

#[test]
fn an_empty_batch_is_not_a_forward_pass() {
    assert!(engine().preview_all(&[]).is_empty());
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
    let first = engine.preview(&document);
    let second = engine.preview(&document);
    assert_eq!(first.summary, second.summary);
    assert_eq!(first.class, second.class);
}
