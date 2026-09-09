use super::*;
use crate::slots::{self, CallSummary, PlanDocument};
use burn::tensor::TensorData;

type TestBackend = burn::backend::NdArray;

type TestDevice = burn::backend::ndarray::NdArrayDevice;

fn device() -> TestDevice {
    TestDevice::default()
}

/// A batch of one plan, padded to `length`.
/// One padded batch: ids, the padding mask, the copyable mask, and the
/// slotization the ids came from.
struct Batch {
    ids: Tensor<TestBackend, 2, Int>,
    pad: Tensor<TestBackend, 2, Bool>,
    copyable: Tensor<TestBackend, 2, Bool>,
    slotized: slots::Slotized,
}

fn batch(length: usize) -> Batch {
    let document = PlanDocument {
        calls: vec![CallSummary {
            description: Some(
                "approve spender 0x1111111254EEB25477B68fb85Ed929f73A960582 for 5.5 USDC (0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)"
                    .to_owned(),
            ),
            ..CallSummary::default()
        }],
    };
    let slotized = slots::slotize(&document);
    let device = device();
    let mut ids: Vec<i32> = slotized
        .tokens
        .iter()
        .map(|token| i32::try_from(*token).unwrap_or_default())
        .collect();
    let mut pad = vec![false; ids.len()];
    let mut copyable: Vec<bool> = slotized
        .tokens
        .iter()
        .map(|token| crate::vocab::slot_index(*token).is_some())
        .collect();
    ids.resize(length, i32::try_from(crate::vocab::PAD).unwrap_or_default());
    pad.resize(length, true);
    copyable.resize(length, false);
    Batch {
        ids: Tensor::from_data(TensorData::new(ids, [1, length]), &device),
        pad: Tensor::from_data(TensorData::new(pad, [1, length]), &device),
        copyable: Tensor::from_data(TensorData::new(copyable, [1, length]), &device),
        slotized,
    }
}

#[test]
fn a_forward_pass_answers_one_score_per_class_and_per_risk_band() {
    let device = device();
    let model = PreviewModel::<TestBackend>::new(&device);
    let Batch { ids, pad, .. } = batch(64);
    let memory = model.encode(ids, &pad);
    assert_eq!(memory.dims(), [1, 64, D_MODEL]);
    let prediction = model.classify(memory, &pad);
    assert_eq!(prediction.class.dims(), [1, CLASS_COUNT]);
    assert_eq!(prediction.risk.dims(), [1, RISK_COUNT]);
}

#[test]
fn the_decoder_scores_every_word_and_every_input_position() {
    let device = device();
    let model = PreviewModel::<TestBackend>::new(&device);
    let Batch {
        ids, pad, copyable, ..
    } = batch(64);
    let memory = model.encode(ids, &pad);
    let prefix = Tensor::<TestBackend, 2, Int>::from_data(
        TensorData::new(
            vec![i32::try_from(crate::vocab::BOS).unwrap_or_default(), 5, 6],
            [1, 3],
        ),
        &device,
    );
    let logits = model.decode(memory, &pad, &copyable, prefix);
    assert_eq!(logits.dims(), [1, 3, crate::vocab::size() + 64]);
}

/// The property the copy head exists to guarantee: a position that holds no
/// slot reference cannot be pointed at, so a copy can only ever land on a
/// value the deterministic interpretation lifted.
#[test]
fn a_position_holding_no_slot_reference_can_never_be_copied() {
    let device = device();
    let model = PreviewModel::<TestBackend>::new(&device);
    let length = 64;
    let Batch {
        ids,
        pad,
        copyable,
        slotized,
    } = batch(length);
    let memory = model.encode(ids, &pad);
    let prefix = Tensor::<TestBackend, 2, Int>::from_data(
        TensorData::new(
            vec![i32::try_from(crate::vocab::BOS).unwrap_or_default()],
            [1, 1],
        ),
        &device,
    );
    let logits = model.decode(memory, &pad, &copyable, prefix);
    let scores: Vec<f32> = logits
        .slice([
            0..1,
            0..1,
            crate::vocab::size()..crate::vocab::size() + length,
        ])
        .into_data()
        .to_vec()
        .expect("copy scores read back");

    let holds_slot: Vec<bool> = (0..length)
        .map(|position| {
            slotized
                .tokens
                .get(position)
                .and_then(|token| crate::vocab::slot_index(*token))
                .is_some()
        })
        .collect();
    assert!(
        holds_slot.iter().any(|held| *held),
        "the fixture lifted values"
    );
    for (position, score) in scores.iter().enumerate() {
        if holds_slot[position] {
            assert!(
                score.is_finite(),
                "position {position} holds a value and must be reachable"
            );
        } else {
            assert!(
                score.is_infinite() && score.is_sign_negative(),
                "position {position} holds no value yet scored {score}"
            );
        }
    }
}

/// A decoder step must not be able to read the summary it has not written
/// yet, or training would teach it to rely on tokens inference cannot supply.
#[test]
fn a_decoder_position_cannot_read_its_own_future() {
    let device = device();
    let mask = causal_mask::<TestBackend>(1, 4, &device);
    let values: Vec<bool> = mask.into_data().to_vec().expect("mask read back");
    for query in 0..4 {
        for key in 0..4 {
            assert_eq!(
                values[query * 4 + key],
                key > query,
                "query {query} key {key} masked wrongly"
            );
        }
    }
}

/// The heads are sized from the enums, so widening a taxonomy without
/// retraining is a shape mismatch rather than a silent misreading.
#[test]
fn the_heads_are_sized_from_the_closed_enums() {
    let device = device();
    let model = PreviewModel::<TestBackend>::new(&device);
    assert_eq!(model.class_head.weight.dims()[1], CLASS_COUNT);
    assert_eq!(model.risk_head.weight.dims()[1], RISK_COUNT);
    assert_eq!(model.word_head.weight.dims()[1], crate::vocab::size());
}

#[test]
fn encoder_output_does_not_depend_on_padding_width() {
    let model = PreviewModel::<TestBackend>::new(&device());
    let short = batch(32);
    let long = batch(128);
    let real = short.slotized.tokens.len();
    let a: Vec<f32> = model
        .encode(short.ids, &short.pad)
        .slice([0..1, 0..real, 0..D_MODEL])
        .into_data()
        .to_vec()
        .unwrap();
    let b: Vec<f32> = model
        .encode(long.ids, &long.pad)
        .slice([0..1, 0..real, 0..D_MODEL])
        .into_data()
        .to_vec()
        .unwrap();
    let difference = a
        .iter()
        .zip(b)
        .map(|(a, b)| (a - b).abs())
        .fold(0.0_f32, f32::max);
    assert!(
        difference < 1e-4,
        "padding changed encoded real tokens by {difference}"
    );
}

#[test]
fn word_head_cannot_emit_slots_or_input_only_markers() {
    let model = PreviewModel::<TestBackend>::new(&device());
    let batch = batch(32);
    let memory = model.encode(batch.ids, &batch.pad);
    let prefix = Tensor::from_data(
        TensorData::new(vec![i32::try_from(vocab::BOS).unwrap()], [1, 1]),
        &device(),
    );
    let scores: Vec<f32> = model
        .decode(memory, &batch.pad, &batch.copyable, prefix)
        .into_data()
        .to_vec()
        .unwrap();
    for (index, score) in scores.iter().take(vocab::size()).enumerate() {
        let token = vocab::Token::try_from(index).unwrap();
        if token != vocab::EOS
            && (vocab::slot_index(token).is_some() || vocab::text_of(token).is_none())
        {
            assert!(
                score.is_infinite() && score.is_sign_negative(),
                "input-only token {token} can be generated"
            );
        }
    }
}
