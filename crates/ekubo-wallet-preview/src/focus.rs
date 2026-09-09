//! Distilled whole-plan salience. A small contextual ranker allocates the card's
//! detail budget; it cannot create a call, value, permission, or reorder steps.
//! Inputs include all call categories, neighboring actions and call position.

use crate::TransactionClass;
use std::sync::LazyLock;

const CLASSES: usize = 20;
const FEATURES: usize = CLASSES * 4 + 2;
const HIDDEN: usize = 16;
const BYTES: &[u8] = include_bytes!("../model/focus.bin");

struct Ranker {
    weights: Vec<f32>,
    bias: Vec<f32>,
    output: Vec<f32>,
}
static RANKER: LazyLock<Ranker> = LazyLock::new(|| {
    assert_eq!(&BYTES[..8], b"EKFOCUS1");
    assert_eq!(
        u32::from_le_bytes(BYTES[8..12].try_into().expect("header")),
        82
    );
    assert_eq!(
        u32::from_le_bytes(BYTES[12..16].try_into().expect("header")),
        16
    );
    let values: Vec<_> = BYTES[16..]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| f32::from_le_bytes(*word))
        .collect();
    assert_eq!(values.len(), FEATURES * HIDDEN + HIDDEN * 2);
    assert!(values.iter().all(|value| value.is_finite()));
    Ranker {
        weights: values[..FEATURES * HIDDEN].to_vec(),
        bias: values[FEATURES * HIDDEN..(FEATURES + 1) * HIDDEN].to_vec(),
        output: values[(FEATURES + 1) * HIDDEN..].to_vec(),
    }
});

/// One score per call, computed in linear time with constant hidden width.
#[must_use]
pub fn scores(classes: &[TransactionClass]) -> Vec<f32> {
    if classes.is_empty() {
        return Vec::new();
    }
    let size = number(classes.len());
    let mut frequency = [0.0; CLASSES];
    for class in classes {
        frequency[class.index()] += 1.0 / size;
    }
    let model = &*RANKER;
    let shared: Vec<_> = (0..HIDDEN)
        .map(|h| {
            model.bias[h]
                + frequency
                    .iter()
                    .enumerate()
                    .map(|(class, frequency)| {
                        frequency * model.weights[(CLASSES * 3 + class) * HIDDEN + h]
                    })
                    .sum::<f32>()
        })
        .collect();
    classes
        .iter()
        .enumerate()
        .map(|(index, class)| {
            (0..HIDDEN)
                .map(|h| {
                    let mut activation = shared[h] + model.weights[class.index() * HIDDEN + h];
                    if index > 0 {
                        activation +=
                            model.weights[(CLASSES + classes[index - 1].index()) * HIDDEN + h];
                    }
                    if index + 1 < classes.len() {
                        activation +=
                            model.weights[(CLASSES * 2 + classes[index + 1].index()) * HIDDEN + h];
                    }
                    activation += model.weights[(FEATURES - 2) * HIDDEN + h] * number(index)
                        / (size - 1.0).max(1.0);
                    if index + 1 == classes.len() {
                        activation += model.weights[(FEATURES - 1) * HIDDEN + h];
                    }
                    activation.tanh() * model.output[h]
                })
                .sum()
        })
        .collect()
}

fn number(value: usize) -> f32 {
    f32::from(u16::try_from(value).unwrap_or(u16::MAX))
}

#[cfg(test)]
#[path = "focus_test.rs"]
mod tests;
