//! Reading the labeled corpus, batching it, and fitting the model to it.
//!
//! Compiled only under the `train` feature; nothing here ships in the wallet.
//!
//! The one part worth reading closely is how a summary's slot references
//! become training targets. A reference is *not* a vocabulary id in the
//! target: it is resolved to the input position holding that reference, and
//! the target index becomes `vocabulary + position`. That is the same joint
//! space [`crate::model::PreviewModel::decode`] scores in, so the loss teaches
//! the copy head to point rather than teaching the word head to recite. A
//! summary naming a slot the input does not carry has no valid target and the
//! example is dropped rather than pointed somewhere arbitrary.

use crate::{
    model::PreviewModel,
    slots::{MAX_INPUT_TOKENS, MAX_SUMMARY_TOKENS},
    taxonomy::{CLASS_COUNT, RiskBand, TransactionClass},
    vocab::{self, Token},
};
use burn::{
    nn::loss::CrossEntropyLossConfig,
    tensor::{Bool, Int, Tensor, TensorData, backend::Backend},
};
use serde::Deserialize;
use std::collections::BTreeMap;

/// One labeled example, as `scripts/preview-labels.py` writes it.
#[derive(Clone, Debug, Deserialize)]
pub struct Labeled {
    pub formats: Vec<String>,
    pub input_pieces: Vec<String>,
    /// The plan exactly as the interpretation left it, so a sample can be run
    /// through the engine the way the wallet runs it.
    #[serde(default)]
    pub document: crate::slots::PlanDocument,
    pub summary_pieces: Vec<String>,
    pub class: String,
    pub risk: String,
}

/// One example converted to ids, ready to batch.
#[derive(Clone, Debug)]
pub struct Encoded {
    pub input: Vec<Token>,
    /// True at positions holding a slot reference: the only ones a copy may
    /// land on.
    pub copyable: Vec<bool>,
    /// What the decoder is *fed*: `[BOS, …]` in vocabulary ids, where a step
    /// that names a value is fed the `<sN>` token.
    ///
    /// Separate from [`Self::summary_targets`] and it has to be. The target
    /// for a copy is `vocabulary + position`, which is an index into the joint
    /// output space -- but the decoder's input goes through an embedding table
    /// with one row per *vocabulary* entry, so feeding it a joint index reads
    /// off the end of that table. Inference already fed back the `<sN>` token;
    /// training fed back the joint index, and burn's `select` panicked on the
    /// out-of-range row.
    pub summary_inputs: Vec<Token>,
    /// What each fed position should predict: `[…, EOS]` in the joint index
    /// space, so a copy is scored against the input position it names.
    pub summary_targets: Vec<usize>,
    pub class: usize,
    pub risk: usize,
    /// The descriptor formats this example was built from, which is what the
    /// held-out split is drawn along.
    pub formats: Vec<String>,
}

/// Convert one labeled example, or drop it.
///
/// Every reason to drop is a reason the example could not have been learned
/// from: a class the enum does not have, a summary piece outside the
/// vocabulary, or a slot reference the input does not carry. Each would
/// otherwise become a target the model cannot reach.
#[must_use]
pub fn encode(labeled: &Labeled, vocabulary: usize) -> Option<Encoded> {
    let class = TransactionClass::from_corpus_name(&labeled.class)?.index();
    let risk = RiskBand::from_corpus_name(&labeled.risk)?.index();
    let input: Vec<Token> = labeled
        .input_pieces
        .iter()
        .take(MAX_INPUT_TOKENS)
        .map(|piece| vocab::token_of(piece))
        .collect();
    if input.is_empty() {
        return None;
    }
    let copyable: Vec<bool> = input
        .iter()
        .map(|token| vocab::slot_index(*token).is_some())
        .collect();
    // Where each slot reference sits in the input, which is what a copy
    // target has to name.
    let positions: BTreeMap<usize, usize> = input
        .iter()
        .enumerate()
        .filter_map(|(position, token)| Some((vocab::slot_index(*token)?, position)))
        .collect();

    let mut summary_inputs = vec![vocab::BOS];
    let mut summary_targets = Vec::new();
    for piece in labeled.summary_pieces.iter().take(MAX_SUMMARY_TOKENS - 2) {
        if let Some(slot) = slot_reference(piece) {
            summary_targets.push(vocabulary + positions.get(&slot).copied()?);
            summary_inputs.push(vocab::slot_token(slot)?);
        } else {
            let token = vocab::token_of(piece);
            if token == vocab::UNK {
                return None;
            }
            summary_targets.push(token as usize);
            summary_inputs.push(token);
        }
    }
    summary_targets.push(vocab::EOS as usize);
    Some(Encoded {
        input,
        copyable,
        summary_inputs,
        summary_targets,
        class,
        risk,
        formats: labeled.formats.clone(),
    })
}

/// The slot a `<sN>` piece refers to.
fn slot_reference(piece: &str) -> Option<usize> {
    piece
        .strip_prefix("<s")
        .and_then(|rest| rest.strip_suffix('>'))
        .and_then(|digits| digits.parse().ok())
}

/// A padded batch on one device.
pub struct Batch<B: Backend> {
    pub input: Tensor<B, 2, Int>,
    pub pad: Tensor<B, 2, Bool>,
    pub copyable: Tensor<B, 2, Bool>,
    /// The decoder's input: the summary without its last token.
    pub prefix: Tensor<B, 2, Int>,
    /// What each prefix position should predict: the summary without its
    /// first token, with padding written as [`vocab::PAD`] so the loss can
    /// ignore it.
    pub target: Tensor<B, 2, Int>,
    pub class: Tensor<B, 1, Int>,
    pub risk: Tensor<B, 1, Int>,
    pub length: usize,
}

/// Pad a slice of examples into one batch of a fixed shape.
///
/// The shape comes from the caller rather than from the members, because a
/// shape that varies with the batch is a shape `cubecl` compiles a new kernel
/// for. An example longer than the bucket's width is truncated, which only
/// reaches examples past the widest bucket.
#[must_use]
pub fn batch<B: Backend>(examples: &[Encoded], shape: Shape, device: &B::Device) -> Batch<B> {
    let size = examples.len();
    let length = shape.width;
    let steps = SUMMARY_WIDTH - 1;

    let mut input = Vec::with_capacity(size * length);
    let mut pad = Vec::with_capacity(size * length);
    let mut copyable = Vec::with_capacity(size * length);
    let mut prefix = Vec::with_capacity(size * steps);
    let mut target = Vec::with_capacity(size * steps);
    for example in examples {
        for position in 0..length {
            let token = example.input.get(position).copied();
            input.push(i32::try_from(token.unwrap_or(vocab::PAD)).unwrap_or_default());
            pad.push(token.is_none());
            copyable.push(example.copyable.get(position).copied().unwrap_or(false));
        }
        for step in 0..steps {
            // Fed as a vocabulary id, scored against the joint space. Feeding
            // the joint index back would index an embedding table that only
            // has vocabulary rows.
            prefix.push(
                i32::try_from(
                    example
                        .summary_inputs
                        .get(step)
                        .copied()
                        .unwrap_or(vocab::PAD),
                )
                .unwrap_or_default(),
            );
            target.push(
                i32::try_from(
                    example
                        .summary_targets
                        .get(step)
                        .copied()
                        .unwrap_or(vocab::PAD as usize),
                )
                .unwrap_or_default(),
            );
        }
    }

    Batch {
        input: Tensor::from_data(TensorData::new(input, [size, length]), device),
        pad: Tensor::from_data(TensorData::new(pad, [size, length]), device),
        copyable: Tensor::from_data(TensorData::new(copyable, [size, length]), device),
        prefix: Tensor::from_data(TensorData::new(prefix, [size, steps]), device),
        target: Tensor::from_data(TensorData::new(target, [size, steps]), device),
        class: Tensor::from_data(
            TensorData::new(
                examples
                    .iter()
                    .map(|example| i32::try_from(example.class).unwrap_or_default())
                    .collect::<Vec<_>>(),
                [size],
            ),
            device,
        ),
        risk: Tensor::from_data(
            TensorData::new(
                examples
                    .iter()
                    .map(|example| i32::try_from(example.risk).unwrap_or_default())
                    .collect::<Vec<_>>(),
                [size],
            ),
            device,
        ),
        length,
    }
}

/// The three losses, summed.
///
/// The class loss is inverse-frequency weighted. The corpus is what the
/// vendored registry happens to describe -- five thousand withdrawals against
/// sixty-eight borrows -- and unweighted, the cheapest way to a low loss is to
/// answer "withdraw" and never say "borrow" at all.
pub fn loss<B: Backend>(
    model: &PreviewModel<B>,
    batch: &Batch<B>,
    weights: &[f32],
    device: &B::Device,
) -> Tensor<B, 1> {
    let memory = model.encode(batch.input.clone(), &batch.pad);
    let prediction = model.classify(memory.clone(), &batch.pad);
    let class_loss = CrossEntropyLossConfig::new()
        .with_weights(Some(weights.to_vec()))
        .init(device)
        .forward(prediction.class, batch.class.clone());
    let risk_loss = CrossEntropyLossConfig::new()
        .init(device)
        .forward(prediction.risk, batch.risk.clone());

    let logits = model.decode(memory, &batch.pad, &batch.copyable, batch.prefix.clone());
    let [size, steps, width] = logits.dims();
    // Padding in the target is written as PAD, and the loss is told to ignore
    // it, so a short summary in a batch of long ones costs nothing.
    let summary_loss = CrossEntropyLossConfig::new()
        .with_pad_tokens(Some(vec![vocab::PAD as usize]))
        .init(device)
        .forward(
            logits.reshape([size * steps, width]),
            batch.target.clone().reshape([size * steps]),
        );
    class_loss + risk_loss + summary_loss
}

/// Inverse-frequency class weights, normalized to average one.
#[must_use]
pub fn class_weights(examples: &[Encoded]) -> Vec<f32> {
    let mut counts = [0_usize; CLASS_COUNT];
    for example in examples {
        if let Some(count) = counts.get_mut(example.class) {
            *count += 1;
        }
    }
    let present = counts.iter().filter(|count| **count > 0).count().max(1);
    let total: usize = counts.iter().sum::<usize>().max(1);
    let mean = ratio(total, present);
    counts
        .iter()
        .map(|count| {
            if *count == 0 {
                1.0
            } else {
                // Square-rooted rather than raw inverse frequency: the raw
                // ratio here is 75x, which would make sixty-eight borrow
                // examples outweigh five thousand withdrawals and teach the
                // model to shout "borrow" at everything.
                (mean / ratio(*count, 1)).sqrt().clamp(0.25, 4.0)
            }
        })
        .collect()
}

/// The padded widths a batch may have, and how many examples each holds.
///
/// Both halves of this table exist for the same reason, and it is not
/// performance tuning. Every distinct tensor shape makes `cubecl` compile a
/// fresh kernel and reserve fresh buffers for it, and this model trains on an
/// integrated GPU with a 2 GB carve-out. Batching by a token budget gave
/// almost every batch its own `(count, width)` pair -- hundreds of shapes --
/// and the run died with "radv/amdgpu: not enough memory for command
/// submission" before finishing one epoch.
///
/// Five widths means five shapes. The counts fall as the widths rise so that
/// `count * width` stays near constant, which is what keeps the longest one
/// percent of the corpus from deciding how much memory the run needs.
/// Widths come from [`crate::slots::WIDTHS`], which inference pads to as well.
/// The counts fall as the widths rise so `count * width` stays near constant.
const COUNTS: [usize; 5] = [64, 32, 16, 8, 4];

/// Summaries are padded to one width for the same reason a plan is: the step
/// count is another shape axis.
///
/// This is [`MAX_SUMMARY_TOKENS`] rather than a number of its own, because the
/// width the corpus pads to is exactly the range of positional embeddings the
/// decoder is allowed to decode into later.
pub const SUMMARY_WIDTH: usize = MAX_SUMMARY_TOKENS;

/// One batch's fixed shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub width: usize,
    pub count: usize,
}

/// The bucket an example of this length belongs to.
#[must_use]
pub fn bucket_of(length: usize) -> Shape {
    let index = crate::slots::WIDTHS
        .iter()
        .position(|width| length <= *width)
        .unwrap_or(COUNTS.len() - 1);
    Shape {
        width: crate::slots::WIDTHS[index],
        count: COUNTS[index],
    }
}

/// Group examples into fixed-shape batches, then shuffle the batches.
///
/// A trailing partial batch is filled by cycling that bucket's own examples
/// rather than being padded with nothing or dropped: keeping the shape fixed
/// is the whole point, and repeating a handful of examples once per epoch
/// weighs less than losing them.
///
/// Shuffling the batches rather than the examples keeps the gradient noise
/// shuffling is for -- a batch's composition is fixed, but the order it
/// arrives in is not.
#[must_use]
pub fn batches(examples: &[Encoded], rng: &mut impl rand::RngExt) -> Vec<(Shape, Vec<Encoded>)> {
    let mut by_bucket: BTreeMap<usize, Vec<Encoded>> = BTreeMap::new();
    for example in examples {
        let shape = bucket_of(example.input.len());
        by_bucket
            .entry(shape.width)
            .or_default()
            .push(example.clone());
    }
    let mut batched = Vec::new();
    for (width, mut members) in by_bucket {
        let shape = Shape {
            width,
            count: bucket_of(width).count,
        };
        rand::seq::SliceRandom::shuffle(&mut members[..], rng);
        let mut at = 0;
        while at < members.len() {
            let mut chunk: Vec<Encoded> =
                members.iter().skip(at).take(shape.count).cloned().collect();
            let original = chunk.len();
            while chunk.len() < shape.count && original > 0 {
                let filler = chunk[chunk.len() % original].clone();
                chunk.push(filler);
            }
            batched.push((shape, chunk));
            at += shape.count;
        }
    }
    rand::seq::SliceRandom::shuffle(&mut batched[..], rng);
    batched
}

/// A count as a float. Corpus counts are far below `f32`'s exact-integer
/// range, so this is a conversion rather than a narrowing; it saturates so a
/// count that somehow exceeded it produces a large weight rather than a wrong
/// one.
fn ratio(numerator: usize, denominator: usize) -> f32 {
    // u16 rather than u32 because every count here is a corpus population, and
    // saturating a class count at 65535 changes a weight by a fraction of a
    // percent while keeping the conversion exact.
    let numerator = f32::from(u16::try_from(numerator).unwrap_or(u16::MAX));
    let denominator = f32::from(u16::try_from(denominator.max(1)).unwrap_or(u16::MAX));
    numerator / denominator
}

/// Split examples so that no descriptor format appears on both sides.
///
/// Splitting by example would measure how well the model memorizes the
/// formats it was fitted on, which is not the claim it exists to make. It has
/// to read a protocol nobody vendored a descriptor for, so the held-out set is
/// drawn along formats: an entire format goes to one side or the other.
#[must_use]
pub fn split(examples: Vec<Encoded>, held_out_in: u64) -> (Vec<Encoded>, Vec<Encoded>) {
    let mut train = Vec::new();
    let mut evaluate = Vec::new();
    for example in examples {
        let held = example
            .formats
            .iter()
            .filter(|format| !format.is_empty())
            .any(|format| hash(format).is_multiple_of(held_out_in));
        if held {
            evaluate.push(example);
        } else {
            train.push(example);
        }
    }
    (train, evaluate)
}

/// A stable hash, so the same format lands on the same side across runs and
/// machines. `DefaultHasher` promises neither.
fn hash(text: &str) -> u64 {
    let mut value = 0xcbf2_9ce4_8422_2325_u64;
    for byte in text.as_bytes() {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value
}

#[cfg(test)]
#[path = "training_test.rs"]
mod tests;
