//! Running the model: greedy decoding, and the checks that stand between it
//! and a reviewer.
//!
//! Two things here are not optimizations and must not be treated as such.
//!
//! A plan whose calls nothing decoded never reaches the model at all. There is
//! no signal in it to classify, and a confident category over calldata nobody
//! read is the exact failure this whole surface has to avoid; the honest
//! answer is [`TransactionClass::Unrecognized`], and it is cheaper as well as
//! truer.
//!
//! And every rendered summary is checked against the values that were lifted
//! out of the plan. Slotization already makes a fabricated digit unreachable
//! -- the model emits positions, and rendering substitutes verbatim -- so this
//! check should never fire. It is here because "should never fire" is a claim
//! about code that will be changed later by someone reading less of it than
//! you are now. If a summary ever contains a number or an address that is not
//! in the plan it describes, the summary is dropped and the class stands
//! alone.

use crate::{
    TransactionPreview,
    model::PreviewModel,
    slots::{MAX_SUMMARY_TOKENS, PlanDocument, Slotized, slotize},
    taxonomy::{RiskBand, TransactionClass},
    vocab::{self, Token},
};
use burn::tensor::{Bool, Int, Tensor, TensorData, backend::Backend};

/// The model, loaded and ready.
pub struct PreviewEngine<B: Backend> {
    model: PreviewModel<B>,
    device: B::Device,
}

impl<B: Backend> PreviewEngine<B> {
    /// Wrap an already-loaded model.
    pub const fn new(model: PreviewModel<B>, device: B::Device) -> Self {
        Self { model, device }
    }

    /// The preview for one plan.
    #[must_use]
    pub fn preview(&self, document: &PlanDocument) -> TransactionPreview {
        self.preview_all(std::slice::from_ref(document))
            .pop()
            .unwrap_or_else(TransactionPreview::unrecognized)
    }

    /// Previews for several plans at once.
    ///
    /// Batched because the review list asks for every waiting request at the
    /// same moment, and the decode loop is sequential in *steps* but not in
    /// plans: forty plans cost about what one does.
    #[must_use]
    pub fn preview_all(&self, documents: &[PlanDocument]) -> Vec<TransactionPreview> {
        let mut previews = Vec::with_capacity(documents.len());
        let mut pending = Vec::new();
        let mut undecoded = Vec::new();
        for (index, document) in documents.iter().enumerate() {
            previews.push(TransactionPreview::unrecognized());
            if document.is_opaque() {
                continue;
            }
            if document.nothing_decoded() {
                undecoded.push(index);
            }
            pending.push((index, slotize(document)));
        }
        if pending.is_empty() {
            return previews;
        }
        for (index, mut preview) in self.run(&pending) {
            // A plan nothing decoded keeps the answer we know rather than the
            // one the model guessed. It still gets the sentence, because the
            // value it is moving is worth naming.
            if undecoded.contains(&index) {
                preview.class = TransactionClass::Unrecognized;
                preview.risk = RiskBand::Critical;
            }
            if let Some(slot) = previews.get_mut(index) {
                *slot = preview;
            }
        }
        previews
    }

    /// Encode, classify, and decode one batch.
    fn run(&self, pending: &[(usize, Slotized)]) -> Vec<(usize, TransactionPreview)> {
        // Rounded up to one of a handful of widths rather than padded to the
        // longest member: a shape the backend has already compiled a kernel
        // for costs nothing, and a new one costs a compile and a fresh
        // allocation. See `slots::WIDTHS`.
        let length = crate::slots::width_for(
            pending
                .iter()
                .map(|(_, slotized)| slotized.tokens.len())
                .max()
                .unwrap_or(1),
        );
        let (input, pad, copyable) = self.tensors(pending, length);
        let memory = self.model.encode(input, &pad);
        let prediction = self.model.classify(memory.clone(), &pad);
        let classes = indices(prediction.class.argmax(1));
        let risks = indices(prediction.risk.argmax(1));
        let summaries = self.decode_greedy(&memory, &pad, &copyable, pending);

        pending
            .iter()
            .enumerate()
            .map(|(row, (index, slotized))| {
                let class = classes
                    .get(row)
                    .and_then(|value| usize::try_from(*value).ok())
                    .map_or(TransactionClass::Unrecognized, TransactionClass::from_index);
                let risk = risks
                    .get(row)
                    .and_then(|value| usize::try_from(*value).ok())
                    .map_or(RiskBand::Critical, RiskBand::from_index);
                let summary = summaries
                    .get(row)
                    .map(|tokens| slotized.render(tokens))
                    .filter(|summary| values_are_all_from(summary, slotized))
                    .unwrap_or_default();
                (
                    *index,
                    TransactionPreview {
                        class,
                        risk,
                        summary,
                    },
                )
            })
            .collect()
    }

    /// The padded input, the padding mask, and the mask of positions a copy
    /// may land on.
    fn tensors(
        &self,
        pending: &[(usize, Slotized)],
        length: usize,
    ) -> (Tensor<B, 2, Int>, Tensor<B, 2, Bool>, Tensor<B, 2, Bool>) {
        let size = pending.len();
        let mut input = Vec::with_capacity(size * length);
        let mut pad = Vec::with_capacity(size * length);
        let mut copyable = Vec::with_capacity(size * length);
        for (_, slotized) in pending {
            for position in 0..length {
                let token = slotized.tokens.get(position).copied();
                input.push(i32::try_from(token.unwrap_or(vocab::PAD)).unwrap_or_default());
                pad.push(token.is_none());
                copyable.push(token.is_some_and(|token| vocab::slot_index(token).is_some()));
            }
        }
        (
            Tensor::from_data(TensorData::new(input, [size, length]), &self.device),
            Tensor::from_data(TensorData::new(pad, [size, length]), &self.device),
            Tensor::from_data(TensorData::new(copyable, [size, length]), &self.device),
        )
    }

    /// Greedy decoding, every plan in the batch stepping together.
    ///
    /// Greedy rather than sampled, deliberately: the same plan must produce
    /// the same sentence every time it is drawn, or a reviewer refreshing a
    /// request would see the wording change under them and have no way to tell
    /// that from the plan having changed.
    fn decode_greedy(
        &self,
        memory: &Tensor<B, 3>,
        pad: &Tensor<B, 2, Bool>,
        copyable: &Tensor<B, 2, Bool>,
        pending: &[(usize, Slotized)],
    ) -> Vec<Vec<Token>> {
        let size = pending.len();
        let vocabulary = vocab::size();
        let mut prefixes = vec![vec![vocab::BOS]; size];
        let mut summaries = vec![Vec::new(); size];
        let mut finished = vec![false; size];
        // One fewer than the width the corpus padded to, because the prefix
        // starts at BOS. Decoding further would index positional embeddings
        // no training example ever reached.
        for _ in 0..MAX_SUMMARY_TOKENS - 1 {
            if finished.iter().all(|done| *done) {
                break;
            }
            let steps = prefixes[0].len();
            let flat: Vec<i32> = prefixes
                .iter()
                .flat_map(|prefix| {
                    prefix
                        .iter()
                        .map(|token| i32::try_from(*token).unwrap_or_default())
                })
                .collect();
            let prefix = Tensor::from_data(TensorData::new(flat, [size, steps]), &self.device);
            let logits = self
                .model
                .decode(memory.clone(), pad, copyable, prefix)
                .slice([0..size, steps - 1..steps]);
            let chosen = indices(logits.argmax(2));
            for row in 0..size {
                let picked = chosen.get(row).copied().unwrap_or(0);
                let picked = usize::try_from(picked).unwrap_or(0);
                // Past the vocabulary the model is pointing at an input
                // position; what it named is the slot reference sitting there.
                let token = if picked >= vocabulary {
                    slot_at(&pending[row].1, picked - vocabulary)
                } else {
                    Token::try_from(picked).unwrap_or(vocab::PAD)
                };
                if token == vocab::EOS || token == vocab::PAD || finished[row] {
                    finished[row] = true;
                    prefixes[row].push(vocab::EOS);
                    continue;
                }
                summaries[row].push(token);
                prefixes[row].push(token);
            }
        }
        summaries
    }
}

/// Read a tensor of indices back to the host.
///
/// The conversion is the point. A tensor's integer element type is the
/// backend's choice -- `i64` under `NdArray`, `i32` under `Wgpu` -- and asking
/// `to_vec` for the wrong one fails rather than converting. Paired with
/// `unwrap_or_default` that failure becomes an *empty vector*, which every
/// caller then reads as "no index at this position" and silently substitutes a
/// default for.
///
/// This is not hypothetical. Fitting on a GPU reported a held-out accuracy of
/// exactly 0.0% while the loss fell normally, because every `argmax` came back
/// empty; the same call sits in the decode loop, where it would have made
/// every preview answer the first class and the first risk band. The tests
/// could not have caught it, because they run on `NdArray`, where the type
/// happens to match.
pub fn indices<B: Backend, const D: usize>(tensor: Tensor<B, D, Int>) -> Vec<i64> {
    tensor
        .into_data()
        .convert::<i64>()
        .to_vec()
        .unwrap_or_default()
}

/// The slot reference sitting at an input position.
///
/// Every non-slot position was masked to negative infinity before the argmax,
/// so landing on one means the mask and the logits disagree about what this
/// plan even contains. That answers [`vocab::PAD`], which ends the summary
/// where it stands: a truncated sentence is a defect a reader can see, and
/// continuing past a disagreement about which values exist is how one would
/// end up naming a value that does not.
fn slot_at(slotized: &Slotized, position: usize) -> Token {
    slotized
        .tokens
        .get(position)
        .copied()
        .filter(|token| vocab::slot_index(*token).is_some())
        .unwrap_or(vocab::PAD)
}

/// Whether every number and address in a rendered summary came from the plan.
///
/// This should be impossible to violate: the model emits words and positions,
/// and a position renders as verbatim slot text. The check exists because that
/// argument is about today's code, and a summary that names a value the plan
/// does not contain is the one failure that must never reach a reviewer.
#[must_use]
pub fn values_are_all_from(summary: &str, slotized: &Slotized) -> bool {
    summary.split_whitespace().all(|word| {
        // Punctuation the renderer attached, not part of the value. Stripping
        // only `,` and `.` here silently refused every summary that used a
        // colon -- which is every summary naming a protocol, since those read
        // "Aave DAO: repay loan". A refusal renders as no summary at all, so
        // the bug looked like the model failing to write one rather than like
        // this check being wrong about punctuation.
        let word = word.trim_matches(|character: char| character.is_ascii_punctuation());
        if word.is_empty() {
            return true;
        }
        let looks_like_a_value = word.starts_with("0x")
            || word
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_digit());
        !looks_like_a_value || slotized.slots.iter().any(|slot| slot.text.contains(word))
    })
}

#[cfg(test)]
#[path = "infer_test.rs"]
mod tests;
