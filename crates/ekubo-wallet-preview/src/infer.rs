//! Bounded, asynchronous inference with copy constraints and explicit handling
//! of incomplete inputs. Predictions are advisory and can be semantically wrong.

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
    /// plans. Dispatches contain at most eight rows to bound tensor memory.
    #[must_use]
    pub fn preview_all(&self, documents: &[PlanDocument]) -> Vec<TransactionPreview> {
        futures::executor::block_on(self.preview_all_async(documents))
            .unwrap_or_else(|_| vec![TransactionPreview::unrecognized(); documents.len()])
    }

    /// Browser-safe inference: GPU readbacks must yield to the event loop.
    /// Batches are bounded and grouped by width so one long request cannot
    /// inflate every other request's attention tensors.
    pub async fn legacy_all_async(
        &self,
        documents: &[PlanDocument],
    ) -> Result<Vec<TransactionPreview>, String> {
        let mut prepared = Prepared::default();
        for document in documents {
            prepared.push(document);
        }
        prepared
            .pending
            .sort_by_key(|(_, slots)| crate::slots::width_for(slots.tokens.len()));
        for rows in prepared.pending.chunk_by(|a, b| {
            crate::slots::width_for(a.1.tokens.len()) == crate::slots::width_for(b.1.tokens.len())
        }) {
            let width = crate::slots::width_for(rows[0].1.tokens.len());
            for chunk in rows.chunks(batch_size_for(width)) {
                for (index, mut preview) in self.run(chunk).await? {
                    if let Some(floor) = prepared.warned.get(&index) {
                        // A learned label cannot downgrade a decoded warning.
                        preview.risk =
                            RiskBand::from_index(preview.risk.index().max(floor.index()));
                    }
                    prepared.previews[index] = preview;
                }
            }
        }
        Ok(prepared
            .groups
            .iter()
            .map(|group| aggregate(&prepared.previews[group.clone()]))
            .collect())
    }

    /// Card summaries are the public default on every backend.
    pub async fn preview_all_async(
        &self,
        documents: &[PlanDocument],
    ) -> Result<Vec<TransactionPreview>, String> {
        self.card_all_async(documents).await
    }

    #[cfg(test)]
    fn legacy_preview_all(&self, documents: &[PlanDocument]) -> Vec<TransactionPreview> {
        futures::executor::block_on(self.legacy_all_async(documents)).expect("legacy inference")
    }

    #[cfg(test)]
    fn legacy_preview(&self, document: &PlanDocument) -> TransactionPreview {
        self.legacy_preview_all(std::slice::from_ref(document))
            .remove(0)
    }

    /// Fast card summaries: encode distinct call readings once, then realize
    /// the complete ordered plan under a character budget. Concrete values do
    /// not enter the neural vocabulary, so repeated readings can share a
    /// prediction even when their amounts or addresses differ.
    pub async fn card_all_async(
        &self,
        documents: &[PlanDocument],
    ) -> Result<Vec<TransactionPreview>, String> {
        let mut outputs = Vec::with_capacity(documents.len());
        let mut shared =
            std::collections::BTreeMap::<Vec<Token>, (TransactionClass, RiskBand)>::new();
        for document in documents {
            let mut work = 0_usize;
            let mut predictions: Vec<_> = document
                .calls
                .iter()
                .map(|call| TransactionPreview {
                    basis: crate::SummaryBasis::Interpretation,
                    class: TransactionClass::Unrecognized,
                    risk: if call.description.is_some() {
                        RiskBand::Caution
                    } else {
                        RiskBand::Critical
                    },
                    summary: String::new(),
                })
                .collect();
            let mut unique = std::collections::BTreeMap::<Vec<Token>, Vec<usize>>::new();
            let mut pending = Vec::new();
            for (index, call) in document.calls.iter().enumerate() {
                let part = PlanDocument {
                    simulation: None,
                    calls: vec![crate::evidence::project(call)],
                };
                let slots = slotize(&part);
                if part.calls[0].description.is_none() || slots.truncated {
                    continue;
                }
                if let Some(indices) = unique.get_mut(&slots.tokens) {
                    indices.push(index);
                    continue;
                }
                let width = crate::slots::width_for(slots.tokens.len());
                // Quadratic attention work, not just number of rows, bounds
                // latency. Full-plan realization still examines EVERY call.
                let cost = width * width;
                if work + cost > 262_144 {
                    continue;
                }
                work += cost;
                unique.insert(slots.tokens.clone(), vec![index]);
                if !shared.contains_key(&slots.tokens) {
                    pending.push((index, slots));
                }
            }
            pending.sort_by_key(|(_, slots)| crate::slots::width_for(slots.tokens.len()));
            for rows in pending.chunk_by(|a, b| {
                crate::slots::width_for(a.1.tokens.len())
                    == crate::slots::width_for(b.1.tokens.len())
            }) {
                let width = crate::slots::width_for(rows[0].1.tokens.len());
                for chunk in rows.chunks(batch_size_for(width)) {
                    let (input, pad, _) = self.tensors(chunk, width);
                    let prediction = self.model.classify(self.model.encode(input, &pad), &pad);
                    let classes = indices_async(prediction.class.argmax(1)).await?;
                    let risks = indices_async(prediction.risk.argmax(1)).await?;
                    for ((_, slots), (class, risk)) in
                        chunk.iter().zip(classes.into_iter().zip(risks))
                    {
                        shared.insert(
                            slots.tokens.clone(),
                            (
                                TransactionClass::from_index(
                                    usize::try_from(class).unwrap_or(usize::MAX),
                                ),
                                RiskBand::from_index(usize::try_from(risk).unwrap_or(usize::MAX)),
                            ),
                        );
                    }
                }
            }
            for (tokens, indices) in &unique {
                if let Some((class, risk)) = shared.get(tokens) {
                    for index in indices {
                        predictions[*index].class = *class;
                        predictions[*index].risk = *risk;
                    }
                }
            }
            for (call, prediction) in document.calls.iter().zip(&mut predictions) {
                if let Some(class) = standard_class(call) {
                    prediction.class = class;
                    prediction.risk = match class {
                        TransactionClass::Approval => RiskBand::Critical,
                        TransactionClass::Transfer => RiskBand::Caution,
                        _ => RiskBand::Routine,
                    };
                }
                prediction.risk =
                    RiskBand::from_index(prediction.risk.index().max(call_risk_floor(call)));
            }
            let mut result = aggregate(&predictions);
            let focus = crate::focus::scores(
                &predictions
                    .iter()
                    .zip(&document.calls)
                    .map(|(p, call)| {
                        if call.description.is_some() {
                            p.class
                        } else {
                            TransactionClass::Unrecognized
                        }
                    })
                    .collect::<Vec<_>>(),
            );
            if let Some(index) = (0..focus.len()).max_by(|a, b| focus[*a].total_cmp(&focus[*b])) {
                result.class = predictions[index].class;
            }
            if document.nothing_decoded() {
                result.class = TransactionClass::Unrecognized;
            }
            let summary = crate::card::compose(document, &predictions);
            result.summary = summary.text;
            result.basis = summary.basis;
            if let Some(class) = summary.inferred_class {
                result.class = class;
            }
            outputs.push(result);
        }
        Ok(outputs)
    }

    /// Encode, classify, and decode one batch.
    async fn run(
        &self,
        pending: &[(usize, Slotized)],
    ) -> Result<Vec<(usize, TransactionPreview)>, String> {
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
        let classes = indices_async(prediction.class.argmax(1)).await?;
        let risks = indices_async(prediction.risk.argmax(1)).await?;
        let summaries = self
            .decode_greedy(&memory, &pad, &copyable, pending)
            .await?;

        Ok(pending
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
                    .filter(|tokens| preserves_actions(tokens, slotized))
                    .filter(|tokens| values_are_all_from(&slotized.render(tokens), slotized))
                    .map_or_else(
                        || action_fallback(slotized),
                        |tokens| render_summary(slotized, tokens),
                    );
                (
                    *index,
                    TransactionPreview {
                        basis: crate::SummaryBasis::Interpretation,
                        class,
                        risk,
                        summary,
                    },
                )
            })
            .collect())
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
    async fn decode_greedy(
        &self,
        memory: &Tensor<B, 3>,
        pad: &Tensor<B, 2, Bool>,
        copyable: &Tensor<B, 2, Bool>,
        pending: &[(usize, Slotized)],
    ) -> Result<Vec<Vec<Token>>, String> {
        let size = pending.len();
        let vocabulary = vocab::size();
        let length = memory.dims()[1];
        let blocked: Vec<bool> = pending
            .iter()
            .flat_map(|(_, slots)| {
                (0..vocabulary + length).map(move |index| {
                    index < vocabulary
                        && !grounded_word(
                            vocab::Token::try_from(index).unwrap_or(vocab::UNK),
                            slots,
                        )
                })
            })
            .collect();
        let blocked = Tensor::<B, 3, Bool>::from_data(
            TensorData::new(blocked, [size, 1, vocabulary + length]),
            &self.device,
        );
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
                .slice([0..size, steps - 1..steps])
                .mask_fill(blocked.clone(), f64::NEG_INFINITY);
            let chosen = indices_async(logits.argmax(2)).await?;
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
                    if token == vocab::PAD {
                        summaries[row].clear();
                    }
                    finished[row] = true;
                    prefixes[row].push(vocab::EOS);
                    continue;
                }
                summaries[row].push(token);
                prefixes[row].push(token);
            }
        }
        for (summary, done) in summaries.iter_mut().zip(finished) {
            if !done {
                summary.clear();
            }
        }
        Ok(summaries)
    }
}

/// Attention memory grows with batch × width². Long calls use smaller
/// batches so a queue of near-limit inputs cannot multiply peak memory by eight.
fn batch_size_for(width: usize) -> usize {
    (8 * 128 * 128 / width.max(1).pow(2)).clamp(1, 8)
}

/// Action copies must preserve their original call order, with no omission or
/// repetition. If generation cannot do this, show the decoded actions directly.
fn preserves_actions(tokens: &[Token], slots: &Slotized) -> bool {
    let expected: Vec<_> = slots
        .slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| {
            matches!(
                slot.kind,
                crate::slots::SlotKind::Action | crate::slots::SlotKind::Protocol
            )
        })
        .map(|(index, _)| index)
        .collect();
    let actual: Vec<_> = tokens
        .iter()
        .filter_map(|token| vocab::slot_index(*token))
        .filter(|index| {
            slots.slots.get(*index).is_some_and(|slot| {
                matches!(
                    slot.kind,
                    crate::slots::SlotKind::Action | crate::slots::SlotKind::Protocol
                )
            })
        })
        .collect();
    actual == expected
}

fn action_fallback(slots: &Slotized) -> String {
    render_summary(slots, &[])
}

/// The model selects supporting fields; their original labels supply the
/// relationship. Never turn "Minimum output: 0.01 ETH" into an assertion that
/// the transaction removes 0.01 ETH of liquidity, or a contract into a recipient.
#[must_use]
pub fn render_summary(slots: &Slotized, tokens: &[Token]) -> String {
    let selected: std::collections::BTreeSet<_> = tokens
        .iter()
        .filter_map(|token| vocab::slot_index(*token))
        .filter_map(|index| slots.slots.get(index).and_then(|slot| slot.field))
        .collect();
    slots
        .slots
        .iter()
        .filter(|slot| slot.kind == crate::slots::SlotKind::Action)
        .map(|action| {
            let mut text = slots
                .call_slots(action.call)
                .find(|(_, slot)| slot.kind == crate::slots::SlotKind::Protocol)
                .map_or_else(
                    || action.text.clone(),
                    |(_, protocol)| format!("{}: {}", protocol.text, action.text),
                );
            let fields: Vec<_> = selected
                .iter()
                .filter_map(|index| slots.fields.get(*index))
                .filter(|field| {
                    field.call == action.call
                        && field.text.chars().count() <= 160
                        && field
                            .text
                            .split_once(':')
                            .is_some_and(|(label, _)| !label.trim().is_empty())
                })
                .take(2)
                .map(|field| field.text.as_str())
                .collect();
            if !fields.is_empty() {
                text.push_str(" — ");
                text.push_str(&fields.join("; "));
            }
            text
        })
        .collect::<Vec<_>>()
        .join("; then ")
}

/// Content words must occur in the decoded input. Only grammatical connectors
/// and generic summary scaffolding can be supplied from outside it. This stops
/// familiar but unsupported completions such as "withdraw celo" for "withdraw
/// core" without changing the model's learned weights or its copy mechanism.
fn grounded_word(token: Token, slots: &Slotized) -> bool {
    token == vocab::EOS
        || slots.tokens.contains(&token)
        || vocab::text_of(token).is_some_and(|word| {
            matches!(
                word,
                "," | "."
                    | ":"
                    | ";"
                    | "then"
                    | "and"
                    | "more"
                    | "call"
                    | "calls"
                    | "one"
                    | "two"
                    | "three"
                    | "several"
                    | "a"
                    | "an"
                    | "the"
                    | "contract"
                    | "unrecognized"
                    | "using"
                    | "through"
                    | "for"
                    | "to"
                    | "from"
                    | "with"
                    | "on"
                    | "of"
                    | "if"
                    | "letting"
                    | "spend"
                    | "let"
                    | "stop"
                    | "controlling"
                    | "every"
                    | "token"
                    | "tokens"
                    | "actions"
            )
        })
}

/// Prepared rows retain their original grouping while inference sorts by width.
#[derive(Default)]
struct Prepared {
    previews: Vec<TransactionPreview>,
    pending: Vec<(usize, Slotized)>,
    warned: std::collections::BTreeMap<usize, RiskBand>,
    groups: Vec<std::ops::Range<usize>>,
}

impl Prepared {
    fn push(&mut self, document: &PlanDocument) {
        let start = self.previews.len();
        let slots = slotize(document);
        if document.calls.len() > 1
            && (document.calls.len() > 2
                || slots.truncated
                || document
                    .calls
                    .iter()
                    .any(|call| standard_class(call).is_some() || call.description.is_none()))
        {
            // Every call is examined, including a dangerous final call. Never
            // label the entire plan from its first 512 tokens.
            for call in &document.calls {
                let part = PlanDocument {
                    simulation: None,
                    calls: vec![call.clone()],
                };
                let slots = slotize(&part);
                self.push_part(&part, slots);
            }
        } else {
            self.push_part(document, slots);
        }
        self.groups.push(start..self.previews.len());
    }

    fn push_part(&mut self, document: &PlanDocument, slots: Slotized) {
        let index = self.previews.len();
        self.previews.push(TransactionPreview::unrecognized());
        if let [call] = document.calls.as_slice()
            && let Some(class) = standard_class(call)
        {
            let base_risk = match class {
                TransactionClass::Approval => RiskBand::Critical,
                TransactionClass::Transfer => RiskBand::Caution,
                _ => RiskBand::Routine,
            };
            self.previews[index] = TransactionPreview {
                basis: crate::SummaryBasis::Interpretation,
                class,
                risk: RiskBand::from_index(base_risk.index().max(call_risk_floor(call))),
                summary: call.description.clone().unwrap_or_default(),
            };
            return;
        }
        if slots.truncated {
            self.previews[index].summary =
                "Call exceeds preview limits; review decoded fields.".into();
            return;
        }
        if document.nothing_decoded() {
            // There is no action verb to infer. State the missing reading and
            // preserve the known native value without asking the model to guess.
            if let [call] = document.calls.as_slice()
                && !crate::slots::is_zero_value(&call.native_value)
            {
                self.previews[index].summary = format!(
                    "Undecoded call to {} sending {}",
                    call.target, call.native_value
                );
            }
            return;
        }
        let floor = document
            .calls
            .iter()
            .map(call_risk_floor)
            .max()
            .unwrap_or(0);
        if floor > 0 {
            self.warned.insert(index, RiskBand::from_index(floor));
        }
        self.pending.push((index, slots));
    }
}

fn call_risk_floor(call: &crate::slots::CallSummary) -> usize {
    if call
        .evidence
        .as_ref()
        .is_some_and(crate::evidence::unlimited_approval)
    {
        return RiskBand::Critical.index();
    }
    if call.description.is_none() && call.details.is_empty() {
        return RiskBand::Critical.index();
    }
    let critical = call.warnings.iter().any(|warning| {
        let warning = warning.to_lowercase();
        [
            "unlimited",
            "setapprovalforall",
            "operator",
            "all tokens",
            "unrecognized",
        ]
        .iter()
        .any(|phrase| warning.contains(phrase))
    });
    if critical {
        RiskBand::Critical.index()
    } else if call.warnings.is_empty() {
        RiskBand::Routine.index()
    } else {
        RiskBand::Caution.index()
    }
}

/// These standard readings already state the direction of authority or the
/// sender/recipient relationship. A learned category must not reverse them.
fn standard_class(call: &crate::slots::CallSummary) -> Option<TransactionClass> {
    let description = call.description.as_deref()?;
    if description.starts_with("transferFrom ") {
        return Some(TransactionClass::Transfer);
    }
    let explicit_flag = description.starts_with("setApprovalForAll operator ");
    if description.starts_with("setApprovalForAll: revoke operator ")
        || (explicit_flag && description.ends_with(" approved false"))
    {
        return Some(TransactionClass::Revocation);
    }
    if description.starts_with("setApprovalForAll: grant operator ")
        || (explicit_flag && description.ends_with(" approved true"))
    {
        return Some(TransactionClass::Approval);
    }
    None
}

fn aggregate(parts: &[TransactionPreview]) -> TransactionPreview {
    if parts.len() == 1 {
        return parts[0].clone();
    }
    let Some(first) = parts.first() else {
        return TransactionPreview::unrecognized();
    };
    let class = if parts.iter().all(|part| part.class == first.class) {
        first.class
    } else {
        TransactionClass::Batch
    };
    let (index, most_attention) = parts
        .iter()
        .enumerate()
        .max_by_key(|(index, part)| {
            (
                part.risk.index(),
                part.class == TransactionClass::Unrecognized,
                std::cmp::Reverse(*index),
            )
        })
        .expect("nonempty parts");
    let detail = if most_attention.summary.is_empty() {
        most_attention.class.label()
    } else {
        &most_attention.summary
    };
    TransactionPreview {
        basis: crate::SummaryBasis::Interpretation,
        class,
        risk: most_attention.risk,
        summary: format!(
            "{} calls; call {}: {detail}. Review all calls.",
            parts.len(),
            index + 1
        ),
    }
}

/// Readback failure is an error, never an empty index vector interpreted as
/// the first (routine) label. Awaiting is required for browser WebGPU.
async fn indices_async<B: Backend, const D: usize>(
    tensor: Tensor<B, D, Int>,
) -> Result<Vec<i64>, String> {
    let expected: usize = tensor.dims().iter().product();
    let data = tensor.into_data_async().await.map_err(|e| e.to_string())?;
    let values: Vec<i64> = data
        .convert::<i64>()
        .to_vec()
        .map_err(|e| format!("reading indices: {e:?}"))?;
    if values.len() != expected {
        return Err("incomplete index readback".into());
    }
    Ok(values)
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
        !looks_like_a_value
            || slotized.slots.iter().any(|slot| {
                slot.text
                    .split_whitespace()
                    .any(|value| value.trim_matches(|c: char| c.is_ascii_punctuation()) == word)
            })
    })
}

#[cfg(test)]
#[path = "infer_test.rs"]
mod tests;
