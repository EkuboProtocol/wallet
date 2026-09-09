//! The model itself: a small encoder, two classification heads, and a decoder
//! that can only ever emit a word or point at a value.
//!
//! # Shape
//!
//! The encoder reads the slotized plan. Its pooled state feeds a class head
//! and a risk head, both of which select an index into a closed enum, so
//! neither can answer something the review surface cannot display. Its
//! per-position states feed a two-layer decoder that writes the summary one
//! token at a time.
//!
//! # Why the decoder has a copy head
//!
//! A summary names values: "approve *this spender* to spend *this amount*".
//! The slot references that stand for those values could simply be vocabulary
//! entries -- `<s3>` as a word -- and a model would learn to emit them. What
//! it would learn, though, is *positions*: that swaps tend to name `<s1>`,
//! that approvals tend to name `<s0>`. That is memorization of the corpus's
//! layout, and it breaks on the first plan whose values sit somewhere else.
//!
//! So slot references are not produced from the vocabulary at all. At each
//! step the decoder also scores every *input position* that holds a slot
//! reference, by attending to it, and emitting a copy means naming whatever
//! value that position happens to carry. "The first address of this call" is
//! then something the model can learn as a relation between its state and the
//! encoder's, rather than as a lexical habit. It also means the set of things
//! it can name is exactly the set of values the deterministic interpretation
//! lifted -- never a superset.
//!
//! The model is generic over the backend so the same weights run under
//! `NdArray` in a test and `Wgpu` on a GPU in the wallet, and so training can
//! wrap either in `Autodiff`.

use crate::{
    slots::{MAX_INPUT_TOKENS, MAX_SUMMARY_TOKENS},
    taxonomy::{CLASS_COUNT, RISK_COUNT},
    vocab,
};
use burn::{
    module::Module,
    nn::{
        Embedding, EmbeddingConfig, LayerNorm, LayerNormConfig, Linear, LinearConfig,
        attention::{MhaInput, MultiHeadAttention, MultiHeadAttentionConfig},
    },
    tensor::{Bool, Int, Tensor, activation::gelu, backend::Backend},
};

/// Width of the residual stream.
pub const D_MODEL: usize = 192;
/// Attention heads per layer.
pub(crate) const HEADS: usize = 6;
/// The attention scale for copy scores, written out because `D_MODEL` is a
/// constant and `sqrt` is not available in a const context.
const SCALE: f64 = 13.856_406_460_551_018;
const _: () = assert!(D_MODEL == 192, "SCALE is sqrt(D_MODEL); recompute it");

/// Feed-forward width.
pub(crate) const D_FF: usize = 384;
/// Encoder depth.
pub(crate) const ENCODER_LAYERS: usize = 4;
/// Decoder depth. The summary is one short sentence with no long-range
/// structure worth more than this.
pub(crate) const DECODER_LAYERS: usize = 2;

/// One pre-norm transformer block. `cross` is present in the decoder only.
#[derive(Module, Debug)]
pub struct Block<B: Backend> {
    norm_self: LayerNorm<B>,
    attention: MultiHeadAttention<B>,
    norm_cross: Option<LayerNorm<B>>,
    cross: Option<MultiHeadAttention<B>>,
    norm_ff: LayerNorm<B>,
    up: Linear<B>,
    down: Linear<B>,
}

impl<B: Backend> Block<B> {
    fn new(device: &B::Device, with_cross: bool) -> Self {
        Self {
            norm_self: LayerNormConfig::new(D_MODEL).init(device),
            attention: MultiHeadAttentionConfig::new(D_MODEL, HEADS).init(device),
            norm_cross: with_cross.then(|| LayerNormConfig::new(D_MODEL).init(device)),
            cross: with_cross.then(|| MultiHeadAttentionConfig::new(D_MODEL, HEADS).init(device)),
            norm_ff: LayerNormConfig::new(D_MODEL).init(device),
            up: LinearConfig::new(D_MODEL, D_FF).init(device),
            down: LinearConfig::new(D_FF, D_MODEL).init(device),
        }
    }

    /// One block. `pad` masks padded key positions; `causal` stops a decoder
    /// position from reading its own future.
    fn forward(
        &self,
        input: Tensor<B, 3>,
        memory: Option<Tensor<B, 3>>,
        pad: Option<Tensor<B, 2, Bool>>,
        causal: Option<Tensor<B, 3, Bool>>,
    ) -> Tensor<B, 3> {
        let normed = self.norm_self.forward(input.clone());
        let mut attention = MhaInput::self_attn(normed);
        if memory.is_none()
            && let Some(mask) = &pad
        {
            attention = attention.mask_pad(mask.clone());
        }
        if let Some(mask) = causal {
            attention = attention.mask_attn(mask);
        }
        let mut output = input + self.attention.forward(attention).context;

        if let (Some(norm), Some(layer), Some(memory)) =
            (self.norm_cross.as_ref(), self.cross.as_ref(), memory)
        {
            let query = norm.forward(output.clone());
            let mut cross = MhaInput::new(query, memory.clone(), memory);
            if let Some(mask) = pad {
                cross = cross.mask_pad(mask);
            }
            output = output + layer.forward(cross).context;
        }

        let normed = self.norm_ff.forward(output.clone());
        output + self.down.forward(gelu(self.up.forward(normed)))
    }
}

/// The transaction-preview model.
#[derive(Module, Debug)]
pub struct PreviewModel<B: Backend> {
    tokens: Embedding<B>,
    input_positions: Embedding<B>,
    summary_positions: Embedding<B>,
    encoder: Vec<Block<B>>,
    encoder_norm: LayerNorm<B>,
    decoder: Vec<Block<B>>,
    decoder_norm: LayerNorm<B>,
    class_head: Linear<B>,
    risk_head: Linear<B>,
    word_head: Linear<B>,
    /// Projects a decoder state into the space its copy scores are measured
    /// in, so pointing at a value is a learned relation rather than raw
    /// similarity between two spaces that were never aligned.
    copy_query: Linear<B>,
}

/// What one forward pass answers.
pub struct Prediction<B: Backend> {
    /// `[batch, CLASS_COUNT]`
    pub class: Tensor<B, 2>,
    /// `[batch, RISK_COUNT]`
    pub risk: Tensor<B, 2>,
}

impl<B: Backend> PreviewModel<B> {
    /// A model with freshly initialized weights.
    #[must_use]
    pub fn new(device: &B::Device) -> Self {
        let vocabulary = vocab::size();
        Self {
            tokens: EmbeddingConfig::new(vocabulary, D_MODEL).init(device),
            input_positions: EmbeddingConfig::new(MAX_INPUT_TOKENS, D_MODEL).init(device),
            summary_positions: EmbeddingConfig::new(MAX_SUMMARY_TOKENS, D_MODEL).init(device),
            encoder: (0..ENCODER_LAYERS)
                .map(|_| Block::new(device, false))
                .collect(),
            encoder_norm: LayerNormConfig::new(D_MODEL).init(device),
            decoder: (0..DECODER_LAYERS)
                .map(|_| Block::new(device, true))
                .collect(),
            decoder_norm: LayerNormConfig::new(D_MODEL).init(device),
            class_head: LinearConfig::new(D_MODEL, CLASS_COUNT).init(device),
            risk_head: LinearConfig::new(D_MODEL, RISK_COUNT).init(device),
            word_head: LinearConfig::new(D_MODEL, vocabulary).init(device),
            copy_query: LinearConfig::new(D_MODEL, D_MODEL).init(device),
        }
    }

    /// Encode a batch of slotized plans. `input` is `[batch, length]` of token
    /// ids; `pad` is true where a position is padding.
    pub fn encode(&self, input: Tensor<B, 2, Int>, pad: &Tensor<B, 2, Bool>) -> Tensor<B, 3> {
        let [batch, length] = input.dims();
        let device = input.device();
        let positions = Tensor::arange(0..span(length), &device)
            .reshape([1, length])
            .repeat_dim(0, batch);
        let mut state = self.tokens.forward(input) + self.input_positions.forward(positions);
        for block in &self.encoder {
            state = block.forward(state, None, Some(pad.clone()), None);
        }
        self.encoder_norm.forward(state)
    }

    /// The class and risk heads, from the encoder's mean over real positions.
    ///
    /// Masked mean rather than the first position: a plan's class is a
    /// property of all of its calls, and pooling from one token would make the
    /// answer depend on which call happened to be written first.
    pub fn classify(&self, memory: Tensor<B, 3>, pad: &Tensor<B, 2, Bool>) -> Prediction<B> {
        let keep = pad.clone().bool_not().float().unsqueeze_dim(2);
        let counts = keep.clone().sum_dim(1).clamp_min(1.0);
        let pooled = (memory * keep).sum_dim(1) / counts;
        let pooled: Tensor<B, 2> = pooled.squeeze_dims(&[1]);
        Prediction {
            class: self.class_head.forward(pooled.clone()),
            risk: self.risk_head.forward(pooled),
        }
    }

    /// Run the decoder over a summary prefix, answering the joint logits over
    /// the vocabulary followed by the input positions.
    ///
    /// The result is `[batch, steps, vocabulary + length]`. An index below
    /// `vocabulary` is a word; at or above it, the model is pointing at that
    /// input position, and what it has named is whatever value the slot there
    /// refers to. Positions that do not hold a slot reference are masked out,
    /// so a copy can only ever land on a lifted value.
    pub fn decode(
        &self,
        memory: Tensor<B, 3>,
        pad: &Tensor<B, 2, Bool>,
        copyable: &Tensor<B, 2, Bool>,
        prefix: Tensor<B, 2, Int>,
    ) -> Tensor<B, 3> {
        let [batch, steps] = prefix.dims();
        let device = prefix.device();
        let positions = Tensor::arange(0..span(steps), &device)
            .reshape([1, steps])
            .repeat_dim(0, batch);
        let mut state = self.tokens.forward(prefix) + self.summary_positions.forward(positions);
        let causal = causal_mask::<B>(batch, steps, &device);
        for block in &self.decoder {
            state = block.forward(
                state,
                Some(memory.clone()),
                Some(pad.clone()),
                Some(causal.clone()),
            );
        }
        let state = self.decoder_norm.forward(state);

        // Input markers and slot IDs have embeddings but are never words the
        // decoder may generate. Slots must go through the masked copy head.
        let blocked_words: Vec<bool> = (0..vocab::size())
            .map(|index| {
                !vocab::is_output_word(vocab::Token::try_from(index).unwrap_or(vocab::UNK))
            })
            .collect();
        let blocked_words = Tensor::<B, 1, Bool>::from_data(
            burn::tensor::TensorData::new(blocked_words, [vocab::size()]),
            &device,
        )
        .reshape([1, 1, vocab::size()])
        .repeat_dim(0, batch)
        .repeat_dim(1, steps);
        let words = self
            .word_head
            .forward(state.clone())
            .mask_fill(blocked_words, f64::NEG_INFINITY);
        // Copy scores: how well each decoder step matches each encoder
        // position, scaled the way attention logits are so the two halves of
        // the joint distribution stay comparable.
        let queries = self.copy_query.forward(state);
        let scale = SCALE;
        let copies = queries.matmul(memory.swap_dims(1, 2)) / scale;
        // A position holding no slot reference is not a value, so pointing at
        // it must be impossible rather than merely unlikely.
        let blocked = copyable
            .clone()
            .bool_not()
            .unsqueeze_dim::<3>(1)
            .repeat_dim(1, steps);
        let copies = copies.mask_fill(blocked, f64::NEG_INFINITY);
        Tensor::cat(vec![words, copies], 2)
    }
}

/// A sequence length as the signed extent `arange` wants.
///
/// Lengths here are bounded by `MAX_INPUT_TOKENS` and the batch shapes built
/// from it, so this is a conversion and not a narrowing; it saturates rather
/// than wrapping so a length that somehow exceeded `i64` would produce a wrong
/// shape and fail loudly instead of an empty one.
fn span(length: usize) -> i64 {
    i64::try_from(length).unwrap_or(i64::MAX)
}

/// True where a decoder position must not read a key position, which is
/// everywhere the key is later than the query.
fn causal_mask<B: Backend>(batch: usize, steps: usize, device: &B::Device) -> Tensor<B, 3, Bool> {
    let rows = Tensor::<B, 1, Int>::arange(0..span(steps), device).reshape([steps, 1]);
    let columns = Tensor::<B, 1, Int>::arange(0..span(steps), device).reshape([1, steps]);
    columns
        .repeat_dim(0, steps)
        .greater(rows.repeat_dim(1, steps))
        .unsqueeze_dim::<3>(0)
        .repeat_dim(0, batch)
}

#[cfg(test)]
#[path = "model_test.rs"]
mod tests;
