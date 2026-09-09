//! Loading the committed weights.
//!
//! The weights ship inside the binary, like every clear-signing descriptor
//! does and for the same reason: a review surface must not depend on a network
//! fetch, and nothing downloaded at runtime should be able to change what a
//! reviewer reads.
//!
//! Loading is fallible and every failure is survivable. A weights file that
//! does not match this build's vocabulary or taxonomy fails here rather than
//! answering confidently from a table that means something else, and a machine
//! with no usable GPU adapter simply has no previews. In both cases the
//! deterministic interpretation is untouched -- it is what the review
//! displays, and this only ever sat beside it.

use crate::{
    model::{D_MODEL, PreviewModel},
    slots::{MAX_INPUT_TOKENS, MAX_SLOTS, MAX_SUMMARY_TOKENS},
    taxonomy::{CLASS_COUNT, RISK_COUNT},
    vocab,
};
use burn::{
    module::Module,
    record::{BinBytesRecorder, HalfPrecisionSettings, Recorder},
    tensor::backend::Backend,
};

/// What the committed weights were fitted against.
///
/// This exists because burn does not check. Loading a record whose tensors are
/// the wrong shape succeeds silently -- verified: a build whose vocabulary had
/// shrunk by two entries loaded weights sized for the old one without
/// complaint, and would then have answered confidently from an embedding table
/// where every learned word had shifted.
///
/// That is the worst available failure for this crate. A preview that is
/// missing is ordinary and handled everywhere; a preview that is fluent and
/// systematically wrong is the thing the whole design exists to prevent. So
/// the numbers a retrain would change are written down beside the weights and
/// compared here, and a disagreement refuses the load.
const FINGERPRINT: &str = include_str!("../model/preview.fingerprint");

/// The fingerprint this build expects.
///
/// Every constant that changes a tensor's shape or an index's meaning. Adding
/// one is cheap; leaving one out means a retrain that should have been forced
/// silently is not.
#[must_use]
pub fn fingerprint() -> String {
    format!(
        "vocab={} classes={CLASS_COUNT} risks={RISK_COUNT} d_model={D_MODEL} \
         slots={MAX_SLOTS} input={MAX_INPUT_TOKENS} summary={MAX_SUMMARY_TOKENS}",
        vocab::size()
    )
}

/// The trained weights, committed under `model/`.
///
/// Stored at half precision. This is a storage decision, not a compute one --
/// the record is widened to the backend's float type on load, so nothing about
/// the forward pass changes. It halves what every retrain writes into git
/// history, which for a file that is rewritten whenever the taxonomy or the
/// vocabulary moves is the cost worth minimizing.
const WEIGHTS: &[u8] = include_bytes!("../model/preview.bin");

/// Why a model could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// No weights are committed. A checkout that has not run the training
    /// pipeline is in this state, and it is not an error worth failing a
    /// build over -- the wallet runs, without previews.
    Absent,
    /// The weights exist but do not deserialize into this build's model.
    Mismatched(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => formatter.write_str("no transaction-preview weights are committed"),
            Self::Mismatched(reason) => write!(
                formatter,
                "the committed transaction-preview weights do not match this build: {reason}"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// Whether this build carries weights at all.
#[must_use]
pub fn present() -> bool {
    !WEIGHTS.is_empty()
}

/// How large the committed weights are, for the test that watches their size.
#[must_use]
pub const fn size() -> usize {
    WEIGHTS.len()
}

/// Load the committed weights onto a device.
///
/// # Errors
///
/// Answers [`LoadError::Absent`] when no weights are committed, and
/// [`LoadError::Mismatched`] when they do not deserialize into this build's
/// model -- which is what a vocabulary or taxonomy changed without retraining
/// produces.
pub fn load<B: Backend>(device: &B::Device) -> Result<PreviewModel<B>, LoadError> {
    if !present() {
        return Err(LoadError::Absent);
    }
    let expected = fingerprint();
    let committed = FINGERPRINT.trim();
    if committed != expected {
        return Err(LoadError::Mismatched(format!(
            "the weights were fitted against `{committed}` but this build is `{expected}`; \
             regenerate the corpus and retrain"
        )));
    }
    let record = BinBytesRecorder::<HalfPrecisionSettings>::default()
        .load(WEIGHTS.to_vec(), device)
        .map_err(|error| LoadError::Mismatched(error.to_string()))?;
    Ok(PreviewModel::new(device).load_record(record))
}

#[cfg(test)]
#[path = "weights_test.rs"]
mod tests;
