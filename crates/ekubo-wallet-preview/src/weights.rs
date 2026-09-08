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

use crate::model::PreviewModel;
use burn::{
    module::Module,
    record::{BinBytesRecorder, FullPrecisionSettings, Recorder},
    tensor::backend::Backend,
};

/// The trained weights, committed under `model/`.
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
    let record = BinBytesRecorder::<FullPrecisionSettings>::default()
        .load(WEIGHTS.to_vec(), device)
        .map_err(|error| LoadError::Mismatched(error.to_string()))?;
    Ok(PreviewModel::new(device).load_record(record))
}

#[cfg(test)]
#[path = "weights_test.rs"]
mod tests;
