//! The CPU-backed engine, which exists everywhere the crate compiles.
//!
//! This is not only a fallback. For a 1.2M-parameter model over a forty-token
//! sequence the arithmetic is small enough that a CPU forward pass is a few
//! milliseconds, and it is the only backend that needs no adapter, no driver
//! and no feature detection. A browser wallet without WebGPU, a headless
//! machine, and a CI runner all land here and all work.
//!
//! It is also what the tests use, which is deliberate: the shapes and the
//! decode loop are checked on a backend that is available on every machine
//! the repository is built on, rather than only where hardware happens to
//! cooperate.

use crate::{
    infer::PreviewEngine,
    weights::{self, LoadError},
};

/// The backend that is always available.
pub type CpuBackend = burn::backend::NdArray;

/// A loaded model running on the CPU.
pub type CpuEngine = PreviewEngine<CpuBackend>;

/// Load the committed weights onto the CPU.
///
/// # Errors
///
/// Answers [`LoadError`] when no weights are committed or they do not match
/// this build. Unlike the GPU path this cannot fail for want of hardware, so
/// an error here is always about the weights themselves.
pub fn load() -> Result<CpuEngine, LoadError> {
    let device = burn::backend::ndarray::NdArrayDevice::default();
    let model = weights::load::<CpuBackend>(&device)?;
    Ok(PreviewEngine::new(model, device))
}
