//! The CPU-backed engine, which exists everywhere the crate compiles.
//!
//! It needs no GPU adapter or driver. Browser wallets without WebGPU,
//! headless machines, and CI can all use this backend. See the review report
//! for measured one-core latency and memory use.
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
