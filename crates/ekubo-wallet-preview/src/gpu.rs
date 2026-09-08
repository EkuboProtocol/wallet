//! The GPU-backed engine the wallet uses, so the wallet does not have to name
//! a tensor library.
//!
//! Which backend the model runs on is this crate's business. Exposing `Wgpu`
//! through the wallet's own dependency list would make every future backend
//! change a change to the wallet as well, and would put burn's types in the
//! signature of code whose job is to draw a list.
//!
//! `Wgpu` rather than a native backend because the wallet ships on macOS,
//! Windows and Linux from one source tree: Metal, Direct3D and Vulkan behind
//! one interface, and the same one GPUI already draws through.

use crate::{
    infer::PreviewEngine,
    weights::{self, LoadError},
};

/// The backend the shipped model runs on.
pub type GpuBackend = burn::backend::Wgpu;

/// A loaded, GPU-resident model.
pub type GpuEngine = PreviewEngine<GpuBackend>;

/// Load the committed weights onto the default GPU device.
///
/// # Errors
///
/// Answers [`LoadError`] when no weights are committed or they do not match
/// this build. A machine with no usable adapter does not fail here -- `wgpu`
/// resolves one lazily -- so the caller must still be prepared for the first
/// forward pass to be the thing that fails.
pub fn load() -> Result<GpuEngine, LoadError> {
    let device = burn::backend::wgpu::WgpuDevice::default();
    let model = weights::load::<GpuBackend>(&device)?;
    Ok(PreviewEngine::new(model, device))
}
