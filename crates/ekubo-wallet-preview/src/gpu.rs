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
/// this build. Creating weight tensors can initialize the adapter and panic
/// if no usable device exists. The first dispatch can also fail.
pub fn load() -> Result<GpuEngine, LoadError> {
    let device = burn::backend::wgpu::WgpuDevice::default();
    let model = weights::load::<GpuBackend>(&device)?;
    Ok(PreviewEngine::new(model, device))
}

/// Load onto a GPU, resolving the adapter first.
///
/// This is the browser's entry point and the reason it is a separate function.
/// In a browser there is no synchronous way to obtain a WebGPU adapter: the
/// request is a promise, the user agent may prompt, and it may simply have no
/// adapter to hand back. So the resolution happens here, awaited, rather than
/// lazily inside the first forward pass where a caller has no way to await it
/// and no way to fall back.
///
/// # Errors
///
/// Answers [`LoadError`] when no weights are committed or they do not match
/// this build. Adapter initialization or dispatch can also fail; browser
/// callers should be prepared to use `crate::cpu` instead.
#[cfg(not(target_arch = "wasm32"))]
pub async fn load_async() -> Result<GpuEngine, LoadError> {
    let device = burn::backend::wgpu::WgpuDevice::default();
    burn::backend::wgpu::init_setup_async::<burn::backend::wgpu::graphics::AutoGraphicsApi>(
        &device,
        burn::backend::wgpu::RuntimeOptions::default(),
    )
    .await;
    let model = weights::load::<GpuBackend>(&device)?;
    Ok(PreviewEngine::new(model, device))
}

/// Browser initialization must return adapter/device errors instead of panicking
/// inside a wasm future, which can leave the JavaScript Promise unresolved.
#[cfg(target_arch = "wasm32")]
pub async fn load_async() -> Result<GpuEngine, String> {
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
        backends: wgpu::Backends::BROWSER_WEBGPU,
        ..wgpu::InstanceDescriptor::new_without_display_handle()
    });
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions::default())
        .await
        .map_err(|error| format!("WebGPU adapter unavailable: {error}"))?;
    let (device, queue) = adapter
        .request_device(&wgpu::DeviceDescriptor {
            required_features: adapter.features().difference(
                wgpu::Features::MAPPABLE_PRIMARY_BUFFERS | wgpu::Features::all_experimental_mask(),
            ),
            required_limits: adapter.limits(),
            memory_hints: wgpu::MemoryHints::MemoryUsage,
            ..Default::default()
        })
        .await
        .map_err(|error| format!("WebGPU device unavailable: {error}"))?;
    let setup = burn::backend::wgpu::WgpuSetup {
        backend: adapter.get_info().backend,
        instance,
        adapter,
        device,
        queue,
    };
    let device = burn::backend::wgpu::init_device(setup, Default::default());
    let model = weights::load::<GpuBackend>(&device).map_err(|error| error.to_string())?;
    Ok(PreviewEngine::new(model, device))
}
