//! Browser bindings for the transaction-preview model.
//!
//! The point of this crate is that a browser wallet is the place where an
//! opaque `eth_sendTransaction` most often reaches a person, and where the
//! deterministic clear-signing interpretation is least likely to already be on
//! screen. Publishing the model as a `.wasm` with a small JS surface means any
//! wallet can render the same category, risk band and sentence the desktop
//! wallet does, from the same weights, without a server.
//!
//! # Nothing here changes what the model may say
//!
//! Every guarantee the Rust crate makes holds unchanged in the browser,
//! because this is a binding and not a reimplementation. Values are still
//! lifted into slots before tokenization, the decoder still emits copy
//! references rather than digits, the class and risk answers are still indices
//! into closed enums, and the rendered summary is still checked against the
//! plan's own values before it is returned. A browser wallet that shows this
//! output is subject to the same argument as the desktop one: the preview is
//! supplemental, and the authoritative reading is the decoded field list beside
//! it.
//!
//! # Two backends
//!
//! WebGPU builds offer `initWebGpu` and `initCpu`; CPU-only builds expose
//! `initCpu`. Both inference APIs return Promises. Feature-detect the GPU
//! initializer and fall back to CPU when adapter initialization fails.

use ekubo_wallet_preview::{
    CallSummary, PlanDocument, TransactionPreview, cpu, weights::LoadError,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// One call of a plan, as a wallet hands it over.
///
/// A browser wallet supplies its decoded reading and may attach raw execution
/// evidence plus ABI candidates. The encoder reads a compact projection;
/// displayed values are grounded in labeled interpretation fields.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Call {
    /// The one-line reading, absent when nothing decoded the call.
    #[serde(default)]
    pub description: Option<String>,
    /// Labeled field lines from the interpretation.
    #[serde(default)]
    pub details: Vec<String>,
    /// Warnings the interpretation attached.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The call's target, already labeled.
    #[serde(default)]
    pub target: String,
    /// The call's native value, already rendered with its currency.
    #[serde(default)]
    pub native_value: String,
    #[serde(default)]
    pub evidence: Option<ekubo_wallet_preview::slots::CallEvidence>,
}

impl From<Call> for CallSummary {
    fn from(call: Call) -> Self {
        Self {
            description: call.description,
            details: call.details,
            warnings: call.warnings,
            target: call.target,
            native_value: call.native_value,
            evidence: call.evidence,
        }
    }
}

/// What the model answered, as JS receives it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    /// The category, from a closed set. Render it as a chip.
    pub class: String,
    /// How much attention the plan warrants: `routine`, `caution`, or
    /// `critical`. Advisory ordering only -- this is not a policy verdict and
    /// must not gate anything.
    pub risk: String,
    /// One sentence. Empty when the model produced nothing renderable, which
    /// callers should show as the class alone rather than as an error.
    pub summary: String,
}

impl From<TransactionPreview> for Preview {
    fn from(preview: TransactionPreview) -> Self {
        Self {
            class: preview.class.corpus_name().to_owned(),
            risk: preview.risk.corpus_name().to_owned(),
            summary: preview.summary,
        }
    }
}

/// A loaded model.
#[wasm_bindgen]
pub struct Previewer {
    engine: Backend,
}

// Boxed because the two engines differ by kilobytes and this enum is stored,
// not passed: an unboxed variant would make every `Previewer` as large as the
// biggest backend whichever one it holds.
enum Backend {
    Cpu(Box<cpu::CpuEngine>),
    #[cfg(feature = "webgpu")]
    WebGpu(Box<ekubo_wallet_preview::gpu::GpuEngine>),
}

#[wasm_bindgen]
impl Previewer {
    /// Load the model onto the CPU.
    ///
    /// Always available, needs no adapter, and is the sensible fallback when
    /// `initWebGpu` rejects.
    ///
    /// # Errors
    ///
    /// Rejects when the weights do not match this build, which can only happen
    /// if the `.wasm` and the weights were built from different sources.
    #[wasm_bindgen(js_name = initCpu)]
    pub fn init_cpu() -> Result<Self, JsError> {
        Ok(Self {
            engine: Backend::Cpu(Box::new(cpu::load().map_err(|error| describe(&error))?)),
        })
    }

    /// Load the model onto WebGPU.
    ///
    /// Asynchronous because requesting an adapter is: the browser may prompt,
    /// may take a moment, or may have no adapter to give. A wallet should
    /// await this and fall back to [`Self::init_cpu`] on rejection rather than
    /// surfacing an error, because "this browser has no WebGPU" is an ordinary
    /// state and not a fault.
    ///
    /// # Errors
    ///
    /// Rejects when no adapter is available or the weights do not match.
    #[cfg(feature = "webgpu")]
    #[wasm_bindgen(js_name = initWebGpu)]
    pub async fn init_web_gpu() -> Result<Previewer, JsError> {
        // Adapter resolution is awaited inside the preview crate, which is
        // where the backend lives; this binding only decides what to do when
        // it does not work out.
        let engine = ekubo_wallet_preview::gpu::load_async()
            .await
            .map_err(|error| JsError::new(&error.to_string()))?;
        Ok(Self {
            engine: Backend::WebGpu(Box::new(engine)),
        })
    }

    /// Whether this instance is running on the GPU.
    #[wasm_bindgen(getter, js_name = usingWebGpu)]
    #[must_use]
    pub fn using_web_gpu(&self) -> bool {
        match &self.engine {
            Backend::Cpu(_) => false,
            #[cfg(feature = "webgpu")]
            Backend::WebGpu(_) => true,
        }
    }

    /// Preview one plan, given its decoded calls.
    ///
    /// # Errors
    ///
    /// Rejects when the argument is not an array of calls.
    pub async fn preview(&self, calls: JsValue) -> Result<JsValue, JsError> {
        let document = document_of(calls)?;
        let preview = match &self.engine {
            Backend::Cpu(engine) => engine
                .card_all_async(&[document])
                .await
                .map_err(|e| JsError::new(&e))?
                .remove(0),
            #[cfg(feature = "webgpu")]
            Backend::WebGpu(engine) => engine
                .card_all_async(&[document])
                .await
                .map_err(|e| JsError::new(&e))?
                .remove(0),
        };
        serde_wasm_bindgen::to_value(&Preview::from(preview)).map_err(JsError::from)
    }

    /// Preview several plans in one pass.
    ///
    /// Identical call readings share encoder work across plans. Each plan keeps
    /// an independent neural-work budget; card rendering is not autoregressive.
    ///
    /// # Errors
    ///
    /// Rejects when the argument is not an array of plans.
    #[wasm_bindgen(js_name = previewAll)]
    pub async fn preview_all(&self, plans: JsValue) -> Result<JsValue, JsError> {
        let plans: Vec<Vec<Call>> = serde_wasm_bindgen::from_value(plans)?;
        let documents: Vec<PlanDocument> = plans
            .into_iter()
            .map(|calls| PlanDocument {
                calls: calls.into_iter().map(CallSummary::from).collect(),
            })
            .collect();
        let previews = match &self.engine {
            Backend::Cpu(engine) => engine
                .card_all_async(&documents)
                .await
                .map_err(|e| JsError::new(&e))?,
            #[cfg(feature = "webgpu")]
            Backend::WebGpu(engine) => engine
                .card_all_async(&documents)
                .await
                .map_err(|e| JsError::new(&e))?,
        };
        let answered: Vec<Preview> = previews.into_iter().map(Preview::from).collect();
        serde_wasm_bindgen::to_value(&answered).map_err(JsError::from)
    }
}

fn document_of(calls: JsValue) -> Result<PlanDocument, JsError> {
    let calls: Vec<Call> = serde_wasm_bindgen::from_value(calls)?;
    Ok(PlanDocument {
        calls: calls.into_iter().map(CallSummary::from).collect(),
    })
}

fn describe(error: &LoadError) -> JsError {
    JsError::new(&error.to_string())
}

/// How large the embedded weights are, so a wallet can report what it shipped.
#[wasm_bindgen(js_name = weightsByteLength)]
#[must_use]
pub fn weights_byte_length() -> usize {
    ekubo_wallet_preview::weights::size()
}
