//! The wallet's handle on the embedded transaction-preview model.
//!
//! One engine for the process, built the first time a preview is asked for and
//! kept afterwards: loading the weights is not
//! something to do once per snapshot refresh.
//!
//! # Everything here is allowed to fail
//!
//! A preview is supplemental. The review digest does not cover it, the policy
//! engine does not consult it, and the deterministic clear-signing
//! interpretation beside it remains what a reviewer is actually deciding on.
//! Weight errors or inference failures disable previews. Desktop inference
//! uses CPU for fast startup and predictable memory on modest devices.
//! Review controls do not wait for inference.
//!
//! The panic guard handles Rust unwinding, including adapter initialization
//! failures. It cannot catch a process signal, abort, or kernel-driver fault.

use ekubo_wallet_core::approval_summary::StepInterpretation;
use ekubo_wallet_preview::{CallSummary, PlanDocument, TransactionPreview, cpu};
use std::{
    collections::BTreeMap,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

type PreviewCache = BTreeMap<Uuid, (PlanDocument, TransactionPreview)>;
static CACHE: Mutex<PreviewCache> = Mutex::new(BTreeMap::new());

/// Avoid retrying an inference failure on every refresh.
static DISABLED: AtomicBool = AtomicBool::new(false);

static ENGINE: LazyLock<Option<cpu::CpuEngine>> =
    LazyLock::new(|| match std::panic::catch_unwind(cpu::load) {
        Ok(Ok(engine)) => Some(engine),
        Ok(Err(error)) => {
            tracing::info!("transaction previews are unavailable: {error}");
            None
        }
        Err(_) => {
            tracing::warn!("transaction preview initialization panicked; previews are off");
            None
        }
    });

/// One call as the model reads it, from the interpretation the review already
/// holds.
///
/// Nothing is decoded twice and nothing new is fetched: this is a restatement
/// of `StepInterpretation`, which the caller computed for the review itself.
#[must_use]
pub fn call_summary(
    interpretation: &StepInterpretation,
    target: String,
    native_value: String,
) -> CallSummary {
    CallSummary {
        description: interpretation.description.clone(),
        details: interpretation.details.clone(),
        warnings: interpretation.warnings.clone(),
        target,
        native_value,
    }
}

/// Previews for a batch of waiting requests.
///
/// Batched on purpose. The review list asks about every waiting request in one
/// go, and the decode loop is sequential in summary tokens but not in plans --
/// dispatches contain at most eight requests to bound tensor memory.
///
/// Answers an empty map when the model is unavailable, which callers should
/// render as "no preview" rather than as any particular verdict.
#[must_use]
pub fn previews(plans: Vec<(Uuid, PlanDocument)>) -> BTreeMap<Uuid, TransactionPreview> {
    if plans.is_empty() {
        CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        return BTreeMap::new();
    }
    if DISABLED.load(Ordering::Relaxed) {
        return BTreeMap::new();
    }
    let Some(engine) = ENGINE.as_ref() else {
        return BTreeMap::new();
    };
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let computed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cached_previews(plans, &mut cache, |documents| {
            futures::executor::block_on(engine.preview_all_async(documents))
        })
    }));
    match computed {
        Ok(Ok(previews)) => previews,
        Ok(Err(error)) => {
            tracing::warn!("transaction previews failed: {error}");
            DISABLED.store(true, Ordering::Relaxed);
            BTreeMap::new()
        }
        Err(_) => {
            DISABLED.store(true, Ordering::Relaxed);
            tracing::warn!("the transaction-preview model panicked; previews are now off");
            BTreeMap::new()
        }
    }
}

/// Cache the full interpreted input, including token labels and warnings.
/// A request ID alone is insufficient: the same request can gain new metadata.
fn cached_previews(
    plans: Vec<(Uuid, PlanDocument)>,
    cache: &mut PreviewCache,
    infer: impl FnOnce(&[PlanDocument]) -> Result<Vec<TransactionPreview>, String>,
) -> Result<BTreeMap<Uuid, TransactionPreview>, String> {
    let active: std::collections::BTreeSet<_> = plans.iter().map(|(id, _)| *id).collect();
    cache.retain(|id, _| active.contains(id));
    let (ids, documents): (Vec<_>, Vec<_>) = plans
        .into_iter()
        .filter(|(id, document)| {
            cache
                .get(id)
                .is_none_or(|(previous, _)| previous != document)
        })
        .unzip();
    if !documents.is_empty() {
        let previews = infer(&documents)?;
        if previews.len() != documents.len() {
            return Err("incomplete preview batch".into());
        }
        for ((id, document), preview) in ids.into_iter().zip(documents).zip(previews) {
            cache.insert(id, (document, preview));
        }
    }
    Ok(cache
        .iter()
        .map(|(id, (_, preview))| (*id, preview.clone()))
        .collect())
}

#[cfg(test)]
#[path = "preview_test.rs"]
mod tests;
