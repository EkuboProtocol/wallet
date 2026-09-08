//! The wallet's handle on the embedded transaction-preview model.
//!
//! One engine for the process, built the first time a preview is asked for and
//! kept afterwards: loading the weights and standing up a GPU device are not
//! things to do once per snapshot refresh.
//!
//! # Everything here is allowed to fail
//!
//! A preview is supplemental. The review digest does not cover it, the policy
//! engine does not consult it, and the deterministic clear-signing
//! interpretation beside it remains what a reviewer is actually deciding on.
//! So every failure mode -- no weights committed, weights that do not match
//! this build, no usable GPU adapter, a panic from deep inside a graphics
//! driver -- ends the same way: no preview for that request, and a wallet that
//! works exactly as it did before this file existed.
//!
//! The panic guard is deliberate rather than defensive habit. `wgpu` reaches a
//! kernel driver, and on this machine that driver is known to take processes
//! down; the wallet must not become the kind of program that fails to list a
//! waiting request because a summary could not be written for it.

use ekubo_wallet_core::approval_summary::StepInterpretation;
use ekubo_wallet_preview::{CallSummary, PlanDocument, TransactionPreview, gpu};
use std::{
    collections::BTreeMap,
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

/// Set once the model has failed in a way that will keep failing, so a broken
/// adapter costs one attempt rather than one per refresh.
static DISABLED: AtomicBool = AtomicBool::new(false);

static ENGINE: LazyLock<Option<gpu::GpuEngine>> = LazyLock::new(|| {
    // The guard has to cover loading, not only the forward pass. Loading
    // builds tensors, building tensors resolves a `wgpu` adapter, and a
    // machine without a usable one panics there -- inside this closure, which
    // would poison the `LazyLock` and escape into the snapshot task that
    // called it. The wallet would then fail to list a waiting request because
    // it could not write a sentence about it.
    match std::panic::catch_unwind(gpu::load) {
        Ok(Ok(engine)) => Some(engine),
        Ok(Err(error)) => {
            tracing::info!("transaction previews are unavailable: {error}");
            None
        }
        Err(_) => {
            tracing::info!("no usable GPU adapter; transaction previews are off");
            None
        }
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
/// forty requests cost about what one does.
///
/// Answers an empty map when the model is unavailable, which callers should
/// render as "no preview" rather than as any particular verdict.
#[must_use]
pub fn previews(plans: Vec<(Uuid, PlanDocument)>) -> BTreeMap<Uuid, TransactionPreview> {
    if plans.is_empty() || DISABLED.load(Ordering::Relaxed) {
        return BTreeMap::new();
    }
    let Some(engine) = ENGINE.as_ref() else {
        return BTreeMap::new();
    };
    let (ids, documents): (Vec<Uuid>, Vec<PlanDocument>) = plans.into_iter().unzip();
    // A graphics driver is not part of this program's trust boundary and not
    // part of its correctness argument either. If one takes the forward pass
    // down, previews turn off and the review is unaffected.
    let computed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        engine.preview_all(&documents)
    }));
    let Ok(previews) = computed else {
        DISABLED.store(true, Ordering::Relaxed);
        tracing::warn!("the transaction-preview model panicked; previews are now off");
        return BTreeMap::new();
    };
    ids.into_iter().zip(previews).collect()
}

#[cfg(test)]
#[path = "preview_test.rs"]
mod tests;
