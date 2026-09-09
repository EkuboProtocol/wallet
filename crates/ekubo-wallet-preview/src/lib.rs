//! An embedded encoder-decoder over deterministic clear-signing interpretations.
//! Produces advisory categories, risk bands, and summaries. Copied values preserve
//! their spelling, not their semantic role: a summary can still be wrong.
//! Nothing here grants signing authority. See docs/transaction-previews.md.

#[cfg(feature = "train")]
pub mod corpus;
pub mod cpu;
#[cfg(any(feature = "gpu", feature = "webgpu"))]
pub mod gpu;
pub mod infer;
pub mod model;
pub mod slots;
pub mod taxonomy;
#[cfg(feature = "train")]
pub mod training;
pub mod vocab;
pub mod weights;

pub use slots::{CallSummary, PlanDocument};
pub use taxonomy::{RiskBand, TransactionClass};

/// What the model answered for one plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionPreview {
    /// The category, from a closed set.
    pub class: TransactionClass,
    /// How much attention the plan warrants. Advisory ordering only.
    pub risk: RiskBand,
    /// One sentence, with every value substituted verbatim from the
    /// deterministic interpretation. Empty when the decode produced nothing
    /// renderable, which callers should treat as "show the class alone".
    pub summary: String,
}

impl TransactionPreview {
    /// The answer for a plan nothing decoded: the honest one, with no forward
    /// pass behind it.
    #[must_use]
    pub fn unrecognized() -> Self {
        Self {
            class: TransactionClass::Unrecognized,
            risk: RiskBand::Critical,
            summary: String::new(),
        }
    }
}
