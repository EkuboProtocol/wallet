//! Embedded neural classification and plan-focus ranking over execution evidence.
//! Produces advisory categories, risk bands, and length-constrained card summaries.
//! Values come from labeled interpretations; incomplete or incorrect evidence can
//! still produce a wrong summary. The legacy decoder supports training evaluation.
//! Nothing here grants signing authority. See docs/transaction-previews.md.

pub mod card;
#[cfg(feature = "train")]
pub mod corpus;
pub mod cpu;
pub mod evidence;
pub mod focus;
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SummaryBasis {
    #[default]
    Interpretation,
    BalanceChanges,
    TransferLogs,
    InferredIntent,
}

/// What the model answered for one plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionPreview {
    /// Provenance belongs beside the headline, not inside its sentence.
    pub basis: SummaryBasis,
    /// The category, from a closed set.
    pub class: TransactionClass,
    /// How much attention the plan warrants. Advisory ordering only.
    pub risk: RiskBand,
    /// A complete card summary of at most 100 Unicode scalar values, grounded
    /// in the interpretation. The legacy diagnostic decoder may return empty.
    pub summary: String,
}

impl TransactionPreview {
    /// The answer for a plan nothing decoded: the honest one, with no forward
    /// pass behind it.
    #[must_use]
    pub fn unrecognized() -> Self {
        Self {
            basis: SummaryBasis::Interpretation,
            class: TransactionClass::Unrecognized,
            risk: RiskBand::Critical,
            summary: String::new(),
        }
    }
}
