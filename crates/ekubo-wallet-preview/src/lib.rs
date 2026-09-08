//! The embedded transaction-preview model.
//!
//! A small transformer, shipped inside the binary and run on the GPU, that
//! reads the *deterministic* clear-signing interpretation of a plan's calls
//! and answers three things: which of a fixed set of categories the plan falls
//! into, how much attention it warrants, and one sentence saying what it does.
//!
//! # What this is not
//!
//! It is not part of the security kernel and nothing here decides whether a
//! transaction may be sent. The policy engine never consults it, the review
//! digest never covers it, and a preview that is wrong -- or absent, on a
//! machine with no usable GPU -- changes nothing about what gets signed. It
//! exists so an owner scanning a list of waiting requests can tell a routine
//! swap from an unlimited approval without opening each one, and so the
//! sentence they read was written for the plan in front of them rather than
//! assembled from a template.
//!
//! # Why a generated sentence is safe here
//!
//! Every value is lifted into a numbered slot before the model sees it, and
//! the model emits slot *references* which are substituted verbatim
//! afterwards. It never sees a digit and never writes one. See
//! [`slots`] for the full argument; the short version is that the class of
//! failure a language model would ordinarily be capable of on this surface --
//! a plausible sentence naming the wrong amount -- has no path from the
//! weights to the screen.
//!
//! The authoritative reading remains the deterministic field list the review
//! already renders. This sits beside it, labeled as machine-generated.

#[cfg(feature = "train")]
pub mod corpus;
pub mod model;
pub mod slots;
pub mod taxonomy;
pub mod vocab;

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
