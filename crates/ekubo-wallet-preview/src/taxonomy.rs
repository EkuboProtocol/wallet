//! The closed sets the model is allowed to answer from.
//!
//! A class and a risk band are *labels*, not text: the model selects an index
//! into a fixed enum, so no forward pass can invent a category that the review
//! surface has not been written to display. Widening either enum is a
//! deliberate edit here, and the vocabulary and the trained head have to be
//! regenerated to match — [`CLASS_COUNT`] and [`RISK_COUNT`] are what the
//! output heads are sized from.

use core::fmt;

/// What a plan is doing, as one of a fixed set of readings.
///
/// The variants are ordered, and the order is load-bearing: it is the index
/// the classification head emits. Append new variants at the end, before
/// [`TransactionClass::Unrecognized`] is *not* an option — `Unrecognized`
/// stays last so a model trained before a widening still maps its indices to
/// the same meanings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransactionClass {
    Swap,
    Approval,
    Revocation,
    Transfer,
    Bridge,
    Supply,
    Borrow,
    Repay,
    Withdraw,
    Stake,
    Unstake,
    Claim,
    LiquidityAdd,
    LiquidityRemove,
    Governance,
    Nft,
    WrapUnwrap,
    Delegation,
    Batch,
    /// Nothing in the plan matched a descriptor or a standard call. This is
    /// the honest answer, not a failure: the review still shows the exact
    /// calldata, and a confident label over calldata nobody decoded would be
    /// worse than none.
    Unrecognized,
}

/// Every class, in head-index order.
pub const CLASSES: [TransactionClass; 20] = [
    TransactionClass::Swap,
    TransactionClass::Approval,
    TransactionClass::Revocation,
    TransactionClass::Transfer,
    TransactionClass::Bridge,
    TransactionClass::Supply,
    TransactionClass::Borrow,
    TransactionClass::Repay,
    TransactionClass::Withdraw,
    TransactionClass::Stake,
    TransactionClass::Unstake,
    TransactionClass::Claim,
    TransactionClass::LiquidityAdd,
    TransactionClass::LiquidityRemove,
    TransactionClass::Governance,
    TransactionClass::Nft,
    TransactionClass::WrapUnwrap,
    TransactionClass::Delegation,
    TransactionClass::Batch,
    TransactionClass::Unrecognized,
];

/// How many classes the head emits.
pub const CLASS_COUNT: usize = CLASSES.len();

impl TransactionClass {
    /// The head index for this class.
    #[must_use]
    pub fn index(self) -> usize {
        CLASSES
            .iter()
            .position(|class| *class == self)
            .unwrap_or(CLASS_COUNT - 1)
    }

    /// The class at a head index, or [`TransactionClass::Unrecognized`] for an
    /// index outside the enum. Out of range is not reachable from a correctly
    /// sized head, but this is the boundary where a stale weights file would
    /// arrive, so it saturates rather than panicking.
    #[must_use]
    pub fn from_index(index: usize) -> Self {
        CLASSES.get(index).copied().unwrap_or(Self::Unrecognized)
    }

    /// The label as the review surface prints it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Swap => "Swap",
            Self::Approval => "Approval",
            Self::Revocation => "Revocation",
            Self::Transfer => "Transfer",
            Self::Bridge => "Bridge",
            Self::Supply => "Supply",
            Self::Borrow => "Borrow",
            Self::Repay => "Repay",
            Self::Withdraw => "Withdraw",
            Self::Stake => "Stake",
            Self::Unstake => "Unstake",
            Self::Claim => "Claim",
            Self::LiquidityAdd => "Add liquidity",
            Self::LiquidityRemove => "Remove liquidity",
            Self::Governance => "Governance",
            Self::Nft => "NFT",
            Self::WrapUnwrap => "Wrap",
            Self::Delegation => "Delegation",
            Self::Batch => "Batch",
            Self::Unrecognized => "Unrecognized",
        }
    }

    /// The name used in the training corpus and in fixtures. Distinct from
    /// [`Self::label`] so retitling a chip in the UI cannot silently
    /// invalidate every committed label.
    #[must_use]
    pub const fn corpus_name(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Approval => "approval",
            Self::Revocation => "revocation",
            Self::Transfer => "transfer",
            Self::Bridge => "bridge",
            Self::Supply => "supply",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::Withdraw => "withdraw",
            Self::Stake => "stake",
            Self::Unstake => "unstake",
            Self::Claim => "claim",
            Self::LiquidityAdd => "liquidity_add",
            Self::LiquidityRemove => "liquidity_remove",
            Self::Governance => "governance",
            Self::Nft => "nft",
            Self::WrapUnwrap => "wrap_unwrap",
            Self::Delegation => "delegation",
            Self::Batch => "batch",
            Self::Unrecognized => "unrecognized",
        }
    }

    /// Parse a corpus name. Unknown names answer `None` so corpus validation
    /// rejects a label the enum does not have, rather than silently folding it
    /// into `Unrecognized` and training the model to agree.
    #[must_use]
    pub fn from_corpus_name(name: &str) -> Option<Self> {
        CLASSES
            .iter()
            .copied()
            .find(|class| class.corpus_name() == name)
    }
}

impl fmt::Display for TransactionClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// How much of the owner's attention the plan warrants.
///
/// This is advisory ordering for the review list, not a policy verdict:
/// nothing here decides whether a transaction may be sent. The policy engine
/// does that, and it never consults this model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskBand {
    /// Bounded and self-directed: the plan moves the owner's own assets by an
    /// amount the calldata fixes.
    Routine,
    /// Hands spending power or assets to another party, in a bounded amount.
    Caution,
    /// Unbounded authority: an unlimited allowance, an operator over a whole
    /// collection, an authority delegation, or value sent to a target nothing
    /// decoded.
    Critical,
}

/// Every risk band, in head-index order.
pub const RISKS: [RiskBand; 3] = [RiskBand::Routine, RiskBand::Caution, RiskBand::Critical];

/// How many risk bands the head emits.
pub const RISK_COUNT: usize = RISKS.len();

impl RiskBand {
    /// The head index for this band.
    #[must_use]
    pub fn index(self) -> usize {
        RISKS.iter().position(|risk| *risk == self).unwrap_or(0)
    }

    /// The band at a head index. An index outside the enum saturates to
    /// [`RiskBand::Critical`]: if the weights and this enum ever disagree, the
    /// safe reading of an unknown answer is the one that asks for more
    /// attention, not less.
    #[must_use]
    pub fn from_index(index: usize) -> Self {
        RISKS.get(index).copied().unwrap_or(Self::Critical)
    }

    /// The label as the review surface prints it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Routine => "Routine",
            Self::Caution => "Caution",
            Self::Critical => "Needs care",
        }
    }

    /// The name used in the training corpus.
    #[must_use]
    pub const fn corpus_name(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::Caution => "caution",
            Self::Critical => "critical",
        }
    }

    /// Parse a corpus name, answering `None` for one this enum does not have.
    #[must_use]
    pub fn from_corpus_name(name: &str) -> Option<Self> {
        RISKS
            .iter()
            .copied()
            .find(|risk| risk.corpus_name() == name)
    }
}

impl fmt::Display for RiskBand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[cfg(test)]
#[path = "taxonomy_test.rs"]
mod tests;
