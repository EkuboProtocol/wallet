//! Owner activity and review inventory. These records describe stored state;
//! their fields are never accepted as authorization or authoritative updates.

use chrono::{DateTime, Utc};
use ekubo_wallet_core::approval::ReviewDocument;
use ekubo_wallet_core::{
    config::NetworkConfig, message::PendingMessage, pending::PendingTransaction,
    policy_store::PolicyProposal, token_store::TokenProposal, typed_data::PendingTypedData,
};
use uuid::Uuid;

/// Ordered read selectors for owner activity. These are not signing inputs or
/// authorization; the service always reloads the corresponding stored record.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(
    tag = "kind",
    content = "request_id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OwnerActivityReference {
    Transaction(Uuid),
    Message(Uuid),
    TypedData(Uuid),
}

/// One durable owner-visible activity record. Signature requests remain in
/// the audit trail after approval or rejection just like transactions do.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum OwnerActivityRecord {
    Transaction(Box<PendingTransaction>),
    Message(PendingMessage),
    TypedData(PendingTypedData),
}

impl OwnerActivityRecord {
    #[must_use]
    pub const fn reference(&self) -> OwnerActivityReference {
        match self {
            Self::Transaction(record) => OwnerActivityReference::Transaction(record.request_id),
            Self::Message(record) => OwnerActivityReference::Message(record.request_id),
            Self::TypedData(record) => OwnerActivityReference::TypedData(record.request_id),
        }
    }

    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        match self {
            Self::Transaction(record) => record.request_id,
            Self::Message(record) => record.request_id,
            Self::TypedData(record) => record.request_id,
        }
    }

    #[must_use]
    pub fn created_at(&self) -> DateTime<Utc> {
        match self {
            Self::Transaction(record) => record.created_at,
            Self::Message(record) => record.created_at,
            Self::TypedData(record) => record.created_at,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OwnerReviewQueues {
    pub transactions: Vec<PendingTransaction>,
    pub typed_data: Vec<PendingTypedData>,
    pub messages: Vec<PendingMessage>,
    pub policy_proposals: Vec<PolicyProposal>,
    pub network_proposals: Vec<NetworkConfig>,
    pub token_proposals: Vec<TokenProposal>,
}

/// A human-readable, read-only inspection of one transaction lifecycle row.
///
/// The document is authored from the encrypted execution plan, owner-confirmed
/// token metadata, and (when available) the mined receipt. Receipt lookups
/// grant no capability. The lookup may refresh the stored lifecycle status.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OwnerTransactionInspection {
    pub document: ReviewDocument,
    pub receipt_loaded: bool,
    pub receipt_error: Option<String>,
}

/// Display-only result of an owner transaction action. Never accepted as input
/// to submission or reconciliation; observation provenance stays in core.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerTransactionAction {
    pub record: PendingTransaction,
    pub broadcast: Option<BroadcastDisplay>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BroadcastDisplay {
    pub transaction_hash: String,
    pub receipt_status: ReceiptDisplayStatus,
    pub block_number: Option<String>,
    pub mined_fee: Option<ekubo_wallet_core::rpc::MinedFee>,
    pub broadcast_error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDisplayStatus {
    Success,
    Reverted,
    Pending,
}

impl From<ekubo_wallet_core::execution::BroadcastResult> for BroadcastDisplay {
    fn from(result: ekubo_wallet_core::execution::BroadcastResult) -> Self {
        use ekubo_wallet_core::execution::ReceiptStatus;
        Self {
            transaction_hash: result.transaction_hash,
            receipt_status: match result.receipt_status {
                ReceiptStatus::Success => ReceiptDisplayStatus::Success,
                ReceiptStatus::Reverted => ReceiptDisplayStatus::Reverted,
                ReceiptStatus::Pending => ReceiptDisplayStatus::Pending,
            },
            block_number: result.block_number,
            mined_fee: result.mined_fee,
            broadcast_error: result.broadcast_error,
        }
    }
}

#[cfg(test)]
#[path = "activity_test.rs"]
mod tests;
