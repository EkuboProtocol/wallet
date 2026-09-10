//! Owner activity and review inventory. These records describe stored state;
//! their fields are never accepted as authorization or authoritative updates.

use chrono::{DateTime, Utc};
use ekubo_wallet_core::approval::ReviewDocument;
use ekubo_wallet_core::{
    config::NetworkConfig, message::PendingMessage, pending::PendingTransaction,
    policy_store::PolicyProposal, token_store::TokenProposal, typed_data::PendingTypedData,
};
use uuid::Uuid;

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
