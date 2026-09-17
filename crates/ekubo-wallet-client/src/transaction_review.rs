//! Display-only transaction review frames and generation-bound owner choices.

use ekubo_wallet_core::{approval::ReviewDocument, pending::PendingTransaction};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionReviewFrame {
    pub request_id: Uuid,
    pub review_id: Uuid,
    pub frame_id: Uuid,
    pub document: ReviewDocument,
    pub simulation: crate::simulation_display::SimulationDisplay,
}

/// Intent only. Approve still requires service-side native authentication and
/// core's exact-state revalidation before any key is loaded.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionReviewChoice {
    Approve,
    Reject,
    Refresh,
    Close,
}

/// The stored row after review and attempted submission. If exact-byte sending
/// fails, the row stays signed and the existing "Send now" action can retry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedTransaction {
    pub record: PendingTransaction,
    pub send_error: Option<String>,
}
