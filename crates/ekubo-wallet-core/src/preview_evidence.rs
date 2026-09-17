//! Read-only inputs for desktop advisory inference. No model or signing capability.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewInput {
    pub request_id: Uuid,
    pub wallet_instance_id: Uuid,
    pub plan_digest: String,
    pub calls: Vec<PreviewCall>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreviewCall {
    pub description: Option<String>,
    pub details: Vec<String>,
    pub warnings: Vec<String>,
    pub target: String,
    pub native_value: String,
    pub evidence: CallEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEvidence {
    pub chain_id: String,
    pub from: String,
    pub to: String,
    pub calldata: String,
    pub abi: Vec<AbiCandidate>,
    pub tokens: Vec<(String, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AbiCandidate {
    pub signature: String,
    pub contract_match: bool,
    pub arguments: Vec<(String, String)>,
}

/// Untrusted display text, bound to the immutable transaction it describes.
/// This is never approval evidence and grants no signing authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorySummary {
    pub request_id: Uuid,
    pub wallet_instance_id: Uuid,
    pub plan_digest: String,
    pub summary: String,
}
