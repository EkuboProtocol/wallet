//! Bounded pieces of one immutable advisory-evidence response.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PAGE_BYTES: usize = 256 * 1024;
pub const MAX_EVIDENCE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPage {
    pub transfer_id: Uuid,
    pub offset: usize,
    pub total_bytes: usize,
    pub text: String,
}
