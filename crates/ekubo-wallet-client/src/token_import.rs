//! Token-list review results shared with the desktop. Contains no authority.

use ekubo_wallet_core::token_store::{ProposalSummary, TokenProposal};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OwnerTokenListImport {
    pub source: String,
    pub host: String,
    pub declared_version: Option<String>,
    pub declared_timestamp: Option<String>,
    pub chains_selected: Vec<u64>,
    pub skipped_non_evm: usize,
    pub skipped_other_chain: usize,
    pub summary: ProposalSummary,
    pub proposals: Vec<TokenProposal>,
}
