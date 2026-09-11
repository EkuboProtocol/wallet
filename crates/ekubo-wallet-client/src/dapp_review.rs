//! Display data for a service-owned dapp review. No authorization proof or
//! mutable session scope crosses this boundary.

use ekubo_wallet_core::{approval::ReviewDocument, config::WalletMetadata};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DappReview {
    pub session_id: Uuid,
    pub unselected_document: ReviewDocument,
    pub choices: Vec<DappChoice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DappChoice {
    pub account: WalletMetadata,
    pub document: ReviewDocument,
}
