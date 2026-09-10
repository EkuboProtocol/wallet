//! Public account review data. Custody and native authorization stay in core.

use ekubo_wallet_core::{approval::ReviewDocument, config::WalletMetadata};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccountRemovalReview {
    pub document: ReviewDocument,
    pub wallet: WalletMetadata,
}
