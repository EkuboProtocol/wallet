//! Read-only owner balance snapshots. No request accepts these display facts
//! as token metadata, network configuration, policy inputs, or signing proof.

use ekubo_wallet_core::{
    config::{NetworkConfig, WalletMetadata},
    token_store::Portfolio,
};

/// One owner account's balances across every visible configured network.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPortfolioAccount {
    pub wallet: WalletMetadata,
    pub networks: Vec<OwnerPortfolioNetwork>,
}

/// Preserve one network's failure without hiding successful reads elsewhere.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPortfolioNetwork {
    pub network: NetworkConfig,
    pub result: std::result::Result<Portfolio, String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPortfolioSnapshot {
    pub accounts: Vec<OwnerPortfolioAccount>,
}

#[cfg(test)]
#[path = "portfolio_test.rs"]
mod tests;
