use crate::{
    config::{NetworkConfig, WalletMetadata},
    fork::{ForkContext, ForkPreface, native_balance},
    simulation::CANONICAL_CALIBUR,
};
use alloy::{
    eips::BlockId,
    primitives::{Address, B256, Bytes},
    providers::{Provider, ProviderBuilder},
};
use anyhow::{Context, Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::Duration;

const RPC_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct WalletStatus {
    pub wallet_id: String,
    pub address: String,
    pub network: String,
    pub chain_id: String,
    pub native_balance: String,
    pub transaction_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_implementation: Option<String>,
    /// Present only when this status was read on a temporary simulation fork.
    /// Its presence means the native balance is hypothetical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkContext>,
    /// Set on a fork: the nonce is read from the pinned parent block, because
    /// `eth_simulateV1` runs without transaction validation and so never
    /// advances it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_count_is_pinned_parent: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptStatus {
    pub succeeded: bool,
    pub block_number: u64,
    /// What the transaction actually cost. Carried on every receipt lookup
    /// because the receipt already contains it: the price a transaction paid
    /// is otherwise unrecoverable after the fact, and `eth_gasPrice`-style
    /// reads through a public RPC are not a dependable substitute.
    pub gas_used: u64,
    pub effective_gas_price: u128,
}

/// What a mined transaction actually cost, decimal-encoded for JSON.
///
/// Reported on every settled record so the price a transaction paid never has
/// to be reconstructed from balance deltas, and so a caller deciding whether
/// gas is currently cheap has a real number from this wallet's own recent
/// history rather than an onchain read that a public RPC may answer with a
/// plausible zero.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct MinedFee {
    /// Gas units the receipt reports as burned.
    pub gas_used: String,
    /// Wei per gas the chain actually charged.
    pub effective_gas_price: String,
    /// `gas_used` × `effective_gas_price`, in wei.
    pub transaction_fee_wei: String,
}

impl ReceiptStatus {
    /// Gas actually burned times the price actually paid.
    #[must_use]
    pub fn mined_fee(&self) -> MinedFee {
        MinedFee {
            gas_used: self.gas_used.to_string(),
            effective_gas_price: self.effective_gas_price.to_string(),
            transaction_fee_wei: u128::from(self.gas_used)
                .saturating_mul(self.effective_gas_price)
                .to_string(),
        }
    }
}

pub async fn verify_chain_id(network: &NetworkConfig) -> Result<()> {
    let observed = with_timeout(network, async {
        ProviderBuilder::new()
            .connect_http(network.rpc_url.clone())
            .get_chain_id()
            .await
    })
    .await?;
    ensure!(
        observed == network.chain_id,
        "RPC reports chain {observed}, not {}",
        network.chain_id
    );
    Ok(())
}

pub async fn wallet_status(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    fork: Option<&ForkPreface>,
) -> Result<WalletStatus> {
    if let Some(preface) = fork {
        return fork_wallet_status(wallet, network, preface).await;
    }
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let (chain_id, balance, transaction_count, code) = tokio::try_join!(
        timeout_call(network, provider.get_chain_id()),
        timeout_call(network, async {
            provider.get_balance(wallet.address).await
        }),
        timeout_call(network, async {
            provider.get_transaction_count(wallet.address).await
        }),
        timeout_call(network, async {
            provider.get_code_at(wallet.address).await
        }),
    )?;
    ensure!(
        chain_id == network.chain_id,
        "RPC reports chain {chain_id}, not {}",
        network.chain_id
    );
    Ok(WalletStatus {
        wallet_id: wallet.id.clone(),
        address: format!("{:#x}", wallet.address),
        network: network.name.clone(),
        chain_id: chain_id.to_string(),
        native_balance: balance.to_string(),
        transaction_count,
        delegated_implementation: delegated_implementation(&code)
            .map(|address| format!("{address:#x}")),
        fork: None,
        transaction_count_is_pinned_parent: None,
    })
}

/// Wallet status as a fork sees it.
///
/// The native balance is read through the fork, so it reflects every applied
/// plan. The nonce cannot be: `eth_simulateV1` runs with validation disabled
/// and never advances it, so the pinned parent's count is reported and
/// flagged as such. The delegation is decided by the fork itself — replaying
/// any atomic batch installs the canonical Calibur designator, which is
/// exactly what submitting that plan would do on chain.
async fn fork_wallet_status(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    preface: &ForkPreface,
) -> Result<WalletStatus> {
    ensure!(
        preface.wallet == wallet.address,
        "fork belongs to a different wallet"
    );
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let pinned = BlockId::number(preface.parent.number);
    let (chain_id, transaction_count, code) = tokio::try_join!(
        timeout_call(network, provider.get_chain_id()),
        timeout_call(network, async {
            provider
                .get_transaction_count(wallet.address)
                .block_id(pinned)
                .await
        }),
        timeout_call(network, async {
            provider.get_code_at(wallet.address).block_id(pinned).await
        }),
    )?;
    ensure!(
        chain_id == network.chain_id,
        "RPC reports chain {chain_id}, not {}",
        network.chain_id
    );
    let (balance, _) = native_balance(network, preface, wallet.address).await?;
    let delegated = if preface.requires_calibur() {
        Some(format!("{CANONICAL_CALIBUR:#x}"))
    } else {
        delegated_implementation(&code).map(|address| format!("{address:#x}"))
    };
    Ok(WalletStatus {
        wallet_id: wallet.id.clone(),
        address: format!("{:#x}", wallet.address),
        network: network.name.clone(),
        chain_id: chain_id.to_string(),
        native_balance: balance.to_string(),
        transaction_count,
        delegated_implementation: delegated,
        fork: None,
        transaction_count_is_pinned_parent: Some(true),
    })
}

pub async fn transaction_receipt(
    network: &NetworkConfig,
    transaction_hash: &str,
) -> Result<Option<ReceiptStatus>> {
    let hash = B256::from_str(transaction_hash).context("invalid transaction hash")?;
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let (chain_id, receipt) = tokio::try_join!(
        timeout_call(network, provider.get_chain_id()),
        timeout_call(network, provider.get_transaction_receipt(hash)),
    )?;
    ensure!(
        chain_id == network.chain_id,
        "RPC reports chain {chain_id}, not {}",
        network.chain_id
    );
    receipt
        .map(|receipt| {
            Ok(ReceiptStatus {
                succeeded: receipt.status(),
                block_number: receipt
                    .block_number
                    .context("RPC returned a receipt without a block number")?,
                gas_used: receipt.gas_used,
                effective_gas_price: receipt.effective_gas_price,
            })
        })
        .transpose()
}

/// One receipt log, reduced to the fields transfer decoding needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

/// A mined receipt with the details the human transaction view renders.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptDetails {
    pub succeeded: bool,
    pub block_number: u64,
    pub gas_used: u64,
    pub effective_gas_price: u128,
    pub logs: Vec<ReceiptLog>,
}

/// Fetch the complete receipt for display: status, fee fields, and logs.
pub async fn transaction_receipt_details(
    network: &NetworkConfig,
    transaction_hash: &str,
) -> Result<Option<ReceiptDetails>> {
    let hash = B256::from_str(transaction_hash).context("invalid transaction hash")?;
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let (chain_id, receipt) = tokio::try_join!(
        timeout_call(network, provider.get_chain_id()),
        timeout_call(network, provider.get_transaction_receipt(hash)),
    )?;
    ensure!(
        chain_id == network.chain_id,
        "RPC reports chain {chain_id}, not {}",
        network.chain_id
    );
    receipt
        .map(|receipt| {
            Ok(ReceiptDetails {
                succeeded: receipt.status(),
                block_number: receipt
                    .block_number
                    .context("RPC returned a receipt without a block number")?,
                gas_used: receipt.gas_used,
                effective_gas_price: receipt.effective_gas_price,
                logs: receipt
                    .inner
                    .logs()
                    .iter()
                    .map(|log| ReceiptLog {
                        address: log.address(),
                        topics: log.topics().to_vec(),
                        data: log.data().data.to_vec(),
                    })
                    .collect(),
            })
        })
        .transpose()
}

/// The chain head height, used to count confirmations for a mined receipt.
pub async fn latest_block_number(network: &NetworkConfig) -> Result<u64> {
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let (chain_id, block_number) = tokio::try_join!(
        timeout_call(network, provider.get_chain_id()),
        timeout_call(network, provider.get_block_number()),
    )?;
    ensure!(
        chain_id == network.chain_id,
        "RPC reports chain {chain_id}, not {}",
        network.chain_id
    );
    Ok(block_number)
}

/// The account's mined transaction count (the `latest` tag): the next nonce
/// the chain itself has settled. Deliberately not the `pending` view —
/// replacement detection must only trust nonces consumed by mined blocks,
/// because a competing mempool transaction at the same nonce has not won yet.
pub async fn mined_transaction_count(network: &NetworkConfig, address: Address) -> Result<u64> {
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let (chain_id, count) = tokio::try_join!(
        timeout_call(network, provider.get_chain_id()),
        timeout_call(network, async {
            provider.get_transaction_count(address).latest().await
        }),
    )?;
    ensure!(
        chain_id == network.chain_id,
        "RPC reports chain {chain_id}, not {}",
        network.chain_id
    );
    Ok(count)
}

/// Return whether the configured RPC already knows the exact transaction
/// hash. This is used only to recover a persisted submission lease; callers
/// must still rebroadcast the already-signed bytes rather than prepare a new
/// transaction when the hash is unknown.
pub async fn transaction_known(network: &NetworkConfig, transaction_hash: &str) -> Result<bool> {
    let hash = B256::from_str(transaction_hash).context("invalid transaction hash")?;
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let (chain_id, transaction) = tokio::try_join!(
        timeout_call(network, provider.get_chain_id()),
        timeout_call(network, provider.get_transaction_by_hash(hash)),
    )?;
    ensure!(
        chain_id == network.chain_id,
        "RPC reports chain {chain_id}, not {}",
        network.chain_id
    );
    Ok(transaction.is_some())
}

async fn with_timeout<T, E>(
    network: &NetworkConfig,
    future: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    E: std::fmt::Display,
{
    tokio::time::timeout(RPC_TIMEOUT, future)
        .await
        .context("RPC request timed out")?
        .map_err(|error| sanitized_rpc_error(network, &error))
}

async fn timeout_call<T, E>(
    network: &NetworkConfig,
    future: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    E: std::fmt::Display,
{
    with_timeout(network, future).await
}

/// Strips the configured RPC endpoint from text before it can reach an agent
/// or a log. The exact URL collapses to `<rpc-url>`, and because some
/// providers carry credentials as URL userinfo, any `user:password@host` form
/// collapses to the bare host as well. Every module that surfaces an RPC
/// error goes through this one implementation.
#[must_use]
pub fn sanitize_rpc_message(network: &NetworkConfig, message: &str) -> String {
    let mut sanitized = message.replace(network.rpc_url.as_str(), "<rpc-url>");
    if let Some(host) = network.rpc_url.host_str()
        && (!network.rpc_url.username().is_empty() || network.rpc_url.password().is_some())
    {
        sanitized = sanitized.replace(
            &format!(
                "{}:{}@{host}",
                network.rpc_url.username(),
                network.rpc_url.password().unwrap_or_default()
            ),
            host,
        );
    }
    sanitized
}

pub fn sanitized_rpc_error(
    network: &NetworkConfig,
    error: &impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::anyhow!(
        "RPC request failed: {}",
        sanitize_rpc_message(network, &error.to_string())
    )
}

fn delegated_implementation(code: &Bytes) -> Option<Address> {
    (code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00]))
        .then(|| Address::from_slice(&code[3..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    #[test]
    fn parses_only_eip7702_delegation_designators() {
        let mut code = vec![0xef, 0x01, 0x00];
        code.extend([0x11; 20]);
        assert_eq!(
            delegated_implementation(&Bytes::from(code)),
            Some(Address::repeat_byte(0x11))
        );
        assert_eq!(delegated_implementation(&Bytes::from(vec![0xef, 1])), None);
    }

    #[test]
    fn rpc_errors_do_not_repeat_credential_bearing_url() {
        let mut network = crate::config::default_networks().remove(0);
        network.rpc_url = "https://user:secret@example.invalid/rpc".parse().unwrap();
        let error = sanitized_rpc_error(
            &network,
            &format_args!("request to {} failed", network.rpc_url),
        );
        let message = error.to_string();
        assert!(!message.contains("secret"));
        assert!(message.contains("<rpc-url>"));

        // Providers also echo the credential-bearing authority without the
        // full URL around it; the bare userinfo form is stripped too.
        let bare = sanitized_rpc_error(
            &network,
            &format_args!("connect to user:secret@example.invalid refused"),
        )
        .to_string();
        assert!(!bare.contains("secret"), "{bare}");
        assert!(bare.contains("example.invalid"), "{bare}");
    }

    #[test]
    fn u256_balance_format_is_decimal() {
        assert_eq!(U256::from(123_u64).to_string(), "123");
    }
}
