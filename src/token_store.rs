//! Token display database and Multicall3-backed portfolio reads.
//!
//! Token metadata is display data: nothing in the signing or policy path
//! consults it. It nevertheless lives inside the authenticated encrypted
//! database, because a symbol, name, or decimals edited outside this process
//! could misrepresent balances and amounts to the user. Metadata is verified
//! against the token contracts themselves through Multicall3 at insert time,
//! so the database stores what the configured chain reports rather than what
//! a list claims, and MCP tools may still write it — writes go through that
//! verification, never around it.

use crate::{
    config::NetworkConfig,
    fork::{ForkContext, ForkPreface, execute_reads},
    policy_store::PolicyStore,
};
use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall,
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, str::FromStr, time::Duration};

/// Plain-SQLite file used before the table moved into the encrypted
/// database. Rows are imported once (constraint-checked, never overwriting)
/// and the file is then removed.
const LEGACY_DATABASE_FILE: &str = "tokens.db";
/// Tokens verified per Multicall3 request; three calls each.
const METADATA_CHUNK: usize = 100;
/// Balance reads per Multicall3 request.
const BALANCE_CHUNK: usize = 200;
/// One import may verify at most this many new tokens.
pub const MAX_IMPORT_TOKENS: usize = 1_000;
/// A portfolio read checks at most this many known tokens.
pub const MAX_PORTFOLIO_TOKENS: usize = 2_000;
/// One explicit balances read accepts at most this many token addresses.
pub const MAX_BALANCE_TOKENS: usize = 1_000;
/// The Ekubo `TokenDataFetcher` lens, deployed deterministically at the same
/// address on every Ekubo-supported network. It reads balances for an
/// explicit token list in one call, already returning only nonzero entries;
/// nonexistent or misbehaving tokens read as zero via `SafeTransferLib`
/// rather than reverting, and `address(0)` reads the owner's native balance.
pub const TOKEN_DATA_FETCHER_ADDRESS: Address =
    address!("0x305cf9a34dcb265522780d1d64544d3f7c450407");
/// Tokens per `TokenDataFetcher` call.
const FETCHER_CHUNK: usize = 500;
const RPC_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_TEXT_LEN: usize = 64;

sol! {
    struct TokenCall3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct TokenResult3 {
        bool success;
        bytes returnData;
    }

    function aggregate3(TokenCall3[] calls) external payable returns (TokenResult3[] returnData);

    function symbol() external view returns (string);
    function name() external view returns (string);
    function decimals() external view returns (uint8);
    function balanceOf(address account) external view returns (uint256);
    function getEthBalance(address addr) external view returns (uint256);
    function getBlockNumber() external view returns (uint256);

    struct FetcherBalance {
        address token;
        uint256 amount;
    }

    struct FetcherAllowance {
        address token;
        address spender;
        uint256 amount;
    }

    function getNonzeroBalancesAndAllowances(address owner, address[] tokens, address[] spenders)
        external view returns (FetcherBalance[] balances, FetcherAllowance[] allowances);
}

/// One stored token, addresses rendered checksummed.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct StoredToken {
    pub chain_id: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    pub source: String,
    pub added_at: String,
}

/// Metadata read from the token contract through Multicall3.
#[derive(Clone, Debug, Default)]
pub struct OnchainTokenMetadata {
    pub symbol: Option<String>,
    pub name: Option<String>,
    pub decimals: Option<u8>,
}

pub struct TokenStore {
    database: PolicyStore,
}

impl TokenStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        let store = Self {
            database: PolicyStore::production(data_dir)?,
        };
        store.import_legacy_database(data_dir);
        Ok(store)
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    /// One-time import of the pre-encryption plain-SQLite token file. Rows
    /// pass through the encrypted table's CHECK constraints (`INSERT OR
    /// IGNORE`, so malformed or duplicate rows are dropped rather than
    /// trusted), and the legacy file is removed only after a full pass.
    /// A failed import leaves the file for a later retry and never blocks
    /// opening the store.
    fn import_legacy_database(&self, data_dir: &Path) {
        let legacy_path = data_dir.join(LEGACY_DATABASE_FILE);
        if !legacy_path.exists() {
            return;
        }
        let import = (|| -> Result<()> {
            let legacy =
                Connection::open_with_flags(&legacy_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut statement = legacy.prepare(
                "SELECT chain_id, address, symbol, name, decimals, source, added_at FROM tokens",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })?;
            for row in rows {
                let (chain_id, address, symbol, name, decimals, source, added_at) = row?;
                self.database.connection.execute(
                    "INSERT OR IGNORE INTO tokens(
                        chain_id, address, symbol, name, decimals, source, added_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![chain_id, address, symbol, name, decimals, source, added_at],
                )?;
            }
            Ok(())
        })();
        if import.is_ok() {
            for suffix in ["", "-wal", "-shm"] {
                let _ =
                    std::fs::remove_file(data_dir.join(format!("{LEGACY_DATABASE_FILE}{suffix}")));
            }
        }
    }

    /// Insert one token. Fails if the (chain, address) pair already exists.
    pub fn add(
        &mut self,
        chain_id: u64,
        address: Address,
        metadata: &OnchainTokenMetadata,
        source: &str,
    ) -> Result<StoredToken> {
        let inserted = self.insert_if_absent(chain_id, address, metadata, source)?;
        ensure!(
            inserted,
            "token {} on chain {chain_id} is already in the database",
            address.to_checksum(None)
        );
        self.get(chain_id, address)?
            .context("inserted token missing")
    }

    /// Insert one token unless the pair already exists. Returns whether an
    /// insert happened; an existing entry is never overwritten.
    pub fn insert_if_absent(
        &mut self,
        chain_id: u64,
        address: Address,
        metadata: &OnchainTokenMetadata,
        source: &str,
    ) -> Result<bool> {
        ensure!(chain_id > 0, "chain ID must be positive");
        let changed = self.database.connection.execute(
            "INSERT INTO tokens(chain_id, address, symbol, name, decimals, source, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(chain_id, address) DO NOTHING",
            params![
                i64::try_from(chain_id).context("chain ID out of range")?,
                format!("{address:#x}"),
                metadata.symbol.as_deref().map(sanitize),
                metadata.name.as_deref().map(sanitize),
                metadata.decimals,
                source,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn get(&self, chain_id: u64, address: Address) -> Result<Option<StoredToken>> {
        self.database
            .connection
            .query_row(
                "SELECT chain_id, address, symbol, name, decimals, source, added_at
                 FROM tokens WHERE chain_id = ?1 AND address = ?2",
                params![
                    i64::try_from(chain_id).context("chain ID out of range")?,
                    format!("{address:#x}")
                ],
                row_to_token,
            )
            .optional()
            .context("failed to read token")
    }

    /// List tokens, optionally filtered by chain, ordered deterministically.
    pub fn list(
        &self,
        chain_id: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredToken>> {
        let limit = i64::try_from(limit.min(10_000)).unwrap_or(10_000);
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        let mut rows = Vec::new();
        if let Some(chain) = chain_id {
            let mut statement = self.database.connection.prepare(
                "SELECT chain_id, address, symbol, name, decimals, source, added_at
                 FROM tokens WHERE chain_id = ?1
                 ORDER BY chain_id, address LIMIT ?2 OFFSET ?3",
            )?;
            let mapped = statement.query_map(
                params![
                    i64::try_from(chain).context("chain ID out of range")?,
                    limit,
                    offset
                ],
                row_to_token,
            )?;
            for row in mapped {
                rows.push(row?);
            }
        } else {
            let mut statement = self.database.connection.prepare(
                "SELECT chain_id, address, symbol, name, decimals, source, added_at
                 FROM tokens ORDER BY chain_id, address LIMIT ?1 OFFSET ?2",
            )?;
            let mapped = statement.query_map(params![limit, offset], row_to_token)?;
            for row in mapped {
                rows.push(row?);
            }
        }
        Ok(rows)
    }

    pub fn count(&self, chain_id: Option<u64>) -> Result<u64> {
        let count: i64 = match chain_id {
            Some(chain) => self.database.connection.query_row(
                "SELECT COUNT(*) FROM tokens WHERE chain_id = ?1",
                params![i64::try_from(chain).context("chain ID out of range")?],
                |row| row.get(0),
            )?,
            None => {
                self.database
                    .connection
                    .query_row("SELECT COUNT(*) FROM tokens", [], |row| row.get(0))?
            }
        };
        Ok(u64::try_from(count).unwrap_or(0))
    }
}

fn row_to_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredToken> {
    let chain_id: i64 = row.get(0)?;
    let address: String = row.get(1)?;
    let checksummed = Address::from_str(&address)
        .map(|address| address.to_checksum(None))
        .unwrap_or(address);
    Ok(StoredToken {
        chain_id: chain_id.to_string(),
        address: checksummed,
        symbol: row.get(2)?,
        name: row.get(3)?,
        decimals: row
            .get::<_, Option<i64>>(4)?
            .and_then(|value| u8::try_from(value).ok()),
        source: row.get(5)?,
        added_at: row.get(6)?,
    })
}

/// Read `symbol`, `name`, and `decimals` for each token from the chain, in
/// Multicall3 chunks. Tokens whose calls fail map to empty metadata.
pub async fn fetch_onchain_metadata(
    network: &NetworkConfig,
    tokens: &[Address],
) -> Result<BTreeMap<Address, OnchainTokenMetadata>> {
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let mut out = BTreeMap::new();
    for chunk in tokens.chunks(METADATA_CHUNK) {
        let calls: Vec<TokenCall3> = chunk
            .iter()
            .flat_map(|token| {
                [
                    call(*token, symbolCall {}.abi_encode()),
                    call(*token, nameCall {}.abi_encode()),
                    call(*token, decimalsCall {}.abi_encode()),
                ]
            })
            .collect();
        // Token metadata is only ever verified against real chain state; a
        // fork must never be able to influence what gets stored.
        let results = aggregate(network, &provider, calls, None).await?;
        ensure!(
            results.len() == chunk.len() * 3,
            "Multicall3 returned an unexpected result count"
        );
        for (index, token) in chunk.iter().enumerate() {
            let symbol_result = &results[index * 3];
            let name_result = &results[index * 3 + 1];
            let decimals_result = &results[index * 3 + 2];
            out.insert(
                *token,
                OnchainTokenMetadata {
                    symbol: decode_string(symbol_result, |data| {
                        symbolCall::abi_decode_returns(data).ok()
                    }),
                    name: decode_string(name_result, |data| {
                        nameCall::abi_decode_returns(data).ok()
                    }),
                    decimals: decimals_result
                        .success
                        .then(|| decimalsCall::abi_decode_returns(&decimals_result.returnData).ok())
                        .flatten(),
                },
            );
        }
    }
    Ok(out)
}

/// One token balance line in a portfolio.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct PortfolioToken {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    /// Raw balance in the token's smallest unit, as a decimal string.
    pub balance: String,
}

/// Balances for one address across the tokens known to the database.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct Portfolio {
    pub address: String,
    pub chain_id: String,
    pub network: String,
    /// Native balance in wei.
    pub native_balance: String,
    /// Block number of the first Multicall3 batch.
    pub block_number: String,
    /// Tokens with a nonzero balance; zero balances are never included.
    pub tokens: Vec<PortfolioToken>,
    /// How many known tokens were checked.
    pub tokens_checked: u64,
    /// Set when the database held more tokens than one read may check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_skipped: Option<u64>,
    /// Present only when this portfolio was read on a temporary simulation
    /// fork. Its presence means every balance here is hypothetical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkContext>,
}

/// Read native and token balances for `address` through Multicall3. Only
/// tokens with a nonzero balance are returned.
pub async fn read_portfolio(
    network: &NetworkConfig,
    address: Address,
    known_tokens: &[StoredToken],
    fork: Option<&ForkPreface>,
) -> Result<Portfolio> {
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let checked: Vec<&StoredToken> = known_tokens.iter().take(MAX_PORTFOLIO_TOKENS).collect();
    let skipped = known_tokens.len().saturating_sub(checked.len());

    // The first batch pins the block and reads the native balance alongside
    // the first token chunk; Multicall3 answers both natively.
    let mut block_number = None;
    let mut native_balance = U256::ZERO;
    let mut tokens = Vec::new();
    let mut start = 0_usize;
    loop {
        let chunk: Vec<&StoredToken> = checked
            .iter()
            .skip(start)
            .take(BALANCE_CHUNK)
            .copied()
            .collect();
        if start > 0 && chunk.is_empty() {
            break;
        }
        let mut calls = Vec::with_capacity(chunk.len() + 2);
        if start == 0 {
            calls.push(call(
                crate::batch_read::MULTICALL3_ADDRESS,
                getBlockNumberCall {}.abi_encode(),
            ));
            calls.push(call(
                crate::batch_read::MULTICALL3_ADDRESS,
                getEthBalanceCall { addr: address }.abi_encode(),
            ));
        }
        for token in &chunk {
            let token_address =
                Address::from_str(&token.address).context("stored token address is invalid")?;
            calls.push(call(
                token_address,
                balanceOfCall { account: address }.abi_encode(),
            ));
        }
        let results = aggregate(network, &provider, calls, fork).await?;
        let mut results = results.into_iter();
        if start == 0 {
            let block = results.next().context("missing block number result")?;
            ensure!(block.success, "Multicall3 getBlockNumber failed");
            block_number =
                Some(getBlockNumberCall::abi_decode_returns(&block.returnData)?.to_string());
            let native = results.next().context("missing native balance result")?;
            ensure!(native.success, "Multicall3 getEthBalance failed");
            native_balance = getEthBalanceCall::abi_decode_returns(&native.returnData)?;
        }
        for token in &chunk {
            let result = results.next().context("missing token balance result")?;
            let balance = result
                .success
                .then(|| balanceOfCall::abi_decode_returns(&result.returnData).ok())
                .flatten()
                .unwrap_or(U256::ZERO);
            if balance > U256::ZERO {
                tokens.push(PortfolioToken {
                    address: token.address.clone(),
                    symbol: token.symbol.clone(),
                    decimals: token.decimals,
                    balance: balance.to_string(),
                });
            }
        }
        start += chunk.len().max(1);
        if start >= checked.len() {
            break;
        }
    }

    Ok(Portfolio {
        address: address.to_checksum(None),
        chain_id: network.chain_id.to_string(),
        network: network.name.clone(),
        native_balance: native_balance.to_string(),
        block_number: block_number.context("portfolio read produced no block number")?,
        tokens,
        tokens_checked: checked.len() as u64,
        tokens_skipped: (skipped > 0).then_some(skipped as u64),
        fork: None,
    })
}

/// One nonzero balance from an explicit balances read.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct TokenBalance {
    pub token: String,
    /// Raw balance in the token's smallest unit, as a decimal string.
    pub balance: String,
}

/// Balances for one address across an explicit token list.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct TokenBalances {
    pub address: String,
    pub chain_id: String,
    pub network: String,
    /// Block number reported in the same Multicall3 batch as the first read.
    pub block_number: String,
    /// Only nonzero balances. Zero, nonexistent, and misbehaving tokens are
    /// omitted rather than aborting the batch.
    pub balances: Vec<TokenBalance>,
    /// Distinct token addresses checked after deduplication.
    pub tokens_checked: u64,
    /// `token_data_fetcher` when the Ekubo lens answered, otherwise
    /// `multicall_balance_of`.
    pub source: String,
    /// Present only when these balances were read on a temporary simulation
    /// fork. Its presence means every balance here is hypothetical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkContext>,
}

/// Read balances for an explicit token list through the Ekubo
/// `TokenDataFetcher` lens, falling back to individual Multicall3 `balanceOf`
/// reads on networks where the lens is not deployed. Both paths isolate
/// per-token failures — a bad address reads as zero — and `address(0)` reads
/// the owner's native balance.
pub async fn read_token_balances(
    network: &NetworkConfig,
    owner: Address,
    tokens: &[Address],
    fork: Option<&ForkPreface>,
) -> Result<TokenBalances> {
    ensure!(!tokens.is_empty(), "at least one token address is required");
    ensure!(
        tokens.len() <= MAX_BALANCE_TOKENS,
        "at most {MAX_BALANCE_TOKENS} token addresses may be checked per request"
    );
    let mut seen = std::collections::BTreeSet::new();
    let tokens: Vec<Address> = tokens
        .iter()
        .copied()
        .filter(|token| seen.insert(*token))
        .collect();

    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let mut block_number: Option<String> = None;
    let mut balances = Vec::new();
    let mut fetcher_available = true;
    for (index, chunk) in tokens.chunks(FETCHER_CHUNK).enumerate() {
        let mut calls = Vec::with_capacity(2);
        if index == 0 {
            calls.push(call(
                crate::batch_read::MULTICALL3_ADDRESS,
                getBlockNumberCall {}.abi_encode(),
            ));
        }
        calls.push(call(
            TOKEN_DATA_FETCHER_ADDRESS,
            getNonzeroBalancesAndAllowancesCall {
                owner,
                tokens: chunk.to_vec(),
                spenders: Vec::new(),
            }
            .abi_encode(),
        ));
        let results = aggregate(network, &provider, calls, fork).await?;
        let mut results = results.into_iter();
        if index == 0 {
            let block = results.next().context("missing block number result")?;
            ensure!(block.success, "Multicall3 getBlockNumber failed");
            block_number =
                Some(getBlockNumberCall::abi_decode_returns(&block.returnData)?.to_string());
        }
        let result = results.next().context("missing TokenDataFetcher result")?;
        if !result.success {
            // Not deployed on this network; the Multicall3 wrapper isolated
            // the failure. Fall back to individual reads.
            fetcher_available = false;
            balances.clear();
            break;
        }
        let decoded = getNonzeroBalancesAndAllowancesCall::abi_decode_returns(&result.returnData)
            .context("TokenDataFetcher returned undecodable data")?;
        for entry in decoded.balances {
            balances.push(TokenBalance {
                token: entry.token.to_checksum(None),
                balance: entry.amount.to_string(),
            });
        }
    }

    let source = if fetcher_available {
        "token_data_fetcher"
    } else {
        for chunk in tokens.chunks(BALANCE_CHUNK) {
            let calls = chunk
                .iter()
                .map(|token| {
                    if *token == Address::ZERO {
                        call(
                            crate::batch_read::MULTICALL3_ADDRESS,
                            getEthBalanceCall { addr: owner }.abi_encode(),
                        )
                    } else {
                        call(*token, balanceOfCall { account: owner }.abi_encode())
                    }
                })
                .collect();
            let results = aggregate(network, &provider, calls, fork).await?;
            ensure!(
                results.len() == chunk.len(),
                "Multicall3 returned an unexpected result count"
            );
            for (token, result) in chunk.iter().zip(results) {
                let balance = result
                    .success
                    .then(|| balanceOfCall::abi_decode_returns(&result.returnData).ok())
                    .flatten()
                    .unwrap_or(U256::ZERO);
                if balance > U256::ZERO {
                    balances.push(TokenBalance {
                        token: token.to_checksum(None),
                        balance: balance.to_string(),
                    });
                }
            }
        }
        "multicall_balance_of"
    };

    Ok(TokenBalances {
        address: owner.to_checksum(None),
        chain_id: network.chain_id.to_string(),
        network: network.name.clone(),
        block_number: block_number.context("balances read produced no block number")?,
        balances,
        tokens_checked: tokens.len() as u64,
        source: source.into(),
        fork: None,
    })
}

fn call(target: Address, data: Vec<u8>) -> TokenCall3 {
    TokenCall3 {
        target,
        allowFailure: true,
        callData: data.into(),
    }
}

/// Run one Multicall3 `aggregate3` batch, either against real chain state or
/// inside a temporary simulation fork. Both paths send the identical encoded
/// call, so results decode the same way and per-call failures stay isolated.
async fn aggregate<P: Provider>(
    network: &NetworkConfig,
    provider: &P,
    calls: Vec<TokenCall3>,
    fork: Option<&ForkPreface>,
) -> Result<Vec<TokenResult3>> {
    let request = TransactionRequest::default()
        .with_to(crate::batch_read::MULTICALL3_ADDRESS)
        .with_input(aggregate3Call { calls }.abi_encode());
    if let Some(preface) = fork {
        let outcome = execute_reads(network, preface, vec![request]).await?;
        let result = outcome
            .results
            .first()
            .context("fork Multicall3 read returned no result")?;
        ensure!(
            result.status,
            "Multicall3 failed on this fork; the canonical Multicall3 may not be deployed on chain {}",
            network.chain_id
        );
        return aggregate3Call::abi_decode_returns(&result.return_data)
            .context("Multicall3 returned undecodable data");
    }
    let bytes = tokio::time::timeout(RPC_TIMEOUT, provider.call(request))
        .await
        .context("Multicall3 request timed out")?
        .map_err(|error| {
            let raw = error.to_string();
            anyhow::anyhow!(
                "Multicall3 request failed: {}",
                raw.replace(network.rpc_url.as_str(), "<rpc-url>")
            )
        })?;
    aggregate3Call::abi_decode_returns(&bytes).context("Multicall3 returned undecodable data")
}

fn decode_string<F>(result: &TokenResult3, decode: F) -> Option<String>
where
    F: Fn(&[u8]) -> Option<String>,
{
    if !result.success {
        return None;
    }
    decode(&result.returnData)
        .as_deref()
        .and_then(nonempty_sanitized)
}

fn nonempty_sanitized(text: &str) -> Option<String> {
    let cleaned = sanitize(text);
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Token names and symbols are attacker-controlled contract output; strip
/// control characters and cap length before they reach any display or store.
fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(MAX_TEXT_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

/// A chain ID that accepts both a canonical decimal string and a bare JSON
/// number, because standard token-list files use numeric `chainId` values.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ChainIdInput {
    Number(u64),
    Text(String),
}

impl ChainIdInput {
    pub fn value(&self) -> Result<u64> {
        match self {
            Self::Number(value) => {
                ensure!(*value > 0, "chain ID must be positive");
                Ok(*value)
            }
            Self::Text(text) => {
                ensure!(
                    !text.is_empty()
                        && !text.starts_with('0')
                        && text.bytes().all(|byte| byte.is_ascii_digit()),
                    "invalid decimal chain ID {text}"
                );
                text.parse().context("unsupported chain ID")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_store::DatabaseKey;

    fn open(directory: &Path) -> TokenStore {
        TokenStore::new(
            PolicyStore::open(&directory.join("policies.db"), &DatabaseKey::new([8; 32])).unwrap(),
        )
    }

    fn store() -> (tempfile::TempDir, TokenStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = open(directory.path());
        (directory, store)
    }

    fn usdc() -> OnchainTokenMetadata {
        OnchainTokenMetadata {
            symbol: Some("USDC".into()),
            name: Some("USD Coin".into()),
            decimals: Some(6),
        }
    }

    #[test]
    fn chain_and_address_conflicts_are_impossible() {
        let (_directory, mut store) = store();
        let token = Address::repeat_byte(0x11);
        store.add(1, token, &usdc(), "manual").unwrap();

        // The same pair fails loudly on add and is skipped on bulk insert,
        // never overwritten.
        let error = store
            .add(1, token, &OnchainTokenMetadata::default(), "manual")
            .unwrap_err();
        assert!(error.to_string().contains("already in the database"));
        assert!(!store.insert_if_absent(1, token, &usdc(), "list").unwrap());
        let stored = store.get(1, token).unwrap().unwrap();
        assert_eq!(stored.source, "manual");
        assert_eq!(stored.symbol.as_deref(), Some("USDC"));

        // The same address on another chain is a distinct entry.
        assert!(
            store
                .insert_if_absent(8453, token, &usdc(), "list")
                .unwrap()
        );
        assert_eq!(store.count(None).unwrap(), 2);
        assert_eq!(store.count(Some(1)).unwrap(), 1);
    }

    #[test]
    fn listing_is_deterministic_and_checksummed() {
        let (_directory, mut store) = store();
        store
            .add(1, Address::repeat_byte(0xB2), &usdc(), "manual")
            .unwrap();
        store
            .add(1, Address::repeat_byte(0x0A), &usdc(), "manual")
            .unwrap();
        let listed = store.list(Some(1), 10, 0).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed[0].address < listed[1].address);
        assert_eq!(
            listed[0].address,
            Address::repeat_byte(0x0A).to_checksum(None)
        );
        assert!(store.list(Some(2), 10, 0).unwrap().is_empty());
        assert_eq!(store.list(None, 1, 1).unwrap().len(), 1);
    }

    #[test]
    fn hostile_metadata_is_sanitized_before_storage() {
        let (_directory, mut store) = store();
        let token = Address::repeat_byte(0x33);
        store
            .add(
                1,
                token,
                &OnchainTokenMetadata {
                    symbol: Some("US\u{1b}[31mDC\n".into()),
                    name: Some("x".repeat(500)),
                    decimals: Some(6),
                },
                "manual",
            )
            .unwrap();
        let stored = store.get(1, token).unwrap().unwrap();
        assert_eq!(stored.symbol.as_deref(), Some("US[31mDC"));
        assert_eq!(stored.name.as_deref().map(str::len), Some(MAX_TEXT_LEN));
    }

    #[test]
    fn chain_id_input_accepts_numbers_and_canonical_strings() {
        assert_eq!(ChainIdInput::Number(4663).value().unwrap(), 4663);
        assert_eq!(ChainIdInput::Text("1".into()).value().unwrap(), 1);
        assert!(ChainIdInput::Text("01".into()).value().is_err());
        assert!(ChainIdInput::Text("0x1".into()).value().is_err());
        assert!(ChainIdInput::Number(0).value().is_err());
    }

    #[test]
    fn reopening_preserves_rows() {
        let directory = tempfile::tempdir().unwrap();
        let token = Address::repeat_byte(0x44);
        {
            let mut store = open(directory.path());
            store.add(10, token, &usdc(), "manual").unwrap();
        }
        let store = open(directory.path());
        assert_eq!(store.count(None).unwrap(), 1);
        assert_eq!(
            store.get(10, token).unwrap().unwrap().symbol.as_deref(),
            Some("USDC")
        );
    }

    #[test]
    fn fetcher_call_encodes_the_deployed_selector() {
        use sha3::{Digest, Keccak256};
        let expected = Keccak256::digest(
            b"getNonzeroBalancesAndAllowances(address,address[],address[])".as_slice(),
        );
        assert_eq!(getNonzeroBalancesAndAllowancesCall::SELECTOR, expected[..4]);
        assert_eq!(
            format!("{TOKEN_DATA_FETCHER_ADDRESS:#x}"),
            "0x305cf9a34dcb265522780d1d64544d3f7c450407"
        );
    }

    #[test]
    fn balances_read_bounds_its_input() {
        let network = crate::config::default_networks().remove(0);
        let owner = Address::repeat_byte(0x11);
        let empty: Vec<Address> = Vec::new();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(
            runtime
                .block_on(read_token_balances(&network, owner, &empty, None))
                .is_err()
        );
        let too_many = vec![Address::repeat_byte(0x22); MAX_BALANCE_TOKENS + 1];
        assert!(
            runtime
                .block_on(read_token_balances(&network, owner, &too_many, None))
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "explicit live Ethereum RPC conformance check"]
    async fn live_balances_read_isolates_bad_tokens_and_filters_zeroes() {
        let network = crate::config::default_networks().remove(0);
        // Any fixed address may hold dust on mainnet, so assert the
        // structural guarantees instead of exact holdings: the bogus token
        // must not abort the batch and can never report a balance, entries
        // are nonzero and pinned to a real block, and Binance 8 definitely
        // holds USDC, exercising the nonzero path.
        let bogus = Address::repeat_byte(0x11);
        let usdc = Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
        let binance = Address::from_str("0xf977814e90da44bfa03b6295a0616a897441acec").unwrap();
        let result = read_token_balances(&network, binance, &[usdc, bogus, Address::ZERO], None)
            .await
            .unwrap();
        println!("source={} balances={:?}", result.source, result.balances);
        assert_eq!(result.tokens_checked, 3);
        assert!(result.block_number.parse::<u64>().unwrap() > 0);
        let bogus_checksum = bogus.to_checksum(None);
        assert!(
            result
                .balances
                .iter()
                .all(|entry| entry.token != bogus_checksum)
        );
        assert!(result.balances.iter().all(|entry| {
            entry
                .balance
                .parse::<u128>()
                .map_or(true, |value| value > 0)
        }));
        assert!(
            result
                .balances
                .iter()
                .any(|entry| entry.token == usdc.to_checksum(None))
        );
    }

    #[test]
    fn legacy_plain_database_is_imported_once_and_removed() {
        let directory = tempfile::tempdir().unwrap();
        let legacy_path = directory.path().join(LEGACY_DATABASE_FILE);
        let legacy = Connection::open(&legacy_path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE tokens (
                     chain_id INTEGER NOT NULL,
                     address TEXT NOT NULL,
                     symbol TEXT, name TEXT, decimals INTEGER,
                     source TEXT NOT NULL, added_at TEXT NOT NULL,
                     PRIMARY KEY (chain_id, address)
                 );
                 INSERT INTO tokens VALUES
                     (1, '0x1111111111111111111111111111111111111111',
                      'USDC', 'USD Coin', 6, 'manual', '2026-01-01T00:00:00Z'),
                     (0, '0xbad', 'EVIL', 'Constraint Violator', 6,
                      'manual', '2026-01-01T00:00:00Z');",
            )
            .unwrap();
        drop(legacy);

        let store = open(directory.path());
        store.import_legacy_database(directory.path());
        // The valid row imports; the row violating the encrypted table's
        // constraints is dropped rather than trusted; the file is removed.
        assert_eq!(store.count(None).unwrap(), 1);
        assert_eq!(
            store
                .get(1, Address::repeat_byte(0x11))
                .unwrap()
                .unwrap()
                .symbol
                .as_deref(),
            Some("USDC")
        );
        assert!(!legacy_path.exists());
    }
}
