//! Plain-SQLite token database and Multicall3-backed portfolio reads.
//!
//! Token metadata is public display data, so it deliberately lives outside
//! the encrypted security database: MCP tools may write it without touching
//! signing state, and reading it needs no credential-store access. Nothing in
//! the signing path consults this database. Metadata is verified against the
//! token contracts themselves through Multicall3 at insert time, so the
//! database stores what the configured chain reports rather than what a list
//! claims.

use crate::config::NetworkConfig;
use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U256},
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

const DATABASE_FILE: &str = "tokens.db";
/// Tokens verified per Multicall3 request; three calls each.
const METADATA_CHUNK: usize = 100;
/// Balance reads per Multicall3 request.
const BALANCE_CHUNK: usize = 200;
/// One import may verify at most this many new tokens.
pub const MAX_IMPORT_TOKENS: usize = 1_000;
/// A portfolio read checks at most this many known tokens.
pub const MAX_PORTFOLIO_TOKENS: usize = 2_000;
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
    connection: Connection,
}

impl TokenStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        Self::open(&data_dir.join(DATABASE_FILE))
    }

    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("failed to open token database {}", path.display()))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(Duration::from_secs(5))?;
        // The chain_id/address pair is the primary key, so a conflicting
        // entry is structurally impossible rather than policy-enforced.
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS tokens (
                 chain_id INTEGER NOT NULL CHECK (chain_id > 0),
                 address TEXT NOT NULL CHECK (address = lower(address) AND length(address) = 42),
                 symbol TEXT,
                 name TEXT,
                 decimals INTEGER CHECK (decimals IS NULL OR (decimals >= 0 AND decimals <= 255)),
                 source TEXT NOT NULL,
                 added_at TEXT NOT NULL,
                 PRIMARY KEY (chain_id, address)
             ) STRICT",
        )?;
        Ok(Self { connection })
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
        let changed = self.connection.execute(
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
        self.connection
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
            let mut statement = self.connection.prepare(
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
            let mut statement = self.connection.prepare(
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
            Some(chain) => self.connection.query_row(
                "SELECT COUNT(*) FROM tokens WHERE chain_id = ?1",
                params![i64::try_from(chain).context("chain ID out of range")?],
                |row| row.get(0),
            )?,
            None => self
                .connection
                .query_row("SELECT COUNT(*) FROM tokens", [], |row| row.get(0))?,
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
        let results = aggregate(network, &provider, calls).await?;
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
    /// Tokens with a nonzero balance (unless zero balances were requested).
    pub tokens: Vec<PortfolioToken>,
    /// How many known tokens were checked.
    pub tokens_checked: u64,
    /// Set when the database held more tokens than one read may check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_skipped: Option<u64>,
}

/// Read native and token balances for `address` through Multicall3.
pub async fn read_portfolio(
    network: &NetworkConfig,
    address: Address,
    known_tokens: &[StoredToken],
    include_zero_balances: bool,
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
        let results = aggregate(network, &provider, calls).await?;
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
            if balance > U256::ZERO || include_zero_balances {
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
    })
}

fn call(target: Address, data: Vec<u8>) -> TokenCall3 {
    TokenCall3 {
        target,
        allowFailure: true,
        callData: data.into(),
    }
}

async fn aggregate<P: Provider>(
    network: &NetworkConfig,
    provider: &P,
    calls: Vec<TokenCall3>,
) -> Result<Vec<TokenResult3>> {
    let request = TransactionRequest::default()
        .with_to(crate::batch_read::MULTICALL3_ADDRESS)
        .with_input(aggregate3Call { calls }.abi_encode());
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

    fn store() -> (tempfile::TempDir, TokenStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = TokenStore::production(directory.path()).unwrap();
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
            let mut store = TokenStore::production(directory.path()).unwrap();
            store.add(10, token, &usdc(), "manual").unwrap();
        }
        let store = TokenStore::production(directory.path()).unwrap();
        assert_eq!(store.count(None).unwrap(), 1);
        assert_eq!(
            store.get(10, token).unwrap().unwrap().symbol.as_deref(),
            Some("USDC")
        );
    }
}
