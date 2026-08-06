//! Token display database and Multicall3-backed portfolio reads.
//!
//! This database is where a token's name comes from. Nothing in the signing or
//! policy path consults it, but the review screen does, and a name a reviewer
//! trusts is worth attacking — so the rows live inside the authenticated
//! encrypted database, where a symbol, name, or decimals cannot be edited
//! outside this process.
//!
//! Rows come from token lists, not from token contracts. This is the opposite
//! of what it once was, and deliberately: `symbol()` returns whatever a
//! contract's author wrote, so trusting it let any deployed address call
//! itself `USDC` on the screen where the owner decides. A curated list is a
//! claim by someone the owner chose to trust; a contract's own answer is a
//! claim by the counterparty they are being protected from.
//!
//! The chain still gets a vote, but only a veto. [`verify_listings`] confirms
//! a token-like contract exists at the address and that its `decimals` agrees
//! with the list — `decimals` scales every amount ever displayed for the
//! token, so a disagreement is refused rather than resolved. Neither check can
//! put a contract-chosen string in front of a reviewer.

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
///
/// This is never what gets stored as a token's name. A contract's `symbol()`
/// answers with whatever its author wrote, so it is evidence about the
/// contract, not about the token's identity — see [`ListedToken`].
#[derive(Clone, Debug, Default)]
pub struct OnchainTokenMetadata {
    pub symbol: Option<String>,
    pub name: Option<String>,
    pub decimals: Option<u8>,
}

/// What a token list says about one token, and the only thing the wallet will
/// ever display as a token's name.
///
/// The distinction from [`OnchainTokenMetadata`] is the whole point: a list is
/// a claim by whoever curated it, and the owner decides whether to trust that
/// curator. A contract's own answer is a claim by the counterparty, which is
/// exactly the party a reviewer is being protected from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedToken {
    pub chain_id: u64,
    pub address: Address,
    pub symbol: String,
    pub name: Option<String>,
    pub decimals: u8,
}

/// Why a listed token was refused at import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListingRejection {
    /// The contract answered neither `symbol()` nor `decimals()`, so there is
    /// no evidence a token lives at this address at all.
    NotATokenContract,
    /// The list and the contract disagree about `decimals`. One of them is
    /// wrong, and since `decimals` scales every amount the owner will ever be
    /// shown for this token, guessing which would risk misrendering an amount
    /// by orders of magnitude.
    DecimalsMismatch { listed: u8, onchain: u8 },
}

impl std::fmt::Display for ListingRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotATokenContract => {
                write!(formatter, "answered neither symbol() nor decimals()")
            }
            Self::DecimalsMismatch { listed, onchain } => write!(
                formatter,
                "the list says {listed} decimals, the contract reports {onchain}"
            ),
        }
    }
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

    /// Insert one listed token. Fails if the (chain, address) pair exists.
    pub fn add(&mut self, token: &ListedToken, source: &str) -> Result<StoredToken> {
        let inserted = self.insert_if_absent(token, source)?;
        ensure!(
            inserted,
            "token {} on chain {} is already in the database",
            token.address.to_checksum(None),
            token.chain_id
        );
        self.get(token.chain_id, token.address)?
            .context("inserted token missing")
    }

    /// Insert one listed token unless the pair already exists. Returns whether
    /// an insert happened; an existing entry is never overwritten.
    ///
    /// The stored symbol and name are the list's, never the contract's. They
    /// are sanitized on the way in because a list is untrusted text, and
    /// sanitized again at render time because this is not the only way a row
    /// can reach the database.
    pub fn insert_if_absent(&mut self, token: &ListedToken, source: &str) -> Result<bool> {
        ensure!(token.chain_id > 0, "chain ID must be positive");
        let symbol = sanitize(&token.symbol);
        ensure!(
            !symbol.is_empty(),
            "token {} on chain {} has an empty symbol once sanitized",
            token.address.to_checksum(None),
            token.chain_id
        );
        let changed = self.database.connection.execute(
            "INSERT INTO tokens(chain_id, address, symbol, name, decimals, source, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(chain_id, address) DO NOTHING",
            params![
                i64::try_from(token.chain_id).context("chain ID out of range")?,
                format!("{:#x}", token.address),
                symbol,
                token.name.as_deref().map(sanitize),
                token.decimals,
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

    /// Display metadata for the tokens a plan names, drawn only from rows the
    /// owner confirmed. A token with no row gets no entry, so the reviewer is
    /// shown its address rather than a name the wallet cannot vouch for.
    ///
    /// This is the only source of names in the review path, and it reads
    /// nothing but the local database: a token contract never gets to say what
    /// it is called at the moment the owner is deciding.
    pub fn display_metadata(
        &self,
        chain_id: u64,
        tokens: &[Address],
    ) -> Result<crate::approval_summary::TokenMetadataMap> {
        let mut map = crate::approval_summary::TokenMetadataMap::new();
        for token in tokens {
            if let Some(stored) = self.get(chain_id, *token)? {
                map.insert(
                    *token,
                    crate::approval_summary::TokenMetadata {
                        symbol: stored.symbol,
                        decimals: stored.decimals,
                    },
                );
            }
        }
        Ok(map)
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

/// Check listed tokens against their contracts, returning each token with the
/// reason it must be refused, if any.
///
/// The chain is not consulted about what a token is *called* — that is the
/// list's job and the reason the owner confirms a list at all. It is consulted
/// about two things a list can get wrong without anyone noticing:
///
/// - whether a contract that behaves like a token exists at the address, so a
///   typo or a dead entry cannot become a named row; and
/// - whether `decimals` agrees, because `decimals` silently scales every
///   amount the owner will be shown for this token, and a list that is off by
///   twelve would misrender an amount by a factor of a trillion.
///
/// Neither check can put a contract-chosen string in front of a reviewer.
pub async fn verify_listings(
    network: &NetworkConfig,
    listed: &[ListedToken],
) -> Result<Vec<(ListedToken, Option<ListingRejection>)>> {
    let addresses: Vec<Address> = listed.iter().map(|token| token.address).collect();
    let onchain = fetch_onchain_metadata(network, &addresses).await?;
    Ok(listed
        .iter()
        .map(|token| {
            let found = onchain.get(&token.address).cloned().unwrap_or_default();
            (token.clone(), listing_rejection(token, &found))
        })
        .collect())
}

/// The rule [`verify_listings`] applies to one token, separated from the RPC
/// so it can be read and tested as the decision it is.
fn listing_rejection(
    listed: &ListedToken,
    onchain: &OnchainTokenMetadata,
) -> Option<ListingRejection> {
    if onchain.symbol.is_none() && onchain.decimals.is_none() {
        return Some(ListingRejection::NotATokenContract);
    }
    match onchain.decimals {
        Some(reported) if reported != listed.decimals => Some(ListingRejection::DecimalsMismatch {
            listed: listed.decimals,
            onchain: reported,
        }),
        _ => None,
    }
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
                crate::rpc::MULTICALL3_ADDRESS,
                getBlockNumberCall {}.abi_encode(),
            ));
            calls.push(call(
                crate::rpc::MULTICALL3_ADDRESS,
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
                crate::rpc::MULTICALL3_ADDRESS,
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
        // The lens is absent on some chains, and the EVM does not treat that
        // as a failure: a call to an account with no code succeeds and
        // returns nothing. Anything that is not a decodable lens answer —
        // a reverted call, empty return data, or unexpected bytes — means
        // this chain has no lens, so fall back to individual reads instead of
        // failing the whole balance read.
        let decoded = result
            .success
            .then(|| {
                getNonzeroBalancesAndAllowancesCall::abi_decode_returns(&result.returnData).ok()
            })
            .flatten();
        let Some(decoded) = decoded else {
            fetcher_available = false;
            balances.clear();
            break;
        };
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
                            crate::rpc::MULTICALL3_ADDRESS,
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
        .with_to(crate::rpc::MULTICALL3_ADDRESS)
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
    crate::sanitize::stripped_capped(text, MAX_TEXT_LEN)
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

    fn usdc(chain_id: u64, address: Address) -> ListedToken {
        ListedToken {
            chain_id,
            address,
            symbol: "USDC".into(),
            name: Some("USD Coin".into()),
            decimals: 6,
        }
    }

    #[test]
    fn chain_and_address_conflicts_are_impossible() {
        let (_directory, mut store) = store();
        let token = Address::repeat_byte(0x11);
        store.add(&usdc(1, token), "manual").unwrap();

        // The same pair fails loudly on add and is skipped on bulk insert,
        // never overwritten.
        let error = store
            .add(
                &ListedToken {
                    symbol: "IMPOSTOR".into(),
                    ..usdc(1, token)
                },
                "manual",
            )
            .unwrap_err();
        assert!(error.to_string().contains("already in the database"));
        assert!(
            !store
                .insert_if_absent(
                    &ListedToken {
                        symbol: "IMPOSTOR".into(),
                        ..usdc(1, token)
                    },
                    "list"
                )
                .unwrap()
        );
        let stored = store.get(1, token).unwrap().unwrap();
        assert_eq!(stored.source, "manual");
        // A second list cannot rename a token the owner already confirmed.
        assert_eq!(stored.symbol.as_deref(), Some("USDC"));

        // The same address on another chain is a distinct entry.
        assert!(store.insert_if_absent(&usdc(8453, token), "list").unwrap());
        assert_eq!(store.count(None).unwrap(), 2);
        assert_eq!(store.count(Some(1)).unwrap(), 1);
    }

    #[test]
    fn listing_is_deterministic_and_checksummed() {
        let (_directory, mut store) = store();
        store
            .add(&usdc(1, Address::repeat_byte(0xB2)), "manual")
            .unwrap();
        store
            .add(&usdc(1, Address::repeat_byte(0x0A)), "manual")
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
                &ListedToken {
                    chain_id: 1,
                    address: token,
                    symbol: "US\u{1b}[31mDC\n".into(),
                    name: Some("x".repeat(500)),
                    decimals: 6,
                },
                "manual",
            )
            .unwrap();
        let stored = store.get(1, token).unwrap().unwrap();
        assert_eq!(stored.symbol.as_deref(), Some("US[31mDC"));
        assert_eq!(stored.name.as_deref().map(str::len), Some(MAX_TEXT_LEN));
    }

    /// A list entry whose symbol is nothing but control characters would store
    /// as an empty name and render as a token with no identity at all.
    #[test]
    fn a_symbol_that_sanitizes_away_is_refused() {
        let (_directory, mut store) = store();
        let error = store
            .add(
                &ListedToken {
                    chain_id: 1,
                    address: Address::repeat_byte(0x55),
                    symbol: "\u{202e}\n\t".into(),
                    name: None,
                    decimals: 18,
                },
                "list",
            )
            .unwrap_err();
        assert!(error.to_string().contains("empty symbol"), "{error}");
        assert_eq!(store.count(None).unwrap(), 0);
    }

    /// The rule `verify_listings` applies, exercised directly so it is pinned
    /// without needing an RPC: the contract may veto a listing, but it never
    /// gets to supply the name.
    #[test]
    fn a_listing_is_vetoed_by_decimals_but_never_renamed() {
        let listed = usdc(1, Address::repeat_byte(0x66));

        // Agreement: accepted, and the stored symbol stays the list's even
        // though the contract calls itself something else entirely.
        assert_eq!(
            listing_rejection(
                &listed,
                &OnchainTokenMetadata {
                    symbol: Some("Definitely Not USDC".into()),
                    name: None,
                    decimals: Some(6),
                }
            ),
            None
        );

        // Disagreement about decimals: refused rather than resolved.
        assert_eq!(
            listing_rejection(
                &listed,
                &OnchainTokenMetadata {
                    symbol: Some("USDC".into()),
                    name: None,
                    decimals: Some(18),
                }
            ),
            Some(ListingRejection::DecimalsMismatch {
                listed: 6,
                onchain: 18
            })
        );

        // Nothing token-like at the address at all.
        assert_eq!(
            listing_rejection(&listed, &OnchainTokenMetadata::default()),
            Some(ListingRejection::NotATokenContract)
        );

        // A contract that answers symbol() but not decimals() is still a
        // token; the list's decimals stand because nothing contradicts them.
        assert_eq!(
            listing_rejection(
                &listed,
                &OnchainTokenMetadata {
                    symbol: Some("USDC".into()),
                    name: None,
                    decimals: None,
                }
            ),
            None
        );
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
            store.add(&usdc(10, token), "manual").unwrap();
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
        use alloy::primitives::keccak256;
        let expected =
            keccak256(b"getNonzeroBalancesAndAllowances(address,address[],address[])".as_slice());
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
