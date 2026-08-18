//! Token display database and lens-backed balance reads.
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
//! The chain is not asked about a listing at all. It was once asked whether
//! *something* at the address answered `symbol()` or `name()`, as a check
//! against a typo or a dead entry, and that is gone: the owner's approval is
//! the check. A contract cannot tell them whether a curator is trustworthy,
//! which is the only question a listing raises, and an address that answers
//! nothing yields a row that names nothing — a harmless one, not a dangerous
//! one.
//!
//! `decimals()` in particular is never called, and never was in this design.
//! Every value a contract returns is chosen by whoever deployed it, `decimals`
//! no less than `symbol`, so checking the list against it would let the
//! counterparty overrule the curator the owner picked. The list is the
//! authority on both the name and the scale of every amount displayed for a
//! token.

use crate::{
    chain_client::ChainClient,
    config::NetworkConfig,
    fork::{ForkContext, ForkPreface, execute_reads},
    human_presence::{OwnerAuthorization, OwnerAuthorizationScope},
    policy_store::PolicyStore,
    sql::{self, Blob, Millis, RowExt},
};
use alloy::{
    eips::BlockId,
    network::TransactionBuilder,
    primitives::{Address, U256, address},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr, time::Duration};

/// Balance reads per Multicall3 request.
const BALANCE_CHUNK: usize = 200;
/// Tokens one import may carry.
///
/// This bounds a single list's size so one call cannot fill the review queue
/// by itself. Nothing here is read from a chain, so the limit is about what
/// the owner is handed at once, not about what a batch of RPC calls costs.
///
/// It is deliberately generous, because the decision it bounds is not
/// per-row. `meta-tokens review` groups suggestions by the list that vouched for
/// them and the owner accepts or rejects a whole list at a time: what they
/// are judging is whether the curator is trustworthy, and that question reads
/// the same at ten entries as at ten thousand. A tighter cap bought no extra
/// scrutiny — nobody was checking a thousand rows individually either — while
/// it did refuse ordinary published lists outright. Uniswap Labs Default
/// carries about 1700 rows and `CoinGecko`'s about 5100, and a wallet that
/// could not import either was enforcing a budget nobody was spending.
///
/// What still bounds the damage is that none of it is a name yet: an import
/// is a queue of suggestions no display path reads until the owner confirms
/// the list.
pub const MAX_IMPORT_TOKENS: usize = 10_000;

/// Token suggestions that may await review at once.
///
/// Sized to hold several full imports, so the ordinary case of proposing a
/// couple of curated lists back to back is never refused, while an agent
/// cannot make `meta-tokens review` an unbounded scroll of decisions. It has to
/// stay a multiple of [`MAX_IMPORT_TOKENS`]: capacity is charged per row
/// below, so a queue smaller than one import would make every full-size
/// import fail partway and roll back, which is a cap that refuses the thing
/// it was sized to hold.
pub const MAX_PENDING_TOKEN_PROPOSALS: u64 = 50_000;
/// A portfolio read checks at most this many known tokens.
///
/// Above the largest chain in the shipped list — Ethereum's ~5,600 — so the
/// ordinary answer is complete rather than truncated. The lens returns only
/// nonzero entries, so asking about every known token costs one request and a
/// response sized by what the owner actually holds; the bound exists so an
/// unusually large imported list cannot turn one read into a request no
/// endpoint will serve.
///
/// This one does *not* scale with [`MAX_IMPORT_TOKENS`], and must not be
/// raised to match it. `FETCHER_CHUNK` is sized so a whole portfolio is one
/// call, and that is a correctness property rather than tuning: a second
/// chunk has to be read at the block the first reported, which archive-less
/// public endpoints routinely cannot serve — the failure that broke this on
/// Arbitrum and Base. So an owner who confirms more tokens than this on one
/// chain gets a complete-as-far-as-it-went read with the remainder reported
/// in `tokens_skipped`, which is the honest outcome; silently issuing a
/// second chunk at a stale block would not be.
pub const MAX_PORTFOLIO_TOKENS: usize = 8_000;
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
///
/// Sized so both bounded reads fit in one call: a portfolio asks about at most
/// [`MAX_PORTFOLIO_TOKENS`] plus the native sentinel, and an explicit read at
/// most [`MAX_BALANCE_TOKENS`]. That is the point of the number rather than a
/// throughput tuning. A second chunk has to be read at the block the first one
/// reported, so that the answer is one view of the chain instead of several,
/// and public endpoints are markedly worse at serving a block a moment after
/// announcing it — an archive-less node may already have pruned that state,
/// which is exactly how this failed on Arbitrum and Base before the lens
/// answered a whole portfolio at once.
const FETCHER_CHUNK: usize = 8_192;
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
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
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
    pub added_at: DateTime<Utc>,
    /// Roughly what one whole token is worth in US dollars, if the owner has
    /// said.
    ///
    /// Per whole token rather than per smallest unit — 1.0 for USDC, not
    /// 0.000001 — so the number means the same thing whatever the token's
    /// decimals are, and reading it needs no second field.
    ///
    /// It is display data of the weakest kind there is: nothing in the policy,
    /// signing, or approval path reads it, no amount is scaled by it, and it
    /// never appears in a review. Its only job is to order the portfolio and
    /// to let a tab full of dust be collapsed by default, which is why the tab
    /// always says how many rows that hid. Nothing writes it but the owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approximate_usd_price: Option<f64>,
}

/// What a token list says about one token, and the only thing the wallet will
/// ever display as a token's name.
///
/// Nothing a contract returns is stored or displayed. A list is a claim by
/// whoever curated it, and the owner decides whether to trust that curator; a
/// contract's own answer is a claim by the counterparty, which is exactly the
/// party a reviewer is being protected from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedToken {
    pub chain_id: u64,
    pub address: Address,
    pub symbol: String,
    pub name: Option<String>,
    pub decimals: u8,
}

/// One token an agent has suggested, waiting for the owner to decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenProposal {
    pub token: ListedToken,
    /// The list the suggestion came from, used to group the review screen.
    pub source: String,
    pub proposed_at: DateTime<Utc>,
}

/// What one call to [`TokenStore::propose`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ProposalSummary {
    /// Now awaiting the owner's review.
    pub pending: u64,
    /// Already in the token database, so there is nothing to decide.
    pub already_confirmed: u64,
    /// Refused outright, currently only for an empty symbol.
    pub rejected: u64,
}

pub struct TokenStore {
    database: PolicyStore,
}

/// Where a batch of suggestions came from, and whether anything outside the
/// call says so.
///
/// Review groups suggestions by this string and accepts or rejects a group as
/// one unit, so the string is the whole of what the owner is deciding about.
/// Two ways of producing it that can produce the *same* string are therefore
/// one namespace: an agent that imports a real curator's list and then
/// proposes its own contract under the identical label gets that contract
/// confirmed as the curator's, with a symbol and decimals it chose, which then
/// name and scale amounts on every approval screen afterwards.
///
/// So the two are a type, and their renderings cannot collide.
pub enum ProposalSource<'a> {
    /// Bytes a TLS-verified `host` served, carrying the name the list gives
    /// itself when it gives one. The host leads because it is the one part of
    /// this the caller could not choose.
    Served {
        host: &'a str,
        declared: Option<&'a str>,
    },
    /// A label the caller supplied, for a list it fetched or wrote itself.
    /// Nothing outside the call says the label is true, and the rendering
    /// says as much rather than letting it sit beside a proved one.
    Claimed(&'a str),
}

/// What a caller-supplied label is prefixed with. A DNS host contains no
/// spaces, so no [`ProposalSource::Served`] rendering can begin this way, and
/// the prefix leads so capping the length cannot remove it.
const CLAIMED_PREFIX: &str = "an agent's own list: ";

struct NormalizedOwnerToken {
    chain_id: i64,
    symbol: String,
    name: Option<String>,
    source: String,
}

fn normalize_owner_token(token: &ListedToken, source: &str) -> Result<NormalizedOwnerToken> {
    ensure!(token.chain_id > 0, "chain ID must be positive");
    let symbol = sanitize(&token.symbol);
    ensure!(
        !symbol.is_empty(),
        "token {} on chain {} has an empty symbol once sanitized",
        token.address.to_checksum(None),
        token.chain_id
    );
    let source = sanitize(source);
    ensure!(!source.is_empty(), "token source must not be empty");
    Ok(NormalizedOwnerToken {
        chain_id: i64::try_from(token.chain_id).context("chain ID out of range")?,
        symbol,
        name: token
            .name
            .as_deref()
            .map(sanitize)
            .filter(|name| !name.is_empty()),
        source,
    })
}

fn stored_token_identity(token: &StoredToken) -> Result<(u64, Address)> {
    Ok((
        token
            .chain_id
            .parse()
            .context("stored token has an invalid chain ID")?,
        token
            .address
            .parse()
            .context("stored token has an invalid address")?,
    ))
}

impl ProposalSource<'_> {
    /// The exact string a review groups under.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Served {
                host,
                declared: Some(declared),
            } => format!("{} — {}", sanitize(host), sanitize(declared)),
            Self::Served { host, .. } => sanitize(host),
            Self::Claimed(name) => format!("{CLAIMED_PREFIX}{}", sanitize(name)),
        }
    }
}

impl TokenStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            database: PolicyStore::production(data_dir)?,
        })
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    /// Insert one listed token. Fails if the (chain, address) pair exists.
    #[cfg(any(test, feature = "test-hooks"))]
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
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn insert_if_absent(&mut self, token: &ListedToken, source: &str) -> Result<bool> {
        Ok(self.insert_all_absent(std::slice::from_ref(&(token.clone(), source.to_owned())))? == 1)
    }

    /// Confirm a whole review's worth of tokens in one transaction.
    ///
    /// One transaction, not one per row, because the review path is where an
    /// agent's numbers meet an owner's single decision: an import may carry
    /// [`MAX_IMPORT_TOKENS`] entries and the queue may hold
    /// [`MAX_PENDING_TOKEN_PROPOSALS`]. The database journals in DELETE mode
    /// at FULL synchronization, so every autocommit is several filesystem
    /// syncs — accepting a large list a row at a time froze the review UI for
    /// minutes and left half of it applied if anyone gave up. `propose` has
    /// always been one transaction for the same reason.
    ///
    /// Returns how many rows were genuinely new.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn insert_all_absent(&mut self, tokens: &[(ListedToken, String)]) -> Result<u64> {
        let now = Millis(sql::now());
        let transaction = self.database.connection.transaction()?;
        let mut inserted = 0_u64;
        for (token, source) in tokens {
            ensure!(token.chain_id > 0, "chain ID must be positive");
            let symbol = sanitize(&token.symbol);
            ensure!(
                !symbol.is_empty(),
                "token {} on chain {} has an empty symbol once sanitized",
                token.address.to_checksum(None),
                token.chain_id
            );
            let chain_id = i64::try_from(token.chain_id).context("chain ID out of range")?;
            // The provenance goes through the same sanitizer as the symbol and
            // the name, because it has the same provenance: a token list's
            // declared name, or a filename, both chosen by whoever wrote the
            // list. Two of the three fields were cleaned and this one was not.
            //
            // Newlines are what make it more than untidy. `terminal_safe_multiline`
            // preserves them deliberately -- it exists so multi-line output
            // survives -- and `token list` and `token search` interpolate the
            // stored source into one line each. A source carrying a newline
            // therefore prints as extra inventory rows, which is a forgery of
            // the one column that says where a name came from.
            let source = sanitize(source);
            let changed = transaction.execute(
                "INSERT INTO tokens(
                     chain_id, address, symbol, name, decimals, source, added_at,
                     approximate_usd_price
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(chain_id, address) DO NOTHING",
                params![
                    chain_id,
                    Blob(token.address),
                    symbol,
                    token.name.as_deref().map(sanitize),
                    token.decimals,
                    source,
                    now,
                    // The same value the default list would have carried for
                    // this address. Where a token came from decides nothing
                    // about what it is worth, so a token confirmed through a
                    // review must not sort differently from the same token
                    // shipped with the wallet.
                    crate::token_prices::seeded_token_price(token.chain_id, token.address),
                ],
            )?;
            // A confirmed address has nothing left to decide, so any suggestion
            // for it is consumed here rather than left to be filtered out of every
            // later read. Unconditional: the row is meaningless whether this call
            // inserted the token or found it already there, and the exact-
            // generation delete the review path uses misses a suggestion whose
            // content changed while the owner was looking at it.
            transaction.execute(
                "DELETE FROM token_proposals WHERE chain_id = ?1 AND address = ?2",
                params![chain_id, Blob(token.address)],
            )?;
            inserted += u64::from(changed == 1);
        }
        transaction.commit()?;
        Ok(inserted)
    }

    #[cfg(feature = "test-hooks")]
    pub fn insert_if_absent_for_test(&mut self, token: &ListedToken, source: &str) -> Result<bool> {
        self.insert_if_absent(token, source)
    }

    /// Confirm the exact proposal rows an owner reviewed and consume them in
    /// the same transaction that installs their display metadata.
    ///
    /// A proposal can be replaced while native authentication is open. The
    /// timestamp and complete stored content are therefore checked for every
    /// row before any token is inserted; a changed batch leaves both tables
    /// untouched and must be reviewed again.
    pub fn consume_proposals_authorized(
        &mut self,
        proposals: &[TokenProposal],
        authorization: &OwnerAuthorization,
    ) -> Result<u64> {
        authorization.require(OwnerAuthorizationScope::TokenMetadata)?;
        self.consume_proposals(proposals)
    }

    /// Add genuinely new owner-authored display metadata for one token.
    ///
    /// Create is deliberately not an upsert. A token-list confirmation or a
    /// second owner window may install the same identity while native
    /// authentication is open; the stale Add form must report that conflict
    /// instead of overwriting the row the owner never reviewed.
    pub fn add_authorized(
        &mut self,
        token: &ListedToken,
        source: &str,
        approximate_usd_price: Option<f64>,
        authorization: &OwnerAuthorization,
    ) -> Result<StoredToken> {
        authorization.require(OwnerAuthorizationScope::TokenMetadata)?;
        let fields = normalize_owner_token(token, source)?;
        if let Some(price) = approximate_usd_price {
            ensure!(
                price.is_finite() && price >= 0.0,
                "an approximate value must be a number at or above zero"
            );
        }
        let now = Millis(sql::now());
        let transaction = self.database.connection.transaction()?;
        let inserted = transaction.execute(
            "INSERT INTO tokens(
                 chain_id, address, symbol, name, decimals, source, added_at,
                 approximate_usd_price
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(chain_id, address) DO NOTHING",
            params![
                fields.chain_id,
                Blob(token.address),
                fields.symbol,
                fields.name,
                token.decimals,
                fields.source,
                now,
                approximate_usd_price,
            ],
        )?;
        ensure!(
            inserted == 1,
            "token {} on chain {} was added while authentication was open; review the current row",
            token.address.to_checksum(None),
            token.chain_id
        );
        // Once the owner has supplied exact metadata there is no remaining
        // proposal for this identity to review, regardless of its generation.
        transaction.execute(
            "DELETE FROM token_proposals WHERE chain_id = ?1 AND address = ?2",
            params![fields.chain_id, Blob(token.address)],
        )?;
        transaction.commit()?;
        self.get(token.chain_id, token.address)?
            .context("inserted token missing")
    }

    pub(crate) fn consume_proposals(&mut self, proposals: &[TokenProposal]) -> Result<u64> {
        ensure!(!proposals.is_empty(), "no token proposals were selected");
        let transaction = self.database.connection.transaction()?;
        for proposal in proposals {
            let token = &proposal.token;
            let exists: Option<()> = transaction
                .query_row(
                    "SELECT 1 FROM token_proposals
                     WHERE chain_id = ?1 AND address = ?2 AND symbol = ?3
                       AND name IS ?4 AND decimals = ?5 AND source = ?6
                       AND proposed_at = ?7",
                    params![
                        i64::try_from(token.chain_id).context("chain ID out of range")?,
                        Blob(token.address),
                        token.symbol,
                        token.name,
                        token.decimals,
                        proposal.source,
                        Millis(proposal.proposed_at),
                    ],
                    |_| Ok(()),
                )
                .optional()?;
            ensure!(
                exists.is_some(),
                "a token proposal changed while it was being reviewed; nothing was installed"
            );
        }

        let now = Millis(sql::now());
        let mut inserted = 0_u64;
        for proposal in proposals {
            let token = &proposal.token;
            let chain_id = i64::try_from(token.chain_id).context("chain ID out of range")?;
            inserted += u64::from(
                transaction.execute(
                    "INSERT INTO tokens(
                         chain_id, address, symbol, name, decimals, source, added_at,
                         approximate_usd_price
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(chain_id, address) DO NOTHING",
                    params![
                        chain_id,
                        Blob(token.address),
                        sanitize(&token.symbol),
                        token.name.as_deref().map(sanitize),
                        token.decimals,
                        sanitize(&proposal.source),
                        now,
                        // Accepting a suggestion decides what this wallet
                        // calls a token, not what it is worth. The shipped
                        // value comes from the same snapshot either way, and
                        // nothing in the proposal is consulted about it.
                        crate::token_prices::seeded_token_price(token.chain_id, token.address),
                    ],
                )? == 1,
            );
            let removed = transaction.execute(
                "DELETE FROM token_proposals
                 WHERE chain_id = ?1 AND address = ?2 AND symbol = ?3
                   AND name IS ?4 AND decimals = ?5 AND source = ?6
                   AND proposed_at = ?7",
                params![
                    chain_id,
                    Blob(token.address),
                    token.symbol,
                    token.name,
                    token.decimals,
                    proposal.source,
                    Millis(proposal.proposed_at),
                ],
            )?;
            ensure!(
                removed == 1,
                "a token proposal changed while it was being installed"
            );
        }
        transaction.commit()?;
        Ok(inserted)
    }

    /// Forget one confirmed token after it was presented to the owner.
    ///
    /// Removing a name is fail-safe in a way adding one is not: the wallet
    /// falls back to displaying the bare address, which is the conservative
    /// thing to show. The native UI action is sufficient confirmation; unlike
    /// adding or replacing trusted metadata, removal does not need operating-
    /// system human-presence authentication because nothing here can cause
    /// something to be signed or make an untrusted label appear trustworthy.
    /// The exact reviewed row is part of the delete predicate so a concurrent
    /// metadata change must be shown to the owner before it can be removed.
    ///
    /// It exists because a new database now arrives holding thousands of
    /// seeded names, and an owner who disagrees with one of them had no way to
    /// say so.
    pub fn remove_reviewed(&mut self, reviewed: &StoredToken) -> Result<()> {
        let (chain_id, address) = stored_token_identity(reviewed)?;
        let removed = self.database.connection.execute(
            "DELETE FROM tokens
             WHERE chain_id = ?1 AND address = ?2
               AND symbol IS ?3 AND name IS ?4 AND decimals IS ?5
               AND source = ?6 AND added_at = ?7",
            params![
                i64::try_from(chain_id).context("chain ID out of range")?,
                Blob(address),
                reviewed.symbol,
                reviewed.name,
                reviewed.decimals,
                reviewed.source,
                Millis(reviewed.added_at),
            ],
        )?;
        ensure!(
            removed == 1,
            "token {} on chain {} changed after it was reviewed; review the current metadata",
            address.to_checksum(None),
            chain_id
        );
        Ok(())
    }

    /// Record roughly what one whole token of a reviewed row is worth, or
    /// clear what was recorded.
    ///
    /// Unauthenticated, like removing a row and unlike adding one, and for the
    /// same reason: what needs the owner's authentication is a *name*, because
    /// a name is what a reviewer reads when they decide whether to sign. This
    /// number is read by one tab's sort order and by the filter that hides
    /// dust from it — never by the policy, the signing path, or a review — and
    /// the tab always says how many rows the filter hid, so a wrong price
    /// cannot make a holding disappear quietly.
    ///
    /// The row is matched on the exact metadata that was reviewed, so a price
    /// cannot be attached to a token that changed underneath the screen.
    pub fn set_approximate_price(
        &mut self,
        reviewed: &StoredToken,
        price: Option<f64>,
    ) -> Result<()> {
        let (chain_id, address) = stored_token_identity(reviewed)?;
        if let Some(price) = price {
            ensure!(
                price.is_finite() && price >= 0.0,
                "an approximate value must be a number at or above zero"
            );
        }
        let updated = self.database.connection.execute(
            "UPDATE tokens SET approximate_usd_price = ?8
             WHERE chain_id = ?1 AND address = ?2
               AND symbol IS ?3 AND name IS ?4 AND decimals IS ?5
               AND source = ?6 AND added_at = ?7",
            params![
                i64::try_from(chain_id).context("chain ID out of range")?,
                Blob(address),
                reviewed.symbol,
                reviewed.name,
                reviewed.decimals,
                reviewed.source,
                Millis(reviewed.added_at),
                price,
            ],
        )?;
        ensure!(
            updated == 1,
            "token {} on chain {} changed after it was reviewed; review the current metadata",
            address.to_checksum(None),
            chain_id
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn remove(&mut self, chain_id: u64, address: Address) -> Result<bool> {
        let removed = self.database.connection.execute(
            "DELETE FROM tokens WHERE chain_id = ?1 AND address = ?2",
            params![
                i64::try_from(chain_id).context("chain ID out of range")?,
                Blob(address),
            ],
        )?;
        Ok(removed == 1)
    }

    pub fn get(&self, chain_id: u64, address: Address) -> Result<Option<StoredToken>> {
        self.database
            .connection
            .query_row(
                "SELECT chain_id, address, symbol, name, decimals, source, added_at,
                    approximate_usd_price
                 FROM tokens WHERE chain_id = ?1 AND address = ?2",
                params![
                    i64::try_from(chain_id).context("chain ID out of range")?,
                    Blob(address)
                ],
                row_to_token,
            )
            .optional()
            .context("failed to read token")
    }

    /// Record tokens an agent suggests, for the owner to review in the
    /// native review screen. Nothing here is a display name yet — a suggestion becomes one
    /// only by being confirmed into `tokens`.
    ///
    /// Tokens already confirmed are skipped rather than re-proposed, so review
    /// only ever shows genuinely new decisions. A repeated suggestion for the
    /// same address replaces the previous one: the latest claim is the one the
    /// owner will judge, and keeping stale variants around would mean showing
    /// the same token twice under two different names.
    pub fn propose(
        &mut self,
        tokens: &[ListedToken],
        source: &ProposalSource<'_>,
    ) -> Result<ProposalSummary> {
        let source = sanitize(&source.label());
        ensure!(!source.is_empty(), "a proposal needs a source list name");
        // The queue is a list of decisions a person has to make. Repeats for
        // the same address are idempotent, but an agent calling with a
        // thousand fresh addresses each time grows it without bound — and does
        // not thereby gain a name, it makes the screen where names are granted
        // unreadable, which is the same thing. `meta-tokens review` loads the whole
        // queue and renders one row per token.
        //
        // Capacity is charged per row rather than per call. Checking the count
        // once and then inserting a whole batch let one call carry the queue
        // from just under the cap to `MAX_IMPORT_TOKENS - 1` over it, which is
        // the cap not holding. Replacing an existing suggestion costs nothing,
        // because it adds no decision the owner did not already have.
        //
        // One transaction, so hitting the cap mid-batch leaves the queue as it
        // was rather than half-extended by the part that fit.
        let mut pending = self.count_proposals()?;
        ensure!(
            pending < MAX_PENDING_TOKEN_PROPOSALS,
            "{pending} tokens already await review; the owner must resolve them in the Tokens screen before more can be suggested"
        );
        let mut summary = ProposalSummary::default();
        let transaction = self.database.connection.transaction()?;
        for token in tokens {
            ensure!(token.chain_id > 0, "chain ID must be positive");
            let confirmed: Option<()> = transaction
                .query_row(
                    "SELECT 1 FROM tokens WHERE chain_id = ?1 AND address = ?2",
                    params![
                        i64::try_from(token.chain_id).context("chain ID out of range")?,
                        Blob(token.address)
                    ],
                    |_| Ok(()),
                )
                .optional()?;
            if confirmed.is_some() {
                // And any suggestion left over for it goes, in this same
                // transaction. Otherwise the row survives every read that
                // filters it out and every review that cannot show it.
                transaction.execute(
                    "DELETE FROM token_proposals WHERE chain_id = ?1 AND address = ?2",
                    params![
                        i64::try_from(token.chain_id).context("chain ID out of range")?,
                        Blob(token.address)
                    ],
                )?;
                summary.already_confirmed += 1;
                continue;
            }
            let symbol = sanitize(&token.symbol);
            if symbol.is_empty() {
                summary.rejected += 1;
                continue;
            }
            let queued: Option<()> = transaction
                .query_row(
                    "SELECT 1 FROM token_proposals WHERE chain_id = ?1 AND address = ?2",
                    params![
                        i64::try_from(token.chain_id).context("chain ID out of range")?,
                        Blob(token.address)
                    ],
                    |_| Ok(()),
                )
                .optional()?;
            if queued.is_none() {
                ensure!(
                    pending < MAX_PENDING_TOKEN_PROPOSALS,
                    "this batch would leave more than {MAX_PENDING_TOKEN_PROPOSALS} tokens \
                     awaiting review; the owner must resolve them in the Tokens screen first"
                );
                pending += 1;
            }
            // `proposed_at` is what the owner's decision names when it comes
            // back to consume this row, so rotating it throws that decision
            // away. Rotating it for a re-proposal that changed nothing threw
            // it away for free: an agent could repeat the identical suggestion
            // while the picker was open, or during the owner-authentication
            // pause after it, and both accept and reject would then match no
            // row. Repeated, that keeps rejected names reappearing and holds
            // the queue at its cap with decisions that can never land.
            //
            // So the timestamp moves only when the content behind it moves,
            // which makes it stand for what was reviewed rather than for when
            // it was last mentioned. A genuinely changed suggestion does
            // rotate it, and should: the owner is being asked about something
            // else now, and a decision taken against the old text is not an
            // answer to it. `IS NOT` rather than `<>` because a name is
            // nullable and `NULL <> NULL` is not true.
            transaction.execute(
                "INSERT INTO token_proposals(
                     chain_id, address, symbol, name, decimals, source, proposed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(chain_id, address) DO UPDATE SET
                     symbol = excluded.symbol,
                     name = excluded.name,
                     decimals = excluded.decimals,
                     source = excluded.source,
                     -- Strictly later than the value being replaced, rather
                     -- than simply the current moment. sql::now is truncated
                     -- to milliseconds, so a suggestion rewritten inside the
                     -- same millisecond as the one it replaces would keep the
                     -- old name -- and that name is what a decision reaches
                     -- back for, so a reject taken against the text the owner
                     -- read would consume text they never saw. One
                     -- millisecond is enough: this only has to be a value
                     -- that is not the one it just was.
                     proposed_at = max(excluded.proposed_at, proposed_at + 1)
                 WHERE symbol IS NOT excluded.symbol
                    OR name IS NOT excluded.name
                    OR decimals IS NOT excluded.decimals
                    OR source IS NOT excluded.source",
                params![
                    i64::try_from(token.chain_id).context("chain ID out of range")?,
                    Blob(token.address),
                    symbol,
                    token.name.as_deref().map(sanitize),
                    token.decimals,
                    source,
                    Millis(sql::now()),
                ],
            )?;
            summary.pending += 1;
        }
        transaction.commit()?;
        Ok(summary)
    }

    /// Every suggestion awaiting the owner, oldest source first so the review
    /// screen's grouping is stable between runs.
    pub fn proposals(&self) -> Result<Vec<TokenProposal>> {
        // A suggestion for a token that already has a name is not a decision
        // the owner has left to make, and showing it as one made both answers
        // wrong: rejecting deleted the suggestion and reported that nothing
        // was named, while the confirmed row it was about carried on naming
        // the token on every approval; accepting preserved that row and
        // reported zero confirmations. `propose` already treats a confirmed
        // address as nothing to decide and counts it separately — this is the
        // same rule, applied to what the review screen reads, so the two
        // cannot disagree about a row that arrived before an import confirmed
        // it. Changing a name that is already there is what `meta-tokens remove`
        // is for.
        let mut statement = self.database.connection.prepare(
            "SELECT chain_id, address, symbol, name, decimals, source, proposed_at
             FROM token_proposals AS proposal
             WHERE NOT EXISTS (
                 SELECT 1 FROM tokens
                 WHERE tokens.chain_id = proposal.chain_id
                   AND tokens.address = proposal.address
             )
             ORDER BY source, chain_id, symbol, address",
        )?;
        let mapped = statement.query_map([], |row| {
            let chain_id: i64 = row.get(0)?;
            let decimals: i64 = row.get(4)?;
            Ok(TokenProposal {
                token: ListedToken {
                    chain_id: u64::try_from(chain_id).unwrap_or_default(),
                    address: row.blob(1)?,
                    symbol: row.get(2)?,
                    name: row.get(3)?,
                    decimals: u8::try_from(decimals).unwrap_or_default(),
                },
                source: row.get(5)?,
                proposed_at: row.time(6)?,
            })
        })?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }

    /// Suggestions the owner can actually act on, which is the same set
    /// [`Self::proposals`] renders and the same set capacity is charged
    /// against.
    ///
    /// The `NOT EXISTS` is what makes those three agree. Review has always
    /// hidden a proposal whose address is already confirmed -- there is no
    /// decision left to take about it -- while the count included it, so a
    /// hidden row went on occupying capacity that no amount of reviewing could
    /// release. Filling the queue with rows the owner is then told to review,
    /// on a screen that shows none of them, denies the whole naming pipeline
    /// until someone edits the database.
    pub fn count_proposals(&self) -> Result<u64> {
        let count: i64 = self.database.connection.query_row(
            "SELECT COUNT(*) FROM token_proposals AS proposal
             WHERE NOT EXISTS (
                 SELECT 1 FROM tokens
                 WHERE tokens.chain_id = proposal.chain_id
                   AND tokens.address = proposal.address
             )",
            [],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count).unwrap_or_default())
    }

    /// Drop suggestions the owner has decided on, whether they accepted or
    /// rejected them: either way the decision is made and re-asking would
    /// train the owner to dismiss the screen.
    ///
    /// Each entry names the exact row that was shown, by its `proposed_at` as
    /// well as its key. The review screen holds no lock — it snapshots the
    /// proposals, releases the store, and waits on a person — so an agent can
    /// replace a suggestion for the same chain and address in the meantime,
    /// with a different symbol, name, or decimals. Deleting by key alone
    /// consumed that replacement under a decision made about its predecessor,
    /// and the owner was never shown the row that disappeared. A row whose
    /// timestamp has moved is left in place to be reviewed on its own terms.
    pub fn discard_proposals(&mut self, tokens: &[(u64, Address, DateTime<Utc>)]) -> Result<u64> {
        // One transaction, as [`Self::insert_all_absent`] is and for the same
        // reason: a rejection covers as many rows as an acceptance does, and
        // the per-row autocommit made the owner wait through a filesystem sync
        // for each of them.
        let transaction = self.database.connection.transaction()?;
        let mut removed = 0;
        for (chain_id, address, proposed_at) in tokens {
            removed += transaction.execute(
                "DELETE FROM token_proposals
                 WHERE chain_id = ?1 AND address = ?2 AND proposed_at = ?3",
                params![
                    i64::try_from(*chain_id).context("chain ID out of range")?,
                    Blob(*address),
                    Millis(*proposed_at)
                ],
            )?;
        }
        transaction.commit()?;
        Ok(u64::try_from(removed).unwrap_or_default())
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

    /// Find confirmed tokens by symbol, name, or address.
    ///
    /// An address query matches exactly rather than as a substring: addresses
    /// share long hex runs, and a partial match would answer a question about
    /// one token with a different one. Symbol and name match on substring,
    /// case-insensitively, which is how a person actually remembers a token.
    ///
    /// Only confirmed rows are searched. A pending suggestion is not yet a
    /// token as far as anything outside the review screen is concerned.
    pub fn search(
        &self,
        query: &str,
        chain_id: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredToken>> {
        let query = query.trim();
        ensure!(!query.is_empty(), "a search needs something to search for");
        let limit = i64::try_from(limit.min(1_000)).unwrap_or(1_000);
        // An address is matched as itself, as the exact bytes stored.
        let address = Address::from_str(query).ok().map(Blob);
        let pattern = format!("%{}%", escape_like(&query.to_lowercase()));
        let chain = chain_id
            .map(|chain| i64::try_from(chain).context("chain ID out of range"))
            .transpose()?;
        let mut statement = self.database.connection.prepare(
            "SELECT chain_id, address, symbol, name, decimals, source, added_at,
                    approximate_usd_price
             FROM tokens
             WHERE (?1 IS NULL OR chain_id = ?1)
               AND (
                     address = ?2
                  OR lower(symbol) LIKE ?3 ESCAPE '\\'
                  OR lower(name) LIKE ?3 ESCAPE '\\'
               )
             ORDER BY
               -- Exact symbol matches first: someone typing USDC wants USDC,
               -- not every token whose name happens to contain it.
               CASE WHEN lower(symbol) = ?4 THEN 0
                    WHEN address = ?2 THEN 0
                    ELSE 1 END,
               length(symbol),
               chain_id, address
             LIMIT ?5",
        )?;
        let mapped = statement.query_map(
            params![chain, address, pattern, query.to_lowercase(), limit],
            row_to_token,
        )?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
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
                "SELECT chain_id, address, symbol, name, decimals, source, added_at,
                    approximate_usd_price
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
                "SELECT chain_id, address, symbol, name, decimals, source, added_at,
                    approximate_usd_price
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
    // No fallback for an unparseable address: the column holds 20 bytes or the
    // row does not exist, so checksumming cannot fail.
    let address: Address = row.blob(1)?;
    Ok(StoredToken {
        chain_id: chain_id.to_string(),
        address: address.to_checksum(None),
        symbol: row.get(2)?,
        name: row.get(3)?,
        decimals: row
            .get::<_, Option<i64>>(4)?
            .and_then(|value| u8::try_from(value).ok()),
        source: row.get(5)?,
        added_at: row.time(6)?,
        // A price that is not finite is not a price. The column check refuses
        // a negative one, and a stored NaN would sort a row into an arbitrary
        // place forever, so anything else reads as "the owner has not said".
        approximate_usd_price: row
            .get::<_, Option<f64>>(7)?
            .filter(|price| price.is_finite() && *price >= 0.0),
    })
}

/// One token balance line in a portfolio.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
pub struct PortfolioToken {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    /// Raw balance in the token's smallest unit, as a decimal string.
    pub balance: String,
    /// Roughly what one whole token is worth, as the owner recorded it. See
    /// [`StoredToken::approximate_usd_price`]: display data only, and the
    /// balance beside it is the exact figure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approximate_usd_price: Option<f64>,
}

/// Balances for one address across the tokens known to the database.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
pub struct Portfolio {
    pub address: String,
    pub chain_id: String,
    pub network: String,
    /// Native balance in wei.
    pub native_balance: String,
    /// The block every balance here was read at. One lens call answers the
    /// whole portfolio, so this is simply the block that call saw rather than
    /// a block several batches had to be held to.
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

/// Read native and token balances for `address` over the tokens the owner's
/// database knows, through the same lens path as an explicit balances read.
///
/// Only nonzero balances come back, and the native balance arrives with them:
/// the lens reads `address(0)` as the owner's native balance, so one call
/// answers both instead of spending a separate Multicall3 slot on it.
pub async fn read_portfolio(
    network: &NetworkConfig,
    address: Address,
    known_tokens: &[StoredToken],
    fork: Option<&ForkPreface>,
) -> Result<Portfolio> {
    let checked: Vec<&StoredToken> = known_tokens.iter().take(MAX_PORTFOLIO_TOKENS).collect();
    let skipped = known_tokens.len().saturating_sub(checked.len());

    // `address(0)` is the lens's native-balance sentinel, and a database row
    // may legitimately name it too. Asking once and keeping the answer as the
    // native balance is what stops the same wei being reported twice — once
    // as the chain's currency and again as a token called "ETH".
    let mut seen = std::collections::BTreeSet::new();
    let mut requested = vec![Address::ZERO];
    seen.insert(Address::ZERO);
    let mut rows: Vec<(Address, &StoredToken)> = Vec::with_capacity(checked.len());
    for token in &checked {
        let parsed =
            Address::from_str(&token.address).context("stored token address is invalid")?;
        rows.push((parsed, token));
        if seen.insert(parsed) {
            requested.push(parsed);
        }
    }

    let read = fetch_nonzero_balances(network, address, &requested, fork).await?;
    let balances: std::collections::BTreeMap<Address, U256> = read.balances.into_iter().collect();

    let native_balance = balances
        .get(&Address::ZERO)
        .copied()
        .unwrap_or(U256::ZERO)
        .to_string();
    let tokens = rows
        .into_iter()
        .filter(|(parsed, _)| *parsed != Address::ZERO)
        .filter_map(|(parsed, token)| {
            let balance = balances.get(&parsed)?;
            Some(PortfolioToken {
                address: token.address.clone(),
                symbol: token.symbol.clone(),
                name: token.name.clone(),
                decimals: token.decimals,
                balance: balance.to_string(),
                approximate_usd_price: token.approximate_usd_price,
            })
        })
        .collect();

    Ok(Portfolio {
        address: address.to_checksum(None),
        chain_id: network.chain_id.to_string(),
        network: network.name.clone(),
        native_balance,
        block_number: read
            .block_number
            .context("portfolio read produced no block number")?,
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
    /// The block every balance here was read at. The first Multicall3 batch
    /// reports it and each later batch — including every batch of the
    /// `balanceOf` fallback — is sent against it.
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

    let read = fetch_nonzero_balances(network, owner, &tokens, fork).await?;
    Ok(TokenBalances {
        address: owner.to_checksum(None),
        chain_id: network.chain_id.to_string(),
        network: network.name.clone(),
        block_number: read
            .block_number
            .context("balances read produced no block number")?,
        balances: read
            .balances
            .iter()
            .map(|(token, amount)| TokenBalance {
                token: token.to_checksum(None),
                balance: amount.to_string(),
            })
            .collect(),
        tokens_checked: tokens.len() as u64,
        source: read.source.into(),
        fork: None,
    })
}

/// One chunked balance read, and how it was answered.
struct NonzeroBalances {
    block_number: Option<String>,
    /// Only tokens with a nonzero balance. `address(0)` is the native balance.
    balances: Vec<(Address, U256)>,
    source: &'static str,
}

/// Read nonzero balances for an explicit token list.
///
/// One code path for every balance this wallet reports, because the checks
/// that make a lens answer trustworthy — that it named no token nobody asked
/// about, and returned no more entries than were requested — are only worth
/// writing once. A second copy is a copy that can be updated alone.
///
/// The lens answers a whole chunk in one `eth_call` and returns only the
/// nonzero entries, so the response stays small no matter how many tokens
/// were asked about. That is the difference that matters against a public
/// endpoint: the per-token `balanceOf` fan-out this replaces sent five times
/// as many requests for the same answer, and every one of them was another
/// chance to be rate-limited or to ask for a block the node had already
/// pruned.
async fn fetch_nonzero_balances(
    network: &NetworkConfig,
    owner: Address,
    tokens: &[Address],
    fork: Option<&ForkPreface>,
) -> Result<NonzeroBalances> {
    crate::rpc::try_clients(network, |client| async move {
        // Every attempt re-verifies the chain, which is the rule the rest of
        // the failover paths keep and this one did not. Nothing further down
        // would have caught it: Multicall3 and the lens are deployed at the
        // same addresses everywhere, `balanceOf` is a standard selector, and
        // the structural checks below ask whether the answer is about the
        // tokens that were requested — never which chain it came from. So a
        // fallback pointed at another EVM chain answered, and the result was
        // labelled with the configured network's name, chain ID, and a block
        // number from a chain nobody asked about.
        crate::rpc::ensure_serving_chain(client.as_ref(), network.chain_id).await?;
        nonzero_balances_through(network, client.as_ref(), owner, tokens, fork).await
    })
    .await
}

/// The chunked read itself, against one endpoint.
///
/// Split out so failover can run the whole read again elsewhere rather than
/// half of it: the chunks after the first are pinned to the block the first
/// one reported, so a chunk that fails partway cannot simply be re-sent to
/// another endpoint and appended — the answer would mix two chains' views of
/// one wallet.
async fn nonzero_balances_through(
    network: &NetworkConfig,
    client: &dyn ChainClient,
    owner: Address,
    tokens: &[Address],
    fork: Option<&ForkPreface>,
) -> Result<NonzeroBalances> {
    let mut block_number: Option<String> = None;
    let mut pinned = None;
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
        let results = aggregate(network, client, calls, fork, pinned).await?;
        let mut results = results.into_iter();
        if index == 0 {
            let block = results.next().context("missing block number result")?;
            ensure!(block.success, "Multicall3 getBlockNumber failed");
            let number = getBlockNumberCall::abi_decode_returns(&block.returnData)?;
            pinned = Some(pin(number)?);
            block_number = Some(number.to_string());
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
        // The lens was asked about a bounded list, so it cannot answer with
        // more entries than were asked about, and it cannot answer about a
        // token nobody asked about. An endpoint that says otherwise is not
        // returning a lens result — this is a structural mismatch, which is
        // the class the threat model expects local validation to catch, as
        // distinct from a coherent lie about a balance it was asked for.
        let requested: std::collections::BTreeSet<Address> = chunk.iter().copied().collect();
        ensure!(
            decoded.balances.len() <= chunk.len(),
            "TokenDataFetcher returned {} balances for {} requested tokens",
            decoded.balances.len(),
            chunk.len()
        );
        for entry in decoded.balances {
            ensure!(
                requested.contains(&entry.token),
                "TokenDataFetcher returned a balance for {}, which was not requested",
                entry.token.to_checksum(None)
            );
            balances.push((entry.token, entry.amount));
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
            let results = aggregate(network, client, calls, fork, pinned).await?;
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
                    balances.push((*token, balance));
                }
            }
        }
        "multicall_balance_of"
    };

    Ok(NonzeroBalances {
        block_number,
        balances,
        source,
    })
}

/// The block every later batch of one read is sent against, from the number
/// the first batch reported. A number that does not fit `u64` is not a block
/// this chain has: refusing beats pinning to something else.
fn pin(number: U256) -> Result<BlockId> {
    Ok(BlockId::number(u64::try_from(number).context(
        "Multicall3 reported a block number that does not fit u64",
    )?))
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
/// `block` pins the read. The first batch of a multi-batch read learns the
/// block number and every later batch is sent against it, so the number
/// reported beside the balances is the number they were all read at. A fork
/// read ignores it: `execute_reads` is already pinned to the fork's parent.
async fn aggregate(
    network: &NetworkConfig,
    client: &dyn ChainClient,
    calls: Vec<TokenCall3>,
    fork: Option<&ForkPreface>,
    block: Option<BlockId>,
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
    let bytes = tokio::time::timeout(
        RPC_TIMEOUT,
        client.call(request, block.unwrap_or_else(BlockId::latest)),
    )
    .await
    .context("Multicall3 request timed out")??;
    aggregate3Call::abi_decode_returns(&bytes).context("Multicall3 returned undecodable data")
}

/// Token names and symbols are attacker-controlled contract output; strip
/// control characters and cap length before they reach any display or store.
/// Neutralize `LIKE` wildcards in user input, so a query of `%` searches for a
/// literal percent sign instead of returning the whole database.
fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub(crate) fn sanitize(text: &str) -> String {
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
            // The shared parser rather than a second copy of the same rules.
            // This one had drifted already: it never bounded the length, so a
            // filter could hand over an arbitrarily long run of digits to be
            // scanned before being rejected for not fitting a uint64.
            Self::Text(text) => crate::input_validation::parse_chain_id(text),
        }
    }
}

#[cfg(test)]
#[path = "token_store_test.rs"]
mod tests;
