use crate::{
    chain_client::{ChainClient, SharedChainClient},
    config::{NetworkConfig, WalletMetadata},
    fork::{ForkContext, ForkPreface, native_balance},
    simulation::CANONICAL_CALIBUR,
};
use alloy::{
    eips::{BlockId, BlockNumberOrTag},
    network::TransactionResponse as _,
    primitives::{Address, B256, Bytes},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::{TransactionRequest, simulate::SimulatePayload},
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const RPC_TIMEOUT: Duration = Duration::from_secs(15);

/// RPC clients pooled per endpoint URL, the same way [`crate::plan_fetch`]
/// pools its reference-fetch clients. Bounded and evicted oldest-first so a
/// configuration with the maximum 192 networks of 8 RPC URLs each — or a
/// sequence of proposed networks a dapp keeps changing — cannot grow this
/// without bound. Comfortably above the number of distinct endpoints
/// `rpc_test.rs` registers against this same process-wide pool over a test
/// run, so an unrelated test's endpoints do not evict this test's own before
/// it reads them back.
type PooledRpcClient = (url::Url, SharedChainClient);

static RPC_CLIENTS: OnceLock<Mutex<Vec<PooledRpcClient>>> = OnceLock::new();
const MAX_POOLED_CLIENTS: usize = 128;

struct RpcChainClient {
    provider: DynProvider,
    endpoint: url::Url,
}

impl RpcChainClient {
    fn result<T, E: std::fmt::Display>(&self, result: std::result::Result<T, E>) -> Result<T> {
        rpc_result(&self.endpoint, result)
    }
}

#[async_trait]
impl ChainClient for RpcChainClient {
    async fn chain_id(&self) -> Result<u64> {
        self.result(self.provider.get_chain_id().await)
    }

    async fn block_number(&self) -> Result<u64> {
        self.result(self.provider.get_block_number().await)
    }

    async fn block_by_number(
        &self,
        block: BlockNumberOrTag,
    ) -> Result<Option<alloy::rpc::types::Block>> {
        self.result(self.provider.get_block_by_number(block).await)
    }

    async fn balance(&self, address: Address, block: BlockId) -> Result<alloy::primitives::U256> {
        self.result(self.provider.get_balance(address).block_id(block).await)
    }

    async fn transaction_count(&self, address: Address, block: BlockId) -> Result<u64> {
        self.result(
            self.provider
                .get_transaction_count(address)
                .block_id(block)
                .await,
        )
    }

    async fn code(&self, address: Address, block: BlockId) -> Result<Bytes> {
        self.result(self.provider.get_code_at(address).block_id(block).await)
    }

    async fn call(&self, request: TransactionRequest, block: BlockId) -> Result<Bytes> {
        self.result(self.provider.call(request).block(block).await)
    }

    async fn simulate_v1(
        &self,
        payload: SimulatePayload,
        block_number: Option<u64>,
    ) -> Result<Vec<alloy::rpc::types::simulate::SimulatedBlock>> {
        let request = self.provider.simulate(&payload);
        self.result(match block_number {
            Some(number) => request.number(number).await,
            None => request.await,
        })
    }

    async fn estimate_eip1559_fees(&self) -> Result<alloy::eips::eip1559::Eip1559Estimation> {
        self.result(self.provider.estimate_eip1559_fees().await)
    }

    async fn estimate_gas(&self, request: TransactionRequest) -> Result<u64> {
        self.result(self.provider.estimate_gas(request).await)
    }

    async fn transaction_receipt(
        &self,
        hash: B256,
    ) -> Result<Option<alloy::rpc::types::TransactionReceipt>> {
        self.result(self.provider.get_transaction_receipt(hash).await)
    }

    async fn transaction_by_hash(
        &self,
        hash: B256,
    ) -> Result<Option<alloy::rpc::types::Transaction>> {
        self.result(self.provider.get_transaction_by_hash(hash).await)
    }

    async fn send_transaction(&self, bytes: Bytes) -> Result<B256> {
        self.result(self.provider.send_raw_transaction(&bytes).await)
            .map(|pending| *pending.tx_hash())
    }
}

fn rpc_result<T, E: std::fmt::Display>(
    endpoint: &url::Url,
    result: std::result::Result<T, E>,
) -> Result<T> {
    result.map_err(|error| rpc_error(endpoint, &error))
}

/// A chain client backed by one configured RPC endpoint.
///
/// Type-erased because failover hands the same closure a different client per
/// attempt, and the RPC adapter's own type names the filler stack rather than
/// anything a caller cares about. Pooled by endpoint: every read in this
/// module goes through this function, including the once-a-second poll
/// `wallet_wait_for_execution` runs while a caller waits on confirmation, so
/// building a fresh provider (and the `reqwest::Client` connection pool
/// underneath it) on every call meant every one of those reads paid a new TCP
/// handshake, and a new TLS handshake for an `https` endpoint, instead of
/// reusing one already open to the same endpoint.
async fn client_for(endpoint: &url::Url) -> Result<SharedChainClient> {
    let pool = RPC_CLIENTS.get_or_init(|| Mutex::new(Vec::new()));
    {
        let entries = pool.lock().expect("endpoint provider pool lock");
        if let Some((_, client)) = entries.iter().find(|(existing, _)| existing == endpoint) {
            return Ok(client.clone());
        }
    }

    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(url::Host::Domain(domain)) = endpoint.host() {
        let addresses = crate::plan_fetch::public_endpoint_addresses(endpoint, "RPC URL").await?;
        builder = builder.resolve_to_addrs(domain, &addresses);
    }
    let http = builder.build().context("failed to build RPC HTTP client")?;
    let client: SharedChainClient = Arc::new(RpcChainClient {
        provider: ProviderBuilder::new()
            .connect_reqwest(http, endpoint.clone())
            .erased(),
        endpoint: endpoint.clone(),
    });
    let mut entries = pool.lock().expect("endpoint provider pool lock");
    if let Some((_, existing)) = entries.iter().find(|(existing, _)| existing == endpoint) {
        return Ok(existing.clone());
    }
    if entries.len() >= MAX_POOLED_CLIENTS {
        entries.remove(0);
    }
    entries.push((endpoint.clone(), client.clone()));
    Ok(client)
}

/// Run one read against the network's clients, in the selected order, until
/// one of them answers.
///
/// This is the whole failover mechanism, and it is deliberately per-request
/// rather than a sticky choice of endpoint: a public RPC does not fail as a
/// unit. It rate-limits one request and serves the next, loses its archive
/// state while still reporting a head, or answers reads and refuses
/// `eth_simulateV1`. A wallet that picked one endpoint at startup would ride
/// that endpoint's bad minute all the way to a refusal to sign.
///
/// `operation` must be safe to run more than once. Every caller here is a
/// read; broadcasting is not routed through this, because deciding what a
/// failed send meant needs the endpoint that failed it — see
/// [`crate::execution`].
///
/// Failures accumulate rather than replace each other. When no endpoint
/// answers, the error names every one that was tried and what it said, because
/// "RPC request failed" about an unnamed member of a list of eight is not a
/// diagnosis anyone can act on.
pub async fn try_clients<T, F, Fut>(network: &NetworkConfig, operation: F) -> Result<T>
where
    F: Fn(SharedChainClient) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut failures = Vec::new();
    for endpoint in endpoint_order(network) {
        let result = match client_for(endpoint).await {
            Ok(client) => operation(client).await,
            Err(error) => Err(error),
        };
        match result {
            Ok(value) => return Ok(value),
            Err(error) => failures.push((endpoint, error)),
        }
    }
    Err(all_endpoints_failed(network, &failures))
}

/// The clients to attempt for one coherent operation, already arranged by
/// the network's ordered or random policy.
///
/// Keeping this here means simulation and submission never inspect URLs or
/// reimplement selection. A future non-RPC factory can supply the same client
/// objects without changing either operation.
pub async fn clients_for(network: &NetworkConfig) -> Result<Vec<SharedChainClient>> {
    let mut clients = Vec::new();
    let mut failures = Vec::new();
    for endpoint in endpoint_order(network) {
        // One endpoint that cannot even be built is a reason to leave it out
        // of the attempt order, not a reason to fail the request. Building a
        // client resolves the endpoint's domain and requires it to answer with
        // a public address, so a provider that has shut its domain down, or a
        // resolver that refuses it, fails here rather than on a call — and
        // taking the whole network down for that would mean a list of six
        // endpoints had six ways to fail where a list of one had one. The
        // point of listing several is that any of them can carry the request.
        match client_for(endpoint).await {
            Ok(client) => clients.push(client),
            Err(error) => failures.push((endpoint, error)),
        }
    }
    // Nothing to attempt is still an error, and it is the one failover already
    // reports: every endpoint this network has, with the reason each refused.
    if clients.is_empty() {
        return Err(all_endpoints_failed(network, &failures));
    }
    Ok(clients)
}

/// The order this request should visit the endpoints in.
///
/// Configured order, unless the network asks for a fresh random order.
fn endpoint_order(network: &NetworkConfig) -> Vec<&url::Url> {
    let mut order: Vec<&url::Url> = network.rpc_urls.iter().collect();
    if network.rpc_strategy.shuffles() {
        shuffle(&mut order);
    }
    order
}

/// Fisher-Yates over the thread RNG. Written out rather than pulled from
/// `rand`'s slice extension so the crate keeps its single, auditable use of
/// randomness.
fn shuffle<T>(items: &mut [T]) {
    use rand::TryRng as _;
    for index in (1..items.len()).rev() {
        let mut bytes = [0_u8; 8];
        // A failure to read randomness leaves the order as it is: configured
        // order is a worse privacy answer than a shuffled one, never a wrong
        // one, and no request should fail because entropy was unavailable.
        if rand::rng().try_fill_bytes(&mut bytes).is_err() {
            return;
        }
        let pick =
            usize::try_from(u64::from_le_bytes(bytes) % (index as u64 + 1)).unwrap_or_default();
        items.swap(index, pick);
    }
}

/// The error raised when every endpoint a network lists has been tried.
pub(crate) fn all_endpoints_failed(
    network: &NetworkConfig,
    failures: &[(&url::Url, anyhow::Error)],
) -> anyhow::Error {
    let mut message = format!(
        "all {} RPC endpoints configured for {} failed",
        failures.len(),
        network.name
    );
    for (endpoint, error) in failures {
        let label = rpc_endpoint_label(endpoint);
        let detail = redact_endpoint_text(endpoint, &format!("{error:#}"));
        let _ = write!(message, "\n  {label}: {detail}");
    }
    anyhow::anyhow!(message)
}

/// Confirm a client is serving the chain the network claims, and fail in a
/// way failover understands.
///
/// Checked on every endpoint rather than once for the network: the list is
/// several independent services, and one of them being pointed at the wrong
/// chain must disqualify that endpoint instead of the request.
pub async fn ensure_serving_chain(client: &dyn ChainClient, expected: u64) -> Result<()> {
    let observed = with_timeout(client.chain_id()).await?;
    ensure!(
        observed == expected,
        "RPC reports chain {observed}, not {expected}"
    );
    Ok(())
}

/// The canonical Multicall3 deployment, at the same address on every chain.
pub const MULTICALL3_ADDRESS: Address =
    alloy::primitives::address!("cA11bde05977b3631167028862bE2a173976CA11");

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
    pub block_hash: B256,
    /// Head observed by the same RPC client as the receipt. Keeping the two
    /// reads on one client avoids manufacturing confirmation depth by mixing
    /// endpoints at different chain views.
    pub head_block_number: u64,
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
    #[must_use]
    pub fn confirmations(&self) -> u64 {
        self.head_block_number
            .saturating_sub(self.block_number)
            .saturating_add(1)
    }

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
    try_clients(network, |client| async move {
        ensure_serving_chain(client.as_ref(), network.chain_id).await
    })
    .await
}

pub async fn wallet_status(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    fork: Option<&ForkPreface>,
) -> Result<WalletStatus> {
    if let Some(preface) = fork {
        return fork_wallet_status(wallet, network, preface).await;
    }
    let (chain_id, balance, transaction_count, code) = try_clients(network, |client| async move {
        let (chain_id, balance, transaction_count, code) = tokio::try_join!(
            with_timeout(client.chain_id()),
            with_timeout(client.balance(wallet.address, BlockId::latest())),
            with_timeout(client.transaction_count(wallet.address, BlockId::latest())),
            with_timeout(client.code(wallet.address, BlockId::latest())),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        Ok((chain_id, balance, transaction_count, code))
    })
    .await?;
    Ok(WalletStatus {
        wallet_id: wallet.id.clone(),
        address: wallet.address.to_checksum(None),
        network: network.name.clone(),
        chain_id: chain_id.to_string(),
        native_balance: balance.to_string(),
        transaction_count,
        delegated_implementation: delegated_implementation(&code)
            .map(|address| address.to_checksum(None)),
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
    let pinned = BlockId::number(preface.parent.number);
    let (chain_id, transaction_count, code) = try_clients(network, |client| async move {
        let (chain_id, transaction_count, code) = tokio::try_join!(
            with_timeout(client.chain_id()),
            with_timeout(client.transaction_count(wallet.address, pinned)),
            with_timeout(client.code(wallet.address, pinned)),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        Ok((chain_id, transaction_count, code))
    })
    .await?;
    let (balance, _) = native_balance(network, preface, wallet.address).await?;
    let delegated = if preface.requires_calibur() {
        Some(CANONICAL_CALIBUR.to_checksum(None))
    } else {
        delegated_implementation(&code).map(|address| address.to_checksum(None))
    };
    Ok(WalletStatus {
        wallet_id: wallet.id.clone(),
        address: wallet.address.to_checksum(None),
        network: network.name.clone(),
        chain_id: chain_id.to_string(),
        native_balance: balance.to_string(),
        transaction_count,
        delegated_implementation: delegated,
        fork: None,
        transaction_count_is_pinned_parent: Some(true),
    })
}

/// Refuse a receipt whose values the lifecycle cannot store.
///
/// `block_number` and `gas_used` arrive as `u64` and end up in `INTEGER`
/// columns, which are signed. A value above `i64::MAX` is not a plausible
/// block height or gas figure on any chain — it is an endpoint answering
/// nonsense — and the conversion used to fail at the far end, inside
/// `PendingStore::finalize`, after this answer had already been accepted as
/// the truth about the chain. The row then stayed `broadcast` forever, holding
/// the wallet's one in-flight slot for that chain, and asking again reached
/// the same endpoint and got the same answer.
///
/// Checked here instead, inside the failover closure, so an endpoint that
/// answers this way has failed and the next one gets its turn.
fn storable_receipt_fields(block_number: u64, gas_used: u64) -> Result<()> {
    ensure!(
        i64::try_from(block_number).is_ok(),
        "RPC reported a receipt at block {block_number}, which is not a block height"
    );
    ensure!(
        i64::try_from(gas_used).is_ok(),
        "RPC reported a receipt burning {gas_used} gas, which no block could hold"
    );
    Ok(())
}

pub async fn transaction_receipt(
    network: &NetworkConfig,
    transaction_hash: &str,
) -> Result<Option<ReceiptStatus>> {
    let hash = B256::from_str(transaction_hash).context("invalid transaction hash")?;
    try_clients(network, |client| async move {
        transaction_receipt_through(client.as_ref(), network.chain_id, hash).await
    })
    .await
}

/// Read and validate a receipt without changing clients midway through a
/// send-and-reconcile attempt.
pub(crate) async fn transaction_receipt_through(
    client: &dyn ChainClient,
    expected_chain_id: u64,
    hash: B256,
) -> Result<Option<ReceiptStatus>> {
    let (chain_id, receipt, head_block_number) = tokio::try_join!(
        with_timeout(client.chain_id()),
        with_timeout(client.transaction_receipt(hash)),
        with_timeout(client.block_number()),
    )?;
    ensure!(
        chain_id == expected_chain_id,
        "RPC reports chain {chain_id}, not {expected_chain_id}"
    );
    // Inside the closure, so an unusable receipt is this endpoint failing
    // rather than the whole lookup failing on its word.
    receipt
        .map(|receipt| {
            // The receipt has to be the receipt for the hash that was
            // asked about. Nothing else here establishes that: the request
            // names a hash, and the response is taken as the answer to it
            // on the endpoint's word alone.
            //
            // Every terminal settlement in the wallet runs through this
            // one function. `observe` treats any receipt as `Mined`,
            // `reconcile_cancelling` finalizes the original or marks the
            // request cancelled from one, and none of those states is ever
            // reconciled again — leaving them releases the wallet's
            // in-flight slot for that chain. So an endpoint returning some
            // unrelated transaction's receipt settles a still-live
            // envelope as confirmed, reverted, or cancelled, and the real
            // one goes on to mine with the wallet no longer watching it.
            ensure!(
                receipt.transaction_hash == hash,
                "RPC returned a receipt for {:#x} rather than the requested {hash:#x}",
                receipt.transaction_hash
            );
            let block_number = receipt
                .block_number
                .context("RPC returned a receipt without a block number")?;
            let block_hash = receipt
                .block_hash
                .context("RPC returned a receipt without a block hash")?;
            storable_receipt_fields(block_number, receipt.gas_used)?;
            Ok(ReceiptStatus {
                succeeded: receipt.status(),
                block_number,
                block_hash,
                head_block_number,
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
    /// The block the receipt names. Carried because a caller reporting a
    /// receipt onward — EIP-5792's `wallet_getCallsStatus` does — has to say
    /// which block it read, and a height alone does not survive a reorg.
    pub block_hash: B256,
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
    let receipt = try_clients(network, |client| async move {
        let (chain_id, receipt) = tokio::try_join!(
            with_timeout(client.chain_id()),
            with_timeout(client.transaction_receipt(hash)),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        // The same check as its twin above, and for the same reason: this
        // receipt settles a lifecycle row too.
        if let Some(receipt) = &receipt {
            let block_number = receipt
                .block_number
                .context("RPC returned a receipt without a block number")?;
            storable_receipt_fields(block_number, receipt.gas_used)?;
        }
        Ok(receipt)
    })
    .await?;
    receipt
        .map(|receipt| {
            Ok(ReceiptDetails {
                succeeded: receipt.status(),
                block_number: receipt
                    .block_number
                    .context("RPC returned a receipt without a block number")?,
                block_hash: receipt
                    .block_hash
                    .context("RPC returned a receipt without a block hash")?,
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
    try_clients(network, |client| async move {
        let (chain_id, block_number) = tokio::try_join!(
            with_timeout(client.chain_id()),
            with_timeout(client.block_number()),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        Ok(block_number)
    })
    .await
}

/// The account's mined transaction count (the `latest` tag): the next nonce
/// the chain itself has settled. Deliberately not the `pending` view —
/// replacement detection must only trust nonces consumed by mined blocks,
/// because a competing mempool transaction at the same nonce has not won yet.
pub async fn mined_transaction_count(network: &NetworkConfig, address: Address) -> Result<u64> {
    try_clients(network, |client| async move {
        let (chain_id, count) = tokio::try_join!(
            with_timeout(client.chain_id()),
            with_timeout(client.transaction_count(address, BlockId::latest())),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        Ok(count)
    })
    .await
}

/// Return whether the configured RPC already knows the exact transaction
/// hash. This is used only to recover a persisted submission lease; callers
/// must still rebroadcast the already-signed bytes rather than prepare a new
/// transaction when the hash is unknown.
pub async fn transaction_known(network: &NetworkConfig, transaction_hash: &str) -> Result<bool> {
    let hash = B256::from_str(transaction_hash).context("invalid transaction hash")?;
    try_clients(network, |client| async move {
        let (chain_id, transaction) = tokio::try_join!(
            with_timeout(client.chain_id()),
            with_timeout(client.transaction_by_hash(hash)),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        Ok(transaction.is_some_and(|transaction| transaction.tx_hash() == hash))
    })
    .await
}

async fn with_timeout<T>(future: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(RPC_TIMEOUT, future)
        .await
        .context("RPC request timed out")?
}

/// An endpoint label safe to expose to agents, logs, and error surfaces.
///
/// Scheme, host, and port identify which provider failed without exposing a
/// bearer credential commonly embedded in a URL path or query string.
#[must_use]
pub fn rpc_endpoint_label(endpoint: &url::Url) -> String {
    let mut label = endpoint.clone();
    if label.set_username("").is_err() || label.set_password(None).is_err() {
        return format!("{}://<redacted>/", endpoint.scheme());
    }
    label.set_path("/");
    label.set_query(None);
    label.set_fragment(None);
    label.to_string()
}

fn redact_endpoint_text(endpoint: &url::Url, text: &str) -> String {
    let mut redacted = text.replace(endpoint.as_str(), &rpc_endpoint_label(endpoint));
    // Transport stacks do not all format URLs alike. Some print the complete
    // URL, while others put the path or query in a separate cause. Remove
    // those credential-bearing components independently as well.
    if endpoint.path() != "/" && !endpoint.path().is_empty() {
        redacted = redacted.replace(endpoint.path(), "/<redacted>");
    }
    if let Some(query) = endpoint.query()
        && !query.is_empty()
    {
        redacted = redacted.replace(query, "<redacted>");
    }
    redacted
}

/// One shared spelling for a failed RPC request, preserving the provider's
/// useful diagnostic while replacing its complete credential-bearing URL.
pub fn rpc_error(endpoint: &url::Url, error: &impl std::fmt::Display) -> anyhow::Error {
    let error = redact_endpoint_text(endpoint, &error.to_string());
    anyhow::anyhow!("RPC request failed: {error}")
}

/// Parses an EIP-7702 delegation designator: the 23-byte runtime code form
/// `0xef0100 || address`. The single implementation for every module that
/// inspects account code.
#[must_use]
pub fn delegated_implementation(code: &Bytes) -> Option<Address> {
    (code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00]))
        .then(|| Address::from_slice(&code[3..]))
}

#[cfg(test)]
#[path = "rpc_test.rs"]
mod tests;
