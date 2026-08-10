use crate::{
    config::{NetworkConfig, WalletMetadata},
    fork::{ForkContext, ForkPreface, native_balance},
    simulation::CANONICAL_CALIBUR,
};
use alloy::{
    eips::BlockId,
    primitives::{Address, B256, Bytes},
    providers::{DynProvider, Provider, ProviderBuilder},
};
use anyhow::{Context, Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const RPC_TIMEOUT: Duration = Duration::from_secs(15);
/// Shorter than [`RPC_TIMEOUT`], because this one is paid `agree` times over
/// on a path a person may be waiting on, and a slow endpoint here costs a
/// second opinion rather than the answer itself.
const FEE_ESTIMATE_TIMEOUT: Duration = Duration::from_secs(8);

/// Providers pooled per endpoint URL, the same way [`crate::plan_fetch`]
/// pools its reference-fetch clients. Bounded and evicted oldest-first so a
/// configuration with the maximum 192 networks of 8 RPC URLs each — or a
/// sequence of proposed networks a dapp keeps changing — cannot grow this
/// without bound. Comfortably above the number of distinct endpoints
/// `rpc_test.rs` registers against this same process-wide pool over a test
/// run, so an unrelated test's endpoints do not evict this test's own before
/// it reads them back.
static ENDPOINT_PROVIDERS: OnceLock<Mutex<Vec<(url::Url, DynProvider)>>> = OnceLock::new();
const MAX_POOLED_PROVIDERS: usize = 128;

/// A provider for one configured endpoint.
///
/// Type-erased because failover hands the same closure a different provider
/// per attempt, and the builder's own type names the filler stack rather than
/// anything a caller cares about. Pooled by endpoint: every read in this
/// module goes through this function, including the once-a-second poll
/// `wallet_wait_for_execution` runs while a caller waits on confirmation, so
/// building a fresh provider (and the `reqwest::Client` connection pool
/// underneath it) on every call meant every one of those reads paid a new TCP
/// handshake, and a new TLS handshake for an `https` endpoint, instead of
/// reusing one already open to the same endpoint.
#[must_use]
pub fn provider_for(endpoint: &url::Url) -> DynProvider {
    let pool = ENDPOINT_PROVIDERS.get_or_init(|| Mutex::new(Vec::new()));
    let mut entries = pool.lock().expect("endpoint provider pool lock");
    if let Some(position) = entries
        .iter()
        .position(|(existing, _)| existing == endpoint)
    {
        return entries[position].1.clone();
    }
    let provider = ProviderBuilder::new()
        .connect_http(endpoint.clone())
        .erased();
    if entries.len() >= MAX_POOLED_PROVIDERS {
        entries.remove(0);
    }
    entries.push((endpoint.clone(), provider.clone()));
    provider
}

/// Run one read against the network's endpoints, in configured order, until
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
pub async fn try_endpoints<T, F, Fut>(network: &NetworkConfig, operation: F) -> Result<T>
where
    F: Fn(DynProvider) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut failures = Vec::new();
    for endpoint in endpoint_order(network) {
        match operation(provider_for(endpoint)).await {
            Ok(value) => return Ok(value),
            Err(error) => failures.push((endpoint, error)),
        }
    }
    Err(all_endpoints_failed(network, &failures))
}

/// The order this request should visit the endpoints in.
///
/// Configured order, unless the network asks for a random one. `m_of_n` is
/// deliberately absent here: it is not an ordering, and the reads that route
/// through [`try_endpoints`] are the ones whose answers cannot be compared —
/// a chain head, a receipt that only one endpoint has seen yet. Those take
/// the first answer under every strategy. Agreement is applied where it means
/// something, by [`agree_across_endpoints`] and by simulation.
pub(crate) fn endpoint_order(network: &NetworkConfig) -> Vec<&url::Url> {
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

/// What a completed round of quorum voting decided.
///
/// There are two quorums in this crate — a generic read in
/// [`agree_across_endpoints`] and a simulation in `simulation.rs` — and they
/// bucket entirely different things. What they must not do differently is
/// *decide*, so the rule lives here and neither of them reasons about it
/// locally. Both used to, and both made the same mistake: accepting the
/// `required`-th matching witness as final, which made a later contradiction
/// unobservable and left "a disagreement is refused" true only when the
/// disagreeing endpoint happened to be visited early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuorumVerdict {
    /// Every endpoint that answered gave the same answer, and at least
    /// `required` of them did. The index is the single bucket.
    Agreed(usize),
    /// Endpoints answered and contradicted each other. Refuse; there is no
    /// basis on which to pick a side.
    Contradicted,
    /// One answer at most, but too few endpoints stood behind it. Carries how
    /// many did, which is what separates "unavailable" from "disagreed".
    TooFewWitnesses(usize),
}

/// Decide a quorum from how many endpoints stood behind each distinct answer.
///
/// Takes counts rather than the answers themselves so the two callers can keep
/// their own bucket types, and so the rule is testable without either of them.
/// Call it only after every configured endpoint has been heard: a verdict
/// computed from a partial tally is the very bug this exists to prevent.
pub(crate) fn quorum_verdict(witness_counts: &[usize], required: usize) -> QuorumVerdict {
    if witness_counts.len() > 1 {
        return QuorumVerdict::Contradicted;
    }
    match witness_counts.first() {
        Some(&count) if count >= required => QuorumVerdict::Agreed(0),
        Some(&count) => QuorumVerdict::TooFewWitnesses(count),
        None => QuorumVerdict::TooFewWitnesses(0),
    }
}

/// Run one read against enough endpoints to satisfy the network's strategy,
/// and return the answer only if that many of them agree.
///
/// Under `ordered` and `random` this is [`try_endpoints`]: one answer, from
/// whichever endpoint answers first. Under `m_of_n` it keeps asking further
/// endpoints until the required number have returned *equal* answers.
///
/// Three outcomes are deliberately distinct:
///
/// - Enough endpoints agreed. The answer is returned.
/// - Endpoints answered but did not agree. The read **fails**, naming the
///   disagreement. There is no basis on which the wallet could pick a side,
///   and picking the majority of two is picking at random; a disagreement
///   between endpoints about a pinned, deterministic read is either a bug or
///   a lie, and both are reasons to stop rather than to continue.
/// - Too few endpoints answered at all. The read fails as unavailable. An
///   endpoint that errors is a missing witness, not a dissenting one, so it
///   never counts toward agreement in either direction.
///
/// Only meaningful for reads that are deterministic across honest endpoints —
/// pinned to a block and free of per-node state. A chain head or a pending
/// nonce legitimately differs between two honest nodes, and requiring those
/// to match would refuse every request.
pub async fn agree_across_endpoints<T, F, Fut>(network: &NetworkConfig, operation: F) -> Result<T>
where
    T: PartialEq,
    F: Fn(DynProvider) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let required = network.rpc_strategy.required_agreement();
    if required <= 1 {
        return try_endpoints(network, operation).await;
    }
    let mut failures = Vec::new();
    // Answers, each with the endpoints that returned it. A second endpoint
    // returning an answer already seen is what agreement means.
    let mut answers: Vec<(T, Vec<&url::Url>)> = Vec::new();
    // Every configured endpoint is asked, including the ones after the
    // `required`-th agreement. Returning at the threshold made the
    // contradiction check below unreachable exactly when it mattered: with
    // `m_of_n(2)` over three endpoints, two agreeing answers ended the loop
    // and the third endpoint — the one that would have disagreed — was never
    // consulted. Whether a disagreement was noticed then depended on the order
    // the endpoints happened to be visited in, which under `random` is a coin
    // flip. "A genuine disagreement fails closed" has to mean every configured
    // witness was heard, or it means nothing.
    //
    // The cost is the difference between `agree` requests and one per
    // configured endpoint. That is what the guarantee costs; an owner who does
    // not want to pay it is asking for `ordered`.
    for endpoint in endpoint_order(network) {
        match operation(provider_for(endpoint)).await {
            Ok(value) => {
                if let Some(slot) = answers.iter_mut().find(|(seen, _)| *seen == value) {
                    slot.1.push(endpoint);
                } else {
                    answers.push((value, vec![endpoint]));
                }
            }
            Err(error) => failures.push((endpoint, error)),
        }
    }
    let counts: Vec<usize> = answers
        .iter()
        .map(|(_, witnesses)| witnesses.len())
        .collect();
    if let QuorumVerdict::Agreed(index) = quorum_verdict(&counts, required) {
        return Ok(answers
            .into_iter()
            .nth(index)
            .map(|(value, _)| value)
            .expect("the bucket the verdict names is still there"));
    }
    // Disagreement outranks unavailability in the message: an owner whose
    // endpoints contradict each other has a different problem, and a more
    // urgent one, than an owner whose endpoints are down.
    if answers.len() > 1 {
        let mut message = format!(
            "the RPC endpoints configured for {} do not agree, so the answer was refused; {} distinct answers from",
            network.name,
            answers.len()
        );
        for (_, witnesses) in &answers {
            let names: Vec<&str> = witnesses.iter().map(|url| url.as_str()).collect();
            let _ = write!(message, "\n  {}", names.join(", "));
        }
        return Err(anyhow::anyhow!(message));
    }
    let reached = answers.first().map_or(0, |(_, witnesses)| witnesses.len());
    let mut message = format!(
        "{} requires {required} endpoints to agree but only {reached} answered",
        network.name
    );
    for (endpoint, error) in &failures {
        let _ = write!(message, "\n  {endpoint}: {error:#}");
    }
    Err(anyhow::anyhow!(message))
}

/// The EIP-1559 fee pair to sign, given what the endpoint that answered the
/// rest of preparation said.
///
/// Under `ordered` and `random` that answer stands: those strategies have
/// already chosen to trust whichever endpoint is first, and asking more of
/// them here would spend requests the owner said they did not want to spend.
///
/// Under `m_of_n` it does not. A fee estimate cannot go through
/// [`agree_across_endpoints`], which requires equality and would refuse every
/// request, because two honest nodes legitimately disagree about what the next
/// block will cost. What is available instead is a median: draw estimates from
/// the configured endpoints until `agree` of them have answered, and take the
/// middle of each field. With a majority honest, the middle value is one no
/// single operator picked — which is the whole of what `m_of_n` promises and
/// what these two fields were getting none of.
///
/// The two fields are taken independently, so the pair is re-ordered
/// afterwards rather than assumed consistent.
pub async fn median_fee_estimate(
    network: &NetworkConfig,
    first_max_fee: u128,
    first_priority_fee: u128,
) -> Result<(u128, u128)> {
    let required = network.rpc_strategy.required_agreement();
    if required <= 1 {
        return Ok((first_max_fee, first_priority_fee));
    }
    let mut failures = Vec::new();
    let mut max_fees = Vec::new();
    let mut priority_fees = Vec::new();
    // Every configured endpoint votes, not the first `required` to answer.
    // See `median_head` below for why stopping early defeats the median.
    for endpoint in endpoint_order(network) {
        match tokio::time::timeout(
            FEE_ESTIMATE_TIMEOUT,
            provider_for(endpoint).estimate_eip1559_fees(),
        )
        .await
        {
            Ok(Ok(estimate)) => {
                max_fees.push(estimate.max_fee_per_gas);
                priority_fees.push(estimate.max_priority_fee_per_gas);
            }
            Ok(Err(error)) => failures.push((endpoint, rpc_error(&error))),
            Err(_) => failures.push((endpoint, anyhow::anyhow!("fee estimate timed out"))),
        }
    }
    ensure!(
        max_fees.len() >= required,
        "{} requires {required} endpoints to agree on the fee but only {} answered",
        network.name,
        max_fees.len()
    );
    let max_fee_per_gas = median(&mut max_fees);
    let max_priority_fee_per_gas = median(&mut priority_fees).min(max_fee_per_gas);
    Ok((max_fee_per_gas, max_priority_fee_per_gas))
}

/// The height a quorum simulation pins to, as the median of what `agree`
/// endpoints say the chain head is.
///
/// `None` under `ordered` and `random`, where there is no quorum to protect
/// and the endpoint that runs the simulation reads its own head.
///
/// Under `m_of_n` there is. The pin used to be whichever height the first
/// endpoint happened to report, and every later endpoint was then held to it —
/// so an endpoint reporting an old head chose the state the whole quorum
/// evaluated against, and the others honestly agreed about that height. The
/// agreement was real and the thing agreed on was the attacker's. A median
/// with a majority honest is a height an honest endpoint reported, and one
/// liar moves it by at most a position.
pub async fn median_head(network: &NetworkConfig) -> Result<Option<u64>> {
    let required = network.rpc_strategy.required_agreement();
    if required <= 1 {
        return Ok(None);
    }
    let mut heads = Vec::new();
    // Every configured endpoint votes, not the first `required` to answer.
    //
    // "A median with a majority honest is a height an honest endpoint
    // reported, and one liar moves it by at most a position" is only true of a
    // median over the whole set. Stopping at `required` made the sample the
    // first responders, and a liar is fast — with `m_of_n(2)` over three
    // endpoints, one stale endpoint answering alongside one current endpoint
    // is half the sample, the lower median takes the stale height, and the
    // honest third endpoint is never asked. Every other endpoint then
    // simulates against the state the liar chose, agrees honestly about it,
    // and the quorum is real while the thing agreed on is the attacker's.
    //
    // This is the same mistake `agree_across_endpoints` made, fixed the same
    // way and at the same cost: one request per configured endpoint.
    for endpoint in endpoint_order(network) {
        if let Ok(Ok(number)) = tokio::time::timeout(
            FEE_ESTIMATE_TIMEOUT,
            provider_for(endpoint).get_block_number(),
        )
        .await
        {
            heads.push(u128::from(number));
        }
    }
    ensure!(
        heads.len() >= required,
        "{} requires {required} endpoints to agree but only {} reported a chain head",
        network.name,
        heads.len()
    );
    Ok(Some(
        u64::try_from(median(&mut heads)).expect("every element came from a u64"),
    ))
}

/// The lower of the two middle values for an even count, so the answer is
/// always one an endpoint actually returned rather than an average of two
/// that nobody did.
fn median(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    values[(values.len() - 1) / 2]
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
        let _ = write!(message, "\n  {endpoint}: {error:#}");
    }
    anyhow::anyhow!(message)
}

/// Confirm a provider is serving the chain the network claims, and fail in a
/// way failover understands.
///
/// Checked on every endpoint rather than once for the network: the list is
/// several independent services, and one of them being pointed at the wrong
/// chain must disqualify that endpoint instead of the request.
pub async fn ensure_serving_chain(provider: &DynProvider, expected: u64) -> Result<()> {
    let observed = with_timeout(provider.get_chain_id()).await?;
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
    try_endpoints(network, |provider| async move {
        ensure_serving_chain(&provider, network.chain_id).await
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
    let (chain_id, balance, transaction_count, code) =
        try_endpoints(network, |provider| async move {
            let (chain_id, balance, transaction_count, code) = tokio::try_join!(
                with_timeout(provider.get_chain_id()),
                with_timeout(async { provider.get_balance(wallet.address).await }),
                with_timeout(async { provider.get_transaction_count(wallet.address).await }),
                with_timeout(async { provider.get_code_at(wallet.address).await }),
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
    let pinned = BlockId::number(preface.parent.number);
    let (chain_id, transaction_count, code) = try_endpoints(network, |provider| async move {
        let (chain_id, transaction_count, code) = tokio::try_join!(
            with_timeout(provider.get_chain_id()),
            with_timeout(async {
                provider
                    .get_transaction_count(wallet.address)
                    .block_id(pinned)
                    .await
            }),
            with_timeout(async { provider.get_code_at(wallet.address).block_id(pinned).await }),
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
    try_endpoints(network, |provider| async move {
        let (chain_id, receipt) = tokio::try_join!(
            with_timeout(provider.get_chain_id()),
            with_timeout(provider.get_transaction_receipt(hash)),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        // Inside the closure, so an unusable receipt is this endpoint failing
        // rather than the whole lookup failing on its word.
        receipt
            .map(|receipt| {
                let block_number = receipt
                    .block_number
                    .context("RPC returned a receipt without a block number")?;
                storable_receipt_fields(block_number, receipt.gas_used)?;
                Ok(ReceiptStatus {
                    succeeded: receipt.status(),
                    block_number,
                    gas_used: receipt.gas_used,
                    effective_gas_price: receipt.effective_gas_price,
                })
            })
            .transpose()
    })
    .await
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
    let receipt = try_endpoints(network, |provider| async move {
        let (chain_id, receipt) = tokio::try_join!(
            with_timeout(provider.get_chain_id()),
            with_timeout(provider.get_transaction_receipt(hash)),
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

/// An address's native balance just before and just after one block:
/// `(parent, at_block)`. The difference is the net native change the block
/// made to the address — including internal transfers no log records and the
/// gas its own transactions paid. Needs an RPC that still serves the parent
/// block's state; callers treat an error as "unavailable", not as zero.
pub async fn native_balances_around_block(
    network: &NetworkConfig,
    address: Address,
    block_number: u64,
) -> Result<(alloy::primitives::U256, alloy::primitives::U256)> {
    let parent = block_number
        .checked_sub(1)
        .context("the genesis block has no parent state to diff against")?;
    try_endpoints(network, |provider| async move {
        let (chain_id, before, after) = tokio::try_join!(
            with_timeout(provider.get_chain_id()),
            with_timeout(async { provider.get_balance(address).block_id(parent.into()).await }),
            with_timeout(async {
                provider
                    .get_balance(address)
                    .block_id(block_number.into())
                    .await
            }),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        Ok((before, after))
    })
    .await
}

/// The chain head height, used to count confirmations for a mined receipt.
pub async fn latest_block_number(network: &NetworkConfig) -> Result<u64> {
    try_endpoints(network, |provider| async move {
        let (chain_id, block_number) = tokio::try_join!(
            with_timeout(provider.get_chain_id()),
            with_timeout(provider.get_block_number()),
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
    try_endpoints(network, |provider| async move {
        let (chain_id, count) = tokio::try_join!(
            with_timeout(provider.get_chain_id()),
            with_timeout(async { provider.get_transaction_count(address).latest().await }),
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
    try_endpoints(network, |provider| async move {
        let (chain_id, transaction) = tokio::try_join!(
            with_timeout(provider.get_chain_id()),
            with_timeout(provider.get_transaction_by_hash(hash)),
        )?;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        Ok(transaction.is_some())
    })
    .await
}

async fn with_timeout<T, E>(future: impl Future<Output = std::result::Result<T, E>>) -> Result<T>
where
    E: std::fmt::Display,
{
    tokio::time::timeout(RPC_TIMEOUT, future)
        .await
        .context("RPC request timed out")?
        .map_err(|error| rpc_error(&error))
}

/// One shared spelling for a failed RPC request. The error passes through
/// unredacted, endpoint and all: the RPC URL is configuration, and a provider
/// credential embedded in it is read-only and easy to rotate, so which exact
/// endpoint failed is worth more than hiding it.
pub fn rpc_error(error: &impl std::fmt::Display) -> anyhow::Error {
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
