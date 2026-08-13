//! Live-RPC conformance matrix for the wallet's chain-facing surface.
//!
//! Every default network is expected to behave identically, so each chain runs
//! the same battery: bounded batch reads, explicit balance reads, wallet
//! status, one-shot simulation of both a direct call and an atomic Calibur
//! batch, and the full temporary-simulation-fork workflow — apply a plan to a
//! fork, read the state it produced back through that fork, confirm real chain
//! state is untouched, and apply a second plan that depends on the first.
//!
//! These tests exercise the exact functions the MCP tools delegate to
//! (`fork`, `simulation`, `batch_read`, `token_store`, `rpc`), with the same
//! inputs those tools construct. They deliberately do not spawn the stdio
//! server: the tool layer is a thin wrapper whose behaviour is covered by unit
//! tests, while what needs a real chain is everything below it.
//!
//! Nothing here needs funds, keys, or a configured wallet. The synthetic
//! sender holds no balance, and `eth_simulateV1` runs without transaction
//! validation, so every plan is executed by the RPC exactly as written without
//! anything ever being signed or broadcast.
//!
//! Skipped unless `EKUBO_WALLET_LIVE_RPC_TESTS=1`. Per-chain endpoints can be
//! overridden with `EKUBO_WALLET_LIVE_RPC_<chain-id>`, which is how a chain
//! whose default public endpoint rate-limits `eth_simulateV1` is tested.
//!
//! This matrix runs locally, on demand, and nowhere else. It depends on shared
//! public endpoints, which throttle and go down on their own schedule, so as a
//! CI job it failed for reasons that had nothing to do with the code and taught
//! us to ignore it. Run it by hand when the chain-facing surface changes.
//!
//! One chain at a time: the shared endpoints throttle a parallel run, and a
//! throttled retry loop is slower than running serially.
//!
//! ```sh
//! EKUBO_WALLET_LIVE_RPC_TESTS=1 cargo test --locked --all-features \
//!     --test live_networks -- --nocapture --test-threads=1
//! ```
//!
//! Some live cases live in the library instead, behind `#[ignore]`. Restrict
//! Cargo to the library harness; a name filter alone also links every unrelated
//! integration-test binary before filtering it.
//!
//! ```sh
//! EKUBO_WALLET_LIVE_RPC_TESTS=1 cargo test --locked --all-features \
//!     --lib live_ -- --ignored --nocapture
//! ```

use alloy::{
    primitives::{Address, U256, address},
    rpc::types::simulate::{SimBlock, SimulatePayload},
    sol,
    sol_types::SolCall,
};
use chrono::Utc;
use ekubo_wallet::{
    abi_decoder::{AbiDecodePlan, AbiParameterInput},
    batch_read::{BatchEthCallInput, BatchReadCall, BatchStrategy, batch_eth_call},
    config::{NetworkConfig, WalletMetadata, WalletSource, default_networks},
    core::{execution_plan::ExecutionPlan, policy::WalletPolicy},
    fork::{ForkParent, ForkPreface, ForkSession, ForkStore, MAX_PLANS_PER_FORK, pin_parent_block},
    policy_store::StoredPolicy,
    rpc::wallet_status,
    simulation::{ExecutionMode, SimulationFailureCategory, SimulationResult, simulate_execution},
    token_store::read_token_balances,
};
use serde_json::json;
use std::{future::Future, time::Duration};
use uuid::Uuid;

/// Deployed at the same address on every network in this matrix, and writable
/// without holding any balance: `approve` only records an allowance. That
/// makes it the one universally available way to produce state on a fork and
/// then read that state back.
const PERMIT2: Address = address!("000000000022D473030F116dDEE9F6B43aC78BA3");
const MULTICALL3: Address = address!("cA11bde05977b3631167028862bE2a173976CA11");
/// The canonical Calibur implementation every atomic batch delegates to. It
/// is not deployed on every default network, and where it is missing a
/// multi-call plan must fail loudly rather than quietly become something else.
const CANONICAL_CALIBUR: Address = address!("000000005c84F8Fd50b21CAC312528A64437030e");

sol! {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
    function allowance(address user, address token, address spender)
        external view returns (uint160 amount, uint48 expiration, uint48 nonce);
    function getBlockNumber() external view returns (uint256);
    function getChainId() external view returns (uint256);
}

/// The synthetic sender. It holds nothing anywhere, which is the point: every
/// assertion below must hold for an address with no funds and no history.
fn sender() -> Address {
    address!("00000000000000000000000000000000000f0e0d")
}

fn spender() -> Address {
    address!("00000000000000000000000000000000000babe1")
}

fn other_spender() -> Address {
    address!("00000000000000000000000000000000000babe2")
}

fn token() -> Address {
    address!("00000000000000000000000000000000000c0ffe")
}

fn wallet() -> WalletMetadata {
    WalletMetadata {
        instance_id: wallet_instance_id(),
        id: "live-matrix".into(),
        address: sender(),
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    }
}

fn wallet_instance_id() -> Uuid {
    Uuid::from_u128(0x11e)
}

fn policy_context() -> ekubo_wallet::core::predicate::PolicyContext {
    ekubo_wallet::core::predicate::PolicyContext { wallet: sender() }
}

fn policy() -> StoredPolicy {
    StoredPolicy {
        wallet_instance_id: wallet_instance_id(),
        wallet_id: "live-matrix".into(),
        wallet_address: sender(),
        policy: WalletPolicy::allow_anything(),
        revision: 1,
        updated_at: Utc::now(),
    }
}

/// Resolve the network under test, honouring a per-chain RPC override.
fn network(chain_id: u64) -> Option<NetworkConfig> {
    if std::env::var("EKUBO_WALLET_LIVE_RPC_TESTS").as_deref() != Ok("1") {
        return None;
    }
    let mut network = default_networks()
        .into_iter()
        .find(|network| network.chain_id == chain_id)
        .unwrap_or_else(|| panic!("chain {chain_id} is not a default network"));
    if let Ok(url) = std::env::var(format!("EKUBO_WALLET_LIVE_RPC_{chain_id}")) {
        network.rpc_urls = vec![url.parse().expect("override RPC URL is a URL")];
    }
    Some(network)
}

/// One `Permit2.approve` call: an allowance write that needs no balance.
fn approve_call(spender: Address, amount: u128) -> (Address, Vec<u8>) {
    (
        PERMIT2,
        approveCall {
            token: token(),
            spender,
            amount: amount.try_into().expect("uint160 amount"),
            expiration: 4_000_000_000_u64.try_into().expect("uint48 expiration"),
        }
        .abi_encode(),
    )
}

/// One `Permit2.approve` call as a signer-neutral execution plan.
fn approve_plan(chain_id: u64, spender: Address, amount: u128) -> ExecutionPlan {
    plan(chain_id, vec![approve_call(spender, amount)])
}

fn plan(chain_id: u64, calls: Vec<(Address, Vec<u8>)>) -> ExecutionPlan {
    let steps = calls
        .into_iter()
        .enumerate()
        .map(|(index, (to, data))| {
            json!({
                "step": index + 1,
                "kind": "execution",
                "transaction": {
                    "chain_id": chain_id.to_string(),
                    "from": format!("{:#x}", sender()),
                    "to": format!("{to:#x}"),
                    "data": format!("0x{}", hex::encode(data)),
                    "value": "0",
                },
            })
        })
        .collect::<Vec<_>>();
    ExecutionPlan::parse(json!({
        "schema_version": "1",
        "chain_id": chain_id.to_string(),
        "caip2_chain_id": format!("eip155:{chain_id}"),
        "sender": format!("{:#x}", sender()),
        "ordered_steps": steps,
    }))
    .expect("plan is valid")
}

/// Shared public endpoints throttle hard, and this battery is deliberately
/// request-heavy. Only transport-level throttling and timeouts are retried:
/// they say nothing about whether the wallet behaves correctly on this chain.
/// Every other error fails immediately.
async fn retrying<T, F, Fut>(label: &str, mut attempt: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let mut delay = Duration::from_secs(2);
    let mut last = None;
    for _ in 0..4 {
        match attempt().await {
            Ok(value) => return value,
            Err(error) if is_throttled(&error) => {
                eprintln!("  retrying {label}: {error}");
                tokio::time::sleep(delay).await;
                delay *= 2;
                last = Some(error);
            }
            Err(error) => panic!("{label}: {error:#}"),
        }
    }
    panic!(
        "{label} stayed throttled: {:#}",
        last.expect("a throttled error")
    )
}

fn is_throttled(error: &anyhow::Error) -> bool {
    let text = format!("{error:#}").to_ascii_lowercase();
    [
        "429",
        "too many requests",
        "rate limit",
        "timed out",
        "timeout",
        "502",
        "503",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

/// Simulate, retrying only the RPC-error category. A transient RPC failure is
/// folded into the result rather than returned as an error, so it has to be
/// recognized here rather than by `retrying`.
async fn simulate_retrying(
    network: &NetworkConfig,
    plan: &ExecutionPlan,
    fork: Option<&ForkPreface>,
) -> SimulationResult {
    let mut delay = Duration::from_secs(2);
    for _ in 0..4 {
        let result =
            simulate_execution(&wallet(), network, plan, &policy(), &policy_context(), fork)
                .await
                .expect("simulation returns a result");
        let throttled = result
            .simulation
            .failure
            .as_ref()
            .is_some_and(|failure| failure.category == SimulationFailureCategory::RpcError);
        if result.simulation.success || !throttled {
            return result;
        }
        eprintln!("  retrying simulation: {:?}", result.simulation.error);
        tokio::time::sleep(delay).await;
        delay *= 2;
    }
    simulate_execution(&wallet(), network, plan, &policy(), &policy_context(), fork)
        .await
        .expect("simulation returns a result")
}

/// Read one Permit2 allowance, optionally through a fork.
async fn permit2_allowance(
    network: &NetworkConfig,
    fork: Option<&ForkPreface>,
    spender: Address,
) -> U256 {
    let input = BatchEthCallInput {
        chain_id: network.chain_id.to_string(),
        block_parameter: "latest".into(),
        from: None,
        reference: None,
        fork_id: fork.map(|preface| preface.fork_id),
        calls: vec![BatchReadCall {
            id: Some("allowance".into()),
            to: PERMIT2.to_checksum(None),
            data: format!(
                "0x{}",
                hex::encode(
                    allowanceCall {
                        user: sender(),
                        token: token(),
                        spender,
                    }
                    .abi_encode()
                )
            ),
            decode: None,
            include_raw: true,
        }],
    };
    let output = retrying("allowance read", || batch_eth_call(network, &input, fork)).await;
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0].success, "allowance read reverted");
    let raw = output.results[0]
        .return_data
        .as_deref()
        .expect("raw return data");
    let decoded = allowanceCall::abi_decode_returns(
        &hex::decode(raw.trim_start_matches("0x")).expect("hex return data"),
    )
    .expect("allowance decodes");
    U256::from(decoded.amount)
}

/// Open a fork and keep it in a store, exactly as the MCP server does.
async fn open_fork(network: &NetworkConfig) -> (ForkStore, ForkSession) {
    let parent: ForkParent = retrying("pin fork parent", || pin_parent_block(network)).await;
    let mut store = ForkStore::new();
    let session = store
        .create(
            "live-matrix",
            wallet_instance_id(),
            sender(),
            network.chain_id,
            parent,
            Utc::now(),
        )
        .expect("fork opens");
    (store, session)
}

/// Simulate `plan` on `session` and append it on success, as
/// `wallet_simulate_execution_plan` does.
async fn simulate_on_fork(
    network: &NetworkConfig,
    store: &mut ForkStore,
    session: &ForkSession,
    plan: &ExecutionPlan,
) -> (SimulationResult, ForkSession) {
    let applied = session.plans.len();
    let mut result = simulate_retrying(network, plan, Some(&session.preface())).await;
    assert!(
        result.simulation.success,
        "fork simulation failed on chain {}: {result:#?}",
        network.chain_id
    );
    // The simulation layer never labels its own output; only the caller knows
    // whether the plan was appended, so it owns the fork context.
    let updated = store
        .append(session.fork_id, plan.clone(), applied, Utc::now())
        .expect("a successful plan is appended");
    result.fork = Some(updated.applied_context());
    (result, updated)
}

// --- the per-chain battery -------------------------------------------------

async fn batch_reads_are_pinned_and_decoded(network: &NetworkConfig) {
    let input = BatchEthCallInput {
        chain_id: network.chain_id.to_string(),
        block_parameter: "latest".into(),
        from: None,
        reference: None,
        fork_id: None,
        calls: vec![
            BatchReadCall {
                id: Some("block".into()),
                to: MULTICALL3.to_checksum(None),
                data: format!("0x{}", hex::encode(getBlockNumberCall {}.abi_encode())),
                decode: Some(AbiDecodePlan::AbiParameters {
                    parameters: vec![AbiParameterInput {
                        name: None,
                        ty: "uint256".into(),
                        internal_type: None,
                        components: None,
                    }],
                    semantic_codecs: Vec::new(),
                    required: true,
                }),
                include_raw: false,
            },
            BatchReadCall {
                id: Some("chain".into()),
                to: MULTICALL3.to_checksum(None),
                data: format!("0x{}", hex::encode(getChainIdCall {}.abi_encode())),
                decode: Some(AbiDecodePlan::AbiParameters {
                    parameters: vec![AbiParameterInput {
                        name: None,
                        ty: "uint256".into(),
                        internal_type: None,
                        components: None,
                    }],
                    semantic_codecs: Vec::new(),
                    required: true,
                }),
                include_raw: false,
            },
        ],
    };
    let mut output = retrying("batch read", || batch_eth_call(network, &input, None)).await;
    // `batch_eth_call` deliberately falls back to individual calls whenever
    // an endpoint transiently refuses Multicall3. That is valid production
    // behaviour, but this conformance assertion also needs to prove the
    // optimized path works. Give the public endpoint the same bounded chance
    // to recover that transport errors receive above before judging support.
    let mut delay = Duration::from_secs(2);
    for _ in 0..3 {
        if output.strategy == BatchStrategy::Multicall3 {
            break;
        }
        eprintln!("  retrying Multicall3 batch read after individual-call fallback");
        tokio::time::sleep(delay).await;
        delay *= 2;
        output = retrying("batch read", || batch_eth_call(network, &input, None)).await;
    }
    assert_eq!(output.strategy, BatchStrategy::Multicall3);
    assert!(output.fork.is_none());
    assert!(output.block_number.parse::<u64>().unwrap() > 0);
    assert_eq!(
        output.results[1].decoded.as_ref().unwrap().as_str(),
        Some(network.chain_id.to_string().as_str()),
        "Multicall3 must report the chain this network claims"
    );

    // An explicit caller forces the individual-call path on the same chain.
    let mut individual = input;
    individual.from = Some(sender().to_checksum(None));
    let output = retrying("individual batch read", || {
        batch_eth_call(network, &individual, None)
    })
    .await;
    assert_eq!(output.strategy, BatchStrategy::Individual);
    assert!(output.results.iter().all(|result| result.success));
}

async fn status_and_balances_read(network: &NetworkConfig) {
    let metadata = wallet();
    let status = retrying("wallet status", || wallet_status(&metadata, network, None)).await;
    assert_eq!(status.chain_id, network.chain_id.to_string());
    assert!(status.fork.is_none());
    assert!(status.transaction_count_is_pinned_parent.is_none());

    let tokens = [Address::ZERO, token()];
    let balances = retrying("balances", || {
        read_token_balances(network, sender(), &tokens, None)
    })
    .await;
    // Either read path is correct; which one answers depends on whether the
    // Ekubo lens is deployed on this chain, and both must work.
    assert!(
        ["token_data_fetcher", "multicall_balance_of"].contains(&balances.source.as_str()),
        "unexpected balance source {}",
        balances.source
    );
    assert!(balances.block_number.parse::<u64>().unwrap() > 0);
    assert!(
        balances.balances.is_empty(),
        "the synthetic sender must hold nothing on chain {}",
        network.chain_id
    );
}

/// What this chain's published endpoint can actually do.
///
/// Both of these are properties of the chain and its RPC, not of the wallet,
/// and both change what correct behaviour looks like — so they are probed
/// rather than baked into a table that would quietly rot.
#[derive(Clone, Copy, Debug)]
struct Capabilities {
    simulate: bool,
    calibur: bool,
}

async fn capabilities(network: &NetworkConfig) -> Capabilities {
    let client = ekubo_wallet_core::rpc::clients_for(network)
        .into_iter()
        .next()
        .expect("shipped networks have an RPC client");
    let calibur = retrying("calibur code", || async {
        client
            .code(CANONICAL_CALIBUR, alloy::eips::BlockId::latest())
            .await
    })
    .await;
    let payload = SimulatePayload {
        block_state_calls: vec![SimBlock::default()],
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };
    let simulate = match client.simulate_v1(payload, None).await {
        Ok(_) => true,
        Err(error) => {
            let text = error.to_string().to_ascii_lowercase();
            let unsupported = text.contains("not supported")
                || text.contains("method not found")
                || text.contains("unsupported")
                || text.contains("does not exist");
            assert!(
                unsupported,
                "eth_simulateV1 failed on chain {} for a reason other than being unimplemented: {error}",
                network.chain_id
            );
            false
        }
    };
    Capabilities {
        simulate,
        calibur: !calibur.is_empty(),
    }
}

/// A chain whose RPC cannot simulate cannot be signed for automatically. The
/// wallet must say so rather than let an unsimulated plan through.
async fn simulation_failure_is_reported_and_blocks_signing(network: &NetworkConfig) {
    let result = simulate_execution(
        &wallet(),
        network,
        &approve_plan(network.chain_id, spender(), 1_000),
        &policy(),
        &policy_context(),
        None,
    )
    .await
    .expect("simulation returns a result even when the RPC cannot simulate");
    assert!(!result.simulation.success);
    assert!(
        !result.allowed,
        "an unsimulated plan must never be allowed on chain {}",
        network.chain_id
    );
    assert!(
        result
            .policy_findings
            .iter()
            .any(|finding| finding.code == "simulation_failed"),
        "chain {} must report why it could not simulate: {result:#?}",
        network.chain_id
    );
}

async fn one_shot_simulation_covers_direct_and_batch(
    network: &NetworkConfig,
    capabilities: Capabilities,
) {
    let direct = simulate_retrying(
        network,
        &approve_plan(network.chain_id, spender(), 1_000),
        None,
    )
    .await;
    assert!(direct.simulation.success, "{direct:#?}");
    assert_eq!(direct.execution_mode, ExecutionMode::Direct);
    assert!(!direct.will_authorize_delegation);
    assert!(direct.fork.is_none());
    assert!(direct.block_number.parse::<u64>().unwrap() > 0);

    let batch_plan = plan(
        network.chain_id,
        vec![
            approve_call(spender(), 1_000),
            approve_call(other_spender(), 2_000),
        ],
    );
    let batch = simulate_retrying(network, &batch_plan, None).await;
    assert_eq!(batch.execution_mode, ExecutionMode::CaliburBatch);
    if capabilities.calibur {
        assert!(
            batch.simulation.success,
            "canonical Calibur must execute this batch on chain {}: {batch:#?}",
            network.chain_id
        );
        assert!(
            batch.will_authorize_delegation,
            "an undelegated wallet must authorize the canonical delegation"
        );
    } else {
        // Nothing on this chain can execute an atomic batch, so the wallet
        // has to name that rather than degrade into unrelated calls.
        assert!(!batch.simulation.success);
        assert!(!batch.allowed);
        let message = batch.simulation.failure.expect("a stated failure").message;
        assert!(
            message.contains("Calibur"),
            "chain {} must say the implementation is missing: {message}",
            network.chain_id
        );
    }
}

async fn a_fork_carries_state_between_dependent_plans(
    network: &NetworkConfig,
    capabilities: Capabilities,
) {
    let chain_id = network.chain_id;
    let (mut store, session) = open_fork(network).await;
    let parent = session.parent.number;

    // Nothing is applied yet, so the fork agrees with the chain.
    assert_eq!(
        permit2_allowance(network, Some(&session.preface()), spender()).await,
        U256::ZERO
    );

    // Step 1 writes an allowance that does not exist on chain.
    let first = approve_plan(chain_id, spender(), 111_000);
    let (result, session) = simulate_on_fork(network, &mut store, &session, &first).await;
    let fork = result.fork.expect("a fork simulation reports its fork");
    assert!(fork.hypothetical);
    assert_eq!(fork.applied_plans, 1);
    assert_eq!(fork.parent_block_number, parent.to_string());
    // The plan ran in the first block after the pinned parent.
    assert_eq!(fork.simulated_block_number, (parent + 1).to_string());
    assert_eq!(result.block_number, parent.to_string());

    // The whole point of the feature: a read through the fork observes state
    // the simulated plan produced.
    assert_eq!(
        permit2_allowance(network, Some(&session.preface()), spender()).await,
        U256::from(111_000),
        "a fork read must observe the applied plan on chain {chain_id}"
    );
    // ...and the same read without the fork still sees the real chain.
    assert_eq!(
        permit2_allowance(network, None, spender()).await,
        U256::ZERO,
        "a fork must never leak into real chain state on chain {chain_id}"
    );

    // Step 2 depends on step 1's world and is applied on top of it.
    let second = approve_plan(chain_id, spender(), 222_000);
    let (result, session) = simulate_on_fork(network, &mut store, &session, &second).await;
    let fork = result.fork.expect("a fork simulation reports its fork");
    assert_eq!(fork.applied_plans, 2);
    assert_eq!(
        fork.simulated_block_number,
        (parent + 2).to_string(),
        "each applied plan advances the simulated block by exactly one"
    );
    assert_eq!(
        permit2_allowance(network, Some(&session.preface()), spender()).await,
        U256::from(222_000)
    );

    // A Calibur batch replays through the delegation designator override, so
    // the state it writes has to survive replay like any other step. Chains
    // without the implementation deployed never get that far, and their batch
    // behaviour is asserted by the one-shot battery instead.
    let session = if capabilities.calibur {
        let batch = plan(
            chain_id,
            vec![
                approve_call(other_spender(), 333_000),
                approve_call(spender(), 444_000),
            ],
        );
        let (result, session) = simulate_on_fork(network, &mut store, &session, &batch).await;
        assert_eq!(result.execution_mode, ExecutionMode::CaliburBatch);
        assert_eq!(result.fork.expect("fork context").applied_plans, 3);
        let preface = session.preface();
        assert!(preface.requires_calibur());
        assert_eq!(
            permit2_allowance(network, Some(&preface), other_spender()).await,
            U256::from(333_000)
        );
        assert_eq!(
            permit2_allowance(network, Some(&preface), spender()).await,
            U256::from(444_000),
            "the batch must overwrite what the two earlier plans wrote"
        );
        session
    } else {
        session
    };
    let preface = session.preface();

    // Balance and status reads route through the same replay.
    let native_only = [Address::ZERO];
    let balances = retrying("fork balances", || {
        read_token_balances(network, sender(), &native_only, Some(&preface))
    })
    .await;
    // This number is Multicall3's `block.number`, which is chain-defined —
    // Arbitrum Nitro reports an L1-derived height there rather than the L2
    // block. The fork's own accounting is what carries the pinned parent and
    // simulated heights, and `validate_replay` already checked those against
    // the block headers the RPC returned.
    assert!(balances.block_number.parse::<u64>().unwrap() > 0);
    let metadata = wallet();
    let status = retrying("fork status", || {
        wallet_status(&metadata, network, Some(&preface))
    })
    .await;
    assert_eq!(
        status.transaction_count_is_pinned_parent,
        Some(true),
        "a fork never advances the nonce, and must say so"
    );
    if capabilities.calibur {
        assert_eq!(
            status.delegated_implementation.as_deref(),
            Some("0x000000005c84f8fd50b21cac312528a64437030e"),
            "replaying a batch installs the canonical Calibur designator"
        );
    } else {
        // With no batch in the fork, the wallet's real code is reported.
        assert!(status.delegated_implementation.is_none());
    }

    assert!(session.has_capacity());
    assert!(session.plans.len() < MAX_PLANS_PER_FORK);
    assert!(store.discard(session.fork_id));
    assert!(store.is_empty());
    assert!(
        store.session(session.fork_id, Utc::now()).is_err(),
        "a discarded fork must not resolve"
    );
}

async fn run_matrix(chain_id: u64) {
    let Some(network) = network(chain_id) else {
        eprintln!("skipping chain {chain_id}: set EKUBO_WALLET_LIVE_RPC_TESTS=1 to run");
        return;
    };
    eprintln!(
        "chain {chain_id} via {}",
        network.rpc_urls[0].host_str().unwrap()
    );
    // Reads never depend on chain capabilities and must work everywhere.
    batch_reads_are_pinned_and_decoded(&network).await;
    status_and_balances_read(&network).await;

    let capabilities = capabilities(&network).await;
    eprintln!("chain {chain_id} capabilities: {capabilities:?}");
    if capabilities.simulate {
        one_shot_simulation_covers_direct_and_batch(&network, capabilities).await;
        a_fork_carries_state_between_dependent_plans(&network, capabilities).await;
    } else {
        simulation_failure_is_reported_and_blocks_signing(&network).await;
    }
    eprintln!("chain {chain_id} passed");
}

macro_rules! live_matrix {
    ($($name:ident => $chain_id:expr),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread")]
            async fn $name() {
                run_matrix($chain_id).await;
            }
        )+
    };
}

// Every default network. The wallet is supposed to behave identically on all
// of them, and the differences that do exist belong to the chains rather than
// to this code — so they are probed and asserted, never skipped.
live_matrix! {
    ethereum => 1,
    optimism => 10,
    gnosis => 100,
    monad => 143,
    robinhood => 4663,
    base => 8453,
    arbitrum => 42161,
    ink => 57073,
    berachain => 80094,
    gnosis_chiado => 10200,
    robinhood_testnet => 46630,
    berachain_bepolia => 80069,
    base_sepolia => 84532,
    arbitrum_sepolia => 421_614,
    ink_sepolia => 763_373,
    optimism_sepolia => 11_155_420,
}

/// Failover, proven against a real chain rather than a stub.
///
/// The unit tests in `rpc_test.rs` show that a read moves past a dead endpoint;
/// this shows that the thing signing depends on — a complete `eth_simulateV1`
/// against live state, with the pinned block and state override the wallet
/// actually sends — still produces a successful simulation when the endpoints
/// ahead of the working one are unreachable. That is the whole claim of the
/// feature, and it is the one a stub cannot make.
#[tokio::test(flavor = "multi_thread")]
async fn simulation_survives_dead_endpoints_ahead_of_a_working_one() {
    let Some(mut network) = network(1) else {
        eprintln!("skipping failover check: set EKUBO_WALLET_LIVE_RPC_TESTS=1 to run");
        return;
    };
    let working = network.rpc_urls.clone();
    // Port 1 on loopback refuses immediately, so this measures failover rather
    // than a stack of timeouts.
    network.rpc_urls =
        std::iter::repeat_n("http://127.0.0.1:1/".parse().expect("dead endpoint URL"), 2)
            .chain(working.iter().take(1).cloned())
            .collect();

    let plan = approve_plan(1, Address::repeat_byte(0x42), 1);
    let result = simulate_retrying(&network, &plan, None).await;
    assert!(
        result.simulation.success,
        "simulation did not reach the working endpoint: {:?}",
        result.simulation.failure
    );
    assert!(
        result.block_number.parse::<u64>().expect("a block number") > 0,
        "a successful simulation names the block it ran against"
    );
}

/// The mirror image: when nothing answers, the failure names every endpoint
/// tried. A wallet that cannot reach a chain is a support question, and an
/// error that hides which of six endpoints failed does not answer it.
#[tokio::test(flavor = "multi_thread")]
async fn every_endpoint_dead_reports_each_one() {
    let Some(mut network) = network(1) else {
        eprintln!("skipping failover check: set EKUBO_WALLET_LIVE_RPC_TESTS=1 to run");
        return;
    };
    network.rpc_urls = vec![
        "http://127.0.0.1:1/".parse().unwrap(),
        "http://127.0.0.1:2/".parse().unwrap(),
    ];
    let error = format!(
        "{:#}",
        ekubo_wallet_core::rpc::latest_block_number(&network)
            .await
            .expect_err("no endpoint could answer")
    );
    assert!(error.contains("127.0.0.1:1"), "unexpected: {error}");
    assert!(error.contains("127.0.0.1:2"), "unexpected: {error}");
}
