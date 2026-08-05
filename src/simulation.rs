//! Exact transaction simulation through the standardized `eth_simulateV1`
//! RPC method.
//!
//! The wallet builds the same direct call or canonical Calibur batch that it
//! will later sign. The RPC executes that call against a pinned parent block;
//! this process validates the response linkage and locally derives policy
//! findings from the returned call result, balance probes, and transfer logs.
//! No local EVM, `eth_getProof`, or RPC-side `eth_call` fallback is used.
//!
//! A simulation may optionally run on top of a temporary fork
//! ([`crate::fork`]): the plans that fork has already applied are replayed as
//! earlier `SimBlock`s in the very same `eth_simulateV1` request, so the plan
//! under simulation observes their state. That is the only difference; the
//! RPC still executes everything, and a fork never affects signing, policy
//! authorization, or submission, all of which re-simulate against real chain
//! state.

use crate::{
    abi_decoder::decode_abi_error,
    config::{NetworkConfig, WalletMetadata},
    core::{
        execution_plan::{ExecutionPlan, SimulationFailureAction, SimulationFailureDirective},
        policy::{FindingSeverity, PolicyFinding, TokenSpends, evaluate_policy, policy_allows},
    },
    fork::{ForkContext, ForkParent, ForkPreface, validate_replay},
    policy_store::StoredPolicy,
};
use alloy::{
    consensus::BlockHeader,
    eips::{BlockId, BlockNumberOrTag},
    network::primitives::BlockResponse,
    primitives::{Address, B256, Bytes, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{
        Log, TransactionInput, TransactionRequest,
        simulate::{SimBlock, SimCallResult, SimulatePayload},
        state::{AccountOverride, StateOverride},
    },
    sol,
    sol_types::SolCall,
};
use anyhow::{Context as _, Result, ensure};
use num_bigint::BigUint;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::sync::Semaphore;

const RPC_SETUP_TIMEOUT: Duration = Duration::from_secs(20);
const SIMULATION_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_SIMULATIONS: usize = 2;
const MAX_TRACKED_TOKENS: usize = 128;
const BALANCE_PROBE_GAS: u64 = 100_000;
pub(crate) const CANONICAL_CALIBUR: Address = address!("000000005c84F8Fd50b21CAC312528A64437030e");
const CANONICAL_CALIBUR_RUNTIME_HASH: B256 =
    alloy::primitives::b256!("ba697585ba58ba66ebd095ab4c7f980ed42ad115b2e3bb9b5b9bdf167bf08b1b");
const TRANSFER_EVENT: B256 =
    alloy::primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
const NATIVE_TRANSFER_EMITTER: Address = address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

static SIMULATION_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_SIMULATIONS)));
static STANDARD_ERROR_ABI: LazyLock<Vec<Value>> = LazyLock::new(|| {
    vec![
        json!({"type":"error","name":"Error","inputs":[{"name":"message","type":"string"}]}),
        json!({"type":"error","name":"Panic","inputs":[{"name":"code","type":"uint256"}]}),
        json!({"type":"error","name":"CallFailed","inputs":[{"name":"revertData","type":"bytes"}]}),
        json!({"type":"error","name":"TransferFromFailed","inputs":[]}),
    ]
});

sol! {
    struct CaliburCall {
        address to;
        uint256 value;
        bytes data;
    }

    struct BatchedCall {
        CaliburCall[] calls;
        bool revertOnFailure;
    }

    function execute(BatchedCall batchedCall) external payable;
    function balanceOf(address account) external view returns (uint256);
    error CallFailed(bytes revertData);
    error TargetFailure(uint256 amount);
}

#[derive(Clone, Copy, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Direct,
    CaliburBatch,
}

#[derive(Clone, Copy, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SimulationFailureCategory {
    RpcError,
    ExecutionReverted,
    SimulationSetupError,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SimulationFailure {
    pub category: SimulationFailureCategory,
    pub message: String,
    pub retryable_same_plan: bool,
    pub recommended_action: SimulationFailureAction,
    pub instruction: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrapped_revert_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrapped_revert_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_errors: Option<Vec<WrappedSimulationError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_error: Option<DecodedSimulationError>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct WrappedSimulationError {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::abi_decoder::any_json_schema")]
    pub args: Option<Value>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct DecodedSimulationError {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::abi_decoder::any_json_schema")]
    pub args: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SimulationExecution {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_gas_limit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<SimulationFailure>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NativeBalanceChange {
    pub before: String,
    pub after: String,
    pub delta: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct TokenBalanceChange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<String>,
    pub incoming_transfers: String,
    pub outgoing_transfers: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct BalanceChanges {
    pub native: NativeBalanceChange,
    pub tokens: BTreeMap<String, TokenBalanceChange>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SimulationResult {
    /// Identifies this exact result so it can be sent without simulating
    /// again. Usable once, for a short time, and only for the wallet and chain
    /// it was produced for. Absent on a fork, whose results are hypothetical
    /// and can never be sent, and on a result that has just been consumed by a
    /// send.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation_id: Option<uuid::Uuid>,
    pub digest: String,
    pub allowed: bool,
    pub policy_findings: Vec<PolicyFinding>,
    pub policy_revision: u64,
    pub execution_mode: ExecutionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation: Option<String>,
    pub will_authorize_delegation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces_delegated_implementation: Option<String>,
    pub simulation: SimulationExecution,
    pub token_spends: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_changes: Option<BalanceChanges>,
    /// Parent block number whose state was used by `eth_simulateV1`. On a
    /// fork this is still the fork's pinned parent; the block this plan
    /// actually executed in is `fork.simulated_block_number`.
    pub block_number: String,
    /// Present only when the plan was simulated on a temporary fork. Its
    /// presence means every number above is hypothetical: nothing was signed,
    /// approved, or authorized by simulating here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkContext>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedCall {
    pub(crate) mode: ExecutionMode,
    pub(crate) to: Address,
    pub(crate) data: Bytes,
    pub(crate) value: U256,
}

#[derive(Clone, Copy, Default)]
struct TransferActivity {
    incoming: U256,
    outgoing: U256,
}

/// Simulate the exact direct call or Calibur batch used by signing.
///
/// With `fork` set, the plans that fork has already applied are replayed as
/// earlier blocks of the same `eth_simulateV1` request and this plan executes
/// on top of them. The result is hypothetical: the caller is responsible for
/// labelling it, and nothing about it may substitute for the real-state
/// simulation performed at submission.
pub async fn simulate_execution(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
    stored_policy: &StoredPolicy,
    fork: Option<&ForkPreface>,
) -> Result<SimulationResult> {
    ensure!(
        plan.sender == wallet.address,
        "execution plan sender does not match selected wallet"
    );
    ensure!(
        plan.chain_id.as_str() == network.chain_id.to_string(),
        "execution plan chain does not match selected network"
    );
    ensure!(
        stored_policy.wallet_id == wallet.id,
        "policy does not belong to selected wallet"
    );
    if let Some(preface) = fork {
        ensure!(
            preface.chain_id == network.chain_id,
            "fork chain does not match selected network"
        );
        ensure!(
            preface.wallet == wallet.address,
            "fork belongs to a different wallet"
        );
    }

    let _permit = simulation_slot().await?;
    let planned = planned_call(plan, wallet.address);
    let fork_calls: &[PlannedCall] = fork.map_or(&[], |preface| preface.calls.as_slice());
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let setup = tokio::time::timeout(RPC_SETUP_TIMEOUT, async {
        let chain_id = provider.get_chain_id().await?;
        // A fork already pinned its parent when it was created, and that
        // header can no longer change, so replay never re-reads it.
        let block = match fork {
            Some(_) => None,
            None => {
                provider
                    .get_block_by_number(BlockNumberOrTag::Latest)
                    .await?
            }
        };
        Ok::<_, alloy::transports::TransportError>((chain_id, block))
    })
    .await
    .context("simulation RPC setup timed out")
    .and_then(|result| result.map_err(anyhow::Error::from));
    let (chain_id, parent) = match setup {
        Ok((chain_id, block)) => {
            let parent = match (fork, block) {
                (Some(preface), _) => preface.parent,
                (None, Some(block)) => {
                    let header = block.header();
                    ForkParent {
                        number: header.number(),
                        hash: header.hash,
                        gas_limit: header.gas_limit(),
                    }
                }
                (None, None) => {
                    return Ok(setup_failure_result(
                        plan,
                        stored_policy,
                        planned.mode,
                        "RPC returned no latest block",
                        network,
                    ));
                }
            };
            (chain_id, parent)
        }
        Err(error) => {
            return Ok(rpc_failure_result(
                plan,
                stored_policy,
                planned.mode,
                &error,
                network,
            ));
        }
    };
    if chain_id != network.chain_id {
        return Ok(setup_failure_result(
            plan,
            stored_policy,
            planned.mode,
            &format!("RPC reports chain {chain_id}, not {}", network.chain_id),
            network,
        ));
    }

    let block_number = parent.number;
    let gas_limit = match effective_gas_limit(network, parent.gas_limit) {
        Ok(limit) => limit,
        Err(error) => {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                planned.mode,
                &error.to_string(),
                network,
                block_number,
            ));
        }
    };
    let block_id = BlockId::number(block_number);
    let pinned = tokio::time::timeout(RPC_SETUP_TIMEOUT, async {
        tokio::try_join!(
            provider.get_code_at(wallet.address).block_id(block_id),
            provider.get_balance(wallet.address).block_id(block_id),
        )
    })
    .await
    .context("pinned simulation setup RPC timed out")
    .and_then(|result| result.map_err(anyhow::Error::from));
    let (wallet_code, native_before) = match pinned {
        Ok(values) => values,
        Err(error) => {
            return Ok(rpc_failure_result_at_block(
                plan,
                stored_policy,
                planned.mode,
                &error,
                network,
                block_number,
            ));
        }
    };

    // A fork replays earlier batch plans in the same request, so the
    // delegation designator has to be in place for those too even when the
    // plan under simulation is a single direct call.
    let batch_present = planned.mode == ExecutionMode::CaliburBatch
        || fork_calls
            .iter()
            .any(|call| call.mode == ExecutionMode::CaliburBatch);
    let mut needs_override = false;
    let mut replaces = None;
    if batch_present {
        let implementation_code = tokio::time::timeout(
            RPC_SETUP_TIMEOUT,
            provider.get_code_at(CANONICAL_CALIBUR).block_id(block_id),
        )
        .await
        .context("Calibur-code RPC request timed out")
        .and_then(|result| result.map_err(anyhow::Error::from));
        let implementation_code = match implementation_code {
            Ok(code) => code,
            Err(error) => {
                return Ok(rpc_failure_result_at_block(
                    plan,
                    stored_policy,
                    planned.mode,
                    &error,
                    network,
                    block_number,
                ));
            }
        };
        if implementation_code.is_empty() {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                planned.mode,
                "Calibur implementation is not deployed on this chain",
                network,
                block_number,
            ));
        }
        let runtime_hash = keccak256(&implementation_code);
        if runtime_hash != CANONICAL_CALIBUR_RUNTIME_HASH {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                planned.mode,
                &format!(
                    "Calibur runtime code hash mismatch: expected {CANONICAL_CALIBUR_RUNTIME_HASH:#x}, received {runtime_hash:#x}"
                ),
                network,
                block_number,
            ));
        }
        match delegated_implementation(&wallet_code) {
            Some(address) if address == CANONICAL_CALIBUR => {}
            Some(address) => {
                needs_override = true;
                replaces = Some(format!("{address:#x}"));
            }
            None if wallet_code.is_empty() => needs_override = true,
            None => {
                return Ok(setup_failure_result_at_block(
                    plan,
                    stored_policy,
                    planned.mode,
                    "wallet has code that is not an EIP-7702 delegation designator",
                    network,
                    block_number,
                ));
            }
        }
    }
    // Only the plan under simulation can authorize a delegation when it is
    // actually submitted; an override that exists purely so a fork's earlier
    // batch replays is not something this plan would do on chain.
    let will_authorize = needs_override && planned.mode == ExecutionMode::CaliburBatch;
    let replaces = replaces.filter(|_| planned.mode == ExecutionMode::CaliburBatch);

    let tracked_tokens = tracked_tokens(&stored_policy.policy, plan.chain_id.as_str());
    if tracked_tokens.len() > MAX_TRACKED_TOKENS {
        return Ok(setup_failure_result_at_block(
            plan,
            stored_policy,
            planned.mode,
            &format!(
                "policy tracks {} tokens; eth_simulateV1 supports at most {MAX_TRACKED_TOKENS} balance probes",
                tracked_tokens.len()
            ),
            network,
            block_number,
        ));
    }
    let (pre_balance_payload, execution_payload) = simulation_payloads(
        plan,
        network.chain_id,
        wallet.address,
        &planned,
        gas_limit,
        &tracked_tokens,
        needs_override,
        fork_calls,
    );
    let response = tokio::time::timeout(SIMULATION_TIMEOUT, async {
        let pre_balance_blocks = match &pre_balance_payload {
            Some(payload) => Some(provider.simulate(payload).number(block_number).await?),
            None => None,
        };
        let execution_blocks = provider
            .simulate(&execution_payload)
            .number(block_number)
            .await?;
        Ok::<_, alloy::transports::TransportError>((pre_balance_blocks, execution_blocks))
    })
    .await
    .context("eth_simulateV1 request timed out")
    .and_then(|result| result.map_err(anyhow::Error::from));
    let (pre_balance_blocks, blocks) = match response {
        Ok(blocks) => blocks,
        Err(error) => {
            return Ok(rpc_failure_result_at_block(
                plan,
                stored_policy,
                planned.mode,
                &error,
                network,
                block_number,
            ));
        }
    };
    // One block per already-applied fork plan, then the block this plan runs
    // in. Without a fork that is exactly the single block simulated today.
    let mut blocks = match validate_replay(
        parent,
        fork_calls.len(),
        fork.map(|preface| preface.fork_id),
        blocks,
    ) {
        Ok(blocks) => blocks,
        Err(error) => {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                planned.mode,
                &error.to_string(),
                network,
                block_number,
            ));
        }
    };
    // The replayed blocks are consumed first: their native transfers move the
    // fork's balance from the pinned parent's to the one this plan starts at.
    let replayed = blocks.drain(..fork_calls.len()).collect::<Vec<_>>();
    let mut native_before = native_before;
    for block in &replayed {
        let mut activity = transfer_activity(wallet.address, &block.calls[0].logs);
        let native = activity
            .remove(&NATIVE_TRANSFER_EMITTER)
            .unwrap_or_default();
        let Some(updated) = native_before
            .checked_add(native.incoming)
            .and_then(|balance| balance.checked_sub(native.outgoing))
        else {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                planned.mode,
                "fork replay native transfer logs do not reconcile with the pinned balance",
                network,
                block_number,
            ));
        };
        native_before = updated;
    }
    let simulated = blocks.pop().expect("validated execution block");
    let simulated_header = simulated.inner.header();
    let expected_calls = tracked_tokens.len() + 1;
    if simulated.calls.len() != expected_calls {
        return Ok(setup_failure_result_at_block(
            plan,
            stored_policy,
            planned.mode,
            &format!(
                "eth_simulateV1 returned {} call results for {expected_calls} calls",
                simulated.calls.len()
            ),
            network,
            block_number,
        ));
    }

    let balances_before = match pre_balance_blocks {
        Some(blocks) => {
            let Ok(mut blocks) = validate_replay(
                parent,
                fork_calls.len(),
                fork.map(|preface| preface.fork_id),
                blocks,
            ) else {
                return Ok(setup_failure_result_at_block(
                    plan,
                    stored_policy,
                    planned.mode,
                    "pre-balance eth_simulateV1 response did not match the pinned request",
                    network,
                    block_number,
                ));
            };
            let block = blocks.pop().expect("validated pre-balance block");
            if block.calls.len() != tracked_tokens.len() {
                return Ok(setup_failure_result_at_block(
                    plan,
                    stored_policy,
                    planned.mode,
                    "pre-balance eth_simulateV1 response did not match the pinned request",
                    network,
                    block_number,
                ));
            }
            token_balance_results(&tracked_tokens, &block.calls)
        }
        None => BTreeMap::new(),
    };
    // The exact transaction is always the first call in its simulation. No
    // diagnostic probe can mutate state before it executes.
    let main = &simulated.calls[0];
    let balances_after = token_balance_results(&tracked_tokens, &simulated.calls[1..]);
    let mut activity = transfer_activity(wallet.address, &main.logs);
    let native_activity = activity
        .remove(&NATIVE_TRANSFER_EMITTER)
        .unwrap_or_default();
    let Some(native_after) = native_before
        .checked_add(native_activity.incoming)
        .and_then(|balance| balance.checked_sub(native_activity.outgoing))
    else {
        return Ok(setup_failure_result_at_block(
            plan,
            stored_policy,
            planned.mode,
            "eth_simulateV1 native transfer logs do not reconcile with the pinned balance",
            network,
            block_number,
        ));
    };
    let mut all_tokens = tracked_tokens.iter().copied().collect::<BTreeSet<_>>();
    all_tokens.extend(activity.keys().copied());
    let (token_spends, token_spends_public) = observed_token_spends(
        &tracked_tokens,
        &balances_before,
        &balances_after,
        &activity,
    );
    let balance_changes = BalanceChanges {
        native: NativeBalanceChange {
            before: native_before.to_string(),
            after: native_after.to_string(),
            delta: signed_delta(native_before, native_after),
        },
        tokens: token_balance_changes(&all_tokens, &balances_before, &balances_after, &activity),
    };

    let mut findings = evaluate_policy(plan, &stored_policy.policy, Some(&token_spends));
    let simulation = execution_output(plan, main, network, simulated_header.gas_limit());
    // A plan that does not execute is never allowed, whatever the policy says
    // about its calls: there is no policy setting that turns a revert into an
    // automatic signature.
    if !simulation.success {
        findings.push(PolicyFinding {
            severity: FindingSeverity::Error,
            code: "simulation_failed".into(),
            message: "eth_simulateV1 execution did not succeed".into(),
            step: None,
        });
    }
    Ok(SimulationResult {
        // Stamped by the caller that records it, if it records it at all.
        simulation_id: None,
        digest: format!("{:#x}", plan.digest()),
        allowed: simulation.success && policy_allows(&findings),
        policy_findings: findings,
        policy_revision: stored_policy.revision,
        execution_mode: planned.mode,
        implementation: (planned.mode == ExecutionMode::CaliburBatch)
            .then(|| format!("{CANONICAL_CALIBUR:#x}")),
        will_authorize_delegation: will_authorize,
        replaces_delegated_implementation: replaces,
        simulation,
        token_spends: token_spends_public,
        balance_changes: Some(balance_changes),
        block_number: block_number.to_string(),
        // The caller owns fork labelling: it is the only layer that knows
        // whether this plan was appended to the fork after simulating.
        fork: None,
    })
}

/// Acquire one of the process-wide `eth_simulateV1` slots. Fork replay and
/// one-shot simulation share the same limiter, because a fork request is
/// simply a larger simulation.
pub(crate) async fn simulation_slot() -> Result<tokio::sync::OwnedSemaphorePermit> {
    Arc::clone(&SIMULATION_SLOTS)
        .acquire_owned()
        .await
        .context("simulation limiter was closed")
}

pub(crate) fn planned_call(plan: &ExecutionPlan, wallet: Address) -> PlannedCall {
    if let [step] = plan.ordered_steps.as_slice() {
        return PlannedCall {
            mode: ExecutionMode::Direct,
            to: step.transaction.to,
            data: step.transaction.data.clone(),
            value: step.transaction.value.value(),
        };
    }
    let calls = plan
        .ordered_steps
        .iter()
        .map(|step| CaliburCall {
            to: step.transaction.to,
            value: step.transaction.value.value(),
            data: step.transaction.data.clone(),
        })
        .collect();
    PlannedCall {
        mode: ExecutionMode::CaliburBatch,
        to: wallet,
        data: executeCall {
            batchedCall: BatchedCall {
                calls,
                revertOnFailure: true,
            },
        }
        .abi_encode()
        .into(),
        value: U256::ZERO,
    }
}

/// Build the pinned `eth_simulateV1` payloads.
///
/// `fork_calls` are the plans a fork has already applied, replayed one per
/// leading `SimBlock` so the plan under simulation observes their state.
/// Without a fork the slice is empty and each payload is the single block the
/// one-shot path has always sent.
#[allow(clippy::too_many_arguments)]
fn simulation_payloads(
    plan: &ExecutionPlan,
    chain_id: u64,
    wallet: Address,
    planned: &PlannedCall,
    gas_limit: u64,
    tracked_tokens: &[Address],
    needs_override: bool,
    fork_calls: &[PlannedCall],
) -> (Option<SimulatePayload>, SimulatePayload) {
    let probe = balance_probe_address(plan);
    let pre_balance_calls = tracked_tokens
        .iter()
        .copied()
        .map(|token| balance_probe_request(token, wallet, probe, chain_id))
        .collect::<Vec<_>>();
    let mut execution_calls = Vec::with_capacity(tracked_tokens.len() + 1);
    execution_calls.push(planned_request(planned, wallet, gas_limit, chain_id));
    execution_calls.extend(
        tracked_tokens
            .iter()
            .copied()
            .map(|token| balance_probe_request(token, wallet, probe, chain_id)),
    );

    let replay = || {
        fork_calls
            .iter()
            .map(|call| {
                SimBlock::default()
                    .extend_calls([planned_request(call, wallet, gas_limit, chain_id)])
            })
            .collect::<Vec<_>>()
    };
    let mut execution_blocks = replay();
    execution_blocks.push(SimBlock::default().extend_calls(execution_calls));
    if needs_override {
        // State set by an override carries into every later block, so the
        // designator only has to be installed once, at the front.
        let first = std::mem::take(&mut execution_blocks[0]);
        execution_blocks[0] = delegation_override(first, wallet);
    }
    let pre_balance_payload = (!pre_balance_calls.is_empty()).then(|| {
        let mut blocks = replay();
        blocks.push(SimBlock::default().extend_calls(pre_balance_calls));
        // Balance probes are static reads, so the designator matters only
        // when there is fork history to replay ahead of them.
        if needs_override && !fork_calls.is_empty() {
            let first = std::mem::take(&mut blocks[0]);
            blocks[0] = delegation_override(first, wallet);
        }
        SimulatePayload {
            block_state_calls: blocks,
            trace_transfers: false,
            validation: false,
            return_full_transactions: false,
        }
    });
    (
        pre_balance_payload,
        SimulatePayload {
            block_state_calls: execution_blocks,
            trace_transfers: true,
            // This mirrors eth_call semantics: nonce, signature, and fee
            // preparation happen later and cannot alter target/value/calldata.
            validation: false,
            return_full_transactions: false,
        },
    )
}

/// The exact transaction request for one planned direct call or Calibur
/// batch. Fork replay and the plan under simulation build theirs identically.
pub(crate) fn planned_request(
    planned: &PlannedCall,
    wallet: Address,
    gas_limit: u64,
    chain_id: u64,
) -> TransactionRequest {
    let mut request = TransactionRequest::default()
        .from(wallet)
        .to(planned.to)
        .gas_limit(gas_limit)
        .value(planned.value)
        .input(TransactionInput::new(planned.data.clone()));
    request.chain_id = Some(chain_id);
    request
}

/// Install the canonical Calibur EIP-7702 delegation designator on the
/// wallet for this block and every block after it.
pub(crate) fn delegation_override(block: SimBlock, wallet: Address) -> SimBlock {
    let mut overrides = StateOverride::default();
    overrides.insert(
        wallet,
        AccountOverride::default().with_7702_delegation_designator(CANONICAL_CALIBUR),
    );
    block.with_state_overrides(overrides)
}

fn balance_probe_request(
    token: Address,
    wallet: Address,
    probe: Address,
    chain_id: u64,
) -> TransactionRequest {
    let mut request = TransactionRequest::default()
        .from(probe)
        .to(token)
        .gas_limit(BALANCE_PROBE_GAS)
        .input(TransactionInput::new(
            balanceOfCall { account: wallet }.abi_encode().into(),
        ));
    request.chain_id = Some(chain_id);
    request
}

fn balance_probe_address(plan: &ExecutionPlan) -> Address {
    let mut material = b"org.ekubo.wallet-mcp.balance-probe.v1".to_vec();
    material.extend_from_slice(plan.digest().as_slice());
    let digest = keccak256(material);
    Address::from_slice(&digest.as_slice()[12..])
}

fn token_balance_results(
    tokens: &[Address],
    results: &[SimCallResult],
) -> BTreeMap<Address, Option<U256>> {
    tokens
        .iter()
        .copied()
        .zip(results.iter())
        .map(|(token, result)| {
            let balance = result
                .status
                .then(|| balanceOfCall::abi_decode_returns(&result.return_data).ok())
                .flatten();
            (token, balance)
        })
        .collect()
}

pub(crate) fn effective_gas_limit(network: &NetworkConfig, block_limit: u64) -> Result<u64> {
    let configured = network
        .max_gas_limit
        .as_deref()
        .map(str::parse::<u64>)
        .transpose()
        .context("configured max gas limit is invalid")?
        .unwrap_or(block_limit);
    let limit = configured.min(block_limit);
    ensure!(
        limit >= 21_000,
        "effective simulation gas limit is below intrinsic gas"
    );
    Ok(limit)
}

fn tracked_tokens(policy: &crate::core::policy::WalletPolicy, chain_id: &str) -> Vec<Address> {
    policy.chain(chain_id).map_or_else(Vec::new, |chain| {
        chain
            .tokens
            .keys()
            .filter(|token| token.as_str() != "*")
            .filter_map(|token| Address::from_str(token).ok())
            .collect()
    })
}

fn delegated_implementation(code: &Bytes) -> Option<Address> {
    (code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00]))
        .then(|| Address::from_slice(&code[3..]))
}

fn transfer_activity(wallet: Address, logs: &[Log]) -> BTreeMap<Address, TransferActivity> {
    let mut observed = BTreeMap::new();
    for log in logs {
        let topics = log.topics();
        let data = &log.data().data;
        if topics.len() != 3 || topics[0] != TRANSFER_EVENT || data.len() != 32 {
            continue;
        }
        let from = Address::from_slice(&topics[1].as_slice()[12..]);
        let to = Address::from_slice(&topics[2].as_slice()[12..]);
        let amount = U256::from_be_slice(data);
        if amount.is_zero() || (from != wallet && to != wallet) {
            continue;
        }
        let activity = observed
            .entry(log.address())
            .or_insert(TransferActivity::default());
        if from == wallet {
            activity.outgoing = activity.outgoing.saturating_add(amount);
        }
        if to == wallet {
            activity.incoming = activity.incoming.saturating_add(amount);
        }
    }
    observed
}

fn observed_token_spends(
    tracked: &[Address],
    before: &BTreeMap<Address, Option<U256>>,
    after: &BTreeMap<Address, Option<U256>>,
    activity: &BTreeMap<Address, TransferActivity>,
) -> (TokenSpends, BTreeMap<String, String>) {
    let mut observed = activity
        .iter()
        .map(|(token, activity)| (*token, activity.outgoing))
        .collect::<BTreeMap<_, _>>();
    for token in tracked {
        let measured_decrease = match (
            before.get(token).copied().flatten(),
            after.get(token).copied().flatten(),
        ) {
            (Some(before), Some(after)) => Some(before.saturating_sub(after)),
            _ => None,
        };
        let event_spend = observed.get(token).copied();
        if let Some(amount) = measured_decrease
            .map(|decrease| decrease.max(event_spend.unwrap_or_default()))
            .or(event_spend)
        {
            observed.insert(*token, amount);
        }
    }
    let public = observed
        .iter()
        .map(|(token, amount)| (format!("{token:#x}"), amount.to_string()))
        .collect();
    let policy = observed
        .into_iter()
        .map(|(token, amount)| {
            (
                format!("{token:#x}"),
                BigUint::from_bytes_be(&amount.to_be_bytes::<32>()),
            )
        })
        .collect();
    (policy, public)
}

fn token_balance_changes(
    tokens: &BTreeSet<Address>,
    before: &BTreeMap<Address, Option<U256>>,
    after: &BTreeMap<Address, Option<U256>>,
    activity: &BTreeMap<Address, TransferActivity>,
) -> BTreeMap<String, TokenBalanceChange> {
    let mut changes = BTreeMap::new();
    for token in tokens {
        let before_value = before.get(token).copied().flatten();
        let after_value = after.get(token).copied().flatten();
        let transfers = activity.get(token).copied().unwrap_or_default();
        if before_value == after_value
            && transfers.incoming.is_zero()
            && transfers.outgoing.is_zero()
        {
            continue;
        }
        changes.insert(
            format!("{token:#x}"),
            TokenBalanceChange {
                before: before_value.map(|value| value.to_string()),
                after: after_value.map(|value| value.to_string()),
                delta: before_value
                    .zip(after_value)
                    .map(|(before, after)| signed_delta(before, after)),
                incoming_transfers: transfers.incoming.to_string(),
                outgoing_transfers: transfers.outgoing.to_string(),
            },
        );
    }
    changes
}

fn signed_delta(before: U256, after: U256) -> String {
    if after >= before {
        (after - before).to_string()
    } else {
        format!("-{}", before - after)
    }
}

fn execution_output(
    plan: &ExecutionPlan,
    result: &SimCallResult,
    network: &NetworkConfig,
    block_gas_limit: u64,
) -> SimulationExecution {
    // maxUsedGas is the high-water mark before refunds. It is the safer input
    // to the wallet's bounded gas multiplier when the RPC provides it.
    let gas_used = Some(result.max_used_gas.unwrap_or(result.gas_used).to_string());
    let output = Some(format!("0x{}", hex::encode(&result.return_data)));
    let block_gas_limit = Some(block_gas_limit.to_string());
    if result.status {
        return SimulationExecution {
            success: true,
            gas_used,
            block_gas_limit,
            output,
            error: None,
            failure: None,
        };
    }
    let message = result.error.as_ref().map_or_else(
        || "eth_simulateV1 execution failed without an error object".into(),
        |error| format!("{} (RPC code {})", error.message, error.code),
    );
    let revert_bytes = result
        .error
        .as_ref()
        .and_then(|error| error.data.as_ref())
        .filter(|data| !data.is_empty())
        .unwrap_or(&result.return_data);
    let revert_data =
        (!revert_bytes.is_empty()).then(|| format!("0x{}", hex::encode(revert_bytes)));
    let failure = failure(
        plan,
        SimulationFailureCategory::ExecutionReverted,
        &message,
        revert_data.as_deref(),
        network,
    );
    SimulationExecution {
        success: false,
        gas_used,
        block_gas_limit,
        output,
        error: Some(failure.message.clone()),
        failure: Some(failure),
    }
}

fn failure(
    plan: &ExecutionPlan,
    category: SimulationFailureCategory,
    message: &str,
    revert_data: Option<&str>,
    network: &NetworkConfig,
) -> SimulationFailure {
    let configured = plan
        .simulation_failure_policy
        .as_ref()
        .map(|policy| match category {
            SimulationFailureCategory::RpcError => &policy.rpc_error,
            SimulationFailureCategory::ExecutionReverted => &policy.execution_reverted,
            SimulationFailureCategory::SimulationSetupError => &policy.simulation_setup_error,
        });
    let fallback = default_directive(category);
    let directive = configured.unwrap_or(&fallback);
    let inspected = revert_data.map(|data| inspect_revert(plan, data));
    let message = inspected
        .as_ref()
        .and_then(|inspection| inspection.decoded_error.as_ref())
        .and_then(|error| error.message.as_deref())
        .unwrap_or(message);
    let message = sanitize_error(message, network);
    SimulationFailure {
        category,
        message,
        retryable_same_plan: directive.action == SimulationFailureAction::RetrySamePlan,
        recommended_action: directive.action,
        instruction: directive.instruction.clone(),
        source: if configured.is_some() {
            "execution_plan_policy"
        } else {
            "wallet_default"
        }
        .into(),
        revert_data: revert_data.map(ToOwned::to_owned),
        revert_selector: revert_data
            .filter(|data| data.len() >= 10)
            .map(|data| data[..10].to_owned()),
        unwrapped_revert_data: inspected
            .as_ref()
            .and_then(|inspection| inspection.unwrapped_revert_data.clone()),
        unwrapped_revert_selector: inspected.as_ref().and_then(|inspection| {
            inspection
                .unwrapped_revert_data
                .as_deref()
                .filter(|data| data.len() >= 10)
                .map(|data| data[..10].to_owned())
        }),
        wrapped_errors: inspected.as_ref().and_then(|inspection| {
            (!inspection.wrapped_errors.is_empty()).then(|| inspection.wrapped_errors.clone())
        }),
        decoded_error: inspected.and_then(|inspection| inspection.decoded_error),
    }
}

struct RevertInspection {
    unwrapped_revert_data: Option<String>,
    wrapped_errors: Vec<WrappedSimulationError>,
    decoded_error: Option<DecodedSimulationError>,
}

fn inspect_revert(plan: &ExecutionPlan, outer: &str) -> RevertInspection {
    const MAX_WRAPPER_DEPTH: usize = 8;
    let mut current = outer.to_owned();
    let mut wrapped_errors = Vec::new();
    let mut decoded_error = None;
    for _ in 0..MAX_WRAPPER_DEPTH {
        let Some(bytes) = current
            .strip_prefix("0x")
            .and_then(|encoded| hex::decode(encoded).ok())
        else {
            break;
        };
        if let Some(decoded) = decode_abi_error(&bytes, &STANDARD_ERROR_ABI) {
            let args = Value::Array(decoded.args.clone());
            if decoded.name == "CallFailed" {
                wrapped_errors.push(WrappedSimulationError {
                    name: decoded.name,
                    args: Some(args.clone()),
                });
                if let Some(inner) = decoded.args.first().and_then(Value::as_str)
                    && valid_revert_data(inner)
                {
                    inner.clone_into(&mut current);
                    continue;
                }
                decoded_error = Some(DecodedSimulationError {
                    name: "CallFailed".into(),
                    args: Some(args),
                    message: Some("Calibur batch call reverted without return data".into()),
                    step: None,
                    target: None,
                });
                break;
            }
            let message = match decoded.name.as_str() {
                "Error" => decoded
                    .args
                    .first()
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                "TransferFromFailed" => Some("ERC-20 transferFrom failed".into()),
                _ => None,
            };
            decoded_error = Some(DecodedSimulationError {
                name: decoded.name,
                args: Some(args),
                message,
                step: None,
                target: None,
            });
            break;
        }
        for step in &plan.ordered_steps {
            let Some(decode) = &step.revert_decode else {
                continue;
            };
            if let Some(decoded) = decode_abi_error(&bytes, decode.abi()) {
                decoded_error = Some(DecodedSimulationError {
                    message: Some(format!("{} reverted", decoded.name)),
                    name: decoded.name,
                    args: Some(Value::Array(decoded.args)),
                    step: Some(step.step),
                    target: Some(format!("{:#x}", step.transaction.to)),
                });
                break;
            }
        }
        break;
    }
    RevertInspection {
        unwrapped_revert_data: (current != outer).then_some(current),
        wrapped_errors,
        decoded_error,
    }
}

fn valid_revert_data(value: &str) -> bool {
    value.starts_with("0x")
        && value.len() >= 10
        && value.len().is_multiple_of(2)
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn default_directive(category: SimulationFailureCategory) -> SimulationFailureDirective {
    match category {
        SimulationFailureCategory::RpcError => SimulationFailureDirective {
            action: SimulationFailureAction::RetrySamePlan,
            instruction: "The eth_simulateV1 infrastructure or RPC failed transiently. Retry the same plan after the service recovers.".into(),
        },
        SimulationFailureCategory::ExecutionReverted => SimulationFailureDirective {
            action: SimulationFailureAction::RepreparePlan,
            instruction: "The exact calldata reverted against current state. Do not retry it; obtain newly prepared calldata from the originating action or quote provider.".into(),
        },
        SimulationFailureCategory::SimulationSetupError => SimulationFailureDirective {
            action: SimulationFailureAction::UserReview,
            instruction: "Check the selected wallet, network, RPC eth_simulateV1 support, and delegation before continuing.".into(),
        },
    }
}

fn base_failure_result(
    plan: &ExecutionPlan,
    stored_policy: &StoredPolicy,
    mode: ExecutionMode,
    failure: SimulationFailure,
    block_number: u64,
) -> SimulationResult {
    let mut findings = evaluate_policy(plan, &stored_policy.policy, None);
    findings.push(PolicyFinding {
        severity: FindingSeverity::Error,
        code: "simulation_failed".into(),
        message: "eth_simulateV1 simulation did not succeed".into(),
        step: None,
    });
    SimulationResult {
        simulation_id: None,
        digest: format!("{:#x}", plan.digest()),
        allowed: false,
        policy_findings: findings,
        policy_revision: stored_policy.revision,
        execution_mode: mode,
        implementation: (mode == ExecutionMode::CaliburBatch)
            .then(|| format!("{CANONICAL_CALIBUR:#x}")),
        will_authorize_delegation: mode == ExecutionMode::CaliburBatch,
        replaces_delegated_implementation: None,
        simulation: SimulationExecution {
            success: false,
            gas_used: None,
            block_gas_limit: None,
            output: None,
            error: Some(failure.message.clone()),
            failure: Some(failure),
        },
        token_spends: BTreeMap::new(),
        balance_changes: None,
        block_number: block_number.to_string(),
        fork: None,
    }
}

fn rpc_failure_result(
    plan: &ExecutionPlan,
    policy: &StoredPolicy,
    mode: ExecutionMode,
    error: &anyhow::Error,
    network: &NetworkConfig,
) -> SimulationResult {
    rpc_failure_result_at_block(plan, policy, mode, error, network, 0)
}

fn rpc_failure_result_at_block(
    plan: &ExecutionPlan,
    policy: &StoredPolicy,
    mode: ExecutionMode,
    error: &anyhow::Error,
    network: &NetworkConfig,
    block_number: u64,
) -> SimulationResult {
    base_failure_result(
        plan,
        policy,
        mode,
        failure(
            plan,
            SimulationFailureCategory::RpcError,
            &error.to_string(),
            None,
            network,
        ),
        block_number,
    )
}

fn setup_failure_result(
    plan: &ExecutionPlan,
    policy: &StoredPolicy,
    mode: ExecutionMode,
    message: &str,
    network: &NetworkConfig,
) -> SimulationResult {
    setup_failure_result_at_block(plan, policy, mode, message, network, 0)
}

fn setup_failure_result_at_block(
    plan: &ExecutionPlan,
    policy: &StoredPolicy,
    mode: ExecutionMode,
    message: &str,
    network: &NetworkConfig,
    block_number: u64,
) -> SimulationResult {
    base_failure_result(
        plan,
        policy,
        mode,
        failure(
            plan,
            SimulationFailureCategory::SimulationSetupError,
            message,
            None,
            network,
        ),
        block_number,
    )
}

fn sanitize_error(message: &str, network: &NetworkConfig) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{WalletSource, default_networks},
        core::execution_plan::{
            DecimalU256, ExecutionStep, ExecutionStepKind, PlannedTransaction, RevertDecodePlan,
            SubmitCondition,
        },
        core::policy::{NamedAddressPolicy, TokenPolicy},
    };
    use alloy::sol_types::SolError;
    use chrono::Utc;

    fn plan(calls: usize) -> ExecutionPlan {
        let sender = Address::repeat_byte(0x11);
        ExecutionPlan {
            schema_version: "1".into(),
            chain_id: DecimalU256::new("1").unwrap(),
            caip2_chain_id: "eip155:1".into(),
            sender,
            ordered_steps: (0..calls)
                .map(|index| ExecutionStep {
                    step: u32::try_from(index + 1).unwrap(),
                    kind: ExecutionStepKind::Execution,
                    submit_condition: SubmitCondition::Always,
                    transaction: PlannedTransaction {
                        chain_id: DecimalU256::new("1").unwrap(),
                        from: sender,
                        to: Address::repeat_byte(u8::try_from(index + 2).unwrap()),
                        data: Bytes::new(),
                        value: DecimalU256::new("0").unwrap(),
                        gas: None,
                    },
                    eip1193: None,
                    revert_decode: None,
                })
                .collect(),
            execution_policy: None,
            adapters: None,
            simulation_failure_policy: None,
        }
    }

    #[test]
    fn direct_and_batch_encoding_are_deterministic() {
        let direct = planned_call(&plan(1), Address::repeat_byte(0x11));
        assert_eq!(direct.mode, ExecutionMode::Direct);
        assert_eq!(direct.to, Address::repeat_byte(2));

        let batch = planned_call(&plan(2), Address::repeat_byte(0x11));
        assert_eq!(batch.mode, ExecutionMode::CaliburBatch);
        assert_eq!(batch.to, Address::repeat_byte(0x11));
        assert_eq!(&batch.data[..4], &executeCall::SELECTOR);
        assert_eq!(batch.value, U256::ZERO);
    }

    #[test]
    fn builds_typed_eth_simulate_payload_with_delegation_override() {
        let plan = plan(2);
        let planned = planned_call(&plan, plan.sender);
        let token = Address::repeat_byte(0x55);
        let (pre_balance, payload) = simulation_payloads(
            &plan,
            1,
            plan.sender,
            &planned,
            1_000_000,
            &[token],
            true,
            &[],
        );
        assert_eq!(pre_balance.unwrap().block_state_calls[0].calls.len(), 1);
        assert!(payload.trace_transfers);
        assert!(!payload.validation);
        assert_eq!(payload.block_state_calls[0].calls.len(), 2);
        let code = payload.block_state_calls[0]
            .state_overrides
            .as_ref()
            .unwrap()
            .get(&plan.sender)
            .unwrap()
            .code
            .as_ref()
            .unwrap();
        assert_eq!(delegated_implementation(code), Some(CANONICAL_CALIBUR));
        let encoded = serde_json::to_value(&payload).unwrap();
        assert_eq!(encoded["traceTransfers"], true);
        assert_eq!(
            encoded["blockStateCalls"][0]["calls"][0]["to"],
            format!("{:#x}", plan.sender)
        );
    }

    #[test]
    fn fork_replay_prepends_one_block_per_applied_plan() {
        let plan = plan(1);
        let planned = planned_call(&plan, plan.sender);
        let applied = [
            planned_call(&plan, plan.sender),
            planned_call(&self::tests::plan(2), plan.sender),
        ];
        let token = Address::repeat_byte(0x55);
        let (pre_balance, payload) = simulation_payloads(
            &plan,
            1,
            plan.sender,
            &planned,
            1_000_000,
            &[token],
            true,
            &applied,
        );
        // Two replayed plans, then the block this plan runs in. The balance
        // probes ride along in the last block of each payload, so both
        // payloads report balances at the same simulated height.
        let payload_blocks = &payload.block_state_calls;
        assert_eq!(payload_blocks.len(), 3);
        assert_eq!(payload_blocks[0].calls.len(), 1);
        assert_eq!(payload_blocks[1].calls.len(), 1);
        assert_eq!(payload_blocks[2].calls.len(), 2);
        let pre_balance = pre_balance.unwrap();
        assert_eq!(pre_balance.block_state_calls.len(), 3);
        assert_eq!(pre_balance.block_state_calls[2].calls.len(), 1);

        // The designator is installed once, on the first block, because
        // overridden state carries forward to every block after it.
        for blocks in [payload_blocks, &pre_balance.block_state_calls] {
            let code = blocks[0]
                .state_overrides
                .as_ref()
                .unwrap()
                .get(&plan.sender)
                .unwrap()
                .code
                .as_ref()
                .unwrap();
            assert_eq!(delegated_implementation(code), Some(CANONICAL_CALIBUR));
            assert!(blocks[1].state_overrides.is_none());
            assert!(blocks[2].state_overrides.is_none());
        }
    }

    #[test]
    fn a_replayed_batch_does_not_become_this_plan_authorizing_a_delegation() {
        // A one-call plan is always a direct call, so even when the fork it
        // replays on needs the Calibur designator, submitting this plan for
        // real would not create one.
        let direct = planned_call(&plan(1), Address::repeat_byte(0x11));
        assert_eq!(direct.mode, ExecutionMode::Direct);
        let batch = planned_call(&plan(2), Address::repeat_byte(0x11));
        assert_eq!(batch.mode, ExecutionMode::CaliburBatch);
        let needs_override = true;
        assert!(!(needs_override && direct.mode == ExecutionMode::CaliburBatch));
        assert!(needs_override && batch.mode == ExecutionMode::CaliburBatch);
    }

    #[test]
    fn replay_validation_requires_the_pinned_parent_and_consecutive_blocks() {
        use crate::fork::ForkParent;

        let parent = ForkParent {
            number: 100,
            hash: B256::repeat_byte(0xab),
            gas_limit: 30_000_000,
        };
        // An empty response can never satisfy even the zero-replay case.
        let empty: Vec<alloy::rpc::types::simulate::SimulatedBlock<alloy::rpc::types::Block>> =
            Vec::new();
        let error = validate_replay(parent, 0, None, empty).expect_err("one block is required");
        assert!(error.to_string().contains("returned 0 blocks"));
    }

    #[test]
    fn recognizes_only_eip7702_designators() {
        let mut code = vec![0xef, 0x01, 0x00];
        code.extend([0x42; 20]);
        assert_eq!(
            delegated_implementation(&Bytes::from(code)),
            Some(Address::repeat_byte(0x42))
        );
        assert_eq!(delegated_implementation(&Bytes::from(vec![0xef, 1])), None);
    }

    #[test]
    fn signed_balance_delta_never_wraps() {
        assert_eq!(signed_delta(U256::from(10), U256::from(7)), "-3");
        assert_eq!(signed_delta(U256::from(7), U256::from(10)), "3");
    }

    #[test]
    fn recursively_unwraps_calibur_and_decodes_declared_target_error() {
        let mut execution_plan = plan(2);
        execution_plan.ordered_steps[0].revert_decode = Some(RevertDecodePlan::ErrorResult {
            abi: vec![json!({
                "type": "error",
                "name": "TargetFailure",
                "inputs": [{"name": "amount", "type": "uint256"}]
            })],
            required: false,
        });
        let inner = TargetFailure {
            amount: U256::from(42),
        }
        .abi_encode();
        let outer = CallFailed {
            revertData: inner.clone().into(),
        }
        .abi_encode();
        let encoded = format!("0x{}", hex::encode(outer));
        let failure = failure(
            &execution_plan,
            SimulationFailureCategory::ExecutionReverted,
            "execution reverted",
            Some(&encoded),
            &default_networks()[0],
        );
        assert_eq!(
            failure.unwrapped_revert_data,
            Some(format!("0x{}", hex::encode(inner)))
        );
        assert_eq!(failure.wrapped_errors.unwrap()[0].name, "CallFailed");
        let decoded = failure.decoded_error.unwrap();
        assert_eq!(decoded.name, "TargetFailure");
        assert_eq!(decoded.args, Some(json!(["42"])));
        assert_eq!(decoded.step, Some(1));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires an Ethereum RPC with eth_simulateV1 support"]
    async fn live_direct_simulation_uses_eth_simulate_v1() {
        let wallet = WalletMetadata {
            id: "live-test".into(),
            address: Address::repeat_byte(0x11),
            created_at: Utc::now(),
            source: WalletSource::Created,
            exported_at: None,
        };
        let policy = StoredPolicy {
            wallet_id: wallet.id.clone(),
            policy: crate::core::policy::WalletPolicy::allow_all_with_approval(),
            revision: 1,
            updated_at: Utc::now(),
        };
        let result = simulate_execution(&wallet, &default_networks()[0], &plan(1), &policy, None)
            .await
            .unwrap();
        assert!(result.simulation.success, "{result:#?}");
        assert_ne!(result.block_number, "0");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires eth_simulateV1 and canonical Calibur on Ethereum"]
    async fn live_batch_simulation_executes_canonical_calibur() {
        let wallet = WalletMetadata {
            id: "live-batch-test".into(),
            address: Address::repeat_byte(0x11),
            created_at: Utc::now(),
            source: WalletSource::Created,
            exported_at: None,
        };
        let policy = StoredPolicy {
            wallet_id: wallet.id.clone(),
            policy: crate::core::policy::WalletPolicy::allow_all_with_approval(),
            revision: 1,
            updated_at: Utc::now(),
        };
        let result = simulate_execution(&wallet, &default_networks()[0], &plan(2), &policy, None)
            .await
            .unwrap();
        assert!(result.simulation.success, "{result:#?}");
        assert_eq!(result.execution_mode, ExecutionMode::CaliburBatch);
        assert!(result.will_authorize_delegation);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires an Ethereum RPC with eth_simulateV1 support"]
    async fn live_token_balance_probes_use_separate_pinned_simulations() {
        let wallet = WalletMetadata {
            id: "live-token-test".into(),
            address: Address::repeat_byte(0x11),
            created_at: Utc::now(),
            source: WalletSource::Created,
            exported_at: None,
        };
        let weth = address!("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
        let mut execution_plan = plan(1);
        execution_plan.ordered_steps[0].transaction.to = weth;
        execution_plan.ordered_steps[0].transaction.data = balanceOfCall {
            account: wallet.address,
        }
        .abi_encode()
        .into();
        let mut wallet_policy = crate::core::policy::WalletPolicy::allow_all_with_approval();
        wallet_policy.chains.get_mut("*").unwrap().tokens = BTreeMap::from([(
            format!("{weth:#x}"),
            TokenPolicy {
                label: Some("Wrapped Ether".into()),
                max_spend_per_transaction: "0".into(),
                transfer_recipients: BTreeMap::from([(
                    "*".into(),
                    NamedAddressPolicy { label: None },
                )]),
            },
        )]);
        let policy = StoredPolicy {
            wallet_id: wallet.id.clone(),
            policy: wallet_policy,
            revision: 1,
            updated_at: Utc::now(),
        };
        let result = simulate_execution(
            &wallet,
            &default_networks()[0],
            &execution_plan,
            &policy,
            None,
        )
        .await
        .unwrap();
        assert!(result.simulation.success, "{result:#?}");
        assert_eq!(
            result
                .token_spends
                .get(&format!("{weth:#x}"))
                .map(String::as_str),
            Some("0")
        );
    }
}
