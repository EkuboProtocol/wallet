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
        policy::{
            DELEGATION_AUTHORIZED_CODE, DELEGATION_REPLACED_CODE, FindingSeverity, PolicyFinding,
            PolicyOutcome, SIMULATION_FAILED_CODE, evaluate_policy, policy_allows, policy_outcome,
        },
        predicate::PolicyContext,
    },
    fork::{ForkContext, ForkParent, ForkPreface, validate_replay},
    policy_store::StoredPolicy,
    rpc::delegated_implementation,
};
use alloy::{
    consensus::BlockHeader,
    eips::{BlockId, BlockNumberOrTag},
    network::primitives::BlockResponse,
    primitives::{Address, B256, Bytes, U256, address, keccak256},
    providers::Provider,
    rpc::types::{
        Log, TransactionInput, TransactionRequest,
        simulate::{SimBlock, SimCallResult, SimulatePayload},
        state::{AccountOverride, StateOverride},
    },
    sol,
    sol_types::SolCall,
};
use anyhow::{Context as _, Result, ensure};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::{
    collections::{BTreeMap, BTreeSet},
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
    /// True only when the policy allowed every call *and* the simulation
    /// succeeded, i.e. this signs with no prompt. `policy_outcome` says which
    /// of the two a `false` came from.
    pub allowed: bool,
    /// What the policy alone decided, independent of whether the simulation
    /// succeeded: signs automatically, needs a human, or is refused outright
    /// with no approval path at all.
    pub policy_outcome: PolicyOutcome,
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
    context: &PolicyContext,
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

    // Failover, at the granularity of the whole simulation rather than the
    // individual request. Each attempt re-reads the head block and the pinned
    // account state from the endpoint that will run `eth_simulateV1`, because
    // a simulation assembled from one endpoint's block and another's execution
    // is not a simulation of anything.
    //
    // Only `RpcError` moves to the next endpoint. That is the category an
    // endpoint earns by timing out, rate-limiting, or answering
    // `eth_simulateV1` with "method not found" — all facts about the endpoint.
    // A reverted call or a setup failure is a fact about the plan or the
    // chain, and asking seven more endpoints returns the same answer more
    // slowly.
    let required = network.rpc_strategy.required_agreement();
    // Under `m_of_n`, where the quorum simulates is decided before any of them
    // is asked to. Left as `None` under the single-answer strategies, where the
    // endpoint that runs the simulation reads its own head and there is no
    // quorum for a stale one to drag backwards.
    let mut pin = if fork.is_none() {
        crate::rpc::median_head(network).await?
    } else {
        None
    };
    let mut last: Option<SimulationResult> = None;
    // Successful simulations, grouped by the part of them that has to match.
    let mut agreed: Vec<(SimulationAgreement, Vec<String>, SimulationResult)> = Vec::new();
    let endpoints = crate::rpc::endpoint_order(network);
    let mut remaining = endpoints.len();
    for endpoint in endpoints {
        remaining -= 1;
        let provider = crate::rpc::provider_for(endpoint);
        let mut observed_parent = None;
        let result = simulate_execution_through(
            &provider,
            wallet,
            network,
            plan,
            stored_policy,
            context,
            fork,
            pin,
            &mut observed_parent,
        )
        .await?;
        // Under a single-answer strategy the height is still whatever the
        // first endpoint that read a header reported — there is one answer and
        // it is that endpoint's, so there is nothing here to protect. Under
        // `m_of_n` the pin was already set from the median head above, and
        // this cannot move it. Either way the endpoint has by now been shown
        // to be on the chain it was asked about.
        if pin.is_none() && fork.is_none() {
            pin = observed_parent.map(|parent| parent.number);
        }

        if required <= 1 {
            let retryable = result
                .simulation
                .failure
                .as_ref()
                .is_some_and(|failure| failure.category == SimulationFailureCategory::RpcError);
            if !retryable || remaining == 0 {
                return Ok(result);
            }
            last = Some(result);
            continue;
        }

        // Under m_of_n only a *successful* simulation is a vote. A failure is
        // this endpoint declining to witness — it may be down, out of sync,
        // or refusing the method — and demanding that failures match too
        // would turn "two nodes worded a revert differently" into a refusal
        // to produce the reviewable failure the caller is entitled to.
        let Some(parent) = observed_parent else {
            last = Some(result);
            continue;
        };
        if !result.simulation.success {
            last = Some(result);
            continue;
        }
        // No early return at the threshold. Stopping as soon as `required`
        // endpoints agreed made the contradiction branch below unreachable
        // precisely when a contradiction existed: under `m_of_n(2)` over three
        // endpoints, the third — the one about to disagree — was never asked.
        // A quorum that stops listening once it has heard what it needs is not
        // a quorum, and this one decides what an automatic signature is
        // evaluated against.
        let witness = SimulationAgreement::of(&result, parent);
        if let Some(slot) = agreed.iter_mut().find(|(seen, _, _)| *seen == witness) {
            slot.1.push(endpoint.to_string());
        } else {
            agreed.push((witness, vec![endpoint.to_string()], result));
        }
    }

    if required > 1 {
        // The same rule the generic read quorum uses, from the same function,
        // so the two cannot drift apart again.
        let counts: Vec<usize> = agreed
            .iter()
            .map(|(_, witnesses, _)| witnesses.len())
            .collect();
        if let crate::rpc::QuorumVerdict::Agreed(index) =
            crate::rpc::quorum_verdict(&counts, required)
        {
            return Ok(agreed
                .into_iter()
                .nth(index)
                .map(|(_, _, result)| result)
                .expect("the bucket the verdict names is still there"));
        }
        // Endpoints that answered and contradicted each other. This is
        // reported as a simulation failure rather than an error so it lands
        // in front of a human with the reason on the screen: a contradiction
        // between independent operators about a pinned, deterministic read is
        // exactly the thing a person should see before signing, and an
        // `Err` here would collapse it into a failed command.
        if agreed.len() > 1 {
            let mut detail = String::new();
            for (_, witnesses, _) in &agreed {
                let _ = write!(detail, " [{}]", witnesses.join(", "));
            }
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                context,
                planned_call(plan, wallet.address).mode,
                &format!(
                    "the RPC endpoints for {} returned {} different simulations of this plan at \
                     the same block, so none of them was used:{detail}",
                    network.name,
                    agreed.len()
                ),
                pin.unwrap_or_default(),
            ));
        }
        if let Some((_, witnesses, _)) = agreed.first() {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                context,
                planned_call(plan, wallet.address).mode,
                &format!(
                    "{} requires {required} endpoints to agree on this simulation but only {} \
                     produced one",
                    network.name,
                    witnesses.len()
                ),
                pin.unwrap_or_default(),
            ));
        }
        // No endpoint produced a simulation to agree on, so `last` holds one
        // endpoint's failure — and returning it fell out of the loop looking
        // exactly like an answer. Under `m_of_n` one endpoint's word is the
        // thing the owner configured this strategy in order not to act on,
        // and a failure is the word most worth doubting: a reverted plan is
        // reviewed with its effects unavailable, and a human override may
        // sign it anyway, so an endpoint that invents a revert hides what the
        // call really does from the person approving it.
        //
        // The reason still reaches the reviewer, because a plan that honestly
        // reverts everywhere is the ordinary case here and they need to know
        // why. What changes is that it arrives as a setup failure that says
        // the threshold was never met — carrying no gas figures, so nothing
        // downstream can sign against numbers a single endpoint chose.
        let reported = last
            .as_ref()
            .and_then(|result| result.simulation.error.clone())
            .unwrap_or_else(|| "no endpoint answered".to_owned());
        return Ok(setup_failure_result_at_block(
            plan,
            stored_policy,
            context,
            planned_call(plan, wallet.address).mode,
            &format!(
                "{} requires {required} endpoints to agree on this simulation and none produced \
                 one to agree on, so no endpoint's answer was used; the last reported: {reported}",
                network.name
            ),
            pin.unwrap_or_default(),
        ));
    }

    // Unreachable while a network is required to list an endpoint, but a
    // configuration is a file: an empty list must not silently report a
    // successful simulation of nothing.
    last.context("network has no RPC endpoints to simulate against")
}

/// The part of a simulation that independent endpoints must return
/// identically before the wallet will act on it.
///
/// Deliberately a projection rather than the whole result. Left out are the
/// fields that differ for honest reasons — the simulation's own identifier,
/// and the wording a particular node chooses for an error — and the fields
/// derived locally from the plan and the policy, which cannot differ because
/// no endpoint contributes to them. What is left is exactly what an endpoint
/// gets to assert: which block it built on, whether the plan executed, what
/// it cost, what it may cost, what it returned, what moved, and what it found
/// at the wallet's own address.
///
/// "Derived locally" is the line to be careful about, and run 6251 found two
/// fields on the wrong side of it. A value computed here from an endpoint's
/// answer is the endpoint's assertion however much arithmetic sits in
/// between — the delegation fields read as decisions this module makes and
/// are decisions it makes *about the code an endpoint returned*. The test is
/// not who computes the field. It is whether a dishonest endpoint could
/// change it while leaving everything else compared here alone.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SimulationAgreement {
    /// The hash of the block simulated on top of. Two endpoints naming
    /// different blocks at one height are on different chains, or one of them
    /// is lying about which chain it is on.
    parent_hash: alloy::primitives::B256,
    success: bool,
    gas_used: Option<String>,
    /// The ceiling the signed gas limit is computed against, and so the one
    /// number here that reaches the chain rather than the screen. It comes out
    /// of the simulated header, which is the endpoint's to write and is bound
    /// to nothing: an endpoint that matched every other field could set this
    /// alone and either fail preparation outright or collapse the margin
    /// `signing_gas_limit` leaves, so a transaction the quorum agreed on runs
    /// out of gas and burns its fee.
    block_gas_limit: Option<String>,
    output: Option<String>,
    token_spends: BTreeMap<String, String>,
    balance_changes: Option<BalanceChanges>,
    /// What the endpoint said about the wallet's own code, by way of what this
    /// plan would then do about it.
    ///
    /// These read as locally derived and are not: both follow from the code
    /// the endpoint returned for the wallet at the pinned block. An endpoint
    /// reporting canonical delegation code for an EOA that has none turns
    /// `will_authorize_delegation` off while every compared field stays put,
    /// and preparation then signs a plain EIP-1559 call to the wallet itself —
    /// which mines successfully, executing none of the batch. The other
    /// direction buys an unnecessary authorization, or hides that an existing
    /// non-canonical delegation is about to be replaced.
    will_authorize_delegation: bool,
    replaces_delegated_implementation: Option<String>,
}

impl SimulationAgreement {
    fn of(result: &SimulationResult, parent: ForkParent) -> Self {
        Self {
            parent_hash: parent.hash,
            success: result.simulation.success,
            gas_used: result.simulation.gas_used.clone(),
            block_gas_limit: result.simulation.block_gas_limit.clone(),
            output: result.simulation.output.clone(),
            token_spends: result.token_spends.clone(),
            balance_changes: result.balance_changes.clone(),
            will_authorize_delegation: result.will_authorize_delegation,
            replaces_delegated_implementation: result.replaces_delegated_implementation.clone(),
        }
    }
}

async fn simulate_execution_through(
    provider: &alloy::providers::DynProvider,
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
    stored_policy: &StoredPolicy,
    context: &PolicyContext,
    fork: Option<&ForkPreface>,
    pin: Option<u64>,
    observed_parent: &mut Option<ForkParent>,
) -> Result<SimulationResult> {
    let planned = planned_call(plan, wallet.address);
    let fork_calls: &[PlannedCall] = fork.map_or(&[], |preface| preface.calls.as_slice());
    let setup = tokio::time::timeout(RPC_SETUP_TIMEOUT, async {
        let chain_id = provider.get_chain_id().await?;
        // A fork already pinned its parent when it was created, and that
        // header can no longer change, so replay never re-reads it.
        // Pinned when a previous endpoint already chose the block: two
        // endpoints simulating the same plan at different heights would
        // disagree for an entirely honest reason, and comparing those answers
        // would measure block times rather than truthfulness. Each endpoint
        // still reads the header itself, so a disagreement about *which*
        // block that height holds is one of the things agreement catches.
        let block = match (fork, pin) {
            (Some(_), _) => None,
            (None, Some(number)) => {
                provider
                    .get_block_by_number(BlockNumberOrTag::Number(number))
                    .await?
            }
            (None, None) => {
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
                        context,
                        planned.mode,
                        "RPC returned no latest block",
                    ));
                }
            };
            (chain_id, parent)
        }
        Err(error) => {
            return Ok(rpc_failure_result(
                plan,
                stored_policy,
                context,
                planned.mode,
                &error,
            ));
        }
    };
    if chain_id != network.chain_id {
        return Ok(setup_failure_result(
            plan,
            stored_policy,
            context,
            planned.mode,
            &format!("RPC reports chain {chain_id}, not {}", network.chain_id),
        ));
    }
    // Reported only now, after the endpoint has been shown to be on the chain
    // it was asked about. The caller promotes this to the height every later
    // endpoint is held to, so writing it before the check let an endpoint that
    // was about to be disqualified for serving the wrong chain still choose
    // where the quorum simulates.
    *observed_parent = Some(parent);

    let block_number = parent.number;
    let gas_limit = match effective_gas_limit(network, parent.gas_limit) {
        Ok(limit) => limit,
        Err(error) => {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                context,
                planned.mode,
                &error.to_string(),
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
                context,
                planned.mode,
                &error,
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
                    context,
                    planned.mode,
                    &error,
                    block_number,
                ));
            }
        };
        if implementation_code.is_empty() {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                context,
                planned.mode,
                "Calibur implementation is not deployed on this chain",
                block_number,
            ));
        }
        let runtime_hash = keccak256(&implementation_code);
        if runtime_hash != CANONICAL_CALIBUR_RUNTIME_HASH {
            return Ok(setup_failure_result_at_block(
                plan,
                stored_policy,
                context,
                planned.mode,
                &format!(
                    "Calibur runtime code hash mismatch: expected {CANONICAL_CALIBUR_RUNTIME_HASH:#x}, received {runtime_hash:#x}"
                ),
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
                    context,
                    planned.mode,
                    "wallet has code that is not an EIP-7702 delegation designator",
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
            context,
            planned.mode,
            &format!(
                "policy tracks {} tokens; eth_simulateV1 supports at most {MAX_TRACKED_TOKENS} balance probes",
                tracked_tokens.len()
            ),
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
                context,
                planned.mode,
                &error,
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
                context,
                planned.mode,
                &error.to_string(),
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
                context,
                planned.mode,
                "fork replay native transfer logs do not reconcile with the pinned balance",
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
            context,
            planned.mode,
            &format!(
                "eth_simulateV1 returned {} call results for {expected_calls} calls",
                simulated.calls.len()
            ),
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
                    context,
                    planned.mode,
                    "pre-balance eth_simulateV1 response did not match the pinned request",
                    block_number,
                ));
            };
            let block = blocks.pop().expect("validated pre-balance block");
            if block.calls.len() != tracked_tokens.len() {
                return Ok(setup_failure_result_at_block(
                    plan,
                    stored_policy,
                    context,
                    planned.mode,
                    "pre-balance eth_simulateV1 response did not match the pinned request",
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
            context,
            planned.mode,
            "eth_simulateV1 native transfer logs do not reconcile with the pinned balance",
            block_number,
        ));
    };
    let mut all_tokens = tracked_tokens.iter().copied().collect::<BTreeSet<_>>();
    all_tokens.extend(activity.keys().copied());
    let token_spends_public = observed_token_spends(
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

    let mut findings = evaluate_policy(plan, &stored_policy.policy, context);
    let simulation = execution_output(plan, main, simulated_header.gas_limit());
    // A plan that does not execute is never allowed, whatever the policy says
    // about its calls: there is no policy setting that turns a revert into an
    // automatic signature.
    if !simulation.success {
        findings.push(PolicyFinding {
            severity: FindingSeverity::Error,
            code: SIMULATION_FAILED_CODE.into(),
            message: "eth_simulateV1 execution did not succeed".into(),
            step: None,
        });
    }
    // Replacing the account's delegation is not one of the plan's calls, so no
    // allowlist covering those calls has anything to say about it. Without
    // this the replacement was a sentence in the review document only, and the
    // automatic path never draws a review document.
    if let Some(replaced) = &replaces {
        findings.push(PolicyFinding {
            severity: FindingSeverity::Error,
            code: DELEGATION_REPLACED_CODE.into(),
            message: format!(
                "this batch would replace the account's EIP-7702 delegation to {replaced} with \
                 {CANONICAL_CALIBUR:#x}, which persists whether or not the batch succeeds and \
                 may leave the previous implementation's storage under one that reads it \
                 differently"
            ),
            step: None,
        });
    } else if will_authorize {
        // Whether the finding above fires is decided by one `get_code_at`
        // answer. An endpoint that reports empty code for an account that is
        // actually delegated elsewhere takes the `None if is_empty` branch:
        // the authorization is still signed and the replacement still happens
        // on chain, but `replaces` is None, so nothing above says so and the
        // automatic path never draws a document to say it in.
        //
        // Disclosing the authorization itself does not depend on that answer
        // being honest. A warning rather than an error because a first
        // delegation is what every account's first batch does, and refusing it
        // would mean no unattended batch could ever run.
        findings.push(PolicyFinding {
            severity: FindingSeverity::Warning,
            code: DELEGATION_AUTHORIZED_CODE.into(),
            message: format!(
                "this batch would sign an EIP-7702 authorization delegating the account to \
                 {CANONICAL_CALIBUR:#x}, which persists whether or not the batch succeeds; the \
                 account was observed to have no delegation, and if that observation is wrong \
                 this authorization replaces whatever is actually there"
            ),
            step: None,
        });
    }
    Ok(SimulationResult {
        // Stamped by the caller that records it, if it records it at all.
        simulation_id: None,
        digest: format!("{:#x}", plan.digest()),
        allowed: simulation.success && policy_allows(&findings),
        policy_outcome: policy_outcome(&findings),
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
    policy
        .chain(chain_id)
        .map_or_else(Vec::new, crate::core::policy::ChainPolicy::named_addresses)
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
) -> BTreeMap<String, String> {
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
    observed
        .into_iter()
        .map(|(token, amount)| (format!("{token:#x}"), amount.to_string()))
        .collect()
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
    SimulationFailure {
        category,
        message: message.to_owned(),
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
            // Quoted and attributed rather than restated as this wallet's own
            // conclusion. The reverting contract is named by the plan, and a
            // `require` string is whatever its author chose to put there, so
            // presenting it as the simulation's finding lends it a standing it
            // has not got.
            let message = match decoded.name.as_str() {
                "Error" => decoded
                    .args
                    .first()
                    .and_then(Value::as_str)
                    .map(|reason| format!("reverted with reason {reason:?}")),
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
                // `revert_decode` is supplied by whoever wrote the plan and is
                // outside the digest, so this name is the plan's reading of the
                // revert rather than an independent one. Say whose reading it
                // is: the sentence lands in the approval screen beside findings
                // this wallet reached for itself.
                decoded_error = Some(DecodedSimulationError {
                    message: Some(format!(
                        "reverted as {}, per the error ABI the plan supplied",
                        decoded.name
                    )),
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
    context: &PolicyContext,
    mode: ExecutionMode,
    failure: SimulationFailure,
    block_number: u64,
) -> SimulationResult {
    let mut findings = evaluate_policy(plan, &stored_policy.policy, context);
    findings.push(PolicyFinding {
        severity: FindingSeverity::Error,
        code: SIMULATION_FAILED_CODE.into(),
        message: "eth_simulateV1 simulation did not succeed".into(),
        step: None,
    });
    // A failure can happen before the wallet's code was ever read, so this
    // result knows nothing about the account's delegation — and it says so
    // rather than letting `replaces_delegated_implementation: None` be read as
    // "there is nothing to replace". It is not: the field is empty because
    // nobody looked.
    //
    // The distinction matters because a failed simulation is exactly the case
    // a human is asked to override, and the review document draws its
    // replacement warning from that same empty field. Overriding the failure
    // would then sign an authorization that silently replaces a delegation the
    // document never mentioned.
    if mode == ExecutionMode::CaliburBatch {
        findings.push(PolicyFinding {
            severity: FindingSeverity::Warning,
            code: DELEGATION_AUTHORIZED_CODE.into(),
            message: format!(
                "this batch would sign an EIP-7702 authorization delegating the account to \
                 {CANONICAL_CALIBUR:#x}, and the simulation failed before the account's current \
                 delegation could be observed; if it is already delegated elsewhere, this \
                 replaces that, and the replacement persists whether or not the batch succeeds"
            ),
            step: None,
        });
    }
    SimulationResult {
        simulation_id: None,
        digest: format!("{:#x}", plan.digest()),
        allowed: false,
        policy_outcome: policy_outcome(&findings),
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
    context: &PolicyContext,
    mode: ExecutionMode,
    error: &anyhow::Error,
) -> SimulationResult {
    rpc_failure_result_at_block(plan, policy, context, mode, error, 0)
}

fn rpc_failure_result_at_block(
    plan: &ExecutionPlan,
    policy: &StoredPolicy,
    context: &PolicyContext,
    mode: ExecutionMode,
    error: &anyhow::Error,
    block_number: u64,
) -> SimulationResult {
    base_failure_result(
        plan,
        policy,
        context,
        mode,
        failure(
            plan,
            SimulationFailureCategory::RpcError,
            &error.to_string(),
            None,
        ),
        block_number,
    )
}

fn setup_failure_result(
    plan: &ExecutionPlan,
    policy: &StoredPolicy,
    context: &PolicyContext,
    mode: ExecutionMode,
    message: &str,
) -> SimulationResult {
    setup_failure_result_at_block(plan, policy, context, mode, message, 0)
}

fn setup_failure_result_at_block(
    plan: &ExecutionPlan,
    policy: &StoredPolicy,
    context: &PolicyContext,
    mode: ExecutionMode,
    message: &str,
    block_number: u64,
) -> SimulationResult {
    base_failure_result(
        plan,
        policy,
        context,
        mode,
        failure(
            plan,
            SimulationFailureCategory::SimulationSetupError,
            message,
            None,
        ),
        block_number,
    )
}

#[cfg(test)]
#[path = "simulation_test.rs"]
mod tests;
