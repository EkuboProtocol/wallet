//! Owner-installed bytecode that the wallet polls on a schedule and turns into
//! calls.
//!
//! An automation is EVM runtime bytecode plus a cron expression, bound to one
//! wallet, one network, and one policy revision. Each tick runs the bytecode
//! through `eth_simulateV1` — installed as the code at the wallet's own address
//! — and decodes an `(address,uint256,bytes)[]` out of the return value. Those
//! calls become an ordinary [`ExecutionPlan`], which means everything after
//! this module is the path any other plan takes: exact simulation, exact
//! preparation, policy evaluation, and only then a signature.
//!
//! Nothing here signs, and nothing here decides authority. A blob can emit any
//! call it likes; whether that call executes is the policy's answer, given at
//! send time to the synthesized plan. See [docs/automation.md].
//!
//! The override is installed at the wallet's own address rather than at a
//! scratch address on purpose. A scratch address gives only the outermost call
//! the wallet as `msg.sender`; every call the blob makes downstream would come
//! from the scratch address, so a `msg.sender`-gated `claim` reverts during the
//! poll and succeeds in the batch the wallet would actually send. Running at
//! the wallet's address makes the poll agree with execution — at the cost,
//! documented for authors, of displacing the EIP-7702 delegation for the
//! duration of the poll.
//!
//! [docs/automation.md]: https://github.com/EkuboProtocol/wallet/blob/main/docs/automation.md

use crate::{
    chain_client::ChainClient,
    core::execution_plan::{
        DecimalU256, ExecutionPlan, ExecutionStep, ExecutionStepKind, MAX_EXECUTION_STEPS,
        MAX_TOTAL_CALLDATA_BYTES, PlannedTransaction,
    },
};
use alloy::{
    eips::BlockNumberOrTag,
    network::primitives::BlockResponse,
    primitives::{Address, B256, Bytes, U256, keccak256},
    rpc::types::{
        TransactionInput, TransactionRequest,
        simulate::{SimBlock, SimulatePayload},
        state::{AccountOverride, StateOverride},
    },
    sol,
    sol_types::SolCall,
};
use anyhow::{Context as _, Result, bail, ensure};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr, time::Duration};
use uuid::Uuid;

sol! {
    struct AutomationCall {
        address to;
        uint256 value;
        bytes data;
    }

    /// The entry point every automation exposes. Not `view`: the blob runs
    /// inside a simulation whose writes are discarded, so it is free to perform
    /// the call it is considering and inspect the result before emitting it.
    function automate(bytes config) external returns (AutomationCall[] calls);
}

/// The most runtime bytecode an automation may carry.
///
/// The mainnet contract-size limit is 24 KiB and this is not a contract that
/// gets deployed, so the limit is a storage and review bound rather than a
/// consensus one. A blob is a `BLOB` column the database keeps, bytes the
/// state override ships on every single tick, and a hash a human is asked to
/// compare. Generous against anything an automation plausibly needs, and small
/// enough that a per-second schedule cannot turn the RPC bill into a payload
/// problem.
pub const MAX_BYTECODE_BYTES: usize = 49_152;

/// The most owner-supplied configuration an automation may carry.
///
/// `config` exists so one blob serves many parameterizations without
/// recompiling — an address, a threshold, a pool key. It is not a data channel,
/// and a caller who needs more than this wants storage they can read on chain.
pub const MAX_CONFIG_BYTES: usize = 8_192;

/// The longest display name an automation may carry.
pub const MAX_NAME_LEN: usize = 120;

/// The longest cron expression this accepts, before parsing decides whether it
/// means anything. Bounds the parser's input rather than describing a real
/// schedule; a six-field expression naming every value it can name is well
/// under this.
pub const MAX_CRON_LEN: usize = 256;

/// Consecutive failed ticks before an automation stops trying.
///
/// A tick that fails is one of three things — the endpoint is unreachable, the
/// blob reverted, or the return value did not decode. All three repeat: no
/// blob rewrites itself, and an endpoint that has been down for ten ticks is
/// not the kind of outage a wallet should keep quietly retrying past. Stopping
/// makes the failure something the owner sees.
pub const MAX_CONSECUTIVE_FAILURES: u32 = 10;

/// How long a tick's whole RPC conversation may take before it is a failure.
///
/// Deliberately shorter than the plan-simulation timeouts either side of it:
/// this is one call against one endpoint, and a tick that outlives its own
/// schedule is a tick the scheduler is going to skip anyway.
pub const POLL_TIMEOUT: Duration = Duration::from_secs(20);

/// What an automation is doing, and whether the scheduler will run it.
///
/// Only `Enabled` ticks. The other two are both "stopped", kept apart because
/// they are recovered from differently and because collapsing them would hide
/// the distinction that matters most to an owner: whether the automation broke,
/// or whether *they* changed something underneath it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutomationState {
    Enabled,
    /// It failed, and `stopped_reason` says how. The owner re-enables it, which
    /// also rebinds it to the current policy revision.
    Disabled,
    /// The policy revision moved after it was installed. Nothing is wrong with
    /// the automation; the authority it was installed under no longer exists,
    /// and the owner has to look at it again.
    AwaitingRelink,
}

impl AutomationState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::AwaitingRelink => "awaiting_relink",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            "awaiting_relink" => Ok(Self::AwaitingRelink),
            other => bail!("unknown automation state {other:?}"),
        }
    }
}

/// A parsed cron expression, kept beside the exact text the owner approved.
///
/// The text is what a review shows and what the database stores, so it must
/// survive a round trip unchanged: a schedule redisplayed as some normalized
/// spelling is a schedule the owner cannot compare against the one they
/// approved.
#[derive(Clone, Debug)]
pub struct CronSchedule {
    expression: String,
    schedule: cron::Schedule,
}

impl CronSchedule {
    /// Parses a six-field expression, seconds first.
    ///
    /// Six fields rather than five because minute resolution cannot express
    /// "about every block", which is the cadence automations exist for. The
    /// `cron` crate requires the seconds field, so a five-field expression
    /// pasted from a crontab is rejected here rather than silently reinterpreted
    /// — its minute field would land in the seconds column and the schedule
    /// would fire sixty times too often.
    pub fn parse(expression: &str) -> Result<Self> {
        let trimmed = expression.trim();
        ensure!(!trimmed.is_empty(), "cron expression is empty");
        ensure!(
            trimmed.len() <= MAX_CRON_LEN,
            "cron expression exceeds {MAX_CRON_LEN} characters"
        );
        let fields = trimmed.split_whitespace().count();
        ensure!(
            (6..=7).contains(&fields),
            "cron expression has {fields} fields; automations use six, seconds first \
             (for example \"*/12 * * * * *\" for roughly every block)"
        );
        let schedule = cron::Schedule::from_str(trimmed)
            .with_context(|| format!("cron expression {trimmed:?} is not a schedule"))?;
        // A syntactically valid expression that names no moment at all — the
        // 31st of February — parses and then never fires. Better to refuse it
        // at install than to display "next run: never" forever.
        ensure!(
            schedule.upcoming(Utc).next().is_some(),
            "cron expression {trimmed:?} never fires"
        );
        Ok(Self {
            expression: trimmed.to_owned(),
            schedule,
        })
    }

    #[must_use]
    pub fn expression(&self) -> &str {
        &self.expression
    }

    /// The first fire time strictly after `after`.
    ///
    /// Strictly after, so a tick that completes within the same second as the
    /// one that scheduled it cannot immediately re-fire on its own timestamp.
    #[must_use]
    pub fn next_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.schedule.after(&after).next()
    }

    /// The next `count` fire times, for showing an owner what a schedule means
    /// before they approve it. An expression is not a cadence anybody reads at
    /// a glance.
    #[must_use]
    pub fn preview(&self, after: DateTime<Utc>, count: usize) -> Vec<DateTime<Utc>> {
        self.schedule.after(&after).take(count).collect()
    }
}

impl PartialEq for CronSchedule {
    fn eq(&self, other: &Self) -> bool {
        self.expression == other.expression
    }
}

impl Eq for CronSchedule {}

impl fmt::Display for CronSchedule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.expression)
    }
}

/// One installed automation, exactly as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Automation {
    pub id: Uuid,
    pub wallet_instance_id: Uuid,
    pub wallet_id: String,
    pub wallet_address: Address,
    pub chain_id: u64,
    /// Owner-facing label. Untrusted display text: it names the automation in
    /// lists and notifications and decides nothing.
    pub name: String,
    pub bytecode: Bytes,
    pub config: Bytes,
    pub schedule: CronSchedule,
    /// The policy revision this automation was installed or relinked against.
    /// A tick whose current revision differs does not run.
    pub policy_revision: u64,
    pub state: AutomationState,
    /// Why it stopped, when it is not `Enabled`. Owner-facing text.
    pub stopped_reason: Option<String>,
    pub consecutive_failures: u32,
    pub last_tick_at: Option<DateTime<Utc>>,
    pub last_outcome: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Automation {
    /// The identity a review shows. An owner cannot read runtime bytecode, but
    /// they can compare a hash to the one the agent that compiled it reported.
    #[must_use]
    pub fn bytecode_hash(&self) -> B256 {
        keccak256(&self.bytecode)
    }
}

/// Everything about an automation that the owner authorizes, separated from the
/// bookkeeping the wallet maintains.
///
/// This is what an agent proposes and what a review renders. It is deliberately
/// not [`Automation`]: an agent has no business supplying a policy revision, a
/// failure count, or the moment of the last tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutomationDefinition {
    pub name: String,
    pub bytecode: Bytes,
    pub config: Bytes,
    pub schedule: CronSchedule,
    pub chain_id: u64,
}

impl AutomationDefinition {
    pub fn new(
        name: &str,
        bytecode: Bytes,
        config: Bytes,
        schedule: CronSchedule,
        chain_id: u64,
    ) -> Result<Self> {
        let name = name.trim();
        ensure!(!name.is_empty(), "automation name is empty");
        ensure!(
            name.chars().count() <= MAX_NAME_LEN,
            "automation name exceeds {MAX_NAME_LEN} characters"
        );
        // Refused rather than sanitized. Every other stored label the wallet
        // shows arrives from a third party it cannot argue with — a token
        // symbol, a dapp's title — so it is stripped and drawn. A name is
        // supplied by whoever is installing the automation, and the useful
        // answer to a control character in one is to say so while they can
        // still fix it.
        ensure!(
            !name.chars().any(crate::sanitize::is_disallowed),
            "automation name contains a control, bidirectional, or invisible character"
        );
        ensure!(!bytecode.is_empty(), "automation bytecode is empty");
        ensure!(
            bytecode.len() <= MAX_BYTECODE_BYTES,
            "automation bytecode is {} bytes, over the {MAX_BYTECODE_BYTES}-byte limit",
            bytecode.len()
        );
        // A blob whose first byte is 0xEF cannot be deployed code: the prefix
        // is reserved by EIP-3541 and, as EIP-7702's delegation designator,
        // is what a delegated account's "code" actually looks like. Someone
        // supplying one has pasted an account's code field rather than a
        // compiler's runtime output, and the poll would run a delegation
        // indicator as a program.
        ensure!(
            bytecode[0] != 0xEF,
            "automation bytecode starts with 0xEF, which is not runtime code — this looks \
             like an EIP-7702 delegation designator or an EOF container rather than a \
             compiler's deployedBytecode"
        );
        ensure!(
            config.len() <= MAX_CONFIG_BYTES,
            "automation config is {} bytes, over the {MAX_CONFIG_BYTES}-byte limit",
            config.len()
        );
        ensure!(chain_id > 0, "automation chain id must be positive");
        Ok(Self {
            name: name.to_owned(),
            bytecode,
            config,
            schedule,
            chain_id,
        })
    }

    #[must_use]
    pub fn bytecode_hash(&self) -> B256 {
        keccak256(&self.bytecode)
    }
}

/// Why a tick produced no calls.
///
/// Kept apart because they read differently to whoever is debugging: an
/// endpoint failure is about the wallet's connectivity, a revert is about the
/// blob's logic, and a decode failure is about its return type. All three count
/// the same toward [`MAX_CONSECUTIVE_FAILURES`], because all three repeat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollFailure {
    /// The endpoint could not be reached, timed out, or refused the method.
    Rpc(String),
    /// The blob ran and reverted.
    Reverted {
        message: String,
        /// The exact return data, hex-encoded. An agent iterating on bytecode
        /// needs the bytes, not a summary of them.
        revert_data: String,
        /// The leading four bytes, when there are four to have.
        revert_selector: Option<String>,
        /// `Error(string)` or `Panic(uint256)`, when the revert was one.
        decoded: Option<String>,
    },
    /// The blob returned successfully, and the bytes were not an
    /// `(address,uint256,bytes)[]`.
    Undecodable {
        message: String,
        return_data: String,
    },
}

impl fmt::Display for PollFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(message) => write!(formatter, "RPC error: {message}"),
            Self::Reverted {
                message, decoded, ..
            } => match decoded {
                Some(decoded) => write!(formatter, "automation reverted: {decoded}"),
                None => write!(formatter, "automation reverted: {message}"),
            },
            Self::Undecodable { message, .. } => {
                write!(
                    formatter,
                    "automation return value did not decode: {message}"
                )
            }
        }
    }
}

/// What one tick learned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollOutcome {
    /// Empty means the blob had nothing to do this tick, which is the normal
    /// case and not a failure.
    pub calls: Vec<PolledCall>,
    pub gas_used: u64,
    /// The block the poll observed, for the record an owner reads later.
    pub block_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolledCall {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
}

/// Run one automation through `eth_simulateV1` and decode what it wants done.
///
/// Performs no policy evaluation and no signing: the caller takes the calls to
/// [`synthesize_plan`] and then through the ordinary send path, which is where
/// authority is decided.
pub async fn poll(
    client: &dyn ChainClient,
    wallet: Address,
    bytecode: &Bytes,
    config: &Bytes,
) -> Result<Result<PollOutcome, PollFailure>> {
    let setup = tokio::time::timeout(POLL_TIMEOUT, async {
        let block = client
            .block_by_number(BlockNumberOrTag::Latest)
            .await?
            .context("endpoint returned no latest block")?;
        let header = block.header();
        Ok::<_, anyhow::Error>((header.number, header.gas_limit))
    })
    .await;
    let (block_number, gas_limit) = match setup {
        Err(_) => {
            return Ok(Err(PollFailure::Rpc(
                "reading the head block timed out".into(),
            )));
        }
        Ok(Err(error)) => return Ok(Err(PollFailure::Rpc(format!("{error:#}")))),
        Ok(Ok(head)) => head,
    };

    let payload = poll_payload(wallet, bytecode, config, gas_limit);
    let simulated = tokio::time::timeout(
        POLL_TIMEOUT,
        client.simulate_v1(payload, Some(block_number)),
    )
    .await;
    let blocks = match simulated {
        Err(_) => return Ok(Err(PollFailure::Rpc("eth_simulateV1 timed out".into()))),
        Ok(Err(error)) => return Ok(Err(PollFailure::Rpc(format!("{error:#}")))),
        Ok(Ok(blocks)) => blocks,
    };

    let Some(result) = blocks.first().and_then(|block| block.calls.first()) else {
        return Ok(Err(PollFailure::Rpc(
            "eth_simulateV1 returned no call result for the automation".into(),
        )));
    };
    if !result.status {
        return Ok(Err(revert_failure(
            &result.return_data,
            result.error.as_ref(),
        )));
    }
    match automateCall::abi_decode_returns(&result.return_data) {
        Err(error) => Ok(Err(PollFailure::Undecodable {
            message: format!("{error}"),
            return_data: hex_of(&result.return_data),
        })),
        Ok(calls) => match bound_calls(&calls) {
            Err(error) => Ok(Err(PollFailure::Undecodable {
                message: format!("{error:#}"),
                return_data: hex_of(&result.return_data),
            })),
            Ok(calls) => Ok(Ok(PollOutcome {
                calls,
                gas_used: result.gas_used,
                block_number,
            })),
        },
    }
}

/// The exact `eth_simulateV1` payload one tick sends.
///
/// Separated from [`poll`] so a test can assert the shape — the code override
/// lands on the wallet's own address and the call comes from it — without an
/// endpoint.
#[must_use]
pub fn poll_payload(
    wallet: Address,
    bytecode: &Bytes,
    config: &Bytes,
    gas_limit: u64,
) -> SimulatePayload {
    let mut overrides = StateOverride::default();
    overrides.insert(
        wallet,
        AccountOverride::default().with_code(bytecode.clone()),
    );
    let request = TransactionRequest::default()
        .from(wallet)
        .to(wallet)
        .gas_limit(gas_limit)
        .input(TransactionInput::new(
            automateCall {
                config: config.clone(),
            }
            .abi_encode()
            .into(),
        ));
    SimulatePayload {
        block_state_calls: vec![
            SimBlock::default()
                .with_state_overrides(overrides)
                .extend_calls(vec![request]),
        ],
        trace_transfers: false,
        // The poll is a read. Nothing it returns is signed, and a blob that
        // wants to probe a call the wallet could not afford should learn that
        // from the plan simulation, which does validate.
        validation: false,
        return_full_transactions: false,
    }
}

/// Reject a call list that could not become a plan before it becomes one.
///
/// The bounds are the execution plan's own, not a second set: a list this
/// rejects is a list `ExecutionPlan::validate` would reject a moment later,
/// and rediscovering that at plan-synthesis time would report it as a
/// malformed plan rather than as what it is — a blob that returned too much.
fn bound_calls(calls: &[AutomationCall]) -> Result<Vec<PolledCall>> {
    ensure!(
        calls.len() <= MAX_EXECUTION_STEPS,
        "automation returned {} calls, over the {MAX_EXECUTION_STEPS}-call limit",
        calls.len()
    );
    let mut total = 0_usize;
    for call in calls {
        total = total
            .checked_add(call.data.len())
            .context("automation calldata size overflow")?;
        ensure!(
            total <= MAX_TOTAL_CALLDATA_BYTES,
            "automation returned more than {MAX_TOTAL_CALLDATA_BYTES} bytes of calldata"
        );
    }
    Ok(calls
        .iter()
        .map(|call| PolledCall {
            to: call.to,
            value: call.value,
            data: Bytes::copy_from_slice(&call.data),
        })
        .collect())
}

/// Turn a tick's calls into the plan the ordinary send path consumes.
///
/// Every step is `Execution`: an automation's calls are all the thing it asked
/// for, and labelling one of them an approval would be a guess about calldata
/// this module deliberately does not decode.
pub fn synthesize_plan(
    wallet: Address,
    chain_id: u64,
    calls: &[PolledCall],
) -> Result<ExecutionPlan> {
    ensure!(
        !calls.is_empty(),
        "an automation that returned no calls has no plan"
    );
    let chain = DecimalU256::new(chain_id.to_string())?;
    let ordered_steps = calls
        .iter()
        .enumerate()
        .map(|(index, call)| {
            let step = u32::try_from(index + 1).context("automation call index overflow")?;
            Ok(ExecutionStep {
                step,
                kind: ExecutionStepKind::Execution,
                transaction: PlannedTransaction {
                    chain_id: chain.clone(),
                    from: wallet,
                    to: call.to,
                    data: call.data.clone(),
                    value: DecimalU256::new(call.value.to_string())?,
                    // Left to the wallet's own exact preparation, which is the
                    // only place a gas limit is allowed to come from for
                    // something nobody reviews.
                    gas: None,
                },
                revert_decode: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let plan = ExecutionPlan {
        schema_version: "1".into(),
        chain_id: chain,
        caip2_chain_id: format!("eip155:{chain_id}"),
        sender: wallet,
        ordered_steps,
        required_capabilities: Vec::new(),
        extensions: serde_json::Map::new(),
        simulation_failure_policy: None,
    };
    plan.validate()?;
    Ok(plan)
}

fn revert_failure(return_data: &Bytes, error: Option<&impl fmt::Debug>) -> PollFailure {
    let selector = (return_data.len() >= 4).then(|| hex_of(&return_data[..4]));
    PollFailure::Reverted {
        message: error.map_or_else(
            || "the automation reverted without a message".to_owned(),
            |error| format!("{error:?}"),
        ),
        revert_data: hex_of(return_data),
        revert_selector: selector,
        decoded: decode_standard_revert(return_data),
    }
}

/// `Error(string)` and `Panic(uint256)`, the two reverts solc emits on its own.
///
/// Anything else stays hex: this module has no ABI for the blob's own errors,
/// and guessing at one would put an invented decoding in front of an agent
/// trying to debug real bytes.
fn decode_standard_revert(data: &Bytes) -> Option<String> {
    if data.len() < 4 {
        return None;
    }
    match &data[..4] {
        // Error(string)
        [0x08, 0xc3, 0x79, 0xa0] => {
            let decoded = alloy::sol_types::SolValue::abi_decode(&data[4..]).ok()?;
            let message: String = decoded;
            Some(format!("Error({message:?})"))
        }
        // Panic(uint256)
        [0x4e, 0x48, 0x7b, 0x71] => {
            let code: U256 = alloy::sol_types::SolValue::abi_decode(&data[4..]).ok()?;
            Some(format!("Panic({code:#x})"))
        }
        _ => None,
    }
}

fn hex_of(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
#[path = "automation_test.rs"]
mod tests;
