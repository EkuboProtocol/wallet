use alloy::json_abi::JsonAbi;
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use anyhow::{Context, Result, bail, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{fmt, str::FromStr};

const MAX_EXECUTION_STEPS: usize = 4_096;
const MAX_TOTAL_CALLDATA_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SERIALIZED_PLAN_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Hash, JsonSchema)]
#[schemars(transparent)]
pub struct DecimalU256(String);

impl DecimalU256 {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        ensure!(
            value == "0"
                || (value.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    && !value.starts_with('0')
                    && value.bytes().all(|byte| byte.is_ascii_digit())),
            "must be a canonical unsigned decimal quantity"
        );
        U256::from_str(&value).context("decimal quantity must fit uint256")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn value(&self) -> U256 {
        U256::from_str(&self.0).expect("validated decimal U256")
    }
}

impl fmt::Display for DecimalU256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for DecimalU256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DecimalU256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStepKind {
    Approval,
    Execution,
    AllowanceCleanup,
    SignatureDependentExecution,
    Other,
}

impl ExecutionStepKind {
    /// Why this step is in the plan at all, where that is not simply "it is
    /// the thing you asked for".
    ///
    /// A plan's own call needs no explanation: the review already carries a
    /// decoded account of what it does, directly above this, and answering
    /// "why is this here" with "does the work you asked for" spent a line of a
    /// security review saying nothing. The steps worth naming are the ones a
    /// reader did not ask for and would otherwise have to account for
    /// themselves — an allowance granted before the call, the same allowance
    /// taken back after it, a call that spends a signature approved earlier.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Approval => Some("Grants a spending allowance the next call needs"),
            Self::AllowanceCleanup => Some("Takes that spending allowance back afterwards"),
            Self::SignatureDependentExecution => Some("Uses a signature you approved earlier"),
            // "Does the work you asked for" and "Something else" are both
            // true of every plan and useful about none of them.
            Self::Execution | Self::Other => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PlannedTransaction {
    pub chain_id: DecimalU256,
    #[schemars(with = "String")]
    pub from: Address,
    #[schemars(with = "String")]
    pub to: Address,
    #[schemars(with = "String")]
    pub data: Bytes,
    pub value: DecimalU256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<DecimalU256>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStep {
    pub step: u32,
    pub kind: ExecutionStepKind,
    pub transaction: PlannedTransaction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_decode: Option<RevertDecodePlan>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevertDecodePlan {
    ErrorResult {
        #[schemars(schema_with = "crate::abi_decoder::any_json_array_schema")]
        abi: Vec<Value>,
        #[serde(default)]
        required: bool,
    },
}

impl RevertDecodePlan {
    #[must_use]
    pub fn abi(&self) -> &[Value] {
        match self {
            Self::ErrorResult { abi, .. } => abi,
        }
    }

    fn validate(&self) -> Result<()> {
        const MAX_ABI_ENTRIES: usize = 128;
        const MAX_ABI_BYTES: usize = 65_536;
        let abi = self.abi();
        ensure!(
            (1..=MAX_ABI_ENTRIES).contains(&abi.len()),
            "revert_decode ABI must contain 1-{MAX_ABI_ENTRIES} entries"
        );
        let encoded = serde_json::to_vec(abi)?;
        ensure!(
            encoded.len() <= MAX_ABI_BYTES,
            "revert_decode ABI exceeds {MAX_ABI_BYTES} bytes"
        );
        let parsed: JsonAbi =
            serde_json::from_slice(&encoded).context("revert_decode ABI is malformed")?;
        ensure!(
            parsed.errors.values().flatten().next().is_some(),
            "revert_decode ABI must contain at least one error"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SimulationFailureAction {
    RetrySamePlan,
    RepreparePlan,
    UserReview,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimulationFailureDirective {
    pub action: SimulationFailureAction,
    pub instruction: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimulationFailurePolicy {
    pub rpc_error: SimulationFailureDirective,
    pub execution_reverted: SimulationFailureDirective,
    pub simulation_setup_error: SimulationFailureDirective,
}

/// The behaviors this wallet implements that a plan may require. A plan
/// listing anything else is rejected outright: a capability the wallet cannot
/// honor silently is a plan it must not execute. `atomic_batch` is trivially
/// satisfied — multi-step plans always execute as one atomic Calibur EIP-7702
/// batch with `revertOnFailure` (see `simulation::planned_call`).
const SUPPORTED_CAPABILITIES: &[&str] = &["atomic_batch"];
const MAX_REQUIRED_CAPABILITIES: usize = 32;
const MAX_EXTENSIONS_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    pub schema_version: String,
    pub chain_id: DecimalU256,
    pub caip2_chain_id: String,
    #[schemars(with = "String")]
    pub sender: Address,
    #[schemars(length(min = 1, max = 4096))]
    pub ordered_steps: Vec<ExecutionStep>,
    /// Capabilities this plan requires of the executing wallet; every entry
    /// must be in `SUPPORTED_CAPABILITIES` or the plan is rejected.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    /// Producer extension bag: ignored by this wallet, but size-bounded so it
    /// cannot become a smuggling or bloat channel.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    #[schemars(schema_with = "crate::abi_decoder::any_json_object_schema")]
    pub extensions: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation_failure_policy: Option<SimulationFailurePolicy>,
}

impl ExecutionPlan {
    pub fn parse(input: Value) -> Result<Self> {
        let plan: Self = serde_json::from_value(input).context("invalid execution plan")?;
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == "1",
            "unsupported execution-plan schema version"
        );
        ensure!(
            !self.ordered_steps.is_empty(),
            "execution plan requires at least one step"
        );
        ensure!(
            self.ordered_steps.len() <= MAX_EXECUTION_STEPS,
            "execution plan exceeds {MAX_EXECUTION_STEPS} steps"
        );
        ensure!(
            self.caip2_chain_id == format!("eip155:{}", self.chain_id),
            "CAIP-2 chain does not match chain_id"
        );
        ensure!(
            self.required_capabilities.len() <= MAX_REQUIRED_CAPABILITIES,
            "execution plan lists more than {MAX_REQUIRED_CAPABILITIES} required capabilities"
        );
        for capability in &self.required_capabilities {
            ensure!(
                capability.len() <= 64 && capability.bytes().all(|byte| byte.is_ascii_graphic()),
                "required capability names must be short printable ASCII"
            );
            ensure!(
                SUPPORTED_CAPABILITIES.contains(&capability.as_str()),
                "this wallet does not implement required capability {capability:?}; supported: {SUPPORTED_CAPABILITIES:?}"
            );
        }
        ensure!(
            serde_json::to_vec(&self.extensions)?.len() <= MAX_EXTENSIONS_BYTES,
            "execution plan extensions exceed {MAX_EXTENSIONS_BYTES} bytes"
        );
        if let Some(policy) = &self.simulation_failure_policy {
            ensure_directive(&policy.rpc_error)?;
            ensure_directive(&policy.execution_reverted)?;
            ensure_directive(&policy.simulation_setup_error)?;
            ensure!(
                policy.execution_reverted.action != SimulationFailureAction::RetrySamePlan,
                "execution_reverted cannot recommend retrying identical calldata"
            );
            ensure!(
                policy.simulation_setup_error.action != SimulationFailureAction::RetrySamePlan,
                "simulation_setup_error cannot recommend retrying identical calldata"
            );
        }
        let mut total_calldata = 0_usize;
        for (index, step) in self.ordered_steps.iter().enumerate() {
            total_calldata = total_calldata
                .checked_add(step.transaction.data.len())
                .context("execution plan calldata size overflow")?;
            ensure!(
                total_calldata <= MAX_TOTAL_CALLDATA_BYTES,
                "execution plan calldata exceeds {MAX_TOTAL_CALLDATA_BYTES} bytes"
            );
            ensure!(
                step.step as usize == index + 1,
                "steps must be consecutive and one-indexed"
            );
            ensure!(
                step.transaction.chain_id == self.chain_id,
                "transaction chain does not match plan"
            );
            ensure!(
                step.transaction.from == self.sender,
                "transaction sender does not match plan"
            );
            if let Some(revert_decode) = &step.revert_decode {
                revert_decode.validate()?;
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_SERIALIZED_PLAN_BYTES,
            "execution plan exceeds {MAX_SERIALIZED_PLAN_BYTES} serialized bytes"
        );
        Ok(())
    }

    /// Digest identity = exactly what gets broadcast plus the step labels
    /// shown at approval: `schema_version`, `chain_id`, `sender`, and each
    /// step's number, kind, and transaction (`chain_id`, `from`, `to`,
    /// `data`, `value`). It deliberately excludes `gas`, `revert_decode`,
    /// `simulation_failure_policy`, `required_capabilities`, and
    /// `extensions`: none of those change the bytes the human's approval
    /// binds.
    #[must_use]
    pub fn digest(&self) -> B256 {
        let steps = self
            .ordered_steps
            .iter()
            .map(|step| {
                json!({
                    "step": step.step,
                    "kind": step.kind,
                    "transaction": {
                        "chain_id": step.transaction.chain_id,
                        "from": format!("{:#x}", step.transaction.from),
                        "to": format!("{:#x}", step.transaction.to),
                        "data": format!("0x{}", hex::encode(&step.transaction.data)),
                        "value": step.transaction.value,
                    }
                })
            })
            .collect::<Vec<_>>();
        let canonical = json!({
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "sender": format!("{:#x}", self.sender),
            "ordered_steps": steps,
        });
        keccak256(serde_json::to_vec(&canonical).expect("canonical plan serializes"))
    }
}

fn ensure_directive(directive: &SimulationFailureDirective) -> Result<()> {
    let length = directive.instruction.chars().count();
    if length == 0 || length > 2_000 {
        bail!("simulation failure instruction must contain 1-2000 characters");
    }
    Ok(())
}

#[cfg(test)]
#[path = "execution_plan_test.rs"]
mod tests;
