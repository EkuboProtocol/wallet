use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use anyhow::{Context, Result, bail, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{fmt, str::FromStr};

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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubmitCondition {
    Always,
    IfRequiredByCurrentAllowance,
    AfterPriorRequiredStepsHaveSuccessfulReceipts,
    AfterExecutionHasSuccessfulReceiptIfAllowanceRemains,
    AfterRequiredSignatureIsSupplied,
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
    pub submit_condition: SubmitCondition,
    pub transaction: PlannedTransaction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eip1193: Option<Map<String, Value>>,
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

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    pub schema_version: String,
    pub chain_id: DecimalU256,
    pub caip2_chain_id: String,
    #[schemars(with = "String")]
    pub sender: Address,
    pub ordered_steps: Vec<ExecutionStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_policy: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapters: Option<Map<String, Value>>,
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
            self.caip2_chain_id == format!("eip155:{}", self.chain_id),
            "CAIP-2 chain does not match chain_id"
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
        for (index, step) in self.ordered_steps.iter().enumerate() {
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
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> B256 {
        let steps = self
            .ordered_steps
            .iter()
            .map(|step| {
                json!({
                    "step": step.step,
                    "kind": step.kind,
                    "submit_condition": step.submit_condition,
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
mod tests {
    use super::*;

    fn plan() -> Value {
        json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "submit_condition": "always",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0x",
                    "value": "0"
                }
            }]
        })
    }

    #[test]
    fn parses_and_hashes_canonical_plan() {
        let parsed = ExecutionPlan::parse(plan()).unwrap();
        assert_eq!(
            format!("{:#x}", parsed.digest()),
            "0x42716b445f3fba53b743e84bac446db55e3e1bda6fa71130dd9c16bbbc395b0b"
        );
    }

    #[test]
    fn rejects_mismatched_chain_and_unknown_fields() {
        let mut input = plan();
        input["caip2_chain_id"] = json!("eip155:2");
        assert!(ExecutionPlan::parse(input).is_err());
        let mut input = plan();
        input["surprise"] = json!(true);
        assert!(ExecutionPlan::parse(input).is_err());
    }
}
