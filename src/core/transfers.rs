use crate::core::execution_plan::{
    DecimalU256, ExecutionPlan, ExecutionStep, ExecutionStepKind, PlannedTransaction,
    SubmitCondition,
};
use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};
use anyhow::{Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

sol! {
    function transfer(address to, uint256 amount) external returns (bool);
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeTransfer {
    #[schemars(with = "String")]
    pub to: Address,
    pub amount_wei: DecimalU256,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Erc20Transfer {
    #[schemars(with = "String")]
    pub token: Address,
    #[schemars(with = "String")]
    pub to: Address,
    pub amount: DecimalU256,
}

pub fn native_transfer_plan(
    chain_id: &DecimalU256,
    sender: Address,
    transfers: Vec<NativeTransfer>,
) -> Result<ExecutionPlan> {
    ensure!(!transfers.is_empty(), "at least one transfer is required");
    make_plan(
        chain_id,
        sender,
        transfers
            .into_iter()
            .map(|transfer| (transfer.to, Bytes::new(), transfer.amount_wei))
            .collect(),
    )
}

pub fn erc20_transfer_plan(
    chain_id: &DecimalU256,
    sender: Address,
    transfers: Vec<Erc20Transfer>,
) -> Result<ExecutionPlan> {
    ensure!(!transfers.is_empty(), "at least one transfer is required");
    make_plan(
        chain_id,
        sender,
        transfers
            .into_iter()
            .map(|transfer| {
                let call = transferCall {
                    to: transfer.to,
                    amount: U256::from_str_radix(transfer.amount.as_str(), 10)
                        .expect("validated token amount"),
                };
                (
                    transfer.token,
                    call.abi_encode().into(),
                    DecimalU256::new("0").unwrap(),
                )
            })
            .collect(),
    )
}

fn make_plan(
    chain_id: &DecimalU256,
    sender: Address,
    calls: Vec<(Address, Bytes, DecimalU256)>,
) -> Result<ExecutionPlan> {
    let plan = ExecutionPlan {
        schema_version: "1".into(),
        caip2_chain_id: format!("eip155:{chain_id}"),
        chain_id: chain_id.clone(),
        sender,
        ordered_steps: calls
            .into_iter()
            .enumerate()
            .map(|(index, (to, data, value))| ExecutionStep {
                step: u32::try_from(index + 1).expect("number of calls fits u32"),
                kind: ExecutionStepKind::Execution,
                submit_condition: SubmitCondition::Always,
                transaction: PlannedTransaction {
                    chain_id: chain_id.clone(),
                    from: sender,
                    to,
                    data,
                    value,
                    gas: None,
                },
                eip1193: None,
                revert_decode: None,
            })
            .collect(),
        execution_policy: None,
        adapters: None,
        simulation_failure_policy: None,
    };
    plan.validate()?;
    Ok(plan)
}
