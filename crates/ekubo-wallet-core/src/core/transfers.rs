use crate::core::execution_plan::{
    DecimalU256, ExecutionPlan, ExecutionStep, ExecutionStepKind, PlannedTransaction,
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
pub struct Transfer {
    /// Token contract to transfer. Address
    /// 0x0000000000000000000000000000000000000000 transfers the native token.
    #[schemars(with = "String")]
    pub token: Address,
    /// Recipient of the transfer.
    #[schemars(with = "String")]
    pub to: Address,
    /// Raw smallest-unit quantity: wei for the native token, the token's own
    /// smallest unit otherwise.
    pub amount: DecimalU256,
}

pub fn transfer_plan(
    chain_id: &DecimalU256,
    sender: Address,
    transfers: Vec<Transfer>,
) -> Result<ExecutionPlan> {
    ensure!(!transfers.is_empty(), "at least one transfer is required");
    // The zero address is not a recipient. For the native token this builds a
    // value-bearing transaction to `0x0`, which nothing can undo; for an
    // ERC-20 it encodes a `transfer` whose effect depends entirely on whether
    // that particular contract happens to refuse it, and a great many burn the
    // amount instead.
    //
    // Refused here rather than left to the policy, because no policy rule
    // speaks about it: a plan whose recipient is zero can be authorized by an
    // ordinary allowlist for the token, and `ExecutionPlan::validate` checks
    // calldata bounds, step ordering, chain, and sender -- everything about
    // the shape of the request except where the value is going.
    for transfer in &transfers {
        ensure!(
            !transfer.to.is_zero(),
            "a transfer to the zero address cannot be undone: the native token is destroyed and \
             many ERC-20s burn the amount, so it is refused rather than signed"
        );
    }
    make_plan(
        chain_id,
        sender,
        transfers
            .into_iter()
            .map(|transfer| {
                if transfer.token.is_zero() {
                    return (transfer.to, Bytes::new(), transfer.amount);
                }
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
                transaction: PlannedTransaction {
                    chain_id: chain_id.clone(),
                    from: sender,
                    to,
                    data,
                    value,
                    gas: None,
                },
                revert_decode: None,
            })
            .collect(),
        required_capabilities: Vec::new(),
        extensions: serde_json::Map::new(),
        simulation_failure_policy: None,
    };
    plan.validate()?;
    Ok(plan)
}

#[cfg(test)]
#[path = "transfers_test.rs"]
mod tests;
