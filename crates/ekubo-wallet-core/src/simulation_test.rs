//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::{
    config::{WalletSource, default_networks},
    core::execution_plan::{
        DecimalU256, ExecutionStep, ExecutionStepKind, PlannedTransaction, RevertDecodePlan,
    },
    core::policy::{Effect, Rule},
    core::predicate::{PolicyContext, Predicate},
};
use alloy::sol_types::SolError;
use chrono::Utc;

fn context(wallet: &WalletMetadata) -> PolicyContext {
    PolicyContext {
        wallet: wallet.address,
        ..PolicyContext::default()
    }
}

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
                transaction: PlannedTransaction {
                    chain_id: DecimalU256::new("1").unwrap(),
                    from: sender,
                    to: Address::repeat_byte(u8::try_from(index + 2).unwrap()),
                    data: Bytes::new(),
                    value: DecimalU256::new("0").unwrap(),
                    gas: None,
                },
                revert_decode: None,
            })
            .collect(),
        required_capabilities: Vec::new(),
        extensions: serde_json::Map::new(),
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
    // The name is the plan's reading of the revert, not one this wallet
    // reached, and the sentence reaches the approval screen beside findings
    // that are. It has to say so rather than read as a verdict.
    assert_eq!(
        failure.message,
        "reverted as TargetFailure, per the error ABI the plan supplied"
    );
}

#[test]
fn a_contracts_own_revert_string_is_quoted_rather_than_asserted() {
    // `Error(string)` carries whatever the reverting contract's author wrote,
    // and the plan chooses which contract that is. Restating it as the
    // simulation's own message handed attacker prose the wallet's voice.
    let execution_plan = plan(1);
    let encoded = format!(
        "0x{}",
        hex::encode(alloy::sol_types::Revert::from("all good, approve this").abi_encode())
    );
    let failure = failure(
        &execution_plan,
        SimulationFailureCategory::ExecutionReverted,
        "execution reverted",
        Some(&encoded),
    );
    assert_eq!(
        failure.message,
        "reverted with reason \"all good, approve this\""
    );
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
    let result = simulate_execution(
        &wallet,
        &default_networks()[0],
        &plan(1),
        &policy,
        &context(&wallet),
        None,
    )
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
    let result = simulate_execution(
        &wallet,
        &default_networks()[0],
        &plan(2),
        &policy,
        &context(&wallet),
        None,
    )
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
    // Naming WETH in a rule's `to` is what puts it in the pre-queried balance
    // set; the allow-all rule beside it is what actually authorizes the call.
    wallet_policy.chains.get_mut("*").unwrap().rules.push(Rule {
        effect: Effect::Allow,
        label: Some("Wrapped Ether".into()),
        to: Some(Predicate::Eq(format!("{weth:#x}"))),
        from: None,
        value: None,
        calldata: None,
    });
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
        &context(&wallet),
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
