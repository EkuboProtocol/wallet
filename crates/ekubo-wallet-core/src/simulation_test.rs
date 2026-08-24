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
use uuid::Uuid;

fn context(wallet: &WalletMetadata) -> PolicyContext {
    PolicyContext {
        wallet: wallet.address,
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
        instance_id: Uuid::new_v4(),
        id: "live-test".into(),
        address: Address::repeat_byte(0x11),
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    };
    let policy = StoredPolicy {
        wallet_instance_id: wallet.instance_id,
        wallet_id: wallet.id.clone(),
        wallet_address: wallet.address,
        policy: crate::core::policy::WalletPolicy::allow_anything(),
        revision: 1,
        updated_at: Utc::now(),
    };
    let result = simulate_execution(
        &wallet,
        &default_networks()[0],
        &plan(1),
        &policy,
        &RequestSource::Unknown,
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
        instance_id: Uuid::new_v4(),
        id: "live-batch-test".into(),
        address: Address::repeat_byte(0x11),
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    };
    let policy = StoredPolicy {
        wallet_instance_id: wallet.instance_id,
        wallet_id: wallet.id.clone(),
        wallet_address: wallet.address,
        policy: crate::core::policy::WalletPolicy::allow_anything(),
        revision: 1,
        updated_at: Utc::now(),
    };
    let result = simulate_execution(
        &wallet,
        &default_networks()[0],
        &plan(2),
        &policy,
        &RequestSource::Unknown,
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
        instance_id: Uuid::new_v4(),
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
    let mut wallet_policy = crate::core::policy::WalletPolicy::allow_anything();
    // Naming WETH in a rule's `to` is what puts it in the pre-queried balance
    // set; the allow-all rule beside it is what actually authorizes the call.
    wallet_policy.rules.insert(
        0,
        Rule {
            effect: Effect::Allow,
            label: Some("Wrapped Ether".into()),
            chain_id: None,
            to: Some(Predicate::Eq(format!("{weth:#x}"))),
            native_value: None,
            calldata: None,
            transaction_type: None,
            source: None,
            nonce: None,
            gas_limit: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            delegation: None,
            envelope_to: None,
            envelope_native_value: None,
        },
    );
    let policy = StoredPolicy {
        wallet_instance_id: wallet.instance_id,
        wallet_id: wallet.id.clone(),
        wallet_address: wallet.address,
        policy: wallet_policy,
        revision: 1,
        updated_at: Utc::now(),
    };
    let result = simulate_execution(
        &wallet,
        &default_networks()[0],
        &execution_plan,
        &policy,
        &RequestSource::Unknown,
        &context(&wallet),
        None,
    )
    .await
    .unwrap();
    assert!(result.simulation.success, "{result:#?}");
    assert_eq!(
        result
            .token_spends
            .get(&weth.to_checksum(None))
            .map(String::as_str),
        Some("0")
    );
}

#[test]
fn a_failed_batch_does_not_invent_prepared_delegation_facts() {
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "failed-batch".into(),
        address: Address::repeat_byte(0x11),
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    };
    let policy = StoredPolicy {
        wallet_instance_id: wallet.instance_id,
        wallet_id: wallet.id.clone(),
        wallet_address: wallet.address,
        policy: crate::core::policy::WalletPolicy::allow_anything(),
        revision: 1,
        updated_at: Utc::now(),
    };
    let result = setup_failure_result_at_block(
        &plan(2),
        &policy,
        &RequestSource::Unknown,
        &context(&wallet),
        ExecutionMode::CaliburBatch,
        "the endpoint refused eth_simulateV1",
        100,
    );

    assert!(result.will_authorize_delegation);
    assert!(result.replaces_delegated_implementation.is_none());
    assert!(result.prepared_transaction.is_none());
    assert!(result.prepared_execution.is_none());

    // A direct call signs no authorization, so it must not carry the warning.
    let direct = setup_failure_result_at_block(
        &plan(1),
        &policy,
        &RequestSource::Unknown,
        &context(&wallet),
        ExecutionMode::Direct,
        "the endpoint refused eth_simulateV1",
        100,
    );
    assert!(!direct.will_authorize_delegation);
    assert!(direct.prepared_transaction.is_none());
}

mod bounded_rpc_message_tests {
    //! A revert reason is written by the endpoint and read by a person.

    use super::*;

    /// Nothing bounded it. The string was copied into the failure, into the
    /// stored simulation result, and onto the approval screen at whatever
    /// length arrived -- from the one party in the exchange with an interest
    /// in the person not reading it.
    #[test]
    fn an_oversized_message_is_bounded_and_says_so() {
        let flood = "A".repeat(MAX_RPC_MESSAGE_BYTES * 4);
        let bounded = bounded_rpc_message(&flood);
        assert!(bounded.len() < flood.len());
        assert!(
            bounded.contains("more bytes from the endpoint, not shown"),
            "truncation is disclosed rather than silent: {}",
            &bounded[bounded.len().saturating_sub(80)..]
        );
    }

    /// A real revert reason is a sentence and passes through untouched. The
    /// ceiling exists to have one, not to edit diagnostics.
    #[test]
    fn an_ordinary_message_is_unchanged() {
        for message in [
            "execution reverted: ERC20: transfer amount exceeds balance",
            "",
            "insufficient funds for gas * price + value",
        ] {
            assert_eq!(bounded_rpc_message(message), message);
        }
    }

    /// Truncation lands on a character boundary, so the result is still a
    /// `String` a terminal can render. Cutting by byte through a multi-byte
    /// character would panic on the slice.
    #[test]
    fn truncation_does_not_split_a_character() {
        let multibyte = "é".repeat(MAX_RPC_MESSAGE_BYTES);
        let bounded = bounded_rpc_message(&multibyte);
        assert!(bounded.starts_with('é'));
        assert!(bounded.contains("not shown"));
    }
}

mod bounded_rpc_data_tests {
    //! Endpoint bytes end up in a cache and in an agent's context window.

    use super::*;

    /// `MAX_TOOL_ERROR_CHARS` bounds what an endpoint can write into a
    /// transcript on the path that fails, "because an RPC or a plan producer
    /// chose it". `return_data` is the same text on the path that succeeds,
    /// and nothing bounded it.
    #[test]
    fn oversized_return_data_is_bounded_and_identifiable() {
        let flood = vec![0xab_u8; MAX_RPC_DATA_BYTES * 3];
        let rendered = bounded_hex(&flood);
        assert!(rendered.len() < flood.len() * 2);
        assert!(rendered.contains("not shown"), "the drop is disclosed");
        assert!(
            rendered.contains(&format!("{:#x}", alloy::primitives::keccak256(&flood))),
            "and the complete value stays identifiable"
        );
        // Deliberately no longer parseable as hex: a value that still looks
        // like return data but is not is the worse failure.
        assert!(rendered.contains('…'));
    }

    /// An ordinary return value is untouched and still plain hex.
    #[test]
    fn ordinary_return_data_is_unchanged() {
        let small = [0x01_u8, 0x02, 0x03];
        assert_eq!(bounded_hex(&small), "0x010203");
        assert_eq!(bounded_hex(&[]), "0x");
    }

    /// Revert bytes are read rather than only shown: `inspect_revert` takes
    /// the selector from the first four bytes and decodes a standard payload
    /// at the head. So this one stays parseable and says so in the message.
    #[test]
    fn oversized_revert_data_stays_parseable_at_the_head() {
        let mut flood = vec![0x08, 0xc3, 0x79, 0xa0];
        flood.extend(std::iter::repeat_n(0x00, MAX_RPC_DATA_BYTES * 2));
        let (rendered, truncated) = bounded_revert_hex(&flood);
        assert!(truncated);
        assert!(
            rendered.starts_with("0x08c379a0"),
            "the selector survives, which is what reads it"
        );
        assert!(
            rendered.len() % 2 == 0 && rendered[2..].chars().all(|c| c.is_ascii_hexdigit()),
            "and the value is still hex a decoder can take"
        );
    }

    /// A revert that fits is returned whole and reports no truncation.
    #[test]
    fn ordinary_revert_data_reports_no_truncation() {
        let (rendered, truncated) = bounded_revert_hex(&[0x08, 0xc3, 0x79, 0xa0]);
        assert_eq!(rendered, "0x08c379a0");
        assert!(!truncated);
    }
}
