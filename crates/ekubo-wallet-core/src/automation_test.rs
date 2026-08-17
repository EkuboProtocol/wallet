use super::*;
use alloy::{primitives::address, sol_types::SolValue};
use chrono::TimeZone;

fn wallet() -> Address {
    address!("00000000000000000000000000000000000000a1")
}

fn schedule(expression: &str) -> CronSchedule {
    CronSchedule::parse(expression).expect("valid schedule")
}

fn definition(bytecode: Bytes) -> Result<AutomationDefinition> {
    AutomationDefinition::new(
        "nightly claim",
        bytecode,
        Bytes::new(),
        schedule("0 0 * * * *"),
        1,
    )
}

#[test]
fn six_field_expressions_parse_and_five_field_ones_do_not() {
    assert!(CronSchedule::parse("*/12 * * * * *").is_ok());
    let error = CronSchedule::parse("*/5 * * * *").expect_err("five fields must be refused");
    // The whole reason to refuse it: read as six fields the minute column
    // becomes seconds and the schedule fires sixty times too often.
    assert!(format!("{error:#}").contains("six"), "{error:#}");
}

#[test]
fn a_schedule_keeps_the_exact_text_it_was_given() {
    let parsed = schedule("  */12 * * * * *  ");
    assert_eq!(parsed.expression(), "*/12 * * * * *");
    assert_eq!(parsed.to_string(), "*/12 * * * * *");
}

#[test]
fn next_after_is_strict() {
    let parsed = schedule("0 * * * * *");
    let on_the_minute = Utc.with_ymd_and_hms(2026, 1, 1, 0, 1, 0).unwrap();
    let next = parsed.next_after(on_the_minute).expect("a next fire time");
    assert!(
        next > on_the_minute,
        "a fire time equal to its own trigger would let one tick re-fire itself"
    );
    assert_eq!(next, Utc.with_ymd_and_hms(2026, 1, 1, 0, 2, 0).unwrap());
}

#[test]
fn a_schedule_that_never_fires_is_refused() {
    let error = CronSchedule::parse("0 0 0 31 2 *").expect_err("February 31 never arrives");
    assert!(format!("{error:#}").contains("never fires"), "{error:#}");
}

#[test]
fn preview_lists_the_next_fire_times() {
    let parsed = schedule("0 0 * * * *");
    let from = Utc.with_ymd_and_hms(2026, 1, 1, 0, 30, 0).unwrap();
    let upcoming = parsed.preview(from, 3);
    assert_eq!(
        upcoming,
        vec![
            Utc.with_ymd_and_hms(2026, 1, 1, 1, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 1, 1, 2, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 1, 1, 3, 0, 0).unwrap(),
        ]
    );
}

#[test]
fn empty_bytecode_is_refused() {
    let error = definition(Bytes::new()).expect_err("empty bytecode is not a program");
    assert!(format!("{error:#}").contains("empty"), "{error:#}");
}

#[test]
fn oversized_bytecode_is_refused() {
    let error = definition(Bytes::from(vec![0x60; MAX_BYTECODE_BYTES + 1]))
        .expect_err("oversized bytecode is refused");
    assert!(format!("{error:#}").contains("over the"), "{error:#}");
}

#[test]
fn a_delegation_designator_is_not_runtime_code() {
    // 0xef0100 || address is exactly what `eth_getCode` returns for a
    // 7702-delegated account, which is the thing someone pastes by mistake.
    let mut designator = vec![0xEF, 0x01, 0x00];
    designator.extend_from_slice(wallet().as_slice());
    let error =
        definition(Bytes::from(designator)).expect_err("a delegation designator is not code");
    assert!(format!("{error:#}").contains("0xEF"), "{error:#}");
}

#[test]
fn a_name_with_a_bidirectional_control_is_refused() {
    let error = AutomationDefinition::new(
        "claim\u{202E}rewards",
        Bytes::from_static(&[0x60, 0x00]),
        Bytes::new(),
        schedule("0 0 * * * *"),
        1,
    )
    .expect_err("a bidi override in a label is refused");
    assert!(format!("{error:#}").contains("bidirectional"), "{error:#}");
}

#[test]
fn the_poll_installs_the_blob_at_the_wallets_own_address() {
    let bytecode = Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xF3]);
    let payload = poll_payload(wallet(), &bytecode, &Bytes::new(), 30_000_000);
    let block = payload
        .block_state_calls
        .first()
        .expect("one simulated block");
    let overrides = block
        .state_overrides
        .as_ref()
        .expect("the poll overrides state");
    let account = overrides.get(&wallet()).expect("override on the wallet");
    assert_eq!(account.code.as_ref(), Some(&bytecode));
    assert_eq!(
        overrides.len(),
        1,
        "the poll overrides exactly one account, and it is the wallet's"
    );

    let call = block.calls.first().expect("one call");
    assert_eq!(call.from, Some(wallet()));
    assert_eq!(call.to, Some(wallet().into()));
    // `msg.sender == address(this) == the wallet`, which is what a Calibur
    // self-batch looks like and what makes a probe agree with execution.
    assert_eq!(call.from, Some(wallet()));
}

#[test]
fn the_poll_calls_automate_with_the_stored_config() {
    let config = Bytes::from_static(&[0xAA, 0xBB]);
    let payload = poll_payload(wallet(), &Bytes::from_static(&[0x00]), &config, 1_000_000);
    let call = payload.block_state_calls[0].calls[0].clone();
    let input = call.input.input().expect("calldata").clone();
    assert_eq!(&input[..4], &automateCall::SELECTOR);
    let decoded = automateCall::abi_decode(&input).expect("the poll's own calldata decodes");
    assert_eq!(decoded.config, config);
}

#[test]
fn an_empty_call_list_is_not_a_plan() {
    let error = synthesize_plan(wallet(), 1, &[]).expect_err("no calls is not a plan");
    assert!(format!("{error:#}").contains("no calls"), "{error:#}");
}

#[test]
fn calls_become_consecutive_one_indexed_steps() {
    let calls = vec![
        PolledCall {
            to: address!("00000000000000000000000000000000000000b1"),
            value: U256::ZERO,
            data: Bytes::from_static(&[0x11, 0x22]),
        },
        PolledCall {
            to: address!("00000000000000000000000000000000000000b2"),
            value: U256::from(7_u64),
            data: Bytes::new(),
        },
    ];
    let plan = synthesize_plan(wallet(), 8453, &calls).expect("a valid plan");
    assert_eq!(plan.chain_id.as_str(), "8453");
    assert_eq!(plan.caip2_chain_id, "eip155:8453");
    assert_eq!(plan.sender, wallet());
    assert_eq!(plan.ordered_steps.len(), 2);
    assert_eq!(plan.ordered_steps[0].step, 1);
    assert_eq!(plan.ordered_steps[1].step, 2);
    assert_eq!(plan.ordered_steps[1].transaction.value.as_str(), "7");
    assert_eq!(plan.ordered_steps[0].transaction.from, wallet());
    // The wallet's own preparation supplies gas for anything nobody reviews.
    assert!(plan.ordered_steps[0].transaction.gas.is_none());
    // And it is an ordinary plan, so the ordinary validator accepts it.
    plan.validate().expect("synthesized plans validate");
}

#[test]
fn a_returned_list_decodes_to_calls() {
    let encoded = vec![
        AutomationCall {
            to: address!("00000000000000000000000000000000000000b1"),
            value: U256::from(1_u64),
            data: vec![0xDE, 0xAD].into(),
        },
        AutomationCall {
            to: address!("00000000000000000000000000000000000000b2"),
            value: U256::ZERO,
            data: Vec::new().into(),
        },
    ];
    let bytes = encoded.abi_encode();
    let decoded = automateCall::abi_decode_returns(&bytes).expect("the return type round-trips");
    let calls = bound_calls(&decoded).expect("within bounds");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].value, U256::from(1_u64));
    assert_eq!(calls[0].data, Bytes::from_static(&[0xDE, 0xAD]));
    assert!(calls[1].data.is_empty());
}

#[test]
fn more_calls_than_a_plan_can_hold_are_refused_as_a_return_value() {
    let calls: Vec<AutomationCall> = (0..=MAX_EXECUTION_STEPS)
        .map(|_| AutomationCall {
            to: wallet(),
            value: U256::ZERO,
            data: Vec::new().into(),
        })
        .collect();
    let error = bound_calls(&calls).expect_err("over the plan's own step limit");
    assert!(format!("{error:#}").contains("call limit"), "{error:#}");
}

#[test]
fn standard_reverts_decode_and_others_stay_hex() {
    let mut error_string = vec![0x08, 0xc3, 0x79, 0xa0];
    error_string.extend_from_slice(&"nothing to do".to_owned().abi_encode());
    assert_eq!(
        decode_standard_revert(&Bytes::from(error_string)),
        Some(r#"Error("nothing to do")"#.to_owned())
    );

    let mut panic = vec![0x4e, 0x48, 0x7b, 0x71];
    panic.extend_from_slice(&U256::from(0x11_u64).abi_encode());
    assert_eq!(
        decode_standard_revert(&Bytes::from(panic)),
        Some("Panic(0x11)".to_owned())
    );

    // A custom error the wallet has no ABI for stays bytes rather than
    // becoming an invented decoding.
    assert_eq!(
        decode_standard_revert(&Bytes::from_static(&[0x01, 0x02, 0x03, 0x04, 0x05])),
        None
    );
    assert_eq!(decode_standard_revert(&Bytes::from_static(&[0x01])), None);
}

#[test]
fn every_state_survives_a_round_trip_through_its_stored_name() {
    for state in [
        AutomationState::Enabled,
        AutomationState::Disabled,
        AutomationState::AwaitingRelink,
    ] {
        assert_eq!(AutomationState::parse(state.as_str()).unwrap(), state);
    }
    assert!(AutomationState::parse("running").is_err());
}

/// A `ChainClient` that answers only the two calls a poll makes.
///
/// Every other method is unreachable by construction rather than stubbed with
/// a plausible value: a poll that started making other RPC calls should fail
/// this test loudly instead of quietly passing against invented state.
struct PollClient {
    block: u64,
    result: Option<alloy::rpc::types::simulate::SimCallResult>,
}

#[async_trait::async_trait]
impl crate::chain_client::ChainClient for PollClient {
    async fn chain_id(&self) -> Result<u64> {
        Ok(1)
    }

    async fn block_number(&self) -> Result<u64> {
        Ok(self.block)
    }

    async fn block_by_number(
        &self,
        _block: alloy::eips::BlockNumberOrTag,
    ) -> Result<Option<alloy::rpc::types::Block>> {
        let mut block: alloy::rpc::types::Block = alloy::rpc::types::Block::default();
        block.header.inner.number = self.block;
        block.header.inner.gas_limit = 30_000_000;
        Ok(Some(block))
    }

    async fn simulate_v1(
        &self,
        _payload: SimulatePayload,
        _block_number: Option<u64>,
    ) -> Result<Vec<alloy::rpc::types::simulate::SimulatedBlock>> {
        let Some(result) = self.result.clone() else {
            anyhow::bail!("endpoint refused eth_simulateV1");
        };
        Ok(vec![alloy::rpc::types::simulate::SimulatedBlock {
            inner: alloy::rpc::types::Block::default(),
            calls: vec![result],
        }])
    }

    async fn balance(&self, _address: Address, _block: alloy::eips::BlockId) -> Result<U256> {
        unimplemented!("a poll reads no balances")
    }

    async fn transaction_count(
        &self,
        _address: Address,
        _block: alloy::eips::BlockId,
    ) -> Result<u64> {
        unimplemented!("a poll reads no nonces")
    }

    async fn code(&self, _address: Address, _block: alloy::eips::BlockId) -> Result<Bytes> {
        unimplemented!("a poll installs code rather than reading it")
    }

    async fn call(
        &self,
        _request: alloy::rpc::types::TransactionRequest,
        _block: alloy::eips::BlockId,
    ) -> Result<Bytes> {
        unimplemented!("a poll goes through eth_simulateV1")
    }

    async fn estimate_eip1559_fees(&self) -> Result<alloy::providers::utils::Eip1559Estimation> {
        unimplemented!("a poll prepares no transaction")
    }

    async fn estimate_gas(&self, _request: alloy::rpc::types::TransactionRequest) -> Result<u64> {
        unimplemented!("a poll prepares no transaction")
    }

    async fn transaction_receipt(
        &self,
        _hash: B256,
    ) -> Result<Option<alloy::rpc::types::TransactionReceipt>> {
        unimplemented!("a poll sends nothing")
    }

    async fn transaction_by_hash(
        &self,
        _hash: B256,
    ) -> Result<Option<alloy::rpc::types::Transaction>> {
        unimplemented!("a poll sends nothing")
    }

    async fn send_transaction(&self, _bytes: Bytes) -> Result<B256> {
        unimplemented!("a poll never signs or sends")
    }
}

fn succeeded(return_data: Vec<u8>) -> alloy::rpc::types::simulate::SimCallResult {
    alloy::rpc::types::simulate::SimCallResult {
        return_data: return_data.into(),
        gas_used: 21_000,
        status: true,
        ..Default::default()
    }
}

fn reverted(return_data: Vec<u8>) -> alloy::rpc::types::simulate::SimCallResult {
    alloy::rpc::types::simulate::SimCallResult {
        return_data: return_data.into(),
        gas_used: 21_000,
        status: false,
        error: Some(alloy::rpc::types::simulate::SimulateError {
            code: -32000,
            message: "execution reverted".into(),
            data: None,
        }),
        ..Default::default()
    }
}

async fn poll_with(
    result: Option<alloy::rpc::types::simulate::SimCallResult>,
) -> Result<PollOutcome, PollFailure> {
    let client = PollClient { block: 100, result };
    poll(
        &client,
        wallet(),
        &Bytes::from_static(&[0x60, 0x00]),
        &Bytes::new(),
    )
    .await
    .expect("polling itself does not error; it reports")
}

#[tokio::test]
async fn a_poll_returning_calls_reports_them() {
    let calls = vec![AutomationCall {
        to: address!("00000000000000000000000000000000000000b1"),
        value: U256::from(3_u64),
        data: vec![0x01].into(),
    }];
    let outcome = poll_with(Some(succeeded(calls.abi_encode())))
        .await
        .expect("a well-formed return value");
    assert_eq!(outcome.calls.len(), 1);
    assert_eq!(outcome.calls[0].value, U256::from(3_u64));
    assert_eq!(outcome.block_number, 100);
    assert_eq!(outcome.gas_used, 21_000);
}

#[tokio::test]
async fn an_empty_return_is_an_idle_tick_rather_than_a_failure() {
    let empty: Vec<AutomationCall> = Vec::new();
    let outcome = poll_with(Some(succeeded(empty.abi_encode())))
        .await
        .expect("an empty list decodes");
    assert!(outcome.calls.is_empty());
}

#[tokio::test]
async fn a_revert_carries_the_bytes_an_author_needs() {
    let mut data = vec![0x08, 0xc3, 0x79, 0xa0];
    data.extend_from_slice(&"not yet".to_owned().abi_encode());
    let failure = poll_with(Some(reverted(data.clone())))
        .await
        .expect_err("a revert");
    let PollFailure::Reverted {
        revert_data,
        revert_selector,
        decoded,
        ..
    } = failure
    else {
        panic!("a reverting blob must report as reverted: {failure:?}");
    };
    assert_eq!(revert_data, format!("0x{}", hex::encode(&data)));
    assert_eq!(revert_selector.as_deref(), Some("0x08c379a0"));
    assert_eq!(decoded.as_deref(), Some(r#"Error("not yet")"#));
}

#[tokio::test]
async fn a_return_value_of_the_wrong_type_reports_the_bytes_it_got() {
    let failure = poll_with(Some(succeeded(vec![0xAA; 7])))
        .await
        .expect_err("seven bytes are not a call list");
    let PollFailure::Undecodable { return_data, .. } = failure else {
        panic!("a wrong return type must report as undecodable: {failure:?}");
    };
    assert_eq!(return_data, "0xaaaaaaaaaaaaaa");
}

#[tokio::test]
async fn an_endpoint_that_refuses_the_method_is_an_rpc_failure() {
    let failure = poll_with(None).await.expect_err("the endpoint refused");
    assert!(
        matches!(failure, PollFailure::Rpc(ref message) if message.contains("refused")),
        "{failure:?}"
    );
}
