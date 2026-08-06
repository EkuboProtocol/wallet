//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::{config::WalletSource, core::execution_plan::ExecutionPlan};
use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use chrono::Utc;
use serde_json::json;

/// The "already known" family a node answers with when the transaction it
/// is being asked to accept is already in its mempool or a block.
const ALREADY_KNOWN: &[&str] = &[
    "nonce too low: address 0x0000, tx: 610 state: 611",
    "already known",
    "replacement transaction underpriced",
];

#[test]
fn cancellation_outbids_every_incumbent_at_the_replacement_floor() {
    // A quiet market: the incumbent's bumped fees decide both fields.
    let (max_fee, priority) = cancellation_fees(&[(800, 80)], 100, 10).unwrap();
    assert_eq!(max_fee, 900);
    assert_eq!(priority, 90);

    // A hot market: current estimates already clear the floor.
    let (max_fee, priority) = cancellation_fees(&[(800, 80)], 2_000, 200).unwrap();
    assert_eq!(max_fee, 2_000);
    assert_eq!(priority, 200);

    // Repricing outbids the highest incumbent, not the first.
    let (max_fee, priority) = cancellation_fees(&[(800, 80), (1_600, 160)], 100, 10).unwrap();
    assert_eq!(max_fee, 1_800);
    assert_eq!(priority, 180);

    // The bump rounds up so a tiny fee still strictly increases.
    assert_eq!(bumped_fee(1), 2);
    assert_eq!(bumped_fee(0), 0);

    // The pair stays EIP-1559-consistent when the priority floor passes
    // the market maximum fee.
    let (max_fee, priority) = cancellation_fees(&[(100, 100)], 50, 5).unwrap();
    assert_eq!(priority, 113);
    assert!(max_fee >= priority);

    // No incumbent means nothing to cancel.
    assert!(cancellation_fees(&[], 100, 10).is_err());
}

#[test]
fn a_rejected_send_whose_transaction_landed_is_reported_as_mined() {
    for rejection in ALREADY_KNOWN {
        let result = send_failure_outcome(
            "0xabc",
            Some(crate::rpc::ReceiptStatus {
                succeeded: true,
                block_number: 27_923_617,
                gas_used: 21_000,
                effective_gas_price: 1_000_000_000,
            }),
            false,
            (*rejection).to_owned(),
        );
        assert_eq!(result.receipt_status, ReceiptStatus::Success);
        assert_eq!(result.block_number.as_deref(), Some("27923617"));
        assert!(
            result.broadcast_error.is_none(),
            "a mined transaction must never carry a broadcast error: {rejection}"
        );
    }
}

#[test]
fn a_rejected_send_whose_transaction_reverted_reports_the_revert_not_the_rejection() {
    let result = send_failure_outcome(
        "0xabc",
        Some(crate::rpc::ReceiptStatus {
            succeeded: false,
            block_number: 42,
            gas_used: 21_000,
            effective_gas_price: 1_000_000_000,
        }),
        false,
        "nonce too low".to_owned(),
    );
    assert_eq!(result.receipt_status, ReceiptStatus::Reverted);
    assert_eq!(result.block_number.as_deref(), Some("42"));
    assert!(result.broadcast_error.is_none());
}

#[test]
fn a_rejected_send_whose_transaction_is_in_the_mempool_is_an_ordinary_pending_send() {
    // Submission succeeded; the rejection described an earlier attempt.
    // An agent must not be able to tell this from a clean send, because
    // there is nothing different for it to do.
    let result = send_failure_outcome("0xabc", None, true, "already known".to_owned());
    assert_eq!(result.receipt_status, ReceiptStatus::Pending);
    assert_eq!(result.block_number, None);
    assert!(result.broadcast_error.is_none());
}

#[test]
fn a_send_the_chain_never_heard_of_keeps_its_error() {
    let result = send_failure_outcome(
        "0xabc",
        None,
        false,
        "insufficient funds for gas * price + value".to_owned(),
    );
    assert_eq!(result.receipt_status, ReceiptStatus::Pending);
    assert_eq!(
        result.broadcast_error.as_deref(),
        Some("insufficient funds for gas * price + value")
    );
}

fn wallet(signer: &PrivateKeySigner) -> WalletMetadata {
    WalletMetadata {
        id: "primary".into(),
        address: signer.address(),
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    }
}

fn network() -> NetworkConfig {
    let mut network = crate::config::default_networks().remove(0);
    network.max_gas_limit = Some("1000000".into());
    network
}

fn plan(sender: Address, steps: usize) -> ExecutionPlan {
    let ordered_steps = (0..steps)
        .map(|index| {
            json!({
                "step": index + 1,
                "kind": "execution",
                "transaction": {
                    "chain_id": "1",
                    "from": sender,
                    "to": Address::repeat_byte(u8::try_from(index + 1).unwrap()),
                    "data": "0x1234",
                    "value": index.to_string(),
                }
            })
        })
        .collect::<Vec<_>>();
    ExecutionPlan::parse(json!({
        "schema_version": "1",
        "chain_id": "1",
        "caip2_chain_id": "eip155:1",
        "sender": sender,
        "ordered_steps": ordered_steps,
    }))
    .unwrap()
}

fn finalize_digest(mut signed: SignedExecution, plan: &ExecutionPlan) -> SignedExecution {
    signed.digest = format!("{:#x}", plan.digest());
    signed
}

#[test]
fn signs_and_validates_exact_direct_transaction() {
    let local_signer = PrivateKeySigner::from_slice(&[7; 32]).unwrap();
    let wallet = wallet(&local_signer);
    let network = network();
    let plan = plan(wallet.address, 1);
    let signed_execution = finalize_digest(
        sign_prepared(
            &local_signer,
            1,
            3,
            100_000,
            20,
            2,
            &planned_call(&plan, wallet.address),
            false,
        )
        .unwrap(),
        &plan,
    );
    validate_signed_execution(&signed_execution, &wallet, &network, &plan).unwrap();
    assert!(signed_execution.serialized_transaction.starts_with("0x02"));
}

#[test]
fn signs_and_validates_canonical_calibur_authorization() {
    let local_signer = PrivateKeySigner::from_slice(&[8; 32]).unwrap();
    let wallet = wallet(&local_signer);
    let network = network();
    let plan = plan(wallet.address, 2);
    let signed_execution = finalize_digest(
        sign_prepared(
            &local_signer,
            1,
            4,
            200_000,
            30,
            3,
            &planned_call(&plan, wallet.address),
            true,
        )
        .unwrap(),
        &plan,
    );
    validate_signed_execution(&signed_execution, &wallet, &network, &plan).unwrap();
    assert!(signed_execution.serialized_transaction.starts_with("0x04"));
}

#[test]
fn rejects_tampered_plan_or_signed_bytes() {
    let local_signer = PrivateKeySigner::from_slice(&[9; 32]).unwrap();
    let wallet = wallet(&local_signer);
    let network = network();
    let plan = plan(wallet.address, 1);
    let mut signed_execution = finalize_digest(
        sign_prepared(
            &local_signer,
            1,
            0,
            100_000,
            20,
            2,
            &planned_call(&plan, wallet.address),
            false,
        )
        .unwrap(),
        &plan,
    );
    signed_execution.serialized_transaction.push_str("00");
    assert!(validate_signed_execution(&signed_execution, &wallet, &network, &plan).is_err());
}

#[test]
fn review_digest_binds_every_prepared_transaction_field() {
    let local_signer = PrivateKeySigner::from_slice(&[10; 32]).unwrap();
    let wallet = wallet(&local_signer);
    let plan = plan(wallet.address, 1);
    let prepared = PreparedExecution {
        chain_id: 1,
        nonce: 7,
        gas_limit: 100_000,
        max_fee_per_gas: 30,
        max_priority_fee_per_gas: 3,
        planned: planned_call(&plan, wallet.address),
        authorize_delegation: false,
        plan_digest: format!("{:#x}", plan.digest()),
    };
    let expected = prepared.review_digest();
    let mut mutations = Vec::new();

    let mut changed = prepared.clone();
    changed.chain_id += 1;
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.nonce += 1;
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.gas_limit += 1;
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.max_fee_per_gas += 1;
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.max_priority_fee_per_gas += 1;
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.planned.to = Address::repeat_byte(0xaa);
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.planned.value += U256::from(1);
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.planned.data = vec![0xff].into();
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.authorize_delegation = true;
    mutations.push(changed);
    let mut changed = prepared.clone();
    changed.plan_digest = format!("{:#x}", B256::repeat_byte(0xbb));
    mutations.push(changed);

    assert!(
        mutations
            .iter()
            .all(|changed| changed.review_digest() != expected)
    );
}

#[test]
fn signed_envelope_must_match_reviewed_preparation() {
    let local_signer = PrivateKeySigner::from_slice(&[11; 32]).unwrap();
    let wallet = wallet(&local_signer);
    let plan = plan(wallet.address, 1);
    let prepared = PreparedExecution {
        chain_id: 1,
        nonce: 8,
        gas_limit: 100_000,
        max_fee_per_gas: 30,
        max_priority_fee_per_gas: 3,
        planned: planned_call(&plan, wallet.address),
        authorize_delegation: false,
        plan_digest: format!("{:#x}", plan.digest()),
    };
    let signed = finalize_digest(
        sign_prepared(
            &local_signer,
            prepared.chain_id,
            prepared.nonce,
            prepared.gas_limit,
            prepared.max_fee_per_gas,
            prepared.max_priority_fee_per_gas,
            &prepared.planned,
            prepared.authorize_delegation,
        )
        .unwrap(),
        &plan,
    );
    validate_signed_preparation(&signed, &prepared).unwrap();

    let mut changed = prepared;
    changed.nonce += 1;
    assert!(validate_signed_preparation(&signed, &changed).is_err());
}
