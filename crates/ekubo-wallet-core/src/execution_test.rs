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

    // An endpoint naming an enormous market fee no longer names the ceiling
    // as well. The cap used to include `market_max_fee` in the maximum it was
    // capping, so a reported fee of M was checked against at least 2M and
    // every M it could name passed -- the one signing path with no policy and
    // no approval screen behind it, taking a builder tip from a stranger.
    let (max_fee, priority) = cancellation_fees(&[(800, 80)], 10_000_000, 9_000_000).unwrap();
    assert_eq!(max_fee, 3_200, "four times the fee the owner committed to");
    assert_eq!(priority, 3_200);

    // Clamped rather than refused, so the envelope still replaces the one it
    // is cancelling. Refusing would let the same endpoint deny cancellation
    // by reporting a large enough number.
    assert!(max_fee >= 900 && priority >= 90);
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
            Presence::Absent,
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
        Presence::Absent,
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
    let result = send_failure_outcome("0xabc", None, Presence::Held, "already known".to_owned());
    assert_eq!(result.receipt_status, ReceiptStatus::Pending);
    assert_eq!(result.block_number, None);
    assert!(result.broadcast_error.is_none());
}

#[test]
fn a_send_the_chain_never_heard_of_keeps_its_error() {
    let result = send_failure_outcome(
        "0xabc",
        None,
        Presence::Absent,
        "insufficient funds for gas * price + value".to_owned(),
    );
    assert_eq!(result.receipt_status, ReceiptStatus::Pending);
    assert_eq!(
        result.broadcast_error.as_deref(),
        Some("insufficient funds for gas * price + value")
    );
    assert!(
        result.absence_established,
        "the node answered, so the lifecycle may act on this"
    );
}

/// The third answer, which used to arrive as the second. A raw-send timeout
/// can happen *after* the node accepted the transaction, so an observation
/// that timed out or errored establishes nothing -- and `submit_claimed` used
/// to spend it on releasing the submission lease, putting a possibly-live
/// transaction back to `signed` where it is retryable and discardable.
#[test]
fn a_send_whose_absence_could_not_be_observed_says_so() {
    let result = send_failure_outcome(
        "0xabc",
        None,
        Presence::Unobserved,
        "transaction submission RPC timed out".to_owned(),
    );
    assert_eq!(result.receipt_status, ReceiptStatus::Pending);
    assert_eq!(
        result.broadcast_error.as_deref(),
        Some("transaction submission RPC timed out"),
        "the caller asked for a send and did not get one, so the failure is still reported"
    );
    assert!(
        !result.absence_established,
        "but nothing observed the transaction to be absent, so the lifecycle must not act on it"
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

#[test]
fn the_gas_ceiling_falls_back_to_the_block_when_nothing_is_configured() {
    // Run 6251, finding 186999. Signing after a simulation always had this
    // fallback; cancellation bounded nothing at all unless the network carried
    // a configured maximum — which most shipped profiles do not, so on an
    // ordinary network one endpoint's `estimate_gas` decided the signed gas
    // limit by itself. A cancellation cannot be simulated and is asked for
    // exactly when something is already stuck, so an absurd estimate produced
    // an envelope every honest peer rejects while spending one of the eight
    // attempts this wallet will ever make.
    let mut network = network();

    network.max_gas_limit = None;
    assert_eq!(
        usable_gas_ceiling(&network, 30_000_000).unwrap(),
        30_000_000,
        "with nothing configured the block's own limit is the ceiling"
    );

    // A configured maximum narrows it.
    network.max_gas_limit = Some("1000000".into());
    assert_eq!(usable_gas_ceiling(&network, 30_000_000).unwrap(), 1_000_000);

    // And never widens it past what the block will accept, however the owner
    // wrote it.
    assert_eq!(usable_gas_ceiling(&network, 500_000).unwrap(), 500_000);

    network.max_gas_limit = Some("not a number".into());
    assert!(usable_gas_ceiling(&network, 30_000_000).is_err());

    // A ceiling below what every transaction costs before it does anything is
    // not a bound, it is a refusal to sign at all -- and `block_maximum` comes
    // from whichever endpoint answered, so a small enough answer would
    // otherwise disqualify the plain self-send a cancellation is while looking
    // like an ordinary limit.
    network.max_gas_limit = None;
    assert!(usable_gas_ceiling(&network, 20_999).is_err());
    assert_eq!(usable_gas_ceiling(&network, 21_000).unwrap(), 21_000);
    network.max_gas_limit = Some("20999".into());
    assert!(usable_gas_ceiling(&network, 30_000_000).is_err());
}

#[test]
fn a_configured_fee_ceiling_refuses_an_endpoint_that_names_more() {
    // The one field on the automatic path with nothing behind it: no policy
    // rule speaks about fees, and nobody reviews an automatic transaction, so
    // `gas_limit × max_fee_per_gas` used to be whatever one endpoint said.
    let mut network = network();

    network.max_fee_per_gas = None;
    assert_eq!(capped_fee(&network, u128::MAX).unwrap(), u128::MAX);

    network.max_fee_per_gas = Some("1000000000".into());
    assert_eq!(capped_fee(&network, 999_999_999).unwrap(), 999_999_999);
    assert_eq!(capped_fee(&network, 1_000_000_000).unwrap(), 1_000_000_000);

    // Refused rather than clamped: a clamped fee is an envelope that may never
    // mine, holding the wallet's one in-flight slot for the chain. The error
    // says what to change.
    let error = capped_fee(&network, 1_000_000_001).unwrap_err().to_string();
    assert!(error.contains("1000000000"), "{error}");
    assert!(error.contains("max_fee_per_gas"), "{error}");

    network.max_fee_per_gas = Some("not a number".into());
    assert!(capped_fee(&network, 1).is_err());
}

/// The window between recording a simulation and sending it. Nothing in
/// `validate_send` moves when a delegation does -- it checks the wallet, the
/// chain, the policy revision, the plan digest, and the fork flag -- so the
/// batch used to be signed against whatever `will_authorize_delegation` said
/// minutes earlier.
#[test]
fn a_delegation_that_moved_after_simulation_refuses_the_send() {
    use alloy::primitives::{Address, Bytes};

    let wallet = Address::repeat_byte(0x11);
    let other = Address::repeat_byte(0x22);
    let designator = |address: Address| {
        let mut bytes = vec![0xef, 0x01, 0x00];
        bytes.extend_from_slice(address.as_slice());
        Bytes::from(bytes)
    };
    let empty = Bytes::new();

    // Undelegated at simulation and still undelegated: authorize, as before.
    assert!(authorization_for_send(&empty, wallet, None).unwrap());

    // Already delegated to the implementation this batch targets. The
    // authorization would be a no-op that still consumes a nonce.
    assert!(
        !authorization_for_send(&designator(CANONICAL_CALIBUR), wallet, None).unwrap(),
        "an account already delegated to Calibur must not pay for a second authorization"
    );

    // Simulated against no delegation, but the account acquired one in the
    // meantime. The batch would replace an implementation nobody reviewed.
    let error = format!(
        "{:#}",
        authorization_for_send(&designator(other), wallet, None)
            .expect_err("a delegation that appeared after simulation must stop the send")
    );
    assert!(error.contains("delegation changed"), "{error}");
    assert!(error.contains("Simulate the plan again"), "{error}");

    // And the reverse: reviewed as replacing `other`, but it is gone now.
    let error = format!(
        "{:#}",
        authorization_for_send(&empty, wallet, Some(&format!("{other:#x}")))
            .expect_err("a delegation that vanished after simulation must stop the send")
    );
    assert!(error.contains("delegation changed"), "{error}");

    // Reviewed as replacing `other`, and that is still what is there.
    assert!(
        authorization_for_send(&designator(other), wallet, Some(&format!("{other:#x}"))).unwrap()
    );

    // Code that is not a designator at all is not something to sign against.
    assert!(authorization_for_send(&Bytes::from(vec![0x60, 0x00]), wallet, None).is_err());
}

mod cancellation_gas_tests {
    //! A cancellation that cannot be mined is a cancellation that did not happen.

    use super::*;

    /// The estimate is an endpoint's answer and a cancellation cannot be
    /// simulated, so nothing else checks it. Zero -- or anything under half the
    /// intrinsic cost, since the multiplier is 2 -- signed an envelope below
    /// the 21,000 gas every transaction costs before it does anything, which
    /// every honest peer rejects.
    ///
    /// The rejection is not the damage. The envelope is persisted before it is
    /// broadcast, so each one spends a slot in a history capped at
    /// `MAX_CANCELLATION_ATTEMPTS`; at the cap, reconciliation stops repricing
    /// and rebroadcasts the newest stored envelope. Eight bad estimates leave
    /// the owner resending an invalid envelope forever while the transaction
    /// they were trying to stop mines.
    #[test]
    fn an_estimate_below_the_intrinsic_cost_still_signs_a_mineable_limit() {
        let ceiling = 30_000_000;
        for dishonest in [0, 1, 10_499] {
            assert_eq!(
                cancellation_gas_limit(dishonest, ceiling),
                INTRINSIC_TRANSACTION_GAS,
                "an estimate of {dishonest} must still buy a transaction that can mine"
            );
        }
    }

    /// An honest estimate is doubled as before. The floor is a floor, not a
    /// replacement for the estimate.
    #[test]
    fn an_ordinary_estimate_is_unchanged() {
        assert_eq!(cancellation_gas_limit(21_000, 30_000_000), 42_000);
        assert_eq!(cancellation_gas_limit(50_000, 30_000_000), 100_000);
    }

    /// And the ceiling still wins over the multiplier, because that is the
    /// bound protecting against the estimate being too large rather than too
    /// small.
    #[test]
    fn the_usable_ceiling_still_caps_the_result() {
        assert_eq!(cancellation_gas_limit(u64::MAX, 100_000), 100_000);
        assert_eq!(cancellation_gas_limit(60_000, 100_000), 100_000);
    }

    /// The floor can never breach the ceiling, because `usable_gas_ceiling`
    /// refuses a ceiling below the intrinsic cost before this is reached. This
    /// is what makes raising safe rather than a second guess about the bound.
    #[test]
    fn the_floor_cannot_exceed_a_ceiling_that_was_admitted() {
        let network = crate::config::default_networks()
            .into_iter()
            .find(|network| network.chain_id == 1)
            .expect("mainnet preset");
        assert!(usable_gas_ceiling(&network, INTRINSIC_TRANSACTION_GAS - 1).is_err());
        let admitted = usable_gas_ceiling(&network, INTRINSIC_TRANSACTION_GAS).unwrap();
        assert!(cancellation_gas_limit(0, admitted) <= admitted);
    }
}
