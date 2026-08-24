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
use uuid::Uuid;

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
    let (max_fee, priority) = cancellation_fees((800, 80), (800, 80), 100, 10).unwrap();
    assert_eq!(max_fee, 900);
    assert_eq!(priority, 90);

    // A hot market: current estimates already clear the floor.
    let (max_fee, priority) = cancellation_fees((800, 80), (800, 80), 2_000, 200).unwrap();
    assert_eq!(max_fee, 2_000);
    assert_eq!(priority, 200);

    // Repricing outbids the newest incumbent but keeps the original as the
    // immutable cap anchor.
    let (max_fee, priority) = cancellation_fees((800, 80), (1_600, 160), 100, 10).unwrap();
    assert_eq!(max_fee, 1_800);
    assert_eq!(priority, 180);

    // The bump rounds up so a tiny fee still strictly increases.
    assert_eq!(bumped_fee(1), 2);
    assert_eq!(bumped_fee(0), 0);

    // The pair stays EIP-1559-consistent when the priority floor passes
    // the market maximum fee.
    let (max_fee, priority) = cancellation_fees((100, 100), (100, 100), 50, 5).unwrap();
    assert_eq!(priority, 113);
    assert!(max_fee >= priority);

    // An endpoint naming an enormous market fee no longer names the ceiling
    // as well. The cap used to include `market_max_fee` in the maximum it was
    // capping, so a reported fee of M was checked against at least 2M and
    // every M it could name passed -- the one signing path with no policy and
    // no approval screen behind it, taking a builder tip from a stranger.
    let (max_fee, priority) =
        cancellation_fees((800, 80), (800, 80), 10_000_000, 9_000_000).unwrap();
    assert_eq!(max_fee, 3_200, "four times the fee the owner committed to");
    assert_eq!(priority, 3_200);

    // Clamped rather than refused, so the envelope still replaces the one it
    // is cancelling. Refusing would let the same endpoint deny cancellation
    // by reporting a large enough number.
    assert!(max_fee >= 900 && priority >= 90);
}

#[test]
fn cancellation_retries_never_ratchet_the_originals_cap() {
    let original = (800, 80);
    let absolute_cap = 3_200;

    // Feed every selected cancellation back as the newest incumbent, exactly
    // as all eight agent-callable retries do. The first replacement reaches the
    // cap the original envelope set, which is the only cap there is now that a
    // network profile carries none: an owner's own ceiling is a policy rule,
    // and a cancellation asks no policy question. The next retry needs 12.5%
    // more, so the core says to rebroadcast rather than treat its own
    // unauthenticated signature as a new, wider authorization.
    let first = cancellation_fees(original, original, u128::MAX, u128::MAX)
        .expect("the first bounded cancellation exists");
    assert_eq!(first, (absolute_cap, absolute_cap));

    for _ in 1..crate::pending::MAX_CANCELLATION_ATTEMPTS {
        assert!(
            cancellation_fees(original, first, u128::MAX, u128::MAX).is_none(),
            "a retry above the immutable cap must rebroadcast, not sign"
        );
    }
}

#[test]
fn a_rejected_send_whose_transaction_landed_is_reported_as_mined() {
    for rejection in ALREADY_KNOWN {
        let result = send_failure_outcome(
            "0xabc",
            Some(crate::rpc::ReceiptStatus {
                succeeded: true,
                block_number: 27_923_617,
                block_hash: alloy::primitives::B256::ZERO,
                head_block_number: 27_923_617,
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
            block_hash: alloy::primitives::B256::ZERO,
            head_block_number: 42,
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
        instance_id: Uuid::new_v4(),
        id: "primary".into(),
        address: signer.address(),
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    }
}

fn network() -> NetworkConfig {
    crate::config::default_networks().remove(0)
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
fn the_gas_ceiling_is_the_block_the_endpoint_reported() {
    // Run 6251, finding 186999. Signing after a simulation always had this
    // bound; cancellation used to have none unless the network carried a
    // configured maximum, which most shipped profiles did not — so on an
    // ordinary network one endpoint's `estimate_gas` decided the signed gas
    // limit by itself. A cancellation cannot be simulated and is asked for
    // exactly when something is already stuck, so an absurd estimate produced
    // an envelope every honest peer rejects while spending one of the eight
    // attempts this wallet will ever make.
    //
    // Narrower ceilings are the owner's to write as a policy rule on
    // `gas_limit`, which no longer leaves this path unbounded when they do not.
    assert_eq!(usable_gas_ceiling(30_000_000).unwrap(), 30_000_000);
    assert_eq!(usable_gas_ceiling(500_000).unwrap(), 500_000);

    // A ceiling below what every transaction costs before it does anything is
    // not a bound, it is a refusal to sign at all -- and the block limit comes
    // from whichever endpoint answered, so a small enough answer would
    // otherwise disqualify the plain self-send a cancellation is while looking
    // like an ordinary limit.
    assert!(usable_gas_ceiling(20_999).is_err());
    assert_eq!(usable_gas_ceiling(21_000).unwrap(), 21_000);
}

#[test]
fn cancellation_is_bounded_by_the_original_envelope_it_replaces() {
    let signer = PrivateKeySigner::from_slice(&[13; 32]).unwrap();
    let wallet = wallet(&signer);
    let original = sign_prepared(
        &signer,
        1,
        9,
        100_000,
        30,
        3,
        &crate::simulation::PlannedCall {
            mode: ExecutionMode::Direct,
            to: Address::repeat_byte(0x44),
            data: alloy::primitives::Bytes::new(),
            value: U256::ZERO,
        },
        false,
    )
    .unwrap();
    let cancellation = sign_prepared(
        &signer,
        1,
        9,
        100_000,
        101,
        10,
        &crate::simulation::PlannedCall {
            mode: ExecutionMode::Direct,
            to: wallet.address,
            data: alloy::primitives::Bytes::new(),
            value: U256::ZERO,
        },
        false,
    )
    .unwrap();

    let above_original_bound = sign_prepared(
        &signer,
        1,
        9,
        100_000,
        121,
        10,
        &crate::simulation::PlannedCall {
            mode: ExecutionMode::Direct,
            to: wallet.address,
            data: alloy::primitives::Bytes::new(),
            value: U256::ZERO,
        },
        false,
    )
    .unwrap();

    // The original envelope's fourfold bound is what a cancellation is checked
    // against. It is the one cap a network profile never supplied and cannot
    // now: the owner authorized this nonce at that price, and no later
    // signature of the wallet's own widens it.
    let network = network();
    let error = validate_signed_cancellation(
        &above_original_bound,
        &wallet,
        &network,
        &original.serialized_transaction,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("original transaction's fee bound"),
        "{error}"
    );

    validate_signed_cancellation(
        &cancellation,
        &wallet,
        &network,
        &original.serialized_transaction,
    )
    .unwrap();
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
    // Letters, so its lowercase and checksum spellings differ.
    let other = Address::repeat_byte(0xab);
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

    // Reviewed as replacing `other`, and that is still what is there. The
    // record spells the address in checksum case now and spelled it lowercase
    // before this was compared as an address, and both name the same thing.
    assert!(
        authorization_for_send(&designator(other), wallet, Some(&format!("{other:#x}"))).unwrap()
    );
    assert!(
        authorization_for_send(&designator(other), wallet, Some(&other.to_checksum(None))).unwrap()
    );
    // A record that is not an address at all matches nothing.
    let error = format!(
        "{:#}",
        authorization_for_send(&designator(other), wallet, Some("not-an-address"))
            .expect_err("a record that names no address must stop the send")
    );
    assert!(error.contains("delegation changed"), "{error}");

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
        assert!(usable_gas_ceiling(INTRINSIC_TRANSACTION_GAS - 1).is_err());
        let admitted = usable_gas_ceiling(INTRINSIC_TRANSACTION_GAS).unwrap();
        assert!(cancellation_gas_limit(0, admitted) <= admitted);
    }
}

mod automatic_gas_floor_tests {
    //! The twin of the cancellation floor, on the path with no human on it.

    use super::*;

    fn simulation(gas_used: &str, block_gas_limit: &str, delegating: bool) -> SimulationResult {
        let mut result = crate::simulation::SimulationResult {
            simulation_id: None,
            digest: format!("0x{}", "11".repeat(32)),
            allowed: true,
            policy_outcome: crate::core::policy::PolicyOutcome::Allowed,
            policy_findings: Vec::new(),
            policy_revision: 1,
            execution_mode: crate::simulation::ExecutionMode::Direct,
            implementation: None,
            will_authorize_delegation: delegating,
            replaces_delegated_implementation: None,
            prepared_transaction: None,
            prepared_execution: None,
            simulation: crate::simulation::SimulationExecution {
                success: true,
                gas_used: Some(gas_used.into()),
                block_gas_limit: Some(block_gas_limit.into()),
                output: None,
                error: None,
                failure: None,
            },
            token_spends: std::collections::BTreeMap::new(),
            balance_changes: None,
            block_number: "100".into(),
            fork: None,
        };
        result.simulation.success = true;
        result
    }

    /// `execution_output` copies `max_used_gas` or `gas_used` through
    /// untouched, so a successful simulation claiming `0` multiplied to `0`
    /// and was signed. Nodes reject an envelope under the intrinsic cost
    /// before executing it, and the automatic path records it -- taking the
    /// wallet's one in-flight slot for the chain, with no human anywhere in
    /// the sequence to notice.
    #[test]
    fn a_simulation_reporting_no_gas_still_signs_a_mineable_limit() {
        for reported in ["0", "1", "10499"] {
            let limit = signing_gas_limit(&simulation(reported, "30000000", false))
                .expect("an endpoint's number is not a reason to refuse to sign");
            assert!(
                limit >= INTRINSIC_TRANSACTION_GAS,
                "{reported} gas produced a limit of {limit}"
            );
        }
    }

    /// A delegation pays its authorization on top of the intrinsic cost, so
    /// the floor moves with it rather than being a constant.
    ///
    /// It does not bind here, and that is worth stating rather than asserting
    /// around: the authorization cost is already in the baseline, so doubling
    /// it clears the floor by itself. What the floor guarantees is the bound,
    /// not that it is the answer.
    #[test]
    fn a_delegating_transaction_floors_above_the_bare_intrinsic_cost() {
        let floor = INTRINSIC_TRANSACTION_GAS + EIP7702_AUTHORIZATION_INTRINSIC_COST;
        let limit = signing_gas_limit(&simulation("0", "30000000", true)).unwrap();
        assert!(
            limit >= floor,
            "{limit} is below the {floor} this transaction costs"
        );
        assert!(
            limit > INTRINSIC_TRANSACTION_GAS,
            "the bare intrinsic cost is not enough for a transaction that authorizes"
        );
    }

    /// An ordinary simulation is unchanged: the floor is a floor, not a
    /// replacement for the estimate.
    #[test]
    fn an_ordinary_simulation_is_unchanged() {
        let limit = signing_gas_limit(&simulation("50000", "30000000", false)).unwrap();
        assert_eq!(limit, 100_000);
    }

    /// And a ceiling that cannot hold the floor is refused rather than
    /// silently clamped past it -- the one case where raising would otherwise
    /// breach the bound a block itself imposes.
    #[test]
    fn a_ceiling_below_the_floor_is_refused() {
        assert!(signing_gas_limit(&simulation("0", "21000", true)).is_err());
    }
}
