//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::{core::policy::WalletPolicy, policy_store::DatabaseKey};
use serde_json::json;

fn plan() -> ExecutionPlan {
    plan_with_value("1")
}

fn plan_with_value(value: &str) -> ExecutionPlan {
    ExecutionPlan::parse(json!({
        "schema_version": "1",
        "chain_id": "1",
        "caip2_chain_id": "eip155:1",
        "sender": "0x1111111111111111111111111111111111111111",
        "ordered_steps": [{
            "step": 1,
            "kind": "execution",
            "transaction": {
                "chain_id": "1",
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0x",
                "value": value
            }
        }]
    }))
    .unwrap()
}

fn store() -> (tempfile::TempDir, PendingStore) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut database = PolicyStore::open(&path, &DatabaseKey::new([9; 32])).unwrap();
    database
        .put("primary", &WalletPolicy::allow_all_with_approval(), None)
        .unwrap();
    (directory, PendingStore::new(database))
}

#[test]
fn persists_exact_plan_and_lifecycle_without_spend_state() {
    let (_directory, mut store) = store();
    let request = store
        .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
        .unwrap();
    assert_eq!(request.status, PendingStatus::AwaitingApproval);
    let hash = hash_of(ORIGINAL_BYTES);
    let hash = hash.as_str();
    let signed = store
        .store_signed(
            request.request_id,
            &request.digest,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ORIGINAL_BYTES,
            hash,
        )
        .unwrap();
    assert_eq!(signed.status, PendingStatus::Signed);
    let claimed = store.claim_for_submission(request.request_id).unwrap();
    assert_eq!(claimed.status, PendingStatus::Submitting);
    assert_eq!(
        store
            .mark_broadcast(request.request_id, hash, claimed.updated_at)
            .unwrap()
            .status,
        PendingStatus::Broadcast
    );
    assert_eq!(
        store
            .finalize(request.request_id, true, "123", None)
            .unwrap()
            .status,
        PendingStatus::Confirmed
    );
}

#[test]
fn automatic_signatures_are_recorded_but_never_enter_approval_queue() {
    let (_directory, mut store) = store();
    let hash = hash_of(ORIGINAL_BYTES);
    let hash = hash.as_str();
    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash,
        )
        .unwrap();
    assert_eq!(signed.status, PendingStatus::Signed);
    assert!(!signed.approval_required);
    assert!(signed.approved_at.is_none());
    assert!(store.awaiting_approval(None).unwrap().is_empty());
    assert_eq!(
        store.list(Some("primary"), 10).unwrap(),
        std::slice::from_ref(&signed)
    );
    assert_eq!(store.get_by_identifier(hash).unwrap(), signed);
}

#[test]
fn only_one_signed_transaction_can_be_in_flight_per_wallet_and_chain() {
    let (_directory, mut store) = store();
    let first_hash = hash_of(ORIGINAL_BYTES);
    let first_hash = first_hash.as_str();
    let second_hash = hash_of(CANCEL_BYTES_ONE);
    let second_hash = second_hash.as_str();
    let first = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            first_hash,
        )
        .unwrap();
    assert!(
        store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                CANCEL_BYTES_ONE,
                second_hash,
            )
            .is_err()
    );

    let leased = store.claim_for_submission(first.request_id).unwrap();
    store
        .mark_broadcast(first.request_id, first_hash, leased.updated_at)
        .unwrap();
    store.finalize(first.request_id, true, "123", None).unwrap();
    assert!(
        store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                CANCEL_BYTES_ONE,
                second_hash,
            )
            .is_ok()
    );
}

/// A send interrupted after signing leaves the caller without the
/// `request_id`, and every tool that could clear the slot needs one. The
/// rejection has to hand it back or the wallet is stuck on that chain.
#[test]
fn the_in_flight_rejection_names_the_request_holding_the_slot() {
    let (_directory, mut store) = store();
    let blocker = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash_of(ORIGINAL_BYTES).as_str(),
        )
        .unwrap();
    let error = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            CANCEL_BYTES_ONE,
            hash_of(CANCEL_BYTES_ONE).as_str(),
        )
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains(&blocker.request_id.to_string()),
        "rejection must name the blocking request: {message}"
    );
    assert!(message.contains("signed"), "{message}");
    assert!(message.contains("wallet_attempt_cancel"), "{message}");
}

/// The receipt is the only place the price paid exists, so settlement has
/// to capture it: a caller pricing gas from its own history reads this
/// rather than reconstructing it from balance deltas.
#[test]
fn a_stale_observer_cannot_release_a_lease_that_was_reclaimed() {
    let (_directory, mut store) = store();
    let hash = hash_of(ORIGINAL_BYTES);
    let hash = hash.as_str();
    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash,
        )
        .unwrap();

    // What reconciliation observes, outside any lock.
    let observed = store.claim_for_submission(signed.request_id).unwrap();

    // What happens in the meantime: the lease is released and taken again
    // by someone else. The row is `submitting` either way, so status alone
    // cannot tell the two leases apart.
    store
        .release_submission(signed.request_id, observed.updated_at)
        .unwrap();
    let live = store.claim_for_submission(signed.request_id).unwrap();
    assert_ne!(live.updated_at, observed.updated_at);

    // The stale release must not land on the live lease, and must not
    // steal the broadcast either.
    assert!(
        store
            .release_submission(signed.request_id, observed.updated_at)
            .is_err()
    );
    assert!(
        store
            .mark_broadcast(signed.request_id, hash, observed.updated_at)
            .is_err()
    );
    assert_eq!(
        store.get(signed.request_id).unwrap().status,
        PendingStatus::Submitting
    );

    // The holder of the live lease still gets its envelope on the wire.
    assert_eq!(
        store
            .mark_broadcast(signed.request_id, hash, live.updated_at)
            .unwrap()
            .status,
        PendingStatus::Broadcast
    );
}

#[test]
fn settlement_records_what_the_transaction_actually_cost() {
    let (_directory, mut store) = store();
    let hash = hash_of(ORIGINAL_BYTES);
    let hash = hash.as_str();
    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash,
        )
        .unwrap();
    assert!(signed.mined_fee.is_none());
    let leased = store.claim_for_submission(signed.request_id).unwrap();
    store
        .mark_broadcast(signed.request_id, hash, leased.updated_at)
        .unwrap();
    let fee = MinedFee {
        gas_used: "447730".into(),
        effective_gas_price: "320000000".into(),
        transaction_fee_wei: "143273600000000".into(),
    };
    let settled = store
        .finalize(signed.request_id, true, "123", Some(&fee))
        .unwrap();
    assert_eq!(settled.mined_fee.as_ref(), Some(&fee));
    // Survives a reload: the fee is persisted, not just returned.
    assert_eq!(store.get(signed.request_id).unwrap().mined_fee, Some(fee));
}

#[test]
fn ambiguous_broadcast_can_only_reclaim_the_same_signed_bytes() {
    let (_directory, mut store) = store();
    let hash = hash_of(ORIGINAL_BYTES);
    let hash = hash.as_str();
    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash,
        )
        .unwrap();
    let leased = store.claim_for_submission(signed.request_id).unwrap();
    store
        .mark_broadcast(signed.request_id, hash, leased.updated_at)
        .unwrap();

    let current = store.database.get("primary").unwrap().unwrap();
    store
        .database
        .put("primary", &current.policy, Some(current.revision))
        .unwrap();
    let reclaimed = store.claim_broadcast_retry(signed.request_id).unwrap();
    assert_eq!(reclaimed.status, PendingStatus::Submitting);
    assert_eq!(reclaimed.serialized_transaction.as_deref(), Some("0x0102"));
    assert_eq!(reclaimed.signed_transaction_hash.as_deref(), Some(hash));
    assert!(store.claim_broadcast_retry(signed.request_id).is_err());
}

#[test]
fn replacement_is_terminal_and_frees_the_in_flight_slot() {
    let (_directory, mut store) = store();
    let first_hash = hash_of(ORIGINAL_BYTES);
    let first_hash = first_hash.as_str();
    let second_hash = hash_of(CANCEL_BYTES_ONE);
    let second_hash = second_hash.as_str();
    let first = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            first_hash,
        )
        .unwrap();

    // Not yet in flight: a signed-but-never-submitted envelope cannot have
    // been replaced on chain.
    assert!(store.mark_replaced(first.request_id).is_err());

    let leased = store.claim_for_submission(first.request_id).unwrap();
    store
        .mark_broadcast(first.request_id, first_hash, leased.updated_at)
        .unwrap();
    let replaced = store.mark_replaced(first.request_id).unwrap();
    assert_eq!(replaced.status, PendingStatus::Replaced);

    // No rebroadcast and no second replacement: this envelope is done
    // being sent, and the verdict is not something to re-derive.
    assert!(store.claim_broadcast_retry(first.request_id).is_err());
    assert!(store.mark_replaced(first.request_id).is_err());

    // But a receipt still settles it. `replaced` is inferred from a
    // consumed nonce and a missing receipt, which is also what a node
    // whose receipt index lags its nonce reports about a transaction that
    // did mine — so the verdict has to be correctable, or one transient
    // gap says "replaced" forever about funds that moved.
    assert_eq!(
        store
            .finalize(first.request_id, true, "123", None)
            .unwrap()
            .status,
        PendingStatus::Confirmed
    );

    // The wallet+chain in-flight slot is free for the next transaction.
    assert!(
        store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                CANCEL_BYTES_ONE,
                second_hash,
            )
            .is_ok()
    );
}

/// The hash of some serialized bytes, as the store now requires the pair
/// to agree. Hard-coded constants would have to be recomputed by hand
/// every time a fixture's bytes change, and a fixture whose hash does not
/// match its bytes is a fixture that cannot occur in production.
fn hash_of(serialized: &str) -> String {
    let bytes = hex::decode(serialized.trim_start_matches("0x")).expect("fixture hex");
    format!("{:#x}", alloy::primitives::keccak256(bytes))
}

const ORIGINAL_BYTES: &str = "0x0102";
const CANCEL_BYTES_ONE: &str = "0x0304";
const CANCEL_BYTES_TWO: &str = "0x0506";
const CANCEL_BYTES_THREE: &str = "0x0708";

fn broadcast_original(store: &mut PendingStore) -> Uuid {
    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash_of(ORIGINAL_BYTES).as_str(),
        )
        .unwrap();
    let leased = store.claim_for_submission(signed.request_id).unwrap();
    store
        .mark_broadcast(
            signed.request_id,
            hash_of(ORIGINAL_BYTES).as_str(),
            leased.updated_at,
        )
        .unwrap();
    signed.request_id
}

#[test]
fn cancellation_reprices_on_one_row_until_an_attempt_mines() {
    let (_directory, mut store) = store();

    // A cancellation may only race an envelope that reached the network.
    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash_of(ORIGINAL_BYTES).as_str(),
        )
        .unwrap();
    assert!(
        store
            .store_cancellation(
                signed.request_id,
                None,
                CANCEL_BYTES_ONE,
                hash_of(CANCEL_BYTES_ONE).as_str()
            )
            .is_err()
    );
    let leased = store.claim_for_submission(signed.request_id).unwrap();
    store
        .mark_broadcast(
            signed.request_id,
            hash_of(ORIGINAL_BYTES).as_str(),
            leased.updated_at,
        )
        .unwrap();
    let request_id = signed.request_id;

    // Repricing appends to the hash history, keeps only the newest bytes,
    // and refuses duplicates.
    let cancelling = store
        .store_cancellation(
            request_id,
            None,
            CANCEL_BYTES_ONE,
            hash_of(CANCEL_BYTES_ONE).as_str(),
        )
        .unwrap();
    assert_eq!(cancelling.status, PendingStatus::Cancelling);
    assert!(
        store
            .store_cancellation(
                request_id,
                Some(hash_of(CANCEL_BYTES_ONE).as_str()),
                CANCEL_BYTES_ONE,
                hash_of(CANCEL_BYTES_ONE).as_str()
            )
            .is_err()
    );
    let repriced = store
        .store_cancellation(
            request_id,
            Some(hash_of(CANCEL_BYTES_ONE).as_str()),
            CANCEL_BYTES_TWO,
            hash_of(CANCEL_BYTES_TWO).as_str(),
        )
        .unwrap();
    assert_eq!(
        repriced.cancel_serialized_transaction.as_deref(),
        Some("0x0506")
    );
    assert_eq!(
        repriced.cancel_transaction_hashes,
        [
            hash_of(CANCEL_BYTES_ONE).as_str(),
            hash_of(CANCEL_BYTES_TWO).as_str()
        ]
    );

    // A replacement is a replacement of the thing it outbid. This one was
    // priced against the first hash while the second is already newest, so
    // its fee came from a superseded baseline — storing it would install a
    // cheaper envelope as the newest and the next reprice would bump from
    // there, handing the race back to the transaction being cancelled.
    let stale = store
        .store_cancellation(
            request_id,
            Some(hash_of(CANCEL_BYTES_ONE).as_str()),
            CANCEL_BYTES_THREE,
            "0x3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap_err()
        .to_string();
    assert!(stale.contains("while this one was being priced"), "{stale}");

    let cancelled = store.mark_cancelled(request_id, "123", None).unwrap();
    assert_eq!(cancelled.status, PendingStatus::Cancelled);
    assert_eq!(cancelled.block_number.as_deref(), Some("123"));
    assert!(store.mark_cancelled(request_id, "124", None).is_err());
    assert!(store.finalize(request_id, true, "124", None).is_err());

    // Terminal: the wallet+chain in-flight slot is free again.
    broadcast_original(&mut store);
}

#[test]
fn the_in_flight_slot_is_queryable_and_unsent_signatures_can_be_discarded() {
    let (_directory, mut store) = store();
    assert!(store.in_flight("primary", "1").unwrap().is_none());

    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash_of(ORIGINAL_BYTES).as_str(),
        )
        .unwrap();
    assert_eq!(
        store
            .in_flight("primary", "1")
            .unwrap()
            .expect("signed row holds the slot")
            .request_id,
        signed.request_id
    );

    // Never broadcast: discarding locally is honest and frees the slot.
    let discarded = store.discard_unsent(signed.request_id).unwrap();
    assert_eq!(discarded.status, PendingStatus::Cancelled);
    assert!(store.in_flight("primary", "1").unwrap().is_none());

    // Anything that may have reached the network is refused.
    let request_id = broadcast_original(&mut store);
    assert!(store.discard_unsent(request_id).is_err());
    assert!(store.in_flight("primary", "1").unwrap().is_some());
}

#[test]
fn original_can_still_win_the_race_against_its_own_cancellation() {
    let (_directory, mut store) = store();
    let request_id = broadcast_original(&mut store);
    store
        .store_cancellation(
            request_id,
            None,
            CANCEL_BYTES_ONE,
            hash_of(CANCEL_BYTES_ONE).as_str(),
        )
        .unwrap();
    assert_eq!(
        store
            .finalize(request_id, true, "123", None)
            .unwrap()
            .status,
        PendingStatus::Confirmed
    );
}

#[test]
fn foreign_replacement_can_win_the_race_against_a_cancellation() {
    // An envelope this wallet never signed consumed the nonce, for
    // example one sent from the same key imported on another device.
    let (_directory, mut store) = store();
    let request_id = broadcast_original(&mut store);
    store
        .store_cancellation(
            request_id,
            None,
            CANCEL_BYTES_ONE,
            hash_of(CANCEL_BYTES_ONE).as_str(),
        )
        .unwrap();
    assert_eq!(
        store.mark_replaced(request_id).unwrap().status,
        PendingStatus::Replaced
    );
}

#[test]
fn policy_change_cancels_signed_transaction_before_submission() {
    let (_directory, mut store) = store();
    let request = store
        .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
        .unwrap();
    let hash = hash_of(ORIGINAL_BYTES);
    let hash = hash.as_str();
    store
        .store_signed(
            request.request_id,
            &request.digest,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ORIGINAL_BYTES,
            hash,
        )
        .unwrap();
    let current = store.database.get("primary").unwrap().unwrap();
    store
        .database
        .put("primary", &current.policy, Some(current.revision))
        .unwrap();
    assert_eq!(
        store.get(request.request_id).unwrap().status,
        PendingStatus::Cancelled
    );
    assert!(store.claim_for_submission(request.request_id).is_err());
    assert!(
        store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                2,
                CANCEL_BYTES_ONE,
                hash_of(CANCEL_BYTES_ONE).as_str(),
            )
            .is_ok()
    );
}

#[test]
fn policy_change_preserves_a_claimed_submission_for_hash_reconciliation() {
    let (_directory, mut store) = store();
    let hash = hash_of(ORIGINAL_BYTES);
    let hash = hash.as_str();
    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            hash,
        )
        .unwrap();
    store.claim_for_submission(signed.request_id).unwrap();

    let current = store.database.get("primary").unwrap().unwrap();
    store
        .database
        .put("primary", &current.policy, Some(current.revision))
        .unwrap();
    assert_eq!(
        store.get(signed.request_id).unwrap().status,
        PendingStatus::Submitting
    );
}

#[test]
fn rejection_is_terminal() {
    let (_directory, mut store) = store();
    let request = store
        .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
        .unwrap();
    assert_eq!(
        store.reject(request.request_id).unwrap().status,
        PendingStatus::Rejected
    );
    assert!(store.reject(request.request_id).is_err());
}

#[test]
fn duplicate_pending_plan_reuses_request_and_queue_is_bounded() {
    let (_directory, mut store) = store();
    let first = store
        .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
        .unwrap();
    // Provenance round-trips: the vetted producer host survives storage
    // so the approval screen can display it.
    assert_eq!(first.plan_source.as_deref(), Some("mcp.ekubo.org"));
    let duplicate = store
        .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
        .unwrap();
    assert_eq!(duplicate.request_id, first.request_id);
    // A source that is neither the inline literal nor a plain host is
    // refused before it can reach a terminal.
    assert!(
        store
            .create(
                "primary",
                "ethereum",
                &plan_with_value("999"),
                Some("evil\u{1b}[31mhost"),
                1,
            )
            .is_err()
    );

    for value in 2..=MAX_AWAITING_APPROVALS_PER_WALLET {
        store
            .create(
                "primary",
                "ethereum",
                &plan_with_value(&value.to_string()),
                None,
                1,
            )
            .unwrap();
    }
    assert!(
        store
            .create(
                "primary",
                "ethereum",
                &plan_with_value(&(MAX_AWAITING_APPROVALS_PER_WALLET + 1).to_string()),
                None,
                1,
            )
            .is_err()
    );
}

#[test]
fn policy_change_replaces_stale_duplicate_approval_request() {
    let (_directory, mut store) = store();
    let stale = store
        .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
        .unwrap();
    let current = store.database.get("primary").unwrap().unwrap();
    store
        .database
        .put("primary", &current.policy, Some(current.revision))
        .unwrap();

    assert_eq!(
        store.get(stale.request_id).unwrap().status,
        PendingStatus::Cancelled
    );
    let replacement = store
        .create("primary", "ethereum", &plan(), None, 2)
        .unwrap();
    assert_ne!(replacement.request_id, stale.request_id);
    assert_eq!(replacement.policy_revision, 2);
}

#[test]
fn wallet_state_removal_cancels_pending_requests() {
    let (_directory, mut store) = store();
    let request = store
        .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
        .unwrap();
    store.database.delete("primary", 1).unwrap();
    assert_eq!(
        store.get(request.request_id).unwrap().status,
        PendingStatus::Cancelled
    );
}
