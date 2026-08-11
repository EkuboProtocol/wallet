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
            .mark_broadcast(request.request_id, hash, claimed.generation)
            .unwrap()
            .status,
        PendingStatus::Broadcast
    );
    assert_eq!(
        store
            .finalize(request.request_id, true, 123, None)
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
        .mark_broadcast(first.request_id, first_hash, leased.generation)
        .unwrap();
    store.finalize(first.request_id, true, 123, None).unwrap();
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
        .release_submission(signed.request_id, observed.generation)
        .unwrap();
    let live = store.claim_for_submission(signed.request_id).unwrap();
    assert_ne!(live.updated_at, observed.updated_at);

    // The stale release must not land on the live lease, and must not
    // steal the broadcast either.
    assert!(
        store
            .release_submission(signed.request_id, observed.generation)
            .is_err()
    );
    assert!(
        store
            .mark_broadcast(signed.request_id, hash, observed.generation)
            .is_err()
    );
    assert_eq!(
        store.get(signed.request_id).unwrap().status,
        PendingStatus::Submitting
    );

    // The holder of the live lease still gets its envelope on the wire.
    assert_eq!(
        store
            .mark_broadcast(signed.request_id, hash, live.generation)
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
        .mark_broadcast(signed.request_id, hash, leased.generation)
        .unwrap();
    let fee = MinedFee {
        gas_used: "447730".into(),
        effective_gas_price: "320000000".into(),
        transaction_fee_wei: "143273600000000".into(),
    };
    let settled = store
        .finalize(signed.request_id, true, 123, Some(&fee))
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
        .mark_broadcast(signed.request_id, hash, leased.generation)
        .unwrap();

    let current = store.database.get("primary").unwrap().unwrap();
    store
        .database
        .put("primary", &current.policy, Some(current.revision))
        .unwrap();
    let reclaimed = store.claim_broadcast_retry(signed.request_id).unwrap();
    assert_eq!(reclaimed.status, PendingStatus::Submitting);
    assert_eq!(
        reclaimed.serialized_transaction.as_deref(),
        Some(ORIGINAL_BYTES)
    );
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
    assert!(
        store
            .mark_replaced(first.request_id, first.generation)
            .is_err()
    );

    let leased = store.claim_for_submission(first.request_id).unwrap();
    let broadcast = store
        .mark_broadcast(first.request_id, first_hash, leased.generation)
        .unwrap();
    // A verdict reached from a snapshot older than the row does not apply.
    assert!(
        store
            .mark_replaced(first.request_id, leased.generation)
            .is_err(),
        "a stale observation must not retire a row that has moved since"
    );
    let replaced = store
        .mark_replaced(first.request_id, broadcast.generation)
        .unwrap();
    assert_eq!(replaced.status, PendingStatus::Replaced);

    // No rebroadcast and no second replacement: this envelope is done
    // being sent, and the verdict is not something to re-derive.
    assert!(store.claim_broadcast_retry(first.request_id).is_err());
    assert!(
        store
            .mark_replaced(first.request_id, replaced.generation)
            .is_err()
    );

    // But a receipt still settles it. `replaced` is inferred from a
    // consumed nonce and a missing receipt, which is also what a node
    // whose receipt index lags its nonce reports about a transaction that
    // did mine — so the verdict has to be correctable, or one transient
    // gap says "replaced" forever about funds that moved.
    assert_eq!(
        store
            .finalize(first.request_id, true, 123, None)
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

// Real signed EIP-1559 envelopes, differing only in nonce. They used to be
// `0x0102`, `0x0304`, and so on: bytes paired with their own keccak, which
// satisfied every check the row parser made and could not occur in production,
// where the bytes are always something this wallet signed. `PendingRow::parse`
// now decodes what it reads -- a hash agrees with whatever it was taken over,
// so hashing correctly says the two columns agree about the bytes and nothing
// about the bytes being a transaction -- and these fixtures had to become
// transactions for the tests to keep meaning what they said.
//
// Generated once with the same construction `sign_prepared` uses, from the key
// `0x1111…11`, chain 1, nonces 0 to 3.
const ORIGINAL_BYTES: &str = "0x02f86a0180843b9aca00843b9aca008252089422222222222222222222222222222222222222228080c080a0179e0e4ffd0fe7f5c13b483a7d47be35f1d7d20919724a2ff4c44fd93804dc90a07d7160f72aa22229680c207433e9615a12e805e301d368a3e8a61f725a61324c";
const CANCEL_BYTES_ONE: &str = "0x02f86a0101843b9aca00843b9aca008252089422222222222222222222222222222222222222228080c080a078a611bc68dbf7d8b8c7934fe99d0159e6d5eb63ae5eb0aca5c49bfc894f38bca06e6f49aa2a067ce8c35ccaecbc1c235311e3fbabb8cc0f30bc02c0b249319a0a";
const CANCEL_BYTES_TWO: &str = "0x02f86a0102843b9aca00843b9aca008252089422222222222222222222222222222222222222228080c080a0032c9b0e183e38094d411c6b7b8d4acf2ff361f5ce4733fe9f70de38ce67c295a01fb5907a94320e39860297ea2d20160534f10950a96cd88db6f1c3693c5f73eb";
const CANCEL_BYTES_THREE: &str = "0x02f86a0103843b9aca00843b9aca008252089422222222222222222222222222222222222222228080c080a05e9bc29265b16802653fd6e68488b7af3d69bd77649f67d6027d9e7ad5405486a07157d705413b14993118ada56d0a17e25756247798ba911b0444b0412e4bc7e1";

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
            leased.generation,
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
            leased.generation,
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
        Some(CANCEL_BYTES_TWO)
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
            // Its own hash, not an arbitrary one. The envelope and the hash
            // are validated as a pair before anything else now, so a junk hash
            // here would be rejected for the wrong reason and this assertion
            // would stop testing what it names.
            hash_of(CANCEL_BYTES_THREE).as_str(),
        )
        .unwrap_err()
        .to_string();
    assert!(stale.contains("while this one was being priced"), "{stale}");

    let cancelled = store.mark_cancelled(request_id, 123, None).unwrap();
    assert_eq!(cancelled.status, PendingStatus::Cancelled);
    assert_eq!(cancelled.block_number.as_deref(), Some("123"));
    assert!(store.mark_cancelled(request_id, 124, None).is_err());
    assert!(store.finalize(request_id, true, 124, None).is_err());

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
        store.finalize(request_id, true, 123, None).unwrap().status,
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
        store
            .mark_replaced(request_id, store.get(request_id).unwrap().generation)
            .unwrap()
            .status,
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

/// The approval screen labels this field "Plan source", and a reviewer reads
/// it to know whose word they are taking. So a bare host means TLS proved that
/// host, and anything a dapp wrote about itself only ever appears behind the
/// prefix that says as much.
#[test]
fn a_plan_source_separates_what_was_proved_from_what_was_claimed() {
    for proved in ["mcp.ekubo.org", "localhost:8545", "inline data URI"] {
        validate_plan_source(Some(proved)).unwrap_or_else(|error| panic!("{proved}: {error}"));
    }
    for claimed in [
        "WalletConnect: Ekubo (ekubo.org)",
        "WalletConnect: an unnamed dapp",
        // A dapp naming itself after somewhere else is still legible as a
        // claim, which is the whole job of the prefix.
        "WalletConnect: ekubo.org (claim-rewards.xyz)",
    ] {
        validate_plan_source(Some(claimed)).unwrap_or_else(|error| panic!("{claimed}: {error}"));
    }

    // What the prefix does not buy: a claim that could redraw the screen it is
    // displayed on, or one that says nothing at all.
    for refused in [
        "WalletConnect: ",
        "WalletConnect: \u{202e}gro.obuke",
        "WalletConnect: two\nlines",
        "Ekubo (ekubo.org)",
        "mcp.ekubo.org, connected over WalletConnect",
    ] {
        assert!(
            validate_plan_source(Some(refused)).is_err(),
            "{refused} was accepted"
        );
    }

    // The cap is on bytes, because that is what the column holds.
    let long = format!("WalletConnect: {}", "e".repeat(MAX_PLAN_SOURCE_BYTES));
    assert!(validate_plan_source(Some(&long)).is_err());
}

#[test]
fn a_reclaim_within_one_millisecond_still_invalidates_a_replacement_verdict() {
    // The reconciler reads a row outside the lock, decides from a node's
    // answer that the envelope was replaced, and writes that verdict some
    // moments later. In between, `claim_broadcast_retry` can take the row back
    // for an exact-byte rebroadcast. `mark_replaced` accepts both `broadcast`
    // and `submitting`, so only the lease name keeps the stale verdict off the
    // new lease -- and `updated_at` at millisecond resolution is not a name,
    // because both writes can land inside the same millisecond.
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
    let observed = store
        .mark_broadcast(signed.request_id, hash, leased.generation)
        .unwrap();

    let reclaimed = store.claim_broadcast_retry(signed.request_id).unwrap();
    assert_eq!(reclaimed.status, PendingStatus::Submitting);
    assert_ne!(reclaimed.generation, observed.generation);

    assert!(
        store
            .mark_replaced(signed.request_id, observed.generation)
            .is_err(),
        "a verdict from before the reclaim retired a live submission"
    );
    assert_eq!(
        store.get(signed.request_id).unwrap().status,
        PendingStatus::Submitting
    );
}

#[test]
fn a_mismatched_envelope_and_hash_never_reach_the_database() {
    // The pair used to be checked only by `PendingRow::parse`, on the way back
    // out. A well-formed but mismatched pair therefore committed, and only the
    // `self.get` after the commit failed -- leaving a durable row that every
    // read rejects while `signed` and `cancelling` both hold the wallet's one
    // in-flight slot through the partial unique index. `reconcile_all`
    // swallows the read error to keep a listing rendering, so the slot stays
    // held and nothing further can be signed for that wallet on that chain.
    let (_directory, mut store) = store();
    let wrong = hash_of(CANCEL_BYTES_ONE);

    let error = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan(),
            None,
            1,
            ORIGINAL_BYTES,
            wrong.as_str(),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("do not hash to"), "{error}");

    // Nothing was written, so the in-flight slot is still free and the honest
    // pair goes in.
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
        .expect("the slot was never taken by the rejected write");

    // And the same on the cancellation writer, which is the worse one to wedge
    // -- the owner is trying to stop a transaction.
    let leased = store.claim_for_submission(signed.request_id).unwrap();
    store
        .mark_broadcast(
            signed.request_id,
            hash_of(ORIGINAL_BYTES).as_str(),
            leased.generation,
        )
        .unwrap();
    let error = store
        .store_cancellation(
            signed.request_id,
            None,
            CANCEL_BYTES_ONE,
            hash_of(CANCEL_BYTES_TWO).as_str(),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("do not hash to"), "{error}");
    assert_eq!(
        store.get(signed.request_id).unwrap().status,
        PendingStatus::Broadcast,
        "the row is still readable and still progressing"
    );
}

#[test]
fn a_broadcast_hash_naming_another_transaction_is_refused_on_read() {
    // `mark_broadcast` will only write the signed hash -- its UPDATE matches on
    // `signed_transaction_hash = ?2` -- but a guard in one writer is not an
    // invariant of the row, and this field is read by code that trusts it
    // completely. `reconcile` looks a receipt up by `broadcast_transaction_hash`
    // in preference to the signed hash while `observe` takes the nonce from
    // `serialized_transaction`, so the two disagreeing means another
    // transaction's receipt settles this plan and releases the in-flight slot
    // while the envelope actually signed is still out there.
    let (_directory, mut store) = store();
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
            leased.generation,
        )
        .unwrap();
    assert_eq!(
        store.get(signed.request_id).unwrap().status,
        PendingStatus::Broadcast
    );

    // The writer refuses an unrelated hash outright.
    let leased = store.claim_for_submission(signed.request_id);
    assert!(
        leased.is_err(),
        "a broadcast row is not claimable for submission again"
    );

    // So plant it the way an altered database would, and confirm the read is
    // what catches it rather than reconciliation acting on it.
    let other =
        B256::from_str("0x4444444444444444444444444444444444444444444444444444444444444444")
            .unwrap();
    store
        .database
        .connection
        .execute(
            "UPDATE pending_transactions SET broadcast_transaction_hash = ?2
             WHERE request_id = ?1",
            params![signed.request_id, Blob(other)],
        )
        .unwrap();
    let error = format!("{:#}", store.get(signed.request_id).unwrap_err());
    assert!(error.contains("names a different transaction"), "{error}");

    // A broadcast hash with no signed envelope behind it is refused too.
    store
        .database
        .connection
        .execute(
            "UPDATE pending_transactions
             SET broadcast_transaction_hash = ?2, signed_transaction_hash = NULL,
                 serialized_transaction = NULL
             WHERE request_id = ?1",
            params![signed.request_id, Blob(other)],
        )
        .unwrap();
    let error = format!("{:#}", store.get(signed.request_id).unwrap_err());
    assert!(
        error.contains("no signed transaction to belong to"),
        "{error}"
    );
}

#[test]
fn an_in_flight_row_without_its_envelope_is_refused_rather_than_wedging_the_slot() {
    // An envelope is not optional decoration on an in-flight row; it is the
    // thing the row is about. Without one, nothing can move the row on:
    // `claim_for_submission` leases any `signed` row without looking,
    // `submit_claimed` then fails building `SignedExecution` before reaching
    // its lease-release handling, and reconciliation cannot take a nonce from
    // a record that has no bytes. `reconcile_all` keeps the record on error,
    // so the wallet's one in-flight slot for that chain is held until someone
    // repairs the database by hand.
    let (_directory, mut store) = store();
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
    store
        .database
        .connection
        .execute(
            "UPDATE pending_transactions
             SET serialized_transaction = NULL, signed_transaction_hash = NULL
             WHERE request_id = ?1",
            params![signed.request_id],
        )
        .unwrap();
    let error = format!("{:#}", store.get(signed.request_id).unwrap_err());
    assert!(error.contains("must carry the signed envelope"), "{error}");
}

#[test]
fn a_rejected_row_carrying_signed_bytes_is_refused() {
    // The quiet direction. `rejected` is reachable only from
    // `awaiting_approval`, which never had an envelope, so signed bytes on one
    // are bytes that should not exist -- and they are readable through the
    // ordinary transaction reads.
    let (_directory, mut store) = store();
    let request = store
        .create("primary", "ethereum", &plan(), None, 1)
        .unwrap();
    store.reject(request.request_id).unwrap();
    store
        .database
        .connection
        .execute(
            "UPDATE pending_transactions
             SET serialized_transaction = ?2, signed_transaction_hash = ?3
             WHERE request_id = ?1",
            params![
                request.request_id,
                Blob(Bytes::from_str(ORIGINAL_BYTES).unwrap()),
                Blob(B256::from_str(hash_of(ORIGINAL_BYTES).as_str()).unwrap()),
            ],
        )
        .unwrap();
    let error = format!("{:#}", store.get(request.request_id).unwrap_err());
    assert!(error.contains("must not carry signed bytes"), "{error}");
}

#[test]
fn a_cancelled_row_is_accepted_from_either_origin() {
    // `discard_unsent` cancels a `signed` row that was never submitted, which
    // has its envelope. Removing a wallet's state cancels its
    // `awaiting_approval` rows, which never had one. Both are the wallet's own
    // writes, so the invariant above has to admit both rather than picking the
    // origin it happened to be written against.
    let (_directory, mut store) = store();
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
    let discarded = store.discard_unsent(signed.request_id).unwrap();
    assert_eq!(discarded.status, PendingStatus::Cancelled);
    assert!(discarded.serialized_transaction.is_some());
}

#[test]
fn a_cancelled_row_from_wallet_removal_never_had_an_envelope() {
    // The other origin, and the one that caught an over-strict first attempt
    // at the invariant above: removing a wallet's state cancels its
    // `awaiting_approval` rows, which have no envelope and never did.
    let (_directory, mut store) = store();
    let awaiting = store
        .create("primary", "ethereum", &plan(), None, 1)
        .unwrap();
    store.database.delete("primary", 1).unwrap();
    let cancelled = store.get(awaiting.request_id).unwrap();
    assert_eq!(cancelled.status, PendingStatus::Cancelled);
    assert!(cancelled.serialized_transaction.is_none());
}

#[test]
fn terminal_history_is_bounded_while_live_rows_are_left_alone() {
    // Nothing bounded what queued and in-flight rows *become*. Every automatic
    // signature writes a durable row before it broadcasts, so repeated valid
    // requests grow the shared database until writes fail -- for every wallet
    // in the store, not just the noisy one.
    let (_directory, mut store) = store();

    // One row that must survive whatever else happens: still awaiting a
    // decision, so it is live lifecycle state rather than history.
    let live = store
        .create("primary", "ethereum", &plan_with_value("7"), None, 1)
        .unwrap();

    // Terminal rows are written directly: driving 1_001 transactions through
    // the real lifecycle would take far longer than the invariant is worth.
    let connection = &store.database.connection;
    for index in 0..(MAX_TERMINAL_HISTORY_PER_WALLET + 5) {
        connection
            .execute(
                "INSERT INTO pending_transactions(
                    request_id, wallet_id, network_name, chain_id, plan_json,
                    plan_digest, policy_revision, status, created_at, updated_at,
                    decided_at, approval_required
                 ) VALUES (?1, 'primary', 'ethereum', 1, '{}', ?2, 1, 'confirmed', ?3, ?3, ?3, 1)",
                params![
                    uuid::Uuid::new_v4(),
                    Blob(B256::repeat_byte(1)),
                    Millis(sql::now() + chrono::Duration::milliseconds(index)),
                ],
            )
            .unwrap();
    }
    let terminal: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pending_transactions WHERE status = 'confirmed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(terminal, MAX_TERMINAL_HISTORY_PER_WALLET + 5);

    // The next insert reclaims the excess.
    store
        .create("primary", "ethereum", &plan_with_value("9"), None, 1)
        .unwrap();
    let terminal: i64 = store
        .database
        .connection
        .query_row(
            "SELECT COUNT(*) FROM pending_transactions WHERE status = 'confirmed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        terminal, MAX_TERMINAL_HISTORY_PER_WALLET,
        "the oldest finished rows past the bound are dropped"
    );
    assert_eq!(
        store.get(live.request_id).unwrap().status,
        PendingStatus::AwaitingApproval,
        "a row the lifecycle still needs is never history"
    );
}

#[test]
fn only_a_missing_row_invites_the_next_queue_to_be_searched() {
    // A request id does not say which of the three signing queues owns it, so
    // the reconciler tries each in turn -- and treated every failure as "not here".
    // A row that has already been decided, an envelope that no longer parses,
    // a database that cannot be read: each sent the search onward, where the
    // rejection path could terminally close whatever the next queue held under
    // that id while the request the owner meant stayed awaiting a decision.
    let (_directory, mut store) = store();

    // Genuinely absent: the only answer that means "look elsewhere".
    let missing = store.get(uuid::Uuid::new_v4()).unwrap_err();
    assert!(
        is_unknown_request(&missing),
        "a row that is not there is not there: {missing:#}"
    );

    // Present but already decided. The request exists in *this* queue, so the
    // search must stop here even though the operation failed.
    let request = store
        .create("primary", "ethereum", &plan(), None, 1)
        .unwrap();
    store.reject(request.request_id).unwrap();
    let decided = store.reject(request.request_id).unwrap_err();
    assert!(
        !is_unknown_request(&decided),
        "an already-decided request is this queue's answer, not an absence: {decided:#}"
    );

    // Present but unreadable, which is the case that used to look identical to
    // absence and is the reason the distinction is worth a function.
    let signed = store
        .record_automatic_signed(
            "primary",
            "ethereum",
            &plan_with_value("3"),
            None,
            1,
            ORIGINAL_BYTES,
            hash_of(ORIGINAL_BYTES).as_str(),
        )
        .unwrap();
    store
        .database
        .connection
        .execute(
            "UPDATE pending_transactions SET signed_transaction_hash = ?2 WHERE request_id = ?1",
            params![signed.request_id, Blob(B256::repeat_byte(7))],
        )
        .unwrap();
    let unreadable = store.get(signed.request_id).unwrap_err();
    assert!(
        !is_unknown_request(&unreadable),
        "a row this queue holds but cannot read must not read as absent: {unreadable:#}"
    );
}
