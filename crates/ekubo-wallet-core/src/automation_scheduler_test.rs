use super::*;
use crate::pending::PendingStatus;
use alloy::primitives::Address;
use chrono::TimeZone;
use uuid::Uuid;

fn moment(minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, 12, minute, 0).unwrap()
}

/// A pending record is a large struct and these tests care about three fields
/// of it, so this builds one through its own constructor-free shape rather than
/// through the store: the functions under test read `status`, `updated_at`, and
/// `request_id` and nothing else.
fn record(status: PendingStatus, updated_at: DateTime<Utc>) -> PendingTransaction {
    PendingTransaction {
        request_id: Uuid::from_u128(7),
        wallet_instance_id: Uuid::from_u128(1),
        wallet_id: "primary".into(),
        wallet_address: Address::repeat_byte(0x11),
        network_name: "mainnet".into(),
        chain_id: "1".into(),
        execution_plan: plan(),
        plan_source: Some("automation:test".into()),
        digest: "0x00".into(),
        review_digest: None,
        policy_revision: 1,
        approval_required: false,
        requested_review: false,
        status,
        created_at: updated_at,
        updated_at,
        approved_at: None,
        rejected_at: None,
        serialized_transaction: None,
        signed_transaction_hash: None,
        broadcast_transaction_hash: None,
        block_number: None,
        block_hash: None,
        settlement_transaction_hash: None,
        finalized_at: None,
        mined_fee: None,
        cancel_serialized_transaction: None,
        cancel_transaction_hashes: Vec::new(),
        generation: 0,
    }
}

fn plan() -> crate::core::execution_plan::ExecutionPlan {
    crate::automation::synthesize_plan(
        Address::repeat_byte(0x11),
        1,
        &[crate::automation::PolledCall {
            to: Address::repeat_byte(0x22),
            value: alloy::primitives::U256::ZERO,
            data: alloy::primitives::Bytes::new(),
        }],
    )
    .expect("a one-call plan")
}

#[test]
fn a_transaction_still_within_the_timeout_is_left_alone() {
    let sent = record(PendingStatus::Broadcast, moment(0));
    assert!(stuck_reason(&sent, moment(29)).is_none());
}

#[test]
fn a_transaction_past_the_timeout_stops_the_automation_and_names_it() {
    let sent = record(PendingStatus::Broadcast, moment(0));
    let reason = stuck_reason(&sent, moment(31)).expect("past the timeout");
    assert!(reason.contains("has not mined"), "{reason}");
    assert!(
        reason.contains(&sent.request_id.to_string()),
        "the owner has to be able to find the transaction: {reason}"
    );
    // Recoverable by hand rather than silently retried, so the reason says how.
    assert!(reason.contains("relink"), "{reason}");
}

#[test]
fn the_timeout_only_ever_stops_and_never_authorizes() {
    // A clock far in the past cannot make a stuck transaction look fresh in a
    // way that signs anything: the only decision this function makes is
    // whether to disable, so a wrong clock disables early or late and never
    // permits a send.
    let sent = record(PendingStatus::Broadcast, moment(30));
    assert!(stuck_reason(&sent, moment(0)).is_none());
}

#[test]
fn the_driver_sleeps_until_the_next_fire_time() {
    let at = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
    let next = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 30).unwrap();
    assert_eq!(sleep_for(Some(next), at), Duration::from_secs(30));
}

#[test]
fn the_driver_never_spins_and_never_sleeps_past_its_ceiling() {
    // A fire time already past — an automation that has never ticked — must
    // not become a zero-length sleep and a hot loop.
    assert_eq!(sleep_for(Some(moment(0)), moment(5)), MIN_SLEEP);
    // Nothing due at all still wakes within the ceiling, so an automation
    // installed while the driver sleeps starts within a minute rather than
    // whenever the last plan happened to expire...
    assert_eq!(sleep_for(None, moment(0)), MAX_IDLE_SLEEP);
    // ...and so does a schedule whose next fire is hours away, for the same
    // reason: the plan can be made stale by an install the driver cannot see.
    let hours_away = Utc.with_ymd_and_hms(2026, 6, 1, 20, 0, 0).unwrap();
    assert_eq!(sleep_for(Some(hours_away), moment(0)), MAX_IDLE_SLEEP);
}
