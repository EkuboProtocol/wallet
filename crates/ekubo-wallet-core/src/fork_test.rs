//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::core::execution_plan::{
    DecimalU256, ExecutionStep, ExecutionStepKind, PlannedTransaction,
};
use alloy::primitives::Bytes;

fn parent() -> ForkParent {
    ForkParent {
        number: 100,
        hash: B256::repeat_byte(0xab),
        gas_limit: 30_000_000,
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

fn store_with_fork() -> (ForkStore, ForkSession, DateTime<Utc>) {
    let now = Utc::now();
    let mut store = ForkStore::new();
    let session = store
        .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
        .unwrap();
    (store, session, now)
}

#[test]
fn a_new_fork_is_empty_and_pinned() {
    let (_, session, now) = store_with_fork();
    assert!(session.plans.is_empty());
    assert_eq!(session.parent.number, 100);
    assert_eq!(
        session.expires_at,
        now + TimeDelta::seconds(FORK_TTL_SECONDS)
    );
    let preface = session.preface();
    assert_eq!(preface.applied_plans(), 0);
    // With nothing applied, the first simulated block is the one that
    // directly follows the pinned parent, exactly like a one-shot
    // simulation.
    assert_eq!(preface.simulated_block(), 101);
    assert!(!preface.requires_calibur());
}

#[test]
fn each_applied_plan_advances_the_simulated_block_by_one() {
    let (mut store, session, now) = store_with_fork();
    let session = store.append(session.fork_id, plan(1), 0, now).unwrap();
    assert_eq!(session.preface().simulated_block(), 102);
    let session = store.append(session.fork_id, plan(2), 1, now).unwrap();
    assert_eq!(session.preface().simulated_block(), 103);
    assert_eq!(session.context(103).applied_plans, 2);
    // A multi-call plan replays through Calibur, so replay needs the
    // delegation designator override.
    assert!(session.preface().requires_calibur());
}

#[test]
fn a_fork_is_bounded_by_retained_plan_bytes_as_well_as_plan_count() {
    let (mut store, session, now) = store_with_fork();
    let mut bulky = plan(1);
    // Well under MAX_PLANS_PER_FORK, well over the byte budget: the count
    // says nothing about how much calldata each plan carries, and a plan
    // this size validates, simulates, and is therefore kept.
    bulky.ordered_steps[0].transaction.data = vec![0_u8; MAX_FORK_PLAN_BYTES].into();
    let error = store
        .append(session.fork_id, bulky, 0, now)
        .expect_err("an oversized plan must not be retained");
    assert!(error.to_string().contains("bytes of applied plans"));

    // The ordinary case is untouched: a real plan is kilobytes.
    assert_eq!(
        store
            .append(session.fork_id, plan(1), 0, now)
            .unwrap()
            .plans
            .len(),
        1
    );
}

#[test]
fn capacity_is_refusable_before_a_parent_block_is_pinned() {
    let now = Utc::now();
    let mut store = ForkStore::new();
    for _ in 0..MAX_FORKS_PER_WALLET {
        store.ensure_capacity("wallet-a", now).unwrap();
        store
            .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
            .unwrap();
    }
    // Same answer `create` would give, reached without the RPC round trip
    // that pinning a parent block costs.
    let error = store
        .ensure_capacity("wallet-a", now)
        .expect_err("a wallet at its fork limit must be refused up front");
    assert!(error.to_string().contains("already holds"));
    assert!(
        store
            .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
            .is_err()
    );
    // Another wallet is unaffected: this is a per-wallet limit.
    store.ensure_capacity("wallet-b", now).unwrap();
}

#[test]
fn appending_rejects_a_concurrently_changed_fork() {
    let (mut store, session, now) = store_with_fork();
    store.append(session.fork_id, plan(1), 0, now).unwrap();
    let error = store
        .append(session.fork_id, plan(1), 0, now)
        .expect_err("a stale applied count must not append");
    assert!(error.to_string().contains("changed while this plan"));
}

#[test]
fn a_fork_stops_accepting_plans_at_its_cap() {
    let (mut store, session, now) = store_with_fork();
    for index in 0..MAX_PLANS_PER_FORK {
        let current = store.append(session.fork_id, plan(1), index, now).unwrap();
        assert_eq!(current.has_capacity(), index + 1 < MAX_PLANS_PER_FORK);
    }
    let error = store
        .append(session.fork_id, plan(1), MAX_PLANS_PER_FORK, now)
        .expect_err("the plan cap must hold");
    assert!(error.to_string().contains("maximum"));
}

#[test]
fn forks_are_capped_per_wallet_and_globally() {
    let now = Utc::now();
    let mut store = ForkStore::new();
    for _ in 0..MAX_FORKS_PER_WALLET {
        store
            .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
            .unwrap();
    }
    let error = store
        .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
        .expect_err("the per-wallet cap must hold");
    assert!(error.to_string().contains("already holds"));
    // A different wallet is unaffected until the global cap.
    store
        .create("wallet-b", Address::repeat_byte(0x22), 1, parent(), now)
        .unwrap();
    assert_eq!(store.len(), MAX_FORKS_PER_WALLET + 1);
}

#[test]
fn an_expired_fork_is_indistinguishable_from_one_that_never_existed() {
    let (mut store, session, now) = store_with_fork();
    let later = now + TimeDelta::seconds(FORK_TTL_SECONDS + 1);
    let error = store
        .session(session.fork_id, later)
        .expect_err("an expired fork must not resolve");
    assert!(error.to_string().contains("unknown or expired"));
    assert!(store.is_empty());
    let unknown = store
        .session(Uuid::new_v4(), now)
        .expect_err("an unknown fork must not resolve");
    assert!(unknown.to_string().contains("unknown or expired"));
}

#[test]
fn expiry_frees_capacity_for_the_same_wallet() {
    let now = Utc::now();
    let mut store = ForkStore::new();
    for _ in 0..MAX_FORKS_PER_WALLET {
        store
            .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
            .unwrap();
    }
    let later = now + TimeDelta::seconds(FORK_TTL_SECONDS + 1);
    store
        .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), later)
        .expect("expired forks are swept before the cap is applied");
    assert_eq!(store.len(), 1);
}

#[test]
fn discarding_is_idempotent() {
    let (mut store, session, _) = store_with_fork();
    assert!(store.discard(session.fork_id));
    assert!(!store.discard(session.fork_id));
}

#[test]
fn replay_blocks_carry_one_exact_call_each() {
    let (mut store, session, now) = store_with_fork();
    store.append(session.fork_id, plan(1), 0, now).unwrap();
    let session = store.append(session.fork_id, plan(2), 1, now).unwrap();
    let preface = session.preface();
    let blocks = replay_blocks(&preface, 1_000_000);
    assert_eq!(blocks.len(), 2);
    for block in &blocks {
        assert_eq!(block.calls.len(), 1);
    }
    // The single-call plan runs directly at its own target; the two-call
    // plan runs through the wallet itself as a Calibur batch.
    assert_eq!(blocks[0].calls[0].to, Some(Address::repeat_byte(2).into()));
    assert_eq!(
        blocks[1].calls[0].to,
        Some(Address::repeat_byte(0x11).into())
    );
}

#[test]
fn fork_context_always_marks_output_hypothetical() {
    let (_, session, _) = store_with_fork();
    let context = session.context(101);
    assert!(context.hypothetical);
    assert_eq!(context.parent_block_number, "100");
    assert_eq!(context.simulated_block_number, "101");
    assert_eq!(
        context.max_plans,
        u32::try_from(MAX_PLANS_PER_FORK).unwrap()
    );
    assert!(context.note.contains("nothing observed through a fork"));
}
