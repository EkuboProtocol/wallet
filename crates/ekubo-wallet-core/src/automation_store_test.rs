use super::*;
use crate::{
    automation::MAX_CONSECUTIVE_FAILURES,
    config::WalletSource,
    core::policy::WalletPolicy,
    policy_store::{DatabaseKey, PolicyStore},
};
use chrono::TimeZone;

const CHAIN: u64 = 1;

fn wallet() -> WalletMetadata {
    WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "primary".into(),
        address: Address::repeat_byte(0x11),
        created_at: Utc::now(),
        source: WalletSource::Imported,
        exported_at: None,
    }
}

/// A store whose wallet is registered, which the automations table's foreign
/// key requires.
fn store_with(wallet: &WalletMetadata) -> (tempfile::TempDir, AutomationStore) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut policies = PolicyStore::open(&path, &DatabaseKey::new([9; 32])).unwrap();
    policies
        .initialize_policy(wallet, &WalletPolicy::require_approval_for_everything())
        .unwrap();
    (directory, AutomationStore::new(policies))
}

fn definition(name: &str, expression: &str) -> AutomationDefinition {
    AutomationDefinition::new(
        name,
        Bytes::from_static(&[0x60, 0x00, 0x60, 0x00, 0xF3]),
        Bytes::from_static(&[0x01]),
        CronSchedule::parse(expression).unwrap(),
        CHAIN,
    )
    .unwrap()
}

fn at(hour: u32, minute: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 1, hour, minute, 0).unwrap()
}

#[test]
fn an_installed_automation_round_trips() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "job", &definition("claim", "0 0 * * * *"), 1)
        .unwrap()
        .automation;

    assert_eq!(installed.state, AutomationState::Enabled);
    assert_eq!(installed.policy_revision, 1);
    assert_eq!(installed.chain_id, CHAIN);
    assert_eq!(installed.wallet_address, wallet.address);
    assert_eq!(installed.schedule.expression(), "0 0 * * * *");
    assert_eq!(installed.consecutive_failures, 0);
    assert!(installed.stopped_reason.is_none());
    assert_eq!(store.get(installed.id).unwrap().as_ref(), Some(&installed));
    assert_eq!(store.list_for_wallet(wallet.instance_id).unwrap().len(), 1);
}

#[test]
fn a_policy_revision_that_moved_unlinks_rather_than_running() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "job", &definition("claim", "0 0 * * * *"), 1)
        .unwrap()
        .automation;

    // Same revision: it runs.
    let due = store.due(wallet.instance_id, 1, at(12, 0)).unwrap();
    assert_eq!(due.ready.len(), 1);
    assert!(due.unlinked.is_empty());

    // A new policy is installed for some unrelated reason. The dormant
    // automation must not simply inherit the later revision.
    let due = store.due(wallet.instance_id, 2, at(13, 0)).unwrap();
    assert!(due.ready.is_empty());
    assert_eq!(due.unlinked.len(), 1);
    let unlinked = store.get(installed.id).unwrap().unwrap();
    assert_eq!(unlinked.state, AutomationState::AwaitingRelink);
    assert!(
        unlinked
            .stopped_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("revision 2")),
        "{:?}",
        unlinked.stopped_reason
    );

    // And it stays stopped on later ticks, including a tick that arrives back
    // at the revision it was installed under.
    let due = store.due(wallet.instance_id, 1, at(14, 0)).unwrap();
    assert!(due.ready.is_empty());
    assert!(due.unlinked.is_empty());
}

#[test]
fn relinking_rebinds_to_the_current_revision_and_starts_it_again() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "job", &definition("claim", "0 0 * * * *"), 1)
        .unwrap()
        .automation;
    store.due(wallet.instance_id, 4, at(12, 0)).unwrap();

    let relinked = store.relink(installed.id, 4).unwrap();
    assert_eq!(relinked.state, AutomationState::Enabled);
    assert_eq!(relinked.policy_revision, 4);
    assert!(relinked.stopped_reason.is_none());

    let due = store.due(wallet.instance_id, 4, at(13, 0)).unwrap();
    assert_eq!(due.ready.len(), 1);
}

#[test]
fn an_automation_that_has_never_ticked_is_due_immediately() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    store
        .install(&wallet, "job", &definition("hourly", "0 0 * * * *"), 1)
        .unwrap();
    // 12:01, so the next scheduled hour has not arrived. Waiting for it would
    // leave a just-installed automation idle with nothing on screen to say why.
    let due = store.due(wallet.instance_id, 1, at(12, 1)).unwrap();
    assert_eq!(due.ready.len(), 1);
}

#[test]
fn a_schedule_that_has_not_come_round_yet_is_not_due() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "job", &definition("hourly", "0 0 * * * *"), 1)
        .unwrap()
        .automation;
    store
        .record_tick(installed.id, "no calls", at(12, 0))
        .unwrap();

    assert!(
        store
            .due(wallet.instance_id, 1, at(12, 59))
            .unwrap()
            .ready
            .is_empty()
    );
    assert_eq!(
        store
            .due(wallet.instance_id, 1, at(13, 0))
            .unwrap()
            .ready
            .len(),
        1
    );
}

#[test]
fn a_disabled_automation_never_becomes_due() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "job", &definition("claim", "0 0 * * * *"), 1)
        .unwrap()
        .automation;
    let disabled = store
        .disable(installed.id, "the batch reverted on chain")
        .unwrap();
    assert_eq!(disabled.state, AutomationState::Disabled);
    assert_eq!(
        disabled.stopped_reason.as_deref(),
        Some("the batch reverted on chain")
    );
    assert!(
        store
            .due(wallet.instance_id, 1, at(23, 0))
            .unwrap()
            .ready
            .is_empty()
    );
}

#[test]
fn consecutive_failures_disable_and_a_good_tick_forgets_them() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "job", &definition("claim", "0 0 * * * *"), 1)
        .unwrap()
        .automation;

    for count in 1..MAX_CONSECUTIVE_FAILURES {
        let current = store
            .record_failure(installed.id, "endpoint refused eth_simulateV1", at(12, 0))
            .unwrap();
        assert_eq!(current.consecutive_failures, count);
        assert_eq!(current.state, AutomationState::Enabled);
    }
    let stopped = store
        .record_failure(installed.id, "endpoint refused eth_simulateV1", at(12, 0))
        .unwrap();
    assert_eq!(stopped.state, AutomationState::Disabled);
    assert!(
        stopped
            .stopped_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("consecutive")),
        "{:?}",
        stopped.stopped_reason
    );

    // A run that reaches the chain clears the count: an automation healthy for
    // a month must not be one outage away from its tenth lifetime failure.
    store.relink(installed.id, 1).unwrap();
    store
        .record_failure(installed.id, "endpoint refused eth_simulateV1", at(12, 0))
        .unwrap();
    store
        .record_tick(installed.id, "no calls", at(13, 0))
        .unwrap();
    assert_eq!(
        store
            .get(installed.id)
            .unwrap()
            .unwrap()
            .consecutive_failures,
        0
    );
}

#[test]
fn a_skipped_tick_consumes_the_schedule_without_forgiving_failures() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "job", &definition("claim", "0 0 * * * *"), 1)
        .unwrap()
        .automation;
    store
        .record_failure(installed.id, "endpoint refused eth_simulateV1", at(11, 0))
        .unwrap();

    store
        .record_skip(
            installed.id,
            "another send holds the signing slot",
            at(12, 0),
        )
        .unwrap();

    // The tick is consumed, so the schedule moves on rather than retrying
    // immediately...
    assert!(
        store
            .due(wallet.instance_id, 1, at(12, 30))
            .unwrap()
            .ready
            .is_empty()
    );
    // ...but a busy slot said nothing about whether the automation works, so
    // it cannot be what rescues one that is nine failures deep.
    assert_eq!(
        store
            .get(installed.id)
            .unwrap()
            .unwrap()
            .consecutive_failures,
        1
    );
}

#[test]
fn the_per_wallet_chain_limit_holds() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    for index in 0..MAX_AUTOMATIONS_PER_WALLET_CHAIN {
        store
            .install(
                &wallet,
                &format!("job-{index}"),
                &definition(&format!("job {index}"), "0 0 * * * *"),
                1,
            )
            .unwrap();
    }
    let error = store
        .install(
            &wallet,
            "overflow",
            &definition("one too many", "0 0 * * * *"),
            1,
        )
        .expect_err("the limit holds");
    assert!(format!("{error:#}").contains("the limit is"), "{error:#}");
}

#[test]
fn removing_an_automation_reports_whether_there_was_one() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "job", &definition("claim", "0 0 * * * *"), 1)
        .unwrap()
        .automation;
    assert!(store.remove(installed.id).unwrap());
    assert!(!store.remove(installed.id).unwrap());
    assert!(store.get(installed.id).unwrap().is_none());
}

#[test]
fn an_unknown_automation_is_not_silently_updated() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let absent = Uuid::new_v4();
    assert!(store.record_tick(absent, "no calls", at(12, 0)).is_err());
    assert!(store.disable(absent, "gone").is_err());
    assert!(store.relink(absent, 1).is_err());
    assert!(store.get(absent).unwrap().is_none());
}

#[test]
fn installing_under_the_same_key_twice_replaces_rather_than_duplicates() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let first = store
        .install(&wallet, "rebalance", &definition("v1", "0 0 * * * *"), 1)
        .unwrap();
    assert!(first.replaced.is_none());

    // The retry an agent makes after a tool call times out. One automation,
    // not two contending for the same signing slot.
    let again = store
        .install(&wallet, "rebalance", &definition("v1", "0 0 * * * *"), 1)
        .unwrap();
    assert_eq!(again.automation.id, first.automation.id);
    assert!(again.replaced.is_some());
    assert_eq!(store.list_for_wallet(wallet.instance_id).unwrap().len(), 1);

    // A different key is a different automation.
    store
        .install(&wallet, "claim", &definition("v1", "0 0 * * * *"), 1)
        .unwrap();
    assert_eq!(store.list_for_wallet(wallet.instance_id).unwrap().len(), 2);
}

#[test]
fn replacing_bytecode_resets_the_history_that_described_the_old_bytecode() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "rebalance", &definition("v1", "0 0 * * * *"), 1)
        .unwrap()
        .automation;
    store
        .record_failure(installed.id, "reverted", at(12, 0))
        .unwrap();
    let stopped = store.disable(installed.id, "gave up").unwrap();
    assert_eq!(stopped.state, AutomationState::Disabled);

    let replaced = store
        .install(&wallet, "rebalance", &definition("v2", "*/12 * * * * *"), 3)
        .unwrap()
        .automation;

    // New bytecode, so the counters describing the old bytecode's failures
    // would be a lie, and the automation runs again under the revision the
    // caller named.
    assert_eq!(replaced.id, installed.id);
    assert_eq!(replaced.state, AutomationState::Enabled);
    assert_eq!(replaced.consecutive_failures, 0);
    assert!(replaced.stopped_reason.is_none());
    assert!(replaced.last_tick_at.is_none());
    assert!(replaced.last_request_id.is_none());
    assert_eq!(replaced.policy_revision, 3);
    assert_eq!(replaced.schedule.expression(), "*/12 * * * * *");
}

#[test]
fn a_key_is_scoped_to_its_wallet() {
    let first = wallet();
    let (_directory, mut store) = store_with(&first);
    store
        .install(&first, "claim", &definition("v1", "0 0 * * * *"), 1)
        .unwrap();
    assert!(store.by_key(first.instance_id, "claim").unwrap().is_some());
    // Another wallet's identical key names nothing here: the key is the
    // caller's vocabulary, and two wallets automated by one agent will reuse
    // the obvious names.
    assert!(store.by_key(Uuid::new_v4(), "claim").unwrap().is_none());
}

#[test]
fn a_key_with_a_control_character_is_refused() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let error = store
        .install(
            &wallet,
            "claim\u{202E}",
            &definition("v1", "0 0 * * * *"),
            1,
        )
        .expect_err("a bidi override in a key is refused");
    assert!(format!("{error:#}").contains("bidirectional"), "{error:#}");
}

#[test]
fn every_tick_is_recorded_including_the_quiet_ones() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "claim", &definition("v1", "0 0 * * * *"), 1)
        .unwrap()
        .automation;
    let sent = Uuid::new_v4();

    store
        .record_run(
            installed.id,
            RunOutcome::Idle,
            "nothing to do",
            None,
            0,
            at(12, 0),
        )
        .unwrap();
    store
        .record_run(
            installed.id,
            RunOutcome::Sent,
            "sent 2 call(s)",
            Some(sent),
            2,
            at(13, 0),
        )
        .unwrap();
    store
        .record_run(
            installed.id,
            RunOutcome::Skipped,
            "the slot was held",
            None,
            0,
            at(14, 0),
        )
        .unwrap();

    let runs = store.runs(installed.id, 10).unwrap();
    assert_eq!(runs.len(), 3, "a quiet run is still a run");
    // Newest first: the screen answers "what just happened" before "what has
    // it been doing".
    assert_eq!(runs[0].outcome, RunOutcome::Skipped);
    assert_eq!(runs[1].outcome, RunOutcome::Sent);
    assert_eq!(runs[2].outcome, RunOutcome::Idle);
    // And the run that produced a transaction names it, which is the whole
    // point of keeping the log.
    assert_eq!(runs[1].request_id, Some(sent));
    assert_eq!(runs[1].calls, 2);
    assert!(runs[0].request_id.is_none());
}

#[test]
fn the_run_log_is_bounded_and_drops_the_oldest_first() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "chatty", &definition("v1", "* * * * * *"), 1)
        .unwrap()
        .automation;
    // One over the cap, each a minute apart so the ordering is unambiguous.
    for index in 0..=MAX_RUNS_PER_AUTOMATION {
        let minute = u32::try_from(index % 60).unwrap();
        let hour = u32::try_from(index / 60).unwrap();
        store
            .record_run(
                installed.id,
                RunOutcome::Idle,
                &format!("run {index}"),
                None,
                0,
                Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap()
                    + chrono::TimeDelta::hours(i64::from(hour))
                    + chrono::TimeDelta::minutes(i64::from(minute)),
            )
            .unwrap();
    }
    let runs = store
        .runs(installed.id, MAX_RUNS_PER_AUTOMATION * 2)
        .unwrap();
    assert_eq!(runs.len(), MAX_RUNS_PER_AUTOMATION);
    // A per-second schedule would otherwise grow a log nobody reads, and the
    // rows worth keeping are the recent ones.
    assert_eq!(runs[0].detail, format!("run {MAX_RUNS_PER_AUTOMATION}"));
    assert!(!runs.iter().any(|run| run.detail == "run 0"));
}

#[test]
fn removing_an_automation_takes_its_runs_with_it() {
    let wallet = wallet();
    let (_directory, mut store) = store_with(&wallet);
    let installed = store
        .install(&wallet, "claim", &definition("v1", "0 0 * * * *"), 1)
        .unwrap()
        .automation;
    store
        .record_run(
            installed.id,
            RunOutcome::Idle,
            "nothing",
            None,
            0,
            at(12, 0),
        )
        .unwrap();
    assert!(store.remove(installed.id).unwrap());
    assert!(store.runs(installed.id, 10).unwrap().is_empty());
}
