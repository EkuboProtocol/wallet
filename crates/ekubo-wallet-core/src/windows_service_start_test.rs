use super::*;
use std::{cell::Cell, collections::VecDeque};

struct Scm {
    states: VecDeque<Result<State>>,
    starts: usize,
    fail_start: bool,
}

impl Scm {
    fn new(states: impl IntoIterator<Item = State>) -> Self {
        Self {
            states: states.into_iter().map(Ok).collect(),
            starts: 0,
            fail_start: false,
        }
    }
}

impl Backend for Scm {
    fn state(&mut self) -> Result<State> {
        self.states.pop_front().expect("unexpected SCM query")
    }
    fn start(&mut self) -> Result<()> {
        self.starts += 1;
        ensure!(!self.fail_start, "ambiguous start failure");
        Ok(())
    }
}

#[test]
fn stopped_service_is_started_once_and_waits_for_running() {
    let mut scm = Scm::new([
        State::Stopped,
        State::Starting,
        State::Starting,
        State::Running,
    ]);
    let mut waits = 0;
    activate(&mut scm, || true, || waits += 1).unwrap();
    assert_eq!(scm.starts, 1);
    assert_eq!(waits, 3);
    assert!(scm.states.is_empty());
}

#[test]
fn running_services_and_concurrent_starts_need_no_start_request() {
    for states in [vec![State::Running], vec![State::Starting, State::Running]] {
        let mut scm = Scm::new(states);
        activate(&mut scm, || true, || {}).unwrap();
        assert_eq!(scm.starts, 0);
    }
}

#[test]
fn failed_starts_and_services_that_stop_are_not_restarted() {
    let mut scm = Scm::new([State::Stopped]);
    scm.fail_start = true;
    assert!(activate(&mut scm, || true, || panic!("must not retry")).is_err());
    assert_eq!(scm.starts, 1);
    for initial in [State::Stopped, State::Starting] {
        let mut scm = Scm::new([initial, State::Stopped]);
        assert!(activate(&mut scm, || true, || {}).is_err());
        assert_eq!(scm.starts, usize::from(matches!(initial, State::Stopped)));
        assert!(scm.states.is_empty());
    }
}

#[test]
fn unavailable_or_unreadable_service_is_not_started() {
    let mut scm = Scm::new([State::Unavailable]);
    assert!(activate(&mut scm, || true, || panic!("must not wait")).is_err());
    assert_eq!(scm.starts, 0);
    scm.states.push_back(Err(anyhow::anyhow!("access denied")));
    assert!(activate(&mut scm, || true, || panic!("must not wait")).is_err());
    assert_eq!(scm.starts, 0);
}

#[test]
fn cancellation_before_query_or_after_a_blocking_query_prevents_start() {
    let mut scm = Scm::new([State::Stopped]);
    assert!(activate(&mut scm, || false, || panic!("must not wait")).is_err());
    assert_eq!(scm.states.len(), 1);
    let checks = Cell::new(0);
    assert!(
        activate(
            &mut scm,
            || {
                checks.set(checks.get() + 1);
                checks.get() == 1
            },
            || panic!("must not wait")
        )
        .is_err()
    );
    assert_eq!(scm.starts, 0);
}

#[test]
fn expired_wait_does_not_issue_another_query_or_start() {
    let mut scm = Scm::new([State::Stopped, State::Starting]);
    let active = Cell::new(true);
    assert!(activate(&mut scm, || active.get(), || active.set(false)).is_err());
    assert_eq!(scm.starts, 1);
    assert_eq!(scm.states.len(), 1);
}
