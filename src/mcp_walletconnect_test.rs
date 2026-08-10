//! Tests for [`super`].

use super::*;
use crate::walletconnect::protocol::AppMetadata;

/// The budget is the protocol's, not a number somebody liked.
///
/// A `wc_sessionRequest` response is worth nothing to the dapp after
/// `ttl::SESSION_REQUEST_RESPONSE`, so a wait longer than that answers nobody
/// while leaving a row an owner could approve afterwards. That row is one
/// `wallet_send_execution_plan` away from broadcasting a transaction the dapp
/// was already told had failed.
#[test]
fn the_request_budget_ends_before_the_dapp_stops_listening() {
    let ttl = crate::walletconnect::protocol::ttl::SESSION_REQUEST_RESPONSE;
    assert!(
        REQUEST_BUDGET.as_secs() < ttl,
        "a {}s budget outlasts the {ttl}s response TTL",
        REQUEST_BUDGET.as_secs()
    );
    // And long enough to be worth offering: a person has to notice the agent's
    // message, open a terminal, and read a document.
    assert!(REQUEST_BUDGET.as_secs() >= 120);
}

/// The tools say the number the code enforces.
///
/// Both are in a tool description an agent reads once and then plans around:
/// a description promising a longer wait than the code gives has the agent
/// telling the user they have time they do not, and one promising more
/// sessions than the registry holds has it opening one that fails.
#[test]
fn the_tool_descriptions_state_the_limits_this_module_enforces() {
    let mcp = include_str!("mcp.rs");
    let wait = format!("within {} seconds", REQUEST_BUDGET.as_secs());
    assert!(
        mcp.contains(&wait),
        "no tool description states the {wait} approval bound"
    );
    let sessions = format!("At most {MAX_SESSIONS} sessions");
    assert!(
        mcp.contains(&sessions),
        "no tool description states `{sessions}`"
    );
}

/// Giving up on a wait must make the record terminal in the same step.
///
/// Pinned in the source because the alternative costs a live relay, a settled
/// session, and a dapp that will hold a request open for four minutes. What is
/// checkable is that every one of the three waits hands `await_decision` a
/// `give_up` that rejects rather than merely re-reads: a `give_up` that only
/// read would answer the dapp "not approved" and leave the row approvable,
/// which is the double-send this whole design exists to prevent.
#[test]
fn every_wait_that_gives_up_rejects_the_record_it_was_waiting_on() {
    let source = include_str!("mcp_walletconnect.rs");
    for resolve in ["resolve_queued", "resolve_message", "resolve_typed_data"] {
        let body = source
            .split_once(&format!("async fn {resolve}("))
            .unwrap_or_else(|| panic!("{resolve} is gone"))
            .1;
        let end = body.find("\n    async fn ").unwrap_or(body.len());
        let body = &body[..end];
        let give_up = body
            .find("let give_up =")
            .unwrap_or_else(|| panic!("{resolve} has no give_up"));
        let rejects = body[give_up..]
            .find("store.reject(request_id)")
            .unwrap_or_else(|| panic!("{resolve} gives up without rejecting the record"));
        // And it falls back to reading rather than failing, because a reject
        // that loses the race to an owner's approval is the case where the
        // signature exists and should be used.
        assert!(
            body[give_up + rejects..].contains("store.get(request_id)"),
            "{resolve} treats a lost reject race as an error instead of using the approval"
        );
    }
}

/// A closed session must not be waited out.
///
/// Without this the disconnect tool would take as long as an approval nobody
/// is going to give -- up to `REQUEST_BUDGET` per request in flight -- and the
/// agent would be told the session was still up the whole time.
#[test]
fn closing_a_session_cuts_short_a_wait_for_the_owner() {
    let source = include_str!("mcp_walletconnect.rs");
    let body = source
        .split_once("async fn await_decision<R>(")
        .expect("await_decision is declared")
        .1;
    let end = body.find("\n#[async_trait").unwrap_or(body.len());
    assert!(
        body[..end].contains("self.quit.load(Ordering::Relaxed)"),
        "a wait that ignores the quit flag makes a disconnect wait for an approval"
    );
}

/// The relay is never a caller's choice.
///
/// It sees which topics talk to which and when, and the connection's
/// authentication token travels in its URL. `--relay-url` is the owner's flag
/// on their own command line; a tool parameter would let an untrusted caller
/// pick who observes the session.
#[test]
fn no_caller_can_name_the_relay() {
    let source = include_str!("mcp_walletconnect.rs");
    assert!(
        source.contains("url::Url::parse(DEFAULT_RELAY_URL)"),
        "the relay must be the compiled default"
    );
    assert_eq!(
        source.matches("relay_url").count(),
        source.matches("let relay_url =").count() + source.matches("&relay_url").count(),
        "relay_url appears somewhere other than the one local binding and its use"
    );
}

#[test]
fn a_dapp_summary_carries_the_cautions_the_review_would_have_drawn() {
    // The exact shape the connection review exists to catch: a name that
    // spells one domain served from another. With no review to draw it, the
    // caution has to reach the agent.
    let impostor = AppMetadata {
        name: "app.uniswap.org".to_owned(),
        url: "https://claim-rewards.example".to_owned(),
        ..AppMetadata::default()
    };
    let summary = DappSummary::of(&impostor);
    assert_eq!(summary.host.as_deref(), Some("claim-rewards.example"));
    assert_eq!(summary.name.as_deref(), Some("app.uniswap.org"));
    assert!(
        summary
            .cautions
            .iter()
            .any(|caution| caution.contains("claim-rewards.example")),
        "{:?}",
        summary.cautions
    );
}

#[test]
fn a_plain_dapp_produces_no_cautions_and_a_host_to_compare() {
    let summary = DappSummary::of(&AppMetadata {
        name: "Example".to_owned(),
        url: "https://example.com".to_owned(),
        ..AppMetadata::default()
    });
    assert_eq!(summary.host.as_deref(), Some("example.com"));
    assert!(summary.cautions.is_empty(), "{:?}", summary.cautions);
}

#[test]
fn the_activity_log_is_bounded_and_sanitized() {
    let mut shared = SessionShared::default();
    for index in 0..MAX_ACTIVITY * 2 {
        shared.note(&format!("line {index}"));
    }
    assert_eq!(shared.activity.len(), MAX_ACTIVITY);
    // Oldest first, and the oldest surviving line is the one that fits.
    assert_eq!(
        shared.activity.front().map(|entry| entry.message.as_str()),
        Some("line 64")
    );

    // A dapp names itself, and every name it chooses ends up here.
    shared.note("Line\u{202e}break");
    let last = shared.activity.back().expect("a line was pushed");
    assert!(
        !last.message.contains('\u{202e}'),
        "an unsanitized override reached the log: {last:?}"
    );
}

#[test]
fn a_session_that_has_ended_stops_occupying_a_slot() {
    let mut registry = SessionRegistry::new();
    let shared = Arc::new(Mutex::new(SessionShared::default()));
    let id = Uuid::from_u128(1);
    registry.sessions.insert(
        id,
        LiveSession {
            wallet_id: "primary".to_owned(),
            opened_at: Utc::now(),
            shared: Arc::clone(&shared),
            quit: Arc::new(AtomicBool::new(false)),
        },
    );
    assert_eq!(registry.list().len(), 1);

    shared.lock().expect("fresh lock").lifecycle =
        Some(SessionLifecycle::Closed("done".to_owned()));
    assert!(
        registry.list().is_empty(),
        "a finished session still holds a slot"
    );
}

/// A session that has not settled yet reads as pairing rather than as nothing,
/// so the connect tool can return a report for a dapp that never proposed.
#[test]
fn an_unsettled_session_reports_as_pairing() {
    let shared = SessionShared::default();
    assert_eq!(shared.lifecycle(), SessionLifecycle::Pairing);
    assert!(!shared.lifecycle().is_over());
    assert!(SessionLifecycle::Closed(String::new()).is_over());
    assert!(SessionLifecycle::Failed(String::new()).is_over());
}

/// The first word about why a session ended is the true one.
///
/// A dapp that sent `wc_sessionDelete` said why, and the loop then returns
/// `Ok` — so a `finish` that overwrote would replace "the dapp closed the
/// session (6000): user disconnected" with "the session ended".
#[test]
fn the_reason_a_session_ended_is_not_overwritten_by_the_generic_one() {
    let shared = Mutex::new(SessionShared::default());
    finish(
        &shared,
        SessionLifecycle::Closed("the dapp said goodbye".to_owned()),
    );
    finish(
        &shared,
        SessionLifecycle::Closed("The session ended.".to_owned()),
    );
    assert_eq!(
        shared.lock().expect("fresh lock").lifecycle(),
        SessionLifecycle::Closed("the dapp said goodbye".to_owned())
    );
}

mod agent_gate_tests {
    //! A dapp's plan reaches the policy only through the agent.

    use super::*;

    fn shared_with_proposal(proposal_id: Uuid) -> Arc<Mutex<SessionShared>> {
        let shared = Arc::new(Mutex::new(SessionShared::default()));
        shared.lock().expect("fresh lock").proposed = Some(ProposedTransaction {
            session_id: Uuid::from_u128(7),
            proposal_id,
            method: "eth_sendTransaction".to_owned(),
            chain_id: "1".to_owned(),
            dapp: DappSummary::of(&AppMetadata::default()),
            execution_plan: serde_json::from_value(serde_json::json!({
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
                        "value": "0"
                    }
                }]
            }))
            .expect("the fixture plan parses"),
            simulation: crate::simulation::SimulationResult {
                simulation_id: None,
                digest: "0x00".to_owned(),
                allowed: true,
                policy_outcome: crate::core::policy::PolicyOutcome::Allowed,
                policy_findings: Vec::new(),
                policy_revision: 1,
                execution_mode: crate::simulation::ExecutionMode::Direct,
                implementation: None,
                will_authorize_delegation: false,
                replaces_delegated_implementation: None,
                simulation: crate::simulation::SimulationExecution {
                    success: true,
                    gas_used: None,
                    block_gas_limit: None,
                    output: None,
                    error: None,
                    failure: None,
                },
                token_spends: std::collections::BTreeMap::new(),
                balance_changes: None,
                block_number: "1".to_owned(),
                fork: None,
            },
            proposed_at: Utc::now(),
            expires_at: Utc::now(),
            instruction: String::new(),
        });
        shared
    }

    fn registry_holding(shared: &Arc<Mutex<SessionShared>>, id: Uuid) -> Mutex<SessionRegistry> {
        let mut registry = SessionRegistry::new();
        registry.sessions.insert(
            id,
            LiveSession {
                wallet_id: "primary".to_owned(),
                opened_at: Utc::now(),
                shared: Arc::clone(shared),
                quit: Arc::new(AtomicBool::new(false)),
            },
        );
        Mutex::new(registry)
    }

    /// The decision has to be about the plan that was read.
    ///
    /// A stale id applied to whatever happens to be waiting now is the exact
    /// substitution this gate exists to prevent: the agent judged one plan and
    /// one simulation, and a dapp that withdraws and re-proposes between the
    /// read and the answer would otherwise collect a verdict meant for
    /// something else.
    #[test]
    fn a_decision_names_the_proposal_it_was_made_about() {
        let session = Uuid::from_u128(7);
        let waiting = Uuid::from_u128(1);
        let shared = shared_with_proposal(waiting);
        let registry = registry_holding(&shared, session);

        let stale = decide_proposal(&registry, session, Uuid::from_u128(2), true, None)
            .expect_err("a stale id is refused");
        assert!(format!("{stale:#}").contains("is waiting on"), "{stale:#}");
        assert!(
            shared.lock().expect("fresh lock").decision.is_none(),
            "a refused decision must not be recorded"
        );

        decide_proposal(&registry, session, waiting, true, None).expect("the waiting id is taken");
        let recorded = shared
            .lock()
            .expect("fresh lock")
            .decision
            .clone()
            .expect("the decision was recorded");
        assert_eq!(recorded.proposal_id, waiting);
        assert!(recorded.approve);
    }

    /// And when nothing is waiting, the error says so rather than reading as a
    /// refusal the agent could take for a decision it made.
    #[test]
    fn deciding_with_nothing_waiting_says_so() {
        let session = Uuid::from_u128(7);
        let shared = Arc::new(Mutex::new(SessionShared::default()));
        let registry = registry_holding(&shared, session);
        let error = decide_proposal(&registry, session, Uuid::from_u128(1), false, None)
            .expect_err("nothing is waiting");
        assert!(
            format!("{error:#}").contains("already been decided"),
            "{error:#}"
        );
    }

    /// A session that has ended will never propose anything, so the wait says
    /// so at once rather than spending the caller's timeout finding out.
    #[tokio::test]
    async fn waiting_on_a_finished_session_returns_immediately() {
        let session = Uuid::from_u128(7);
        let shared = Arc::new(Mutex::new(SessionShared::default()));
        shared.lock().expect("fresh lock").lifecycle =
            Some(SessionLifecycle::Closed("done".to_owned()));
        let registry = registry_holding(&shared, session);
        // The registry prunes finished sessions, so this is also the shape an
        // agent sees when it waits after a disconnect: an error naming the
        // session, not a hang.
        let outcome = next_proposal(&registry, session, Duration::from_secs(30)).await;
        assert!(
            outcome.is_err(),
            "a pruned session is not silently waited on"
        );
    }

    /// Every path out of the gate that is not an explicit approval refuses.
    ///
    /// Pinned in the source because standing the alternatives up needs a relay
    /// and a dapp: what is checkable is that the loop's three exits are a
    /// decision, the quit flag, and the deadline, and that only the first can
    /// produce `Proceed`.
    #[test]
    fn the_agent_gate_is_fail_closed_on_every_other_path() {
        // The decision loop alone. The cleanup below it also names `Proceed`,
        // in the line it writes to the session log, and that is not an exit.
        let source = include_str!("mcp_walletconnect.rs");
        let body = source
            .split_once("let verdict = loop {")
            .expect("approve_plan's decision loop is declared")
            .1;
        let end = body.find("\n        };").expect("the loop ends");
        let body = &body[..end];
        assert_eq!(
            body.matches("PlanVerdict::Proceed").count(),
            1,
            "more than one path through the gate proceeds"
        );
        let proceeds = body
            .find("PlanVerdict::Proceed")
            .expect("one path proceeds");
        let decided = body
            .find("if decision.approve")
            .expect("the gate reads an explicit decision");
        assert!(
            decided < proceeds,
            "the only path that proceeds must be an explicit approval"
        );
        for exit in ["self.quit.load(Ordering::Relaxed)", ">= deadline"] {
            assert!(body.contains(exit), "the gate has no {exit} exit");
        }
    }

    /// The gate runs before the policy, not after it.
    ///
    /// After would be worthless: `execute_automatic` signs a plan the policy
    /// covers, so a gate downstream of it would be reviewing something already
    /// broadcast.
    #[test]
    fn the_gate_runs_before_the_policy_sees_the_plan() {
        let source = include_str!("dapp.rs");
        let body = source
            .split_once("async fn execute_plan(")
            .expect("execute_plan is declared")
            .1;
        let gate = body
            .find("self.surface.approve_plan(")
            .expect("execute_plan gates the plan");
        let policy = body
            .find("orchestrator::execute_automatic(")
            .expect("it then puts it to the policy");
        assert!(
            gate < policy,
            "the surface must see the plan before execute_automatic can sign it"
        );
    }
}
