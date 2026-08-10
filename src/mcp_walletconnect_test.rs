//! Tests for [`super`].

use super::*;
use crate::walletconnect::protocol::AppMetadata;

/// The bound is the protocol's, not a number somebody liked.
///
/// A `wc_sessionRequest` response is worth nothing to the dapp after
/// `ttl::SESSION_REQUEST_RESPONSE`, so a wait longer than that answers nobody
/// while leaving a row an owner could approve afterwards. That row is one
/// `wallet_send_execution_plan` away from broadcasting a transaction the dapp
/// was already told had failed.
#[test]
fn the_approval_wait_ends_before_the_dapp_stops_listening() {
    let ttl = crate::walletconnect::protocol::ttl::SESSION_REQUEST_RESPONSE;
    assert!(
        APPROVAL_WAIT.as_secs() < ttl,
        "a {}s wait outlasts the {ttl}s response TTL",
        APPROVAL_WAIT.as_secs()
    );
    // And long enough to be worth offering: a person has to notice the agent's
    // message, open a terminal, and read a document.
    assert!(APPROVAL_WAIT.as_secs() >= 120);
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
    let wait = format!("within {} seconds", APPROVAL_WAIT.as_secs());
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
/// is going to give -- up to `APPROVAL_WAIT` per request in flight -- and the
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
