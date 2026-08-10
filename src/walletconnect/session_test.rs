//! Tests for [`super`].
//!
//! The session boundary is what stands between a settled dapp and this
//! wallet's signing paths, so the checks here are the ones that matter most:
//! everything below is about a request that arrives naming something the
//! person never approved.

use super::*;
use crate::walletconnect::protocol::{Participant, SessionRequestPayload};

fn scope() -> ApprovedScope {
    ApprovedScope {
        address: "0x1111111111111111111111111111111111111111".to_owned(),
        chains: vec!["eip155:1".to_owned(), "eip155:10".to_owned()],
        methods: vec!["personal_sign".to_owned(), "eth_sendTransaction".to_owned()],
        events: vec!["chainChanged".to_owned()],
    }
}

fn request(method: &str, chain: &str) -> SessionRequestParams {
    SessionRequestParams {
        chain_id: chain.to_owned(),
        request: SessionRequestPayload {
            method: method.to_owned(),
            params: Value::Null,
            expiry_timestamp: None,
        },
    }
}

fn far_future() -> i64 {
    Utc::now().timestamp() + 3600
}

#[test]
fn an_in_scope_request_passes() {
    assert!(
        check_in_scope(
            &scope(),
            &request("personal_sign", "eip155:1"),
            far_future()
        )
        .is_ok()
    );
}

#[test]
fn a_chain_the_session_never_approved_is_refused() {
    // The dapp asked for mainnet and optimism; this arrives naming Base. If
    // this check were missing, the request would reach the wallet and be
    // carried out on a chain the person never saw on the approval screen.
    let (code, message) = check_in_scope(
        &scope(),
        &request("personal_sign", "eip155:8453"),
        far_future(),
    )
    .expect_err("an unapproved chain was accepted");
    assert_eq!(code, error_code::UNAUTHORIZED_CHAIN);
    assert!(message.contains("eip155:8453"), "{message}");
}

#[test]
fn a_method_the_session_never_approved_is_refused() {
    let (code, message) = check_in_scope(
        &scope(),
        &request("eth_signTypedData_v4", "eip155:1"),
        far_future(),
    )
    .expect_err("an unapproved method was accepted");
    assert_eq!(code, error_code::UNSUPPORTED_METHODS);
    assert!(message.contains("eth_signTypedData_v4"), "{message}");
}

#[test]
fn a_non_eip155_chain_is_refused_even_if_it_somehow_reached_the_scope() {
    let mut scope = scope();
    scope.chains.push("solana:mainnet".to_owned());
    let (code, _) = check_in_scope(
        &scope,
        &request("personal_sign", "solana:mainnet"),
        far_future(),
    )
    .expect_err("a non-eip155 chain was accepted");
    assert_eq!(code, error_code::UNAUTHORIZED_CHAIN);
}

#[test]
fn an_expired_session_stops_serving() {
    let expired = Utc::now().timestamp() - 1;
    let (code, message) = check_in_scope(&scope(), &request("personal_sign", "eip155:1"), expired)
        .expect_err("an expired session still served a request");
    assert_eq!(code, error_code::USER_DISCONNECTED);
    assert!(message.contains("expired"), "{message}");
}

#[test]
fn a_request_that_expired_before_it_arrived_is_refused() {
    let mut stale = request("personal_sign", "eip155:1");
    stale.request.expiry_timestamp = Some(Utc::now().timestamp() - 1);
    let (code, _) = check_in_scope(&scope(), &stale, far_future())
        .expect_err("an expired request was accepted");
    assert_eq!(code, error_code::INVALID_METHOD);
}

#[test]
fn a_caip2_chain_reads_as_a_number_only_for_eip155() {
    assert_eq!(numeric_chain_id("eip155:1"), Some(1));
    assert_eq!(numeric_chain_id("eip155:42161"), Some(42_161));
    assert_eq!(numeric_chain_id("solana:4sGjMW1s"), None);
    assert_eq!(numeric_chain_id("eip155:not-a-number"), None);
    assert_eq!(numeric_chain_id("eip155"), None);
    assert_eq!(numeric_chain_id(""), None);
}

fn proposal(
    required: Vec<(&str, ProposalNamespace)>,
    optional: Vec<(&str, ProposalNamespace)>,
) -> SessionProposeParams {
    SessionProposeParams {
        relays: Vec::new(),
        proposer: Participant {
            public_key: "ab".repeat(32),
            metadata: AppMetadata::default(),
        },
        required_namespaces: required
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
        optional_namespaces: optional
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
        expiry_timestamp: None,
    }
}

fn namespace(chains: Option<&[&str]>, methods: &[&str], events: &[&str]) -> ProposalNamespace {
    ProposalNamespace {
        chains: chains.map(|chains| chains.iter().map(|c| (*c).to_owned()).collect()),
        methods: methods.iter().map(|m| (*m).to_owned()).collect(),
        events: events.iter().map(|e| (*e).to_owned()).collect(),
    }
}

/// A dapp says how long its own lists are, and every entry in them is joined
/// into the review a person reads before choosing which account to expose. The
/// megabyte cap on the envelope bounds the memory and not the screen: a
/// megabyte of JSON is tens of thousands of method names, and burying the
/// account and the chains under them is the same outcome as misdescribing
/// them.
///
/// Refused rather than truncated, because a truncated proposal either hides
/// part of what the dapp asked for from the person approving it or quietly
/// narrows what gets settled.
#[test]
fn a_proposal_nobody_could_read_is_refused_rather_than_trimmed() {
    let many: Vec<String> = (0..MAX_PROPOSAL_ENTRIES)
        .map(|n| format!("eth_{n}"))
        .collect();
    let borrowed: Vec<&str> = many.iter().map(String::as_str).collect();
    let flood = proposal(
        vec![("eip155", namespace(Some(&["eip155:1"]), &borrowed, &[]))],
        Vec::new(),
    );
    let refusal = oversized_refusal(&flood).expect("a flood was accepted for review");
    assert!(
        refusal.contains(&MAX_PROPOSAL_ENTRIES.to_string()),
        "{refusal}"
    );

    // What a real dapp sends is nowhere near it.
    let ordinary = proposal(
        vec![(
            "eip155",
            namespace(
                Some(&["eip155:1", "eip155:8453"]),
                &["eth_sendTransaction", "personal_sign"],
                &["chainChanged"],
            ),
        )],
        Vec::new(),
    );
    assert!(oversized_refusal(&ordinary).is_none());
}

/// The count is over the whole proposal rather than per field, so spreading
/// the same flood across namespaces, chains, events, and the proposer's icons
/// does not get under it.
#[test]
fn the_count_is_over_everything_a_proposal_asks_for() {
    // Each namespace is itself, one chain, one method, and one event.
    let keys: Vec<String> = (0..=MAX_PROPOSAL_ENTRIES / 4)
        .map(|n| format!("eip155:{n}"))
        .collect();
    let spread: Vec<(&str, ProposalNamespace)> = keys
        .iter()
        .map(|key| {
            (
                key.as_str(),
                namespace(Some(&["eip155:1"]), &["personal_sign"], &["chainChanged"]),
            )
        })
        .collect();
    assert!(oversized_refusal(&proposal(spread, Vec::new())).is_some());

    let mut icons = proposal(Vec::new(), Vec::new());
    icons.proposer.metadata.icons = (0..=MAX_PROPOSAL_ENTRIES)
        .map(|n| format!("https://cdn{n}.example.com/icon.png"))
        .collect();
    assert!(oversized_refusal(&icons).is_some());
}

#[test]
fn a_summary_keeps_required_and_optional_apart() {
    let proposal = proposal(
        vec![(
            "eip155",
            namespace(
                Some(&["eip155:1"]),
                &["eth_sendTransaction"],
                &["chainChanged"],
            ),
        )],
        vec![(
            "eip155:10",
            namespace(None, &["personal_sign", "eth_sendTransaction"], &[]),
        )],
    );
    let summary = summarize(&proposal, "topic");
    assert_eq!(summary.required_chains, ["eip155:1"]);
    assert_eq!(summary.optional_chains, ["eip155:10"]);
    assert_eq!(summary.required_methods, ["eth_sendTransaction"]);
    // Required and optional never overlap: a method the dapp cannot work
    // without is not also listed as one it merely prefers.
    assert_eq!(summary.optional_methods, ["personal_sign"]);
    assert_eq!(summary.events, ["chainChanged"]);
    assert_eq!(summary.pairing_topic, "topic");
}

#[test]
fn a_chain_named_by_the_namespace_key_is_found() {
    // The two legal spellings: `eip155:1` as the key, or a bare `eip155` key
    // with a chains list. A wallet that reads only one of them silently sees
    // no chains at all for half the ecosystem.
    let by_key = proposal(vec![("eip155:1", namespace(None, &[], &[]))], vec![]);
    assert_eq!(summarize(&by_key, "t").required_chains, ["eip155:1"]);

    let by_list = proposal(
        vec![("eip155", namespace(Some(&["eip155:1"]), &[], &[]))],
        vec![],
    );
    assert_eq!(summarize(&by_list, "t").required_chains, ["eip155:1"]);
}

#[test]
fn settled_namespaces_mirror_the_keys_the_proposal_used() {
    let proposal = proposal(
        vec![(
            "eip155:1",
            namespace(
                None,
                &["eth_sendTransaction", "personal_sign"],
                &["chainChanged"],
            ),
        )],
        vec![],
    );
    let settled = settled_namespaces(&proposal, &scope());
    let entry = settled.get("eip155:1").expect("the proposal's own key");
    // A CAIP-2 key names its own chain, so repeating it in `chains` is not
    // what the reference client emits and some validators reject it.
    assert!(entry.chains.is_none());
    assert_eq!(
        entry.accounts,
        ["eip155:1:0x1111111111111111111111111111111111111111"]
    );
    assert!(entry.methods.contains(&"personal_sign".to_owned()));
}

#[test]
fn a_bare_namespace_key_keeps_its_chains_list() {
    let proposal = proposal(
        vec![(
            "eip155",
            namespace(
                Some(&["eip155:1", "eip155:10"]),
                &["eth_sendTransaction"],
                &["chainChanged"],
            ),
        )],
        vec![],
    );
    let settled = settled_namespaces(&proposal, &scope());
    let entry = settled.get("eip155").unwrap();
    assert_eq!(
        entry.chains.as_deref(),
        Some(["eip155:1".to_owned(), "eip155:10".to_owned()].as_slice())
    );
    assert_eq!(entry.accounts.len(), 2);
}

#[test]
fn settling_narrows_to_the_approved_scope_and_can_never_widen_it() {
    // The dapp asks for four chains and three methods; the person approved two
    // chains and two methods. Nothing outside the scope may appear in what is
    // sent back, or the dapp would believe it had permissions nobody granted.
    let proposal = proposal(
        vec![(
            "eip155",
            namespace(
                Some(&["eip155:1", "eip155:10", "eip155:8453", "eip155:137"]),
                &["eth_sendTransaction", "personal_sign", "eth_sign"],
                &["chainChanged", "accountsChanged"],
            ),
        )],
        vec![],
    );
    let settled = settled_namespaces(&proposal, &scope());
    let entry = settled.get("eip155").unwrap();
    assert_eq!(
        entry.chains.as_deref(),
        Some(["eip155:1".to_owned(), "eip155:10".to_owned()].as_slice())
    );
    assert!(
        !entry.methods.contains(&"eth_sign".to_owned()),
        "a method outside the approved scope was settled: {:?}",
        entry.methods
    );
    assert_eq!(entry.events, ["chainChanged"]);
    for account in &entry.accounts {
        assert!(
            account.ends_with("0x1111111111111111111111111111111111111111"),
            "{account}"
        );
    }
}

#[test]
fn a_namespace_outside_eip155_is_never_settled() {
    let proposal = proposal(
        vec![
            ("eip155:1", namespace(None, &["personal_sign"], &[])),
            (
                "solana",
                namespace(Some(&["solana:x"]), &["signMessage"], &[]),
            ),
        ],
        vec![],
    );
    let settled = settled_namespaces(&proposal, &scope());
    assert!(settled.contains_key("eip155:1"));
    assert!(!settled.contains_key("solana"));
}

#[test]
fn a_proposal_naming_nothing_recognizable_still_settles_a_usable_session() {
    // Without the fallback the namespaces would be empty and the dapp would
    // have no account to talk to, even though the person approved a session.
    let settled = settled_namespaces(&proposal(vec![], vec![]), &scope());
    let entry = settled.get(EIP155).expect("a fallback namespace");
    assert_eq!(entry.accounts.len(), 2);
    assert_eq!(entry.methods, scope().methods);
}

#[test]
fn the_pairing_key_stops_being_an_authority_once_a_session_settles() {
    // The URI a person pastes is a credential that goes on existing: in a
    // dapp's local storage, in a screenshot, in a terminal's scrollback. Only
    // the proposal it exists to deliver may be answered with it, so a copy of
    // that URI cannot act as the settled session afterwards.
    assert!(answerable_from(method::SESSION_PROPOSE, Origin::Pairing));
    for method in [
        method::SESSION_REQUEST,
        method::SESSION_DELETE,
        method::SESSION_EXTEND,
        method::SESSION_UPDATE,
        method::SESSION_EVENT,
        method::SESSION_PING,
    ] {
        assert!(
            !answerable_from(method, Origin::Pairing),
            "{method} was answerable on the pairing topic"
        );
        assert!(
            answerable_from(method, Origin::Session),
            "{method} was refused on the session topic"
        );
    }

    // And the session key does not get to propose: one `connect` run serves
    // one session, and `on_propose` is the pairing's business.
    assert!(!answerable_from(method::SESSION_PROPOSE, Origin::Session));

    // A method nobody dispatches is not answerable from anywhere. It used to
    // reach the replay set on its way to being ignored, which is a peer
    // spending this process's memory for the cost of a tiny envelope.
    for origin in [Origin::Pairing, Origin::Session] {
        assert!(!answerable_from("wc_somethingElse", origin));
        assert!(!answerable_from("", origin));
    }
}

#[test]
fn the_deadline_is_the_same_deadline_for_every_method() {
    // `wc_sessionExtend` sets a new deadline seven days out. If expiry were
    // only an admission check on `wc_sessionRequest`, a dapp could let its
    // session lapse, extend it, and go on signing under a scope whose stated
    // lifetime had ended -- forever, and without the person ever seeing
    // another connection review. Both gates read this one rule.
    assert!(lapsed(100, 100), "the deadline itself is past it");
    assert!(lapsed(100, 101));
    assert!(!lapsed(100, 99));

    // And the scope check agrees, at the same boundary.
    let expired = Utc::now().timestamp();
    let (code, message) = check_in_scope(&scope(), &request("personal_sign", "eip155:1"), expired)
        .expect_err("a session at its deadline still served a request");
    assert_eq!(code, error_code::USER_DISCONNECTED);
    assert_eq!(message, EXPIRED_REFUSAL);
}

#[test]
fn a_pairings_own_deadline_outlives_the_moment_the_uri_was_pasted() {
    // A pairing URI is a secret that travels through a clipboard and a
    // terminal's scrollback, and its expiry is the dapp's statement about how
    // long a copy is worth anything. Parsing used to be the only place that
    // read it, after which the session waited on the topic indefinitely and
    // settled a fresh seven days whenever a proposal turned up.
    let now = Utc::now();
    assert!(pairing_refusal(None, now).is_none(), "no deadline to pass");
    assert!(pairing_refusal(Some(now + chrono::TimeDelta::seconds(60)), now).is_none());

    let lapsed = pairing_refusal(Some(now - chrono::TimeDelta::seconds(1)), now)
        .expect("a pairing past its deadline must be refused");
    assert!(lapsed.contains("expired"), "{lapsed}");
    assert!(lapsed.contains("connect again"), "{lapsed}");

    // The deadline itself is past it, matching how a settled session's own
    // deadline is read.
    assert!(pairing_refusal(Some(now), now).is_some());
}

#[test]
fn the_replay_set_forgets_the_oldest_arrival_rather_than_growing() {
    // "Oldest" is the order they arrived in, not their numeric value. The id
    // is a u64 the peer chooses, and this set is the only thing between a
    // captured envelope and a second execution of the request inside it.
    let mut answered = AnsweredIds::default();
    let capacity = u64::try_from(MAX_ANSWERED_IDS).unwrap();
    for id in 0..capacity * 2 {
        assert!(remember(&mut answered, id), "every id here is new");
    }
    assert_eq!(answered.len(), MAX_ANSWERED_IDS);

    // The first half arrived first and is gone; the second half is retained.
    assert!(
        remember(&mut answered, 0),
        "the earliest arrival was forgotten"
    );
    assert!(
        !remember(&mut answered, capacity * 2 - 1),
        "and a redelivery inside the window is still caught, which is the whole point"
    );
}

/// The eviction rule used to be "drop the numerically smallest", justified in
/// a comment by protocol ids being microsecond timestamps. They usually are --
/// but the id is a `u64` a peer chooses, so that rule let the peer pick what
/// was forgotten.
///
/// A settled dapp sends enough high-valued answerable messages to push out the
/// low id it used earlier, replays the authenticated envelope carrying that
/// id, and the replay is admitted as new. `on_request` dispatches it again,
/// and a policy-allowed `eth_sendTransaction` reaches simulation, signing and
/// broadcast a second time at a fresh nonce with no new review.
#[test]
fn a_peer_cannot_choose_which_answered_id_is_forgotten() {
    let mut answered = AnsweredIds::default();
    let capacity = u64::try_from(MAX_ANSWERED_IDS).unwrap();
    let high = u64::MAX - capacity * 2;

    // The session has been busy: the cache is one short of full, and every id
    // in it is numerically above the one the dapp is about to use.
    for offset in 0..capacity - 1 {
        assert!(remember(&mut answered, high + offset));
    }

    // The request the dapp actually made, with an ordinary low id, arriving
    // last of everything so far.
    let replayed = 1_000_u64;
    assert!(remember(&mut answered, replayed));

    // One more message tips the cache over capacity. Exactly one entry has to
    // go, and it is the one that arrived first -- not the one with the
    // smallest number, which is the id the peer wants forgotten.
    assert!(remember(&mut answered, high + capacity));
    assert!(
        !remember(&mut answered, replayed),
        "the id the dapp chose arrived after every other entry, so nothing about their values \
         may displace it"
    );
    assert!(
        remember(&mut answered, high),
        "the entry that actually arrived first is the one that went"
    );
}
