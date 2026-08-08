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
