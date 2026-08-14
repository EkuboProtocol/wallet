use super::*;

#[test]
fn supported_methods_match_the_desktop_session_surface() {
    assert!(SUPPORTED_METHODS.contains(&"personal_sign"));
    assert!(SUPPORTED_METHODS.contains(&"wallet_sendCalls"));
    assert!(!SUPPORTED_METHODS.contains(&"eth_sign"));
}

#[test]
fn empty_proposal_lists_are_named_explicitly() {
    assert_eq!(join_or_none(&[]), "none");
    assert_eq!(join_or_none(&["eip155:1".into()]), "eip155:1");
}

#[test]
fn dapp_review_identity_is_stable_for_exactly_the_same_proposal_and_account() {
    let review_id = uuid::Uuid::new_v4();
    let proposal = ProposalSummary {
        metadata: AppMetadata::default(),
        required_chains: vec!["eip155:1".into()],
        optional_chains: Vec::new(),
        required_methods: vec!["personal_sign".into()],
        optional_methods: Vec::new(),
        events: Vec::new(),
        requested_grants: vec![walletconnect_session::ScopeGrant {
            chains: vec!["eip155:1".into()],
            methods: vec!["personal_sign".into()],
        }],
        pairing_topic: "11".repeat(32),
    };
    let account = ekubo_wallet_core::config::WalletMetadata {
        instance_id: uuid::Uuid::new_v4(),
        id: "primary".into(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    };
    let scope = DesktopSession::scope_for(
        &account,
        proposal.required_chains.clone(),
        proposal.required_methods.clone(),
        &proposal.requested_grants,
    );
    let first = DesktopSession::proposal_document(review_id, &proposal, &account, &scope);
    let second = DesktopSession::proposal_document(review_id, &proposal, &account, &scope);
    assert_eq!(first.identity, second.identity);

    let mut changed = scope;
    changed.chains.push("eip155:10".into());
    let stale = DesktopSession::proposal_document(review_id, &proposal, &account, &changed);
    assert_ne!(first.identity, stale.identity);
}

#[test]
fn batch_ids_round_trip_and_reject_arbitrary_values() {
    let request_id = uuid::Uuid::new_v4();
    assert_eq!(parse_batch_id(&batch_id(request_id)), Some(request_id));
    assert_eq!(parse_batch_id("0x1234"), None);
    assert_eq!(parse_batch_id("not-hex"), None);
}

#[test]
fn batch_statuses_match_eip_5792_terminal_states() {
    assert_eq!(calls_status_code(PendingStatus::AwaitingApproval), 100);
    assert_eq!(calls_status_code(PendingStatus::Confirmed), 200);
    assert_eq!(calls_status_code(PendingStatus::Rejected), 400);
    assert_eq!(calls_status_code(PendingStatus::Reverted), 500);
}
