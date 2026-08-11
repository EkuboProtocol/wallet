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
