//! Tests for [`super`].

use super::*;
use serde_json::json;

#[test]
fn a_request_and_a_response_are_told_apart() {
    let request: IncomingMessage = serde_json::from_value(json!({
        "id": 1, "jsonrpc": "2.0", "method": "wc_sessionPing", "params": {},
    }))
    .unwrap();
    assert_eq!(
        request.as_request().map(|(method, _)| method),
        Some("wc_sessionPing")
    );

    let response: IncomingMessage =
        serde_json::from_value(json!({ "id": 1, "jsonrpc": "2.0", "result": true })).unwrap();
    assert!(response.as_request().is_none());

    let failure: IncomingMessage = serde_json::from_value(json!({
        "id": 1, "jsonrpc": "2.0", "error": { "code": 5000, "message": "User rejected." },
    }))
    .unwrap();
    assert!(failure.as_request().is_none());
    assert_eq!(failure.error.unwrap().code, 5000);
}

#[test]
fn a_request_without_params_is_still_a_request() {
    // `wc_sessionPing` is sent with an empty object, and a peer that omits the
    // field entirely means the same thing.
    let message: IncomingMessage =
        serde_json::from_value(json!({ "id": 7, "jsonrpc": "2.0", "method": "wc_sessionPing" }))
            .unwrap();
    assert_eq!(
        message.as_request().map(|(method, _)| method),
        Some("wc_sessionPing")
    );
}

#[test]
fn a_proposal_from_a_newer_sdk_still_parses() {
    // Unknown fields at every level. Refusing the message over one of them
    // would break pairing against dapps on a newer SDK, and nothing unknown is
    // ever acted on.
    let proposal: SessionProposeParams = serde_json::from_value(json!({
        "relays": [{ "protocol": "irn" }],
        "proposer": {
            "publicKey": "ab".repeat(32),
            "metadata": {
                "name": "Example", "description": "", "url": "https://example.com",
                "icons": [], "verifyUrl": "https://verify.example", "redirect": { "native": "x://" },
            },
        },
        "requiredNamespaces": { "eip155": { "chains": ["eip155:1"], "methods": [], "events": [] } },
        "somethingEntirelyNew": { "nested": true },
        "expiryTimestamp": 1_700_000_300_i64,
    }))
    .unwrap();
    assert_eq!(proposal.proposer.metadata.name, "Example");
    assert_eq!(proposal.expiry_timestamp, Some(1_700_000_300));
}

#[test]
fn a_proposal_with_no_metadata_at_all_still_parses() {
    // Every metadata field defaults, because a dapp is free to send none of
    // them and the review has to be able to say "not stated" rather than fail.
    let proposal: SessionProposeParams = serde_json::from_value(json!({
        "proposer": { "publicKey": "cd".repeat(32) },
    }))
    .unwrap();
    assert!(proposal.proposer.metadata.name.is_empty());
    assert!(proposal.required_namespaces.is_empty());
    assert!(proposal.optional_namespaces.is_empty());
}

#[test]
fn a_session_request_parses_with_and_without_an_expiry() {
    let request: SessionRequestParams = serde_json::from_value(json!({
        "chainId": "eip155:1",
        "request": { "method": "personal_sign", "params": ["0x68", "0xabc"] },
    }))
    .unwrap();
    assert_eq!(request.chain_id, "eip155:1");
    assert_eq!(request.request.method, "personal_sign");
    assert_eq!(request.request.expiry_timestamp, None);

    let request: SessionRequestParams = serde_json::from_value(json!({
        "chainId": "eip155:1",
        "request": { "method": "eth_chainId", "params": [], "expiryTimestamp": 99 },
    }))
    .unwrap();
    assert_eq!(request.request.expiry_timestamp, Some(99));
}

#[test]
fn a_response_serializes_with_exactly_one_of_result_and_error() {
    let result = serde_json::to_value(OutgoingResponse::result(1, json!("0xhash"))).unwrap();
    assert_eq!(result["result"], "0xhash");
    assert!(result.get("error").is_none());

    let failure =
        serde_json::to_value(OutgoingResponse::error(1, error_code::USER_REJECTED, "no")).unwrap();
    assert_eq!(failure["error"]["code"], 5000);
    assert_eq!(failure["error"]["message"], "no");
    assert!(failure.get("result").is_none());
    assert_eq!(failure["jsonrpc"], "2.0");
}

#[test]
fn a_relay_object_omits_data_when_there_is_none() {
    let relay = serde_json::to_value(Relay {
        protocol: "irn".to_owned(),
        data: None,
    })
    .unwrap();
    assert_eq!(relay, json!({ "protocol": "irn" }));
}

#[test]
fn request_ids_look_like_recent_microsecond_timestamps() {
    // Some peers sanity-check the shape; a counter starting at 1 fails that.
    let id = request_id(1_700_000_000_000, 7);
    assert_eq!(id, 1_700_000_000_000_007);
    assert_ne!(request_id(1_700_000_000_000, 1), id);
    // A salt beyond the reserved tail wraps rather than overflowing into the
    // timestamp.
    assert!(request_id(1_700_000_000_000, 65_535) < 1_700_000_000_001_000);
}
