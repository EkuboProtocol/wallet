//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::policy_store::DatabaseKey;
use serde_json::json;

#[test]
fn a_member_the_type_does_not_declare_is_refused() {
    // EIP-712 hashes only the members listed for the type. Anything else
    // in `message` is displayed to the reviewer and signed by nothing, so
    // it can describe a transaction other than the one being authorized.
    let mut payload = permit_payload();
    payload["message"]["note"] = json!("Approving 10 USDC");
    let error = parse_typed_data(&payload).unwrap_err().to_string();
    assert!(error.contains("\"note\""), "{error}");
    assert!(error.contains("not signed"), "{error}");

    // A member shadowing a declared one is the same problem wearing the
    // right name, and is caught by the type not declaring it.
    let mut shadowed = permit_payload();
    shadowed["message"]["Deadline"] = json!(1);
    assert!(parse_typed_data(&shadowed).is_err());

    // The domain is checked the same way.
    let mut domain = permit_payload();
    domain["domain"]["salt"] = json!("0x01");
    assert!(parse_typed_data(&domain).is_err());

    // And an untouched payload still parses.
    assert!(parse_typed_data(&permit_payload()).is_ok());
}

pub(crate) fn permit_payload() -> serde_json::Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"}
            ]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "USD Coin",
            "version": "2",
            "chainId": 1,
            "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        },
        "message": {
            "owner": "0x1111111111111111111111111111111111111111",
            "spender": "0x2222222222222222222222222222222222222222",
            "value": "1000000",
            "nonce": "0",
            "deadline": "1900000000"
        }
    })
}

fn store() -> (tempfile::TempDir, TypedDataStore) {
    let directory = tempfile::tempdir().unwrap();
    let database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([9; 32]),
    )
    .unwrap();
    (directory, TypedDataStore::new(database))
}

#[test]
fn parses_and_digests_typed_data_with_pinned_chain() {
    let (_, chain_id, digest) = parse_typed_data(&permit_payload()).unwrap();
    assert_eq!(chain_id, 1);
    assert_ne!(digest, B256::ZERO);

    let mut chainless = permit_payload();
    chainless["domain"]
        .as_object_mut()
        .unwrap()
        .remove("chainId");
    assert!(parse_typed_data(&chainless).is_err());

    let mut domain_only = permit_payload();
    domain_only["primaryType"] = json!("EIP712Domain");
    assert!(parse_typed_data(&domain_only).is_err());
}

#[test]
fn lifecycle_persists_exact_payload_and_signature() {
    let (_directory, mut store) = store();
    let payload = permit_payload();
    let (_, chain_id, digest) = parse_typed_data(&payload).unwrap();
    let request = store.create("primary", chain_id, &payload, digest).unwrap();
    assert_eq!(request.status, TypedDataStatus::AwaitingApproval);
    assert_eq!(request.typed_data, payload);

    // The identical payload reuses the pending request.
    let duplicate = store.create("primary", chain_id, &payload, digest).unwrap();
    assert_eq!(duplicate.request_id, request.request_id);
    assert_eq!(store.awaiting_approval(None).unwrap().len(), 1);

    let signature = format!("0x{}", "11".repeat(65));
    let signed = store
        .store_signature(request.request_id, &request.digest, &signature)
        .unwrap();
    assert_eq!(signed.status, TypedDataStatus::Signed);
    assert_eq!(signed.signature.as_deref(), Some(signature.as_str()));
    assert!(signed.approved_at.is_some());
    assert!(store.awaiting_approval(None).unwrap().is_empty());

    // A signed request cannot be re-signed or rejected.
    assert!(
        store
            .store_signature(request.request_id, &request.digest, &signature)
            .is_err()
    );
    assert!(store.reject(request.request_id).is_err());
}

#[test]
fn recognizes_erc2612_permits_only_for_the_signing_wallet() {
    let payload = permit_payload();
    let (typed, _, _) = parse_typed_data(&payload).unwrap();
    let wallet = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
    let approvals = interpret_permit_approvals(&typed, wallet).unwrap().unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].kind, "erc2612_permit");
    assert_eq!(
        approvals[0].token,
        Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
            .unwrap()
            .to_checksum(None)
    );
    assert_eq!(approvals[0].amount, "1000000");

    let stranger = Address::repeat_byte(0x77);
    assert!(interpret_permit_approvals(&typed, stranger).is_err());
}

#[test]
fn lookalike_permit_types_are_not_treated_as_approvals() {
    let mut payload = permit_payload();
    // Same primary type name, different fields: must not be recognized.
    payload["types"]["Permit"] = json!([
        {"name": "owner", "type": "address"},
        {"name": "spender", "type": "address"},
        {"name": "data", "type": "bytes32"}
    ]);
    payload["message"] = json!({
        "owner": "0x1111111111111111111111111111111111111111",
        "spender": "0x2222222222222222222222222222222222222222",
        "data": "0x1111111111111111111111111111111111111111111111111111111111111111"
    });
    let (typed, _, _) = parse_typed_data(&payload).unwrap();
    let wallet = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
    assert!(
        interpret_permit_approvals(&typed, wallet)
            .unwrap()
            .is_none()
    );
}

fn permit2_payload(verifying_contract: &str) -> serde_json::Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "PermitSingle": [
                {"name": "details", "type": "PermitDetails"},
                {"name": "spender", "type": "address"},
                {"name": "sigDeadline", "type": "uint256"}
            ],
            "PermitDetails": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint160"},
                {"name": "expiration", "type": "uint48"},
                {"name": "nonce", "type": "uint48"}
            ]
        },
        "primaryType": "PermitSingle",
        "domain": {
            "name": "Permit2",
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": {
            "details": {
                "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "amount": "1461501637330902918203684832716283019655932542975",
                "expiration": "1900000000",
                "nonce": "0"
            },
            "spender": "0x3333333333333333333333333333333333333333",
            "sigDeadline": "1900000000"
        }
    })
}

#[test]
fn permit2_is_recognized_only_at_the_canonical_deployment() {
    let (typed, _, _) = parse_typed_data(&permit2_payload(
        "0x000000000022d473030f116ddee9f6b43ac78ba3",
    ))
    .unwrap();
    let wallet = Address::repeat_byte(0x11);
    let approvals = interpret_permit_approvals(&typed, wallet).unwrap().unwrap();
    assert_eq!(approvals[0].kind, "permit2_permit");
    assert_eq!(
        approvals[0].spender,
        Address::from_str("0x3333333333333333333333333333333333333333")
            .unwrap()
            .to_checksum(None)
    );

    let (impostor, _, _) = parse_typed_data(&permit2_payload(
        "0x4444444444444444444444444444444444444444",
    ))
    .unwrap();
    assert!(interpret_permit_approvals(&impostor, wallet).is_err());
}

#[test]
fn a_signature_can_only_come_from_an_approved_request() {
    // The store offers exactly one way to attach a signature, and it works
    // only on a request that is awaiting approval. There is no path that
    // records a signed payload without a human having approved it.
    let (_directory, mut store) = store();
    let payload = permit_payload();
    let (_, chain_id, digest) = parse_typed_data(&payload).unwrap();
    let request = store.create("primary", chain_id, &payload, digest).unwrap();
    store.reject(request.request_id).unwrap();
    assert!(
        store
            .store_signature(
                request.request_id,
                &request.digest,
                &format!("0x{}", "33".repeat(65)),
            )
            .is_err()
    );
}

#[test]
fn rejection_is_terminal_and_digest_is_bound() {
    let (_directory, mut store) = store();
    let payload = permit_payload();
    let (_, chain_id, digest) = parse_typed_data(&payload).unwrap();
    let request = store.create("primary", chain_id, &payload, digest).unwrap();
    assert!(
        store
            .store_signature(
                request.request_id,
                &format!("{:#x}", B256::repeat_byte(0xEE)),
                &format!("0x{}", "22".repeat(65)),
            )
            .is_err()
    );
    assert_eq!(
        store.reject(request.request_id).unwrap().status,
        TypedDataStatus::Rejected
    );
    assert!(store.reject(request.request_id).is_err());
}

/// A payload whose primary type nests a struct and an array of structs.
fn nested_payload() -> serde_json::Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"}
            ],
            "Order": [
                {"name": "maker", "type": "address"},
                {"name": "details", "type": "Details"},
                {"name": "legs", "type": "Leg[]"}
            ],
            "Details": [{"name": "amount", "type": "uint256"}],
            "Leg": [{"name": "token", "type": "address"}]
        },
        "primaryType": "Order",
        "domain": { "name": "Exchange", "chainId": 1 },
        "message": {
            "maker": "0x1111111111111111111111111111111111111111",
            "details": { "amount": "1" },
            "legs": [{ "token": "0x2222222222222222222222222222222222222222" }]
        }
    })
}

#[test]
fn a_nested_member_the_type_does_not_declare_is_refused() {
    // Structs nest, and each level's hash covers only the members its own type
    // declares, so every level has the gap the top level has. Checking
    // `message`'s immediate keys alone left a whole object of free text in the
    // reviewed payload with no signature over it.
    assert!(
        parse_typed_data(&nested_payload()).is_ok(),
        "the honest payload must still parse"
    );

    let mut nested = nested_payload();
    nested["message"]["details"]["note"] = json!("Approving 10 USDC");
    let error = parse_typed_data(&nested).unwrap_err().to_string();
    assert!(error.contains("\"note\""), "{error}");
    assert!(error.contains("message.details"), "{error}");
    assert!(error.contains("not signed"), "{error}");

    // An array of structs is the same gap once per element.
    let mut in_array = nested_payload();
    in_array["message"]["legs"][0]["note"] = json!("harmless");
    let error = parse_typed_data(&in_array).unwrap_err().to_string();
    assert!(error.contains("message.legs[0]"), "{error}");
}

#[test]
fn an_undeclared_domain_type_still_bounds_the_domain() {
    // Omitting `EIP712Domain` from `types` is legal and common, so the check
    // cannot be skipped when it is absent: that made "do not declare the type
    // you are breaking" a way to carry an unsigned member.
    let mut payload = json!({
        "types": { "Order": [{"name": "amount", "type": "uint256"}] },
        "primaryType": "Order",
        "domain": { "name": "Exchange", "chainId": 1 },
        "message": { "amount": "1" }
    });
    assert!(parse_typed_data(&payload).is_ok());

    payload["domain"]["note"] = json!("Approving 10 USDC");
    let error = parse_typed_data(&payload).unwrap_err().to_string();
    assert!(error.contains("\"note\""), "{error}");
    assert!(error.contains("not signed"), "{error}");
}
