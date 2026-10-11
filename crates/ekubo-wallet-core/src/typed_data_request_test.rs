use super::*;
use alloy::primitives::address;

// The `permit` baseline from the specification's typed-data test vectors:
// fictional data, not a signable production request.
const PERMIT_REQUEST: &str = r#"{
  "schema_version": "1",
  "kind": "typed_data_signature_request",
  "signer": "0xabcdef0123456789abcdef0123456789abcdef01",
  "typed_data": {
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
      "name": "Example Token",
      "version": "1",
      "chainId": "1",
      "verifyingContract": "0x2222222222222222222222222222222222222222"
    },
    "message": {
      "owner": "0xabcdef0123456789abcdef0123456789abcdef01",
      "spender": "0x3333333333333333333333333333333333333333",
      "value": "1000000",
      "nonce": "7",
      "deadline": "1800000100"
    }
  },
  "valid_until": "1800000000"
}"#;

#[test]
fn permit_vector_digests_match_the_specification() {
    let request = parse_signature_request_bytes(PERMIT_REQUEST.as_bytes()).unwrap();
    assert_eq!(
        format!("{:#x}", request.signing_digest),
        "0xe7f18db2b4d1fcc298da816d44dc9358d62866803fb92dd0aecf70106dc87c3f"
    );
    assert_eq!(
        format!("{:#x}", request.request_digest),
        "0x52966f5b3b68cc7c68070316bbf3155d902e6cc27b163174bae549b1d9e3e90d"
    );
    assert_eq!(request.chain_id, 1);
    assert_eq!(request.valid_until, Some(1_800_000_000));
    assert_eq!(
        request.signer,
        address!("0xabcdef0123456789abcdef0123456789abcdef01")
    );
}

#[test]
fn object_key_order_changes_bytes_but_not_digests() {
    // Same request with shuffled object keys: identical digests.
    let shuffled = r#"{
      "valid_until": "1800000000",
      "typed_data": {
        "message": {
          "deadline": "1800000100",
          "nonce": "7",
          "value": "1000000",
          "spender": "0x3333333333333333333333333333333333333333",
          "owner": "0xabcdef0123456789abcdef0123456789abcdef01"
        },
        "domain": {
          "verifyingContract": "0x2222222222222222222222222222222222222222",
          "chainId": "1",
          "version": "1",
          "name": "Example Token"
        },
        "primaryType": "Permit",
        "types": {
          "Permit": [
            {"type": "address", "name": "owner"},
            {"type": "address", "name": "spender"},
            {"type": "uint256", "name": "value"},
            {"type": "uint256", "name": "nonce"},
            {"type": "uint256", "name": "deadline"}
          ],
          "EIP712Domain": [
            {"type": "string", "name": "name"},
            {"type": "string", "name": "version"},
            {"type": "uint256", "name": "chainId"},
            {"type": "address", "name": "verifyingContract"}
          ]
        }
      },
      "signer": "0xabcdef0123456789abcdef0123456789abcdef01",
      "kind": "typed_data_signature_request",
      "schema_version": "1"
    }"#;
    let request = parse_signature_request_bytes(shuffled.as_bytes()).unwrap();
    assert_eq!(
        format!("{:#x}", request.signing_digest),
        "0xe7f18db2b4d1fcc298da816d44dc9358d62866803fb92dd0aecf70106dc87c3f"
    );
    assert_eq!(
        format!("{:#x}", request.request_digest),
        "0x52966f5b3b68cc7c68070316bbf3155d902e6cc27b163174bae549b1d9e3e90d"
    );
}

#[test]
fn wallet_cutoff_changes_only_the_request_digest() {
    let earlier = PERMIT_REQUEST.replace("\"1800000000\"", "\"1799999999\"");
    let request = parse_signature_request_bytes(earlier.as_bytes()).unwrap();
    assert_eq!(
        format!("{:#x}", request.signing_digest),
        "0xe7f18db2b4d1fcc298da816d44dc9358d62866803fb92dd0aecf70106dc87c3f"
    );
    assert_eq!(
        format!("{:#x}", request.request_digest),
        "0xbd136b37684f72dc5746cd84f44d5b52bc008c60acb354952f9449c90179edc5"
    );
}

#[test]
fn absent_cutoff_projects_as_null() {
    let no_cutoff = PERMIT_REQUEST.replace(",\n  \"valid_until\": \"1800000000\"", "");
    let request = parse_signature_request_bytes(no_cutoff.as_bytes()).unwrap();
    assert_eq!(request.valid_until, None);
    assert_eq!(
        format!("{:#x}", request.request_digest),
        "0xb250bfba1de3a54857828acec8d09a9948499e65a7d299cb6b54e3f9592faec1"
    );
}

#[test]
fn duplicate_object_keys_are_rejected() {
    let duplicated =
        PERMIT_REQUEST.replace("\"nonce\": \"7\",", "\"nonce\": \"7\", \"nonce\": \"8\",");
    let error = parse_signature_request_bytes(duplicated.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("duplicate"), "{error}");
}

#[test]
fn duplicate_keys_hidden_behind_escapes_are_rejected() {
    let duplicated = PERMIT_REQUEST.replace(
        "\"nonce\": \"7\",",
        "\"nonce\": \"7\", \"\\u006eonce\": \"8\",",
    );
    let error = parse_signature_request_bytes(duplicated.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("duplicate"), "{error}");
}

#[test]
fn json_numbers_are_rejected_for_integers() {
    let numbered = PERMIT_REQUEST.replace("\"value\": \"1000000\"", "\"value\": 1000000");
    let error = parse_signature_request_bytes(numbered.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("never a JSON number"), "{error}");
}

#[test]
fn leading_zero_integers_are_rejected() {
    let padded = PERMIT_REQUEST.replace("\"value\": \"1000000\"", "\"value\": \"01000000\"");
    let error = parse_signature_request_bytes(padded.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("canonical"), "{error}");
}

#[test]
fn extra_message_members_are_rejected() {
    let extra = PERMIT_REQUEST.replace(
        "\"deadline\": \"1800000100\"",
        "\"deadline\": \"1800000100\", \"note\": \"only a test\"",
    );
    let error = parse_signature_request_bytes(extra.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("declares"), "{error}");
}

#[test]
fn missing_message_members_are_rejected() {
    let missing = PERMIT_REQUEST.replace(",\n      \"deadline\": \"1800000100\"", "");
    let error = parse_signature_request_bytes(missing.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("missing"), "{error}");
}

#[test]
fn unreachable_type_declarations_are_rejected() {
    let unreachable = PERMIT_REQUEST.replace(
        "\"Permit\": [",
        "\"Reassurance\": [{\"name\": \"capped\", \"type\": \"string\"}], \"Permit\": [",
    );
    let error = parse_signature_request_bytes(unreachable.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("does not reach"), "{error}");
}

#[test]
fn unknown_body_members_are_rejected() {
    let enriched =
        PERMIT_REQUEST.replace("\"signer\":", "\"instruction\": \"sign this\", \"signer\":");
    let error = parse_signature_request_bytes(enriched.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("unknown member"), "{error}");
}

#[test]
fn explicit_null_cutoff_is_rejected() {
    let nulled = PERMIT_REQUEST.replace("\"valid_until\": \"1800000000\"", "\"valid_until\": null");
    let error = parse_signature_request_bytes(nulled.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("explicit null"), "{error}");
}

#[test]
fn delivery_is_rejected() {
    let delivered = PERMIT_REQUEST.replace(
        "\"valid_until\": \"1800000000\"",
        "\"valid_until\": \"1800000000\", \"delivery\": \
         {\"url\": \"https://producer.example/signature-results\", \"request_id\": \"quote-1\"}",
    );
    let error = parse_signature_request_bytes(delivered.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("controlled delivery"), "{error}");
}

#[test]
fn undeclared_primary_type_is_rejected() {
    let renamed =
        PERMIT_REQUEST.replace("\"primaryType\": \"Permit\"", "\"primaryType\": \"Order\"");
    let error = parse_signature_request_bytes(renamed.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("not declared"), "{error}");
}

#[test]
fn bare_domain_payload_is_rejected() {
    let bare = PERMIT_REQUEST.replace(
        "\"primaryType\": \"Permit\"",
        "\"primaryType\": \"EIP712Domain\"",
    );
    let error = parse_signature_request_bytes(bare.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("bare EIP712Domain"), "{error}");
}

#[test]
fn expiry_comparison_uses_the_exclusive_cutoff() {
    assert!(!valid_until_expired(Some(1_800_000_000), 1_799_999_999));
    assert!(valid_until_expired(Some(1_800_000_000), 1_800_000_000));
    assert!(valid_until_expired(Some(1_800_000_000), 1_800_000_001));
    assert!(!valid_until_expired(None, 1_900_000_000));
    assert!(!valid_until_expired(Some(100), -1));
}
