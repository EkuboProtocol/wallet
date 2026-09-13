use super::*;

fn challenge() -> Challenge {
    Challenge {
        nonce: "a".repeat(64),
        operation_digest: "b".repeat(64),
        reason: "sign the reviewed transaction".into(),
    }
}

#[test]
fn malformed_native_bindings_and_injected_fields_are_rejected() {
    let mut value = challenge();
    value.validate().unwrap();
    value.nonce = "a".repeat(63);
    assert!(value.validate().is_err());
    value = challenge();
    value.operation_digest = "g".repeat(64);
    assert!(value.validate().is_err());
    value = challenge();
    value.reason.push('\0');
    assert!(value.validate().is_err());
    let mut json = serde_json::to_value(challenge()).unwrap();
    json["verified"] = true.into();
    assert!(serde_json::from_value::<Challenge>(json).is_err());
}

#[test]
fn quoted_json_retains_windows_backslashes_and_quote_delimiters() {
    assert_eq!(quote_argument("a\\b"), "\"a\\b\"");
    assert_eq!(quote_argument("a\\\"b"), "\"a\\\\\\\"b\"");
    assert_eq!(quote_argument("a\\"), "\"a\\\\\"");
}
