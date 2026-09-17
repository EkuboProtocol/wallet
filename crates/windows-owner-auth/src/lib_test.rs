use super::*;

#[test]
fn staged_failures_preserve_hresult_without_colliding_with_raw_errors_or_authorization() {
    for stage in 0..16 {
        let exit = 0x7000_0000 | (stage << 24) | 0x0007_0006;
        assert_eq!(decode_probe_failure(exit).unwrap().1, 0x8007_0006);
        assert_ne!(exit, VERIFIED_EXIT);
        assert!(!(AVAILABILITY_EXIT_BASE..=AVAILABILITY_EXIT_BASE + 4).contains(&exit));
    }
    assert!(decode_probe_failure(0xd000_0005).is_none());
    assert!(decode_probe_failure(0x8007_0006).is_none());
}

#[test]
fn every_availability_result_is_disjoint_from_authorization() {
    for value in 0..=4 {
        assert_ne!(AVAILABILITY_EXIT_BASE + value, VERIFIED_EXIT);
    }
}

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
