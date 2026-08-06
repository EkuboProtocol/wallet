//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use alloy::primitives::U256;

#[test]
fn parses_only_eip7702_delegation_designators() {
    let mut code = vec![0xef, 0x01, 0x00];
    code.extend([0x11; 20]);
    assert_eq!(
        delegated_implementation(&Bytes::from(code)),
        Some(Address::repeat_byte(0x11))
    );
    assert_eq!(delegated_implementation(&Bytes::from(vec![0xef, 1])), None);
}

#[test]
fn rpc_errors_do_not_repeat_credential_bearing_url() {
    let mut network = crate::config::default_networks().remove(0);
    network.rpc_url = "https://user:secret@example.invalid/rpc".parse().unwrap();
    let error = sanitized_rpc_error(
        &network,
        &format_args!("request to {} failed", network.rpc_url),
    );
    let message = error.to_string();
    assert!(!message.contains("secret"));
    assert!(message.contains("<rpc-url>"));

    // Providers also echo the credential-bearing authority without the
    // full URL around it; the bare userinfo form is stripped too.
    let bare = sanitized_rpc_error(
        &network,
        &format_args!("connect to user:secret@example.invalid refused"),
    )
    .to_string();
    assert!(!bare.contains("secret"), "{bare}");
    assert!(bare.contains("example.invalid"), "{bare}");

    // The commonest provider shape carries the key as the username alone.
    // The old pattern was built as `KEY:@host`, which nothing echoes, so
    // this form went out verbatim.
    let mut username_only = crate::config::default_networks().remove(0);
    username_only.rpc_url = "https://KEYMATERIAL@example.invalid/rpc".parse().unwrap();
    for message in [
        "connect to KEYMATERIAL@example.invalid refused",
        "unauthorized for KEYMATERIAL",
    ] {
        let sanitized = sanitized_rpc_error(&username_only, &format_args!("{message}"));
        let sanitized = sanitized.to_string();
        assert!(!sanitized.contains("KEYMATERIAL"), "{sanitized}");
    }

    // The commonest layout of all puts the key in the path, and a provider
    // that quotes only the path it rejected never repeats the whole URL.
    let mut path_key = crate::config::default_networks().remove(0);
    path_key.rpc_url = "https://example.invalid/v3/PROJECTSECRET".parse().unwrap();
    let sanitized = sanitized_rpc_error(
        &path_key,
        &format_args!("404 Not Found for /v3/PROJECTSECRET"),
    )
    .to_string();
    assert!(!sanitized.contains("PROJECTSECRET"), "{sanitized}");

    let mut query_key = crate::config::default_networks().remove(0);
    query_key.rpc_url = "https://example.invalid/rpc?apikey=QUERYSECRET"
        .parse()
        .unwrap();
    let sanitized = sanitized_rpc_error(
        &query_key,
        &format_args!("rejected request with apikey=QUERYSECRET"),
    )
    .to_string();
    assert!(!sanitized.contains("QUERYSECRET"), "{sanitized}");
}

#[test]
fn u256_balance_format_is_decimal() {
    assert_eq!(U256::from(123_u64).to_string(), "123");
}
