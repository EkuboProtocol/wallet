//! Tests for [`super`].

use super::*;

fn example_dapp() -> AppMetadata {
    AppMetadata {
        name: "Example".to_owned(),
        url: "https://example.com".to_owned(),
        ..AppMetadata::default()
    }
}

#[test]
fn a_relay_project_id_is_required_and_says_where_to_get_one() {
    // The public relay refuses a connection without one, so failing here with
    // a link beats failing later with a websocket close code.
    let error = resolve_project_id(Some(String::new())).expect_err("an empty id was accepted");
    let message = format!("{error}");
    assert!(message.contains("dashboard.reown.com"), "{message}");
    assert!(message.contains(PROJECT_ID_ENV), "{message}");
}

#[test]
fn a_project_id_is_trimmed_and_shape_checked() {
    assert_eq!(
        resolve_project_id(Some("  abc123  ".to_owned())).unwrap(),
        "abc123"
    );
    assert!(resolve_project_id(Some("abc_123-XYZ".to_owned())).is_ok());
    // A pasted URL or a whole JSON blob is not a project id, and accepting one
    // would put it straight into a URL query string.
    for wrong in [
        "https://dashboard.reown.com/project/abc",
        "{\"projectId\":\"abc\"}",
        "abc 123",
    ] {
        assert!(
            resolve_project_id(Some(wrong.to_owned())).is_err(),
            "{wrong} was accepted as a project id"
        );
    }
}

#[test]
fn the_methods_offered_exclude_the_two_that_cannot_be_reviewed_or_tracked() {
    // `eth_sign` signs a bare digest, so no review can show what it
    // authorizes. `eth_signTransaction` hands signed bytes to the dapp, which
    // breaks the record this wallet reconciles nonces and cancellations from.
    assert!(!SUPPORTED_METHODS.contains(&"eth_sign"));
    assert!(!SUPPORTED_METHODS.contains(&"eth_signTransaction"));
    assert!(!SUPPORTED_METHODS.contains(&"wallet_addEthereumChain"));
    for expected in [
        "eth_sendTransaction",
        "personal_sign",
        "eth_signTypedData_v4",
        "eth_accounts",
    ] {
        assert!(
            SUPPORTED_METHODS.contains(&expected),
            "{expected} is missing"
        );
    }
}

#[test]
fn dapp_authored_text_cannot_redraw_the_review_it_appears_on() {
    // The name is the one thing a person actually reads on the connection
    // screen, and it is chosen entirely by the dapp. A right-to-left override
    // in it rewrites the line it sits on.
    let hostile = "Uni\u{202e}swap\u{200b} \u{2066}official\u{2069}";
    let safe = sanitized(hostile);
    for character in ['\u{202e}', '\u{200b}', '\u{2066}', '\u{2069}'] {
        assert!(!safe.contains(character), "{character:?} survived: {safe}");
    }
}

#[test]
fn an_over_long_dapp_name_is_capped_rather_than_filling_the_screen() {
    let capped = sanitized(&"a".repeat(5_000));
    assert!(capped.chars().count() <= 130, "{}", capped.chars().count());
}

#[test]
fn a_dapp_that_names_itself_nothing_is_shown_as_such() {
    assert_eq!(sanitized(""), "not stated");
    assert_eq!(sanitized("   "), "not stated");
    assert_eq!(sanitized("\u{200b}"), "not stated");
}

#[test]
fn a_dapp_is_described_by_whichever_of_name_and_url_it_gave() {
    let describe = |name: &str, url: &str| {
        describe_dapp(&AppMetadata {
            name: name.to_owned(),
            url: url.to_owned(),
            ..AppMetadata::default()
        })
    };
    assert_eq!(
        describe("Example", "https://example.com"),
        "Example (https://example.com)"
    );
    assert_eq!(describe("Example", ""), "Example");
    assert_eq!(describe("", "https://example.com"), "https://example.com");
    assert_eq!(describe("", ""), "an unnamed dapp");
}

#[test]
fn the_plan_source_records_what_the_dapp_asked_for_and_did_not_get() {
    let proposed = dapp_request::TransactionRequest {
        from: Address::ZERO,
        to: Address::ZERO,
        data: alloy::primitives::Bytes::new(),
        value: alloy::primitives::U256::ZERO,
        suggested_gas: Some(alloy::primitives::U256::from(21_000)),
        overridden: vec!["nonce".to_owned(), "gasPrice".to_owned()],
    };
    let source = describe_plan_source(&example_dapp(), &proposed);
    assert!(source.contains("WalletConnect"), "{source}");
    // The reviewer is deciding on one transaction, and which site sent it is
    // the first thing they need; "a dapp" alone does not answer that.
    assert!(source.contains("Example"), "{source}");
    assert!(source.contains("21000"), "{source}");
    assert!(source.contains("nonce, gasPrice"), "{source}");
    assert!(source.contains("ignored"), "{source}");
}

#[test]
fn a_plan_source_from_a_plain_request_stays_plain() {
    let proposed = dapp_request::TransactionRequest {
        from: Address::ZERO,
        to: Address::ZERO,
        data: alloy::primitives::Bytes::new(),
        value: alloy::primitives::U256::ZERO,
        suggested_gas: None,
        overridden: Vec::new(),
    };
    assert_eq!(
        describe_plan_source(&example_dapp(), &proposed),
        "Example (https://example.com), connected over WalletConnect"
    );

    // A dapp that named itself nothing still produces a readable line.
    assert_eq!(
        describe_plan_source(&AppMetadata::default(), &proposed),
        "an unnamed dapp, connected over WalletConnect"
    );
}

#[test]
fn an_empty_list_reads_as_none_rather_than_as_nothing() {
    assert_eq!(join_or_none(&[]), "none");
    assert_eq!(
        join_or_none(&["eip155:1".to_owned(), "eip155:10".to_owned()]),
        "eip155:1, eip155:10"
    );
}
