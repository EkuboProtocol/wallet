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
    // The host, not the URL: the plan's source line is what a reviewer reads
    // to know who asked, and the host is the part they can check.
    assert_eq!(
        describe_plan_source(&example_dapp(), &proposed),
        "Example (example.com), connected over WalletConnect"
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
