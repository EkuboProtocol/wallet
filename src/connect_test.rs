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
fn the_logged_request_records_what_the_dapp_asked_for_and_did_not_get() {
    let proposed = dapp_request::TransactionRequest {
        from: Address::ZERO,
        to: Address::ZERO,
        data: alloy::primitives::Bytes::new(),
        value: alloy::primitives::U256::ZERO,
        suggested_gas: Some(alloy::primitives::U256::from(21_000)),
        overridden: vec!["nonce".to_owned(), "gasPrice".to_owned()],
    };
    let line = describe_dapp_request(&example_dapp(), &proposed);
    // The log is a running account of who asked for what, and which site asked
    // is the first thing it has to answer; "a dapp" alone does not.
    assert!(line.contains("Example"), "{line}");
    assert!(line.contains("21000"), "{line}");
    assert!(line.contains("nonce, gasPrice"), "{line}");
    assert!(line.contains("ignored"), "{line}");
}

#[test]
fn a_logged_request_from_a_plain_proposal_stays_plain() {
    let proposed = dapp_request::TransactionRequest {
        from: Address::ZERO,
        to: Address::ZERO,
        data: alloy::primitives::Bytes::new(),
        value: alloy::primitives::U256::ZERO,
        suggested_gas: None,
        overridden: Vec::new(),
    };
    // The host, not the URL: it is the part a reader can compare against the
    // address bar they opened the site from.
    assert_eq!(
        describe_dapp_request(&example_dapp(), &proposed),
        "Example (example.com) proposed a transaction"
    );

    // A dapp that named itself nothing still produces a readable line.
    assert_eq!(
        describe_dapp_request(&AppMetadata::default(), &proposed),
        "an unnamed dapp proposed a transaction"
    );
}

/// The plan source names the dapp, but always behind the prefix: the same
/// field holds a TLS-proved host for a fetched plan, and a dapp free to call
/// itself anything must not be able to produce a value that reads like one.
#[test]
fn the_plan_source_marks_the_dapps_account_of_itself_as_claimed() {
    assert_eq!(
        describe_plan_source(&example_dapp()),
        "WalletConnect: Example (example.com)"
    );
    assert_eq!(
        describe_plan_source(&AppMetadata::default()),
        "WalletConnect: an unnamed dapp"
    );

    // A dapp naming itself after somewhere else still cannot produce a value
    // that reads as a verified host.
    let impostor = AppMetadata {
        name: "ekubo.org".to_owned(),
        url: "https://claim-rewards.xyz".to_owned(),
        ..AppMetadata::default()
    };
    let source = describe_plan_source(&impostor);
    assert!(source.starts_with("WalletConnect: "), "{source}");
    assert!(source.contains("claim-rewards.xyz"), "{source}");
}

/// The store validates this string on write *and* on read, and a value it
/// refuses fails the whole request — which is how every dapp transaction came
/// to die on "stored plan source is not a vetted host name". Nothing else
/// crosses the two modules, so this test does.
#[test]
fn every_plan_source_this_session_produces_is_one_the_store_accepts() {
    let long_name = "ﷺ".repeat(400);
    for dapp in [
        example_dapp(),
        AppMetadata::default(),
        AppMetadata {
            name: long_name,
            url: "https://example.com".to_owned(),
            ..AppMetadata::default()
        },
        AppMetadata {
            name: "Line\u{202e}break".to_owned(),
            url: "not a url".to_owned(),
            ..AppMetadata::default()
        },
    ] {
        let source = describe_plan_source(&dapp);
        assert!(
            source.len() <= crate::pending::MAX_PLAN_SOURCE_BYTES,
            "{} bytes: {source}",
            source.len()
        );
        crate::pending::validate_plan_source(Some(&source))
            .unwrap_or_else(|error| panic!("the store refuses `{source}`: {error}"));
    }
}

#[test]
fn an_empty_list_reads_as_none_rather_than_as_nothing() {
    assert_eq!(join_or_none(&[]), "none");
    assert_eq!(
        join_or_none(&["eip155:1".to_owned(), "eip155:10".to_owned()]),
        "eip155:1, eip155:10"
    );
}

#[test]
fn the_batch_methods_are_offered_together_or_not_at_all() {
    // A dapp told atomicity is supported will send `wallet_sendCalls` and then
    // poll `wallet_getCallsStatus`. Advertising the capability without both is
    // an answer that strands it.
    for method in [
        "wallet_getCapabilities",
        "wallet_sendCalls",
        "wallet_getCallsStatus",
    ] {
        assert!(SUPPORTED_METHODS.contains(&method), "{method} is missing");
    }
}

#[test]
fn a_batch_id_survives_the_round_trip_and_nothing_else_parses_as_one() {
    let request_id = uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    let id = batch_id(request_id);
    assert_eq!(id, "0x0123456789abcdef0123456789abcdef");
    assert_eq!(parse_batch_id(&id), Some(request_id));
    // A dapp asking about an id this wallet never minted gets "unknown batch",
    // which needs these to fail rather than panic.
    for wrong in ["0x", "0xnothex", "0x0123", &"0xab".repeat(40)] {
        assert_eq!(parse_batch_id(wrong), None, "{wrong} parsed as a batch id");
    }
}

/// The one status EIP-5792 defines that this wallet can never report is 600,
/// partial revert — a multi-call plan is one `revertOnFailure` batch, so there
/// is no half-executed outcome to describe.
#[test]
fn every_record_status_maps_to_a_batch_status_and_none_is_partial() {
    use crate::pending::PendingStatus::{
        AwaitingApproval, Broadcast, Cancelled, Cancelling, Confirmed, Rejected, Replaced,
        Reverted, Signed, Submitting,
    };

    for pending in [AwaitingApproval, Signed, Submitting, Broadcast, Cancelling] {
        assert_eq!(calls_status_code(pending), 100, "{pending:?}");
    }
    assert_eq!(calls_status_code(Confirmed), 200);
    // Onchain and reverted as a whole, which is 500 rather than 400: gas was
    // charged and the dapp needs to know the difference.
    assert_eq!(calls_status_code(Reverted), 500);
    for offchain in [Rejected, Cancelled, Replaced] {
        assert_eq!(calls_status_code(offchain), 400, "{offchain:?}");
    }
}

#[test]
fn a_reported_receipt_carries_every_field_the_spec_names() {
    use alloy::primitives::B256;

    let receipt = crate::rpc::ReceiptDetails {
        succeeded: true,
        block_number: 0x123,
        block_hash: B256::repeat_byte(0xbb),
        gas_used: 21_000,
        effective_gas_price: 1_000_000_000,
        logs: vec![crate::rpc::ReceiptLog {
            address: Address::repeat_byte(0xcc),
            topics: vec![B256::repeat_byte(0xdd)],
            data: vec![0x01, 0x02],
        }],
    };
    let json = receipt_json("0xfeed", &receipt);
    assert_eq!(json["status"], "0x1");
    assert_eq!(json["blockNumber"], "0x123");
    assert_eq!(json["gasUsed"], "0x5208");
    assert_eq!(json["transactionHash"], "0xfeed");
    assert_eq!(json["blockHash"].as_str().unwrap().len(), 66);
    assert_eq!(json["logs"][0]["data"], "0x0102");
    assert_eq!(json["logs"][0]["topics"].as_array().unwrap().len(), 1);
}
