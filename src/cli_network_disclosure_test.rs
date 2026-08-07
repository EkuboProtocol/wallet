//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn cli_listing_round_trips_the_complete_configuration() {
    // The listing is how an operator reads back and edits configuration, so
    // it must reproduce the RPC URL exactly rather than an abbreviation.
    let mut network = default_networks().remove(0);
    network.rpc_urls = vec![
        "https://rpc.example.invalid:8545/v2/api-key-1234?token=abcd"
            .parse()
            .unwrap(),
        "https://fallback.example.invalid/rpc".parse().unwrap(),
    ];
    let value = describe_network(&network);
    // Every endpoint, in order: the listing is what an operator edits
    // against, and failover reaches all of them.
    let listed: Vec<&str> = value["rpc_urls"]
        .as_array()
        .expect("rpc_urls is an array")
        .iter()
        .map(|url| url.as_str().expect("each endpoint is a string"))
        .collect();
    let expected: Vec<&str> = network.rpc_urls.iter().map(url::Url::as_str).collect();
    assert_eq!(listed, expected);
    assert_eq!(value["chain_id"].as_str(), Some("1"));
}
