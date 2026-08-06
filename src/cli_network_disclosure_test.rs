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
    network.rpc_url = "https://rpc.example.invalid:8545/v2/api-key-1234?token=abcd"
        .parse()
        .unwrap();
    let value = describe_network(&network);
    assert_eq!(value["rpc_url"].as_str(), Some(network.rpc_url.as_str()));
    assert_eq!(value["chain_id"].as_str(), Some("1"));
}
