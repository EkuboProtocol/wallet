//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn parses_canonical_decimal_chain_id() {
    assert_eq!(parse_chain_id("1").unwrap(), 1);
    assert_eq!(parse_chain_id("137").unwrap(), 137);
}

#[test]
fn rejects_hex_chain_id() {
    assert!(parse_chain_id("0x1").is_err());
    assert!(parse_chain_id("0x89").is_err());
}

#[test]
fn rejects_leading_zero() {
    assert!(parse_chain_id("01").is_err());
    assert!(parse_chain_id("0137").is_err());
}

#[test]
fn rejects_invalid_chain_id() {
    assert!(parse_chain_id("invalid").is_err());
    assert!(parse_chain_id("").is_err());
}

#[test]
fn validates_timeout_seconds() {
    assert!(validate_timeout_seconds(0).is_err());
    assert!(validate_timeout_seconds(1).is_ok());
    assert!(validate_timeout_seconds(30).is_ok());
    assert!(validate_timeout_seconds(55).is_ok());
    assert!(validate_timeout_seconds(56).is_err());
}
