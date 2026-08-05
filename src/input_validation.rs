//! Common input validation for MCP tools.
//!
//! Consolidates validation logic to reduce duplication across tool implementations.

use anyhow::{Result, ensure};

/// Parse a canonical decimal chain ID (not hex).
pub fn parse_chain_id(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty()
            && !value.starts_with('0')
            && value.bytes().all(|byte| byte.is_ascii_digit()),
        "chain ID must be a canonical positive decimal integer"
    );
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("chain ID must fit uint64"))
}

/// Validate a timeout in seconds; must be between 1 and 55.
pub fn validate_timeout_seconds(seconds: u8) -> Result<()> {
    ensure!(
        (1..=55).contains(&seconds),
        "timeout_seconds must be between 1 and 55"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
