//! Common input validation for MCP tools.
//!
//! Consolidates validation logic to reduce duplication across tool implementations.

use anyhow::{Result, ensure};

/// Digits in the largest uint64, and therefore in any chain ID.
const MAX_CHAIN_ID_DIGITS: usize = 20;

/// Parse a canonical decimal chain ID (not hex).
pub fn parse_chain_id(value: &str) -> Result<u64> {
    // Length first, so the digit scan below is over something bounded. The
    // largest uint64 is twenty digits, so anything longer cannot be a chain ID
    // whatever it contains, and refusing it by length is cheaper and clearer
    // than scanning a megabyte of digits to conclude the same thing.
    ensure!(
        value.len() <= MAX_CHAIN_ID_DIGITS,
        "chain ID must be at most {MAX_CHAIN_ID_DIGITS} digits"
    );
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
#[path = "input_validation_test.rs"]
mod tests;
