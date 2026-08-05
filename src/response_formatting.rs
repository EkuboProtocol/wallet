//! Common response formatting utilities for MCP tools.
//!
//! Consolidates response building patterns to reduce duplication across tool handlers.
//! These utilities help format wallet data, execution results, and status information
//! for consistent MCP protocol output.

use chrono::{DateTime, Utc};
use serde::Serializer;
use uuid::Uuid;

/// Helper to format a transaction hash for display.
pub fn format_transaction_hash(hash: &str) -> String {
    hash.to_string()
}

/// Helper to format an approval/request ID for display.
pub fn format_request_id(id: Uuid) -> String {
    id.to_string()
}

/// Helper to format an instruction message for approval workflow.
pub fn approval_instruction(request_id: Uuid) -> String {
    format!(
        "Transaction approval required. Tell the user to run `ekubo-wallet review {}` \
         in their own terminal (never invoke that CLI for them), then call wallet_wait_for_approval \
         with this request_id and keep calling it after each timeout until the request is \
         approved, rejected, or expired. Do not ask the user to report the approval in chat.",
        request_id
    )
}

/// Helper to format an instruction message for message signing workflow.
pub fn message_signing_instruction(request_id: Uuid) -> String {
    format!(
        "Message signing requires explicit human approval. Tell the user to run \
         `ekubo-wallet review {}` in their own terminal (never invoke that CLI for them), \
         then call wallet_wait_for_message with this request_id and keep calling it after \
         each timeout until the request is signed, rejected, or expired. \
         Do not ask the user to report the approval in chat.",
        request_id
    )
}

/// Helper to format an instruction message for typed data signing workflow.
pub fn typed_data_instruction(request_id: Uuid) -> String {
    format!(
        "Typed-data signing requires explicit human approval. Tell the user to run \
         `ekubo-wallet review {}` in their own terminal (never invoke that CLI for them), \
         then call wallet_wait_for_typed_data with this request_id and keep calling it after \
         each timeout until the request is signed, rejected, or expired. \
         Do not ask the user to report the approval in chat.",
        request_id
    )
}

/// Serialize a DateTime as an RFC3339 string for JSON output.
pub fn serialize_datetime<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&dt.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_transaction_hash_as_string() {
        let hash = "0x1234567890abcdef";
        assert_eq!(format_transaction_hash(hash), "0x1234567890abcdef");
    }

    #[test]
    fn formats_request_id_as_uuid_string() {
        let id = Uuid::nil();
        let formatted = format_request_id(id);
        assert_eq!(formatted, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn approval_instruction_includes_request_id() {
        let id = Uuid::nil();
        let instruction = approval_instruction(id);
        assert!(instruction.contains("ekubo-wallet review"));
        assert!(instruction.contains("00000000-0000-0000-0000-000000000000"));
    }
}
