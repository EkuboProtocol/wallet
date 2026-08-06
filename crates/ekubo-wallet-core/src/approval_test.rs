//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn request_builder_preserves_review_data() {
    let request = ApprovalRequest::new(ApprovalKind::Transaction, "Transfer", "Send funds")
        .fact("Recipient", "0xabc")
        .warning("Simulation changed a token allowance")
        .digest("0x1234");

    assert_eq!(request.facts[0].label, "Recipient");
    assert_eq!(request.warnings.len(), 1);
    assert_eq!(request.digest.as_deref(), Some("0x1234"));
}
