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

#[test]
fn facts_belong_to_the_open_section_once_one_starts() {
    let request = ApprovalRequest::new(ApprovalKind::Transaction, "Transfer", "Send funds")
        .fact("Wallet", "main")
        .section("Calls")
        .fact("Target", "0xabc")
        .section("Balance changes")
        .fact("ETH (native)", "-1");

    assert_eq!(
        request.facts.len(),
        1,
        "header facts stay ahead of sections"
    );
    assert_eq!(request.sections[0].heading, "Calls");
    assert_eq!(request.sections[0].facts[0].label, "Target");
    assert_eq!(request.sections[1].facts[0].label, "ETH (native)");
}
