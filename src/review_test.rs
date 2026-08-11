use super::*;
use crate::approval::{ApprovalKind, ApprovalRequest};

fn document(summary: &str) -> ReviewDocument {
    ReviewDocument::from_request(
        ApprovalRequest::new(ApprovalKind::Transaction, "Review", summary),
        vec!["0x1234".into()],
    )
}

#[test]
fn approval_starts_rejected_and_gated() {
    let mut state = ReviewState::new(document("one"));
    assert_eq!(state.selected(), ReviewDecision::Reject);
    assert!(!state.select(1, ReviewDecision::Approve));
    assert!(state.mark_viewed_to_end(1));
    assert!(state.select(1, ReviewDecision::Approve));
}

#[test]
fn refresh_rejects_stale_events_and_resets_changed_documents() {
    let mut state = ReviewState::new(document("one"));
    state.mark_viewed_to_end(1);
    state.set_scroll_offset(1, 500.0);
    state.select(1, ReviewDecision::Approve);
    state.refresh(document("two"));
    assert_eq!(state.selected(), ReviewDecision::Reject);
    assert!(!state.approve_enabled());
    assert!(state.scroll_offset().abs() < f32::EPSILON);
    assert!(!state.select(1, ReviewDecision::Reject));
}
