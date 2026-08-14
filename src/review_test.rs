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
    let generation = state.generation();
    assert_eq!(state.selected(), ReviewDecision::Reject);
    assert!(!state.select(generation, ReviewDecision::Approve));
    assert!(state.mark_viewed_to_end(generation));
    assert!(state.select(generation, ReviewDecision::Approve));
}

#[test]
fn refresh_rejects_stale_events_and_resets_changed_documents() {
    let mut state = ReviewState::new(document("one"));
    let generation = state.generation();
    state.mark_viewed_to_end(generation);
    state.set_scroll_offset(generation, 500.0);
    state.select(generation, ReviewDecision::Approve);
    state.refresh(document("two"));
    assert_eq!(state.selected(), ReviewDecision::Reject);
    assert!(!state.approve_enabled());
    assert!(state.scroll_offset().abs() < f32::EPSILON);
    assert!(!state.select(generation, ReviewDecision::Reject));
}

#[test]
fn refresh_of_same_document_still_requires_it_to_be_viewed_again() {
    let original = document("same");
    let mut state = ReviewState::new(original.clone());
    let generation = state.generation();
    assert!(state.mark_viewed_to_end(generation));
    assert!(state.select(generation, ReviewDecision::Approve));

    state.refresh(original);

    assert_eq!(state.selected(), ReviewDecision::Reject);
    assert!(!state.approve_enabled());
    assert!(!state.select(generation, ReviewDecision::Approve));
}
