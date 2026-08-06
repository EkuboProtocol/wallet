//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::approval::ApprovalKind;
use crossterm::event::KeyModifiers;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn screen() -> ReviewScreen {
    ReviewScreen::new(vec![vec![Span::plain("summary")]])
}

#[test]
fn the_cursor_starts_on_reject_and_enter_there_rejects() {
    let mut review = screen();
    assert!(!review.on_approve, "reject is the default");
    assert_eq!(
        review.handle_key(press(KeyCode::Enter)),
        Some(ApprovalDecision::Rejected)
    );
}

#[test]
fn every_way_out_reads_as_rejection() {
    for key in [
        press(KeyCode::Esc),
        press(KeyCode::Char('q')),
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
    ] {
        let mut review = screen();
        review.on_approve = true;
        review.reached_end = true;
        assert_eq!(
            review.handle_key(key),
            Some(ApprovalDecision::Rejected),
            "{key:?} must reject even with approve highlighted"
        );
    }
}

#[test]
fn approving_takes_a_deliberate_move_and_a_fully_seen_document() {
    let mut review = screen();
    review.handle_key(press(KeyCode::Tab));
    assert!(review.on_approve);
    // The end has not been on screen: Enter refuses and explains.
    assert_eq!(review.handle_key(press(KeyCode::Enter)), None);
    assert!(review.notice.is_some(), "the refusal says why");
    review.reached_end = true;
    assert_eq!(
        review.handle_key(press(KeyCode::Enter)),
        Some(ApprovalDecision::Approved)
    );
}

#[test]
fn scrolling_keys_move_the_viewport_and_never_decide() {
    let mut review = screen();
    review.viewport = 5;
    review.max_offset = 100;
    for key in [
        KeyCode::Down,
        KeyCode::Char('j'),
        KeyCode::PageDown,
        KeyCode::Char(' '),
        KeyCode::Char('f'),
        KeyCode::End,
        KeyCode::Char('G'),
        KeyCode::Up,
        KeyCode::PageUp,
        KeyCode::Home,
    ] {
        assert_eq!(review.handle_key(press(key)), None, "{key:?} only scrolls");
    }
    review.handle_key(press(KeyCode::Down));
    assert_eq!(review.offset, 1);
    review.handle_key(press(KeyCode::PageDown));
    assert_eq!(review.offset, 6);
    review.handle_key(press(KeyCode::Home));
    assert_eq!(review.offset, 0);
}

#[test]
fn the_document_carries_facts_warnings_digest_and_payload_sanitized() {
    let request = ApprovalRequest::new(
        ApprovalKind::MessageSignature,
        "Approve message signature",
        "Sign these exact bytes.",
    )
    .fact("Wallet", "main")
    .warning("verify\u{1b}[2Jevery byte")
    .digest("0xabc");
    let payload = vec![vec![Span::plain("hello world")]];
    let document = review_document(&request, payload);
    let text = fullscreen::lines_to_text(&document, |text, _| text.to_owned());
    assert!(text.contains("Sign these exact bytes."));
    assert!(text.contains("Wallet: main"));
    assert!(text.contains("Digest: 0xabc"));
    assert!(text.contains(&format!("Request: {}", request.id)));
    assert!(text.contains("hello world"), "the payload is appended");
    assert!(
        !text.contains('\u{1b}'),
        "stored text cannot carry escapes into the review"
    );
}
