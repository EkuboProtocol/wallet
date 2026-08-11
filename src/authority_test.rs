use super::*;

#[test]
fn exact_review_payloads_escape_invisible_and_bidirectional_text() {
    let rendered = escape_review_payload("safe\namount\u{202e}123\u{200b}");
    assert!(rendered.starts_with("safe\namount"));
    assert!(rendered.contains("\\u{202e}"));
    assert!(rendered.contains("\\u{200b}"));
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains('\u{200b}'));
}
