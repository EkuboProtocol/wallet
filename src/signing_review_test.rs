//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.

use super::*;

#[test]
fn a_readable_message_still_shows_the_bytes_that_get_signed() {
    // Two messages that render identically after escaping: one holds a
    // real right-to-left override, the other the seven ASCII characters
    // that the escape of an override looks like. Only the hex tells the
    // reviewer which one they are signing.
    let real = "pay \u{202e}1".as_bytes();
    let literal = "pay \\u{202e}1".as_bytes();

    let rows = |bytes: &[u8]| {
        let hex = format!("0x{}", hex::encode(bytes));
        let display = crate::message::describe_message(bytes);
        let lines = message_payload_lines(&hex, &display);
        crate::fullscreen::lines_to_text(&lines, |text, _| text.to_owned())
    };

    let real_text = rows(real);
    let literal_text = rows(literal);
    assert!(real_text.contains("Exact bytes signed"), "{real_text}");
    assert_ne!(
        real_text, literal_text,
        "an override and its own escape rendered identically"
    );
    assert!(real_text.contains(&hex::encode(real)), "{real_text}");
}

#[test]
fn a_review_transcript_carries_nothing_that_can_redraw_a_terminal() {
    // serde_json escapes quotes, backslashes, and C0 controls. Everything
    // below is valid JSON string content and would reach the approver's
    // terminal intact: the override reverses what they read, the isolate
    // and the zero-width space hide inside it.
    let rendered = review_transcript_text(&serde_json::json!({
        "message": {
            "text": "pay \u{202e}0001\u{202c} to \u{2066}them\u{2069}",
            "symbol": "US\u{200b}DC",
        },
    }))
    .unwrap();
    for hostile in ['\u{202e}', '\u{202c}', '\u{2066}', '\u{2069}', '\u{200b}'] {
        assert!(
            !rendered.contains(hostile),
            "{hostile:?} survived into the transcript: {rendered}"
        );
    }
    // The transcript is still JSON, and still readable.
    assert!(rendered.contains("\"symbol\""));
}

#[test]
fn a_long_fact_is_truncated_with_a_pointer_to_the_complete_payload() {
    let long = "a".repeat(500);
    let excerpt = terminal_safe_excerpt(&long);
    assert!(excerpt.ends_with("(complete message below)"), "{excerpt}");
    assert!(excerpt.chars().count() < long.chars().count());

    // A fact that already fits is passed through untouched, so the marker
    // never appears on a message the reviewer is seeing in full.
    let short = "transfer 1 USDC";
    assert_eq!(terminal_safe_excerpt(short), short);
}
