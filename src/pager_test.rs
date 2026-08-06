//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn wrapping_never_exceeds_the_viewport_and_keeps_blank_lines() {
    let text = ["alpha beta gamma delta", "", "  indented item here"];
    let lines = wrap(&text, 12);
    for line in &lines {
        assert!(display_width(line) <= 12, "{line:?} fits the wrap width");
    }
    assert!(lines.contains(&String::new()), "blank line survives");
    // The indent is structure and every wrapped line keeps it.
    let indented: Vec<&String> = lines
        .iter()
        .filter(|line| line.starts_with("  ") && !line.trim().is_empty())
        .collect();
    assert!(indented.len() > 1, "the indented item wrapped: {lines:?}");
}

#[test]
fn prose_is_reflowed_but_structure_is_not() {
    // The document's own hard wrap disappears: these two source lines are
    // one paragraph and refill the width given.
    assert_eq!(
        wrap(&["one two three", "four five"], 40),
        vec!["one two three four five".to_owned()]
    );
    // A heading and a bullet each stay on their own, whatever precedes.
    let lines = wrap(&["intro text", "## Heading", "- first", "- second"], 40);
    assert_eq!(
        lines,
        vec![
            "intro text".to_owned(),
            "## Heading".to_owned(),
            "- first".to_owned(),
            "- second".to_owned(),
        ]
    );
}

#[test]
fn a_wrapped_list_item_hangs_under_its_text() {
    let lines = wrap(&["- alpha beta gamma delta epsilon"], 16);
    assert_eq!(lines[0], "- alpha beta");
    for line in &lines[1..] {
        assert!(line.starts_with("  "), "{line:?} hangs past the bullet");
    }
}

#[test]
fn a_word_longer_than_the_viewport_still_gets_a_line() {
    let long = "0x".to_owned() + &"a".repeat(64);
    let lines = wrap(&[long.as_str()], 20);
    assert_eq!(lines, vec![long]);
}

#[test]
fn only_real_list_markers_start_a_list() {
    assert_eq!(bullet_width("- item"), 2);
    assert_eq!(bullet_width("12. item"), 4);
    assert_eq!(bullet_width("-dash-prefixed prose"), 0);
    assert_eq!(bullet_width("2026 was the year"), 0);
}

#[test]
fn the_footer_reports_the_end_only_at_the_end() {
    assert!(footer(0, 0).contains("END"), "a short document is read");
    assert!(footer(9, 10).contains('%'));
    assert!(footer(10, 10).contains("END"));
}

#[test]
fn keys_follow_less_and_always_offer_a_way_out() {
    let press = |code, modifiers| KeyEvent::new(code, modifiers);
    assert!(matches!(
        action(press(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        Action::Quit
    ));
    assert!(matches!(
        action(press(KeyCode::Esc, KeyModifiers::NONE)),
        Action::Quit
    ));
    assert!(matches!(
        action(press(KeyCode::Char(' '), KeyModifiers::NONE)),
        Action::PageDown
    ));
    assert!(matches!(
        action(press(KeyCode::Char('G'), KeyModifiers::NONE)),
        Action::Bottom
    ));
}

#[test]
fn only_enter_can_leave_a_finished_document() {
    // Held-down PgDn used to run off the end of the legal text and answer
    // the acceptance prompt underneath it. Every scrolling key has to stop
    // at the last line and leave the decision to Enter.
    let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
    for code in [KeyCode::PageDown, KeyCode::Char(' '), KeyCode::Char('f')] {
        assert!(
            matches!(action(press(code)), Action::PageDown),
            "{code:?} should only scroll"
        );
    }
    assert!(matches!(action(press(KeyCode::Enter)), Action::Continue));
}

#[test]
fn a_body_narrower_than_the_minimum_still_wraps_readably() {
    assert_eq!(body_columns(4), MINIMUM_BODY_COLUMNS);
    assert_eq!(body_columns(100), 98);
}
