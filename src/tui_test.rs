//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn the_caret_sits_under_the_character_being_typed() {
    // The prompt draws marker + message + one space, then places the caret
    // at that width plus what has been typed. The bug this pins was a
    // hardcoded 3 for a marker that renders as 2 columns, which put the
    // caret one column right of the text on every text prompt in the
    // product — visible as typing appearing to the left of the cursor.
    assert_eq!(display_width(PROMPT_MARKER), 2);

    for message in ["Alias", "Address", "Note", ""] {
        let prefix_width =
            display_width(PROMPT_MARKER) + display_width(message) + display_width(" ");
        // What the rendered line actually occupies before the value.
        let rendered = format!("{PROMPT_MARKER}{message} ");
        assert_eq!(
            prefix_width,
            display_width(&rendered),
            "caret would drift for message {message:?}"
        );
    }
}

#[test]
fn tones_map_to_distinct_ansi_styles() {
    let rendered: Vec<String> = [
        Tone::Success,
        Tone::Warning,
        Tone::Danger,
        Tone::Info,
        Tone::Muted,
        Tone::Emphasis,
    ]
    .iter()
    .map(|tone| styled("x", *tone))
    .collect();
    for text in &rendered {
        assert!(text.contains('\u{1b}'), "{text:?} carries an escape code");
        assert!(text.ends_with("\u{1b}[0m") || text.contains("39m") || text.contains("22m"));
    }
    let unique: std::collections::BTreeSet<_> = rendered.iter().collect();
    assert_eq!(unique.len(), rendered.len(), "every tone looks different");
}

#[test]
fn every_prompt_separates_its_question_from_the_answer() {
    assert_eq!(question("Network identifier"), "Network identifier:");
    assert_eq!(question("Chain ID  "), "Chain ID:");
    // Already punctuated: a second mark would read as a typo.
    assert_eq!(question("Save this alias?"), "Save this alias?");
    assert_eq!(question("Private key:"), "Private key:");
}

#[test]
fn escape_and_control_chords_cancel_but_plain_keys_do_not() {
    let press = |code, modifiers| KeyEvent::new(code, modifiers);
    assert!(cancels(press(KeyCode::Esc, KeyModifiers::NONE)));
    assert!(cancels(press(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    assert!(cancels(press(KeyCode::Char('d'), KeyModifiers::CONTROL)));
    assert!(!cancels(press(KeyCode::Char('c'), KeyModifiers::NONE)));
    assert!(!cancels(press(KeyCode::Enter, KeyModifiers::NONE)));
}

#[test]
fn text_editing_lands_on_character_boundaries() {
    assert_eq!(char_boundary("héllo", 0), 0);
    assert_eq!(char_boundary("héllo", 1), 1);
    assert_eq!(char_boundary("héllo", 2), 3);
    assert_eq!(char_boundary("héllo", 5), 6);
    assert_eq!(char_boundary("", 0), 0);
}

/// Spending standard input on a document must not, by itself, conclude that a
/// human is watching. The stderr check is the one that decides that, and
/// `meta-tokens import -` in a script — a pipe in, no terminal anywhere — has to
/// keep confirming nothing rather than confirming everything.
#[test]
fn a_spent_stdin_does_not_manufacture_a_terminal() {
    // The test harness gives this process no terminal on stderr, which is
    // exactly the scripted case being asserted about.
    assert!(!io::stderr().is_terminal());
    note_stdin_consumed();
    assert!(
        !interactive(),
        "a consumed stdin must not substitute for a terminal to draw on"
    );
}

/// A permission diff is a list, and a list joined onto one row is a list
/// nobody reads. `Confirmation` clamped every fact to a single line, which is
/// why direct policy replacement showed a wallet name, a revision number and a
/// generic warning where the proposal review had always shown the change
/// itself.
#[test]
fn a_multi_line_fact_keeps_its_lines_apart() {
    let question = Confirmation::new("Replace wallet policy", "Summary").fact_lines(
        "Changes",
        vec![
            "every chain (*): transfers now allowed up to 1 ETH".to_owned(),
            "chain 1: approvals to 0xrouter now signed without asking".to_owned(),
        ],
    );
    let rendered = question.rendered_body();
    assert!(
        rendered.contains("Changes:\n  every chain (*): transfers now allowed up to 1 ETH"),
        "the label stands alone and the first line is indented under it: {rendered}"
    );
    assert!(
        rendered.contains("\n  chain 1: approvals to 0xrouter now signed without asking"),
        "and every later line gets its own row: {rendered}"
    );

    // A single value is unchanged: still `label: value` on one row.
    let single = Confirmation::new("t", "s").fact("Wallet", "primary");
    assert!(single.rendered_body().contains("Wallet: primary"));

    // A newline smuggled into a line cannot forge another fact.
    let sneaky = Confirmation::new("t", "s")
        .fact_lines("Changes", vec!["harmless\nAddress: 0xattacker".to_owned()]);
    let rendered = sneaky.rendered_body();
    assert!(
        !rendered.contains("\nAddress: 0xattacker"),
        "a line is clamped like any other fact value: {rendered}"
    );
}
