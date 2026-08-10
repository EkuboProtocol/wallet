//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use crossterm::event::KeyModifiers;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[test]
fn a_text_field_edits_at_the_caret_and_never_splits_a_character() {
    let mut field = TextField::new("Note").with_value("h\u{e9}llo");
    // `with_value` puts the caret at the end, counted in characters: the
    // string is six bytes and five characters, and a byte-indexed caret
    // would slice the accented character in half on the first backspace.
    assert!(field.handle_key(press(KeyCode::Home)));
    assert!(field.handle_key(press(KeyCode::Right)));
    assert!(field.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)));
    assert_eq!(field.value(), "hx\u{e9}llo");
    assert!(field.handle_key(press(KeyCode::Delete)));
    assert_eq!(field.value(), "hxllo");
    assert!(field.handle_key(press(KeyCode::End)));
    assert!(field.handle_key(press(KeyCode::Backspace)));
    assert_eq!(field.value(), "hxll");
}

#[test]
fn a_text_field_declines_the_keys_a_form_navigates_with() {
    // The form gives the focused field first refusal, so anything it
    // consumes can never also be navigation. These five must fall through
    // or Tab would type a tab and Esc could not back out.
    let mut field = TextField::new("Alias").with_value("alice");
    for code in [
        KeyCode::Enter,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Esc,
        KeyCode::Up,
    ] {
        assert!(!field.handle_key(press(code)), "{code:?} was consumed");
    }
    assert_eq!(field.value(), "alice");

    // Ctrl+U is the field's own, and clears the whole line.
    assert!(field.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)));
    assert_eq!(field.value(), "");
    // A control-modified character is never typed into the value.
    assert!(!field.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)));
    assert_eq!(field.value(), "");
}

use super::*;

fn text_of(lines: &[Line]) -> String {
    lines_to_text(lines, |text, _| text.to_owned())
}

fn sample() -> SearchableTable {
    let columns = vec![
        TableColumn::new("Name", Constraint::Fill(1)),
        TableColumn::new("Kind", Constraint::Length(8)),
    ];
    let rows = vec![
        TableRow::new(
            vec![Span::plain("alpha"), Span::plain("first")],
            &["alpha", "first", "0xaaaa"],
        ),
        TableRow::new(
            vec![Span::plain("beta"), Span::plain("second")],
            &["beta", "second", "0xbbbb"],
        ),
        TableRow::new(
            vec![Span::plain("gamma"), Span::plain("third")],
            &["gamma", "third", "0xcccc"],
        ),
    ];
    SearchableTable::new("Things", columns, rows)
}

#[test]
fn wrapping_respects_width_preserves_tones_and_loses_no_hash_digits() {
    let hash = format!("0x{}", "ab".repeat(32));
    let line: Line = vec![Span::toned("Hash        ", Tone::Muted), Span::plain(&hash)];
    let wrapped = wrap_line(&line, 30);
    assert!(wrapped.len() > 1, "a 66-character hash cannot fit one line");
    for piece in &wrapped {
        let width: usize = piece.iter().map(|span| display_width(&span.text)).sum();
        assert!(width <= 30, "{piece:?} fits the wrap width");
    }
    // Every hash character survives the break, in order: the value can
    // be read (and checked) across lines rather than being clipped.
    let rejoined: String = wrapped
        .iter()
        .flat_map(|piece| piece.iter())
        .map(|span| span.text.as_str())
        .collect::<String>()
        .replace(' ', "");
    assert!(rejoined.contains(&hash));
    // The label kept its tone after reassembly.
    assert_eq!(wrapped[0][0].tone, Some(Tone::Muted));
}

#[test]
fn wrapping_prefers_a_space_and_keeps_blank_lines() {
    let line: Line = vec![Span::plain("alpha beta gamma")];
    let wrapped = wrap_line(&line, 11);
    // The break space stays on the row it ended. This wrapper renders the
    // payload a person signs, so it lays text out and never removes any of it.
    assert_eq!(text_of(&wrapped), "alpha beta \ngamma");
    assert_eq!(wrap_line(&Vec::new(), 10), vec![Vec::new()]);
}

#[test]
fn stored_text_cannot_draw_chrome() {
    // A value with an embedded escape sequence reaches the screen with
    // the control characters flattened to spaces.
    let span = Span::plain("evil\u{1b}[2Jwallet");
    assert!(!span.text.contains('\u{1b}'));
    let toned = Span::toned("bad\nvalue", Tone::Info);
    assert!(!toned.text.contains('\n'));
}

#[test]
fn filtering_matches_the_haystack_and_keeps_the_selection() {
    let mut table = sample();
    table.state.select(Some(1));
    table.filter = "beta".into();
    table.refilter();
    assert_eq!(table.visible, vec![1], "only the matching row remains");
    assert_eq!(table.state.selected(), Some(0), "still on the beta row");
    // The haystack matches what the cells never showed.
    table.filter = "0xcccc".into();
    table.refilter();
    assert_eq!(table.visible, vec![2]);
    // Multiple terms all have to hit, in any order.
    assert!(matches_filter("alpha first 0xaaaa", "FIRST alpha"));
    assert!(!matches_filter("alpha first 0xaaaa", "alpha second"));
    // A filter matching nothing leaves nothing selected rather than a
    // phantom cursor on an empty table.
    table.filter = "no-such-thing".into();
    table.refilter();
    assert_eq!(table.state.selected(), None);
    // Clearing restores everything.
    table.filter.clear();
    table.refilter();
    assert_eq!(table.visible, vec![0, 1, 2]);
}

#[test]
fn keys_navigate_filter_pick_and_quit() {
    let mut table = sample();
    let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

    assert_eq!(table.handle_key(press(KeyCode::Down)), TableEvent::Stay);
    assert_eq!(table.state.selected(), Some(1));
    table.handle_key(press(KeyCode::End));
    assert_eq!(table.state.selected(), Some(2));
    table.handle_key(press(KeyCode::Home));
    assert_eq!(table.state.selected(), Some(0));

    // '/' starts a search; typed characters land in the filter.
    table.handle_key(press(KeyCode::Char('/')));
    assert!(table.typing);
    table.handle_key(press(KeyCode::Char('b')));
    assert_eq!(table.filter, "b");
    // The Enter that confirms the filter must not also pick the
    // selection; only the next Enter, back in the list, does that.
    assert_eq!(table.handle_key(press(KeyCode::Enter)), TableEvent::Stay);
    assert!(!table.typing);
    assert_eq!(
        table.handle_key(press(KeyCode::Enter)),
        TableEvent::Picked(1),
        "picking returns the underlying row index, not the visible one"
    );
    // Esc first clears the filter, and only then quits.
    assert_eq!(table.handle_key(press(KeyCode::Esc)), TableEvent::Stay);
    assert!(table.filter.is_empty());
    assert_eq!(table.handle_key(press(KeyCode::Esc)), TableEvent::Quit);
    assert_eq!(
        table.handle_key(press(KeyCode::Char('q'))),
        TableEvent::Quit
    );
}

#[test]
fn replacing_rows_keeps_the_filter_and_selection() {
    let mut table = sample();
    table.filter = "a".into();
    table.refilter();
    // "a" matches alpha, beta (0xbbbb has none... "beta" has an 'a'),
    // gamma — all three contain the letter a.
    assert_eq!(table.visible.len(), 3);
    table.state.select(Some(2));
    let replacement = vec![
        TableRow::new(vec![Span::plain("alpha")], &["alpha"]),
        TableRow::new(vec![Span::plain("delta")], &["delta"]),
        TableRow::new(vec![Span::plain("gamma")], &["gamma"]),
    ];
    table.set_rows(replacement);
    // The filter survived and re-applied to the new rows; the selected
    // row index (2) still passes it, so the selection stays put.
    assert_eq!(table.filter, "a");
    assert_eq!(table.visible, vec![0, 1, 2]);
    assert_eq!(table.selected_row(), Some(2));
}

#[test]
fn titles_and_hints_reflect_search_state() {
    let mut table = sample();
    assert_eq!(table.title(), "Things — 3");
    assert!(table.footer_hints("details").contains("Enter details"));
    table.filter = "beta".into();
    table.refilter();
    assert_eq!(table.title(), "Things — 1 of 3 match \u{201c}beta\u{201d}");
    assert!(table.footer_hints("details").contains("Esc clear search"));
    table.typing = true;
    assert!(table.footer_hints("details").starts_with("Search: beta"));
}

#[test]
fn interrupts_are_recognized_with_control_only() {
    assert!(is_interrupt(KeyEvent::new(
        KeyCode::Char('c'),
        KeyModifiers::CONTROL
    )));
    assert!(!is_interrupt(KeyEvent::new(
        KeyCode::Char('c'),
        KeyModifiers::NONE
    )));
}

#[test]
fn a_review_keeps_a_list_as_a_list() {
    // The reason this rendering exists: `tui::Confirmation` clamps a fact to
    // one line, so a newline-joined endpoint list collapsed into a run of URLs
    // separated by spaces. A labelled block keeps each one readable.
    let review = Review::new("Accept a new network", "An agent suggested a chain.")
        .fact("Chain ID", "8453")
        .fact_lines(
            "RPC endpoints",
            [
                "https://one.example".to_owned(),
                "https://two.example".to_owned(),
            ],
        )
        .warning("The configured RPC supplies chain state.");
    assert_eq!(
        text_of(&review.document()),
        concat!(
            "An agent suggested a chain.\n",
            "\n",
            "Chain ID: 8453\n",
            "RPC endpoints:\n",
            "  https://one.example\n",
            "  https://two.example\n",
            "\n",
            "\u{26a0} The configured RPC supplies chain state.",
        )
    );
}

#[test]
fn a_review_drops_a_list_with_nothing_in_it() {
    // A heading with no lines under it reads as a fact whose value went
    // missing, which is worse than not mentioning it at all.
    let review = Review::new("Apply proposed wallet policy", "No permissions change.")
        .fact_lines("Changes", Vec::new());
    assert_eq!(text_of(&review.document()), "No permissions change.\n");
}

#[test]
fn stored_text_in_a_review_cannot_draw_its_own_facts() {
    // Every value is one `Span`, and `Span::plain` turns a newline into a
    // space, so an agent-authored rationale cannot forge a line of the
    // wallet's own chrome underneath itself.
    let review = Review::new("Apply proposed wallet policy", "Agent proposed this.").fact(
        "Agent rationale (untrusted)",
        "looks fine\nChanges: allow every spender",
    );
    let text = text_of(&review.document());
    assert!(
        text.ends_with("Agent rationale (untrusted): looks fine Changes: allow every spender"),
        "{text}"
    );
    assert_eq!(text.lines().count(), 3);
}

/// The wrapper renders the complete EIP-712 payload a person reads before
/// signing, so it may lay text out but must never remove any of it. A space
/// inside a JSON string literal is part of the value the digest commits to,
/// and dropping the one a line happened to break at meant the string on the
/// screen was not the string being signed -- with no marker saying anything
/// had gone.
#[test]
fn wrapping_never_drops_a_character_of_what_is_signed() {
    for columns in 4..40_usize {
        for text in [
            "alpha beta gamma",
            r#""memo": "pay  alice  now""#,
            "a b c d e f g h i j k l m n o p",
            "trailing space ",
            " leading space",
            "double  space",
        ] {
            let line: Line = vec![Span::plain(text)];
            let wrapped = wrap_line(&line, columns);
            assert_eq!(
                text_of(&wrapped).replace('\n', ""),
                text,
                "every character survives wrapping {text:?} at {columns} columns"
            );
        }
    }
}

/// The same guarantee for the hanging-indent form, minus the indent it adds.
#[test]
fn hanging_wrapping_never_drops_a_character_either() {
    let text = "label: a value with  several  spaces in it";
    for columns in 12..40_usize {
        let line: Line = vec![Span::plain(text)];
        let wrapped = wrap_line_hanging(&line, columns, 2);
        let rejoined: String = text_of(&wrapped)
            .split('\n')
            .enumerate()
            .map(|(index, row)| {
                if index == 0 {
                    row.to_owned()
                } else {
                    row.strip_prefix("  ").unwrap_or(row).to_owned()
                }
            })
            .collect();
        assert_eq!(
            rejoined, text,
            "every character survives hanging-wrapping at {columns} columns"
        );
    }
}
