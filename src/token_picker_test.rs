//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use alloy::primitives::Address;

fn token(symbol: &str, byte: u8) -> ListedToken {
    ListedToken {
        chain_id: 1,
        address: Address::repeat_byte(byte),
        symbol: symbol.into(),
        name: None,
        decimals: 18,
    }
}

fn app() -> App {
    App::new(vec![
        TokenGroup {
            source: "ekubo-default".into(),
            tokens: vec![token("USDC", 0x11), token("WETH", 0x22)],
        },
        TokenGroup {
            source: "agent-suggested".into(),
            tokens: vec![token("SCAM", 0x33)],
        },
    ])
}

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
}

/// Everything arrives selected, because the owner is confirming a list
/// they asked for rather than assembling one from nothing.
#[test]
fn groups_start_collapsed_and_selected() {
    let app = app();
    assert_eq!(app.rows.len(), 2, "both groups collapsed to one row each");
    assert_eq!(app.total_selected(), 3);
    assert_eq!(app.groups[0].mark(), "[x]");
}

#[test]
fn a_group_is_one_decision() {
    let mut app = app();
    // The cursor starts on the first group header; space clears the whole
    // group without touching the other.
    handle_key(&mut app, press(KeyCode::Char(' ')));
    assert_eq!(app.groups[0].selected(), 0);
    assert_eq!(app.groups[1].selected(), 1);
    assert_eq!(app.total_selected(), 1);

    // Accepting yields exactly what the checkboxes showed.
    let decision = app.decision(true);
    assert_eq!(decision.accepted.len(), 1);
    assert_eq!(decision.accepted[0].symbol, "SCAM");
    assert!(decision.rejected.is_empty());
}

/// The case the grouping exists for: keep the curated list, drop the
/// entry an agent slipped in alongside it.
#[test]
fn a_partially_selected_group_is_visibly_partial() {
    let mut app = app();
    handle_key(&mut app, press(KeyCode::Right));
    assert_eq!(app.rows.len(), 4, "first group expanded");
    handle_key(&mut app, press(KeyCode::Down));
    handle_key(&mut app, press(KeyCode::Char(' ')));
    assert_eq!(app.groups[0].selected(), 1);
    assert_eq!(app.groups[0].mark(), "[~]", "not [x] and not [ ]");
}

#[test]
fn collapsing_from_inside_returns_to_the_header() {
    let mut app = app();
    handle_key(&mut app, press(KeyCode::Right));
    handle_key(&mut app, press(KeyCode::Down));
    assert!(matches!(app.rows[app.cursor], Row::Token(0, 0)));
    handle_key(&mut app, press(KeyCode::Left));
    assert!(matches!(app.rows[app.cursor], Row::Group(0)));
}

#[test]
fn select_all_and_none_span_every_group() {
    let mut app = app();
    handle_key(&mut app, press(KeyCode::Char('n')));
    assert_eq!(app.total_selected(), 0);
    handle_key(&mut app, press(KeyCode::Char('a')));
    assert_eq!(app.total_selected(), 3);
}

/// Accepting nothing is almost certainly a misfire, and writing zero rows
/// while reporting success would read as "done" to the owner.
#[test]
fn accepting_an_empty_selection_is_refused() {
    let mut app = app();
    handle_key(&mut app, press(KeyCode::Char('n')));
    assert_eq!(handle_key(&mut app, press(KeyCode::Enter)), Outcome::Stay);
    assert!(app.notice.is_some());
    assert_eq!(
        handle_key(&mut app, press(KeyCode::Char('r'))),
        Outcome::Stay
    );
}

#[test]
fn rejecting_returns_the_checked_tokens_and_accepts_nothing() {
    let mut app = app();
    assert_eq!(
        handle_key(&mut app, press(KeyCode::Char('r'))),
        Outcome::Reject
    );
    let decision = app.decision(false);
    assert_eq!(decision.rejected.len(), 3);
    assert!(decision.accepted.is_empty());
}

#[test]
fn quitting_decides_nothing() {
    let mut app = app();
    assert_eq!(
        handle_key(&mut app, press(KeyCode::Char('q'))),
        Outcome::Cancel
    );
    assert_eq!(handle_key(&mut app, press(KeyCode::Esc)), Outcome::Cancel);
}
