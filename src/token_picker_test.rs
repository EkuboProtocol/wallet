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

fn token_on(symbol: &str, byte: u8, chain_id: u64) -> ListedToken {
    ListedToken {
        chain_id,
        ..token(symbol, byte)
    }
}

/// Two chains and two sources: the shape a filter has to survive.
fn multichain_app() -> App {
    App::new(vec![
        TokenGroup {
            source: "ekubo-default".into(),
            tokens: vec![
                token_on("USDC", 0x11, 1),
                token_on("WETH", 0x22, 1),
                token_on("USDC", 0x33, 8453),
            ],
        },
        TokenGroup {
            source: "agent-suggested".into(),
            tokens: vec![token_on("SCAM", 0x44, 8453)],
        },
    ])
}

fn type_search(app: &mut App, query: &str) {
    handle_key(app, press(KeyCode::Char('/')));
    for character in query.chars() {
        handle_key(app, press(KeyCode::Char(character)));
    }
    handle_key(app, press(KeyCode::Enter));
}

fn shown_symbols(app: &App) -> Vec<&str> {
    app.rows
        .iter()
        .filter_map(|row| match row {
            Row::Token(group, token) => Some(app.groups[*group].tokens[*token].symbol.as_str()),
            Row::Group(_) => None,
        })
        .collect()
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

/// The search matches symbol, name, or address, and shows the hits without
/// having to be expanded first.
#[test]
fn searching_shows_only_the_matching_tokens() {
    let mut app = multichain_app();
    type_search(&mut app, "usdc");
    assert_eq!(shown_symbols(&app), vec!["USDC", "USDC"]);
    assert_eq!(app.total_shown(), 2);
    assert_eq!(
        app.rows.len(),
        3,
        "the group that matched nothing is gone entirely"
    );
}

#[test]
fn a_search_term_can_be_an_address() {
    let mut app = multichain_app();
    type_search(&mut app, &Address::repeat_byte(0x44).to_checksum(None));
    assert_eq!(shown_symbols(&app), vec!["SCAM"]);
}

#[test]
fn the_chain_filter_cycles_through_every_chain_and_back_to_all() {
    let mut app = multichain_app();
    assert_eq!(app.chains, vec![1, 8453]);
    handle_key(&mut app, press(KeyCode::Char('c')));
    assert_eq!(app.chain_filter(), Some(1));
    assert_eq!(shown_symbols(&app), vec!["USDC", "WETH"]);
    handle_key(&mut app, press(KeyCode::Char('c')));
    assert_eq!(app.chain_filter(), Some(8453));
    assert_eq!(shown_symbols(&app), vec!["USDC", "SCAM"]);
    handle_key(&mut app, press(KeyCode::Char('c')));
    assert_eq!(app.chain_filter(), None, "back to every chain");
    assert_eq!(app.total_shown(), 4);
}

#[test]
fn the_two_filters_narrow_together() {
    let mut app = multichain_app();
    type_search(&mut app, "usdc");
    handle_key(&mut app, press(KeyCode::Char('c')));
    assert_eq!(shown_symbols(&app), vec!["USDC"]);
    assert!(app.title().contains("chain 1 + \u{201c}usdc\u{201d}"));
}

/// The payoff: narrow, clear the lot, and only what was on screen changes.
#[test]
fn bulk_keys_reach_only_what_the_filter_shows() {
    let mut app = multichain_app();
    type_search(&mut app, "usdc");
    handle_key(&mut app, press(KeyCode::Char('n')));
    assert_eq!(app.total_selected(), 2, "WETH and SCAM are untouched");
    handle_key(&mut app, press(KeyCode::Esc));
    assert_eq!(shown_symbols(&app).len(), 0, "collapsed groups again");
    assert_eq!(app.groups[0].mark(), "[~]");
}

/// A group header is one decision about the rows under it, which under a
/// filter means the rows the filter left.
#[test]
fn toggling_a_group_under_a_filter_spares_the_hidden_rows() {
    let mut app = multichain_app();
    handle_key(&mut app, press(KeyCode::Char('c')));
    assert!(matches!(app.rows[app.cursor], Row::Group(0)));
    handle_key(&mut app, press(KeyCode::Char(' ')));
    assert_eq!(
        app.groups[0].selected(),
        1,
        "only the chain-1 pair was cleared"
    );
    assert_eq!(app.groups[0].tokens[2].symbol, "USDC");
    assert!(app.groups[0].checked[2], "the chain-8453 entry survived");
}

/// The title reports the whole selection, never the visible part of it, so a
/// filter can never make a decision look smaller than it is.
#[test]
fn the_title_counts_the_whole_selection_under_a_filter() {
    let mut app = multichain_app();
    type_search(&mut app, "usdc");
    let title = app.title();
    assert!(title.contains("4 of 4 selected"), "{title}");
    assert!(title.contains("showing 2"), "{title}");
    // The provenance disclosure survives a filter, and stays ahead of the
    // filter status so a narrow terminal clips the filter and not it.
    let disclosure = title
        .find("list names are the agent's own claim")
        .expect("the disclosure is still in the filtered title");
    assert!(disclosure < title.find("showing 2").unwrap(), "{title}");
}

/// Accepting eight visible rows must not quietly name the three thousand a
/// filter is hiding, so the first keypress explains and the second decides.
#[test]
fn deciding_past_a_filter_takes_a_second_keypress() {
    let mut app = multichain_app();
    type_search(&mut app, "usdc");
    assert_eq!(handle_key(&mut app, press(KeyCode::Enter)), Outcome::Stay);
    let notice = app.notice.clone().expect("the hidden rows are named");
    assert!(notice.contains("all 4 selected"), "{notice}");
    assert!(notice.contains("2 the filter is hiding"), "{notice}");
    assert_eq!(handle_key(&mut app, press(KeyCode::Enter)), Outcome::Accept);
    assert_eq!(app.decision(true).accepted.len(), 4);
}

#[test]
fn a_confirmation_does_not_survive_an_unrelated_keypress() {
    let mut app = multichain_app();
    type_search(&mut app, "usdc");
    assert_eq!(handle_key(&mut app, press(KeyCode::Enter)), Outcome::Stay);
    handle_key(&mut app, press(KeyCode::Down));
    assert_eq!(
        handle_key(&mut app, press(KeyCode::Enter)),
        Outcome::Stay,
        "the second Enter has to be the very next key"
    );
    assert_eq!(
        handle_key(&mut app, press(KeyCode::Char('r'))),
        Outcome::Stay
    );
    assert_eq!(
        handle_key(&mut app, press(KeyCode::Char('r'))),
        Outcome::Reject
    );
}

/// Nothing is hidden once the visible rows are the only checked ones, so the
/// decision goes through on the first keypress.
#[test]
fn deciding_with_nothing_hidden_needs_no_confirmation() {
    let mut app = multichain_app();
    handle_key(&mut app, press(KeyCode::Char('n')));
    type_search(&mut app, "usdc");
    handle_key(&mut app, press(KeyCode::Char('a')));
    assert_eq!(handle_key(&mut app, press(KeyCode::Enter)), Outcome::Accept);
}

/// Letters typed into the search are the search, not the bulk keys they would
/// otherwise be — "n" in a query must not deselect everything.
#[test]
fn typing_a_search_never_fires_the_list_bindings() {
    let mut app = multichain_app();
    handle_key(&mut app, press(KeyCode::Char('/')));
    for character in "nan".chars() {
        handle_key(&mut app, press(KeyCode::Char(character)));
    }
    assert_eq!(app.total_selected(), 4);
    assert_eq!(app.filter, "nan");
    assert_eq!(app.total_shown(), 0);
    assert!(app.rows.is_empty(), "the empty-state notice draws instead");
    handle_key(&mut app, press(KeyCode::Backspace));
    assert_eq!(app.filter, "na");
}

/// Esc backs out one layer at a time: the filter first, the screen second.
#[test]
fn esc_clears_a_filter_before_it_cancels() {
    let mut app = multichain_app();
    handle_key(&mut app, press(KeyCode::Char('c')));
    type_search(&mut app, "usdc");
    assert_eq!(handle_key(&mut app, press(KeyCode::Esc)), Outcome::Stay);
    assert!(!app.filtering(), "both filters cleared together");
    assert_eq!(handle_key(&mut app, press(KeyCode::Esc)), Outcome::Cancel);
}

#[test]
fn one_chain_has_nothing_to_narrow() {
    let mut app = app();
    handle_key(&mut app, press(KeyCode::Char('c')));
    assert_eq!(app.chain_filter(), None);
    assert!(app.notice.is_some_and(|notice| notice.contains("chain 1")));
}

#[test]
fn nothing_a_list_wrote_can_push_the_address_off_its_row() {
    // A row is clipped at the right edge, so what comes first is what survives
    // a terminal narrower than the row. The address, chain, and decimals are
    // what confirming actually decides and are the wallet's own text; the
    // symbol and name are the claim being judged. So the claim goes last. A
    // symbol wide enough to fill the screen — spaces count, and a stored
    // symbol may be sixty-four characters — can then cost the owner sight of
    // the curator's own text and never of the address it would name.
    let padded = ListedToken {
        symbol: format!("USDC{}X", " ".repeat(50)),
        name: Some("USD Coin".into()),
        ..token("USDC", 0x11)
    };
    let app = App::new(vec![TokenGroup {
        source: "hostile-list".into(),
        tokens: vec![padded],
    }]);
    let lines: Vec<Line> = app.lines().into_iter().map(|(line, _)| line).collect();
    let row = crate::fullscreen::lines_to_text(&lines, |text, _| text.to_owned());

    let address = Address::repeat_byte(0x11).to_checksum(None);
    let address_at = row.find(&address).expect("the row shows the address");
    for claim in ["USDC", "USD Coin"] {
        assert!(
            row.rfind(claim).expect("the row shows the claim") > address_at,
            "`{claim}` precedes the address it would name: {row}"
        );
    }
    // The derived facts are between them, so neither can be displaced either.
    assert!(row.find("chain 1").expect("the row shows the chain") > address_at);
    assert!(row.find("18 decimals").expect("the row shows decimals") > address_at);
}
