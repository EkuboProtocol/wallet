//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crossterm::event::KeyModifiers;

fn entry(alias: &str, chain_id: &str, note: Option<&str>) -> AddressBookEntry {
    AddressBookEntry {
        chain_id: chain_id.to_owned(),
        alias: alias.to_owned(),
        address: Address::repeat_byte(0xab).to_checksum(None),
        note: note.map(str::to_owned),
        added_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn networks() -> Vec<NetworkConfig> {
    crate::config::default_networks()
}

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn add_form() -> Form {
    Form::add(&networks()[0])
}

#[test]
fn the_form_reports_which_field_is_wrong_rather_than_failing_at_the_write() {
    let mut form = add_form();
    form.alias.set_value("not a valid alias!");
    form.address
        .set_value(Address::repeat_byte(0x11).to_checksum(None));
    let (field, _) = form.draft().expect_err("an invalid alias must not draft");
    assert_eq!(field, Field::Alias);

    form.alias.set_value("alice");
    form.address.set_value("0xnope");
    let (field, reason) = form.draft().expect_err("an invalid address must not draft");
    assert_eq!(field, Field::Address);
    assert!(reason.contains("20-byte"));

    // The note rules used to be enforced by the store, one screen later.
    form.address
        .set_value(Address::repeat_byte(0x11).to_checksum(None));
    form.note.set_value("payroll\u{202e}");
    let (field, _) = form.draft().expect_err("a bidi note must not draft");
    assert_eq!(field, Field::Note);
}

#[test]
fn a_valid_form_drafts_with_the_note_trimmed_away_when_empty() {
    let mut form = add_form();
    form.alias.set_value("  alice  ");
    form.address
        .set_value(Address::repeat_byte(0x11).to_checksum(None));
    form.note.set_value("   ");
    let draft = form.draft().expect("a valid form drafts");
    assert_eq!(draft.alias, "alice");
    assert_eq!(draft.note, None);
    assert_eq!(draft.chain_id, networks()[0].chain_id);

    form.note.set_value("  paid weekly  ");
    assert_eq!(
        form.draft().expect("still valid").note.as_deref(),
        Some("paid weekly")
    );
}

#[test]
fn editing_keeps_the_alias_and_chain_it_was_opened_on() {
    let networks = networks();
    let entry = entry("alice", &networks[0].chain_id.to_string(), Some("hi"));
    let form = Form::edit(&entry, &networks).expect("a stored entry opens");
    // The two values an edit cannot change are not fields, so no keystroke
    // can reach them: retargeting an alias is the reviewed change,
    // renaming one would be a different entry.
    assert_eq!(form.fields(), EDIT_FIELDS);
    assert_eq!(form.chain_id, networks[0].chain_id);
    let draft = form.draft().expect("the stored values are valid");
    assert_eq!(draft.alias, "alice");
    assert_eq!(draft.note.as_deref(), Some("hi"));
}

#[test]
fn the_form_cycles_focus_in_both_directions() {
    let mut form = add_form();
    assert_eq!(form.current(), Field::Network);
    form.previous_field();
    assert_eq!(form.current(), Field::Note, "wraps backwards to the last");
    form.next_field();
    assert_eq!(form.current(), Field::Network, "and forwards to the first");
}

#[test]
fn rows_name_the_chain_and_search_the_whole_record() {
    let networks = networks();
    let entries = vec![
        entry("alice", "1", Some("payroll")),
        entry("vault", "424242", None),
    ];
    let rows = rows(&networks, &entries, false);
    assert_eq!(rows[0].cells[0], Span::plain("alice"));
    assert_eq!(
        rows[0].cells[2],
        Span::plain(&networks[0].name),
        "a configured chain is named"
    );
    assert_eq!(
        rows[1].cells[2],
        Span::plain("chain 424242"),
        "an unconfigured chain falls back to its ID"
    );
    // The search matches values the columns may truncate: the full
    // address, the chain ID, and the note.
    assert!(
        rows[0]
            .haystack
            .contains(&Address::repeat_byte(0xab).to_checksum(None).to_lowercase())
    );
    assert!(rows[0].haystack.contains("payroll"));
    assert!(rows[1].haystack.contains("424242"));
}

#[test]
fn editor_keys_map_to_actions_and_never_steal_from_the_search() {
    let networks = networks();
    let entries = vec![entry("alice", "1", None), entry("bob", "1", None)];
    let mut list = SearchableTable::new(
        "Address book entries",
        columns(alias_column_width(&entries), false),
        rows(&networks, &entries, false),
    );

    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Char('a'))),
        Some(Action::Add)
    );
    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Char('e'))),
        Some(Action::Edit(0))
    );
    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Enter)),
        Some(Action::Edit(0)),
        "Enter edits, same as e"
    );
    handle_list_key(&mut list, press(KeyCode::Down));
    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Char('d'))),
        Some(Action::Remove(1))
    );
    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Delete)),
        Some(Action::Remove(1))
    );
    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Char('q'))),
        Some(Action::Quit)
    );

    // While a search is being typed, a/e/d are filter text, not actions.
    assert_eq!(handle_list_key(&mut list, press(KeyCode::Char('/'))), None);
    assert!(list.typing());
    assert_eq!(handle_list_key(&mut list, press(KeyCode::Char('a'))), None);
    assert_eq!(handle_list_key(&mut list, press(KeyCode::Char('d'))), None);
    // Confirming the search hands the keys back to the editor.
    assert_eq!(handle_list_key(&mut list, press(KeyCode::Enter)), None);
    assert!(!list.typing());
}

#[test]
fn an_empty_book_still_offers_add_and_quit() {
    let mut list = SearchableTable::new(
        "Address book entries",
        columns(alias_column_width(&[]), false),
        Vec::new(),
    );
    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Char('a'))),
        Some(Action::Add)
    );
    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Char('e'))),
        None,
        "nothing to edit"
    );
    assert_eq!(handle_list_key(&mut list, press(KeyCode::Char('d'))), None);
    assert_eq!(
        handle_list_key(&mut list, press(KeyCode::Esc)),
        Some(Action::Quit)
    );
}

#[test]
fn hints_carry_the_editor_bindings() {
    let networks = networks();
    let entries = vec![entry("alice", "1", None)];
    let mut list = SearchableTable::new(
        "Address book entries",
        columns(alias_column_width(&entries), false),
        rows(&networks, &entries, false),
    );
    for expected in ["a add", "d remove", "Enter edit", "/ search", "q quit"] {
        assert!(hints(&list).contains(expected), "missing {expected}");
    }
    handle_list_key(&mut list, press(KeyCode::Char('/')));
    handle_list_key(&mut list, press(KeyCode::Char('a')));
    assert!(hints(&list).starts_with("Search: a"));
    handle_list_key(&mut list, press(KeyCode::Enter));
    assert!(hints(&list).contains("Esc clear search"));
}

#[test]
fn a_small_screen_shortens_the_address_and_never_the_alias() {
    let networks = networks();
    let entries = vec![entry("payroll-alice", "1", Some("a fairly long note"))];
    let full = Address::repeat_byte(0xab).to_checksum(None);

    // The alias column is sized to its widest alias, so the fixed-width
    // address cannot squeeze it; the header sets the floor and 24 the
    // ceiling.
    assert_eq!(alias_column_width(&entries), 13);
    assert_eq!(alias_column_width(&[]), 5);
    assert_eq!(alias_column_width(&[entry(&"a".repeat(64), "1", None)]), 24);

    // Compact rows shorten the address around both checkable ends and
    // drop the Updated column; the search still holds the full value.
    let compact = rows(&networks, &entries, true);
    assert_eq!(compact[0].cells.len(), 4);
    let shortened = short_address(&full);
    assert_eq!(compact[0].cells[1], Span::plain(&shortened));
    assert!(shortened.starts_with(&full[..10]) && shortened.ends_with(&full[34..]));
    assert_eq!(
        crate::fullscreen::display_width(&shortened),
        usize::from(SHORT_ADDRESS_WIDTH)
    );
    assert!(compact[0].haystack.contains(&full.to_lowercase()));
    assert_eq!(rows(&networks, &entries, false)[0].cells.len(), 5);

    // A degenerate stored address is shown as-is rather than sliced.
    assert_eq!(short_address("0xshort"), "0xshort");

    // Column layouts match the rows they pair with.
    assert_eq!(columns(13, false).len(), 5);
    assert_eq!(columns(13, true).len(), 4);
    assert!(full_layout_min_width(13) > 13 + FULL_ADDRESS_WIDTH + UPDATED_WIDTH);
}
