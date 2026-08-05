//! Full-screen address book editor.
//!
//! The address book used to be edit-by-command-line only: `address-book add`
//! and `remove` with every value typed as an argument. This browser is the
//! interactive surface over the same store, built on [`crate::fullscreen`]:
//! a [`SearchableTable`] of every entry whose `/` search matches the record
//! itself (alias, full address, network, chain ID, note), with `a` to add,
//! `e` or Enter to edit, and `d` to remove.
//!
//! The browser is only ever navigation. Choosing an action leaves the
//! alternate screen first, and the change itself runs in the ordinary
//! scrollback flow — prompts, a [`crate::tui::Confirmation`] of the exact
//! values, and then platform owner authentication — so the facts of what was
//! changed stay in the terminal transcript exactly as the `address-book`
//! subcommands would leave them. Owner authentication is required because an
//! alias decides where an agent-resolved payment goes; see
//! [`crate::human_presence::PresenceRequest`].

use std::str::FromStr;

use alloy::primitives::Address;
use anyhow::{Context, Result, ensure};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Alignment, Constraint},
    text::{Line as UiLine, Span as UiSpan},
    widgets::Paragraph,
};

use crate::{
    address_book::{AddressBookEntry, AddressBookStore, MAX_NOTE_LEN, validate_alias},
    config::{ConfigStore, NetworkConfig},
    fullscreen::{
        Screen, SearchableTable, Span, TableColumn, TableEvent, TableRow, chrome, footer_line,
        is_interrupt, title_line, tone_style,
    },
    human_presence::{HumanPresence, PresenceRequest},
    tui::{self, Tone},
};

/// Everything a save needs, resolved before anything is shown or asked.
pub struct EntryDraft {
    pub chain_id: u64,
    /// The configured network name, or `chain N` when the chain is no longer
    /// configured — display only, never resolved back to a chain ID.
    pub network_name: String,
    pub alias: String,
    pub address: Address,
    pub note: Option<String>,
}

/// Confirm one alias save in the terminal, authenticate the owner, then
/// write it. `Ok(None)` means the user declined the terminal confirmation
/// and nothing changed; a declined owner prompt is an error, like everywhere
/// else the platform dialog is refused.
pub async fn confirm_and_save(
    config: &ConfigStore,
    presence: &dyn HumanPresence,
    draft: &EntryDraft,
) -> Result<Option<AddressBookEntry>> {
    let mut store = AddressBookStore::production(config.data_dir())?;
    let existing = store.get(draft.chain_id, &draft.alias)?;
    let checksummed = draft.address.to_checksum(None);
    let mut question = tui::Confirmation::new(
        if existing.is_some() {
            "Update address book entry"
        } else {
            "Add address book entry"
        },
        "Store this alias for agent lookups. Aliases carry no signing authority, but an agent \
         resolves payments the user names by alias to this exact address, so a yes here is \
         followed by the platform owner prompt.",
    )
    .fact("Network", &draft.network_name)
    .fact("Chain ID", draft.chain_id.to_string())
    .fact("Alias", &draft.alias)
    .fact("Address", &checksummed);
    if let Some(note) = &draft.note {
        question = question.fact("Note", note);
    }
    if let Some(existing) = &existing {
        if existing.address == checksummed {
            question = question.warning(format!(
                "This rewrites the existing entry for {}; the address is unchanged.",
                draft.alias
            ));
        } else {
            question = question.warning(format!(
                "This retargets {}: payments the user names by this alias will go to the address \
                 above instead of {}.",
                draft.alias, existing.address
            ));
        }
    }
    if !question.ask("Save this alias?")? {
        tui::outro_cancel("Address book unchanged.");
        return Ok(None);
    }
    presence
        .confirm(&PresenceRequest::SaveAddressBookEntry {
            alias: draft.alias.clone(),
        })
        .await?;
    Ok(Some(store.upsert(
        draft.chain_id,
        &draft.alias,
        draft.address,
        draft.note.as_deref(),
    )?))
}

/// Confirm one alias removal in the terminal, authenticate the owner, then
/// delete it. `Ok(None)` means the user declined and nothing changed.
pub async fn confirm_and_remove(
    config: &ConfigStore,
    presence: &dyn HumanPresence,
    network_name: &str,
    chain_id: u64,
    alias: &str,
) -> Result<Option<AddressBookEntry>> {
    let mut store = AddressBookStore::production(config.data_dir())?;
    let existing = store
        .get(chain_id, alias)?
        .with_context(|| format!("no address book entry {alias} on chain {chain_id}"))?;
    if !tui::Confirmation::new(
        "Remove address book entry",
        "Remove this alias from agent lookups. A yes here is followed by the platform owner \
         prompt.",
    )
    .fact("Network", network_name)
    .fact("Chain ID", chain_id.to_string())
    .fact("Alias", alias)
    .fact("Address", &existing.address)
    .ask("Remove this alias?")?
    {
        tui::outro_cancel("Address book unchanged.");
        return Ok(None);
    }
    presence
        .confirm(&PresenceRequest::RemoveAddressBookEntry {
            alias: alias.to_owned(),
        })
        .await?;
    Ok(Some(store.remove(chain_id, alias)?))
}

/// What the list screen resolved to, performed after the alternate screen is
/// released.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Add,
    Edit(usize),
    Remove(usize),
    Quit,
}

/// Interactive loop: browse the entries, drop to the scrollback flow for
/// each change, return to the refreshed list.
pub async fn browse(config: &ConfigStore, presence: &dyn HumanPresence) -> Result<()> {
    if !tui::interactive() {
        return Ok(());
    }
    loop {
        let networks = config.load()?.networks;
        let entries = AddressBookStore::production(config.data_dir())?.list(None, 10_000, 0)?;
        let outcome = match pick_action(&networks, &entries)? {
            Action::Quit => return Ok(()),
            Action::Add => add_flow(config, presence, &networks).await,
            Action::Edit(index) => edit_flow(config, presence, &networks, &entries[index]).await,
            Action::Remove(index) => {
                remove_flow(config, presence, &networks, &entries[index]).await
            }
        };
        // A failed change (declined owner authentication above all) should
        // not tear down the browser; report it and return to the list.
        if let Err(error) = outcome {
            tui::warning(format!("Address book change did not complete: {error:#}"));
        }
    }
}

/// Run the list screen until the user chooses something to do. The
/// [`Screen`] guard is released before this returns, so the caller's flows
/// draw on the ordinary terminal.
fn pick_action(networks: &[NetworkConfig], entries: &[AddressBookEntry]) -> Result<Action> {
    let mut list = SearchableTable::new("Address book entries", columns(), rows(networks, entries));
    let mut screen = Screen::enter()?;
    loop {
        screen.terminal.draw(|frame| {
            let (header, body, footer) = chrome(frame.area());
            frame.render_widget(title_line(&list.title()), header);
            if entries.is_empty() {
                // The table's own empty state says "no rows match the
                // search"; an empty book deserves the invitation instead.
                frame.render_widget(
                    Paragraph::new(UiLine::from(UiSpan::styled(
                        "The address book is empty — press a to add the first alias.",
                        tone_style(Tone::Muted),
                    )))
                    .alignment(Alignment::Center),
                    body,
                );
            } else {
                list.draw(frame, body);
            }
            frame.render_widget(footer_line(None, &hints(&list)), footer);
        })?;
        let key = match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => key,
            // Anything else — a resize above all — just redraws against the
            // new terminal size.
            _ => continue,
        };
        if is_interrupt(key) {
            return Ok(Action::Quit);
        }
        if let Some(action) = handle_list_key(&mut list, key) {
            return Ok(action);
        }
    }
}

/// The editor's own bindings first — but never while the `/` search is being
/// typed, where every letter belongs to the filter — then the table's
/// navigation. Enter and `e` both edit: for a record this small the detail
/// view and the edit form are the same screen.
fn handle_list_key(list: &mut SearchableTable, key: KeyEvent) -> Option<Action> {
    if !list.typing() {
        match key.code {
            KeyCode::Char('a') => return Some(Action::Add),
            KeyCode::Char('e') => return list.selected().map(Action::Edit),
            KeyCode::Char('d') | KeyCode::Delete => return list.selected().map(Action::Remove),
            _ => {}
        }
    }
    match list.handle_key(key) {
        TableEvent::Stay => None,
        TableEvent::Quit => Some(Action::Quit),
        TableEvent::Picked(index) => Some(Action::Edit(index)),
    }
}

fn hints(list: &SearchableTable) -> String {
    if list.typing() {
        // The search-editing footer already explains itself.
        return list.footer_hints("edit");
    }
    let search = if list.searching() {
        "/ edit search · Esc clear search"
    } else {
        "/ search"
    };
    format!("↑↓ select · Enter edit · a add · d remove · {search} · q quit")
}

fn columns() -> Vec<TableColumn> {
    vec![
        TableColumn::new("Alias", Constraint::Fill(1)),
        TableColumn::new("Address", Constraint::Length(42)),
        TableColumn::new("Network", Constraint::Fill(1)),
        TableColumn::new("Note", Constraint::Fill(1)),
        TableColumn::new("Updated", Constraint::Length(14)),
    ]
}

/// The network column names the chain when it is still configured and falls
/// back to the raw chain ID otherwise.
fn network_label(networks: &[NetworkConfig], chain_id: &str) -> String {
    networks
        .iter()
        .find(|network| network.chain_id.to_string() == *chain_id)
        .map_or_else(
            || format!("chain {chain_id}"),
            |network| network.name.clone(),
        )
}

fn rows(networks: &[NetworkConfig], entries: &[AddressBookEntry]) -> Vec<TableRow> {
    entries
        .iter()
        .map(|entry| {
            let network = network_label(networks, &entry.chain_id);
            let updated = chrono::DateTime::parse_from_rfc3339(&entry.updated_at).map_or_else(
                |_| "—".to_owned(),
                |when| crate::render::relative_time(when.with_timezone(&chrono::Utc)),
            );
            let cells = vec![
                Span::plain(&entry.alias),
                Span::plain(&entry.address),
                Span::plain(&network),
                entry
                    .note
                    .as_deref()
                    .map_or_else(|| Span::toned("—", Tone::Muted), Span::plain),
                Span::toned(updated, Tone::Muted),
            ];
            TableRow::new(
                cells,
                &[
                    &entry.alias,
                    &entry.address,
                    &network,
                    &entry.chain_id,
                    entry.note.as_deref().unwrap_or(""),
                ],
            )
        })
        .collect()
}

/// The scrollback add flow: pick a network, name the alias, type the
/// address, optionally note it, then confirm and authenticate.
async fn add_flow(
    config: &ConfigStore,
    presence: &dyn HumanPresence,
    networks: &[NetworkConfig],
) -> Result<()> {
    ensure!(!networks.is_empty(), "no networks are configured");
    tui::init_prompt_theme();
    tui::intro("Add address book entry");
    let labels = networks
        .iter()
        .map(|network| format!("{} (chain {})", network.name, network.chain_id))
        .collect();
    let Some(index) = tui::pick("Network", labels, crate::render::interactive_list_rows(6))? else {
        cancelled();
        return Ok(());
    };
    let network = &networks[index];
    let Some(alias) = prompt_alias()? else {
        cancelled();
        return Ok(());
    };
    let Some(address) = prompt_address(None)? else {
        cancelled();
        return Ok(());
    };
    let NotePrompt::Value(note) = prompt_note(None)? else {
        cancelled();
        return Ok(());
    };
    let draft = EntryDraft {
        chain_id: network.chain_id,
        network_name: network.name.clone(),
        alias,
        address,
        note,
    };
    if let Some(entry) = confirm_and_save(config, presence, &draft).await? {
        tui::outro(format!(
            "Stored {} → {} on chain {}.",
            entry.alias, entry.address, entry.chain_id
        ));
    }
    Ok(())
}

/// The scrollback edit flow: the alias and chain stay what they are; the
/// address and note are retyped starting from their current values.
async fn edit_flow(
    config: &ConfigStore,
    presence: &dyn HumanPresence,
    networks: &[NetworkConfig],
    entry: &AddressBookEntry,
) -> Result<()> {
    tui::init_prompt_theme();
    tui::intro(format!("Edit address book entry {}", entry.alias));
    let chain_id: u64 = entry
        .chain_id
        .parse()
        .context("stored chain ID is invalid")?;
    let Some(address) = prompt_address(Some(&entry.address))? else {
        cancelled();
        return Ok(());
    };
    let NotePrompt::Value(note) = prompt_note(entry.note.as_deref())? else {
        cancelled();
        return Ok(());
    };
    let draft = EntryDraft {
        chain_id,
        network_name: network_label(networks, &entry.chain_id),
        alias: entry.alias.clone(),
        address,
        note,
    };
    if let Some(entry) = confirm_and_save(config, presence, &draft).await? {
        tui::outro(format!(
            "Stored {} → {} on chain {}.",
            entry.alias, entry.address, entry.chain_id
        ));
    }
    Ok(())
}

async fn remove_flow(
    config: &ConfigStore,
    presence: &dyn HumanPresence,
    networks: &[NetworkConfig],
    entry: &AddressBookEntry,
) -> Result<()> {
    tui::init_prompt_theme();
    let chain_id: u64 = entry
        .chain_id
        .parse()
        .context("stored chain ID is invalid")?;
    if let Some(removed) = confirm_and_remove(
        config,
        presence,
        &network_label(networks, &entry.chain_id),
        chain_id,
        &entry.alias,
    )
    .await?
    {
        tui::outro(format!(
            "Removed {} → {} from chain {}.",
            removed.alias, removed.address, removed.chain_id
        ));
    }
    Ok(())
}

/// A backed-out prompt: say so once and leave the flow without an error.
fn cancelled() {
    tui::outro_cancel("Address book unchanged.");
}

/// `Ok(None)` means the user backed out with Esc or Ctrl+C.
fn prompt_alias() -> Result<Option<String>> {
    Ok(tui::optional(
        inquire::Text::new(&tui::question("Alias"))
            .with_placeholder("alice")
            .with_help_message("1-64 letters, numbers, underscores, hyphens, or periods")
            .with_validator(|value: &str| {
                Ok(match validate_alias(value.trim()) {
                    Ok(()) => inquire::validator::Validation::Valid,
                    Err(error) => inquire::validator::Validation::Invalid(error.to_string().into()),
                })
            })
            .prompt(),
    )?
    .map(|alias| alias.trim().to_owned()))
}

fn prompt_address(initial: Option<&str>) -> Result<Option<Address>> {
    let message = tui::question("Address");
    let mut prompt = inquire::Text::new(&message)
        .with_placeholder("0x…")
        .with_validator(|value: &str| {
            Ok(if Address::from_str(value.trim()).is_ok() {
                inquire::validator::Validation::Valid
            } else {
                inquire::validator::Validation::Invalid("must be a 20-byte EVM address".into())
            })
        });
    if let Some(initial) = initial {
        prompt = prompt.with_initial_value(initial);
    }
    Ok(tui::optional(prompt.prompt())?
        .map(|address| Address::from_str(address.trim()).expect("validated above")))
}

/// A note prompt answered with nothing is an entry without a note; backing
/// out with Esc is not an answer at all, and the two must not read alike.
enum NotePrompt {
    Cancelled,
    Value(Option<String>),
}

fn prompt_note(initial: Option<&str>) -> Result<NotePrompt> {
    let message = tui::question("Note");
    let mut prompt = inquire::Text::new(&message)
        .with_help_message("Optional — leave empty for none")
        .with_validator(|value: &str| {
            Ok(if value.chars().any(char::is_control) {
                inquire::validator::Validation::Invalid("cannot contain control characters".into())
            } else if value.len() > MAX_NOTE_LEN {
                inquire::validator::Validation::Invalid(
                    format!("must be at most {MAX_NOTE_LEN} bytes").into(),
                )
            } else {
                inquire::validator::Validation::Valid
            })
        });
    if let Some(initial) = initial {
        prompt = prompt.with_initial_value(initial);
    }
    Ok(
        tui::optional(prompt.prompt())?.map_or(NotePrompt::Cancelled, |note| {
            let note = note.trim().to_owned();
            NotePrompt::Value(if note.is_empty() { None } else { Some(note) })
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn entry(alias: &str, chain_id: &str, note: Option<&str>) -> AddressBookEntry {
        AddressBookEntry {
            chain_id: chain_id.to_owned(),
            alias: alias.to_owned(),
            address: Address::repeat_byte(0xab).to_checksum(None),
            note: note.map(str::to_owned),
            added_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    fn networks() -> Vec<NetworkConfig> {
        crate::config::default_networks()
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn rows_name_the_chain_and_search_the_whole_record() {
        let networks = networks();
        let entries = vec![
            entry("alice", "1", Some("payroll")),
            entry("vault", "424242", None),
        ];
        let rows = rows(&networks, &entries);
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
        let mut list =
            SearchableTable::new("Address book entries", columns(), rows(&networks, &entries));

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
        let mut list = SearchableTable::new("Address book entries", columns(), Vec::new());
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
        let mut list =
            SearchableTable::new("Address book entries", columns(), rows(&networks, &entries));
        for expected in ["a add", "d remove", "Enter edit", "/ search", "q quit"] {
            assert!(hints(&list).contains(expected), "missing {expected}");
        }
        handle_list_key(&mut list, press(KeyCode::Char('/')));
        handle_list_key(&mut list, press(KeyCode::Char('a')));
        assert!(hints(&list).starts_with("Search: a"));
        handle_list_key(&mut list, press(KeyCode::Enter));
        assert!(hints(&list).contains("Esc clear search"));
    }
}
