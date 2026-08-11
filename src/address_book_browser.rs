//! Full-screen address book editor.
//!
//! The address book used to be edit-by-command-line only: `settings address-book add`
//! and `remove` with every value typed as an argument. This browser is the
//! interactive surface over the same store, built on [`crate::fullscreen`]:
//! a [`SearchableTable`] of every entry whose `/` search matches the record
//! itself (alias, full address, network, chain ID, note), with `a` to add,
//! `e` or Enter to edit, and `d` to remove.
//!
//! Every screen the editor shows is drawn in the one alternate screen it
//! opens. It used to leave that screen for each change and run the whole
//! sequence — an intro, a network pick, three prompts, a confirmation block,
//! an outro — as inline viewports in the scrollback, then re-enter. Each of
//! those prompts printed the line it had answered, so a session accumulated a
//! transcript of half-finished forms that was still on the screen after the
//! browser exited, and every step flipped the terminal between two modes.
//!
//! The list, the form, the network pick, and the confirmation are now views of
//! one app. What still reaches the scrollback is one line per completed
//! change, printed after the browser exits: the facts of what was changed
//! belong in the terminal transcript exactly as the `settings address-book`
//! subcommands would leave them, and a form that was abandoned is not a fact.
//!
//! The alternate screen is released around platform owner authentication and
//! restored afterwards. That is the one unavoidable handover: a polkit text
//! agent prompts on the terminal this app is drawing on. Owner authentication
//! is required at all because an alias decides where an agent-resolved payment
//! goes; see [`crate::human_presence::PresenceRequest`].

use std::str::FromStr;

use alloy::primitives::Address;
use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint},
    text::{Line as UiLine, Span as UiSpan},
    widgets::Paragraph,
};

use crate::{
    address_book::{AddressBookEntry, AddressBookStore, MAX_NOTE_LEN, validate_alias},
    config::{ConfigStore, NetworkConfig},
    fullscreen::{
        Screen, SearchableTable, Span, TableColumn, TableEvent, TableRow, TextField, chrome,
        footer_line, is_interrupt, title_line, tone_style, ui_span, wrap_lines,
    },
    human_presence::{HumanPresence, PresenceRequest},
    tui::{self, Tone},
};
use ratatui::layout::Layout;

/// Everything a save needs, resolved before anything is shown or asked.
#[derive(Debug)]
pub struct EntryDraft {
    pub chain_id: u64,
    /// The configured network name, or `chain N` when the chain is no longer
    /// configured — display only, never resolved back to a chain ID.
    pub network_name: String,
    pub alias: String,
    pub address: Address,
    pub note: Option<String>,
}

/// Everything a reviewer is told before one address-book change.
///
/// Built once and rendered two ways — as a [`tui::Confirmation`] for the
/// one-shot `settings address-book` subcommands, and as a view inside the browser's
/// own screen. One producer per change, so the two surfaces cannot drift into
/// describing the same write differently.
struct Review {
    title: &'static str,
    summary: &'static str,
    facts: Vec<(String, String)>,
    warnings: Vec<String>,
    question: &'static str,
    /// The affirmative option under `question` in the in-screen rendering.
    accept_label: &'static str,
}

impl Review {
    /// The scrollback rendering: intro, facts, warnings, and a yes/no.
    fn ask(&self) -> Result<bool> {
        let mut question = tui::Confirmation::new(self.title, self.summary);
        for (label, value) in &self.facts {
            question = question.fact(label, value);
        }
        for warning in &self.warnings {
            question = question.warning(warning);
        }
        question.ask(self.question)
    }

    /// The in-screen rendering: the same text as a scrollable document.
    fn document(&self) -> Vec<crate::fullscreen::Line> {
        let mut lines = vec![vec![Span::toned(self.summary, Tone::Muted)], Vec::new()];
        for (label, value) in &self.facts {
            lines.push(vec![
                Span::toned(format!("{label}: "), Tone::Muted),
                Span::plain(value),
            ]);
        }
        for warning in &self.warnings {
            lines.push(Vec::new());
            lines.push(vec![Span::toned(format!("⚠ {warning}"), Tone::Warning)]);
        }
        lines
    }
}

fn save_review(draft: &EntryDraft, existing: Option<&AddressBookEntry>) -> Review {
    let checksummed = draft.address.to_checksum(None);
    let mut facts = vec![
        ("Network".to_owned(), draft.network_name.clone()),
        ("Chain ID".to_owned(), draft.chain_id.to_string()),
        ("Alias".to_owned(), draft.alias.clone()),
        ("Address".to_owned(), checksummed.clone()),
    ];
    if let Some(note) = &draft.note {
        facts.push(("Note".to_owned(), note.clone()));
    }
    let mut warnings = Vec::new();
    if let Some(existing) = existing {
        if existing.address == checksummed {
            warnings.push(format!(
                "This rewrites the existing entry for {}; the address is unchanged.",
                draft.alias
            ));
        } else {
            warnings.push(format!(
                "This retargets {}: payments the user names by this alias will go to the address \
                 above instead of {}.",
                draft.alias, existing.address
            ));
        }
    }
    Review {
        title: if existing.is_some() {
            "Update address book entry"
        } else {
            "Add address book entry"
        },
        summary: "Store this alias for agent lookups. Aliases carry no signing authority, but an \
                  agent resolves payments the user names by alias to this exact address, so a yes \
                  here is followed by the platform owner prompt.",
        facts,
        warnings,
        question: "Save this alias?",
        accept_label: "Save this alias",
    }
}

fn remove_review(existing: &AddressBookEntry, network_name: &str, chain_id: u64) -> Review {
    Review {
        title: "Remove address book entry",
        summary: "Remove this alias from agent lookups. A yes here is followed by the platform \
                  owner prompt.",
        facts: vec![
            ("Network".to_owned(), network_name.to_owned()),
            ("Chain ID".to_owned(), chain_id.to_string()),
            ("Alias".to_owned(), existing.alias.clone()),
            ("Address".to_owned(), existing.address.clone()),
        ],
        warnings: Vec::new(),
        question: "Remove this alias?",
        accept_label: "Remove this alias",
    }
}

/// Authenticate the owner and write. The terminal confirmation happened
/// before this — in the scrollback for the subcommands, in-screen for the
/// browser — so this is only the part both paths share.
async fn save_entry(
    config: &ConfigStore,
    presence: &dyn HumanPresence,
    draft: &EntryDraft,
) -> Result<AddressBookEntry> {
    presence
        .confirm(&PresenceRequest::SaveAddressBookEntry {
            alias: draft.alias.clone(),
        })
        .await?;
    AddressBookStore::production(config.data_dir())?.upsert(
        draft.chain_id,
        &draft.alias,
        draft.address,
        draft.note.as_deref(),
    )
}

async fn remove_entry(
    config: &ConfigStore,
    presence: &dyn HumanPresence,
    chain_id: u64,
    alias: &str,
) -> Result<AddressBookEntry> {
    presence
        .confirm(&PresenceRequest::RemoveAddressBookEntry {
            alias: alias.to_owned(),
        })
        .await?;
    AddressBookStore::production(config.data_dir())?.remove(chain_id, alias)
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
    let existing =
        AddressBookStore::production(config.data_dir())?.get(draft.chain_id, &draft.alias)?;
    if !save_review(draft, existing.as_ref()).ask()? {
        tui::outro_cancel("Address book unchanged.");
        return Ok(None);
    }
    save_entry(config, presence, draft).await.map(Some)
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
    let existing = AddressBookStore::production(config.data_dir())?
        .get_for_removal(chain_id, alias)?
        .with_context(|| format!("no address book entry {alias} on chain {chain_id}"))?;
    if !remove_review(&existing, network_name, chain_id).ask()? {
        tui::outro_cancel("Address book unchanged.");
        return Ok(None);
    }
    remove_entry(config, presence, chain_id, alias)
        .await
        .map(Some)
}

/// Which screen the editor is showing.
///
/// One app, four views. The form and the confirmation used to be scrollback
/// prompts run after the screen was released, which is what left half-typed
/// forms in the terminal after the browser exited.
enum View {
    List,
    Form(Form),
    /// The network pick, reached from the form's first row. A sub-view rather
    /// than a nested call, so it draws in the same screen.
    Networks(Box<NetworkPicker>),
    Confirm(Confirm),
}

/// One network list and the exact configuration snapshot its row indexes name.
///
/// The browser's outer network list may be older than the one loaded when this
/// picker opens. Keeping only a positional answer let a row from the fresh list
/// index the older one, so a concurrent reorder selected a different chain (or
/// indexed past the end). The rows and their identities now travel together.
struct NetworkPicker {
    table: SearchableTable,
    networks: Vec<NetworkConfig>,
}

impl NetworkPicker {
    fn load(config: &ConfigStore) -> Result<Self> {
        let networks = config.load()?.networks;
        let table = network_picker(&networks);
        Ok(Self { table, networks })
    }

    fn picked(&self, index: usize) -> Option<&NetworkConfig> {
        self.networks.get(index)
    }
}

/// A change the owner has confirmed in-screen and not yet authenticated.
enum Pending {
    Save(EntryDraft),
    Remove { chain_id: u64, alias: String },
}

struct Confirm {
    review: Review,
    pending: Pending,
    /// Which of the two options the cursor is on. Starts on the refusal: the
    /// affirmative answer is always the one that has to be reached for.
    accept: bool,
    offset: usize,
}

/// Which value the form's cursor is on. An edit keeps the alias and the chain
/// the entry already has — retargeting an alias is the change being reviewed,
/// renaming one is a different entry — so those two rows are facts there and
/// fields only when adding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Network,
    Alias,
    Address,
    Note,
}

const ADD_FIELDS: &[Field] = &[Field::Network, Field::Alias, Field::Address, Field::Note];
const EDIT_FIELDS: &[Field] = &[Field::Address, Field::Note];

struct Form {
    adding: bool,
    chain_id: u64,
    network_name: String,
    alias: TextField,
    address: TextField,
    note: TextField,
    focus: usize,
    error: Option<String>,
}

impl Form {
    fn add(network: &NetworkConfig) -> Self {
        Self {
            adding: true,
            chain_id: network.chain_id,
            network_name: network.name.clone(),
            alias: TextField::new("Alias").placeholder("alice"),
            address: TextField::new("Address").placeholder("0x…"),
            note: TextField::new("Note").placeholder("optional"),
            focus: 0,
            error: None,
        }
    }

    fn edit(entry: &AddressBookEntry, networks: &[NetworkConfig]) -> Result<Self> {
        Ok(Self {
            adding: false,
            chain_id: entry
                .chain_id
                .parse()
                .context("stored chain ID is invalid")?,
            network_name: network_label(networks, &entry.chain_id),
            alias: TextField::new("Alias").with_value(&entry.alias),
            address: TextField::new("Address").with_value(&entry.address),
            note: TextField::new("Note")
                .placeholder("optional")
                .with_value(entry.note.clone().unwrap_or_default()),
            focus: 0,
            error: None,
        })
    }

    const fn fields(&self) -> &'static [Field] {
        if self.adding { ADD_FIELDS } else { EDIT_FIELDS }
    }

    fn current(&self) -> Field {
        self.fields()[self.focus.min(self.fields().len() - 1)]
    }

    fn field_mut(&mut self, field: Field) -> Option<&mut TextField> {
        match field {
            Field::Alias => Some(&mut self.alias),
            Field::Address => Some(&mut self.address),
            Field::Note => Some(&mut self.note),
            Field::Network => None,
        }
    }

    fn next_field(&mut self) {
        self.focus = (self.focus + 1) % self.fields().len();
    }

    fn previous_field(&mut self) {
        let count = self.fields().len();
        self.focus = (self.focus + count - 1) % count;
    }

    /// Everything the store would refuse, checked here so the owner is told
    /// which field is wrong while they are still looking at it — rather than
    /// at the write, which is where the note rules used to surface.
    fn draft(&self) -> std::result::Result<EntryDraft, (Field, String)> {
        let alias = self.alias.value().trim().to_owned();
        validate_alias(&alias).map_err(|error| (Field::Alias, error.to_string()))?;
        let address = Address::from_str(self.address.value().trim())
            .map_err(|_| (Field::Address, "must be a 20-byte EVM address".to_owned()))?;
        let note = self.note.value().trim();
        if note.chars().any(ekubo_wallet_core::sanitize::is_disallowed) {
            return Err((
                Field::Note,
                "cannot contain control, bidirectional, or zero-width characters".to_owned(),
            ));
        }
        if note.len() > MAX_NOTE_LEN {
            return Err((Field::Note, format!("must be at most {MAX_NOTE_LEN} bytes")));
        }
        Ok(EntryDraft {
            chain_id: self.chain_id,
            network_name: self.network_name.clone(),
            alias,
            address,
            note: (!note.is_empty()).then(|| note.to_owned()),
        })
    }

    fn focus_on(&mut self, field: Field) {
        if let Some(index) = self
            .fields()
            .iter()
            .position(|candidate| *candidate == field)
        {
            self.focus = index;
        }
    }
}

/// Interactive loop: browse, add, edit, and remove without ever leaving the
/// screen, except to hand the terminal to platform owner authentication.
pub async fn browse(config: &ConfigStore, presence: &dyn HumanPresence) -> Result<()> {
    if !tui::interactive() {
        return Ok(());
    }
    let mut networks = config.load()?.networks;
    let mut entries = AddressBookStore::production(config.data_dir())?.list(None, 10_000, 0)?;
    let mut list = build_list(&networks, &entries);
    let mut view = View::List;
    let mut compact = false;
    // Printed after the screen is gone. A completed change is a fact worth
    // keeping in the transcript; a form the owner backed out of is not.
    let mut transcript: Vec<String> = Vec::new();
    // Shown in the list footer until the next keystroke: a change that did not
    // complete has to be visible without printing onto the screen it happened
    // on, which is the defect this module fixed.
    let mut notice: Option<String> = None;
    let mut screen = Screen::enter()?;

    let outcome = loop {
        let wants_compact =
            screen.terminal.size()?.width < full_layout_min_width(alias_column_width(&entries));
        if wants_compact != compact {
            compact = wants_compact;
            let alias_width = alias_column_width(&entries);
            list.set_columns(columns(alias_width, compact));
            list.set_rows(rows(&networks, &entries, compact));
        }
        if let Err(error) = screen.terminal.draw(|frame| match &mut view {
            View::List => draw_list(frame, &mut list, &entries, notice.as_deref()),
            View::Form(form) => draw_form(frame, form),
            View::Networks(picker) => draw_networks(frame, &mut picker.table),
            View::Confirm(confirm) => draw_confirm(frame, confirm),
        }) {
            break Err(error.into());
        }
        let key = match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => key,
            // A resize above all: redraw against the new size.
            Ok(_) => continue,
            Err(error) => break Err(error.into()),
        };
        if is_interrupt(key) {
            break Ok(());
        }

        match &mut view {
            View::List => {
                // Any keystroke acknowledges whatever the footer was showing.
                notice = None;
                match handle_list_key(&mut list, key) {
                    Some(Action::Quit) => break Ok(()),
                    Some(Action::Add) => {
                        if let Some(network) = networks.first() {
                            view = View::Form(Form::add(network));
                        } else {
                            notice = Some("No networks are configured.".to_owned());
                        }
                    }
                    Some(Action::Edit(index)) => match Form::edit(&entries[index], &networks) {
                        Ok(form) => view = View::Form(form),
                        Err(error) => break Err(error),
                    },
                    Some(Action::Remove(index)) => {
                        let entry = &entries[index];
                        match entry.chain_id.parse::<u64>() {
                            Ok(chain_id) => {
                                view = View::Confirm(Confirm {
                                    review: remove_review(
                                        entry,
                                        &network_label(&networks, &entry.chain_id),
                                        chain_id,
                                    ),
                                    pending: Pending::Remove {
                                        chain_id,
                                        alias: entry.alias.clone(),
                                    },
                                    accept: false,
                                    offset: 0,
                                });
                            }
                            Err(_) => break Err(anyhow::anyhow!("stored chain ID is invalid")),
                        }
                    }
                    None => {}
                }
            }
            View::Form(form) => {
                if let Some(next) = handle_form_key(form, config, key)? {
                    view = next;
                }
            }
            View::Networks(picker) => match picker.table.handle_key(key) {
                TableEvent::Stay => {}
                TableEvent::Quit => view = View::List,
                TableEvent::Picked(index) => {
                    // The picker is only ever opened from an add form, and the
                    // form is rebuilt around the chosen network so the chain
                    // and its display name cannot disagree. Resolve the row
                    // against the snapshot that drew it, not the browser's
                    // older outer snapshot.
                    let network = picker
                        .picked(index)
                        .context("the selected network is no longer in the picker")?;
                    let mut form = Form::add(network);
                    form.focus_on(Field::Alias);
                    view = View::Form(form);
                }
            },
            View::Confirm(confirm) => match handle_confirm_key(confirm, key) {
                ConfirmOutcome::Stay => {}
                ConfirmOutcome::Cancel => view = View::List,
                ConfirmOutcome::Accept => {
                    // The one handover: a polkit text agent prompts on this
                    // terminal, so the alternate screen has to be released
                    // around it and restored afterwards.
                    let View::Confirm(confirm) = std::mem::replace(&mut view, View::List) else {
                        unreachable!("matched above")
                    };
                    drop(screen);
                    let applied = apply(config, presence, confirm.pending).await;
                    screen = Screen::enter()?;
                    match applied {
                        Ok(line) => transcript.push(line),
                        // A declined owner prompt is the ordinary case here,
                        // not a reason to tear the browser down.
                        Err(error) => {
                            notice = Some(format!("Change did not complete: {error:#}"));
                        }
                    }
                    networks = config.load()?.networks;
                    entries =
                        AddressBookStore::production(config.data_dir())?.list(None, 10_000, 0)?;
                    list = build_list(&networks, &entries);
                    compact = false;
                }
            },
        }
    };

    drop(screen);
    for line in transcript {
        tui::outro(line);
    }
    outcome
}

fn build_list(networks: &[NetworkConfig], entries: &[AddressBookEntry]) -> SearchableTable {
    let alias_width = alias_column_width(entries);
    SearchableTable::new(
        "Address book entries",
        columns(alias_width, false),
        rows(networks, entries, false),
    )
}

async fn apply(
    config: &ConfigStore,
    presence: &dyn HumanPresence,
    pending: Pending,
) -> Result<String> {
    match pending {
        Pending::Save(draft) => {
            let entry = save_entry(config, presence, &draft).await?;
            Ok(format!(
                "Stored {} → {} on chain {}.",
                crate::render::terminal_safe_line(&entry.alias),
                entry.address,
                entry.chain_id
            ))
        }
        Pending::Remove { chain_id, alias } => {
            let removed = remove_entry(config, presence, chain_id, &alias).await?;
            Ok(format!(
                "Removed {} → {} from chain {}.",
                crate::render::terminal_safe_line(&removed.alias),
                removed.address,
                removed.chain_id
            ))
        }
    }
}

fn draw_list(
    frame: &mut ratatui::Frame,
    list: &mut SearchableTable,
    entries: &[AddressBookEntry],
    notice: Option<&str>,
) {
    let (header, body, footer) = chrome(frame.area());
    frame.render_widget(title_line(&list.title()), header);
    if entries.is_empty() {
        // The table's own empty state says "no rows match the search"; an
        // empty book deserves the invitation instead.
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
    frame.render_widget(footer_line(notice, &hints(list)), footer);
}

fn draw_networks(frame: &mut ratatui::Frame, picker: &mut SearchableTable) {
    let (header, body, footer) = chrome(frame.area());
    frame.render_widget(title_line(&picker.title()), header);
    picker.draw(frame, body);
    frame.render_widget(footer_line(None, &picker.footer_hints("choose")), footer);
}

fn draw_form(frame: &mut ratatui::Frame, form: &Form) {
    let (header, body, footer) = chrome(frame.area());
    frame.render_widget(
        title_line(if form.adding {
            "Add address book entry"
        } else {
            "Edit address book entry"
        }),
        header,
    );
    let [pad, rows_area, rest] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(u16::try_from(form.fields().len() + 2).unwrap_or(6)),
        Constraint::Fill(1),
    ])
    .areas(body);
    let _ = pad;
    let mut cursor = rows_area;
    cursor.height = 1;
    let mut next_row =
        |frame: &mut ratatui::Frame,
         render: &mut dyn FnMut(&mut ratatui::Frame, ratatui::layout::Rect)| {
            render(frame, cursor);
            cursor.y = cursor.y.saturating_add(1);
        };
    // The two values an edit cannot change are shown as facts, in the same
    // place the add form has them as fields, so the screens read alike.
    if !form.adding {
        let network = form.network_name.clone();
        let chain = form.chain_id;
        let alias = form.alias.value().to_owned();
        next_row(frame, &mut |frame, area| {
            frame.render_widget(
                Paragraph::new(UiLine::from(vec![
                    UiSpan::styled("Network: ", tone_style(Tone::Muted)),
                    UiSpan::raw(crate::render::terminal_safe_line(&network)),
                    UiSpan::styled(format!(" (chain {chain})"), tone_style(Tone::Muted)),
                ])),
                area,
            );
        });
        next_row(frame, &mut |frame, area| {
            frame.render_widget(
                Paragraph::new(UiLine::from(vec![
                    UiSpan::styled("Alias: ", tone_style(Tone::Muted)),
                    UiSpan::raw(crate::render::terminal_safe_line(&alias)),
                ])),
                area,
            );
        });
    }
    for (index, field) in form.fields().iter().enumerate() {
        let focused = index == form.focus;
        match field {
            Field::Network => {
                let network = form.network_name.clone();
                let chain = form.chain_id;
                next_row(frame, &mut |frame, area| {
                    frame.render_widget(
                        Paragraph::new(UiLine::from(vec![
                            UiSpan::styled(
                                "Network: ",
                                if focused {
                                    tone_style(Tone::Emphasis)
                                } else {
                                    tone_style(Tone::Muted)
                                },
                            ),
                            UiSpan::raw(crate::render::terminal_safe_line(&network)),
                            UiSpan::styled(
                                format!(" (chain {chain}) — Enter to change"),
                                tone_style(Tone::Muted),
                            ),
                        ])),
                        area,
                    );
                });
            }
            Field::Alias => {
                let text = &form.alias;
                next_row(frame, &mut |frame, area| text.draw(frame, area, focused));
            }
            Field::Address => {
                let text = &form.address;
                next_row(frame, &mut |frame, area| text.draw(frame, area, focused));
            }
            Field::Note => {
                let text = &form.note;
                next_row(frame, &mut |frame, area| text.draw(frame, area, focused));
            }
        }
    }
    let status = form.error.as_ref().map_or_else(
        || match form.current() {
            Field::Network => "The chain this alias resolves on.".to_owned(),
            Field::Alias => "1-64 letters, numbers, underscores, hyphens, or periods.".to_owned(),
            Field::Address => "The 20-byte EVM address this alias resolves to.".to_owned(),
            Field::Note => format!("Optional — at most {MAX_NOTE_LEN} bytes."),
        },
        Clone::clone,
    );
    let tone = if form.error.is_some() {
        Tone::Warning
    } else {
        Tone::Muted
    };
    let mut status_area = rest;
    status_area.height = status_area.height.min(1);
    frame.render_widget(
        Paragraph::new(UiLine::from(UiSpan::styled(
            crate::render::terminal_safe_line(&status),
            tone_style(tone),
        ))),
        status_area,
    );
    frame.render_widget(
        footer_line(
            None,
            "Tab/↑↓ move · Ctrl+S review · Esc cancel · Ctrl+U clear field",
        ),
        footer,
    );
}

fn draw_confirm(frame: &mut ratatui::Frame, confirm: &mut Confirm) {
    let [header, body, decision, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(4),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    frame.render_widget(title_line(confirm.review.title), header);

    let columns = (body.width as usize).saturating_sub(2).max(10);
    let wrapped = wrap_lines(&confirm.review.document(), columns);
    let viewport = (body.height as usize).max(1);
    confirm.offset = confirm.offset.min(wrapped.len().saturating_sub(viewport));
    let visible: Vec<UiLine> = wrapped
        .iter()
        .skip(confirm.offset)
        .take(viewport)
        .map(|line| {
            let mut spans = vec![UiSpan::raw(" ")];
            spans.extend(line.iter().map(ui_span));
            UiLine::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(visible), body);

    frame.render_widget(
        crate::fullscreen::decision_pane(
            confirm.review.question,
            "Cancel — nothing is written",
            confirm.review.accept_label,
            confirm.accept,
        ),
        decision,
    );
    frame.render_widget(
        footer_line(None, "↑↓/Tab choose · Enter confirm · Esc cancel"),
        footer,
    );
}

enum ConfirmOutcome {
    Stay,
    Cancel,
    Accept,
}

fn handle_confirm_key(confirm: &mut Confirm, key: KeyEvent) -> ConfirmOutcome {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => ConfirmOutcome::Cancel,
        KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
            confirm.accept = !confirm.accept;
            ConfirmOutcome::Stay
        }
        KeyCode::PageDown => {
            confirm.offset = confirm.offset.saturating_add(1);
            ConfirmOutcome::Stay
        }
        KeyCode::PageUp => {
            confirm.offset = confirm.offset.saturating_sub(1);
            ConfirmOutcome::Stay
        }
        KeyCode::Enter => {
            if confirm.accept {
                ConfirmOutcome::Accept
            } else {
                ConfirmOutcome::Cancel
            }
        }
        _ => ConfirmOutcome::Stay,
    }
}

/// `Ok(Some(view))` switches screens; `Ok(None)` stays on the form.
fn handle_form_key(form: &mut Form, config: &ConfigStore, key: KeyEvent) -> Result<Option<View>> {
    // The field editor gets first refusal, so a typed character is never a
    // navigation key. It declines Enter, Tab, Esc, Up, and Down, which is
    // exactly the set the form needs.
    if let Some(field) = form.field_mut(form.current())
        && field.handle_key(key)
    {
        form.error = None;
        return Ok(None);
    }
    match key.code {
        KeyCode::Esc => return Ok(Some(View::List)),
        KeyCode::Tab | KeyCode::Down => form.next_field(),
        KeyCode::BackTab | KeyCode::Up => form.previous_field(),
        KeyCode::Enter => {
            if form.current() == Field::Network {
                return Ok(Some(View::Networks(Box::new(NetworkPicker::load(config)?))));
            }
            if form.focus + 1 < form.fields().len() {
                form.next_field();
            } else {
                return review_form(form, config);
            }
        }
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return review_form(form, config);
        }
        _ => {}
    }
    Ok(None)
}

/// Validate the form and move to the confirmation, or park the cursor on the
/// field that is wrong and say why.
fn review_form(form: &mut Form, config: &ConfigStore) -> Result<Option<View>> {
    match form.draft() {
        Ok(draft) => {
            let existing = AddressBookStore::production(config.data_dir())?
                .get(draft.chain_id, &draft.alias)?;
            Ok(Some(View::Confirm(Confirm {
                review: save_review(&draft, existing.as_ref()),
                pending: Pending::Save(draft),
                accept: false,
                offset: 0,
            })))
        }
        Err((field, reason)) => {
            form.focus_on(field);
            form.error = Some(reason);
            Ok(None)
        }
    }
}

fn network_picker(networks: &[NetworkConfig]) -> SearchableTable {
    SearchableTable::new(
        "Networks",
        vec![
            TableColumn::new("Network", Constraint::Fill(1)),
            TableColumn::new("Chain", Constraint::Length(10)).right_aligned(),
        ],
        networks
            .iter()
            .map(|network| {
                TableRow::new(
                    vec![
                        Span::plain(&network.name),
                        Span::plain(network.chain_id.to_string()),
                    ],
                    &[&network.name, &network.chain_id.to_string()],
                )
            })
            .collect(),
    )
}

/// What a list keystroke resolved to.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Add,
    Edit(usize),
    Remove(usize),
    Quit,
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

/// A full `0x…` address is 42 columns; the shortened form keeps 10 leading
/// and 8 trailing characters around a one-column ellipsis.
const FULL_ADDRESS_WIDTH: u16 = 42;
const SHORT_ADDRESS_WIDTH: u16 = 19;
const UPDATED_WIDTH: u16 = 14;

/// The alias column is sized to its content so the fixed-width address can
/// never squeeze it: the alias is the one value the user knows an entry by,
/// so on a small screen it is everything else that gives way.
fn alias_column_width(entries: &[AddressBookEntry]) -> u16 {
    let width = entries
        .iter()
        // Aliases are validated ASCII, so bytes are display columns.
        .map(|entry| entry.alias.len())
        .max()
        .unwrap_or(0)
        .clamp("Alias".len(), 24);
    u16::try_from(width).expect("clamped to at most 24")
}

/// The narrowest terminal where the full-address layout leaves the network
/// and note columns readable; below it the compact layout applies.
fn full_layout_min_width(alias_width: u16) -> u16 {
    // Fixed columns, four separators of column spacing, and breathing room
    // for the network and note fills.
    alias_width + FULL_ADDRESS_WIDTH + UPDATED_WIDTH + 4 * 2 + 24
}

fn columns(alias_width: u16, compact: bool) -> Vec<TableColumn> {
    let mut columns = vec![
        TableColumn::new("Alias", Constraint::Length(alias_width)),
        TableColumn::new(
            "Address",
            Constraint::Length(if compact {
                SHORT_ADDRESS_WIDTH
            } else {
                FULL_ADDRESS_WIDTH
            }),
        ),
        TableColumn::new("Network", Constraint::Fill(1)),
        TableColumn::new("Note", Constraint::Fill(1)),
    ];
    if !compact {
        columns.push(TableColumn::new(
            "Updated",
            Constraint::Length(UPDATED_WIDTH),
        ));
    }
    columns
}

/// `0xa0b86991…2d883e06`: both checkable ends of the address in a narrow
/// cell. Clipping the tail alone would show a prefix that a vanity-address
/// lookalike could match; the search still holds the full value, and every
/// edit and confirmation shows it whole.
fn short_address(address: &str) -> String {
    crate::render::short_hex(address)
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

fn rows(networks: &[NetworkConfig], entries: &[AddressBookEntry], compact: bool) -> Vec<TableRow> {
    entries
        .iter()
        .map(|entry| {
            let network = network_label(networks, &entry.chain_id);
            let mut cells = vec![
                Span::plain(&entry.alias),
                if compact {
                    Span::plain(short_address(&entry.address))
                } else {
                    Span::plain(&entry.address)
                },
                Span::plain(&network),
                entry
                    .note
                    .as_deref()
                    .map_or_else(|| Span::toned("—", Tone::Muted), Span::plain),
            ];
            if !compact {
                let updated = crate::render::relative_time(entry.updated_at);
                cells.push(Span::toned(updated, Tone::Muted));
            }
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

#[cfg(test)]
#[path = "address_book_browser_test.rs"]
mod tests;
