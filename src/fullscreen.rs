//! Shared machinery for full-screen (alternate screen) ratatui interfaces.
//!
//! The transaction browser proved out a shape worth reusing: draw on the
//! alternate screen, lay out against the live terminal size on every frame
//! so resizing just reflows, and search against a haystack built from the
//! record itself rather than the truncated text the screen happens to show.
//! This module holds the pieces every such interface shares — the sanitized
//! [`Span`]/[`Line`] text model, tone styling, width-aware wrapping, the
//! terminal takeover guard, and [`SearchableTable`], the stateful
//! filter-and-pick list — so each new surface only writes what is actually
//! different about it.
//!
//! Everything drawn through here is either chrome the calling module
//! authored or stored data passed through
//! [`crate::render::terminal_safe_line`] at the moment a [`Span`] is built,
//! so escape sequences in stored text can never reach the terminal.

use std::io::{self, Stderr};

use anyhow::Result;
use crossterm::{
    event::{KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line as UiLine, Span as UiSpan},
    widgets::{Cell, Paragraph, Row as UiRow, Table, TableState},
};
use unicode_width::UnicodeWidthChar;

pub(crate) use crate::render::display_width;
use crate::render::terminal_safe_line;
use crate::tui::Tone;

/// One run of text with one semantic tone. Built through the constructors,
/// which sanitize, so a span can never carry stored escape sequences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub(crate) text: String,
    pub(crate) tone: Option<Tone>,
}

impl Span {
    pub(crate) fn plain(text: impl AsRef<str>) -> Self {
        Self {
            text: terminal_safe_line(text.as_ref()),
            tone: None,
        }
    }

    pub(crate) fn toned(text: impl AsRef<str>, tone: Tone) -> Self {
        Self {
            tone: Some(tone),
            ..Self::plain(text)
        }
    }
}

/// One display line of a styled document.
pub type Line = Vec<Span>;

pub(crate) fn tone_style(tone: Tone) -> Style {
    match tone {
        Tone::Success => Style::new().fg(Color::Green),
        Tone::Warning => Style::new().fg(Color::Yellow),
        Tone::Danger => Style::new().fg(Color::Red),
        Tone::Info => Style::new().fg(Color::Cyan),
        Tone::Muted => Style::new().fg(Color::DarkGray),
        Tone::Emphasis => Style::new().add_modifier(Modifier::BOLD),
    }
}

pub(crate) fn ui_span(span: &Span) -> UiSpan<'static> {
    match span.tone {
        Some(tone) => UiSpan::styled(span.text.clone(), tone_style(tone)),
        None => UiSpan::raw(span.text.clone()),
    }
}

/// Render styled lines for stdout: `paint` decides whether tones become ANSI
/// colors (see [`crate::tui::paint_stdout`]) or stay plain for a pipe.
pub fn lines_to_text(lines: &[Line], paint: impl Fn(&str, Tone) -> String) -> String {
    lines
        .iter()
        .map(|line| {
            line.iter()
                .map(|span| match span.tone {
                    Some(tone) => paint(&span.text, tone),
                    None => span.text.clone(),
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Wrap one line to `columns`, breaking at a space where one is in reach and
/// mid-word otherwise, so a 66-character hash lands on two fully visible
/// lines rather than being clipped at the terminal edge. Tones survive the
/// break: wrapping happens on a flattened `(char, tone)` stream and the
/// pieces are reassembled into runs afterwards.
pub(crate) fn wrap_line(line: &Line, columns: usize) -> Vec<Line> {
    wrap_line_hanging(line, columns, 0)
}

/// [`wrap_line`] with a hanging indent: continuation rows start `indent`
/// blank columns in, so a value that wraps stays one visual block beside its
/// label instead of snapping back to the left edge. An indent that would
/// leave the continuation almost no width is ignored rather than obeyed.
pub(crate) fn wrap_line_hanging(line: &Line, columns: usize, indent: usize) -> Vec<Line> {
    const MIN_CONTINUATION_COLUMNS: usize = 24;
    let columns = columns.max(1);
    let indent = if columns.saturating_sub(indent) >= MIN_CONTINUATION_COLUMNS {
        indent
    } else {
        0
    };
    let flat: Vec<(char, Option<Tone>)> = line
        .iter()
        .flat_map(|span| span.text.chars().map(|character| (character, span.tone)))
        .collect();
    if flat.is_empty() {
        return vec![Vec::new()];
    }
    let mut lines: Vec<Line> = Vec::new();
    let mut start = 0;
    while start < flat.len() {
        let first = lines.is_empty();
        let budget = if first { columns } else { columns - indent };
        let mut width = 0;
        let mut end = start;
        let mut last_space = None;
        while end < flat.len() {
            let advance = UnicodeWidthChar::width(flat[end].0).unwrap_or(0);
            if width + advance > budget && end > start {
                break;
            }
            if flat[end].0 == ' ' {
                last_space = Some(end);
            }
            width += advance;
            end += 1;
        }
        let assemble = |slice: &[(char, Option<Tone>)]| {
            let row = reassemble(slice);
            if first || indent == 0 {
                row
            } else {
                let mut indented = vec![Span::plain(" ".repeat(indent))];
                indented.extend(row);
                indented
            }
        };
        if end == flat.len() {
            lines.push(assemble(&flat[start..end]));
            break;
        }
        // The space a line breaks at stays on the row it ended.
        //
        // Dropping it is ordinary prose wrapping and was wrong here: this
        // wrapper renders the complete EIP-712 payload a person reads before
        // signing it, and a space inside a JSON string literal is part of the
        // value the digest commits to. A requester that puts a meaningful
        // space at a reachable wrap boundary had it vanish from every visual
        // row, with no marker saying anything was removed -- so the string on
        // screen was not the string being signed.
        //
        // Keeping it costs a trailing space at a line end, which no reader
        // will notice, and buys the property that matters: the rendered
        // document contains every character of its input. Layout is this
        // function's job; editing the text is not.
        let (line_end, next_start) = match last_space {
            Some(space) if space > start => (space + 1, space + 1),
            _ => (end, end),
        };
        lines.push(assemble(&flat[start..line_end]));
        start = next_start;
    }
    lines
}

/// Merge a wrapped slice back into spans, one per run of equal tone.
fn reassemble(flat: &[(char, Option<Tone>)]) -> Line {
    let mut spans: Line = Vec::new();
    for (character, tone) in flat {
        match spans.last_mut() {
            Some(span) if span.tone == *tone => span.text.push(*character),
            _ => spans.push(Span {
                text: character.to_string(),
                tone: *tone,
            }),
        }
    }
    spans
}

pub(crate) fn wrap_lines(lines: &[Line], columns: usize) -> Vec<Line> {
    lines
        .iter()
        .flat_map(|line| wrap_line(line, columns))
        .collect()
}

/// Whether a row matches the search: every whitespace-separated term appears
/// somewhere in the haystack, so "reverted base" or a pasted hash both work.
///
/// `haystack` is expected lowercased, as [`TableRow::new`] builds it.
pub(crate) fn matches_filter(haystack: &str, filter: &str) -> bool {
    filter
        .split_whitespace()
        .all(|term| haystack.contains(&term.to_lowercase()))
}

/// The standard three-row layout of a full-screen surface: a one-line title,
/// the body, and a one-line footer for hints or a notice.
pub(crate) fn chrome(area: Rect) -> (Rect, Rect, Rect) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);
    (header, body, footer)
}

pub(crate) fn title_line(title: &str) -> UiLine<'static> {
    UiLine::from(UiSpan::styled(
        title.to_owned(),
        Style::new().add_modifier(Modifier::BOLD),
    ))
}

/// The footer: a one-frame notice when there is one, muted key hints
/// otherwise.
pub(crate) fn footer_line(notice: Option<&str>, hints: &str) -> UiLine<'static> {
    match notice {
        Some(notice) => UiLine::from(UiSpan::styled(
            terminal_safe_line(notice),
            tone_style(Tone::Info),
        )),
        None => UiLine::from(UiSpan::styled(hints.to_owned(), tone_style(Tone::Muted))),
    }
}

/// One column of a [`SearchableTable`].
pub(crate) struct TableColumn {
    pub header: &'static str,
    pub constraint: Constraint,
    pub align: Alignment,
}

impl TableColumn {
    pub(crate) fn new(header: &'static str, constraint: Constraint) -> Self {
        Self {
            header,
            constraint,
            align: Alignment::Left,
        }
    }

    pub(crate) fn right_aligned(mut self) -> Self {
        self.align = Alignment::Right;
        self
    }
}

/// One row of a [`SearchableTable`]: the visible cells plus the lowercased
/// text the search matches against — the values a person knows the record
/// by, not the truncated text the screen happens to show.
pub(crate) struct TableRow {
    pub cells: Vec<Span>,
    pub haystack: String,
}

impl TableRow {
    pub(crate) fn new(cells: Vec<Span>, haystack_parts: &[&str]) -> Self {
        Self {
            cells,
            haystack: haystack_parts.join(" ").to_lowercase(),
        }
    }
}

/// What a keypress meant to the list.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TableEvent {
    Stay,
    Quit,
    /// The row at this index into the constructor's row slice was chosen.
    Picked(usize),
}

/// A filterable, resize-proof pick list.
///
/// The component owns selection, paging, and the `/` search; the caller owns
/// the chrome around it (title and footer, built from [`Self::title`] and
/// [`Self::footer_hints`]) and decides what a [`TableEvent::Picked`] means.
/// Esc backs out one layer at a time — it clears an active search before it
/// ever reads as quit — and the Enter that confirms a search never doubles
/// as the Enter that picks.
pub(crate) struct SearchableTable {
    subject: &'static str,
    columns: Vec<TableColumn>,
    rows: Vec<TableRow>,
    /// Indices into `rows` that pass the current filter, in row order.
    visible: Vec<usize>,
    state: TableState,
    filter: String,
    /// Whether keystrokes currently edit the filter instead of navigating.
    typing: bool,
    /// Body rows the last frame had, so paging moves by what is on screen.
    viewport: usize,
}

impl SearchableTable {
    pub(crate) fn new(
        subject: &'static str,
        columns: Vec<TableColumn>,
        rows: Vec<TableRow>,
    ) -> Self {
        let mut table = Self {
            subject,
            columns,
            rows: Vec::new(),
            visible: Vec::new(),
            state: TableState::default(),
            filter: String::new(),
            typing: false,
            viewport: 1,
        };
        table.set_rows(rows);
        table
    }

    /// Replace the rows — after the underlying data changed — keeping the
    /// filter, and the selection when its row index still exists.
    pub(crate) fn set_rows(&mut self, rows: Vec<TableRow>) {
        self.rows = rows;
        self.refilter();
    }

    /// Replace the columns, for a surface whose layout changes with the
    /// terminal width. Pair with a [`Self::set_rows`] whose cells match.
    pub(crate) fn set_columns(&mut self, columns: Vec<TableColumn>) {
        self.columns = columns;
    }

    fn selected_row(&self) -> Option<usize> {
        self.state
            .selected()
            .and_then(|position| self.visible.get(position).copied())
    }

    /// Re-derive the visible rows after a filter edit, keeping the selection
    /// on the same row when it survives the filter.
    fn refilter(&mut self) {
        let selected_row = self.selected_row();
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| matches_filter(&row.haystack, &self.filter))
            .map(|(index, _)| index)
            .collect();
        let position = selected_row
            .and_then(|row| self.visible.iter().position(|&index| index == row))
            .unwrap_or(0);
        self.state.select(if self.visible.is_empty() {
            None
        } else {
            Some(position.min(self.visible.len() - 1))
        });
    }

    fn move_selection(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let last = self.visible.len() - 1;
        let current = self.state.selected().unwrap_or(0);
        let target = current.saturating_add_signed(delta).min(last);
        self.state.select(Some(target));
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> TableEvent {
        if self.typing {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.typing = false;
                    self.refilter();
                }
                // Enter only keeps the filter and hands the keys back to the
                // list; picking the selection takes a second, deliberate
                // Enter.
                KeyCode::Enter => self.typing = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.refilter();
                }
                KeyCode::Char(character) => {
                    self.filter.push(character);
                    self.refilter();
                }
                KeyCode::Up => self.move_selection(-1),
                KeyCode::Down => self.move_selection(1),
                _ => {}
            }
            return TableEvent::Stay;
        }
        let page = self.viewport.max(1).cast_signed();
        match key.code {
            KeyCode::Char('q') => return TableEvent::Quit,
            KeyCode::Esc if self.filter.is_empty() => return TableEvent::Quit,
            KeyCode::Esc => {
                self.filter.clear();
                self.refilter();
            }
            KeyCode::Enter => {
                if let Some(index) = self.selected_row() {
                    return TableEvent::Picked(index);
                }
            }
            KeyCode::Char('/') => self.typing = true,
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-page),
            KeyCode::PageDown => self.move_selection(page),
            KeyCode::Home | KeyCode::Char('g') => self.state.select_first(),
            KeyCode::End | KeyCode::Char('G') if !self.visible.is_empty() => {
                self.state.select(Some(self.visible.len() - 1));
            }
            _ => {}
        }
        TableEvent::Stay
    }

    /// The header line: the subject, the counts, and the active search.
    pub(crate) fn title(&self) -> String {
        if self.filter.is_empty() {
            format!("{} — {}", self.subject, self.rows.len())
        } else {
            format!(
                "{} — {} of {} match \u{201c}{}\u{201d}",
                self.subject,
                self.visible.len(),
                self.rows.len(),
                terminal_safe_line(&self.filter),
            )
        }
    }

    /// The footer hints matching the current mode; `action` names what Enter
    /// does to the selected row ("details", "edit", "review").
    pub(crate) fn footer_hints(&self, action: &str) -> String {
        if self.typing {
            format!(
                "Search: {}▏  Enter to keep · Esc to clear",
                terminal_safe_line(&self.filter)
            )
        } else if self.filter.is_empty() {
            format!("↑↓ select · Enter {action} · / search · q quit")
        } else {
            format!("↑↓ select · Enter {action} · / edit search · Esc clear search · q quit")
        }
    }

    /// Draw the table (or the empty-search notice) into `area`.
    pub(crate) fn draw(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        // One row of the body is the column header row.
        self.viewport = usize::from(area.height).saturating_sub(1).max(1);
        if self.visible.is_empty() {
            frame.render_widget(
                Paragraph::new(UiLine::from(UiSpan::styled(
                    format!("No {} match the search.", self.subject.to_lowercase()),
                    tone_style(Tone::Muted),
                )))
                .alignment(Alignment::Center),
                area,
            );
            return;
        }
        let rows: Vec<UiRow> = self
            .visible
            .iter()
            .map(|&index| {
                UiRow::new(
                    self.rows[index]
                        .cells
                        .iter()
                        .zip(&self.columns)
                        .map(|(cell, column)| {
                            Cell::from(UiLine::from(ui_span(cell)).alignment(column.align))
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let table = Table::new(
            rows,
            self.columns
                .iter()
                .map(|column| column.constraint)
                .collect::<Vec<_>>(),
        )
        .header(
            UiRow::new(
                self.columns
                    .iter()
                    .map(|column| Cell::from(UiLine::from(column.header).alignment(column.align)))
                    .collect::<Vec<_>>(),
            )
            .style(tone_style(Tone::Muted)),
        )
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .column_spacing(2);
        frame.render_stateful_widget(table, area, &mut self.state);
    }

    pub(crate) fn viewport(&self) -> usize {
        self.viewport
    }

    /// Whether keystrokes currently edit the `/` filter — callers with their
    /// own key bindings must not steal letters from a search being typed.
    pub(crate) const fn typing(&self) -> bool {
        self.typing
    }

    /// The underlying row index of the current selection, for callers whose
    /// extra key bindings act on "the selected row" outside a
    /// [`TableEvent::Picked`].
    pub(crate) fn selected(&self) -> Option<usize> {
        self.selected_row()
    }

    /// Whether a confirmed `/` filter is narrowing the rows, so callers
    /// composing their own footer hints can mirror [`Self::footer_hints`].
    pub(crate) fn searching(&self) -> bool {
        !self.filter.is_empty()
    }
}

/// One editable line of text, drawn inside the alternate screen.
///
/// The pieces for a form already existed and were split across two worlds:
/// [`SearchableTable`] captures keystrokes but only append-and-backspace, into
/// a footer string with a painted caret; `crate::tui::TextPrompt` is a real
/// line editor but opens an inline viewport at the cursor and prints an
/// answered line to the scrollback when it closes. A full-screen form needs
/// the editing of the second inside the screen of the first, which is this.
///
/// Deliberately not a `tui::TextPrompt` that can also draw here: that type
/// owns an event loop and a terminal. This owns neither — the caller's app
/// feeds it keys and gives it a rect — which is what lets several of them sit
/// on one frame with one of them focused.
pub(crate) struct TextField {
    label: String,
    value: String,
    /// Caret position in characters, not bytes. Every edit goes through
    /// [`char_boundary`], so a multi-byte character is never split.
    cursor: usize,
    placeholder: Option<String>,
}

impl TextField {
    pub(crate) fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: String::new(),
            cursor: 0,
            placeholder: None,
        }
    }

    /// Pre-fill the line, caret at the end, for editing an existing value.
    pub(crate) fn with_value(mut self, value: impl Into<String>) -> Self {
        self.set_value(value);
        self
    }

    pub(crate) fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = Some(placeholder.into());
        self
    }

    pub(crate) fn set_value(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.cursor = self.value.chars().count();
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    /// Apply one keystroke. Returns whether it was consumed as editing — a key
    /// this field does not use (Enter, Tab, Up, Down, Esc) is left for the
    /// caller's own navigation, so the form decides what those mean.
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> bool {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Left if !control => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right if !control => {
                self.cursor = (self.cursor + 1).min(self.value.chars().count());
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.value.chars().count(),
            KeyCode::Backspace if self.cursor > 0 => {
                let start = char_boundary(&self.value, self.cursor - 1);
                let end = char_boundary(&self.value, self.cursor);
                self.value.replace_range(start..end, "");
                self.cursor -= 1;
            }
            KeyCode::Delete if self.cursor < self.value.chars().count() => {
                let start = char_boundary(&self.value, self.cursor);
                let end = char_boundary(&self.value, self.cursor + 1);
                self.value.replace_range(start..end, "");
            }
            // The line-kill every readline-shaped editor has, and the fastest
            // way to replace a pre-filled value rather than backspacing it.
            KeyCode::Char('u') if control => {
                self.value.clear();
                self.cursor = 0;
            }
            KeyCode::Char(character) if !control && !character.is_control() => {
                let at = char_boundary(&self.value, self.cursor);
                self.value.insert(at, character);
                self.cursor += 1;
            }
            _ => return false,
        }
        true
    }

    /// Draw `label: value` into `area`, placing the terminal caret when
    /// `focused`. The caret position is measured from the rendered prefix
    /// rather than assumed from its character count, so a wide glyph in a
    /// label cannot drift it.
    pub(crate) fn draw(&self, frame: &mut ratatui::Frame, area: Rect, focused: bool) {
        let prefix = format!("{}: ", self.label);
        let shown = &self.value;
        let mut spans = vec![UiSpan::styled(
            prefix.clone(),
            if focused {
                tone_style(Tone::Emphasis)
            } else {
                tone_style(Tone::Muted)
            },
        )];
        if shown.is_empty() {
            if let Some(placeholder) = &self.placeholder {
                spans.push(UiSpan::styled(
                    terminal_safe_line(placeholder),
                    tone_style(Tone::Muted),
                ));
            }
        } else {
            spans.push(UiSpan::raw(terminal_safe_line(shown)));
        }
        frame.render_widget(Paragraph::new(UiLine::from(spans)), area);
        if focused {
            let ahead: String = shown.chars().take(self.cursor).collect();
            let column = display_width(&prefix) + display_width(&ahead);
            // Clamped so a value wider than the pane cannot put the caret
            // outside the frame, which some terminals render as a stray cell.
            let x = area
                .x
                .saturating_add(u16::try_from(column).unwrap_or(u16::MAX))
                .min(area.right().saturating_sub(1));
            frame.set_cursor_position(ratatui::layout::Position { x, y: area.y });
        }
    }
}

/// The byte offset of character `index`, or the string's length past the end.
fn char_boundary(value: &str, index: usize) -> usize {
    value
        .char_indices()
        .nth(index)
        .map_or(value.len(), |(offset, _)| offset)
}

/// Whether `key` is the session-level interrupt every full-screen surface
/// honors before its own bindings — raw mode suppresses the terminal's own
/// Ctrl+C handling, so each event loop has to honor it itself.
pub(crate) fn is_interrupt(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'd'))
}

/// The question and two-option decision row every confirmation screen ends
/// with. Four lines tall: a blank separator, the question, then the options.
///
/// `accept` is the affirmative option and always sits second, so the cursor
/// starting on the refusal means the affirmative answer is the one that has to
/// be reached for. Shared so three screens cannot style the same decision
/// differently.
pub(crate) fn decision_pane<'a>(
    question: &'a str,
    cancel_label: &'a str,
    accept_label: &'a str,
    accepting: bool,
) -> Paragraph<'a> {
    let option = |selected: bool, text: &str| {
        let line = UiLine::from(UiSpan::raw(format!(
            " {} {text} ",
            if selected { "▸" } else { " " }
        )));
        if selected {
            line.style(Style::new().add_modifier(Modifier::REVERSED))
        } else {
            line
        }
    };
    Paragraph::new(vec![
        UiLine::default(),
        UiLine::from(UiSpan::styled(
            format!(" {question}"),
            Style::new().add_modifier(Modifier::BOLD),
        )),
        option(!accepting, cancel_label),
        option(accepting, accept_label),
    ])
}

/// One labelled value in an [`edit_form`].
pub(crate) struct FormField {
    pub label: String,
    /// The one line shown under the form while this field has the cursor.
    pub help: String,
    pub value: String,
}

/// Edit a set of labelled values in one full-screen form.
///
/// `Ok(None)` means the user backed out and nothing should change. `validate`
/// runs on save and reports `(index, reason)` for the field that is wrong, so
/// the cursor lands on it with the reason under the form — rather than the
/// caller discovering it after the screen is gone, which is where a rejected
/// value used to surface.
///
/// Owns its own screen, exactly like [`pick_table`], so a command composed of
/// a pick and then a form never drops to the scrollback in between.
pub(crate) fn edit_form(
    title: &str,
    mut fields: Vec<FormField>,
    mut validate: impl FnMut(&[String]) -> std::result::Result<(), (usize, String)>,
) -> Result<Option<Vec<String>>> {
    if fields.is_empty() || !crate::tui::interactive() {
        return Ok(None);
    }
    let mut editors: Vec<TextField> = fields
        .iter_mut()
        .map(|field| {
            TextField::new(field.label.clone()).with_value(std::mem::take(&mut field.value))
        })
        .collect();
    let mut focus = 0_usize;
    let mut error: Option<String> = None;
    let mut screen = Screen::enter()?;
    loop {
        screen.terminal.draw(|frame| {
            let (header, body, footer) = chrome(frame.area());
            frame.render_widget(title_line(title), header);
            let rows = Layout::vertical(
                std::iter::repeat_n(Constraint::Length(1), editors.len() + 2)
                    .chain(std::iter::once(Constraint::Fill(1)))
                    .collect::<Vec<_>>(),
            )
            .split(body);
            for (index, editor) in editors.iter().enumerate() {
                editor.draw(frame, rows[index], index == focus);
            }
            let status = error.as_deref().unwrap_or(&fields[focus].help);
            frame.render_widget(
                Paragraph::new(UiLine::from(UiSpan::styled(
                    terminal_safe_line(status),
                    tone_style(if error.is_some() {
                        Tone::Warning
                    } else {
                        Tone::Muted
                    }),
                ))),
                rows[editors.len() + 1],
            );
            frame.render_widget(
                footer_line(
                    None,
                    "Tab/↑↓ move · Ctrl+S save · Esc cancel · Ctrl+U clear",
                ),
                footer,
            );
        })?;
        let key = match crossterm::event::read()? {
            crossterm::event::Event::Key(key)
                if key.kind == crossterm::event::KeyEventKind::Press =>
            {
                key
            }
            _ => continue,
        };
        if is_interrupt(key) {
            return Ok(None);
        }
        // The focused editor gets first refusal, so a typed character is never
        // navigation. It declines exactly the keys used below.
        if editors[focus].handle_key(key) {
            error = None;
            continue;
        }
        // Ctrl+S saves from anywhere; Enter walks to the next field and saves
        // only from the last one. Enter must not do both, which is what
        // deciding this before the match and re-testing it after made it do.
        let save = match key.code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Tab | KeyCode::Down => {
                focus = (focus + 1) % editors.len();
                false
            }
            KeyCode::BackTab | KeyCode::Up => {
                focus = (focus + editors.len() - 1) % editors.len();
                false
            }
            KeyCode::Enter => {
                if focus + 1 < editors.len() {
                    focus += 1;
                    false
                } else {
                    true
                }
            }
            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
            _ => false,
        };
        if !save {
            continue;
        }
        let values: Vec<String> = editors
            .iter()
            .map(|editor| editor.value().to_owned())
            .collect();
        match validate(&values) {
            Ok(()) => return Ok(Some(values)),
            Err((index, reason)) => {
                focus = index.min(editors.len() - 1);
                error = Some(reason);
            }
        }
    }
}

/// One full-screen confirmation: the same facts a `crate::tui::Confirmation`
/// prints to the scrollback, drawn as a document with a decision row.
///
/// For a command that has already shown a full-screen surface. Dropping to an
/// inline prompt to ask the question is what leaves a half-finished exchange
/// in the terminal after the command ends.
pub(crate) fn confirm_review(
    title: &str,
    document: &[Line],
    question: &str,
    accept_label: &str,
    cancel_label: &str,
) -> Result<bool> {
    if !crate::tui::interactive() {
        return Ok(false);
    }
    let mut accepting = false;
    let mut offset = 0_usize;
    // Both are read by the key handler below and written by the draw closure,
    // so paging moves by what the screen currently holds. Deciding a page size
    // before a frame has been laid out would guess at a terminal that resizes.
    let mut page = 1_usize;
    let mut max_offset = 0_usize;
    let mut screen = Screen::enter()?;
    loop {
        screen.terminal.draw(|frame| {
            let [header, body, decision, footer] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Fill(1),
                Constraint::Length(4),
                Constraint::Length(1),
            ])
            .areas(frame.area());
            frame.render_widget(title_line(title), header);
            let columns = (body.width as usize).saturating_sub(2).max(10);
            let wrapped = wrap_lines(document, columns);
            let viewport = (body.height as usize).max(1);
            // One line of overlap between pages, so a fact split across a page
            // boundary is still readable on one of them.
            page = viewport.saturating_sub(1).max(1);
            max_offset = wrapped.len().saturating_sub(viewport);
            offset = offset.min(max_offset);
            let visible: Vec<UiLine> = wrapped
                .iter()
                .skip(offset)
                .take(viewport)
                .map(|line| {
                    let mut spans = vec![UiSpan::raw(" ")];
                    spans.extend(line.iter().map(ui_span));
                    UiLine::from(spans)
                })
                .collect();
            frame.render_widget(Paragraph::new(visible), body);
            frame.render_widget(
                decision_pane(question, cancel_label, accept_label, accepting),
                decision,
            );
            // Scrolling is offered only when there is something to scroll, and
            // the counter is what tells a reviewer that facts they have not
            // read yet sit above the decision they are being asked to make.
            let hints = if max_offset == 0 {
                "↑↓/Tab choose · Enter confirm · Esc cancel".to_owned()
            } else {
                format!(
                    "↑↓/Tab choose · PgUp/PgDn/Home/End scroll ({}/{}) · Enter confirm · Esc \
                     cancel",
                    offset + 1,
                    max_offset + 1
                )
            };
            frame.render_widget(footer_line(None, &hints), footer);
        })?;
        let key = match crossterm::event::read()? {
            crossterm::event::Event::Key(key)
                if key.kind == crossterm::event::KeyEventKind::Press =>
            {
                key
            }
            _ => continue,
        };
        if is_interrupt(key) {
            return Ok(false);
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Ok(false),
            KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
                accepting = !accepting;
            }
            KeyCode::PageDown => offset = offset.saturating_add(page).min(max_offset),
            KeyCode::PageUp => offset = offset.saturating_sub(page),
            KeyCode::Home => offset = 0,
            KeyCode::End => offset = max_offset,
            KeyCode::Enter => return Ok(accepting),
            _ => {}
        }
    }
}

/// Everything a reviewer is told before one change, built once and drawn by
/// [`confirm_review`] as a scrollable document.
///
/// For a change whose description has no fixed length: a permission diff, a
/// list of RPC endpoints. [`crate::tui::Confirmation`] prints its facts
/// straight into the scrollback, so a description taller than the terminal
/// pushes the title, the warnings, and eventually the question itself off the
/// top before the reviewer is asked — and a fact is clamped to one line there,
/// so a multi-line value silently collapses into a run of spaces. A command
/// whose facts are a fixed handful still uses the inline prompt; this is for
/// the ones that cannot promise that.
pub(crate) struct Review {
    title: String,
    summary: String,
    /// Each label with its value as one or more lines. A single-line value
    /// reads as `label: value`; several become a labelled, indented block, so
    /// a list stays a list.
    facts: Vec<(String, Vec<String>)>,
    warnings: Vec<String>,
}

impl Review {
    pub(crate) fn new(title: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            summary: summary.into(),
            facts: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.facts.push((label.into(), vec![value.into()]));
        self
    }

    /// A labelled value that is a list. An empty one is dropped rather than
    /// drawn as a heading with nothing under it.
    #[must_use]
    pub(crate) fn fact_lines(
        mut self,
        label: impl Into<String>,
        values: impl IntoIterator<Item = String>,
    ) -> Self {
        let values: Vec<String> = values.into_iter().collect();
        if !values.is_empty() {
            self.facts.push((label.into(), values));
        }
        self
    }

    #[must_use]
    pub(crate) fn warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// The document [`confirm_review`] draws. Separate from [`Self::ask`] so a
    /// caller that already owns a screen can embed the same lines rather than
    /// describing the change a second time, and so the layout is testable
    /// without a terminal.
    pub(crate) fn document(&self) -> Vec<Line> {
        let mut lines = vec![vec![Span::toned(&self.summary, Tone::Muted)], Vec::new()];
        for (label, values) in &self.facts {
            match values.as_slice() {
                [] => {}
                [only] => lines.push(vec![
                    Span::toned(format!("{label}: "), Tone::Muted),
                    Span::plain(only),
                ]),
                many => {
                    lines.push(vec![Span::toned(format!("{label}:"), Tone::Muted)]);
                    for value in many {
                        lines.push(vec![Span::plain(format!("  {value}"))]);
                    }
                }
            }
        }
        for warning in &self.warnings {
            lines.push(Vec::new());
            lines.push(vec![Span::toned(format!("⚠ {warning}"), Tone::Warning)]);
        }
        lines
    }

    /// Draw the change and ask. `Ok(false)` means it must not happen — which
    /// is also what a non-interactive run answers, since there is nobody to
    /// show it to.
    pub(crate) fn ask(
        &self,
        question: &str,
        accept_label: &str,
        cancel_label: &str,
    ) -> Result<bool> {
        confirm_review(
            &self.title,
            &self.document(),
            question,
            accept_label,
            cancel_label,
        )
    }
}

/// One full-screen pick: draw the table until the user chooses a row
/// (`Ok(Some(index))`) or backs out (`Ok(None)`).
///
/// Requires a terminal on stdin and stderr; callers gate on
/// [`crate::tui::interactive`] first, and without one this backs out rather
/// than half-drawing.
pub(crate) fn pick_table(
    subject: &'static str,
    action: &str,
    columns: Vec<TableColumn>,
    rows: Vec<TableRow>,
) -> Result<Option<usize>> {
    if !crate::tui::interactive() {
        return Ok(None);
    }
    let mut list = SearchableTable::new(subject, columns, rows);
    let mut screen = Screen::enter()?;
    loop {
        screen.terminal.draw(|frame| {
            let (header, body, footer) = chrome(frame.area());
            frame.render_widget(title_line(&list.title()), header);
            list.draw(frame, body);
            frame.render_widget(footer_line(None, &list.footer_hints(action)), footer);
        })?;
        let key = match crossterm::event::read()? {
            crossterm::event::Event::Key(key)
                if key.kind == crossterm::event::KeyEventKind::Press =>
            {
                key
            }
            // Anything else — a resize above all — just redraws against the
            // new terminal size.
            _ => continue,
        };
        if is_interrupt(key) {
            return Ok(None);
        }
        match list.handle_key(key) {
            TableEvent::Stay => {}
            TableEvent::Quit => return Ok(None),
            TableEvent::Picked(index) => return Ok(Some(index)),
        }
    }
}

/// Owns the terminal takeover. Restoring on drop rather than at the end of
/// the calling loop means an error or a panic mid-session still hands the
/// terminal back in raw-mode-off, main-screen state.
pub(crate) struct Screen {
    pub terminal: Terminal<CrosstermBackend<Stderr>>,
}

impl Screen {
    /// Take the terminal, and throw away whatever was typed at whatever used
    /// to be on it.
    ///
    /// The drain lives here rather than in each surface because this is the
    /// one door into the alternate screen. `approve_tui` drained and the
    /// inline prompts drained; `confirm_review` did not, and it is the shared
    /// confirmation behind legal acceptance, policy proposals, network
    /// proposals, and direct network edits. Its decision starts on the safe
    /// answer, but a buffered `Tab` toggles it and a buffered `Enter` returns
    /// it, so two queued keystrokes affirm a document nobody saw. Getting to
    /// one of these screens takes RPC round trips or an authored review, and
    /// the keys typed into that silence were meant for whatever the person
    /// thought was in front of them.
    ///
    /// After `enable_raw_mode`, so the keystrokes are in the queue this drains
    /// rather than in the line discipline, and before the first draw, so
    /// nothing can be read before it runs.
    pub(crate) fn enter() -> Result<Self> {
        crate::render::note_interactive_surface();
        terminal::enable_raw_mode()?;
        crate::tui::drain_type_ahead()?;
        execute!(io::stderr(), EnterAlternateScreen)?;
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(io::stderr()))?,
        })
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _unused = execute!(io::stderr(), LeaveAlternateScreen);
        let _unused = terminal::disable_raw_mode();
    }
}

#[cfg(test)]
#[path = "fullscreen_test.rs"]
mod tests;
