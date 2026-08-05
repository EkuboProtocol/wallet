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

pub(crate) fn display_width(text: &str) -> usize {
    text.chars()
        .map(|character| UnicodeWidthChar::width(character).unwrap_or(0))
        .sum()
}

/// Wrap one line to `columns`, breaking at a space where one is in reach and
/// mid-word otherwise, so a 66-character hash lands on two fully visible
/// lines rather than being clipped at the terminal edge. Tones survive the
/// break: wrapping happens on a flattened `(char, tone)` stream and the
/// pieces are reassembled into runs afterwards.
pub(crate) fn wrap_line(line: &Line, columns: usize) -> Vec<Line> {
    let columns = columns.max(1);
    let flat: Vec<(char, Option<Tone>)> = line
        .iter()
        .flat_map(|span| span.text.chars().map(|character| (character, span.tone)))
        .collect();
    if flat.is_empty() {
        return vec![Vec::new()];
    }
    let mut lines = Vec::new();
    let mut start = 0;
    while start < flat.len() {
        let mut width = 0;
        let mut end = start;
        let mut last_space = None;
        while end < flat.len() {
            let advance = UnicodeWidthChar::width(flat[end].0).unwrap_or(0);
            if width + advance > columns && end > start {
                break;
            }
            if flat[end].0 == ' ' {
                last_space = Some(end);
            }
            width += advance;
            end += 1;
        }
        if end == flat.len() {
            lines.push(reassemble(&flat[start..end]));
            break;
        }
        // The space a line breaks at is dropped; everything else survives.
        let (line_end, next_start) = match last_space {
            Some(space) if space > start => (space, space + 1),
            _ => (end, end),
        };
        lines.push(reassemble(&flat[start..line_end]));
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
fn matches_filter(haystack: &str, filter: &str) -> bool {
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
}

/// Whether `key` is the session-level interrupt every full-screen surface
/// honors before its own bindings — raw mode suppresses the terminal's own
/// Ctrl+C handling, so each event loop has to honor it itself.
pub(crate) fn is_interrupt(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'd'))
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
    pub(crate) fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
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
mod tests {
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
        assert_eq!(text_of(&wrapped), "alpha beta\ngamma");
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
}
