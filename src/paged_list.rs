//! Scrollable single-select list prompt with complete paging keys.
//!
//! `cliclack::Select` moves only one row at a time: `PageUp`, `PageDown`,
//! `Home`, and `End` are silently ignored, and an initial cursor past the
//! first page is
//! drawn off-screen, so a long transaction history could not be paged at all.
//! This prompt keeps cliclack's visual language and draws through `console`
//! (the same terminal backend cliclack uses), but owns pagination as a pure
//! state machine so every movement and windowing rule is testable without a
//! terminal. Cancellation surfaces as `io::ErrorKind::Interrupted`, matching
//! cliclack, so existing callers treat Esc and Ctrl+C identically.

use std::fmt::Display;
use std::io;
use std::ops::Range;

use console::{Emoji, Key, Style, Term};

const STEP_ACTIVE: Emoji = Emoji("◆", "*");
const STEP_CANCEL: Emoji = Emoji("■", "x");
const STEP_SUBMIT: Emoji = Emoji("◇", "o");
const BAR: Emoji = Emoji("│", "|");
const BAR_END: Emoji = Emoji("└", "—");
const RADIO_ACTIVE: Emoji = Emoji("●", ">");
const RADIO_INACTIVE: Emoji = Emoji("○", " ");

/// Columns consumed around an item label: bar, three separating spaces, and
/// the radio symbol. Labels are truncated to the remaining width so a long
/// row can never wrap, which would corrupt the redraw arithmetic.
const ITEM_PREFIX_COLUMNS: usize = 5;

/// Pure pagination state: which item the cursor is on and which contiguous
/// window of items is visible. All movement clamps at the ends (matching the
/// arrow-key behavior users already know from cliclack) and the window always
/// follows the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageState {
    total: usize,
    rows: usize,
    cursor: usize,
    offset: usize,
}

impl PageState {
    /// A window of `rows` items over `total`, scrolled so `cursor` is visible
    /// from the first render — even when it starts pages deep in the list.
    #[must_use]
    pub fn new(total: usize, rows: usize, cursor: usize) -> Self {
        let mut state = Self {
            total,
            rows: rows.max(1),
            cursor: cursor.min(total.saturating_sub(1)),
            offset: 0,
        };
        state.follow_cursor();
        state
    }

    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The indices currently visible.
    #[must_use]
    pub fn window(&self) -> Range<usize> {
        self.offset..self.offset.saturating_add(self.rows).min(self.total)
    }

    /// Whether the list is taller than one page and therefore scrolls.
    #[must_use]
    pub fn scrolls(&self) -> bool {
        self.total > self.rows
    }

    /// Applies one movement key; returns false for keys that do not move.
    pub fn apply(&mut self, key: &Key) -> bool {
        let target = match key {
            Key::ArrowUp | Key::ArrowLeft | Key::Char('k' | 'h') => self.cursor.saturating_sub(1),
            Key::ArrowDown | Key::ArrowRight | Key::Char('j' | 'l') => self.cursor + 1,
            Key::PageUp => self.cursor.saturating_sub(self.rows),
            Key::PageDown => self.cursor.saturating_add(self.rows),
            Key::Home => 0,
            Key::End => self.total.saturating_sub(1),
            _ => return false,
        };
        self.cursor = target.min(self.total.saturating_sub(1));
        self.follow_cursor();
        true
    }

    /// Adopts a new page height (the terminal may be resized mid-prompt)
    /// while keeping the cursor on the same item and on screen.
    pub fn resize(&mut self, rows: usize) {
        self.rows = rows.max(1);
        // Never leave blank rows below the last item while items are hidden
        // above the window.
        self.offset = self.offset.min(self.total.saturating_sub(self.rows));
        self.follow_cursor();
    }

    fn follow_cursor(&mut self) {
        if self.cursor < self.offset {
            self.offset = self.cursor;
        } else if self.cursor >= self.offset.saturating_add(self.rows) {
            self.offset = self.cursor + 1 - self.rows;
        }
    }
}

struct ListItem<T> {
    value: T,
    label: String,
    hint: String,
}

/// A single-selection prompt over a windowed list. API mirrors
/// [`cliclack::Select`] so call sites stay familiar.
pub struct PagedSelect<T> {
    title: String,
    items: Vec<ListItem<T>>,
    initial_value: Option<T>,
    page_rows: Box<dyn Fn() -> usize>,
}

impl<T: Clone + Eq> PagedSelect<T> {
    #[must_use]
    pub fn new(title: impl Display) -> Self {
        Self {
            title: title.to_string(),
            items: Vec::new(),
            initial_value: None,
            page_rows: Box::new(|| usize::MAX),
        }
    }

    #[must_use]
    pub fn item(mut self, value: T, label: impl Display, hint: impl Display) -> Self {
        self.items.push(ListItem {
            value,
            label: label.to_string(),
            hint: hint.to_string(),
        });
        self
    }

    /// Where the cursor starts, by item value.
    #[must_use]
    pub fn initial_value(mut self, value: T) -> Self {
        self.initial_value = Some(value);
        self
    }

    /// How many list rows fit on screen, re-read on every keystroke so a
    /// resized terminal repages immediately.
    #[must_use]
    pub fn page_rows(mut self, rows: impl Fn() -> usize + 'static) -> Self {
        self.page_rows = Box::new(rows);
        self
    }

    /// Runs the prompt. Esc and Ctrl+C return `io::ErrorKind::Interrupted`,
    /// exactly like `cliclack::Select::interact`.
    pub fn interact(&mut self) -> io::Result<T> {
        if self.items.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No items added to the list",
            ));
        }
        let initial = self
            .initial_value
            .as_ref()
            .and_then(|value| self.items.iter().position(|item| item.value == *value))
            .unwrap_or(0);
        let term = Term::stderr();
        let mut state = PageState::new(self.items.len(), (self.page_rows)(), initial);

        term.hide_cursor()?;
        let _guard = CursorGuard(&term);

        loop {
            state.resize((self.page_rows)());
            let frame = self.active_frame(&state, terminal_columns(&term));
            let drawn = frame.lines().count();
            term.write_str(&frame)?;

            let key = term.read_key();
            term.clear_last_lines(drawn)?;
            match key {
                Ok(Key::Enter) => {
                    let chosen = &self.items[state.cursor()];
                    term.write_str(&closing_frame(
                        &self.title,
                        &chosen.label,
                        Outcome::Submitted,
                        terminal_columns(&term),
                    ))?;
                    return Ok(chosen.value.clone());
                }
                Ok(Key::Escape | Key::CtrlC) => {
                    term.write_str(&closing_frame(
                        &self.title,
                        &self.items[state.cursor()].label,
                        Outcome::Cancelled,
                        terminal_columns(&term),
                    ))?;
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Operation cancelled",
                    ));
                }
                Ok(other) => {
                    state.apply(&other);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    term.write_str(&closing_frame(
                        &self.title,
                        &self.items[state.cursor()].label,
                        Outcome::Cancelled,
                        terminal_columns(&term),
                    ))?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// The full frame drawn while the prompt is live. Pure so tests can
    /// assert exactly which items are visible and where the cursor sits.
    fn active_frame(&self, state: &PageState, columns: usize) -> String {
        use std::fmt::Write as _;
        let bar = Style::new().cyan();
        let mut frame = format!(
            "{}  {}\n",
            Style::new().cyan().apply_to(STEP_ACTIVE),
            console::truncate_str(&self.title, columns.saturating_sub(3).max(1), "…"),
        );
        for index in state.window() {
            let item = &self.items[index];
            let selected = index == state.cursor();
            // The hint is only drawn on the selected row; whatever it uses is
            // taken away from the label so the line still cannot wrap.
            let hint_columns = if selected && !item.hint.is_empty() {
                console::measure_text_width(&item.hint) + 3
            } else {
                0
            };
            let label = console::truncate_str(
                &item.label,
                columns
                    .saturating_sub(ITEM_PREFIX_COLUMNS + hint_columns)
                    .max(1),
                "…",
            );
            let rendered = if selected {
                let hint = if item.hint.is_empty() {
                    String::new()
                } else {
                    format!(
                        " {}",
                        Style::new().dim().apply_to(format!("({})", item.hint))
                    )
                };
                format!(
                    "{} {label}{hint}",
                    Style::new().green().apply_to(RADIO_ACTIVE)
                )
            } else {
                format!(
                    "{} {}",
                    Style::new().dim().apply_to(RADIO_INACTIVE),
                    Style::new().dim().apply_to(label)
                )
            };
            let _ = writeln!(frame, "{}  {rendered}", bar.apply_to(BAR));
        }
        let footer = self.footer(state);
        let footer = console::truncate_str(&footer, columns.saturating_sub(3).max(1), "…");
        let _ = writeln!(frame, "{}", bar.apply_to(format!("{BAR_END}  {footer}")));
        frame
    }

    /// The paging help line; states the visible range whenever the list is
    /// longer than one page.
    fn footer(&self, state: &PageState) -> String {
        const KEYS: &str = "↑/↓ move · PgUp/PgDn page · Home/End jump · Enter select · Esc quit";
        if state.scrolls() {
            let window = state.window();
            format!(
                "{}-{} of {} · {KEYS}",
                window.start + 1,
                window.end,
                self.items.len()
            )
        } else {
            KEYS.to_owned()
        }
    }
}

/// Restores the terminal cursor whatever happens during the interaction,
/// including errors and panics.
struct CursorGuard<'a>(&'a Term);

impl Drop for CursorGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.show_cursor();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Submitted,
    Cancelled,
}

/// The compact frame left in the transcript after the prompt ends, matching
/// cliclack: a state symbol, the chosen line, and a closing bar.
fn closing_frame(title: &str, label: &str, outcome: Outcome, columns: usize) -> String {
    use std::fmt::Write as _;
    let (symbol, bar_style) = match outcome {
        Outcome::Submitted => (
            Style::new().green().apply_to(STEP_SUBMIT).to_string(),
            Style::new().black().bright(),
        ),
        Outcome::Cancelled => (
            Style::new().red().apply_to(STEP_CANCEL).to_string(),
            Style::new().red(),
        ),
    };
    let label = console::truncate_str(
        label,
        columns.saturating_sub(ITEM_PREFIX_COLUMNS).max(1),
        "…",
    );
    let label = match outcome {
        Outcome::Submitted => Style::new().dim().apply_to(label).to_string(),
        Outcome::Cancelled => Style::new()
            .dim()
            .strikethrough()
            .apply_to(label)
            .to_string(),
    };
    let mut frame = format!("{symbol}  {title}\n{}  {label}\n", bar_style.apply_to(BAR));
    match outcome {
        Outcome::Submitted => {
            let _ = writeln!(frame, "{}", bar_style.apply_to(BAR));
        }
        Outcome::Cancelled => {
            let _ = writeln!(
                frame,
                "{}",
                bar_style.apply_to(format!("{BAR_END}  Operation cancelled."))
            );
        }
    }
    frame
}

fn terminal_columns(term: &Term) -> usize {
    term.size_checked()
        .map_or(usize::MAX, |(_, columns)| columns as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(text: &str) -> String {
        console::strip_ansi_codes(text).to_string()
    }

    #[test]
    fn arrows_move_one_row_and_clamp_at_the_ends() {
        let mut state = PageState::new(5, 10, 0);
        assert!(state.apply(&Key::ArrowUp));
        assert_eq!(state.cursor(), 0, "top does not wrap");
        state.apply(&Key::ArrowDown);
        assert_eq!(state.cursor(), 1);
        state.apply(&Key::End);
        state.apply(&Key::ArrowDown);
        assert_eq!(state.cursor(), 4, "bottom does not wrap");
        // The vi keys cliclack accepted keep working.
        state.apply(&Key::Char('k'));
        assert_eq!(state.cursor(), 3);
        state.apply(&Key::Char('j'));
        assert_eq!(state.cursor(), 4);
    }

    #[test]
    fn page_keys_jump_by_the_visible_page_and_clamp() {
        let mut state = PageState::new(40, 12, 0);
        state.apply(&Key::PageDown);
        assert_eq!(state.cursor(), 12);
        assert_eq!(state.window(), 1..13, "window follows the cursor down");
        state.apply(&Key::PageDown);
        state.apply(&Key::PageDown);
        assert_eq!(state.cursor(), 36);
        state.apply(&Key::PageDown);
        assert_eq!(state.cursor(), 39, "last page clamps to the final item");
        assert_eq!(state.window(), 28..40);
        state.apply(&Key::PageUp);
        assert_eq!(state.cursor(), 27);
        assert_eq!(state.window(), 27..39, "window follows the cursor up");
        state.apply(&Key::PageUp);
        state.apply(&Key::PageUp);
        state.apply(&Key::PageUp);
        assert_eq!(state.cursor(), 0, "first page clamps to the first item");
        assert_eq!(state.window(), 0..12);
    }

    #[test]
    fn home_and_end_jump_to_the_extremes() {
        let mut state = PageState::new(40, 12, 20);
        state.apply(&Key::End);
        assert_eq!(state.cursor(), 39);
        assert_eq!(state.window(), 28..40);
        state.apply(&Key::Home);
        assert_eq!(state.cursor(), 0);
        assert_eq!(state.window(), 0..12);
    }

    #[test]
    fn initial_cursor_deep_in_the_list_starts_on_screen() {
        // Regression for the cliclack behavior where an initial value past
        // the first page rendered with the highlighted row off-screen.
        let state = PageState::new(40, 12, 30);
        assert!(state.window().contains(&30));
    }

    #[test]
    fn unrelated_keys_do_not_move() {
        let mut state = PageState::new(10, 4, 2);
        let before = state;
        assert!(!state.apply(&Key::Char('x')));
        assert!(!state.apply(&Key::Tab));
        assert_eq!(state, before);
    }

    #[test]
    fn shrinking_and_growing_the_terminal_keeps_the_cursor_visible() {
        let mut state = PageState::new(40, 12, 0);
        state.apply(&Key::PageDown);
        assert_eq!(state.cursor(), 12);
        state.resize(4);
        assert!(state.window().contains(&12));
        state.resize(50);
        assert_eq!(state.window(), 0..40, "growing shows everything again");
        assert_eq!(state.cursor(), 12);
    }

    #[test]
    fn growing_the_page_never_leaves_blank_rows_below_the_list() {
        let mut state = PageState::new(40, 12, 0);
        state.apply(&Key::End);
        assert_eq!(state.window(), 28..40);
        state.resize(20);
        assert_eq!(state.window(), 20..40, "window backfills from the bottom");
    }

    #[test]
    fn tiny_lists_never_scroll_and_degenerate_rows_still_work() {
        let state = PageState::new(3, 12, 1);
        assert!(!state.scrolls());
        assert_eq!(state.window(), 0..3);
        // A zero-row page is impossible to draw; it is clamped to one.
        let mut one = PageState::new(5, 0, 0);
        one.apply(&Key::PageDown);
        assert_eq!(one.cursor(), 1);
        assert!(one.window().contains(&1));
        // An empty list stays inert rather than panicking.
        let mut empty = PageState::new(0, 5, 0);
        assert!(empty.apply(&Key::ArrowDown));
        assert_eq!(empty.window(), 0..0);
    }

    fn forty_item_select() -> PagedSelect<usize> {
        let mut select = PagedSelect::new("40 record(s)");
        for index in 0..40 {
            select = select.item(index, format!("item {index}"), "");
        }
        select
    }

    #[test]
    fn frames_draw_only_the_visible_window_with_the_cursor_marked() {
        let select = forty_item_select();
        let state = PageState::new(40, 12, 13);
        let frame = plain(&select.active_frame(&state, 80));
        assert!(frame.contains("40 record(s)"));
        assert!(
            frame.contains("● item 13"),
            "cursor row uses the active radio"
        );
        assert!(frame.contains("○ item 2"));
        assert!(
            !frame.contains("item 14\n"),
            "rows below the window are absent"
        );
        assert!(
            frame.contains("3-14 of 40"),
            "footer states the visible range"
        );
        assert!(
            frame.contains("PgUp/PgDn"),
            "footer advertises the paging keys"
        );
    }

    #[test]
    fn short_lists_render_without_a_range_and_long_labels_cannot_wrap() {
        let select = PagedSelect::new("pick")
            .item(1usize, "a".repeat(300), "")
            .item(2usize, "b", "");
        let frame = plain(&select.active_frame(&PageState::new(2, 10, 0), 40));
        assert!(!frame.contains(" of 2"), "no range when everything fits");
        assert!(
            frame
                .lines()
                .all(|line| console::measure_text_width(line) <= 40),
            "every drawn line fits the terminal width"
        );
        assert!(
            frame.contains('…'),
            "the long label is truncated, not wrapped"
        );
    }

    #[test]
    fn selected_hint_shows_and_unselected_hint_hides() {
        let select = PagedSelect::new("pick")
            .item(1usize, "Done", "quit")
            .item(2usize, "other", "hidden");
        let frame = plain(&select.active_frame(&PageState::new(2, 10, 0), 80));
        assert!(frame.contains("● Done (quit)"));
        assert!(!frame.contains("hidden"));
    }

    #[test]
    fn closing_frames_match_the_cliclack_transcript_shape() {
        let submitted = plain(&closing_frame("title", "chosen", Outcome::Submitted, 80));
        assert!(submitted.starts_with("◇  title\n"));
        assert!(submitted.contains("│  chosen\n"));
        let cancelled = plain(&closing_frame("title", "chosen", Outcome::Cancelled, 80));
        assert!(cancelled.starts_with("■  title\n"));
        assert!(cancelled.ends_with("└  Operation cancelled.\n"));
    }

    #[test]
    fn a_scripted_session_pages_to_a_deep_item() {
        // Drive the same state transitions interact() performs for the key
        // sequence PageDown, PageDown, ArrowUp, Enter on a 40-item list.
        let mut state = PageState::new(40, 12, 0);
        for key in [Key::PageDown, Key::PageDown, Key::ArrowUp] {
            state.apply(&key);
        }
        assert_eq!(state.cursor(), 23);
        assert!(state.window().contains(&23));
    }
}
