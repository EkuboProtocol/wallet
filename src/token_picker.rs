//! The owner's decision surface for token names.
//!
//! Naming a token is a security decision — the review screen shows a token's
//! symbol, and a symbol the owner trusts is worth forging — but it is a
//! decision that arrives in bulk. A single token list is hundreds of entries,
//! and a prompt per entry would be answered by holding down `y`, which is not
//! consent so much as a slower way of accepting everything.
//!
//! So the unit of decision here is the list, not the token. Suggestions arrive
//! grouped by the source that vouched for them, each group collapses to one
//! line the owner can accept or reject whole, and expanding a group is for the
//! cases where they want to look. Accepting is deliberate: nothing is written
//! until the owner presses the accept key, and what gets written is exactly
//! what the checkboxes show.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::Rect,
    text::Line as UiLine,
    widgets::{List, ListItem, ListState},
};

use crate::{
    fullscreen::{Line, Screen, Span, chrome, footer_line, is_interrupt, title_line, ui_span},
    token_store::ListedToken,
    tui::Tone,
};

/// One source's worth of suggestions: everything a single list vouched for.
pub struct TokenGroup {
    pub source: String,
    pub tokens: Vec<ListedToken>,
}

/// What the owner decided.
pub struct Decision {
    /// Tokens to confirm into the database.
    pub accepted: Vec<ListedToken>,
    /// Tokens explicitly rejected, so the caller can stop re-asking. Empty
    /// when the owner backed out without deciding.
    pub rejected: Vec<ListedToken>,
}

/// A row of the flattened display: either a group header or a token under it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Row {
    Group(usize),
    Token(usize, usize),
}

struct Group {
    source: String,
    tokens: Vec<ListedToken>,
    checked: Vec<bool>,
    expanded: bool,
}

impl Group {
    fn selected(&self) -> usize {
        self.checked.iter().filter(|checked| **checked).count()
    }

    /// Tri-state, because "some" has to be visually distinct from "all" or a
    /// partially selected group collapses into a checkbox that lies.
    fn mark(&self) -> &'static str {
        match self.selected() {
            0 => "[ ]",
            selected if selected == self.tokens.len() => "[x]",
            _ => "[~]",
        }
    }

    fn set_all(&mut self, checked: bool) {
        self.checked.fill(checked);
    }
}

struct App {
    groups: Vec<Group>,
    rows: Vec<Row>,
    cursor: usize,
    state: ListState,
    notice: Option<String>,
}

impl App {
    fn new(groups: Vec<TokenGroup>) -> Self {
        let groups = groups
            .into_iter()
            .map(|group| Group {
                checked: vec![true; group.tokens.len()],
                // A single group is the common case — one list, freshly
                // suggested — and collapsing it would hide the only thing on
                // screen behind a keystroke.
                expanded: false,
                source: group.source,
                tokens: group.tokens,
            })
            .collect::<Vec<_>>();
        let mut app = Self {
            groups,
            rows: Vec::new(),
            cursor: 0,
            state: ListState::default(),
            notice: None,
        };
        if app.groups.len() == 1 {
            app.groups[0].expanded = true;
        }
        app.rebuild_rows();
        app
    }

    /// The visible rows, recomputed whenever expansion changes. Keeping the
    /// flattened list derived rather than stored means a group cannot get out
    /// of step with the rows that represent it.
    fn rebuild_rows(&mut self) {
        let anchor = self.rows.get(self.cursor).copied();
        self.rows.clear();
        for (index, group) in self.groups.iter().enumerate() {
            self.rows.push(Row::Group(index));
            if group.expanded {
                for token in 0..group.tokens.len() {
                    self.rows.push(Row::Token(index, token));
                }
            }
        }
        // Keep the cursor on whatever it was pointing at; if that row is gone
        // (its group just collapsed), fall back to the group header.
        self.cursor = anchor
            .and_then(|row| self.rows.iter().position(|candidate| *candidate == row))
            .or_else(|| {
                anchor.and_then(|row| match row {
                    Row::Token(group, _) => self
                        .rows
                        .iter()
                        .position(|candidate| *candidate == Row::Group(group)),
                    Row::Group(_) => None,
                })
            })
            .unwrap_or(0)
            .min(self.rows.len().saturating_sub(1));
        self.state.select(Some(self.cursor));
    }

    fn total_selected(&self) -> usize {
        self.groups.iter().map(Group::selected).sum()
    }

    fn total_tokens(&self) -> usize {
        self.groups.iter().map(|group| group.tokens.len()).sum()
    }

    fn toggle(&mut self) {
        match self.rows.get(self.cursor).copied() {
            Some(Row::Group(index)) => {
                let group = &mut self.groups[index];
                let all = group.selected() == group.tokens.len();
                group.set_all(!all);
            }
            Some(Row::Token(group, token)) => {
                let checked = &mut self.groups[group].checked[token];
                *checked = !*checked;
            }
            None => {}
        }
    }

    fn set_expanded(&mut self, expanded: bool) {
        if let Some(Row::Group(index) | Row::Token(index, _)) = self.rows.get(self.cursor).copied()
        {
            // Collapsing from inside a group should land on that group's
            // header rather than wherever the row indices happen to shift to.
            if !expanded && matches!(self.rows.get(self.cursor), Some(Row::Token(_, _))) {
                self.cursor = self
                    .rows
                    .iter()
                    .position(|row| *row == Row::Group(index))
                    .unwrap_or(self.cursor);
            }
            self.groups[index].expanded = expanded;
            self.rebuild_rows();
        }
    }

    fn move_cursor(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let last = self.rows.len() - 1;
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
        self.state.select(Some(self.cursor));
    }

    fn decision(&self, accept: bool) -> Decision {
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for group in &self.groups {
            for (token, checked) in group.tokens.iter().zip(&group.checked) {
                // Rejecting means rejecting what is checked; the rest is left
                // undecided rather than silently dismissed, so a token the
                // owner never looked at is still there next time.
                if *checked {
                    if accept {
                        accepted.push(token.clone());
                    } else {
                        rejected.push(token.clone());
                    }
                }
            }
        }
        Decision { accepted, rejected }
    }

    fn lines(&self) -> Vec<(Line, bool)> {
        self.rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let selected = index == self.cursor;
                let line = match row {
                    Row::Group(group) => {
                        let group = &self.groups[*group];
                        vec![
                            Span::plain(format!("{} ", group.mark())),
                            Span::toned(if group.expanded { "▼ " } else { "▶ " }, Tone::Muted),
                            Span::toned(&group.source, Tone::Emphasis),
                            Span::toned(
                                format!("  {} of {} tokens", group.selected(), group.tokens.len()),
                                Tone::Muted,
                            ),
                        ]
                    }
                    Row::Token(group, token) => {
                        let entry = &self.groups[*group];
                        let listed = &entry.tokens[*token];
                        vec![
                            Span::plain(format!(
                                "    {} ",
                                if entry.checked[*token] { "[x]" } else { "[ ]" }
                            )),
                            Span::toned(&listed.symbol, Tone::Info),
                            Span::plain(format!("  {}", listed.address.to_checksum(None))),
                            Span::toned(
                                format!(
                                    "  chain {}  {} decimals",
                                    listed.chain_id, listed.decimals
                                ),
                                Tone::Muted,
                            ),
                        ]
                    }
                };
                (line, selected)
            })
            .collect()
    }
}

fn draw(frame: &mut ratatui::Frame, app: &mut App) {
    let (header, body, footer) = chrome(frame.area());
    frame.render_widget(
        title_line(&format!(
            "Token names to confirm — {} of {} selected",
            app.total_selected(),
            app.total_tokens()
        )),
        header,
    );
    render_rows(frame, app, body);
    let hints = "space toggle · →/← expand · a all · n none · ⏎ accept · r reject · q cancel";
    frame.render_widget(footer_line(app.notice.as_deref(), hints), footer);
}

fn render_rows(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem<'static>> = app
        .lines()
        .into_iter()
        .map(|(line, _)| ListItem::new(UiLine::from(line.iter().map(ui_span).collect::<Vec<_>>())))
        .collect();
    let list = List::new(items).highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut app.state);
}

/// Show the grouped picker and return what the owner decided, or `None` if
/// they backed out without deciding anything.
///
/// Requires a terminal: without one there is no owner present to confirm, and
/// silently accepting would defeat the entire point of asking.
pub fn review(groups: Vec<TokenGroup>) -> Result<Option<Decision>> {
    if !crate::tui::interactive() {
        return Ok(None);
    }
    let groups: Vec<TokenGroup> = groups
        .into_iter()
        .filter(|group| !group.tokens.is_empty())
        .collect();
    if groups.is_empty() {
        return Ok(None);
    }
    let mut app = App::new(groups);
    let mut screen = Screen::enter()?;
    loop {
        screen.terminal.draw(|frame| draw(frame, &mut app))?;
        let key = match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => key,
            // Anything else — a resize above all — just redraws.
            _ => continue,
        };
        app.notice = None;
        if is_interrupt(key) {
            return Ok(None);
        }
        match handle_key(&mut app, key) {
            Outcome::Stay => {}
            Outcome::Cancel => return Ok(None),
            Outcome::Accept => return Ok(Some(app.decision(true))),
            Outcome::Reject => return Ok(Some(app.decision(false))),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    Stay,
    Cancel,
    Accept,
    Reject,
}

fn handle_key(app: &mut App, key: KeyEvent) -> Outcome {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return Outcome::Cancel,
        KeyCode::Enter => {
            if app.total_selected() == 0 {
                app.notice = Some("Nothing selected. Press q to leave these undecided.".into());
                return Outcome::Stay;
            }
            return Outcome::Accept;
        }
        KeyCode::Char('r') => {
            if app.total_selected() == 0 {
                app.notice = Some("Nothing selected to reject.".into());
                return Outcome::Stay;
            }
            return Outcome::Reject;
        }
        KeyCode::Up | KeyCode::Char('k') => app.move_cursor(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_cursor(1),
        KeyCode::Char(' ') => app.toggle(),
        KeyCode::Right | KeyCode::Char('l') => app.set_expanded(true),
        KeyCode::Left | KeyCode::Char('h') => app.set_expanded(false),
        KeyCode::Char('a') => {
            for group in &mut app.groups {
                group.set_all(true);
            }
        }
        KeyCode::Char('n') => {
            for group in &mut app.groups {
                group.set_all(false);
            }
        }
        KeyCode::Home | KeyCode::Char('g') => app.move_cursor(isize::MIN / 2),
        KeyCode::End | KeyCode::Char('G') => app.move_cursor(isize::MAX / 2),
        _ => {}
    }
    Outcome::Stay
}

#[cfg(test)]
mod tests {
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
}
