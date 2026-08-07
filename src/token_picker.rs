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
//!
//! A list is too long to look at whole, so `/` searches it by symbol, name, or
//! address and `c` narrows it to one chain. Filtering only ever changes what is
//! on screen and what the bulk keys reach — never what a decision writes, which
//! stays every checked token. The title therefore always reports the whole
//! selection rather than the visible part of it, and a decision taken while a
//! filter hides checked suggestions asks for a second keypress, because
//! "accept" against eight visible rows must not quietly name three thousand.

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Alignment, Rect},
    text::Line as UiLine,
    widgets::{List, ListItem, ListState, Paragraph},
};

use crate::{
    fullscreen::{
        Line, Screen, Span, chrome, footer_line, is_interrupt, matches_filter, title_line, ui_span,
    },
    render::terminal_safe_line,
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
    /// Lowercased symbol, name, and address per token: what the search matches
    /// against, rather than the text a row happens to have room to show.
    haystacks: Vec<String>,
    checked: Vec<bool>,
    expanded: bool,
    /// Indices into `tokens` passing the current filters, recomputed whenever
    /// either filter changes. With no filter this is every index, which is why
    /// the unfiltered screen behaves exactly as it did before there was one.
    shown: Vec<usize>,
}

impl Group {
    fn selected(&self) -> usize {
        self.checked.iter().filter(|checked| **checked).count()
    }

    /// Tri-state, because "some" has to be visually distinct from "all" or a
    /// partially selected group collapses into a checkbox that lies.
    ///
    /// Counted over the whole group rather than the visible part of it: the
    /// mark describes what the group would contribute to a decision, and a
    /// filter does not change that.
    fn mark(&self) -> &'static str {
        match self.selected() {
            0 => "[ ]",
            selected if selected == self.tokens.len() => "[x]",
            _ => "[~]",
        }
    }

    fn shown_selected(&self) -> usize {
        self.shown
            .iter()
            .filter(|&&token| self.checked[token])
            .count()
    }

    /// Check or uncheck everything the filters currently show. Bulk keys act
    /// on what the owner can see — that is the point of narrowing the list —
    /// and the title keeps reporting the whole selection so what a filter
    /// hides is never mistaken for what a decision writes.
    fn set_shown(&mut self, checked: bool) {
        for &token in &self.shown {
            self.checked[token] = checked;
        }
    }

    fn refilter(&mut self, filter: &str, chain: Option<u64>) {
        self.shown = (0..self.tokens.len())
            .filter(|&token| {
                chain.is_none_or(|chain| self.tokens[token].chain_id == chain)
                    && matches_filter(&self.haystacks[token], filter)
            })
            .collect();
    }
}

struct App {
    groups: Vec<Group>,
    rows: Vec<Row>,
    cursor: usize,
    state: ListState,
    notice: Option<String>,
    /// The `/` search: every whitespace-separated term must appear in a
    /// token's symbol, name, or address.
    filter: String,
    /// Whether keystrokes edit the search instead of driving the list.
    typing: bool,
    /// Every chain the suggestions cover, ascending; `c` cycles through them.
    chains: Vec<u64>,
    /// Position in `chains` of the only chain being shown, or `None` for all.
    chain: Option<usize>,
    /// A decision that asked for confirmation because a filter is hiding part
    /// of what it would write. Cleared by any other key.
    pending: Option<Outcome>,
    /// Body rows the last frame had, so paging moves by what is on screen.
    viewport: usize,
}

impl App {
    fn new(groups: Vec<TokenGroup>) -> Self {
        let mut chains: Vec<u64> = groups
            .iter()
            .flat_map(|group| group.tokens.iter().map(|token| token.chain_id))
            .collect();
        chains.sort_unstable();
        chains.dedup();
        let groups = groups
            .into_iter()
            .map(|group| Group {
                checked: vec![true; group.tokens.len()],
                shown: (0..group.tokens.len()).collect(),
                haystacks: group.tokens.iter().map(haystack).collect(),
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
            filter: String::new(),
            typing: false,
            chains,
            chain: None,
            pending: None,
            viewport: 1,
        };
        if app.groups.len() == 1 {
            app.groups[0].expanded = true;
        }
        app.rebuild_rows();
        app
    }

    /// The chain the list is narrowed to, or `None` when it shows all of them.
    fn chain_filter(&self) -> Option<u64> {
        self.chain.and_then(|index| self.chains.get(index).copied())
    }

    fn filtering(&self) -> bool {
        !self.filter.is_empty() || self.chain.is_some()
    }

    /// Re-derive what each group shows, then the rows built from it.
    fn refilter(&mut self) {
        let chain = self.chain_filter();
        for group in &mut self.groups {
            group.refilter(&self.filter, chain);
        }
        self.rebuild_rows();
    }

    fn clear_filters(&mut self) {
        self.filter.clear();
        self.chain = None;
        self.refilter();
    }

    fn cycle_chain(&mut self) {
        if self.chains.len() < 2 {
            self.notice = Some(match self.chains.first() {
                Some(chain) => format!("Every suggestion is on chain {chain}; nothing to narrow."),
                None => "There is nothing to narrow.".into(),
            });
            return;
        }
        self.chain = match self.chain {
            None => Some(0),
            Some(index) if index + 1 < self.chains.len() => Some(index + 1),
            Some(_) => None,
        };
        self.refilter();
    }

    /// The visible rows, recomputed whenever expansion or a filter changes.
    /// Keeping the flattened list derived rather than stored means a group
    /// cannot get out of step with the rows that represent it.
    fn rebuild_rows(&mut self) {
        let anchor = self.rows.get(self.cursor).copied();
        let filtering = self.filtering();
        self.rows.clear();
        for (index, group) in self.groups.iter().enumerate() {
            // A group a filter emptied is dropped entirely: a header over no
            // rows is just something to scroll past.
            if filtering && group.shown.is_empty() {
                continue;
            }
            self.rows.push(Row::Group(index));
            // Searching is a request to see the hits, so a filter expands what
            // it matched; the owner's own expansion returns when it clears.
            if group.expanded || filtering {
                for &token in &group.shown {
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

    fn total_shown(&self) -> usize {
        self.groups.iter().map(|group| group.shown.len()).sum()
    }

    /// Checked tokens the filters are hiding: what a decision would write
    /// without the screen having shown it.
    fn hidden_selected(&self) -> usize {
        self.total_selected() - self.groups.iter().map(Group::shown_selected).sum::<usize>()
    }

    fn toggle(&mut self) {
        match self.rows.get(self.cursor).copied() {
            Some(Row::Group(index)) => {
                let group = &mut self.groups[index];
                let all = group.shown_selected() == group.shown.len();
                group.set_shown(!all);
            }
            Some(Row::Token(group, token)) => {
                let checked = &mut self.groups[group].checked[token];
                *checked = !*checked;
            }
            None => {}
        }
    }

    fn set_expanded(&mut self, expanded: bool) {
        if !expanded && self.filtering() {
            self.notice = Some("Clear the filter (Esc) to collapse groups again.".into());
            return;
        }
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

    /// Guard a decision before it leaves the screen: refuse an empty one, and
    /// make one taken while a filter hides checked suggestions cost a second,
    /// deliberate keypress. Narrowing to eight rows and pressing accept must
    /// not silently name the three thousand still checked behind the filter.
    fn decide(&mut self, outcome: Outcome, pending: Option<Outcome>) -> Outcome {
        let selected = self.total_selected();
        if selected == 0 {
            self.notice = Some(if outcome == Outcome::Reject {
                "Nothing selected to reject.".into()
            } else {
                "Nothing selected. Press q to leave these undecided.".into()
            });
            return Outcome::Stay;
        }
        let hidden = self.hidden_selected();
        if hidden > 0 && pending != Some(outcome) {
            let (verb, key) = if outcome == Outcome::Reject {
                ("Rejecting", "r")
            } else {
                ("Accepting", "\u{23ce}")
            };
            self.notice = Some(format!(
                "{verb} all {selected} selected, including {hidden} the filter is hiding. \
                 Press {key} again to confirm."
            ));
            self.pending = Some(outcome);
            return Outcome::Stay;
        }
        outcome
    }

    /// The header: the whole selection first, because that is what a decision
    /// writes, and only then what the filters are showing of it.
    ///
    /// The list name is the agent's own claim, not a verified curator, and it
    /// is the grouping the owner judges a batch of names by. Say so where it
    /// is read rather than letting emphasis imply provenance — and say it
    /// ahead of the filter status, so a narrow terminal clips the filter
    /// rather than the disclosure. What a filter is doing is also on every
    /// group row and in the footer; where the list names came from is said
    /// here or nowhere.
    fn title(&self) -> String {
        let selection = format!(
            "Token names to confirm — {} of {} selected · list names are the agent's own claim",
            self.total_selected(),
            self.total_tokens()
        );
        let mut filters = Vec::new();
        if let Some(chain) = self.chain_filter() {
            filters.push(format!("chain {chain}"));
        }
        if !self.filter.is_empty() {
            filters.push(format!(
                "\u{201c}{}\u{201d}",
                terminal_safe_line(&self.filter)
            ));
        }
        if filters.is_empty() {
            selection
        } else {
            format!(
                "{selection} · showing {} for {}",
                self.total_shown(),
                filters.join(" + ")
            )
        }
    }

    fn footer_hints(&self) -> String {
        if self.typing {
            return format!(
                "Search: {}\u{258f}  Enter to keep · Esc to clear",
                terminal_safe_line(&self.filter)
            );
        }
        let mut hints = String::from("space toggle · →/← expand · a all · n none · / search");
        if self.chains.len() > 1 {
            hints.push_str(" · c chain");
        }
        if self.filtering() {
            hints.push_str(" · Esc clear filter");
        }
        hints.push_str(" · ⏎ accept · r reject · q cancel");
        hints
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
                        let mut line = vec![
                            Span::plain(format!("{} ", group.mark())),
                            Span::toned(
                                if group.expanded || self.filtering() {
                                    "▼ "
                                } else {
                                    "▶ "
                                },
                                Tone::Muted,
                            ),
                            Span::toned(&group.source, Tone::Emphasis),
                            Span::toned(
                                format!("  {} of {} tokens", group.selected(), group.tokens.len()),
                                Tone::Muted,
                            ),
                        ];
                        if self.filtering() {
                            line.push(Span::toned(
                                format!(" · {} shown", group.shown.len()),
                                Tone::Info,
                            ));
                        }
                        line
                    }
                    // What the wallet knows comes first, what the list claims
                    // comes last. The address, chain, and decimals are fixed
                    // width and are the whole of what confirming decides; the
                    // symbol and name are the curator's text, and a row is
                    // clipped at the right edge, so putting them first let a
                    // long enough symbol — or a short one padded with spaces —
                    // push the address off the screen and leave the owner
                    // ticking a familiar ticker against an address they were
                    // never shown. Nothing written by the party being reviewed
                    // decides where anything else on its row appears.
                    Row::Token(group, token) => {
                        let entry = &self.groups[*group];
                        let listed = &entry.tokens[*token];
                        let mut line = vec![
                            Span::plain(format!(
                                "    {} ",
                                if entry.checked[*token] { "[x]" } else { "[ ]" }
                            )),
                            Span::plain(listed.address.to_checksum(None)),
                            Span::toned(
                                format!(
                                    "  chain {}  {} decimals  ",
                                    listed.chain_id, listed.decimals
                                ),
                                Tone::Muted,
                            ),
                            Span::toned(&listed.symbol, Tone::Info),
                        ];
                        // The name is searchable, so it is shown: a search that
                        // matched on something invisible reads as a wrong hit,
                        // and "USDC" carrying the name of something else is
                        // exactly what this screen exists to catch.
                        if let Some(name) = &listed.name {
                            line.push(Span::toned(format!("  {name}"), Tone::Muted));
                        }
                        line
                    }
                };
                (line, selected)
            })
            .collect()
    }
}

/// What the search matches a token by: the values a person knows it by, all
/// lowercased so the terms can be compared directly.
fn haystack(token: &ListedToken) -> String {
    format!(
        "{} {} {}",
        token.symbol,
        token.name.as_deref().unwrap_or_default(),
        token.address.to_checksum(None)
    )
    .to_lowercase()
}

fn draw(frame: &mut ratatui::Frame, app: &mut App) {
    let (header, body, footer) = chrome(frame.area());
    frame.render_widget(title_line(&app.title()), header);
    render_rows(frame, app, body);
    let hints = app.footer_hints();
    frame.render_widget(footer_line(app.notice.as_deref(), &hints), footer);
}

fn render_rows(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    app.viewport = usize::from(area.height).max(1);
    if app.rows.is_empty() {
        frame.render_widget(
            Paragraph::new(UiLine::from(ui_span(&Span::toned(
                "No suggestion matches this filter.",
                Tone::Muted,
            ))))
            .alignment(Alignment::Center),
            area,
        );
        return;
    }
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
    // While the search is being typed every letter belongs to it, so none of
    // the bindings below can fire from inside a query.
    if app.typing {
        match key.code {
            KeyCode::Esc => {
                app.filter.clear();
                app.typing = false;
                app.refilter();
            }
            // Enter only keeps the query and hands the keys back to the list;
            // deciding anything takes a second, deliberate Enter.
            KeyCode::Enter => app.typing = false,
            KeyCode::Backspace => {
                app.filter.pop();
                app.refilter();
            }
            KeyCode::Char(character) if !character.is_control() => {
                app.filter.push(character);
                app.refilter();
            }
            KeyCode::Up => app.move_cursor(-1),
            KeyCode::Down => app.move_cursor(1),
            _ => {}
        }
        return Outcome::Stay;
    }
    // A confirmation survives only the keypress that asked for it: the second
    // Enter has to be the very next key, not one arrived at later.
    let pending = app.pending.take();
    let page = app.viewport.max(1).cast_signed();
    match key.code {
        // Esc backs out one layer at a time, so a filter is cleared before Esc
        // ever means "decide nothing and leave".
        KeyCode::Esc if app.filtering() => app.clear_filters(),
        KeyCode::Char('q') | KeyCode::Esc => return Outcome::Cancel,
        KeyCode::Enter => return app.decide(Outcome::Accept, pending),
        KeyCode::Char('r') => return app.decide(Outcome::Reject, pending),
        KeyCode::Char('/') => app.typing = true,
        KeyCode::Char('c') => app.cycle_chain(),
        KeyCode::Up | KeyCode::Char('k') => app.move_cursor(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_cursor(1),
        KeyCode::PageUp => app.move_cursor(-page),
        KeyCode::PageDown => app.move_cursor(page),
        KeyCode::Char(' ') => app.toggle(),
        KeyCode::Right | KeyCode::Char('l') => app.set_expanded(true),
        KeyCode::Left | KeyCode::Char('h') => app.set_expanded(false),
        KeyCode::Char('a') => {
            for group in &mut app.groups {
                group.set_shown(true);
            }
        }
        KeyCode::Char('n') => {
            for group in &mut app.groups {
                group.set_shown(false);
            }
        }
        KeyCode::Home | KeyCode::Char('g') => app.move_cursor(isize::MIN / 2),
        KeyCode::End | KeyCode::Char('G') => app.move_cursor(isize::MAX / 2),
        _ => {}
    }
    Outcome::Stay
}

#[cfg(test)]
#[path = "token_picker_test.rs"]
mod tests;
