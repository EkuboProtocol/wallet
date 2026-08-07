//! The terminal implementation of the approval presentation seam.
//!
//! Everything here is presentation: the review document arrives fully
//! authored by the orchestrator, and the only output is a decision. The one
//! security property this module owns is the shape of the picker — two named
//! outcomes with the cursor starting on Reject, so approval always takes a
//! deliberate movement.
//!
//! Two renderings share that shape. [`TerminalApprovalUi`] prints the
//! document into the scrollback and asks inline, for the short local
//! confirmations; [`review_fullscreen`] draws it on the alternate screen
//! with its own scroll state, for every review of something being signed —
//! transactions, typed data, messages — whose document must be readable in
//! full. There, Approve additionally cannot be confirmed until the end of
//! the document has been on screen.

use crate::{
    approval::{ApprovalDecision, ApprovalFact, ApprovalRequest, ApprovalUi},
    fullscreen::{self, Line, Screen, Span},
    sanitize::terminal_safe_line as terminal_safe,
    tui::Tone,
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::{Line as UiLine, Span as UiSpan},
    widgets::Paragraph,
};
use std::{fmt::Write as _, io::IsTerminal};

/// Polished terminal fallback for direct CLI use and MCP clients without app UI.
#[derive(Debug, Default, Clone, Copy)]
pub struct TerminalApprovalUi;

#[async_trait]
impl ApprovalUi for TerminalApprovalUi {
    async fn review(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        let request = request.clone();
        tokio::task::spawn_blocking(move || review_in_terminal(&request))
            .await
            .context("terminal approval task failed")?
    }
}

fn review_in_terminal(request: &ApprovalRequest) -> Result<ApprovalDecision> {
    ensure!(
        std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && std::io::stderr().is_terminal(),
        "approval requires an interactive terminal"
    );

    crate::tui::intro("Ekubo Wallet approval");

    let mut body = terminal_safe(&request.summary);
    for fact in &request.facts {
        write!(
            body,
            "\n{}: {}",
            terminal_safe(&fact.label),
            terminal_safe(&fact.value)
        )?;
    }
    if let Some(digest) = &request.digest {
        write!(body, "\nDigest: {}", terminal_safe(digest))?;
    }
    write!(body, "\nRequest: {}", request.id)?;
    for section in &request.sections {
        write!(body, "\n\n{}", terminal_safe(&section.heading))?;
        for fact in &section.facts {
            if fact.label.is_empty() {
                write!(body, "\n  {}", terminal_safe(&fact.value))?;
            } else {
                write!(
                    body,
                    "\n{}: {}",
                    terminal_safe(&fact.label),
                    terminal_safe(&fact.value)
                )?;
            }
        }
    }

    crate::tui::note(terminal_safe(&request.title), body);
    for warning in &request.warnings {
        crate::tui::warning(terminal_safe(warning));
    }

    // Two named outcomes rather than a yes/no: at a `(y/N)` prompt the safe
    // answer is the one you get by not reading, and the destructive one is a
    // single character away. Here both outcomes are spelled out, the cursor
    // starts on the one that signs nothing, and approving takes a deliberate
    // move onto it. Esc and Ctrl+C read as rejection for the same reason: an
    // approval must be explicit.
    let approved = crate::tui::pick(
        "Approve or reject this action?",
        vec![
            "Reject — nothing is signed or submitted".to_owned(),
            "Approve — sign this exact action".to_owned(),
        ],
        2,
    )?
    .is_some_and(|choice| choice == 1);
    if approved {
        crate::tui::outro("Approved; owner authentication is still required.");
        Ok(ApprovalDecision::Approved)
    } else {
        crate::tui::outro_cancel("Rejected. Nothing was signed or submitted.");
        Ok(ApprovalDecision::Rejected)
    }
}

/// Full-screen review of a signing request: the complete document — summary,
/// facts, sections, the exact payload being signed, and the warnings — on
/// the alternate screen with its own scroll state, ending in the same
/// reject-default picker as the inline review.
///
/// The payload lines are appended after the authored sections, so the whole
/// review is one scrollable text and the position indicator counts the
/// payload too. Approve cannot be confirmed until the end of the document
/// has been on screen; Reject always can.
pub async fn review_fullscreen(
    request: &ApprovalRequest,
    payload: Vec<Line>,
) -> Result<ApprovalDecision> {
    let request = request.clone();
    tokio::task::spawn_blocking(move || review_fullscreen_blocking(&request, payload))
        .await
        .context("terminal approval task failed")?
}

fn review_fullscreen_blocking(
    request: &ApprovalRequest,
    payload: Vec<Line>,
) -> Result<ApprovalDecision> {
    ensure!(
        std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && std::io::stderr().is_terminal(),
        "approval requires an interactive terminal"
    );
    let mut review = ReviewScreen::new(review_document(request, payload));
    let title = terminal_safe(&request.title);
    let decision = {
        let mut screen = Screen::enter()?;
        loop {
            screen
                .terminal
                .draw(|frame| draw(frame, &title, &mut review))?;
            let key = match crossterm::event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => key,
                // Anything else — a resize above all — just redraws against
                // the new terminal size.
                _ => continue,
            };
            if let Some(decision) = review.handle_key(key) {
                break decision;
            }
        }
        // `screen` drops here: raw mode off, main screen back, so the outro
        // lands in the scrollback transcript.
    };
    match decision {
        ApprovalDecision::Approved => {
            crate::tui::outro("Approved; owner authentication is still required.");
        }
        ApprovalDecision::Rejected => {
            crate::tui::outro_cancel("Rejected. Nothing was signed or submitted.");
        }
    }
    Ok(decision)
}

/// The authored document plus the payload as one styled text, in the same
/// visual language as the transaction browser's detail view: aligned muted
/// label columns, emphasized section headings, signed amounts toned by their
/// sign. Every span is built through the sanitizing [`Span`] constructors,
/// so stored text cannot draw chrome here any more than it can in the
/// browsers.
///
/// The warnings come last, after the sections and the payload: the decision
/// pane refuses Approve until the end of the document has been on screen, so
/// last is the one position a long document can never scroll them away from.
fn review_document(request: &ApprovalRequest, payload: Vec<Line>) -> Vec<Line> {
    let mut lines: Vec<Line> = vec![vec![Span::plain(&request.summary)], Vec::new()];
    let mut header = request.facts.clone();
    if let Some(digest) = &request.digest {
        header.push(ApprovalFact {
            label: "Digest".into(),
            value: digest.clone(),
        });
    }
    header.push(ApprovalFact {
        label: "Request".into(),
        value: request.id.to_string(),
    });
    lines.extend(fact_block(&header, ""));
    for section in &request.sections {
        lines.push(Vec::new());
        lines.push(vec![Span::toned(&section.heading, Tone::Emphasis)]);
        lines.extend(fact_block(&section.facts, "  "));
    }
    lines.extend(payload);
    for warning in &request.warnings {
        lines.push(Vec::new());
        lines.push(vec![Span::toned(format!("⚠ {warning}"), Tone::Warning)]);
    }
    lines
}

/// Labels wider than this stop stretching the value column for everyone
/// else; such a row simply runs long, and its value follows inline.
const MAX_LABEL_COLUMNS: usize = 32;

/// One aligned label/value block: muted labels padded to a shared column,
/// values beside them. A fact with an empty label continues the fact above
/// it — calldata rows — and starts at the value column.
fn fact_block(facts: &[ApprovalFact], indent: &str) -> Vec<Line> {
    use crate::fullscreen::display_width;
    let width = facts
        .iter()
        .map(|fact| display_width(&fact.label))
        .filter(|width| *width <= MAX_LABEL_COLUMNS)
        .max()
        .unwrap_or_default();
    facts
        .iter()
        .map(|fact| {
            let padding = width.saturating_sub(display_width(&fact.label));
            vec![
                Span::toned(
                    format!("{indent}{}{}  ", fact.label, " ".repeat(padding)),
                    Tone::Muted,
                ),
                value_span(&fact.value),
            ]
        })
        .collect()
}

/// Signed amounts — a leading `+` or `-` on a digit — read green or red, the
/// same rule the transaction browser's balance table uses. A presentation
/// rule about number formatting, not knowledge of any particular fact.
fn value_span(value: &str) -> Span {
    let signed = value
        .strip_prefix(['+', '-'])
        .is_some_and(|rest| rest.starts_with(|character: char| character.is_ascii_digit()));
    if signed {
        let tone = if value.starts_with('+') {
            Tone::Success
        } else {
            Tone::Danger
        };
        Span::toned(value, tone)
    } else {
        Span::plain(value)
    }
}

/// Scroll and decision state of one full-screen review. Layout-derived
/// fields (`viewport`, `max_offset`, `reached_end`) are refreshed by
/// [`draw`] each frame, so a resize that reveals the end counts as reaching
/// it and one that hides it again does not un-count.
struct ReviewScreen {
    document: Vec<Line>,
    offset: usize,
    viewport: usize,
    max_offset: usize,
    /// The last line has been on screen at some point.
    reached_end: bool,
    /// The picker cursor; starts on Reject so approving takes a deliberate
    /// movement, exactly like the inline picker.
    on_approve: bool,
    notice: Option<String>,
}

impl ReviewScreen {
    fn new(document: Vec<Line>) -> Self {
        Self {
            document,
            offset: 0,
            viewport: 1,
            max_offset: 0,
            reached_end: false,
            on_approve: false,
            notice: None,
        }
    }

    /// `Some` is the review's final answer. Esc, `q`, and Ctrl+C all read as
    /// rejection: an approval must be explicit. The scrolling keys can never
    /// decide, and Enter on Approve is refused until the end of the document
    /// has been seen.
    fn handle_key(&mut self, key: KeyEvent) -> Option<ApprovalDecision> {
        self.notice = None;
        if fullscreen::is_interrupt(key) {
            return Some(ApprovalDecision::Rejected);
        }
        let page = self.viewport.max(1);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Some(ApprovalDecision::Rejected),
            KeyCode::Enter => {
                if !self.on_approve {
                    return Some(ApprovalDecision::Rejected);
                }
                if self.reached_end {
                    return Some(ApprovalDecision::Approved);
                }
                self.notice =
                    Some("Scroll to the end of the document before approving.".to_owned());
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                self.on_approve = !self.on_approve;
            }
            KeyCode::Up | KeyCode::Char('k') => self.offset = self.offset.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.offset = self.offset.saturating_add(1),
            KeyCode::PageUp | KeyCode::Char('b') => self.offset = self.offset.saturating_sub(page),
            KeyCode::PageDown | KeyCode::Char(' ' | 'f') => {
                self.offset = self.offset.saturating_add(page);
            }
            KeyCode::Home | KeyCode::Char('g') => self.offset = 0,
            KeyCode::End | KeyCode::Char('G') => self.offset = usize::MAX,
            _ => {}
        }
        None
    }

    fn position(&self) -> String {
        if self.offset >= self.max_offset {
            "end".to_owned()
        } else {
            format!("{}%", (self.offset * 100) / self.max_offset.max(1))
        }
    }
}

/// Wrap the document for the viewport with a hanging indent on fact lines: a
/// value that wraps continues at its value column, one visual block beside
/// its label, instead of snapping back under the label column. A fact line
/// is recognized by its shape — a muted leading span with content after it —
/// which is exactly how [`fact_block`] builds one.
fn wrap_document(document: &[Line], columns: usize) -> Vec<Line> {
    document
        .iter()
        .flat_map(|line| {
            let indent = match line.as_slice() {
                [label, _, ..] if label.tone == Some(Tone::Muted) => {
                    crate::fullscreen::display_width(&label.text)
                }
                _ => 0,
            };
            fullscreen::wrap_line_hanging(line, columns, indent)
        })
        .collect()
}

fn draw(frame: &mut ratatui::Frame, title: &str, review: &mut ReviewScreen) {
    let [header, body, decision, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(fullscreen::title_line(title), header);

    let columns = (body.width as usize).saturating_sub(2).max(10);
    let wrapped = wrap_document(&review.document, columns);
    // `max(1)` keeps the scrolling arithmetic sane in a terminal too short to
    // give the body any rows at all. It must not also stand in as evidence
    // that the document was read: with no rows, `Paragraph` draws nothing, and
    // a short document would otherwise satisfy "scrolled to the end" — and so
    // enable approval — having shown the reviewer not one line of what they
    // were approving.
    let drawn_rows = body.height as usize;
    review.viewport = drawn_rows.max(1);
    review.max_offset = wrapped.len().saturating_sub(review.viewport);
    review.offset = review.offset.min(review.max_offset);
    if drawn_rows > 0 && review.offset >= review.max_offset {
        review.reached_end = true;
    }
    let visible: Vec<UiLine> = wrapped
        .iter()
        .skip(review.offset)
        .take(review.viewport)
        .map(|line| {
            let mut spans = vec![UiSpan::raw(" ")];
            spans.extend(line.iter().map(fullscreen::ui_span));
            UiLine::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(visible), body);

    let option = |selected: bool, text: String| {
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
    let approve_label = if review.reached_end {
        "Approve — sign this exact action".to_owned()
    } else {
        "Approve — scroll to the end of the document first".to_owned()
    };
    frame.render_widget(
        Paragraph::new(vec![
            UiLine::default(),
            option(
                !review.on_approve,
                "Reject — nothing is signed or submitted".to_owned(),
            ),
            option(review.on_approve, approve_label),
        ]),
        decision,
    );

    let hints = format!(
        "{} · ↑↓ scroll · PgUp/PgDn page · Tab switch · Enter decide · Esc rejects",
        review.position()
    );
    frame.render_widget(
        fullscreen::footer_line(review.notice.as_deref(), &hints),
        footer,
    );
}

#[cfg(test)]
#[path = "approve_tui_test.rs"]
mod tests;
