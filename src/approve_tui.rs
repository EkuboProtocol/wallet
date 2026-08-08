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
    approval::{ApprovalDecision, ApprovalFact, ApprovalRequest, ApprovalUi, ReviewRefresh},
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
    review_fullscreen_refreshable(request, payload, None).await
}

/// The same review, with `r` bound to re-running the simulation behind it.
///
/// Offered only where a refresh means something. A typed-data or message
/// review has no simulation to re-run, so it gets `None` and the key does
/// nothing — an affordance that answers "cannot be re-simulated" would be a
/// worse screen than one that never offers it.
///
/// The refresh runs on the async side while this screen stays up. That is the
/// reason for the channel pair rather than simply returning and being called
/// again: leaving and re-entering the alternate screen for every refresh is
/// the mode-flipping this codebase deliberately does not do, and it would
/// leave the reviewer looking at their ordinary terminal for however long the
/// RPC takes — which, with endpoint failover, can be a long time.
pub async fn review_fullscreen_refreshable(
    request: &ApprovalRequest,
    payload: Vec<Line>,
    refresh: Option<&dyn ReviewRefresh>,
) -> Result<ApprovalDecision> {
    let title = terminal_safe(&request.title);
    let document = review_document(request, payload);
    // Capacity one and a single in-flight request: the screen blocks while a
    // refresh runs, so it cannot ask twice.
    let (want_tx, mut want_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (fresh_tx, fresh_rx) = std::sync::mpsc::channel::<RefreshOutcome>();
    let refreshable = refresh.is_some();
    let mut blocking = tokio::task::spawn_blocking(move || {
        review_fullscreen_blocking(&title, document, refreshable, &want_tx, &fresh_rx)
    });
    loop {
        tokio::select! {
            joined = &mut blocking => {
                return joined.context("terminal approval task failed")?;
            }
            Some(()) = want_rx.recv() => {
                let outcome = match refresh {
                    Some(refresh) => match refresh.resimulate().await {
                        Ok(refreshed) => {
                            RefreshOutcome::Document(review_document(&refreshed.request, Vec::new()))
                        }
                        Err(error) => RefreshOutcome::Failed(format!("{error:#}")),
                    },
                    None => RefreshOutcome::Failed("this review cannot be re-simulated".to_owned()),
                };
                // A send failure means the screen is already gone, which the
                // join above is about to report.
                let _ = fresh_tx.send(outcome);
            }
        }
    }
}

/// What one refresh produced: a re-authored document, or why there is none.
enum RefreshOutcome {
    Document(Vec<Line>),
    Failed(String),
}

fn review_fullscreen_blocking(
    title: &str,
    document: Vec<Line>,
    refreshable: bool,
    want_refresh: &tokio::sync::mpsc::Sender<()>,
    refreshed: &std::sync::mpsc::Receiver<RefreshOutcome>,
) -> Result<ApprovalDecision> {
    ensure!(
        std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && std::io::stderr().is_terminal(),
        "approval requires an interactive terminal"
    );
    let mut review = ReviewScreen::new(document);
    review.refreshable = refreshable;
    let decision = {
        let mut screen = Screen::enter()?;
        // Authoring this document took RPC round trips, and the terminal was
        // collecting keystrokes throughout. `run_refresh` already drains for
        // exactly this reason after a re-simulation; entering the screen the
        // first time is the same situation and the more dangerous one, because
        // a document that fits the viewport has `reached_end` set by its own
        // first draw — so a buffered Tab and Enter, typed into the silence
        // before anything was drawn, would move to Approve and take it.
        drain_type_ahead()?;
        loop {
            screen
                .terminal
                .draw(|frame| draw(frame, title, &mut review))?;
            let key = match crossterm::event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => key,
                // Anything else — a resize above all — just redraws against
                // the new terminal size.
                _ => continue,
            };
            match review.handle_key(key) {
                Some(ReviewAction::Decide(decision)) => break decision,
                Some(ReviewAction::Refresh) => {
                    run_refresh(&mut screen, title, &mut review, want_refresh, refreshed)?;
                }
                None => {}
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

/// Run one refresh with the screen still up: ask the async side, animate
/// while it works, then apply whatever came back.
///
/// Input is deliberately not read while the refresh is in flight — there is
/// nothing a key could mean — and is **drained** afterwards. Without that
/// drain, a reviewer who pressed Enter during a slow re-simulation would have
/// it delivered to the refreshed document the instant it appeared, deciding on
/// a screen they had not seen. That is the same class of mistake the
/// scroll-to-the-end rule exists to prevent.
fn run_refresh(
    screen: &mut Screen,
    title: &str,
    review: &mut ReviewScreen,
    want_refresh: &tokio::sync::mpsc::Sender<()>,
    refreshed: &std::sync::mpsc::Receiver<RefreshOutcome>,
) -> Result<()> {
    review.begin_refresh();
    screen
        .terminal
        .draw(|frame| draw(frame, title, &mut *review))?;
    if want_refresh.blocking_send(()).is_err() {
        review.finish_refresh(RefreshOutcome::Failed(
            "the review could not be re-simulated".to_owned(),
        ));
        return Ok(());
    }
    let outcome = loop {
        match refreshed.recv_timeout(REFRESH_TICK) {
            Ok(outcome) => break outcome,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                review.tick();
                screen
                    .terminal
                    .draw(|frame| draw(frame, title, &mut *review))?;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break RefreshOutcome::Failed("the review could not be re-simulated".to_owned());
            }
        }
    };
    review.finish_refresh(outcome);
    drain_type_ahead()?;
    Ok(())
}

/// Discard whatever the terminal buffered while nothing was on screen to read
/// it, so a keystroke can only ever answer a document its typist has seen.
fn drain_type_ahead() -> Result<()> {
    while crossterm::event::poll(std::time::Duration::ZERO)? {
        let _ = crossterm::event::read()?;
    }
    Ok(())
}

/// How often the waiting screen redraws. Short enough that the elapsed
/// seconds tick visibly, long enough not to spin.
const REFRESH_TICK_MILLIS: u64 = 200;
/// Braille frames rather than an ASCII spinner: they occupy one cell in every
/// terminal that renders the rest of this document's box drawing, and they
/// animate without the width changing under the text beside them.
const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
const REFRESH_TICK: std::time::Duration = std::time::Duration::from_millis(REFRESH_TICK_MILLIS);

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
/// The same document as plain text, for the one path that takes the decision
/// without opening a screen to ask it.
///
/// `--decision approve` answers the question in advance; it does not make the
/// subject of the question unnecessary. Without this the transaction path
/// showed the reviewer no target, no value, no calldata, no fees, no policy
/// finding, and no digest — while the typed-data and message paths printed
/// their transcripts under the same flag, which made transactions the one
/// exception at the point where there is most to see. Everything queued here
/// is queued because its policy asked a question or its simulation failed.
#[must_use]
pub fn review_document_text(request: &ApprovalRequest, payload: Vec<Line>) -> String {
    crate::fullscreen::lines_to_text(&review_document(request, payload), |text, _| {
        text.to_owned()
    })
}

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
    /// Whether `r` re-runs the simulation behind this review.
    refreshable: bool,
    /// Ticks while a refresh is in flight; `None` when none is.
    refreshing: Option<u32>,
}

/// What a keypress asked for. Only a decision ends the review.
#[derive(Debug, PartialEq, Eq)]
enum ReviewAction {
    Decide(ApprovalDecision),
    Refresh,
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
            refreshable: false,
            refreshing: None,
        }
    }

    /// Enter the waiting state. The cursor goes back to Reject immediately:
    /// the document on screen is about to be replaced, so an Approve the
    /// reviewer had lined up no longer refers to anything they have read.
    fn begin_refresh(&mut self) {
        self.refreshing = Some(0);
        self.on_approve = false;
        self.notice = None;
    }

    fn tick(&mut self) {
        if let Some(ticks) = &mut self.refreshing {
            *ticks = ticks.saturating_add(1);
        }
    }

    /// Apply what the refresh produced.
    ///
    /// A document that came back *different* resets the evidence that it was
    /// read — scroll position, `reached_end`, and the cursor — because the
    /// reviewer has now scrolled through a document that is no longer the one
    /// on screen, and Approve is gated on having seen the end of *this* one.
    /// A document that came back identical keeps it: forcing someone to
    /// re-read an unchanged screen teaches them to scroll past it.
    fn finish_refresh(&mut self, outcome: RefreshOutcome) {
        self.refreshing = None;
        match outcome {
            RefreshOutcome::Document(document) => {
                if document == self.document {
                    self.notice = Some("Re-simulated; nothing changed.".to_owned());
                    return;
                }
                self.document = document;
                self.offset = 0;
                self.reached_end = false;
                self.on_approve = false;
                self.notice =
                    Some("Re-simulated; the review changed, so read it again.".to_owned());
            }
            RefreshOutcome::Failed(reason) => {
                self.notice = Some(format!("Re-simulation failed: {reason}"));
            }
        }
    }

    /// `Some` is the review's final answer. Esc, `q`, and Ctrl+C all read as
    /// rejection: an approval must be explicit. The scrolling keys can never
    /// decide, and Enter on Approve is refused until the end of the document
    /// has been seen.
    fn handle_key(&mut self, key: KeyEvent) -> Option<ReviewAction> {
        self.notice = None;
        if fullscreen::is_interrupt(key) {
            return Some(ReviewAction::Decide(ApprovalDecision::Rejected));
        }
        let page = self.viewport.max(1);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                return Some(ReviewAction::Decide(ApprovalDecision::Rejected));
            }
            KeyCode::Char('r') if self.refreshable => return Some(ReviewAction::Refresh),
            KeyCode::Enter => {
                if !self.on_approve {
                    return Some(ReviewAction::Decide(ApprovalDecision::Rejected));
                }
                if self.reached_end {
                    return Some(ReviewAction::Decide(ApprovalDecision::Approved));
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

    /// What to say while a refresh is in flight, with the elapsed seconds so
    /// a slow chain reads as slow rather than as a hung screen.
    fn waiting_message(&self) -> Option<String> {
        let ticks = self.refreshing?;
        // A moving glyph and a rising count, because the two answer different
        // questions: the glyph says the screen is alive, the seconds say
        // whether the wait is normal or the chain is not answering. With
        // endpoint failover a genuine timeout can take a while, and a still
        // screen with no number on it reads as a hang.
        let frame = SPINNER[(ticks as usize) % SPINNER.len()];
        let seconds = (u64::from(ticks) * REFRESH_TICK_MILLIS) / 1000;
        Some(if seconds == 0 {
            format!("{frame} Re-simulating…")
        } else {
            format!("{frame} Re-simulating… {seconds}s")
        })
    }

    /// The footer key legend. A refresh nobody knows about is a refresh
    /// nobody uses, so the key is advertised exactly where it is available
    /// and nowhere else.
    fn hints(&self) -> String {
        let refresh = if self.refreshable {
            " · r re-simulate"
        } else {
            ""
        };
        format!(
            "{} · ↑↓ scroll · PgUp/PgDn page{refresh} · Tab switch · Enter decide · Esc rejects",
            self.position()
        )
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
    let approve_label = if review.refreshing.is_some() {
        // Nothing on screen is settled while a refresh is running, so the
        // affirmative option says so rather than inviting a decision on
        // numbers that are about to be replaced.
        "Approve — waiting for the new simulation".to_owned()
    } else if review.reached_end {
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

    let hints = review.hints();
    // The waiting message outranks any notice: it is the only thing on screen
    // that is still changing, and it tells the reviewer why their keys are
    // being ignored.
    let waiting = review.waiting_message();
    frame.render_widget(
        fullscreen::footer_line(waiting.as_deref().or(review.notice.as_deref()), &hints),
        footer,
    );
}

#[cfg(test)]
#[path = "approve_tui_test.rs"]
mod tests;
