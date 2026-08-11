//! The full-screen surface `connect` lives on between requests.
//!
//! A dapp session is a long-running conversation, so this command has an idle
//! state — minutes of waiting, punctuated by a review. It used to spend that
//! idle time printing status lines into the scrollback and then opening a
//! full-screen review over them, which is precisely the mode-flipping this
//! codebase does not do: the terminal changed modes at every step and the
//! finished prompts piled up behind the full-screen view.
//!
//! So the whole command is full-screen now. This module owns the idle surface:
//! the dapp's identity, what the session exposes, and a live log of every
//! request. A review owns the terminal instead while it is up.
//!
//! **One owner at a time, handed over explicitly.** This is the constraint
//! everything here is shaped by. Two things reading `crossterm` events at once
//! would steal each other's keystrokes, so the idle view is stopped — its
//! terminal restored, its reader joined — *before* a review opens, and started
//! again after. There is never a moment when both could take a key.
//!
//! That also settles owner authentication. A polkit text agent prompts on the
//! same terminal, so it must not run under an alternate screen. Because the
//! idle view is stopped for the whole of a request, and each review restores
//! the terminal when its own decision is made, the authentication step always
//! happens on the ordinary screen.

use crate::{
    fullscreen::{self, Line, Screen, Span, TextField},
    tui::Tone,
};
use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout},
    text::Line as UiLine,
    widgets::Paragraph,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// How often the idle loop wakes to redraw and to notice it has been stopped.
///
/// Short enough that handing the terminal to a review feels immediate, long
/// enough that a session waiting all afternoon is not a spinning process.
const IDLE_TICK: Duration = Duration::from_millis(100);

/// How many past events the log keeps. A session is not a transcript — the
/// durable record of anything signed is the pending-transaction database — so
/// this only has to cover what a person can remember scrolling back for.
const MAX_LOG_LINES: usize = 200;

/// What the idle surface draws. Written by the session, read by the loop.
#[derive(Default)]
pub struct SessionState {
    /// The line at the top of the screen.
    pub title: String,
    /// The identity block: who the dapp is and what it was given.
    pub header: Vec<Line>,
    /// One line per thing that has happened, oldest first.
    pub log: Vec<Line>,
    /// What the session is doing right now, for the footer.
    pub status: String,
}

impl SessionState {
    /// Append one event, bounding the log.
    pub fn push(&mut self, line: Line) {
        self.log.push(line);
        if self.log.len() > MAX_LOG_LINES {
            let excess = self.log.len() - MAX_LOG_LINES;
            self.log.drain(..excess);
        }
    }
}

/// A handle to the running idle surface.
///
/// Dropping this does *not* stop the loop, because stopping has to be waited
/// for: the terminal is not free until the loop has actually restored it.
/// [`IdleView::stop`] is the only way to end it, and every path that opens a
/// review goes through it.
pub struct IdleView {
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl IdleView {
    /// Take the terminal and start drawing.
    ///
    /// Discarding the returned handle does not stop the loop — see the
    /// struct doc — so a dropped return value is a screen with nobody left
    /// to hand it back.
    ///
    /// `quit` is the session's flag, not this view's. A view is stopped and
    /// replaced around every review, so a disconnect recorded in a flag this
    /// constructor made would be thrown away with the view that held it --
    /// which is precisely what happens when a keystroke lands during the
    /// handoff. The person pressed `q`; the view carrying that answer was
    /// dropped; the replacement started out saying no.
    #[must_use]
    pub fn start(state: Arc<Mutex<SessionState>>, quit: Arc<AtomicBool>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let loop_stop = Arc::clone(&stop);
        let task = tokio::task::spawn_blocking(move || {
            // A surface that cannot be drawn is not worth failing the session
            // over: the requests still work, and the reviews open their own
            // screens. Losing the idle view is a cosmetic loss, and turning it
            // into a disconnect would be a worse one.
            if let Ok(mut screen) = Screen::enter() {
                run_idle(&mut screen, &state, &loop_stop, &quit);
            }
        });
        Self { stop, task }
    }

    /// Stop drawing and wait for the terminal to be handed back.
    ///
    /// Awaiting the join is the whole point: returning before the loop has
    /// dropped its [`Screen`] would let a review enter the alternate screen
    /// while the idle view was still leaving it.
    pub async fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.task.await;
    }
}

fn run_idle(
    screen: &mut Screen,
    state: &Arc<Mutex<SessionState>>,
    stop: &Arc<AtomicBool>,
    quit: &Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        {
            let Ok(state) = state.lock() else { return };
            if screen
                .terminal
                .draw(|frame| draw_idle(frame, &state))
                .is_err()
            {
                return;
            }
        }
        // Polling rather than blocking on a read: the loop has to notice that
        // it has been stopped, and a blocked read would hold the terminal
        // until the next keystroke — which, on an idle session, may never come.
        match crossterm::event::poll(IDLE_TICK) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => return,
        }
        let Ok(event) = crossterm::event::read() else {
            return;
        };
        let Event::Key(key) = event else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        // Raw mode means Ctrl-C is a keystroke here rather than a signal, so
        // the disconnect this screen advertises has to be handled as one.
        if fullscreen::is_interrupt(key) || matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
            quit.store(true, Ordering::Relaxed);
            return;
        }
    }
}

fn draw_idle(frame: &mut ratatui::Frame, state: &SessionState) {
    let (header_area, body, footer_area) = fullscreen::chrome(frame.area());
    frame.render_widget(fullscreen::title_line(&state.title), header_area);

    let columns = (body.width as usize).saturating_sub(2).max(10);
    // The identity block is fixed at the top and the log fills what is left:
    // who this session is with must not scroll away behind a busy dapp.
    let header = fullscreen::wrap_lines(&state.header, columns);
    let header_rows = u16::try_from(header.len()).unwrap_or(u16::MAX);
    let [identity, events] = Layout::vertical([
        Constraint::Length(header_rows.min(body.height)),
        Constraint::Fill(1),
    ])
    .areas(body);

    frame.render_widget(Paragraph::new(to_ui(&header)), identity);

    // The tail, not the head: the newest event is the one being waited on.
    let wrapped = fullscreen::wrap_lines(&state.log, columns);
    let rows = events.height as usize;
    let visible = wrapped.split_at(wrapped.len().saturating_sub(rows)).1;
    frame.render_widget(Paragraph::new(to_ui(visible)), events);

    frame.render_widget(
        fullscreen::footer_line(None, &footer_hints(state, footer_area.width as usize)),
        footer_area,
    );
}

fn footer_hints(state: &SessionState, width: usize) -> String {
    let long = format!("{} · q or Ctrl-C disconnects", state.status);
    if crate::render::display_width(&long) <= width {
        return long;
    }
    let short = format!("{} · q quits", state.status);
    if crate::render::display_width(&short) <= width {
        return short;
    }
    "q quits".to_owned()
}

fn to_ui(lines: &[Line]) -> Vec<UiLine<'static>> {
    lines
        .iter()
        .map(|line| {
            let mut spans = vec![ratatui::text::Span::raw(" ")];
            spans.extend(line.iter().map(fullscreen::ui_span));
            UiLine::from(spans)
        })
        .collect()
}

/// Ask for the pairing link on a full-screen surface.
///
/// Full-screen rather than an inline prompt for the same reason as everything
/// else here: this command opens full-screen surfaces, so it opens them from
/// the first question. It also gives the paste somewhere to explain itself,
/// which a one-line prompt does not.
pub async fn prompt_for_uri(account: &str, address: &str, relay: &str) -> Result<Option<String>> {
    let account = account.to_owned();
    let address = address.to_owned();
    let relay = relay.to_owned();
    tokio::task::spawn_blocking(move || prompt_for_uri_blocking(&account, &address, &relay))
        .await
        .context("the pairing prompt task failed")?
}

fn prompt_for_uri_blocking(account: &str, address: &str, relay: &str) -> Result<Option<String>> {
    let mut screen = Screen::enter()?;
    let mut field =
        TextField::new("WalletConnect link").placeholder("wc:…@2?relay-protocol=irn&symKey=…");
    let mut notice: Option<String> = None;
    loop {
        screen.terminal.draw(|frame| {
            let (header, body, footer) = fullscreen::chrome(frame.area());
            frame.render_widget(fullscreen::title_line("Connect to a dapp"), header);

            let [intro, input, help] = Layout::vertical([
                Constraint::Length(6),
                Constraint::Length(3),
                Constraint::Fill(1),
            ])
            .areas(body);

            let columns = (intro.width as usize).saturating_sub(2).max(10);
            let facts = vec![
                fact("Account", account),
                fact("Address", address),
                fact("Relay", relay),
            ];
            frame.render_widget(
                Paragraph::new(to_ui(&fullscreen::wrap_lines(&facts, columns))),
                intro,
            );
            field.draw(frame, input, true);

            let guidance = vec![
                vec![Span::toned(
                    "In the dapp, choose WalletConnect and use its \"copy link\" button rather \
                     than scanning the QR code, then paste it here.",
                    Tone::Muted,
                )],
                Vec::new(),
                vec![Span::toned(
                    "The link carries the session key, so treat it as a secret and use one only \
                     once.",
                    Tone::Muted,
                )],
            ];
            frame.render_widget(
                Paragraph::new(to_ui(&fullscreen::wrap_lines(&guidance, columns))),
                help,
            );

            frame.render_widget(
                fullscreen::footer_line(notice.as_deref(), "Enter connects · Esc cancels"),
                footer,
            );
        })?;

        let Event::Key(key) = crossterm::event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if fullscreen::is_interrupt(key) || key.code == KeyCode::Esc {
            return Ok(None);
        }
        if key.code == KeyCode::Enter {
            let value = field.value().trim().to_owned();
            if walletconnect_session::uri::looks_like_pairing_uri(&value) {
                return Ok(Some(value));
            }
            notice = Some("A WalletConnect link starts with `wc:`.".to_owned());
            continue;
        }
        notice = None;
        field.handle_key(key);
    }
}

/// One aligned label/value line, in the same visual language as a review.
#[must_use]
pub fn fact(label: &str, value: &str) -> Line {
    vec![
        Span::toned(format!("{label:<9}"), Tone::Muted),
        Span::plain(value),
    ]
}

/// One log line, stamped and toned by what kind of thing happened.
pub fn event(tone: Tone, text: impl AsRef<str>) -> Line {
    vec![
        Span::toned(
            format!("{}  ", chrono::Local::now().format("%H:%M:%S")),
            Tone::Muted,
        ),
        Span::toned(text, tone),
    ]
}

#[cfg(test)]
#[path = "connect_screen_test.rs"]
mod tests;
