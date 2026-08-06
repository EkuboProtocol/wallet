//! A full-screen pager for text the user is meant to actually read.
//!
//! Printing a long document into the scrollback and asking a question
//! underneath it does not work: the question is the only thing on screen, the
//! document is somewhere above it, and scrolling back means fighting the
//! terminal's own buffer. Worse, nothing distinguishes "read it and agreed"
//! from "pressed y at a prompt".
//!
//! So documents that carry a decision are drawn on the alternate screen with
//! their own viewport and scroll state, and [`read_fully`] reports whether the
//! reader ever reached the end. Callers that gate a decision on having read
//! the text — legal acceptance — refuse to ask the question otherwise.
//!
//! The alternate screen means none of this lands in the scrollback: the
//! terminal comes back exactly as it was, which is also what lets an
//! interactive list redraw cleanly after a document is closed. Drawing is
//! ratatui over [`crate::fullscreen::Screen`] — the same stack as every other
//! full-screen view — while the reflow logic here stays the pager's own,
//! because the scroll position must count exactly the lines that were drawn.

use std::io::{self, IsTerminal};

use crate::render::display_width;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::Line,
    widgets::Paragraph,
};

/// How the reader left the document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The last line was on screen at some point before they left.
    ReadToEnd,
    /// They quit early, with text still unseen.
    Quit,
}

/// Narrowest body the pager will wrap to, so a sliver of a terminal still
/// produces readable lines rather than one character per row.
const MINIMUM_BODY_COLUMNS: usize = 20;

/// Show `body` under `title` on the alternate screen until the reader leaves.
///
/// Returns [`Outcome::ReadToEnd`] only if the reader pressed Enter with the
/// end of the document on screen. A document shorter than the viewport is at
/// its end from the first frame, since there is nothing to scroll to, but
/// leaving it still takes that keypress.
///
/// Requires a terminal on stdin and stderr; without one there is nothing to
/// take over and no keys to read, so the caller gets [`Outcome::Quit`] rather
/// than a half-drawn screen. Check [`crate::tui::interactive`] first when the
/// non-interactive path should do something else entirely.
pub fn read_fully(title: &str, body: &str) -> Result<Outcome> {
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        return Ok(Outcome::Quit);
    }
    let mut screen = crate::fullscreen::Screen::enter()?;
    let paragraphs: Vec<&str> = body.split('\n').collect();

    let mut offset = 0_usize;
    let mut wrapped: Vec<String> = Vec::new();
    let mut wrapped_for_columns = 0_usize;
    let mut viewport = 1_usize;
    let mut max_offset = 0_usize;

    loop {
        screen.terminal.draw(|frame| {
            let [title_area, body_area, footer_area] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .areas(frame.area());

            let columns = body_columns(body_area.width);
            if columns != wrapped_for_columns {
                wrapped = wrap(&paragraphs, columns);
                wrapped_for_columns = columns;
            }
            viewport = (body_area.height as usize).max(1);
            max_offset = wrapped.len().saturating_sub(viewport);
            offset = offset.min(max_offset);

            frame.render_widget(
                Paragraph::new(title).style(Style::new().add_modifier(Modifier::BOLD)),
                title_area,
            );
            let visible: Vec<Line> = wrapped
                .iter()
                .skip(offset)
                .take(viewport)
                .map(|line| Line::from(format!(" {line}")))
                .collect();
            frame.render_widget(Paragraph::new(visible), body_area);
            frame.render_widget(
                Paragraph::new(footer(offset, max_offset))
                    .style(Style::new().add_modifier(Modifier::REVERSED)),
                footer_area,
            );
        })?;

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                match action(key) {
                    Action::Quit => return Ok(Outcome::Quit),
                    // Only the deliberate key leaves a finished document. The
                    // scrolling keys stop at the last line however hard they
                    // are leaned on, so nobody pages their way into the
                    // question waiting on the other side.
                    Action::Continue if offset >= max_offset => {
                        return Ok(Outcome::ReadToEnd);
                    }
                    Action::LineDown => offset = offset.saturating_add(1),
                    Action::LineUp => offset = offset.saturating_sub(1),
                    Action::PageDown | Action::Continue => {
                        offset = offset.saturating_add(viewport);
                    }
                    Action::PageUp => offset = offset.saturating_sub(viewport),
                    Action::Top => offset = 0,
                    Action::Bottom => offset = max_offset,
                    Action::Ignore => {}
                }
            }
            // Any other event just redraws, which is what a resize needs.
            _ => {}
        }
    }
}

/// What a keypress means. Keys follow `less`, plus the arrow and page keys
/// that a reader who has never used `less` will try first.
enum Action {
    LineUp,
    LineDown,
    PageUp,
    PageDown,
    /// Page down, and leave the document once there is nothing left below.
    /// Separate from [`Action::PageDown`] because leaving is an answer to
    /// whatever the caller asks next, and a repeat-rate key is no way to give
    /// one.
    Continue,
    Top,
    Bottom,
    Quit,
    Ignore,
}

fn action(key: KeyEvent) -> Action {
    // Raw mode suppresses the terminal's own Ctrl+C handling, so the pager
    // has to honor it itself or the reader is trapped.
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'd'))
    {
        return Action::Quit;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => Action::LineUp,
        KeyCode::Down | KeyCode::Char('j') => Action::LineDown,
        KeyCode::PageUp | KeyCode::Char('b') => Action::PageUp,
        KeyCode::PageDown | KeyCode::Char(' ' | 'f') => Action::PageDown,
        KeyCode::Enter => Action::Continue,
        KeyCode::Home | KeyCode::Char('g') => Action::Top,
        KeyCode::End | KeyCode::Char('G') => Action::Bottom,
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        _ => Action::Ignore,
    }
}

/// Columns the body wraps to, leaving a one-column gutter on each side.
fn body_columns(columns: u16) -> usize {
    (columns as usize)
        .saturating_sub(2)
        .max(MINIMUM_BODY_COLUMNS)
}

fn footer(offset: usize, max_offset: usize) -> String {
    if offset >= max_offset {
        " END — Enter to continue · ↑ PgUp to re-read · q to cancel ".to_owned()
    } else {
        let percent = (offset * 100) / max_offset.max(1);
        format!(
            " {percent}% — Space/PgDn to page · ↑↓ line · End to jump to the end · q to cancel "
        )
    }
}

/// One run of source lines that wraps as a unit.
struct Block {
    /// Prefix on the first output line: the indent plus any bullet.
    lead: String,
    /// Prefix on continuation lines, so wrapped text hangs under the text of
    /// a list item rather than under its bullet.
    hang: String,
    /// The words, with the source document's own line breaks dropped.
    text: String,
}

/// Reflow the document to `columns` display columns.
///
/// The source line breaks inside a paragraph are that document's hard wrap at
/// a width that is not the reader's, so re-wrapping them as-is leaves a stub
/// word on its own line wherever the two widths disagree. Prose is joined
/// back into paragraphs and re-wrapped instead; blank lines, headings, list
/// items, and changes of indent are structure and each start a new block.
///
/// Wrapping happens here rather than being left to the terminal because the
/// pager's scroll position is a line count: a line the terminal wraps behind
/// its back is a line the pager did not know it drew.
fn wrap(source: &[&str], columns: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for block in blocks(source) {
        let Some(block) = block else {
            // A blank source line is a paragraph break and survives as one.
            lines.push(String::new());
            continue;
        };
        let hang = clip(
            &block.hang,
            columns.saturating_sub(MINIMUM_BODY_COLUMNS / 2),
        );
        let mut current = clip(
            &block.lead,
            columns.saturating_sub(MINIMUM_BODY_COLUMNS / 2),
        );
        let mut width = display_width(&current);
        let mut started = false;

        for word in block.text.split_whitespace() {
            let word_width = display_width(word);
            if started && width + 1 + word_width > columns {
                lines.push(std::mem::replace(&mut current, hang.clone()));
                width = display_width(&hang);
                started = false;
            }
            if started {
                current.push(' ');
                width += 1;
            }
            // A single word wider than the viewport still has to land
            // somewhere, so it takes its own line and the terminal deals with
            // the overflow rather than the scroll arithmetic doing so.
            current.push_str(word);
            width += word_width;
            started = true;
        }
        lines.push(current);
    }
    lines
}

/// Group source lines into wrappable blocks. `None` is a blank line.
fn blocks(source: &[&str]) -> Vec<Option<Block>> {
    let mut blocks: Vec<Option<Block>> = Vec::new();
    for line in source {
        if line.trim().is_empty() {
            blocks.push(None);
            continue;
        }
        let indent: String = line
            .chars()
            .take_while(|character| character.is_whitespace())
            .collect();
        let rest = &line[indent.len()..];
        let bullet = bullet_width(rest);

        // A heading, a bullet, or a change of indent is the document saying
        // "this is a new thing", so it never absorbs into what came before.
        let continues = bullet == 0
            && !rest.starts_with('#')
            && blocks
                .last()
                .and_then(Option::as_ref)
                .is_some_and(|block| block.hang == indent);
        if continues {
            let block = blocks
                .last_mut()
                .and_then(Option::as_mut)
                .expect("checked above");
            block.text.push(' ');
            block.text.push_str(rest);
            continue;
        }
        blocks.push(Some(Block {
            lead: format!("{indent}{}", &rest[..bullet]),
            hang: format!("{indent}{}", " ".repeat(bullet)),
            text: rest[bullet..].to_owned(),
        }));
    }
    blocks
}

/// Bytes of the list marker starting `text`, or zero if it does not start one.
/// Only the markers these documents actually use are recognized, so ordinary
/// prose beginning with a dash is never mistaken for a list.
fn bullet_width(text: &str) -> usize {
    if text.starts_with("- ") || text.starts_with("* ") {
        return 2;
    }
    let digits = text
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count()
        .min(text.len());
    if digits > 0 && text[digits..].starts_with(". ") {
        return digits + 2;
    }
    0
}

/// `text` cut to `columns` display columns, so a lead or hang prefix can
/// never eat the whole wrap width.
fn clip(text: &str, columns: usize) -> String {
    let mut kept = String::new();
    let mut width = 0;
    for character in text.chars() {
        let advance = unicode_width::UnicodeWidthChar::width(character).unwrap_or(0);
        if width + advance > columns {
            break;
        }
        width += advance;
        kept.push(character);
    }
    kept
}

#[cfg(test)]
#[path = "pager_test.rs"]
mod tests;
