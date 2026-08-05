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
//! interactive list redraw cleanly after a document is closed.

use std::io::{self, IsTerminal, Write};

use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Print, SetAttribute},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use unicode_width::UnicodeWidthChar;

/// How the reader left the document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The last line was on screen at some point before they left.
    ReadToEnd,
    /// They quit early, with text still unseen.
    Quit,
}

/// Rows the pager spends on its own chrome: one title row and one footer row.
const CHROME_ROWS: usize = 2;
/// Narrowest body the pager will wrap to, so a sliver of a terminal still
/// produces readable lines rather than one character per row.
const MINIMUM_BODY_COLUMNS: usize = 20;

/// Show `body` under `title` on the alternate screen until the reader leaves.
///
/// Returns [`Outcome::ReadToEnd`] only if the end of the document was on
/// screen: a document shorter than the viewport counts immediately, since
/// there is nothing left to scroll to.
///
/// Requires a terminal on stdin and stderr; without one there is nothing to
/// take over and no keys to read, so the caller gets [`Outcome::Quit`] rather
/// than a half-drawn screen. Check [`crate::tui::interactive`] first when the
/// non-interactive path should do something else entirely.
pub fn read_fully(title: &str, body: &str) -> Result<Outcome> {
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        return Ok(Outcome::Quit);
    }
    let _screen = Screen::enter()?;
    let paragraphs: Vec<&str> = body.split('\n').collect();

    let mut offset = 0usize;
    let mut wrapped = Vec::new();
    let mut last_layout = (0u16, 0u16);

    loop {
        let (columns, rows) = terminal::size().unwrap_or((80, 24));
        if (columns, rows) != last_layout {
            wrapped = wrap(&paragraphs, body_columns(columns));
            last_layout = (columns, rows);
        }
        let viewport = (rows as usize).saturating_sub(CHROME_ROWS).max(1);
        let max_offset = wrapped.len().saturating_sub(viewport);
        offset = offset.min(max_offset);

        draw(title, &wrapped, offset, max_offset, viewport, columns)?;

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                match action(key) {
                    Action::Quit => return Ok(Outcome::Quit),
                    // Paging past the last line is how the reader leaves a
                    // document they finished, so the same key that scrolls
                    // also continues once there is nothing left to scroll.
                    Action::PageDown if offset >= max_offset => {
                        return Ok(Outcome::ReadToEnd);
                    }
                    Action::LineDown => offset = offset.saturating_add(1),
                    Action::LineUp => offset = offset.saturating_sub(1),
                    Action::PageDown => offset = offset.saturating_add(viewport),
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
        KeyCode::PageDown | KeyCode::Char(' ' | 'f') | KeyCode::Enter => Action::PageDown,
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

fn draw(
    title: &str,
    wrapped: &[String],
    offset: usize,
    max_offset: usize,
    viewport: usize,
    columns: u16,
) -> Result<()> {
    let mut out = io::stderr().lock();
    // Every row is positioned absolutely. Writing past the last row would
    // scroll the alternate screen and silently shift everything up by one,
    // which is the exact failure this pager exists to avoid.
    queue!(out, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
    queue!(
        out,
        SetAttribute(Attribute::Bold),
        Print(clip(title, columns as usize)),
        SetAttribute(Attribute::Reset),
    )?;

    for (row, line) in wrapped.iter().skip(offset).take(viewport).enumerate() {
        queue!(
            out,
            cursor::MoveTo(0, row_index(row + 1)),
            Print(" "),
            Print(line),
        )?;
    }

    queue!(
        out,
        cursor::MoveTo(0, row_index(viewport + 1)),
        SetAttribute(Attribute::Reverse),
        Print(clip(&footer(offset, max_offset), columns as usize)),
        SetAttribute(Attribute::Reset),
    )?;
    out.flush()?;
    Ok(())
}

fn row_index(row: usize) -> u16 {
    u16::try_from(row).unwrap_or(u16::MAX)
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

fn display_width(text: &str) -> usize {
    text.chars()
        .map(|character| UnicodeWidthChar::width(character).unwrap_or(0))
        .sum()
}

/// `text` cut to `columns` display columns. Chrome is written by this module,
/// so there is nothing to ellipsize — it just must not wrap.
fn clip(text: &str, columns: usize) -> String {
    let mut kept = String::new();
    let mut width = 0;
    for character in text.chars() {
        let advance = UnicodeWidthChar::width(character).unwrap_or(0);
        if width + advance > columns {
            break;
        }
        width += advance;
        kept.push(character);
    }
    kept
}

/// Owns the terminal takeover. Restoring on drop rather than at the end of
/// [`read_fully`] means an error or a panic mid-document still hands the
/// terminal back in raw-mode-off, main-screen, cursor-visible state.
struct Screen;

impl Screen {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        // Claimed only after raw mode succeeds, so the drop below always has
        // exactly the state it needs to undo.
        let guard = Self;
        execute!(io::stderr(), EnterAlternateScreen, cursor::Hide)?;
        Ok(guard)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _unused = execute!(io::stderr(), cursor::Show, LeaveAlternateScreen);
        let _unused = terminal::disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_never_exceeds_the_viewport_and_keeps_blank_lines() {
        let text = ["alpha beta gamma delta", "", "  indented item here"];
        let lines = wrap(&text, 12);
        for line in &lines {
            assert!(display_width(line) <= 12, "{line:?} fits the wrap width");
        }
        assert!(lines.contains(&String::new()), "blank line survives");
        // The indent is structure and every wrapped line keeps it.
        let indented: Vec<&String> = lines
            .iter()
            .filter(|line| line.starts_with("  ") && !line.trim().is_empty())
            .collect();
        assert!(indented.len() > 1, "the indented item wrapped: {lines:?}");
    }

    #[test]
    fn prose_is_reflowed_but_structure_is_not() {
        // The document's own hard wrap disappears: these two source lines are
        // one paragraph and refill the width given.
        assert_eq!(
            wrap(&["one two three", "four five"], 40),
            vec!["one two three four five".to_owned()]
        );
        // A heading and a bullet each stay on their own, whatever precedes.
        let lines = wrap(&["intro text", "## Heading", "- first", "- second"], 40);
        assert_eq!(
            lines,
            vec![
                "intro text".to_owned(),
                "## Heading".to_owned(),
                "- first".to_owned(),
                "- second".to_owned(),
            ]
        );
    }

    #[test]
    fn a_wrapped_list_item_hangs_under_its_text() {
        let lines = wrap(&["- alpha beta gamma delta epsilon"], 16);
        assert_eq!(lines[0], "- alpha beta");
        for line in &lines[1..] {
            assert!(line.starts_with("  "), "{line:?} hangs past the bullet");
        }
    }

    #[test]
    fn a_word_longer_than_the_viewport_still_gets_a_line() {
        let long = "0x".to_owned() + &"a".repeat(64);
        let lines = wrap(&[long.as_str()], 20);
        assert_eq!(lines, vec![long]);
    }

    #[test]
    fn only_real_list_markers_start_a_list() {
        assert_eq!(bullet_width("- item"), 2);
        assert_eq!(bullet_width("12. item"), 4);
        assert_eq!(bullet_width("-dash-prefixed prose"), 0);
        assert_eq!(bullet_width("2026 was the year"), 0);
    }

    #[test]
    fn the_footer_reports_the_end_only_at_the_end() {
        assert!(footer(0, 0).contains("END"), "a short document is read");
        assert!(footer(9, 10).contains('%'));
        assert!(footer(10, 10).contains("END"));
    }

    #[test]
    fn keys_follow_less_and_always_offer_a_way_out() {
        let press = |code, modifiers| KeyEvent::new(code, modifiers);
        assert!(matches!(
            action(press(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Action::Quit
        ));
        assert!(matches!(
            action(press(KeyCode::Esc, KeyModifiers::NONE)),
            Action::Quit
        ));
        assert!(matches!(
            action(press(KeyCode::Char(' '), KeyModifiers::NONE)),
            Action::PageDown
        ));
        assert!(matches!(
            action(press(KeyCode::Char('G'), KeyModifiers::NONE)),
            Action::Bottom
        ));
    }

    #[test]
    fn a_body_narrower_than_the_minimum_still_wraps_readably() {
        assert_eq!(body_columns(4), MINIMUM_BODY_COLUMNS);
        assert_eq!(body_columns(100), 98);
    }
}
