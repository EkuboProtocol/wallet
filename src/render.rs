//! Human-readable CLI output.
//!
//! Every CLI command that reports structured data resolves an [`OutputMode`]:
//! `--json` always prints exact JSON, a non-terminal stdout (pipes, command
//! substitution, agents shelling out) prints JSON so scripts never break, and
//! an interactive terminal gets a human rendering by default. JSON output is
//! the compatibility surface; human output is free to improve.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::io::{self, IsTerminal, Write};
use unicode_width::UnicodeWidthChar;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputMode {
    Json,
    Human,
}

impl OutputMode {
    /// `--json` forces JSON; otherwise a terminal stdout gets the human view
    /// and anything else (pipe, file, agent) keeps machine-readable JSON.
    #[must_use]
    pub fn resolve(json_flag: bool) -> Self {
        if json_flag || !io::stdout().is_terminal() {
            Self::Json
        } else {
            Self::Human
        }
    }
}

/// Print `value` as JSON, or the provided human rendering, per mode. The
/// human text passes through control-character stripping so stored data can
/// never inject terminal escapes.
pub fn emit<T: Serialize>(
    mode: OutputMode,
    value: &T,
    human: impl FnOnce() -> Result<String>,
) -> Result<()> {
    match mode {
        OutputMode::Json => print_json(value),
        OutputMode::Human => {
            let text = human()?;
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{}", terminal_safe_multiline(text.trim_end()))?;
            Ok(())
        }
    }
}

pub fn print_json(value: &impl Serialize) -> Result<()> {
    serde_json::to_writer_pretty(io::stdout().lock(), value)?;
    println!();
    Ok(())
}

pub use crate::sanitize::{terminal_safe_line, terminal_safe_multiline};

/// Rows below which an interactive list stops being scrollable at all.
const MINIMUM_LIST_ROWS: usize = 3;
/// Assumed terminal height when the real one cannot be read.
const FALLBACK_TERMINAL_ROWS: usize = 24;
/// Assumed terminal width when the real one cannot be read.
const FALLBACK_TERMINAL_COLUMNS: usize = 80;
/// Columns the prompt draws to the left of an option's label: the cursor
/// prefix (`●`, `▲`, `▼`, or a space) and the space that follows it.
const LIST_LABEL_CHROME_COLUMNS: usize = 2;

/// How many list rows one interactive prompt may draw.
///
/// An interactive prompt redraws its entire body on every keystroke. A body
/// taller than the terminal therefore scrolls the view to the bottom each time
/// a cursor key is pressed, which makes a long list unusable. Sizing the
/// visible page to the live terminal height keeps the whole prompt on one
/// screen and lets the prompt's own paging scroll the list instead.
///
/// `chrome_rows` is what the prompt draws around the list — header, footer,
/// and any lines already printed above it. Every interactive list must pass
/// the result to `max_rows`; the height is recomputed on each render, so a
/// terminal resized between prompts is respected.
#[must_use]
pub fn interactive_list_rows(chrome_rows: usize) -> usize {
    let rows = crossterm::terminal::size()
        .map_or(FALLBACK_TERMINAL_ROWS, |(_, rows)| rows as usize)
        .max(1);
    rows.saturating_sub(chrome_rows).max(MINIMUM_LIST_ROWS)
}

/// Fit one interactive list label onto exactly one terminal row.
///
/// The row budget above only holds if one option occupies one row. A label
/// wider than the terminal wraps, so the prompt draws more rows than it
/// planned for, the body outgrows the screen, and the terminal scrolls under
/// a prompt that redraws by moving the cursor back up a fixed number of rows.
/// The visible effect is that every cursor key scrolls the whole screen and
/// the highlighted option is nowhere to be seen. Clamping each label to the
/// width the prompt leaves it keeps that from happening at any terminal size.
///
/// Every disallowed character collapses to a space for the same reason,
/// newlines included; the trailing `…` marks what was cut, and the expanded
/// view is where the full value lives.
///
/// Newlines alone were not enough. Bidirectional and zero-width controls
/// report a display width of zero, so the clamp counted them as free and
/// passed them through — which is exactly what a label needs not to do, since
/// these labels carry network names, currency symbols, and URLs that arrived
/// from outside.
#[must_use]
pub fn interactive_list_label(label: &str) -> String {
    let columns = crossterm::terminal::size()
        .map_or(FALLBACK_TERMINAL_COLUMNS, |(columns, _)| columns as usize)
        .saturating_sub(LIST_LABEL_CHROME_COLUMNS);
    clamp_to_columns(&terminal_safe_line(label), columns)
}

/// Display width of `text` in terminal columns, counting wide glyphs as the
/// two columns they actually occupy.
pub(crate) fn display_width(text: &str) -> usize {
    text.chars()
        .map(|character| UnicodeWidthChar::width(character).unwrap_or(0))
        .sum()
}

/// `0x1234567890…12345678`: the head and tail of a long hex identifier.
pub(crate) fn short_hex(value: &str) -> String {
    // Character boundaries, not byte offsets. This wallet writes addresses as
    // ASCII hex, but the function renders *stored* text, and a row that
    // predates a constraint or was written by something else can hold
    // anything. Slicing a multi-byte character in half panics, and this runs
    // inside the address-book browser's draw loop — so one malformed row would
    // take down the whole screen the owner needs in order to delete it.
    let characters: Vec<char> = value.chars().collect();
    if characters.len() <= 19 {
        return value.to_owned();
    }
    let head: String = characters[..10].iter().collect();
    let tail: String = characters[characters.len() - 8..].iter().collect();
    format!("{head}…{tail}")
}

/// `text` cut to at most `columns` columns, ellipsized when anything is lost.
fn clamp_to_columns(text: &str, columns: usize) -> String {
    if display_width(text) <= columns {
        return text.to_owned();
    }
    if columns == 0 {
        return String::new();
    }
    // One column goes to the ellipsis, so the result still fits.
    let budget = columns - 1;
    let mut kept = String::new();
    let mut width = 0;
    for character in text.chars() {
        let advance = UnicodeWidthChar::width(character).unwrap_or(0);
        if width + advance > budget {
            break;
        }
        width += advance;
        kept.push(character);
    }
    kept.push('…');
    kept
}

/// "3 minutes ago", "in 2 hours", "just now".
#[must_use]
pub fn relative_time(when: DateTime<Utc>) -> String {
    let now = Utc::now();
    let (delta, template) = if when <= now {
        (now - when, "{} ago")
    } else {
        (when - now, "in {}")
    };
    let seconds = delta.num_seconds();
    // Rounded rather than truncated units, so "9 minutes from now" does not
    // read as 8 the instant it is computed.
    let text = if seconds < 5 {
        return "just now".into();
    } else if seconds < 90 {
        format!("{seconds} seconds")
    } else if seconds < 90 * 60 {
        plural((seconds + 30) / 60, "minute")
    } else if seconds < 36 * 3600 {
        plural((seconds + 1800) / 3600, "hour")
    } else {
        plural((seconds + 43_200) / 86_400, "day")
    };
    template.replacen("{}", &text, 1)
}

fn plural(amount: i64, unit: &str) -> String {
    if amount == 1 {
        format!("1 {unit}")
    } else {
        format!("{amount} {unit}s")
    }
}

/// A timestamp with both the relative and exact form.
#[must_use]
pub fn described_time(when: DateTime<Utc>) -> String {
    format!(
        "{} ({})",
        relative_time(when),
        when.format("%Y-%m-%d %H:%M:%S UTC")
    )
}

/// The block-explorer transaction page for a hash, when the network has one.
#[must_use]
pub fn explorer_transaction_url(
    network: &crate::config::NetworkConfig,
    transaction_hash: &str,
) -> Option<String> {
    let base = network.block_explorer_url.as_ref()?;
    Some(format!(
        "{}/tx/{transaction_hash}",
        base.as_str().trim_end_matches('/')
    ))
}

#[cfg(test)]
#[path = "render_test.rs"]
mod tests;
