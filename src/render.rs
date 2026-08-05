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

/// Newlines survive; every other control character becomes a space.
#[must_use]
pub fn terminal_safe_multiline(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && character != '\n' {
                ' '
            } else {
                character
            }
        })
        .collect()
}

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
/// Newlines collapse to spaces for the same reason; the trailing `…` marks
/// what was cut, and the expanded view is where the full value lives.
#[must_use]
pub fn interactive_list_label(label: &str) -> String {
    let columns = crossterm::terminal::size()
        .map_or(FALLBACK_TERMINAL_COLUMNS, |(columns, _)| columns as usize)
        .saturating_sub(LIST_LABEL_CHROME_COLUMNS);
    clamp_to_columns(&label.replace('\n', " "), columns)
}

/// Display width of `text` in terminal columns, counting wide glyphs as the
/// two columns they actually occupy.
fn display_width(text: &str) -> usize {
    text.chars()
        .map(|character| UnicodeWidthChar::width(character).unwrap_or(0))
        .sum()
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

/// Generic human rendering for JSON values: indented `key: value` lines with
/// numbered entries for arrays of objects. A fallback for future commands
/// without a bespoke view, so `--json` stays the only way to get raw JSON.
#[must_use]
pub fn generic_human(value: &serde_json::Value) -> String {
    let mut out = String::new();
    render_value(&mut out, value, 0);
    out
}

fn render_value(out: &mut String, value: &serde_json::Value, indent: usize) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                render_entry(out, key, child, indent);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                render_entry(out, &format!("{}.", index + 1), item, indent);
            }
        }
        scalar => {
            out.push_str(&" ".repeat(indent));
            out.push_str(&scalar_text(scalar));
            out.push('\n');
        }
    }
}

fn render_entry(out: &mut String, key: &str, value: &serde_json::Value, indent: usize) {
    use std::fmt::Write as _;
    let pad = " ".repeat(indent);
    match value {
        serde_json::Value::Object(map) if map.is_empty() => {
            let _ = writeln!(out, "{pad}{key}: {{}}");
        }
        serde_json::Value::Array(items) if items.is_empty() => {
            let _ = writeln!(out, "{pad}{key}: (none)");
        }
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
            let _ = writeln!(out, "{pad}{key}:");
            render_value(out, value, indent + 2);
        }
        scalar => {
            let _ = writeln!(out, "{pad}{key}: {}", scalar_text(scalar));
        }
    }
}

fn scalar_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => "null".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn relative_times_read_naturally_in_both_directions() {
        let now = Utc::now();
        assert_eq!(relative_time(now), "just now");
        assert_eq!(
            relative_time(now - TimeDelta::seconds(30)),
            "30 seconds ago"
        );
        assert_eq!(relative_time(now - TimeDelta::minutes(5)), "5 minutes ago");
        assert_eq!(relative_time(now - TimeDelta::hours(3)), "3 hours ago");
        assert_eq!(relative_time(now - TimeDelta::days(2)), "2 days ago");
        assert_eq!(relative_time(now + TimeDelta::minutes(9)), "in 9 minutes");
    }

    #[test]
    fn explorer_links_join_cleanly() {
        let network = crate::config::default_networks().remove(0);
        assert_eq!(
            explorer_transaction_url(&network, "0xabc").as_deref(),
            Some("https://etherscan.io/tx/0xabc")
        );
        let mut bare = network;
        bare.block_explorer_url = None;
        assert_eq!(explorer_transaction_url(&bare, "0xabc"), None);
    }

    #[test]
    fn generic_rendering_flattens_objects_and_numbers_arrays() {
        let rendered = generic_human(&serde_json::json!({
            "wallet": "primary",
            "networks": [{"name": "ethereum"}],
            "empty": [],
        }));
        assert!(rendered.contains("wallet: primary"));
        assert!(rendered.contains("1.:\n") || rendered.contains("1.:"));
        assert!(rendered.contains("  name: ethereum"));
        assert!(rendered.contains("empty: (none)"));
    }

    #[test]
    fn interactive_lists_never_shrink_below_a_scrollable_page() {
        // Chrome can never eat the list: a tiny or unreadable terminal still
        // leaves enough rows for the page to scroll through.
        assert_eq!(interactive_list_rows(usize::MAX), MINIMUM_LIST_ROWS);
        assert!(interactive_list_rows(6) >= MINIMUM_LIST_ROWS);
        // Reserving more rows never yields a taller list.
        assert!(interactive_list_rows(10) <= interactive_list_rows(4));
    }

    #[test]
    fn list_labels_never_exceed_one_row_at_any_width() {
        // A wrapped label would make the prompt draw more rows than it sized
        // its page for, which is what turns a cursor key into a full-screen
        // scroll. Every width, including degenerate ones, stays within budget.
        let label = "3 minutes ago · broadcast, awaiting receipt · primary · chain 1 · 4 call(s)";
        for columns in 0..=label.len() + 5 {
            let clamped = clamp_to_columns(label, columns);
            assert!(
                display_width(&clamped) <= columns,
                "{clamped:?} fits in {columns} columns"
            );
        }
        assert_eq!(clamp_to_columns("abcdef", 4), "abc…");
        assert_eq!(clamp_to_columns("abcdef", 6), "abcdef");
    }

    #[test]
    fn list_labels_measure_wide_glyphs_by_the_columns_they_occupy() {
        // Counting characters would let a CJK name wrap anyway: each of these
        // is one character but two columns.
        assert_eq!(display_width("東京"), 4);
        assert_eq!(display_width("ab"), 2);
        assert!(display_width(&clamp_to_columns("東京証券取引所", 5)) <= 5);
    }

    #[test]
    fn list_labels_collapse_newlines_into_one_row() {
        assert_eq!(interactive_list_label("first\nsecond"), "first second");
    }

    #[test]
    fn human_output_strips_control_sequences_but_keeps_lines() {
        assert_eq!(terminal_safe_multiline("a\u{1b}[31mb\nc"), "a [31mb\nc");
    }
}
