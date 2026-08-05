//! Interactive terminal prompts and styled status output.
//!
//! Every interactive prompt in this CLI is an `inquire` prompt configured
//! with the wallet's one color scheme, and every piece of non-prompt chrome
//! (intro/outro banners, notes, warnings, progress lines) is drawn by the
//! helpers here, so the whole interactive surface lives in one module.
//!
//! Styling never reaches machine-readable output: chrome writes to stderr,
//! colors switch off when the stream is not a terminal or `NO_COLOR` is set,
//! and data printed through [`crate::render::emit`] stays styled by that
//! module's sanitizer, which strips every escape sequence. Anything colored
//! here must therefore be chrome the CLI authored, never stored data — pass
//! untrusted values through [`crate::render::terminal_safe_multiline`] first.

use std::fmt::Display;
use std::io::{self, IsTerminal};
use std::sync::OnceLock;

use crossterm::style::Stylize;
use inquire::InquireError;
use inquire::ui::{Attributes, Color, RenderConfig, StyleSheet, Styled};

/// Semantic colors, so call sites say what a value means and the palette
/// stays consistent everywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Completed, confirmed, safe.
    Success,
    /// Needs attention but not fatal.
    Warning,
    /// Failed, reverted, destructive.
    Danger,
    /// Neutral facts and identifiers.
    Info,
    /// De-emphasized detail.
    Muted,
    /// Headings and the one thing to read first.
    Emphasis,
}

fn styled(text: &str, tone: Tone) -> String {
    match tone {
        Tone::Success => text.green().to_string(),
        Tone::Warning => text.yellow().to_string(),
        Tone::Danger => text.red().to_string(),
        Tone::Info => text.cyan().to_string(),
        Tone::Muted => text.dark_grey().to_string(),
        Tone::Emphasis => text.bold().to_string(),
    }
}

fn stderr_colored() -> bool {
    static COLORED: OnceLock<bool> = OnceLock::new();
    *COLORED.get_or_init(|| io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none())
}

/// Colors `text` for the interactive chrome on stderr; plain text everywhere
/// colors would end up in a pipe or a log.
#[must_use]
pub fn paint(text: &str, tone: Tone) -> String {
    if stderr_colored() {
        styled(text, tone)
    } else {
        text.to_owned()
    }
}

/// Like [`paint`], but for human data lines written to stdout.
#[must_use]
pub fn paint_stdout(text: &str, tone: Tone) -> String {
    static COLORED: OnceLock<bool> = OnceLock::new();
    let colored = *COLORED
        .get_or_init(|| io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none());
    if colored {
        styled(text, tone)
    } else {
        text.to_owned()
    }
}

/// Install the wallet's color scheme for every subsequent inquire prompt.
/// Safe to call more than once.
pub fn init_prompt_theme() {
    let config = if stderr_colored() {
        RenderConfig::default_colored()
            .with_prompt_prefix(Styled::new("◆").with_fg(Color::LightCyan))
            .with_answered_prompt_prefix(Styled::new("◇").with_fg(Color::LightGreen))
            .with_highlighted_option_prefix(Styled::new("●").with_fg(Color::LightGreen))
            .with_scroll_up_prefix(Styled::new("▲").with_fg(Color::DarkGrey))
            .with_scroll_down_prefix(Styled::new("▼").with_fg(Color::DarkGrey))
            .with_selected_option(Some(
                StyleSheet::new()
                    .with_fg(Color::LightCyan)
                    .with_attr(Attributes::BOLD),
            ))
            .with_answer(StyleSheet::new().with_fg(Color::LightCyan))
            .with_help_message(StyleSheet::new().with_fg(Color::DarkGrey))
            .with_canceled_prompt_indicator(Styled::new("(cancelled)").with_fg(Color::DarkRed))
    } else {
        RenderConfig::empty()
    };
    inquire::set_global_render_config(config);
}

/// Whether prompts can run at all: interactive stdin plus a terminal to draw
/// on. Callers decide what to do when they cannot.
#[must_use]
pub fn interactive() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// Maps a prompt result so Esc and Ctrl+C read as "the user declined to
/// answer" (`None`) while real terminal failures stay errors.
pub fn optional<T>(result: Result<T, InquireError>) -> anyhow::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Punctuates a prompt message so the answer cannot read as part of the
/// question.
///
/// inquire redraws an answered prompt as `message answer` with a single
/// space between them, so a message ending in a word runs straight into what
/// was typed — `Network identifier base` reads as a four-word question, not
/// as a question and its answer. Every prompt message in the wallet goes
/// through here, so the separator is the same one everywhere.
#[must_use]
pub fn question(message: &str) -> String {
    let message = message.trim_end();
    if message.ends_with(['?', ':']) {
        message.to_owned()
    } else {
        format!("{message}:")
    }
}

/// A yes-or-no question, defaulting to no.
///
/// `Ok(false)` covers an explicit no and backing out with Esc or Ctrl+C
/// alike: neither is consent, and the caller has nothing to tell them apart
/// for.
pub fn confirm(message: &str) -> anyhow::Result<bool> {
    Ok(optional(
        inquire::Confirm::new(&question(message))
            .with_default(false)
            .prompt(),
    )?
    .unwrap_or(false))
}

/// A local change that needs a yes or no.
///
/// The wallet asks two different kinds of question, and they must not look
/// alike. Anything that takes the private key out of the credential store —
/// signing, exporting, deleting it — goes through [`crate::approval`]: two
/// named outcomes, a cursor that starts on Reject, and platform owner
/// authentication after. Everything else only rewrites local configuration:
/// an address book entry, a policy file, which RPC a network is reached
/// through. Those ask with this instead — the same facts and warnings, then a
/// plain yes or no.
///
/// Reserving the heavier prompt for the operations that can actually sign is
/// what keeps it worth reading. A user who is asked to "approve or reject"
/// before every alias they save has been taught that the phrase means
/// nothing.
pub struct Confirmation {
    title: String,
    summary: String,
    facts: Vec<(String, String)>,
    warnings: Vec<String>,
}

impl Confirmation {
    #[must_use]
    pub fn new(title: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            summary: summary.into(),
            facts: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// One labeled value. Both halves are clamped to a single line: a fact is
    /// often stored or agent-supplied text, and a newline in it would draw
    /// what looks like another fact.
    #[must_use]
    pub fn fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.facts.push((label.into(), value.into()));
        self
    }

    #[must_use]
    pub fn warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Print the change, then ask. `Ok(false)` means it must not happen.
    pub fn ask(self, prompt: &str) -> anyhow::Result<bool> {
        init_prompt_theme();
        intro(crate::render::terminal_safe_line(&self.title));

        let mut body = crate::render::terminal_safe_line(&self.summary);
        for (label, value) in &self.facts {
            body.push('\n');
            body.push_str(&crate::render::terminal_safe_line(label));
            body.push_str(": ");
            body.push_str(&crate::render::terminal_safe_line(value));
        }
        detail(body);
        for text in &self.warnings {
            warning(crate::render::terminal_safe_line(text));
        }
        confirm(prompt)
    }
}

/// One choice from a list of labels, by index. `Ok(None)` means the user
/// backed out with Esc or Ctrl+C. PageUp/PageDown, Home/End, and
/// type-to-filter all work inside the list.
///
/// Labels are clamped to one terminal row each — see
/// [`crate::render::interactive_list_label`] for why a wrapping label breaks
/// the whole prompt rather than just its own line.
pub fn pick(prompt: &str, labels: Vec<String>, page_size: usize) -> anyhow::Result<Option<usize>> {
    struct Choice {
        index: usize,
        label: String,
    }
    impl Display for Choice {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.label)
        }
    }
    let choices = labels
        .into_iter()
        .enumerate()
        .map(|(index, label)| Choice {
            index,
            label: crate::render::interactive_list_label(&label),
        })
        .collect();
    Ok(optional(
        inquire::Select::new(&question(prompt), choices)
            .with_page_size(page_size.max(3))
            .prompt(),
    )?
    .map(|choice| choice.index))
}

/// Opens a titled interactive section.
pub fn intro(title: impl Display) {
    eprintln!(
        "{}  {}",
        paint("◆", Tone::Info),
        paint(&title.to_string(), Tone::Emphasis)
    );
}

/// Closes an interactive section on a good outcome.
pub fn outro(message: impl Display) {
    eprintln!("{}  {message}", paint("◇", Tone::Success));
}

/// Closes an interactive section on a rejection or abort.
pub fn outro_cancel(message: impl Display) {
    eprintln!(
        "{}  {}",
        paint("■", Tone::Danger),
        paint(&message.to_string(), Tone::Danger)
    );
}

/// One neutral status line.
pub fn info(message: impl Display) {
    eprintln!("{}  {message}", paint("●", Tone::Info));
}

/// One warning line that stands out from surrounding chrome.
pub fn warning(message: impl Display) {
    eprintln!(
        "{}  {}",
        paint("▲", Tone::Warning),
        paint(&message.to_string(), Tone::Warning)
    );
}

/// A titled block of body text, indented so it reads as a quotation rather
/// than as chrome. The body must already be terminal-safe.
pub fn note(title: impl Display, body: impl Display) {
    eprintln!(
        "{}  {}",
        paint("│", Tone::Muted),
        paint(&title.to_string(), Tone::Emphasis)
    );
    detail(body);
}

/// The indented body of a note, without a title of its own — for a block
/// that hangs off an [`intro`] rather than starting its own section. The
/// body must already be terminal-safe.
pub fn detail(body: impl Display) {
    for line in body.to_string().lines() {
        eprintln!("{}    {line}", paint("│", Tone::Muted));
    }
}

/// A long-running step: announce it, then report how it ended. Static lines
/// rather than an animated spinner, so output stays honest in transcripts
/// and pipes.
pub struct Progress;

impl Progress {
    #[must_use]
    pub fn start(message: impl Display) -> Self {
        eprintln!(
            "{}  {}",
            paint("…", Tone::Muted),
            paint(&message.to_string(), Tone::Muted)
        );
        Self
    }

    pub fn stop(self, message: impl Display) {
        eprintln!("{}  {message}", paint("✔", Tone::Success));
    }

    pub fn error(self, message: impl Display) {
        eprintln!(
            "{}  {}",
            paint("✖", Tone::Danger),
            paint(&message.to_string(), Tone::Danger)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tones_map_to_distinct_ansi_styles() {
        let rendered: Vec<String> = [
            Tone::Success,
            Tone::Warning,
            Tone::Danger,
            Tone::Info,
            Tone::Muted,
            Tone::Emphasis,
        ]
        .iter()
        .map(|tone| styled("x", *tone))
        .collect();
        for text in &rendered {
            assert!(text.contains('\u{1b}'), "{text:?} carries an escape code");
            assert!(text.ends_with("\u{1b}[0m") || text.contains("39m") || text.contains("22m"));
        }
        let unique: std::collections::BTreeSet<_> = rendered.iter().collect();
        assert_eq!(unique.len(), rendered.len(), "every tone looks different");
    }

    #[test]
    fn every_prompt_separates_its_question_from_the_answer() {
        assert_eq!(question("Network identifier"), "Network identifier:");
        assert_eq!(question("Chain ID  "), "Chain ID:");
        // Already punctuated: a second mark would read as a typo.
        assert_eq!(question("Save this alias?"), "Save this alias?");
        assert_eq!(question("Private key:"), "Private key:");
    }

    #[test]
    fn cancellation_reads_as_none_and_failures_stay_errors() {
        assert_eq!(optional(Ok(1)).unwrap(), Some(1));
        assert_eq!(
            optional::<u8>(Err(InquireError::OperationCanceled)).unwrap(),
            None
        );
        assert_eq!(
            optional::<u8>(Err(InquireError::OperationInterrupted)).unwrap(),
            None
        );
        assert!(optional::<u8>(Err(InquireError::NotTTY)).is_err());
    }
}
