//! Interactive terminal prompts and styled status output.
//!
//! Every interactive prompt in this CLI is drawn by the ratatui-based
//! engine in this module — a short-lived inline viewport that erases itself
//! and leaves one answered line in the scrollback — and every piece of
//! non-prompt chrome (intro/outro banners, notes, warnings, progress lines)
//! is drawn by the helpers here, so the whole interactive surface lives in
//! one module on one terminal stack.
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
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context as _, Result, ensure};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::Stylize;
use crossterm::terminal as raw;
use ratatui::{
    Terminal, TerminalOptions, Viewport,
    backend::{Backend, CrosstermBackend},
    layout::Position,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::render::display_width;

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

/// Set once a command has read standard input to EOF as *data* rather than as
/// keystrokes. See [`note_stdin_consumed`].
static STDIN_CONSUMED: AtomicBool = AtomicBool::new(false);

/// Record that standard input carried a document, not keystrokes, so
/// [`interactive`] stops treating it as evidence either way.
///
/// `ekubo-wallet settings tokens import -` exists so a list can be piped in without an
/// agent re-emitting it, and a pipe is by definition not a terminal — so the
/// ordinary stdin check would conclude "not interactive" and silently confirm
/// nothing, which is the one outcome that would make the feature useless. It
/// is safe to disregard stdin here because no prompt in this wallet reads it:
/// every one of them goes through crossterm, which reads the controlling
/// terminal directly (`/dev/tty` on Unix, the console input handle on
/// Windows) and draws on stderr. Redirecting stdin therefore takes nothing
/// away from the picker.
///
/// The check on stderr below is what still has to hold, and it is the one
/// that matters: with no terminal to draw on there is no review, so a
/// piped-in list in a script confirms nothing rather than confirming
/// everything.
pub fn note_stdin_consumed() {
    STDIN_CONSUMED.store(true, Ordering::Relaxed);
}

/// Whether prompts can run at all: a terminal to draw on, and a standard
/// input that is either a terminal or has already been spent on a document.
/// Callers decide what to do when they cannot.
#[must_use]
pub fn interactive() -> bool {
    (io::stdin().is_terminal() || STDIN_CONSUMED.load(Ordering::Relaxed))
        && io::stderr().is_terminal()
}

/// Punctuates a prompt message so the answer cannot read as part of the
/// question.
///
/// An answered prompt is left in the scrollback as `message answer` with a
/// single space between them, so a message ending in a word runs straight
/// into what was typed — `Network identifier base` reads as a four-word
/// question, not as a question and its answer. Every prompt message in the
/// wallet goes through here, so the separator is the same one everywhere.
#[must_use]
pub fn question(message: &str) -> String {
    let message = message.trim_end();
    if message.ends_with(['?', ':']) {
        message.to_owned()
    } else {
        format!("{message}:")
    }
}

/// Whether a keypress means "back out of this prompt".
fn cancels(key: KeyEvent) -> bool {
    key.code == KeyCode::Esc
        || (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'd')))
}

/// The wallet's prompt palette, disabled alongside every other color.
fn accent(style: Style) -> Style {
    if stderr_colored() {
        style.fg(Color::Cyan)
    } else {
        style
    }
}

fn dimmed(style: Style) -> Style {
    if stderr_colored() {
        style.fg(Color::DarkGray)
    } else {
        style
    }
}

fn strong(style: Style) -> Style {
    if stderr_colored() {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

/// A short-lived inline prompt viewport: raw mode plus a few reserved rows
/// at the cursor. Closing erases the rows, so the one answered line printed
/// after is all that lands in the scrollback. Raw mode is undone on drop so
/// an error or panic mid-prompt still hands the terminal back.
/// The marker every prompt line opens with.
///
/// A constant rather than a literal at each site because the cursor position
/// is computed from its width: when the two were written separately, the
/// arithmetic assumed three columns for what renders as two, and the caret sat
/// one column right of the character it was supposed to be under.
const PROMPT_MARKER: &str = "◆ ";

struct Inline {
    terminal: Terminal<CrosstermBackend<io::Stderr>>,
}

/// Throw away input that arrived before this surface did.
///
/// Called on entering every prompt and screen, and again after anything that
/// takes long enough for someone to have typed at the old picture.
pub(crate) fn drain_type_ahead() -> Result<()> {
    while crossterm::event::poll(std::time::Duration::ZERO)? {
        let _ = crossterm::event::read()?;
    }
    Ok(())
}

impl Inline {
    fn open(height: u16) -> Result<Self> {
        ensure!(
            interactive(),
            "this prompt requires an interactive terminal"
        );
        crate::render::note_interactive_surface();
        raw::enable_raw_mode()?;
        // Whatever the terminal collected while this prompt did not exist is
        // not an answer to it. Getting here took RPC round trips, an authored
        // approval document, or both, and the keys typed into that silence
        // were meant for whatever the person thought was in front of them.
        //
        // The full-screen approval screens already drained for this reason.
        // The inline prompts did not, and they are what `account export` and
        // `account remove` draw: a picker that starts on Reject still reads a
        // buffered arrow key and a buffered Enter, and the two gates in front
        // of revealing a private key become one.
        drain_type_ahead()?;
        match Terminal::with_options(
            CrosstermBackend::new(io::stderr()),
            TerminalOptions {
                viewport: Viewport::Inline(height),
            },
        ) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                let _unused = raw::disable_raw_mode();
                Err(error.into())
            }
        }
    }

    fn close(mut self) -> Result<()> {
        release(&mut self.terminal)?;
        Ok(())
    }
}

/// Erase the prompt's rows and leave the cursor at the top left of where they
/// were, so the answered line printed next starts at the start of a line.
///
/// The cursor move is not redundant with the clear. `Terminal::clear` reads
/// the cursor, clears from the viewport origin, and then puts the cursor back
/// where it found it — and where it found it is wherever the last `draw` left
/// the caret: past the end of the question in `confirm` and `pick`, and past
/// the last typed character in a text prompt. Printing from there indented
/// every answered line by the width of the prompt that had just been erased —
/// far enough on the masked private-key prompt to wrap — and in `pick` left it
/// rows below the blank space instead of in it. Earlier ratatui left the
/// cursor at the origin after a clear, which is the behavior this restores and
/// [`Inline`]'s "leaves one answered line in the scrollback" contract assumes.
fn release<B: Backend>(terminal: &mut Terminal<B>) -> Result<(), B::Error> {
    // Read after the last draw rather than remembered from `open`: a resize
    // mid-prompt moves the inline viewport, and the stale row would put the
    // answered line somewhere the prompt no longer was.
    let origin = terminal.get_frame().area().as_position();
    terminal.clear()?;
    terminal.set_cursor_position(origin)?;
    terminal.show_cursor()?;
    Ok(())
}

impl Drop for Inline {
    fn drop(&mut self) {
        let _unused = raw::disable_raw_mode();
    }
}

/// The next key press, skipping releases, repeats-as-releases, and every
/// non-key event (a resize just redraws on the next loop).
fn next_key() -> Result<KeyEvent> {
    loop {
        if let Event::Key(key) = crossterm::event::read()?
            && key.kind == KeyEventKind::Press
        {
            return Ok(key);
        }
    }
}

/// The answered line a finished prompt leaves in the scrollback.
fn answered(message: &str, answer: &str) {
    eprintln!(
        "{}  {} {}",
        paint("◇", Tone::Success),
        paint(message, Tone::Emphasis),
        paint(answer, Tone::Info)
    );
}

/// The line a cancelled prompt leaves in the scrollback.
fn cancelled_line(message: &str) {
    eprintln!(
        "{}  {} {}",
        paint("■", Tone::Danger),
        paint(message, Tone::Emphasis),
        paint("(cancelled)", Tone::Muted)
    );
}

/// A yes-or-no question, defaulting to no.
///
/// `Ok(false)` covers an explicit no and backing out with Esc or Ctrl+C
/// alike: neither is consent, and the caller has nothing to tell them apart
/// for.
pub fn confirm(message: &str) -> Result<bool> {
    let message = question(message);
    let inline = Inline::open(1)?;
    let mut terminal = inline;
    let answer = loop {
        terminal.terminal.draw(|frame| {
            let line = Line::from(vec![
                Span::styled(PROMPT_MARKER, accent(Style::new())),
                Span::styled(message.clone(), strong(Style::new())),
                Span::styled(" (y/N)", dimmed(Style::new())),
            ]);
            frame.render_widget(Paragraph::new(line), frame.area());
        })?;
        let key = next_key()?;
        if cancels(key) {
            break false;
        }
        match key.code {
            KeyCode::Char('y' | 'Y') => break true,
            KeyCode::Char('n' | 'N') | KeyCode::Enter => break false,
            _ => {}
        }
    };
    terminal.close()?;
    answered(&message, if answer { "Yes" } else { "No" });
    Ok(answer)
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
/// plain yes or no. Two of them follow the yes with the platform prompt as
/// well: replacing a policy, because the policy decides what may be signed
/// with nobody watching, and saving or removing an address book entry,
/// because an alias decides where an agent-resolved payment goes — see
/// [`crate::human_presence::PresenceRequest`].
///
/// Reserving the heavier prompt for the operations that grant or redirect
/// signing authority is what keeps it worth reading. A user who is asked to
/// "approve or reject" before every network they rename has been taught that
/// the phrase means nothing.
pub struct Confirmation {
    title: String,
    summary: String,
    facts: Vec<(String, Vec<String>)>,
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
        self.facts.push((label.into(), vec![value.into()]));
        self
    }

    /// One label over several lines, each clamped like a fact's value.
    ///
    /// For the facts that are a list rather than a value — a permission diff,
    /// most of all. Rendered as the label alone and then the lines indented
    /// under it, because a diff joined onto one row is a diff nobody reads.
    #[must_use]
    pub fn fact_lines(
        mut self,
        label: impl Into<String>,
        lines: impl IntoIterator<Item = String>,
    ) -> Self {
        self.facts.push((label.into(), lines.into_iter().collect()));
        self
    }

    #[must_use]
    pub fn warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Exactly what `ask` prints above the question, so a test can read it
    /// without a terminal.
    #[cfg(test)]
    #[must_use]
    pub fn rendered_body(&self) -> String {
        self.body()
    }

    fn body(&self) -> String {
        let mut body = crate::render::terminal_safe_line(&self.summary);
        for (label, values) in &self.facts {
            body.push('\n');
            body.push_str(&crate::render::terminal_safe_line(label));
            match values.as_slice() {
                [single] => {
                    body.push_str(": ");
                    body.push_str(&crate::render::terminal_safe_line(single));
                }
                lines => {
                    body.push(':');
                    for line in lines {
                        body.push_str("\n  ");
                        body.push_str(&crate::render::terminal_safe_line(line));
                    }
                }
            }
        }
        body
    }

    /// Print the change, then ask. `Ok(false)` means it must not happen.
    pub fn ask(self, prompt: &str) -> Result<bool> {
        intro(crate::render::terminal_safe_line(&self.title));
        detail(self.body());
        for text in &self.warnings {
            warning(crate::render::terminal_safe_line(text));
        }
        confirm(prompt)
    }
}

/// One choice from a list of labels, by index. `Ok(None)` means the user
/// backed out with Esc or Ctrl+C. Arrows move, PageUp/PageDown and Home/End
/// jump, and typing filters the list; Enter selects.
///
/// Labels are clamped to one terminal row each — see
/// [`crate::render::interactive_list_label`] for why a wrapping label breaks
/// the whole prompt rather than just its own line.
#[expect(
    clippy::needless_pass_by_value,
    reason = "callers hand over the labels; borrowing would only move the clone to them"
)]
pub fn pick(prompt: &str, labels: Vec<String>, page_size: usize) -> Result<Option<usize>> {
    let message = question(prompt);
    let labels: Vec<String> = labels
        .iter()
        .map(|label| crate::render::interactive_list_label(label))
        .collect();
    let rows = page_size.max(3).min(labels.len().max(1));
    let inline = Inline::open(u16::try_from(rows + 1).unwrap_or(u16::MAX))?;
    let mut terminal = inline;
    let mut filter = String::new();
    let mut selected = 0_usize;
    let mut offset = 0_usize;

    let outcome = loop {
        let needle = filter.to_lowercase();
        let filtered: Vec<usize> = labels
            .iter()
            .enumerate()
            .filter(|(_, label)| needle.is_empty() || label.to_lowercase().contains(&needle))
            .map(|(index, _)| index)
            .collect();
        selected = selected.min(filtered.len().saturating_sub(1));
        if selected < offset {
            offset = selected;
        }
        if selected + 1 > offset + rows {
            offset = selected + 1 - rows;
        }

        terminal.terminal.draw(|frame| {
            let mut lines = Vec::with_capacity(rows + 1);
            let mut header = vec![
                Span::styled(PROMPT_MARKER, accent(Style::new())),
                Span::styled(message.clone(), strong(Style::new())),
            ];
            if filter.is_empty() {
                header.push(Span::styled(" (type to filter)", dimmed(Style::new())));
            } else {
                header.push(Span::raw(" "));
                header.push(Span::styled(filter.clone(), accent(Style::new())));
            }
            lines.push(Line::from(header));
            if filtered.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  (no matches — Backspace to clear the filter)",
                    dimmed(Style::new()),
                )));
            }
            for (row, &index) in filtered.iter().skip(offset).take(rows).enumerate() {
                let position = offset + row;
                let current = position == selected;
                let more_above = row == 0 && offset > 0;
                let more_below = row + 1 == rows && offset + rows < filtered.len();
                let marker = if current {
                    "● "
                } else if more_above {
                    "▲ "
                } else if more_below {
                    "▼ "
                } else {
                    "  "
                };
                let marker_style = if current {
                    accent(Style::new())
                } else {
                    dimmed(Style::new())
                };
                let label_style = if current {
                    strong(accent(Style::new()))
                } else {
                    Style::new()
                };
                lines.push(Line::from(vec![
                    Span::styled(marker, marker_style),
                    Span::styled(labels[index].clone(), label_style),
                ]));
            }
            frame.render_widget(Paragraph::new(lines), frame.area());
        })?;

        let key = next_key()?;
        if cancels(key) {
            break None;
        }
        match key.code {
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Down => {
                selected = (selected + 1).min(filtered.len().saturating_sub(1));
            }
            KeyCode::PageUp => selected = selected.saturating_sub(rows),
            KeyCode::PageDown => {
                selected = (selected + rows).min(filtered.len().saturating_sub(1));
            }
            KeyCode::Home => selected = 0,
            KeyCode::End => selected = filtered.len().saturating_sub(1),
            KeyCode::Enter => {
                if let Some(&index) = filtered.get(selected) {
                    break Some(index);
                }
            }
            KeyCode::Backspace => {
                filter.pop();
                selected = 0;
                offset = 0;
            }
            KeyCode::Char(character) if !character.is_control() => {
                filter.push(character);
                selected = 0;
                offset = 0;
            }
            _ => {}
        }
    };

    terminal.close()?;
    match outcome {
        Some(index) => answered(&message, &labels[index]),
        None => cancelled_line(&message),
    }
    Ok(outcome)
}

/// A single-line text prompt with live validation, built the same way for
/// plain and masked input. `Ok(None)` means the user backed out with Esc or
/// Ctrl+C.
pub struct TextPrompt<'a> {
    message: String,
    placeholder: Option<String>,
    help: Option<String>,
    value: String,
    default: Option<String>,
    masked: bool,
    #[allow(clippy::type_complexity)]
    validator: Option<Box<dyn Fn(&str) -> std::result::Result<(), String> + 'a>>,
}

/// Starts a text prompt for `message`.
#[must_use]
pub fn text(message: &str) -> TextPrompt<'static> {
    TextPrompt {
        message: question(message),
        placeholder: None,
        help: None,
        value: String::new(),
        default: None,
        masked: false,
        validator: None,
    }
}

impl<'a> TextPrompt<'a> {
    /// Example text shown dimmed while the line is empty.
    #[must_use]
    pub fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = Some(placeholder.into());
        self
    }

    /// One line of guidance shown under the input.
    #[must_use]
    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Pre-fills the line, for editing an existing value.
    #[must_use]
    pub fn initial(mut self, initial: impl Into<String>) -> Self {
        self.value = initial.into();
        self
    }

    /// The answer an empty submission stands for.
    #[must_use]
    pub fn default_value(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }

    /// Echo bullets instead of the typed characters, for key material. The
    /// answered line never echoes the value either way.
    #[must_use]
    pub fn masked(mut self) -> Self {
        self.masked = true;
        self
    }

    /// Rejects invalid submissions with `Err(reason)`; the prompt shows the
    /// reason and stays open.
    #[must_use]
    pub fn validate(
        mut self,
        validator: impl Fn(&str) -> std::result::Result<(), String> + 'a,
    ) -> TextPrompt<'a> {
        self.validator = Some(Box::new(validator));
        self
    }

    /// Runs the prompt. The answered line echoes the value, except for
    /// masked prompts, which leave only bullets behind.
    pub fn prompt(self) -> Result<Option<String>> {
        let inline = Inline::open(2)?;
        let mut terminal = inline;
        let mut value = self.value;
        let mut cursor = value.chars().count();
        let mut error: Option<String> = None;

        let outcome = loop {
            terminal.terminal.draw(|frame| {
                let area = frame.area();
                let shown = if self.masked {
                    "•".repeat(value.chars().count())
                } else {
                    value.clone()
                };
                let mut input = vec![
                    Span::styled(PROMPT_MARKER, accent(Style::new())),
                    Span::styled(self.message.clone(), strong(Style::new())),
                    Span::raw(" "),
                ];
                // Measured, not assumed: this has to match the spans
                // pushed above exactly, or the caret drifts from the text.
                let prefix_width = display_width(PROMPT_MARKER)
                    + display_width(&self.message)
                    + display_width(" ");
                if shown.is_empty() {
                    if let Some(placeholder) = &self.placeholder {
                        input.push(Span::styled(placeholder.clone(), dimmed(Style::new())));
                    } else if let Some(default) = &self.default {
                        input.push(Span::styled(
                            format!("(default: {default})"),
                            dimmed(Style::new()),
                        ));
                    }
                } else {
                    input.push(Span::raw(shown.clone()));
                }
                let status = error.as_ref().map_or_else(
                    || {
                        Line::from(Span::styled(
                            self.help.clone().unwrap_or_default(),
                            dimmed(Style::new()),
                        ))
                    },
                    |reason| {
                        Line::from(Span::styled(
                            format!("▲ {reason}"),
                            if stderr_colored() {
                                Style::new().fg(Color::Red)
                            } else {
                                Style::new()
                            },
                        ))
                    },
                );
                frame.render_widget(Paragraph::new(vec![Line::from(input), status]), area);
                let ahead: String = if self.masked {
                    "•".repeat(cursor)
                } else {
                    value.chars().take(cursor).collect()
                };
                let x = area.x
                    + u16::try_from(prefix_width + display_width(&ahead)).unwrap_or(u16::MAX);
                frame.set_cursor_position(Position { x, y: area.y });
            })?;

            let key = next_key()?;
            if cancels(key) {
                break None;
            }
            match key.code {
                KeyCode::Enter => {
                    let candidate = if value.is_empty() {
                        self.default.clone().unwrap_or_default()
                    } else {
                        value.clone()
                    };
                    match self
                        .validator
                        .as_ref()
                        .map_or(Ok(()), |check| check(&candidate))
                    {
                        Ok(()) => break Some(candidate),
                        Err(reason) => error = Some(reason),
                    }
                }
                KeyCode::Left => cursor = cursor.saturating_sub(1),
                KeyCode::Right => cursor = (cursor + 1).min(value.chars().count()),
                KeyCode::Home => cursor = 0,
                KeyCode::End => cursor = value.chars().count(),
                KeyCode::Backspace => {
                    if cursor > 0 {
                        let byte = char_boundary(&value, cursor - 1);
                        value.remove(byte);
                        cursor -= 1;
                        error = None;
                    }
                }
                KeyCode::Delete => {
                    if cursor < value.chars().count() {
                        let byte = char_boundary(&value, cursor);
                        value.remove(byte);
                        error = None;
                    }
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    value.clear();
                    cursor = 0;
                    error = None;
                }
                KeyCode::Char(character)
                    if !character.is_control()
                        && !key.modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    let byte = char_boundary(&value, cursor);
                    value.insert(byte, character);
                    cursor += 1;
                    error = None;
                }
                _ => {}
            }
        };

        terminal.close()?;
        match &outcome {
            Some(answer) => {
                if self.masked {
                    answered(&self.message, "••••••••");
                } else {
                    answered(&self.message, answer);
                }
            }
            None => cancelled_line(&self.message),
        }
        Ok(outcome)
    }

    /// Like [`TextPrompt::prompt`], but cancellation is an error naming the
    /// field — for flows that cannot continue without an answer.
    pub fn prompt_required(self) -> Result<String> {
        let message = self.message.clone();
        self.prompt()?
            .with_context(|| format!("cancelled at {message}"))
    }
}

/// The byte index of the `index`-th character of `value`.
fn char_boundary(value: &str, index: usize) -> usize {
    value
        .char_indices()
        .nth(index)
        .map_or(value.len(), |(byte, _)| byte)
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
#[path = "tui_test.rs"]
mod tests;
