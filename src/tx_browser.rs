//! Full-screen transaction history browser.
//!
//! The transaction list used to be an `inquire` select: it sized its page
//! once when the prompt opened, so a terminal resized (or simply short) mid
//! prompt scrolled the whole screen instead of the cursor, and its
//! type-to-filter matched only the visible row text — which is truncated to
//! the terminal width, so the values worth searching for (the full request
//! ID, a transaction hash) were exactly the ones it could not see.
//!
//! This browser draws with ratatui on the alternate screen instead. Every
//! frame lays out against the live terminal size, so resizing mid-session
//! just reflows; `/` filters against a haystack built from the record itself
//! (full request ID, hashes, wallet, network, status, addresses) rather than
//! the rendered row; and the expanded view is a styled document — status in
//! its lifecycle color, balance changes in an aligned table, the explorer
//! URL one keystroke from a browser — instead of a wall of `label: value`
//! lines.
//!
//! Everything drawn here is either chrome this module authored or stored
//! data passed through [`crate::render::terminal_safe_line`] at the moment a
//! [`Span`] is built, so escape sequences in stored text can never reach the
//! terminal.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Stderr};
use std::str::FromStr;

use alloy::primitives::{Address, B256, U256, b256};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use num_bigint::BigUint;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line as UiLine, Span as UiSpan},
    widgets::{Cell, Paragraph, Row as UiRow, Table, TableState},
};
use unicode_width::UnicodeWidthChar;

use crate::{
    approval_summary::{TokenMetadataMap, format_fixed_point, load_token_metadata},
    config::{ConfigStore, NetworkConfig},
    pending::{PendingStatus, PendingTransaction},
    render::terminal_safe_line,
    rpc::{ReceiptDetails, transaction_receipt_details},
    tui::Tone,
};

/// keccak256("Transfer(address,address,uint256)"), for receipt log decoding.
const TRANSFER_EVENT: B256 =
    b256!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

#[must_use]
pub fn status_label(status: PendingStatus) -> &'static str {
    match status {
        PendingStatus::AwaitingApproval => "awaiting approval",
        PendingStatus::Rejected => "rejected",
        PendingStatus::Signed => "approved, not submitted",
        PendingStatus::Submitting => "submitting",
        PendingStatus::Broadcast => "broadcast, awaiting receipt",
        PendingStatus::Confirmed => "confirmed",
        PendingStatus::Reverted => "reverted",
        PendingStatus::Expired => "expired",
        PendingStatus::Cancelled => "cancelled",
    }
}

/// The semantic color of a lifecycle state: green once value moved as
/// approved, yellow while something is still pending, red for every path
/// where nothing will move.
#[must_use]
pub fn status_tone(status: PendingStatus) -> Tone {
    match status {
        PendingStatus::Confirmed | PendingStatus::Signed => Tone::Success,
        PendingStatus::AwaitingApproval | PendingStatus::Submitting | PendingStatus::Broadcast => {
            Tone::Warning
        }
        PendingStatus::Rejected
        | PendingStatus::Reverted
        | PendingStatus::Expired
        | PendingStatus::Cancelled => Tone::Danger,
    }
}

/// One run of text with one semantic tone. Built through the constructors,
/// which sanitize, so a span can never carry stored escape sequences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    text: String,
    tone: Option<Tone>,
}

impl Span {
    fn plain(text: impl AsRef<str>) -> Self {
        Self {
            text: terminal_safe_line(text.as_ref()),
            tone: None,
        }
    }

    fn toned(text: impl AsRef<str>, tone: Tone) -> Self {
        Self {
            tone: Some(tone),
            ..Self::plain(text)
        }
    }
}

/// One display line of the detail document.
pub type Line = Vec<Span>;

fn tone_style(tone: Tone) -> Style {
    match tone {
        Tone::Success => Style::new().fg(Color::Green),
        Tone::Warning => Style::new().fg(Color::Yellow),
        Tone::Danger => Style::new().fg(Color::Red),
        Tone::Info => Style::new().fg(Color::Cyan),
        Tone::Muted => Style::new().fg(Color::DarkGray),
        Tone::Emphasis => Style::new().add_modifier(Modifier::BOLD),
    }
}

fn ui_span(span: &Span) -> UiSpan<'static> {
    match span.tone {
        Some(tone) => UiSpan::styled(span.text.clone(), tone_style(tone)),
        None => UiSpan::raw(span.text.clone()),
    }
}

/// Render detail lines for stdout: `paint` decides whether tones become ANSI
/// colors (see [`crate::tui::paint_stdout`]) or stay plain for a pipe.
pub fn lines_to_text(lines: &[Line], paint: impl Fn(&str, Tone) -> String) -> String {
    lines
        .iter()
        .map(|line| {
            line.iter()
                .map(|span| match span.tone {
                    Some(tone) => paint(&span.text, tone),
                    None => span.text.clone(),
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn display_width(text: &str) -> usize {
    text.chars()
        .map(|character| UnicodeWidthChar::width(character).unwrap_or(0))
        .sum()
}

/// Wrap one line to `columns`, breaking at a space where one is in reach and
/// mid-word otherwise, so a 66-character hash lands on two fully visible
/// lines rather than being clipped at the terminal edge. Tones survive the
/// break: wrapping happens on a flattened `(char, tone)` stream and the
/// pieces are reassembled into runs afterwards.
fn wrap_line(line: &Line, columns: usize) -> Vec<Line> {
    let columns = columns.max(1);
    let flat: Vec<(char, Option<Tone>)> = line
        .iter()
        .flat_map(|span| span.text.chars().map(|character| (character, span.tone)))
        .collect();
    if flat.is_empty() {
        return vec![Vec::new()];
    }
    let mut lines = Vec::new();
    let mut start = 0;
    while start < flat.len() {
        let mut width = 0;
        let mut end = start;
        let mut last_space = None;
        while end < flat.len() {
            let advance = UnicodeWidthChar::width(flat[end].0).unwrap_or(0);
            if width + advance > columns && end > start {
                break;
            }
            if flat[end].0 == ' ' {
                last_space = Some(end);
            }
            width += advance;
            end += 1;
        }
        if end == flat.len() {
            lines.push(reassemble(&flat[start..end]));
            break;
        }
        // The space a line breaks at is dropped; everything else survives.
        let (line_end, next_start) = match last_space {
            Some(space) if space > start => (space, space + 1),
            _ => (end, end),
        };
        lines.push(reassemble(&flat[start..line_end]));
        start = next_start;
    }
    lines
}

/// Merge a wrapped slice back into spans, one per run of equal tone.
fn reassemble(flat: &[(char, Option<Tone>)]) -> Line {
    let mut spans: Line = Vec::new();
    for (character, tone) in flat {
        match spans.last_mut() {
            Some(span) if span.tone == *tone => span.text.push(*character),
            _ => spans.push(Span {
                text: character.to_string(),
                tone: *tone,
            }),
        }
    }
    spans
}

fn wrap_lines(lines: &[Line], columns: usize) -> Vec<Line> {
    lines
        .iter()
        .flat_map(|line| wrap_line(line, columns))
        .collect()
}

/// One transaction as the list shows and searches it. The visible cells are
/// precomputed; only the age is formatted at draw time so it does not go
/// stale while the browser sits open.
struct ListRow {
    short_id: String,
    status: &'static str,
    tone: Tone,
    wallet: String,
    network: String,
    calls: String,
    created_at: chrono::DateTime<chrono::Utc>,
    /// Lowercased searchable text: the values a person knows a transaction
    /// by, not the truncated row the screen happens to show.
    haystack: String,
}

/// The network column: the configured name for the chain, the stored name
/// when the network has since been removed, and only then the raw chain ID.
fn network_label(
    networks: &BTreeMap<String, NetworkConfig>,
    record: &PendingTransaction,
) -> String {
    networks.get(&record.chain_id).map_or_else(
        || {
            if record.network_name.is_empty() {
                format!("chain {}", record.chain_id)
            } else {
                record.network_name.clone()
            }
        },
        |network| network.name.clone(),
    )
}

fn configured_networks(config: &ConfigStore) -> BTreeMap<String, NetworkConfig> {
    config
        .load()
        .map(|loaded| {
            loaded
                .networks
                .into_iter()
                .map(|network| (network.chain_id.to_string(), network))
                .collect()
        })
        .unwrap_or_default()
}

fn list_rows(
    networks: &BTreeMap<String, NetworkConfig>,
    records: &[PendingTransaction],
) -> Vec<ListRow> {
    records
        .iter()
        .map(|record| {
            let network = network_label(networks, record);
            let haystack = [
                record.request_id.to_string(),
                record.wallet_id.clone(),
                network.clone(),
                record.chain_id.clone(),
                status_label(record.status).to_owned(),
                record.signed_transaction_hash.clone().unwrap_or_default(),
                record
                    .broadcast_transaction_hash
                    .clone()
                    .unwrap_or_default(),
                format!("{:#x}", record.execution_plan.sender),
                record
                    .execution_plan
                    .ordered_steps
                    .iter()
                    .map(|step| format!("{:#x}", step.transaction.to))
                    .collect::<Vec<_>>()
                    .join(" "),
            ]
            .join(" ")
            .to_lowercase();
            ListRow {
                short_id: short_request_id(record.request_id),
                status: status_label(record.status),
                tone: status_tone(record.status),
                wallet: terminal_safe_line(&record.wallet_id),
                network: terminal_safe_line(&network),
                calls: record.execution_plan.ordered_steps.len().to_string(),
                created_at: record.created_at,
                haystack,
            }
        })
        .collect()
}

/// A UUID's first group: enough to tell rows apart at a glance, while the
/// commands that take an identifier keep getting the full ID elsewhere.
fn short_request_id(request_id: uuid::Uuid) -> String {
    request_id
        .to_string()
        .split('-')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Whether a row matches the search: every whitespace-separated term appears
/// somewhere in the haystack, so "reverted base" or a pasted hash both work.
fn matches_filter(haystack: &str, filter: &str) -> bool {
    filter
        .split_whitespace()
        .all(|term| haystack.contains(&term.to_lowercase()))
}

/// What one receipt lookup produced, resolved before the detail document is
/// composed so composition itself stays pure and testable.
enum ReceiptSection {
    Ready {
        receipt: ReceiptDetails,
        metadata: TokenMetadataMap,
    },
    NotYetAvailable,
    Failed(String),
}

/// Load everything the expanded view needs. Chain lookups are best-effort
/// display work: an unreachable RPC degrades to the stored data.
pub async fn load_detail(config: &ConfigStore, record: &PendingTransaction) -> Vec<Line> {
    let network = config.network_by_chain_id(&record.chain_id).ok();
    let receipt = load_receipt(network.as_ref(), record).await;
    detail_lines(record, network.as_ref(), receipt.as_ref())
}

async fn load_receipt(
    network: Option<&NetworkConfig>,
    record: &PendingTransaction,
) -> Option<ReceiptSection> {
    let network = network?;
    let hash = broadcast_hash(record)?;
    if !matches!(
        record.status,
        PendingStatus::Broadcast | PendingStatus::Confirmed | PendingStatus::Reverted
    ) {
        return None;
    }
    Some(match transaction_receipt_details(network, hash).await {
        Ok(Some(receipt)) => {
            let tokens: Vec<Address> = transfer_activity(record.execution_plan.sender, &receipt)
                .into_iter()
                .map(|(token, _)| token)
                .collect();
            let metadata = load_token_metadata(network, &tokens).await;
            ReceiptSection::Ready { receipt, metadata }
        }
        Ok(None) => ReceiptSection::NotYetAvailable,
        Err(error) => ReceiptSection::Failed(format!("{error:#}")),
    })
}

fn broadcast_hash(record: &PendingTransaction) -> Option<&str> {
    record
        .broadcast_transaction_hash
        .as_deref()
        .or(record.signed_transaction_hash.as_deref())
}

/// Net standard Transfer activity for the sender from the receipt logs:
/// `token -> (received, sent)`, tokens the wallet never touched left out.
fn transfer_activity(wallet: Address, receipt: &ReceiptDetails) -> Vec<(Address, (U256, U256))> {
    let mut activity: BTreeMap<Address, (U256, U256)> = BTreeMap::new();
    for log in &receipt.logs {
        if log.topics.len() != 3 || log.topics[0] != TRANSFER_EVENT || log.data.len() != 32 {
            continue;
        }
        let from = Address::from_slice(&log.topics[1].as_slice()[12..]);
        let to = Address::from_slice(&log.topics[2].as_slice()[12..]);
        let amount = U256::from_be_slice(&log.data);
        let entry = activity.entry(log.address).or_default();
        if to == wallet {
            entry.0 = entry.0.saturating_add(amount);
        }
        if from == wallet {
            entry.1 = entry.1.saturating_add(amount);
        }
    }
    activity
        .into_iter()
        .filter(|(_, (received, sent))| !received.is_zero() || !sent.is_zero())
        .collect()
}

/// Columns a fact label occupies, so values line up into a readable column.
const FACT_LABEL_COLUMNS: usize = 12;

fn fact(label: &str, value: Vec<Span>) -> Line {
    let mut line = vec![Span::toned(
        format!("{label:<FACT_LABEL_COLUMNS$}"),
        Tone::Muted,
    )];
    line.extend(value);
    line
}

fn heading(text: &str) -> Line {
    vec![Span::toned(text, Tone::Emphasis)]
}

/// The expanded human view of one lifecycle record, as styled lines. Pure
/// composition: everything network-dependent was resolved by the caller.
fn detail_lines(
    record: &PendingTransaction,
    network: Option<&NetworkConfig>,
    receipt: Option<&ReceiptSection>,
) -> Vec<Line> {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(fact(
        "Status",
        vec![Span::toned(
            status_label(record.status),
            status_tone(record.status),
        )],
    ));
    lines.push(fact(
        "Request",
        vec![Span::plain(record.request_id.to_string())],
    ));
    lines.push(fact("Wallet", vec![Span::plain(&record.wallet_id)]));
    let network_name = network.map_or(record.network_name.as_str(), |network| {
        network.name.as_str()
    });
    lines.push(fact(
        "Network",
        vec![
            Span::plain(network_name),
            Span::toned(format!("  (chain {})", record.chain_id), Tone::Muted),
        ],
    ));
    lines.push(fact(
        "Created",
        vec![Span::plain(crate::render::described_time(
            record.created_at,
        ))],
    ));
    if record.updated_at != record.created_at {
        lines.push(fact(
            "Updated",
            vec![Span::plain(crate::render::described_time(
                record.updated_at,
            ))],
        ));
    }
    if record.status == PendingStatus::AwaitingApproval {
        lines.push(fact(
            "Expires",
            vec![Span::toned(
                crate::render::described_time(record.expires_at),
                Tone::Warning,
            )],
        ));
    }
    if let Some(approved_at) = record.approved_at {
        lines.push(fact(
            "Approved",
            vec![Span::plain(crate::render::described_time(approved_at))],
        ));
    }
    if let Some(rejected_at) = record.rejected_at {
        lines.push(fact(
            "Rejected",
            vec![Span::plain(crate::render::described_time(rejected_at))],
        ));
    }
    lines.push(fact("Plan digest", vec![Span::plain(&record.digest)]));
    lines.push(fact(
        "Policy",
        vec![Span::plain(format!(
            "revision {} · approval {}",
            record.policy_revision,
            if record.approval_required {
                "required"
            } else {
                "automatic"
            }
        ))],
    ));

    lines.push(Vec::new());
    lines.push(heading(&format!(
        "Calls ({})",
        record.execution_plan.ordered_steps.len()
    )));
    for step in &record.execution_plan.ordered_steps {
        let calldata = step.transaction.data.as_ref();
        let selector = if calldata.is_empty() {
            "no calldata".to_owned()
        } else {
            format!(
                "selector 0x{} · {} bytes",
                hex::encode(&calldata[..calldata.len().min(4)]),
                calldata.len()
            )
        };
        lines.push(vec![
            Span::toned(format!("  {:>2}  ", step.step), Tone::Muted),
            Span::plain(format!("to {:#x}", step.transaction.to)),
        ]);
        lines.push(vec![
            Span::plain("      "),
            Span::plain(native_amount(step.transaction.value.as_str(), network)),
            Span::toned(format!("  ·  {selector}"), Tone::Muted),
        ]);
    }

    if let Some(hash) = broadcast_hash(record) {
        lines.push(Vec::new());
        lines.push(heading("Execution"));
        lines.push(fact("Hash", vec![Span::plain(hash)]));
        if let Some(url) =
            network.and_then(|network| crate::render::explorer_transaction_url(network, hash))
        {
            lines.push(fact("Explorer", vec![Span::toned(url, Tone::Info)]));
        }
        if let Some(block) = &record.block_number {
            lines.push(fact("Block", vec![Span::plain(block)]));
        }
    }

    if let Some(receipt) = receipt {
        lines.push(Vec::new());
        lines.push(heading("Receipt"));
        match receipt {
            ReceiptSection::Ready { receipt, metadata } => {
                lines.extend(receipt_detail_lines(record, network, receipt, metadata));
            }
            ReceiptSection::NotYetAvailable => lines.push(fact(
                "Result",
                vec![Span::toned("not yet available from the RPC", Tone::Warning)],
            )),
            ReceiptSection::Failed(error) => lines.push(fact(
                "Result",
                vec![Span::toned(
                    format!("lookup failed ({error})"),
                    Tone::Danger,
                )],
            )),
        }
    }
    lines
}

/// A native value in the network's currency, with the exact wei in reach:
/// "0.05 ETH (50000000000000000 wei)", or the raw wei alone when the network
/// or the value is unknown.
fn native_amount(value: &str, network: Option<&NetworkConfig>) -> String {
    if BigUint::from_str(value).is_err() {
        return format!("value {value}");
    }
    let currency = network.and_then(|network| network.native_currency.as_ref());
    match currency {
        Some(currency) if value != "0" => format!(
            "{} {} ({value} wei)",
            format_fixed_point(value, currency.decimals),
            currency.symbol
        ),
        Some(currency) => format!("0 {}", currency.symbol),
        None => format!("{value} wei"),
    }
}

fn receipt_detail_lines(
    record: &PendingTransaction,
    network: Option<&NetworkConfig>,
    receipt: &ReceiptDetails,
    metadata: &TokenMetadataMap,
) -> Vec<Line> {
    let mut lines = Vec::new();
    let (result, tone) = if receipt.succeeded {
        ("succeeded", Tone::Success)
    } else {
        ("reverted", Tone::Danger)
    };
    lines.push(fact(
        "Result",
        vec![
            Span::toned(result, tone),
            Span::plain(format!(" in block {}", receipt.block_number)),
        ],
    ));
    let fee_wei = u128::from(receipt.gas_used).saturating_mul(receipt.effective_gas_price);
    lines.push(fact(
        "Fee paid",
        vec![
            Span::plain(native_amount(&fee_wei.to_string(), network)),
            Span::toned(format!("  ·  {} gas", receipt.gas_used), Tone::Muted),
        ],
    ));

    lines.push(Vec::new());
    lines.push(heading("Balance changes"));
    let activity = transfer_activity(record.execution_plan.sender, receipt);
    if activity.is_empty() {
        lines.push(vec![Span::toned(
            "  none for this wallet in the receipt Transfer logs",
            Tone::Muted,
        )]);
        return lines;
    }
    lines.extend(balance_table(&activity, metadata));
    lines
}

/// A token amount for one table cell: the exact scaled value when decimals
/// are known, the exact base units labeled as such otherwise.
fn table_amount(amount: U256, metadata: Option<&crate::approval_summary::TokenMetadata>) -> String {
    let base_units = amount.to_string();
    match metadata.and_then(|metadata| metadata.decimals) {
        Some(decimals) => format_fixed_point(&base_units, decimals),
        None => format!("{base_units} base units"),
    }
}

/// `0xa0b86991…2d883e06`: enough of an address to recognize it, sized for a
/// table cell. The explorer page linked above the table has every full value.
fn short_address(address: Address) -> String {
    let full = format!("{address:#x}");
    format!("{}…{}", &full[..10], &full[full.len() - 8..])
}

/// The wallet's net token movements as an aligned table: one row per token,
/// received amounts green, sent amounts red, columns sized to their content.
fn balance_table(activity: &[(Address, (U256, U256))], metadata: &TokenMetadataMap) -> Vec<Line> {
    let rows: Vec<(String, Option<String>, Option<String>)> = activity
        .iter()
        .map(|(token, (received, sent))| {
            let display = metadata.get(token);
            let label = match display.and_then(|display| display.symbol.as_ref()) {
                Some(symbol) => format!("{} {}", terminal_safe_line(symbol), short_address(*token)),
                None => short_address(*token),
            };
            let cell = |amount: &U256, sign: &str| {
                (!amount.is_zero()).then(|| format!("{sign}{}", table_amount(*amount, display)))
            };
            (label, cell(received, "+"), cell(sent, "-"))
        })
        .collect();

    let token_width = rows
        .iter()
        .map(|(label, ..)| display_width(label))
        .chain([display_width("Token")])
        .max()
        .unwrap_or_default();
    let received_width = rows
        .iter()
        .filter_map(|(_, received, _)| received.as_deref().map(display_width))
        .chain([display_width("Received")])
        .max()
        .unwrap_or_default();
    let sent_width = rows
        .iter()
        .filter_map(|(_, _, sent)| sent.as_deref().map(display_width))
        .chain([display_width("Sent")])
        .max()
        .unwrap_or_default();

    let pad_left = |text: &str, width: usize| {
        format!(
            "{}{text}",
            " ".repeat(width.saturating_sub(display_width(text)))
        )
    };
    let pad_right = |text: &str, width: usize| {
        format!(
            "{text}{}",
            " ".repeat(width.saturating_sub(display_width(text)))
        )
    };

    let mut lines = Vec::new();
    lines.push(vec![Span::toned(
        format!(
            "  {}  {}  {}",
            pad_right("Token", token_width),
            pad_left("Received", received_width),
            pad_left("Sent", sent_width),
        ),
        Tone::Muted,
    )]);
    for (label, received, sent) in &rows {
        let mut line = vec![Span::plain(format!(
            "  {}  ",
            pad_right(label, token_width)
        ))];
        line.push(match received {
            Some(amount) => Span::toned(pad_left(amount, received_width), Tone::Success),
            None => Span::plain(" ".repeat(received_width)),
        });
        line.push(Span::plain("  "));
        line.push(match sent {
            Some(amount) => Span::toned(pad_left(amount, sent_width), Tone::Danger),
            None => Span::plain(" ".repeat(sent_width)),
        });
        lines.push(line);
    }
    lines
}

/// What the browser is currently showing.
enum View {
    List,
    Detail(DetailView),
}

struct DetailView {
    title: String,
    lines: Vec<Line>,
    explorer: Option<String>,
    offset: usize,
}

struct App {
    rows: Vec<ListRow>,
    /// Indices into `rows` that pass the current filter, in list order.
    visible: Vec<usize>,
    table: TableState,
    filter: String,
    /// Whether keystrokes currently edit the filter instead of navigating.
    typing: bool,
    view: View,
    /// One-frame status text shown in the footer instead of the key hints.
    notice: Option<String>,
    /// Body rows the last frame had, so paging moves by what is on screen.
    viewport: usize,
}

impl App {
    fn new(rows: Vec<ListRow>) -> Self {
        let visible = (0..rows.len()).collect();
        Self {
            rows,
            visible,
            table: TableState::default().with_selected(Some(0)),
            filter: String::new(),
            typing: false,
            view: View::List,
            notice: None,
            viewport: 1,
        }
    }

    /// Re-derive the visible rows after a filter edit, keeping the selection
    /// on the same record when it survives the filter.
    fn refilter(&mut self) {
        let selected_row = self
            .table
            .selected()
            .and_then(|position| self.visible.get(position).copied());
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| matches_filter(&row.haystack, &self.filter))
            .map(|(index, _)| index)
            .collect();
        let position = selected_row
            .and_then(|row| self.visible.iter().position(|&index| index == row))
            .unwrap_or(0);
        self.table.select(if self.visible.is_empty() {
            None
        } else {
            Some(position.min(self.visible.len() - 1))
        });
    }

    fn move_selection(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let last = self.visible.len() - 1;
        let current = self.table.selected().unwrap_or(0);
        let target = current.saturating_add_signed(delta).min(last);
        self.table.select(Some(target));
    }
}

/// Interactive loop: pick a transaction, read its expanded details
/// (including live receipt lookups), return to the list.
pub async fn browse(config: &ConfigStore, records: &[PendingTransaction]) -> Result<()> {
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        return Ok(());
    }
    let networks = configured_networks(config);
    let mut app = App::new(list_rows(&networks, records));
    let mut screen = Screen::enter()?;
    loop {
        screen.terminal.draw(|frame| draw(frame, &mut app))?;
        let key = match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => key,
            // Anything else — a resize above all — just redraws against the
            // new terminal size, which is the whole resize story here.
            _ => continue,
        };
        app.notice = None;
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'd'))
        {
            return Ok(());
        }
        match &mut app.view {
            View::List => match handle_list_key(&mut app, key) {
                ListOutcome::Stay => {}
                ListOutcome::Quit => return Ok(()),
                ListOutcome::Open(index) => {
                    // Composing the detail can wait on an RPC; say so instead
                    // of freezing on the last frame.
                    app.notice = Some("Loading details…".into());
                    screen.terminal.draw(|frame| draw(frame, &mut app))?;
                    app.notice = None;
                    let record = &records[index];
                    let network = config.network_by_chain_id(&record.chain_id).ok();
                    let explorer = broadcast_hash(record).and_then(|hash| {
                        network.as_ref().and_then(|network| {
                            crate::render::explorer_transaction_url(network, hash)
                        })
                    });
                    app.view = View::Detail(DetailView {
                        title: format!("Request {}", record.request_id),
                        lines: load_detail(config, record).await,
                        explorer,
                        offset: 0,
                    });
                }
            },
            View::Detail(detail) => match handle_detail_key(detail, key, app.viewport) {
                DetailOutcome::Stay => {}
                DetailOutcome::Back => app.view = View::List,
                DetailOutcome::OpenExplorer => {
                    if let Some(url) = &detail.explorer {
                        app.notice = Some(match open_in_browser(url) {
                            Ok(()) => format!("Opened {url}"),
                            Err(error) => format!("Could not open a browser: {error:#}"),
                        });
                    } else {
                        app.notice = Some("No explorer URL for this transaction.".into());
                    }
                }
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ListOutcome {
    Stay,
    Quit,
    /// Open the record at this index into the caller's record slice.
    Open(usize),
}

fn handle_list_key(app: &mut App, key: KeyEvent) -> ListOutcome {
    if app.typing {
        match key.code {
            KeyCode::Esc => {
                app.filter.clear();
                app.typing = false;
                app.refilter();
            }
            // Enter only keeps the filter and hands the keys back to the
            // list; opening the selection takes a second, deliberate Enter.
            KeyCode::Enter => app.typing = false,
            KeyCode::Backspace => {
                app.filter.pop();
                app.refilter();
            }
            KeyCode::Char(character) => {
                app.filter.push(character);
                app.refilter();
            }
            KeyCode::Up => app.move_selection(-1),
            KeyCode::Down => app.move_selection(1),
            _ => {}
        }
        return ListOutcome::Stay;
    }
    let page = app.viewport.max(1).cast_signed();
    match key.code {
        KeyCode::Char('q') => return ListOutcome::Quit,
        KeyCode::Esc if app.filter.is_empty() => return ListOutcome::Quit,
        KeyCode::Esc => {
            app.filter.clear();
            app.refilter();
        }
        KeyCode::Enter => {
            if let Some(index) = app
                .table
                .selected()
                .and_then(|position| app.visible.get(position).copied())
            {
                return ListOutcome::Open(index);
            }
        }
        KeyCode::Char('/') => app.typing = true,
        KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
        KeyCode::PageUp => app.move_selection(-page),
        KeyCode::PageDown => app.move_selection(page),
        KeyCode::Home | KeyCode::Char('g') => app.table.select_first(),
        KeyCode::End | KeyCode::Char('G') if !app.visible.is_empty() => {
            app.table.select(Some(app.visible.len() - 1));
        }
        _ => {}
    }
    ListOutcome::Stay
}

enum DetailOutcome {
    Stay,
    Back,
    OpenExplorer,
}

fn handle_detail_key(detail: &mut DetailView, key: KeyEvent, viewport: usize) -> DetailOutcome {
    let page = viewport.max(1);
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter => return DetailOutcome::Back,
        KeyCode::Char('o') => return DetailOutcome::OpenExplorer,
        KeyCode::Up | KeyCode::Char('k') => detail.offset = detail.offset.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => detail.offset = detail.offset.saturating_add(1),
        KeyCode::PageUp | KeyCode::Char('b') => detail.offset = detail.offset.saturating_sub(page),
        KeyCode::PageDown | KeyCode::Char(' ' | 'f') => {
            detail.offset = detail.offset.saturating_add(page);
        }
        KeyCode::Home | KeyCode::Char('g') => detail.offset = 0,
        KeyCode::End | KeyCode::Char('G') => detail.offset = usize::MAX,
        _ => {}
    }
    DetailOutcome::Stay
}

/// Open `url` with the platform's default browser handler. The URL is passed
/// as a single argument to a fixed program, never through a shell.
fn open_in_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", ""]);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = std::process::Command::new("xdg-open");
    command.arg(url).spawn()?;
    Ok(())
}

fn draw(frame: &mut ratatui::Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    app.viewport = body.height.saturating_sub(1).max(1) as usize;

    match &mut app.view {
        View::List => {
            let title = if app.filter.is_empty() {
                format!("Transactions — {}", app.rows.len())
            } else {
                format!(
                    "Transactions — {} of {} match \u{201c}{}\u{201d}",
                    app.visible.len(),
                    app.rows.len(),
                    terminal_safe_line(&app.filter),
                )
            };
            frame.render_widget(
                UiLine::from(UiSpan::styled(
                    title,
                    Style::new().add_modifier(Modifier::BOLD),
                )),
                header,
            );

            if app.visible.is_empty() {
                frame.render_widget(
                    Paragraph::new(UiLine::from(UiSpan::styled(
                        "No transactions match the search.",
                        tone_style(Tone::Muted),
                    )))
                    .alignment(Alignment::Center),
                    body,
                );
            } else {
                let rows: Vec<UiRow> = app
                    .visible
                    .iter()
                    .map(|&index| {
                        let row = &app.rows[index];
                        UiRow::new(vec![
                            Cell::from(UiSpan::styled(
                                row.short_id.clone(),
                                tone_style(Tone::Muted),
                            )),
                            Cell::from(crate::render::relative_time(row.created_at)),
                            Cell::from(UiSpan::styled(row.status, tone_style(row.tone))),
                            Cell::from(row.wallet.clone()),
                            Cell::from(row.network.clone()),
                            Cell::from(UiLine::from(row.calls.clone()).alignment(Alignment::Right)),
                        ])
                    })
                    .collect();
                let table = Table::new(
                    rows,
                    [
                        Constraint::Length(8),
                        Constraint::Length(14),
                        Constraint::Length(26),
                        Constraint::Fill(1),
                        Constraint::Fill(1),
                        Constraint::Length(5),
                    ],
                )
                .header(
                    UiRow::new(vec!["Id", "Age", "Status", "Wallet", "Network", "Calls"])
                        .style(tone_style(Tone::Muted)),
                )
                .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
                .column_spacing(2);
                frame.render_stateful_widget(table, body, &mut app.table);
            }

            let hints = if app.typing {
                format!(
                    "Search: {}▏  Enter to keep · Esc to clear",
                    terminal_safe_line(&app.filter)
                )
            } else if app.filter.is_empty() {
                "↑↓ select · Enter details · / search · q quit".to_owned()
            } else {
                "↑↓ select · Enter details · / edit search · Esc clear search · q quit".to_owned()
            };
            frame.render_widget(footer_line(app.notice.as_deref(), &hints), footer);
        }
        View::Detail(detail) => {
            frame.render_widget(
                UiLine::from(UiSpan::styled(
                    detail.title.clone(),
                    Style::new().add_modifier(Modifier::BOLD),
                )),
                header,
            );
            let columns = (body.width as usize).saturating_sub(2).max(10);
            let wrapped = wrap_lines(&detail.lines, columns);
            let viewport = body.height.max(1) as usize;
            let max_offset = wrapped.len().saturating_sub(viewport);
            detail.offset = detail.offset.min(max_offset);
            let visible: Vec<UiLine> = wrapped
                .iter()
                .skip(detail.offset)
                .take(viewport)
                .map(|line| {
                    let mut spans = vec![UiSpan::raw(" ")];
                    spans.extend(line.iter().map(ui_span));
                    UiLine::from(spans)
                })
                .collect();
            frame.render_widget(Paragraph::new(visible), body);

            let position = (detail.offset * 100)
                .checked_div(max_offset)
                .map_or_else(|| "all".to_owned(), |percent| format!("{percent}%"));
            let hints = format!(
                "{position} · ↑↓ scroll · PgUp/PgDn page{} · Esc back · Ctrl+C quit",
                if detail.explorer.is_some() {
                    " · o open explorer"
                } else {
                    ""
                }
            );
            frame.render_widget(footer_line(app.notice.as_deref(), &hints), footer);
        }
    }
}

fn footer_line<'a>(notice: Option<&'a str>, hints: &'a str) -> UiLine<'a> {
    match notice {
        Some(notice) => UiLine::from(UiSpan::styled(
            terminal_safe_line(notice),
            tone_style(Tone::Info),
        )),
        None => UiLine::from(UiSpan::styled(hints.to_owned(), tone_style(Tone::Muted))),
    }
}

/// Owns the terminal takeover. Restoring on drop rather than at the end of
/// [`browse`] means an error or a panic mid-session still hands the terminal
/// back in raw-mode-off, main-screen state.
struct Screen {
    terminal: Terminal<CrosstermBackend<Stderr>>,
}

impl Screen {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        execute!(io::stderr(), EnterAlternateScreen)?;
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(io::stderr()))?,
        })
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _unused = execute!(io::stderr(), LeaveAlternateScreen);
        let _unused = terminal::disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_summary::TokenMetadata;
    use crate::rpc::ReceiptLog;

    fn record() -> PendingTransaction {
        let plan = crate::core::execution_plan::ExecutionPlan::parse(serde_json::json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "submit_condition": "always",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0xa9059cbb",
                    "value": "50000000000000000"
                }
            }]
        }))
        .unwrap();
        let now = chrono::Utc::now();
        PendingTransaction {
            request_id: uuid::Uuid::nil(),
            wallet_id: "primary".into(),
            network_name: "ethereum".into(),
            chain_id: "1".into(),
            digest: format!("{:#x}", plan.digest()),
            execution_plan: plan,
            review_digest: None,
            policy_revision: 3,
            approval_required: true,
            status: PendingStatus::AwaitingApproval,
            created_at: now - chrono::TimeDelta::minutes(7),
            expires_at: now + chrono::TimeDelta::minutes(3),
            updated_at: now - chrono::TimeDelta::minutes(7),
            approved_at: None,
            rejected_at: None,
            serialized_transaction: None,
            signed_transaction_hash: None,
            broadcast_transaction_hash: None,
            block_number: None,
        }
    }

    fn ethereum() -> NetworkConfig {
        crate::config::default_networks().remove(0)
    }

    fn text_of(lines: &[Line]) -> String {
        lines_to_text(lines, |text, _| text.to_owned())
    }

    #[test]
    fn status_tones_separate_final_pending_and_failed_states() {
        assert_eq!(status_tone(PendingStatus::Confirmed), Tone::Success);
        assert_eq!(status_tone(PendingStatus::AwaitingApproval), Tone::Warning);
        assert_eq!(status_tone(PendingStatus::Broadcast), Tone::Warning);
        for failed in [
            PendingStatus::Rejected,
            PendingStatus::Reverted,
            PendingStatus::Expired,
            PendingStatus::Cancelled,
        ] {
            assert_eq!(status_tone(failed), Tone::Danger);
        }
    }

    #[test]
    fn list_rows_name_the_chain_and_search_the_whole_record() {
        let networks = std::iter::once(("1".to_owned(), ethereum())).collect();
        let mut record = record();
        record.broadcast_transaction_hash = Some(format!("0x{}", "ab".repeat(32)));
        let rows = list_rows(&networks, std::slice::from_ref(&record));
        assert_eq!(rows[0].network, "ethereum");
        assert_eq!(rows[0].calls, "1");
        // The haystack finds what the truncated row never showed: the full
        // request ID, the hash, and the counterparty address.
        assert!(matches_filter(
            &rows[0].haystack,
            &uuid::Uuid::nil().to_string()
        ));
        assert!(matches_filter(
            &rows[0].haystack,
            &format!("0x{}", "AB".repeat(32))
        ));
        assert!(matches_filter(
            &rows[0].haystack,
            "0x2222222222222222222222222222222222222222"
        ));
        // Multiple terms all have to hit, in any order.
        assert!(matches_filter(&rows[0].haystack, "awaiting primary"));
        assert!(!matches_filter(&rows[0].haystack, "awaiting other-wallet"));
    }

    #[test]
    fn an_unconfigured_chain_falls_back_to_the_stored_name_then_the_id() {
        let networks = BTreeMap::new();
        let mut record = record();
        record.chain_id = "424242".into();
        let rows = list_rows(&networks, std::slice::from_ref(&record));
        assert_eq!(rows[0].network, "ethereum", "the stored name still applies");
        record.network_name = String::new();
        let rows = list_rows(&networks, std::slice::from_ref(&record));
        assert_eq!(rows[0].network, "chain 424242");
    }

    #[test]
    fn wrapping_respects_width_preserves_tones_and_loses_no_hash_digits() {
        let hash = format!("0x{}", "ab".repeat(32));
        let line: Line = vec![Span::toned("Hash        ", Tone::Muted), Span::plain(&hash)];
        let wrapped = wrap_line(&line, 30);
        assert!(wrapped.len() > 1, "a 66-character hash cannot fit one line");
        for piece in &wrapped {
            let width: usize = piece.iter().map(|span| display_width(&span.text)).sum();
            assert!(width <= 30, "{piece:?} fits the wrap width");
        }
        // Every hash character survives the break, in order: the value can
        // be read (and checked) across lines rather than being clipped.
        let rejoined: String = wrapped
            .iter()
            .flat_map(|piece| piece.iter())
            .map(|span| span.text.as_str())
            .collect::<String>()
            .replace(' ', "");
        assert!(rejoined.contains(&hash));
        // The label kept its tone after reassembly.
        assert_eq!(wrapped[0][0].tone, Some(Tone::Muted));
    }

    #[test]
    fn wrapping_prefers_a_space_and_keeps_blank_lines() {
        let line: Line = vec![Span::plain("alpha beta gamma")];
        let wrapped = wrap_line(&line, 11);
        assert_eq!(text_of(&wrapped), "alpha beta\ngamma");
        assert_eq!(wrap_line(&Vec::new(), 10), vec![Vec::new()]);
    }

    #[test]
    fn detail_renders_offline_records_with_named_facts() {
        let record = record();
        let lines = detail_lines(&record, Some(&ethereum()), None);
        let text = text_of(&lines);
        assert!(text.contains("awaiting approval"));
        assert!(text.contains(&uuid::Uuid::nil().to_string()));
        assert!(text.contains("ethereum"));
        assert!(text.contains("(chain 1)"));
        assert!(text.contains("Expires"));
        assert!(text.contains("revision 3 · approval required"));
        assert!(text.contains("to 0x2222222222222222222222222222222222222222"));
        // The call value reads in the network currency with the exact wei.
        assert!(text.contains("0.05 ETH (50000000000000000 wei)"));
        assert!(text.contains("selector 0xa9059cbb"));
        // Nothing broadcast yet: no execution or receipt sections.
        assert!(!text.contains("Explorer"));
        assert!(!text.contains("Receipt"));
    }

    #[test]
    fn a_signed_record_links_to_the_configured_explorer() {
        let mut record = record();
        record.status = PendingStatus::Signed;
        record.signed_transaction_hash = Some(format!("0x{}", "aa".repeat(32)));
        let lines = detail_lines(&record, Some(&ethereum()), None);
        let text = text_of(&lines);
        assert!(text.contains(&format!("https://etherscan.io/tx/0x{}", "aa".repeat(32))));
    }

    #[test]
    fn balance_changes_render_as_an_aligned_signed_table() {
        let token = Address::from([0xa0; 20]);
        let other = Address::from([0xb1; 20]);
        let wallet = Address::from([0x11; 20]);
        let transfer = |from: Address, to: Address, token: Address, amount: u64| ReceiptLog {
            address: token,
            topics: vec![
                TRANSFER_EVENT,
                B256::left_padding_from(from.as_slice()),
                B256::left_padding_from(to.as_slice()),
            ],
            data: U256::from(amount).to_be_bytes_vec(),
        };
        let receipt = ReceiptDetails {
            succeeded: true,
            block_number: 123,
            gas_used: 21_000,
            effective_gas_price: 1_000_000_000,
            logs: vec![
                transfer(other, wallet, token, 1_500_000),
                transfer(wallet, other, other, 25),
            ],
        };
        let metadata: TokenMetadataMap = std::iter::once((
            token,
            TokenMetadata {
                symbol: Some("USDC".into()),
                decimals: Some(6),
            },
        ))
        .collect();

        let mut record = record();
        record.status = PendingStatus::Confirmed;
        record.broadcast_transaction_hash = Some(format!("0x{}", "aa".repeat(32)));
        let lines = detail_lines(
            &record,
            Some(&ethereum()),
            Some(&ReceiptSection::Ready { receipt, metadata }),
        );
        let text = text_of(&lines);
        assert!(text.contains("succeeded in block 123"));
        assert!(text.contains("0.000021 ETH (21000000000000 wei)"));
        assert!(text.contains("Balance changes"));
        // The known token scales exactly and is labeled by symbol; the
        // unknown one stays in base units. Received and sent are signed.
        assert!(text.contains("+1.5"));
        assert!(text.contains("-25 base units"));
        assert!(text.contains("USDC 0xa0a0a0a0…a0a0a0a0"));
        // The Received column is right-aligned: the header's edge and the
        // amount's edge land on the same display column. Edges are measured
        // in display columns, not bytes — the `…` in a shortened address is
        // three bytes wide but occupies one column.
        let edge = |line: &str, needle: &str| {
            let end = line.find(needle).unwrap() + needle.len();
            display_width(&line[..end])
        };
        let header = text.lines().find(|line| line.contains("Received")).unwrap();
        let usdc = text.lines().find(|line| line.contains("+1.5")).unwrap();
        assert_eq!(edge(header, "Received"), edge(usdc, "+1.5"));
    }

    #[test]
    fn native_amounts_scale_by_the_network_currency() {
        let network = ethereum();
        assert_eq!(
            native_amount("50000000000000000", Some(&network)),
            "0.05 ETH (50000000000000000 wei)"
        );
        assert_eq!(native_amount("0", Some(&network)), "0 ETH");
        assert_eq!(native_amount("7", None), "7 wei");
        assert_eq!(
            native_amount("not-a-number", Some(&network)),
            "value not-a-number"
        );
    }

    #[test]
    fn filtering_keeps_the_selection_on_the_same_record_when_it_survives() {
        let networks = BTreeMap::new();
        let mut second = record();
        second.request_id = uuid::Uuid::from_u128(7);
        second.wallet_id = "trading".into();
        let records = vec![record(), second];
        let mut app = App::new(list_rows(&networks, &records));
        app.table.select(Some(1));
        app.filter = "trading".into();
        app.refilter();
        assert_eq!(app.visible, vec![1], "only the matching record remains");
        assert_eq!(app.table.selected(), Some(0), "still on the trading record");
        // Clearing the filter restores the full list, selection intact.
        app.filter.clear();
        app.refilter();
        assert_eq!(app.visible, vec![0, 1]);
        assert_eq!(app.table.selected(), Some(1));
        // A filter matching nothing leaves nothing selected rather than a
        // phantom cursor on an empty table.
        app.filter = "no-such-thing".into();
        app.refilter();
        assert_eq!(app.table.selected(), None);
    }

    #[test]
    fn list_keys_navigate_filter_and_quit() {
        let networks = BTreeMap::new();
        let records = vec![record(), record(), record()];
        let mut app = App::new(list_rows(&networks, &records));
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        assert_eq!(
            handle_list_key(&mut app, press(KeyCode::Down)),
            ListOutcome::Stay
        );
        assert_eq!(app.table.selected(), Some(1));
        handle_list_key(&mut app, press(KeyCode::End));
        assert_eq!(app.table.selected(), Some(2));
        handle_list_key(&mut app, press(KeyCode::Home));
        assert_eq!(app.table.selected(), Some(0));

        // '/' starts a search; typed characters land in the filter.
        handle_list_key(&mut app, press(KeyCode::Char('/')));
        assert!(app.typing);
        handle_list_key(&mut app, press(KeyCode::Char('p')));
        assert_eq!(app.filter, "p");
        // The Enter that confirms the filter must not also open the
        // selection; only the next Enter, back in the list, does that.
        assert_eq!(
            handle_list_key(&mut app, press(KeyCode::Enter)),
            ListOutcome::Stay
        );
        assert!(
            !app.typing,
            "Enter keeps the filter and returns to the list"
        );
        assert_eq!(
            handle_list_key(&mut app, press(KeyCode::Enter)),
            ListOutcome::Open(0)
        );
        // Esc first clears the filter, and only then quits.
        assert_eq!(
            handle_list_key(&mut app, press(KeyCode::Esc)),
            ListOutcome::Stay
        );
        assert!(app.filter.is_empty());
        assert_eq!(
            handle_list_key(&mut app, press(KeyCode::Esc)),
            ListOutcome::Quit
        );
        assert_eq!(
            handle_list_key(&mut app, press(KeyCode::Char('q'))),
            ListOutcome::Quit
        );
    }

    #[test]
    fn detail_keys_scroll_and_leave() {
        let mut detail = DetailView {
            title: "Request".into(),
            lines: Vec::new(),
            explorer: None,
            offset: 0,
        };
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(matches!(
            handle_detail_key(&mut detail, press(KeyCode::Down), 10),
            DetailOutcome::Stay
        ));
        assert_eq!(detail.offset, 1);
        handle_detail_key(&mut detail, press(KeyCode::PageDown), 10);
        assert_eq!(detail.offset, 11);
        handle_detail_key(&mut detail, press(KeyCode::Home), 10);
        assert_eq!(detail.offset, 0);
        assert!(matches!(
            handle_detail_key(&mut detail, press(KeyCode::Esc), 10),
            DetailOutcome::Back
        ));
        assert!(matches!(
            handle_detail_key(&mut detail, press(KeyCode::Char('o')), 10),
            DetailOutcome::OpenExplorer
        ));
    }

    #[test]
    fn stored_text_cannot_draw_chrome() {
        // A wallet ID with an embedded escape sequence reaches the screen
        // with the control characters flattened to spaces.
        let span = Span::plain("evil\u{1b}[2Jwallet");
        assert!(!span.text.contains('\u{1b}'));
        let toned = Span::toned("bad\nvalue", Tone::Info);
        assert!(!toned.text.contains('\n'));
    }
}
