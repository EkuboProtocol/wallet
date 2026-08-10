//! Full-screen transaction history browser.
//!
//! The transaction list used to be a scrolling select prompt: it sized its page
//! once when the prompt opened, so a terminal resized (or simply short) mid
//! prompt scrolled the whole screen instead of the cursor, and its
//! type-to-filter matched only the visible row text — which is truncated to
//! the terminal width, so the values worth searching for (the full request
//! ID, a transaction hash) were exactly the ones it could not see.
//!
//! This browser is built on [`crate::fullscreen`]: a [`SearchableTable`]
//! list whose network column names the chain and whose `/` search matches
//! the record itself (full request ID, hashes, wallet, network, status,
//! addresses), and an expanded view that is a styled document — status in
//! its lifecycle color, balance changes in an aligned table, the explorer
//! URL one keystroke from a browser — instead of a wall of `label: value`
//! lines.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal};
use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::{Address, B256, U256, b256};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use num_bigint::{BigInt, BigUint, Sign};
use ratatui::{layout::Constraint, text::Line as UiLine, widgets::Paragraph};

use crate::{
    approval_summary::{TokenMetadataMap, format_fixed_point},
    config::{ConfigStore, NetworkConfig},
    fullscreen::{
        Line, Screen, SearchableTable, Span, TableColumn, TableEvent, TableRow, chrome,
        footer_line, is_interrupt, title_line, ui_span, wrap_lines,
    },
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
        PendingStatus::Cancelled => "cancelled",
        PendingStatus::Replaced => "replaced on chain",
        PendingStatus::Cancelling => "cancelling, awaiting receipt",
    }
}

/// The semantic color of a lifecycle state: green once value moved as
/// approved, yellow while something is still pending, red for every path
/// where nothing will move.
#[must_use]
pub fn status_tone(status: PendingStatus) -> Tone {
    match status {
        PendingStatus::Confirmed | PendingStatus::Signed => Tone::Success,
        PendingStatus::AwaitingApproval
        | PendingStatus::Submitting
        | PendingStatus::Broadcast
        | PendingStatus::Cancelling => Tone::Warning,
        PendingStatus::Rejected
        | PendingStatus::Reverted
        | PendingStatus::Cancelled
        | PendingStatus::Replaced => Tone::Danger,
    }
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

fn list_columns() -> Vec<TableColumn> {
    vec![
        TableColumn::new("Id", Constraint::Length(8)),
        TableColumn::new("Age", Constraint::Length(14)),
        TableColumn::new("Status", Constraint::Length(26)),
        TableColumn::new("Wallet", Constraint::Fill(1)),
        TableColumn::new("Network", Constraint::Fill(1)),
        TableColumn::new("Calls", Constraint::Length(5)).right_aligned(),
    ]
}

/// The ages in the rows are formatted at build time, so the caller rebuilds
/// the rows whenever it re-enters the list rather than letting them go stale.
fn list_rows(
    networks: &BTreeMap<String, NetworkConfig>,
    records: &[PendingTransaction],
) -> Vec<TableRow> {
    records
        .iter()
        .map(|record| {
            let network = network_label(networks, record);
            let steps = &record.execution_plan.ordered_steps;
            let cells = vec![
                Span::toned(short_request_id(record.request_id), Tone::Muted),
                Span::plain(crate::render::relative_time(record.created_at)),
                Span::toned(status_label(record.status), status_tone(record.status)),
                Span::plain(&record.wallet_id),
                Span::plain(&network),
                Span::plain(steps.len().to_string()),
            ];
            let counterparties = steps
                .iter()
                .map(|step| format!("{:#x}", step.transaction.to))
                .collect::<Vec<_>>()
                .join(" ");
            TableRow::new(
                cells,
                &[
                    &record.request_id.to_string(),
                    &record.wallet_id,
                    &network,
                    &record.chain_id,
                    status_label(record.status),
                    record.signed_transaction_hash.as_deref().unwrap_or(""),
                    record.broadcast_transaction_hash.as_deref().unwrap_or(""),
                    &format!("{:#x}", record.execution_plan.sender),
                    &counterparties,
                ],
            )
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

/// What one receipt lookup produced, resolved before the detail document is
/// composed so composition itself stays pure and testable.
enum ReceiptSection {
    Ready {
        receipt: ReceiptDetails,
        metadata: TokenMetadataMap,
        /// The wallet's net native change across the receipt's block —
        /// internal transfers included, gas included — or `None` when the
        /// RPC could not serve the parent block's state.
        native_delta: Option<BigInt>,
    },
    NotYetAvailable,
    Failed(String),
}

/// Load everything the expanded view needs. Chain lookups are best-effort
/// display work: an unreachable RPC degrades to the stored data.
pub async fn load_detail(config: &ConfigStore, record: &PendingTransaction) -> Vec<Line> {
    let network = config.network_by_chain_id(&record.chain_id).ok();
    // A receipt is history, but it is read on the same screen and by the same
    // eye as a pending review, so it names tokens by the same rule: only the
    // owner's confirmed database, never the token contract.
    let tokens = crate::token_store::TokenStore::production(config.data_dir()).ok();
    let receipt = load_receipt(network.as_ref(), tokens.as_ref(), record).await;
    detail_lines(record, network.as_ref(), receipt.as_ref())
}

/// Everything one detail view may spend looking for a receipt.
///
/// This lookup runs inside the browser's key loop, so the screen is frozen for
/// its whole duration — and the cancel action is reachable only from the
/// detail view, which puts the freeze directly in front of the recovery the
/// owner opened it for. A `Cancelling` record has up to
/// `MAX_CANCELLATION_ATTEMPTS` hashes plus the original, each previously
/// costing its own RPC timeout, so an unreachable endpoint held the terminal
/// for over two minutes. One budget across all of them instead: past it the
/// detail renders from stored data, which is what it does for an unconfigured
/// network anyway.
const RECEIPT_DETAIL_BUDGET: Duration = Duration::from_secs(15);

async fn load_receipt(
    network: Option<&NetworkConfig>,
    tokens: Option<&crate::token_store::TokenStore>,
    record: &PendingTransaction,
) -> Option<ReceiptSection> {
    let network = network?;
    let hashes = receipt_candidate_hashes(record);
    if hashes.is_empty() {
        return None;
    }
    let lookup = async {
        let mut section = ReceiptSection::NotYetAvailable;
        for hash in hashes {
            match transaction_receipt_details(network, hash).await {
                Ok(Some(receipt)) => {
                    let moved: Vec<Address> =
                        transfer_activity(record.execution_plan.sender, &receipt)
                            .into_iter()
                            .map(|(token, _)| token)
                            .collect();
                    let metadata = tokens
                        .and_then(|tokens| tokens.display_metadata(network.chain_id, &moved).ok())
                        .unwrap_or_default();
                    let native_delta =
                        native_delta(network, record.execution_plan.sender, receipt.block_number)
                            .await;
                    return ReceiptSection::Ready {
                        receipt,
                        metadata,
                        native_delta,
                    };
                }
                Ok(None) => {}
                // A transport failure against one hash will fail for the rest
                // too, so stop rather than paying the timeout once per
                // candidate to learn the same thing eight more times.
                Err(error) => return ReceiptSection::Failed(format!("{error:#}")),
            }
            section = ReceiptSection::NotYetAvailable;
        }
        section
    };
    Some(
        tokio::time::timeout(RECEIPT_DETAIL_BUDGET, lookup)
            .await
            .unwrap_or_else(|_| {
                ReceiptSection::Failed("receipt lookup timed out; showing stored details".into())
            }),
    )
}

/// The transaction hashes that may hold this record's receipt, most likely
/// winner first. A cancelling record races its own cancellations against the
/// original envelope; a cancelled one mined some cancellation attempt.
fn receipt_candidate_hashes(record: &PendingTransaction) -> Vec<&str> {
    match record.status {
        PendingStatus::Broadcast | PendingStatus::Confirmed | PendingStatus::Reverted => {
            broadcast_hash(record).into_iter().collect()
        }
        PendingStatus::Cancelling => record
            .cancel_transaction_hashes
            .iter()
            .rev()
            .map(String::as_str)
            .chain(broadcast_hash(record))
            .collect(),
        PendingStatus::Cancelled => record
            .cancel_transaction_hashes
            .iter()
            .rev()
            .map(String::as_str)
            .collect(),
        _ => Vec::new(),
    }
}

fn broadcast_hash(record: &PendingTransaction) -> Option<&str> {
    record
        .broadcast_transaction_hash
        .as_deref()
        .or(record.signed_transaction_hash.as_deref())
}

/// Best-effort net native change for the wallet across the receipt's block:
/// the balance at the block minus the balance at its parent. This is the
/// only view standard RPC offers of native value received through internal
/// transactions, which emit no log a receipt could carry. It spans the whole
/// block and includes gas, and it is display-only, so an RPC that cannot
/// serve the parent state degrades to `None` rather than an error.
async fn native_delta(
    network: &NetworkConfig,
    wallet: Address,
    block_number: u64,
) -> Option<BigInt> {
    let (before, after) = crate::rpc::native_balances_around_block(network, wallet, block_number)
        .await
        .ok()?;
    let signed = |value: U256| BigInt::from_bytes_be(Sign::Plus, &value.to_be_bytes::<32>());
    Some(signed(after) - signed(before))
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
            ReceiptSection::Ready {
                receipt,
                metadata,
                native_delta,
            } => {
                lines.extend(receipt_detail_lines(
                    record,
                    network,
                    receipt,
                    metadata,
                    native_delta.as_ref(),
                ));
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
    native_delta: Option<&BigInt>,
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
    let mut rows = token_rows(&activity, metadata);
    let native_row = native_delta
        .filter(|delta| delta.sign() != Sign::NoSign)
        .map(|delta| native_balance_row(delta, network));
    if let Some(row) = native_row.clone() {
        rows.insert(0, row);
    }
    if rows.is_empty() {
        lines.push(vec![Span::toned(
            "  none for this wallet in the receipt Transfer logs",
            Tone::Muted,
        )]);
    } else {
        lines.extend(balance_table(&rows));
    }
    // The native figure needs its provenance stated: it is a balance diff
    // across the whole block, not a decoded event, so it includes the gas fee
    // shown above and anything else the block did to this wallet.
    if native_row.is_some() {
        lines.push(vec![Span::toned(
            "  native is the net change across the block, gas fee included",
            Tone::Muted,
        )]);
    } else if native_delta.is_none() {
        lines.push(vec![Span::toned(
            "  native change unavailable: the RPC does not serve the parent block's state",
            Tone::Muted,
        )]);
    }
    lines
}

/// The native delta as one balance-table row, in the Received or Sent column
/// by its sign, scaled by the network currency when it is known.
fn native_balance_row(delta: &BigInt, network: Option<&NetworkConfig>) -> BalanceRow {
    let currency = network.and_then(|network| network.native_currency.as_ref());
    let magnitude = delta.magnitude().to_string();
    let (label, amount) = match currency {
        Some(currency) => (
            format!("{} (native)", terminal_safe_line(&currency.symbol)),
            format_fixed_point(&magnitude, currency.decimals),
        ),
        None => ("Native".to_owned(), format!("{magnitude} wei")),
    };
    if delta.sign() == Sign::Minus {
        (label, None, Some(format!("-{amount}")))
    } else {
        (label, Some(format!("+{amount}")), None)
    }
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
    crate::render::short_hex(&format!("{address:#x}"))
}

/// One row of the balance table: an asset label, and what the wallet
/// received and sent of it, already formatted and signed.
type BalanceRow = (String, Option<String>, Option<String>);

/// The wallet's net token movements from the receipt Transfer logs, as
/// formatted rows.
fn token_rows(
    activity: &[(Address, (U256, U256))],
    metadata: &TokenMetadataMap,
) -> Vec<BalanceRow> {
    activity
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
        .collect()
}

/// Balance rows as an aligned table: received amounts green, sent amounts
/// red, columns sized to their content.
fn balance_table(rows: &[BalanceRow]) -> Vec<Line> {
    use crate::fullscreen::display_width;
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
    for (label, received, sent) in rows {
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
    /// Position of this record in the browsed listing, so actions that
    /// mutate the record can refresh the row they came from.
    index: usize,
    /// Whether the next `c` press broadcasts the cancellation: attempting to
    /// cancel spends gas, so a single accidental keypress must never do it.
    confirm_cancel: bool,
}

struct App {
    list: SearchableTable,
    view: View,
    /// One-frame status text shown in the footer instead of the key hints.
    notice: Option<String>,
    /// Body rows the last frame had, so detail paging moves by what is on
    /// screen.
    viewport: usize,
}

/// Compose a fresh detail view for one record.
async fn detail_view(
    config: &ConfigStore,
    record: &PendingTransaction,
    index: usize,
) -> DetailView {
    let network = config.network_by_chain_id(&record.chain_id).ok();
    let explorer = broadcast_hash(record).and_then(|hash| {
        network
            .as_ref()
            .and_then(|network| crate::render::explorer_transaction_url(network, hash))
    });
    DetailView {
        title: format!("Request {}", record.request_id),
        lines: load_detail(config, record).await,
        explorer,
        offset: 0,
        index,
        confirm_cancel: false,
    }
}

/// Interactive loop: pick a transaction, read its expanded details
/// (including live receipt lookups), return to the list. From the detail
/// view, `c` (pressed twice) attempts an on-chain cancellation of an
/// in-flight transaction.
pub async fn browse(
    config: &ConfigStore,
    pending: &std::sync::Mutex<crate::pending::PendingStore>,
    mut records: Vec<PendingTransaction>,
) -> Result<()> {
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        return Ok(());
    }
    let networks = configured_networks(config);
    let mut app = App {
        list: SearchableTable::new(
            "Transactions",
            list_columns(),
            list_rows(&networks, &records),
        ),
        view: View::List,
        notice: None,
        viewport: 1,
    };
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
        if is_interrupt(key) {
            return Ok(());
        }
        match &mut app.view {
            View::List => match app.list.handle_key(key) {
                TableEvent::Stay => {}
                TableEvent::Quit => return Ok(()),
                TableEvent::Picked(index) => {
                    // Composing the detail can wait on an RPC; say so instead
                    // of freezing on the last frame.
                    app.notice = Some("Loading details…".into());
                    screen.terminal.draw(|frame| draw(frame, &mut app))?;
                    app.notice = None;
                    app.view = View::Detail(detail_view(config, &records[index], index).await);
                }
            },
            View::Detail(detail) => match handle_detail_key(detail, key, app.viewport) {
                DetailOutcome::Stay => {}
                DetailOutcome::Back => {
                    // The relative ages in the rows were formatted when the
                    // list was built; refresh them on the way back to it.
                    app.list.set_rows(list_rows(&networks, &records));
                    app.view = View::List;
                }
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
                DetailOutcome::RequestCancel => {
                    let record = &records[detail.index];
                    if cancel_eligible(record.status) {
                        detail.confirm_cancel = true;
                        app.notice = Some(
                            "Press c again to broadcast a cancellation (spends gas); any other key aborts."
                                .into(),
                        );
                    } else {
                        app.notice = Some("Nothing to cancel for this transaction.".into());
                    }
                }
                DetailOutcome::ConfirmCancel => {
                    let index = detail.index;
                    detail.confirm_cancel = false;
                    app.notice = Some("Broadcasting cancellation…".into());
                    screen.terminal.draw(|frame| draw(frame, &mut app))?;
                    let outcome = cancel_record(config, pending, records[index].clone()).await;
                    app.notice = Some(match outcome {
                        Ok((updated, notice)) => {
                            records[index] = updated;
                            app.view =
                                View::Detail(detail_view(config, &records[index], index).await);
                            notice
                        }
                        Err(error) => format!("Cancellation failed: {error:#}"),
                    });
                }
            },
        }
    }
}

const fn cancel_eligible(status: PendingStatus) -> bool {
    matches!(status, PendingStatus::Broadcast | PendingStatus::Cancelling)
}

/// Attempt the on-chain cancellation of one record and describe the outcome
/// in a footer-sized sentence.
async fn cancel_record(
    config: &ConfigStore,
    pending: &std::sync::Mutex<crate::pending::PendingStore>,
    record: PendingTransaction,
) -> Result<(PendingTransaction, String)> {
    // Cancelling signs, so it takes the same gate as every other signing path.
    crate::legal::require_current_acceptance(config.data_dir())?;
    let wallet = config.wallet(&record.wallet_id)?;
    let network = config.network_by_chain_id(&record.chain_id)?;
    let (updated, broadcast) = crate::reconcile::attempt_cancellation(
        pending,
        config,
        &wallet,
        &network,
        record,
        &crate::custody::OsKeyStore,
    )
    .await?;
    let notice = match updated.status {
        PendingStatus::Cancelled => format!(
            "Cancellation mined in block {}.",
            updated.block_number.as_deref().unwrap_or("unknown")
        ),
        PendingStatus::Cancelling => format!(
            "Cancellation {} broadcast; it races the original at the same nonce.",
            broadcast.transaction_hash
        ),
        other => format!(
            "The chain settled this transaction first: {}.",
            status_label(other)
        ),
    };
    Ok((updated, notice))
}

enum DetailOutcome {
    Stay,
    Back,
    OpenExplorer,
    /// First `c`: ask for confirmation before spending gas.
    RequestCancel,
    /// Second consecutive `c`: broadcast the cancellation.
    ConfirmCancel,
}

fn handle_detail_key(detail: &mut DetailView, key: KeyEvent, viewport: usize) -> DetailOutcome {
    let page = viewport.max(1);
    if key.code == KeyCode::Char('c') {
        return if detail.confirm_cancel {
            DetailOutcome::ConfirmCancel
        } else {
            DetailOutcome::RequestCancel
        };
    }
    // Any key other than the second `c` withdraws the pending confirmation.
    detail.confirm_cancel = false;
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
///
/// That sentence was not true on Windows. The launcher was `cmd /C start ""`,
/// and `cmd.exe` reparses its command line for `&`, `|`, `^` and friends after
/// Rust has finished quoting arguments — so a URL was command syntax, not
/// data. The base of this URL comes from a network profile an MCP caller can
/// propose, and `validate_network` checked only that its scheme was http or
/// https, so an accepted profile could run commands as the wallet's user the
/// first time the owner pressed `o` on a transaction.
///
/// `rundll32 url.dll,FileProtocolHandler` is the same fixed-program, one
/// argument shape the other two platforms already had: it hands the string to
/// the registered protocol handler without a command interpreter in between.
fn open_in_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = std::process::Command::new("xdg-open");
    command.arg(url).spawn()?;
    Ok(())
}

fn draw(frame: &mut ratatui::Frame, app: &mut App) {
    let (header, body, footer) = chrome(frame.area());
    match &mut app.view {
        View::List => {
            frame.render_widget(title_line(&app.list.title()), header);
            app.list.draw(frame, body);
            app.viewport = app.list.viewport();
            frame.render_widget(
                footer_line(app.notice.as_deref(), &app.list.footer_hints("details")),
                footer,
            );
        }
        View::Detail(detail) => {
            frame.render_widget(title_line(&detail.title), header);
            let columns = (body.width as usize).saturating_sub(2).max(10);
            let wrapped = wrap_lines(&detail.lines, columns);
            let viewport = body.height.max(1) as usize;
            app.viewport = viewport;
            let max_offset = wrapped.len().saturating_sub(viewport);
            detail.offset = detail.offset.min(max_offset);
            let visible: Vec<UiLine> = wrapped
                .iter()
                .skip(detail.offset)
                .take(viewport)
                .map(|line| {
                    let mut spans = vec![ratatui::text::Span::raw(" ")];
                    spans.extend(line.iter().map(ui_span));
                    UiLine::from(spans)
                })
                .collect();
            frame.render_widget(Paragraph::new(visible), body);

            let position = (detail.offset * 100)
                .checked_div(max_offset)
                .map_or_else(|| "all".to_owned(), |percent| format!("{percent}%"));
            let hints = format!(
                "{position} · ↑↓ scroll · PgUp/PgDn page{} · c cancel · Esc back · Ctrl+C quit",
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

#[cfg(test)]
#[path = "tx_browser_test.rs"]
mod tests;
