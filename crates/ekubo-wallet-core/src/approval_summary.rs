//! Human-readable interpretation of an execution plan for native review.
//!
//! Every interpretation here is supplemental. The review digest binds the exact
//! ordered calldata; a reviewer must still verify targets, selectors, and
//! values. Decoding is deterministic and local.
//!
//! Token names never come from the token contract. `symbol()` is a string the
//! token's own author chooses, so any address can answer `"USDC"`; a reviewer
//! shown that answer would read a label the attacker wrote. Display metadata is
//! therefore drawn only from the local token database, whose rows come from
//! token lists the owner confirmed. A token absent from it is rendered by
//! address alone and its amounts stay in base units: an unnamed token is a
//! reviewable inconvenience, whereas a wrongly named one is a successful
//! forgery.

use crate::{
    config::{NativeCurrency, NetworkConfig},
    core::execution_plan::ExecutionStep,
    simulation::SimulationResult,
};
use alloy::{
    dyn_abi::{DynSolType, DynSolValue},
    primitives::{Address, Bytes, U256},
};
use num_bigint::{BigInt, Sign};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

/// A nested `multicall` is summarized, not expanded without limit.
const MAX_DISPLAYED_NESTED_CALLS: usize = 16;

const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const TRANSFER_FROM_SELECTOR: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const SET_APPROVAL_FOR_ALL_SELECTOR: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65];
const MULTICALL_SELECTOR: [u8; 4] = [0xac, 0x96, 0x50, 0xd8];

/// Display metadata for one token, drawn from the owner-confirmed token
/// database. Both fields stay optional because a row may omit either, and a
/// token with no row at all must render as raw base units.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenMetadata {
    pub symbol: Option<String>,
    pub decimals: Option<u8>,
}

/// Address-keyed display metadata for the tokens named by one plan.
pub type TokenMetadataMap = BTreeMap<Address, TokenMetadata>;

/// A standard token or batching call recognized for display purposes only.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StandardCall {
    Approve {
        spender: Address,
        amount: U256,
    },
    Transfer {
        to: Address,
        amount: U256,
    },
    TransferFrom {
        from: Address,
        to: Address,
        amount: U256,
    },
    SetApprovalForAll {
        operator: Address,
        approved: bool,
    },
    Multicall {
        calls: Vec<Bytes>,
    },
}

/// One decoded step rendered for a human reviewer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepInterpretation {
    pub step: u32,
    /// Present when the calldata matched a vendored ERC-7730 descriptor or a
    /// recognized standard call.
    pub description: Option<String>,
    /// Labeled field lines from a matching ERC-7730 descriptor.
    pub details: Vec<String>,
    pub warnings: Vec<String>,
}

/// Collect the token contracts a plan names through standard token calldata
/// or through the token references of a matching ERC-7730 descriptor.
///
/// The caller resolves these against the token database. Collection contacts
/// no network: which addresses a plan names is decided by its calldata alone.
///
/// A `multicall(bytes[])` wrapper's nested calls are not unwrapped looking
/// for a token target: see `standard_call_warnings`'s doc comment for why a
/// multicall's contents are treated as unverified rather than individually
/// inspected.
#[must_use]
pub async fn plan_token_targets(steps: &[ExecutionStep]) -> Vec<Address> {
    let mut targets = BTreeSet::new();
    for step in steps {
        if matches!(
            decode_standard_call(&step.transaction.data),
            Some(
                StandardCall::Approve { .. }
                    | StandardCall::Transfer { .. }
                    | StandardCall::TransferFrom { .. }
            )
        ) {
            targets.insert(step.transaction.to);
        }
        if let Ok(chain_id) = step.transaction.chain_id.as_str().parse::<u64>() {
            targets.extend(
                crate::clear_signing::token_references(
                    chain_id,
                    crate::clear_signing::CallEnvelope {
                        from: step.transaction.from,
                        to: step.transaction.to,
                    },
                    &step.transaction.data,
                )
                .await,
            );
        }
    }
    targets.into_iter().collect()
}

/// Interpret every step of an execution plan without contacting the network.
#[must_use]
pub async fn interpret_steps(
    steps: &[ExecutionStep],
    metadata: &TokenMetadataMap,
) -> Vec<StepInterpretation> {
    let mut interpretations = Vec::with_capacity(steps.len());
    for step in steps {
        interpretations.push(interpret_step(step, metadata).await);
    }
    interpretations
}

/// The step's native value as a U256; display-only, zero on parse failure.
fn step_value(step: &ExecutionStep) -> alloy::primitives::U256 {
    step.transaction
        .value
        .as_str()
        .parse::<alloy::primitives::U256>()
        .unwrap_or_default()
}

async fn interpret_step(step: &ExecutionStep, metadata: &TokenMetadataMap) -> StepInterpretation {
    // A vendored ERC-7730 descriptor is the most specific reading available:
    // it matches on exact chain, address, and selector, and was reviewed when
    // the snapshot was committed. Standard token decoding remains the
    // fallback for everything else.
    let token = step.transaction.to;
    let display = metadata.get(&token).cloned().unwrap_or_default();
    let standard = decode_standard_call(&step.transaction.data);
    // Computed before the descriptor is consulted, and carried into whichever
    // reading is shown. A descriptor changes how a call reads, never what it
    // does, so a token having one must not be the reason its allowance ceiling
    // goes unmentioned — and the tokens most likely to have a vendored
    // descriptor are exactly the ones worth approving carefully.
    let warnings = standard_call_warnings(step.step, token, &display, standard.as_ref());

    if let Ok(chain_id) = step.transaction.chain_id.as_str().parse::<u64>()
        && let Some(reading) = crate::clear_signing::interpret(
            chain_id,
            crate::clear_signing::CallEnvelope {
                from: step.transaction.from,
                to: step.transaction.to,
            },
            &step.transaction.data,
            step_value(step),
            metadata,
        )
        .await
    {
        return StepInterpretation {
            step: step.step,
            description: Some(reading.intent),
            details: reading.fields,
            warnings,
        };
    }
    let description = match standard {
        Some(StandardCall::Approve { spender, amount }) => {
            if amount == U256::ZERO {
                Some(format!(
                    "revoke {} allowance for spender {spender:#x}",
                    token_label(token, &display)
                ))
            } else {
                Some(format!(
                    "approve spender {spender:#x} for {}",
                    format_token_amount(amount, token, &display)
                ))
            }
        }
        Some(StandardCall::Transfer { to, amount }) => Some(format!(
            "transfer {} to {to:#x}",
            format_token_amount(amount, token, &display)
        )),
        Some(StandardCall::TransferFrom { from, to, amount }) => Some(format!(
            "transferFrom {from:#x} to {to:#x} for {}",
            format_token_amount(amount, token, &display)
        )),
        Some(StandardCall::SetApprovalForAll {
            operator,
            approved: true,
        }) => Some(format!(
            "setApprovalForAll: grant operator {operator:#x} control of all {token:#x} tokens"
        )),
        Some(StandardCall::SetApprovalForAll {
            operator,
            approved: false,
        }) => Some(format!(
            "setApprovalForAll: revoke operator {operator:#x} for {token:#x}"
        )),
        Some(StandardCall::Multicall { calls }) => {
            let shown = calls.len().min(MAX_DISPLAYED_NESTED_CALLS);
            let mut text = format!("multicall with {} nested calls", calls.len());
            for (index, call) in calls.iter().take(shown).enumerate() {
                let _ = write!(
                    text,
                    "; nested {} selector {} ({} bytes)",
                    index + 1,
                    selector_text(call),
                    call.len()
                );
            }
            if calls.len() > shown {
                let _ = write!(text, "; {} further calls not shown", calls.len() - shown);
            }
            Some(text)
        }
        None => None,
    };
    StepInterpretation {
        step: step.step,
        description,
        details: Vec::new(),
        warnings,
    }
}

/// Token balance changes listed at approval time.
///
/// Entries come from Transfer logs the simulation observed, so a plan controls
/// how many there are. Past this many, nobody is reading them line by line —
/// an unbounded list is a way to bury the one entry that matters, not a way
/// to inform — so the tail is summarized and counted instead.
const MAX_DISPLAYED_BALANCE_CHANGES: usize = 32;

/// Render the simulated net balance changes as `(label, change)` pairs —
/// which asset, then its delta — with symbols and decimals when the wallet
/// could read them. Raw base units are reserved for unrecognized assets whose
/// decimals the owner has not trusted.
#[must_use]
pub fn render_balance_changes(
    simulation: &SimulationResult,
    network: &NetworkConfig,
    metadata: &TokenMetadataMap,
) -> Vec<(String, String)> {
    let Some(changes) = &simulation.balance_changes else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    match parse_signed(&changes.native.delta) {
        // Only a delta that parses and is exactly zero may be omitted. An
        // unparseable value is reported verbatim rather than treated as "no
        // change", which would hide an outflow from the reviewer.
        Some(native) if native.sign() == Sign::NoSign => {}
        Some(native) => {
            let currency = native_currency(network);
            lines.push((
                format!("{} (native)", currency.symbol),
                format_signed_amount(&native, Some(currency.decimals), Some(&currency.symbol)),
            ));
        }
        None => lines.push((
            "Native".to_string(),
            format!(
                "unparseable net change reported as {:?}",
                changes.native.delta
            ),
        )),
    }
    // The set being truncated is attacker-extensible: any contract may emit a
    // `Transfer` log naming this wallet, and every emitter enters the change
    // list. Truncating in address order therefore let someone deploy contracts
    // whose addresses sort early and push the transaction's real outflow past
    // the cut, leaving the reviewer a screen of noise and a "further token(s)"
    // footnote. Sorting by how well substantiated each entry is puts measured
    // balance movements first — only a token this wallet actually queried can
    // have one — so what truncation drops is always the unverifiable tail.
    //
    // Stable, so entries of equal standing keep the map's address order.
    let mut ordered: Vec<_> = changes.tokens.iter().collect();
    ordered.sort_by_key(|(_, change)| substantiation(change));
    let total = ordered.len();
    for (raw_token, change) in ordered.into_iter().take(MAX_DISPLAYED_BALANCE_CHANGES) {
        let token = raw_token.parse::<Address>().ok();
        let display = token
            .and_then(|token| metadata.get(&token).cloned())
            .unwrap_or_default();
        let label = token.map_or_else(|| raw_token.clone(), |token| token_label(token, &display));
        let delta_text = match change.delta.as_deref() {
            // If balanceOf was unavailable, present the signed net of the
            // standard Transfer events instead of an opaque missing-data
            // message. This remains display evidence, never policy authority.
            None => transfer_event_net(change).map_or_else(
                || "unparseable Transfer event amounts".to_string(),
                |delta| format_signed_amount(&delta, display.decimals, display.symbol.as_deref()),
            ),
            Some(raw) => parse_signed(raw).map_or_else(
                || format!("unparseable net change reported as {raw:?}"),
                |delta| format_signed_amount(&delta, display.decimals, display.symbol.as_deref()),
            ),
        };
        lines.push((label, delta_text));
        let incoming = &change.incoming_transfers;
        let outgoing = &change.outgoing_transfers;
        if incoming != "0" || outgoing != "0" {
            let incoming_display = parse_signed(incoming).map_or_else(
                || format!("+{incoming} base units"),
                |amount| format_signed_amount(&amount, display.decimals, display.symbol.as_deref()),
            );
            let outgoing_display = parse_signed(&format!("-{outgoing}")).map_or_else(
                || format!("-{outgoing} base units"),
                |amount| format_signed_amount(&amount, display.decimals, display.symbol.as_deref()),
            );
            // A continuation of the entry above (empty label), so the delta
            // stays a short, sign-toned figure and the gross flows read as
            // their own detail line.
            lines.push((
                String::new(),
                format!("standard Transfer events: {incoming_display} in, {outgoing_display} out"),
            ));
        }
    }
    if total > MAX_DISPLAYED_BALANCE_CHANGES {
        lines.push((
            "…".to_string(),
            format!(
                "and {} further token(s), least substantiated last, not shown",
                total - MAX_DISPLAYED_BALANCE_CHANGES
            ),
        ));
    }
    lines
}

/// Rank for display, lowest first: how far each reported change is from
/// something this wallet measured itself rather than was told.
///
/// A queried token has a net delta because its balance was read before and
/// after; an address that merely emitted a `Transfer` log has none, and
/// anyone can emit one of those.
fn substantiation(change: &crate::simulation::TokenBalanceChange) -> u8 {
    match change.delta.as_deref().map(parse_signed) {
        Some(Some(delta)) if delta.sign() != Sign::NoSign => 0,
        // Measured, but the value did not parse: still a token this wallet
        // tracked, and still worth more of the screen than hearsay.
        Some(None) => 1,
        Some(Some(_)) => 2,
        None => 3,
    }
}

fn native_currency(network: &NetworkConfig) -> NativeCurrency {
    network
        .native_currency
        .clone()
        .unwrap_or_else(|| NativeCurrency {
            name: "Native currency".into(),
            symbol: "native units".into(),
            decimals: 0,
        })
}

/// A signed balance delta is the difference of two uint256 balances, so it does
/// not fit any fixed-width integer. Arbitrary precision is required: silently
/// saturating or wrapping would show a reviewer a number that is not the one
/// being approved.
fn parse_signed(value: &str) -> Option<BigInt> {
    value.parse::<BigInt>().ok()
}

fn transfer_event_net(change: &crate::simulation::TokenBalanceChange) -> Option<BigInt> {
    Some(parse_signed(&change.incoming_transfers)? - parse_signed(&change.outgoing_transfers)?)
}

fn format_signed_amount(delta: &BigInt, decimals: Option<u8>, symbol: Option<&str>) -> String {
    let negative = delta.sign() == Sign::Minus;
    let magnitude = delta.magnitude().to_string();
    let sign = if negative { "-" } else { "+" };
    let Some(decimals) = decimals else {
        return format!("{sign}{magnitude} base units");
    };
    let scaled = format_fixed_point(&magnitude, decimals);
    let unit = symbol.map_or(String::new(), |symbol| format!(" {symbol}"));
    format!("{sign}{scaled}{unit}")
}

pub(crate) fn format_token_amount(amount: U256, token: Address, display: &TokenMetadata) -> String {
    let base_units = amount.to_string();
    let label = token_label(token, display);
    display.decimals.map_or_else(
        || format!("{base_units} base units of {label}"),
        |decimals| format!("{} {label}", format_fixed_point(&base_units, decimals)),
    )
}

/// What a call does, stated independently of how it reads.
///
/// These are the two grants that outlive the transaction carrying them: an
/// allowance the spender may draw whenever it likes, and blanket operator
/// control of a collection. Both are facts about the decoded call, so they are
/// derived from the call and attached to whatever description is displayed —
/// a clear-signing descriptor renders an approval more legibly, which is no
/// reason for its ceiling to stop being mentioned.
///
/// A `multicall(bytes[])` wrapper's nested calls are not unwrapped looking
/// for a grant hiding inside one: a nested call is arbitrary calldata this
/// crate has no bounded way to fully account for, and a scan deep enough to
/// find every grant is also a scan whose cost and coverage a plan's own
/// nesting gets to choose. Rather than promise a specific finding a bounded
/// scan cannot actually guarantee, a multicall earns a warning that its
/// contents were not individually reviewed, so a reviewer treats everything
/// it might carry as unverified instead of trusting the absence of a
/// specific warning as the absence of a specific grant.
fn standard_call_warnings(
    step: u32,
    token: Address,
    display: &TokenMetadata,
    call: Option<&StandardCall>,
) -> Vec<String> {
    match call {
        Some(StandardCall::Multicall { calls }) => vec![format!(
            "Call {step} is a multicall bundling {} nested call(s); their contents are not \
             individually reviewed, so treat this call as unverified.",
            calls.len()
        )],
        Some(StandardCall::Approve { spender, amount })
            if *amount != U256::ZERO && is_effectively_unlimited(*amount) =>
        {
            vec![format!(
                "Call {step} grants an effectively unlimited {} allowance to {spender:#x}.",
                token_label(token, display)
            )]
        }
        Some(StandardCall::SetApprovalForAll {
            operator,
            approved: true,
        }) => {
            vec![format!(
                "Call {step} grants {operator:#x} blanket operator control of every {token:#x} token held by this wallet."
            )]
        }
        _ => Vec::new(),
    }
}

/// A token is named only when the owner's token database names it. Anything
/// else is rendered by address and marked, so a reviewer can never read the
/// absence of a name as the presence of a familiar one.
pub(crate) fn token_label(token: Address, display: &TokenMetadata) -> String {
    display
        .symbol
        .as_deref()
        .and_then(display_symbol)
        .map_or_else(
            || format!("{token:#x} (unlisted token)"),
            |symbol| format!("{symbol} ({token:#x})"),
        )
}

/// A stored symbol is still text the wallet did not author: it reaches the
/// database from a token list, and a list is only as careful as whoever wrote
/// it. A label renders as `SYMBOL (0xaddress)`, so the danger is a symbol that
/// forges that suffix and points the reviewer at a contract the plan never
/// names.
///
/// Stripping the punctuation is not enough — `"USDC (0x2222…)"` merely becomes
/// `"USDC 0x2222…"`, which reads the same at a glance. So this keeps only the
/// characters real symbols actually use, which drops the brackets and the
/// separating spaces, and then refuses any symbol still containing `0x`.
/// Nothing that survives can look like a second address.
pub(crate) fn display_symbol(symbol: &str) -> Option<String> {
    let cleaned: String = crate::sanitize::stripped_capped(symbol, 32)
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '+')
        })
        .collect();
    if cleaned.is_empty() || cleaned.to_ascii_lowercase().contains("0x") {
        return None;
    }
    Some(cleaned)
}

/// Render a decimal base-unit string as a fixed-point quantity without any
/// rounding: every significant digit of the exact value is preserved.
#[must_use]
pub fn format_fixed_point(base_units: &str, decimals: u8) -> String {
    let decimals = usize::from(decimals);
    if decimals == 0 {
        return base_units.to_string();
    }
    let padded = format!("{base_units:0>width$}", width = decimals + 1);
    let split = padded.len() - decimals;
    let whole = &padded[..split];
    let fraction = padded[split..].trim_end_matches('0');
    if fraction.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fraction}")
    }
}

/// An allowance is treated as unlimited at or above `type(uint128).max`.
///
/// This covers every sentinel in common use: `type(uint256).max`,
/// `type(uint256).max / 2`, `type(uint160).max` as used by Permit2, and
/// `type(uint128).max`. It cannot produce a realistic false positive either,
/// because 2^128 base units is 3.4e20 whole tokens at eighteen decimals, which
/// is far beyond any circulating supply.
///
/// It deliberately does not flag `type(uint96).max`, which some older protocols
/// use as their infinite sentinel. At eighteen decimals that is 7.9e10 tokens —
/// large, but within the supply of real tokens, so warning on it would train a
/// reviewer to dismiss the warning.
fn is_effectively_unlimited(amount: U256) -> bool {
    amount >= (U256::from(1_u8) << 128) - U256::from(1_u8)
}

fn selector_text(data: &Bytes) -> String {
    if data.len() < 4 {
        "none".into()
    } else {
        format!("0x{}", hex::encode(&data[..4]))
    }
}

/// Decode only exact, canonical standard calldata. Any trailing byte, short
/// input, or non-canonical encoding yields `None` so the reviewer sees the raw
/// selector rather than a possibly wrong interpretation.
fn decode_standard_call(data: &Bytes) -> Option<StandardCall> {
    let selector: [u8; 4] = data.get(..4)?.try_into().ok()?;
    let body = &data[4..];
    match selector {
        APPROVE_SELECTOR => {
            let (spender, amount) = decode_address_uint(body)?;
            Some(StandardCall::Approve { spender, amount })
        }
        TRANSFER_SELECTOR => {
            let (to, amount) = decode_address_uint(body)?;
            Some(StandardCall::Transfer { to, amount })
        }
        TRANSFER_FROM_SELECTOR => {
            if body.len() != 96 {
                return None;
            }
            Some(StandardCall::TransferFrom {
                from: word_address(&body[..32])?,
                to: word_address(&body[32..64])?,
                amount: U256::from_be_slice(&body[64..96]),
            })
        }
        SET_APPROVAL_FOR_ALL_SELECTOR => {
            if body.len() != 64 {
                return None;
            }
            let operator = word_address(&body[..32])?;
            let approved = match U256::from_be_slice(&body[32..64]) {
                value if value == U256::ZERO => false,
                value if value == U256::from(1_u8) => true,
                _ => return None,
            };
            Some(StandardCall::SetApprovalForAll { operator, approved })
        }
        MULTICALL_SELECTOR => {
            let decoded = DynSolType::Array(Box::new(DynSolType::Bytes))
                .abi_decode_params(body)
                .ok()?;
            // Reject non-canonical encodings the same way the ABI decoder does.
            if decoded.abi_encode_params() != body {
                return None;
            }
            let DynSolValue::Array(items) = decoded else {
                return None;
            };
            let calls = items
                .into_iter()
                .map(|item| match item {
                    DynSolValue::Bytes(bytes) => Some(Bytes::from(bytes)),
                    _ => None,
                })
                .collect::<Option<Vec<Bytes>>>()?;
            Some(StandardCall::Multicall { calls })
        }
        _ => None,
    }
}

fn decode_address_uint(body: &[u8]) -> Option<(Address, U256)> {
    if body.len() != 64 {
        return None;
    }
    Some((
        word_address(&body[..32])?,
        U256::from_be_slice(&body[32..64]),
    ))
}

/// An address word must have its twelve leading bytes zeroed; anything else is
/// not a canonical ABI-encoded address.
fn word_address(word: &[u8]) -> Option<Address> {
    if word.len() != 32 || word[..12].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(Address::from_slice(&word[12..]))
}

#[cfg(test)]
#[path = "approval_summary_test.rs"]
mod tests;
