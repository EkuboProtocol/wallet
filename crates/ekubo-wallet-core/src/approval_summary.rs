//! Human-readable interpretation of an execution plan for terminal review.
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
            warnings: Vec::new(),
        };
    }
    let token = step.transaction.to;
    let display = metadata.get(&token).cloned().unwrap_or_default();
    let mut warnings = Vec::new();
    let description = match decode_standard_call(&step.transaction.data) {
        Some(StandardCall::Approve { spender, amount }) => {
            if amount == U256::ZERO {
                Some(format!(
                    "revoke {} allowance for spender {spender:#x}",
                    token_label(token, &display)
                ))
            } else {
                if is_effectively_unlimited(amount) {
                    warnings.push(format!(
                        "Call {} grants an effectively unlimited {} allowance to {spender:#x}.",
                        step.step,
                        token_label(token, &display)
                    ));
                }
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
        }) => {
            warnings.push(format!(
                "Call {} grants {operator:#x} blanket operator control of every {token:#x} token held by this wallet.",
                step.step
            ));
            Some(format!(
                "setApprovalForAll: grant operator {operator:#x} control of all {token:#x} tokens"
            ))
        }
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

/// Render the simulated net balance changes with symbols and decimals when the
/// wallet could read them, and always with exact base units.
#[must_use]
pub fn render_balance_changes(
    simulation: &SimulationResult,
    network: &NetworkConfig,
    metadata: &TokenMetadataMap,
) -> Vec<String> {
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
            lines.push(format!(
                "Native {}: {}",
                currency.symbol,
                format_signed_amount(&native, Some(currency.decimals), Some(&currency.symbol))
            ));
        }
        None => lines.push(format!(
            "Native: unparseable net change reported as {:?}",
            changes.native.delta
        )),
    }
    for (raw_token, change) in &changes.tokens {
        let token = raw_token.parse::<Address>().ok();
        let display = token
            .and_then(|token| metadata.get(&token).cloned())
            .unwrap_or_default();
        let label = token.map_or_else(|| raw_token.clone(), |token| token_label(token, &display));
        let delta_text = match change.delta.as_deref() {
            None => "net balance unavailable".to_string(),
            Some(raw) => parse_signed(raw).map_or_else(
                || format!("unparseable net change reported as {raw:?}"),
                |delta| format_signed_amount(&delta, display.decimals, display.symbol.as_deref()),
            ),
        };
        let incoming = &change.incoming_transfers;
        let outgoing = &change.outgoing_transfers;
        let transfers = if incoming == "0" && outgoing == "0" {
            String::new()
        } else {
            format!("; standard Transfer events: +{incoming} in, -{outgoing} out")
        };
        lines.push(format!("{label}: {delta_text}{transfers}"));
    }
    lines
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

fn format_signed_amount(delta: &BigInt, decimals: Option<u8>, symbol: Option<&str>) -> String {
    let negative = delta.sign() == Sign::Minus;
    let magnitude = delta.magnitude().to_string();
    let sign = if negative { "-" } else { "+" };
    let base_units = format!("{sign}{magnitude}");
    let Some(decimals) = decimals else {
        return format!("{base_units} base units");
    };
    let scaled = format_fixed_point(&magnitude, decimals);
    let unit = symbol.map_or(String::new(), |symbol| format!(" {symbol}"));
    format!("{sign}{scaled}{unit} ({base_units} base units)")
}

pub(crate) fn format_token_amount(amount: U256, token: Address, display: &TokenMetadata) -> String {
    let base_units = amount.to_string();
    let label = token_label(token, display);
    display.decimals.map_or_else(
        || format!("{base_units} base units of {label}"),
        |decimals| {
            format!(
                "{} {label} ({base_units} base units)",
                format_fixed_point(&base_units, decimals)
            )
        },
    )
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
fn display_symbol(symbol: &str) -> Option<String> {
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
mod tests {
    use super::*;
    use crate::core::execution_plan::{
        DecimalU256, ExecutionStepKind, PlannedTransaction, SubmitCondition,
    };

    fn step(step_number: u32, to: Address, data: Vec<u8>) -> ExecutionStep {
        ExecutionStep {
            step: step_number,
            kind: ExecutionStepKind::Execution,
            submit_condition: SubmitCondition::Always,
            transaction: PlannedTransaction {
                chain_id: DecimalU256::new("1").unwrap(),
                from: Address::repeat_byte(0x11),
                to,
                data: data.into(),
                value: DecimalU256::new("0").unwrap(),
                gas: None,
            },
            eip1193: None,
            revert_decode: None,
        }
    }

    fn approve_calldata(spender: Address, amount: U256) -> Vec<u8> {
        let mut data = APPROVE_SELECTOR.to_vec();
        data.extend_from_slice(&spender.into_word().0);
        data.extend_from_slice(&amount.to_be_bytes::<32>());
        data
    }

    fn simulation_with_native_delta(delta: &str) -> SimulationResult {
        use crate::simulation::{
            BalanceChanges, ExecutionMode, NativeBalanceChange, SimulationExecution,
        };
        SimulationResult {
            simulation_id: None,
            digest: "0x00".into(),
            allowed: true,
            policy_findings: Vec::new(),
            policy_revision: 1,
            execution_mode: ExecutionMode::Direct,
            implementation: None,
            will_authorize_delegation: false,
            replaces_delegated_implementation: None,
            simulation: SimulationExecution {
                success: true,
                gas_used: None,
                block_gas_limit: None,
                output: None,
                error: None,
                failure: None,
            },
            token_spends: BTreeMap::new(),
            balance_changes: Some(BalanceChanges {
                native: NativeBalanceChange {
                    before: "0".into(),
                    after: "0".into(),
                    delta: delta.into(),
                },
                tokens: BTreeMap::new(),
            }),
            block_number: "1".into(),
            fork: None,
        }
    }

    fn usdc_metadata(token: Address) -> TokenMetadataMap {
        TokenMetadataMap::from([(
            token,
            TokenMetadata {
                symbol: Some("USDC".into()),
                decimals: Some(6),
            },
        )])
    }

    #[test]
    fn decodes_canonical_approve_and_rejects_trailing_bytes() {
        let spender = Address::repeat_byte(0x22);
        let calldata = approve_calldata(spender, U256::from(1_000_000_u64));
        assert_eq!(
            decode_standard_call(&calldata.clone().into()),
            Some(StandardCall::Approve {
                spender,
                amount: U256::from(1_000_000_u64),
            })
        );

        let mut trailing = calldata;
        trailing.push(0);
        assert_eq!(decode_standard_call(&trailing.into()), None);
    }

    #[test]
    fn rejects_address_words_with_dirty_high_bytes() {
        let mut calldata = APPROVE_SELECTOR.to_vec();
        calldata.extend_from_slice(&[0xff; 32]);
        calldata.extend_from_slice(&U256::from(1_u8).to_be_bytes::<32>());
        assert_eq!(decode_standard_call(&calldata.into()), None);
    }

    #[tokio::test]
    async fn renders_token_amounts_with_symbol_and_exact_base_units() {
        let token = Address::repeat_byte(0x33);
        let spender = Address::repeat_byte(0x44);
        let interpretation = interpret_step(
            &step(
                1,
                token,
                approve_calldata(spender, U256::from(1_234_500_u64)),
            ),
            &usdc_metadata(token),
        )
        .await;
        let description = interpretation.description.unwrap();
        assert!(description.contains("1.2345 USDC"), "{description}");
        assert!(description.contains("1234500 base units"), "{description}");
        assert!(interpretation.warnings.is_empty());
    }

    #[tokio::test]
    async fn falls_back_to_base_units_without_metadata() {
        let token = Address::repeat_byte(0x33);
        let interpretation = interpret_step(
            &step(
                1,
                token,
                approve_calldata(Address::repeat_byte(0x44), U256::from(7_u8)),
            ),
            &TokenMetadataMap::new(),
        )
        .await;
        let description = interpretation.description.unwrap();
        assert!(description.contains("7 base units"), "{description}");
    }

    #[tokio::test]
    async fn warns_about_effectively_unlimited_allowances() {
        let token = Address::repeat_byte(0x33);
        let interpretation = interpret_step(
            &step(
                1,
                token,
                approve_calldata(Address::repeat_byte(0x44), U256::MAX),
            ),
            &usdc_metadata(token),
        )
        .await;
        assert_eq!(interpretation.warnings.len(), 1);
        assert!(interpretation.warnings[0].contains("unlimited"));
    }

    #[test]
    fn unlimited_threshold_covers_the_sentinels_actually_in_use() {
        for unlimited in [
            U256::MAX,
            U256::MAX / U256::from(2_u8),
            (U256::from(1_u8) << 160) - U256::from(1_u8), // Permit2
            U256::from(u128::MAX),
        ] {
            assert!(
                is_effectively_unlimited(unlimited),
                "{unlimited} should read as unlimited"
            );
        }
        for finite in [
            U256::ZERO,
            U256::from(1_000_000_u64),
            // 100 billion tokens at eighteen decimals: large but real.
            U256::from(10_u8).pow(U256::from(29_u8)),
        ] {
            assert!(
                !is_effectively_unlimited(finite),
                "{finite} should read as a finite allowance"
            );
        }
    }

    #[tokio::test]
    async fn warns_about_blanket_operator_approval() {
        let token = Address::repeat_byte(0x33);
        let operator = Address::repeat_byte(0x55);
        let mut calldata = SET_APPROVAL_FOR_ALL_SELECTOR.to_vec();
        calldata.extend_from_slice(&operator.into_word().0);
        calldata.extend_from_slice(&U256::from(1_u8).to_be_bytes::<32>());
        let interpretation =
            interpret_step(&step(2, token, calldata), &TokenMetadataMap::new()).await;
        assert_eq!(interpretation.warnings.len(), 1);
        assert!(interpretation.warnings[0].contains("blanket operator control"));
    }

    #[tokio::test]
    async fn zero_approval_reads_as_a_revocation() {
        let token = Address::repeat_byte(0x33);
        let interpretation = interpret_step(
            &step(
                1,
                token,
                approve_calldata(Address::repeat_byte(0x44), U256::ZERO),
            ),
            &usdc_metadata(token),
        )
        .await;
        assert!(interpretation.description.unwrap().starts_with("revoke"));
        assert!(interpretation.warnings.is_empty());
    }

    #[tokio::test]
    async fn unknown_calldata_has_no_interpretation() {
        let interpretation = interpret_step(
            &step(1, Address::repeat_byte(0x33), vec![0xde, 0xad, 0xbe, 0xef]),
            &TokenMetadataMap::new(),
        )
        .await;
        assert_eq!(interpretation.description, None);
        assert!(interpretation.warnings.is_empty());
    }

    #[tokio::test]
    async fn summarizes_nested_multicall_selectors() {
        let inner = DynSolValue::Array(vec![
            DynSolValue::Bytes(vec![0x11, 0x22, 0x33, 0x44]),
            DynSolValue::Bytes(vec![0x55, 0x66, 0x77, 0x88, 0x99]),
        ]);
        let mut calldata = MULTICALL_SELECTOR.to_vec();
        calldata.extend_from_slice(&inner.abi_encode_params());
        let interpretation = interpret_step(
            &step(1, Address::repeat_byte(0x33), calldata),
            &TokenMetadataMap::new(),
        )
        .await;
        let description = interpretation.description.unwrap();
        assert!(description.contains("2 nested calls"), "{description}");
        assert!(description.contains("0x11223344"), "{description}");
        assert!(description.contains("0x55667788"), "{description}");
    }

    #[tokio::test]
    async fn token_targets_only_include_standard_token_calls() {
        let token = Address::repeat_byte(0x33);
        let other = Address::repeat_byte(0x66);
        let steps = vec![
            step(
                1,
                token,
                approve_calldata(Address::repeat_byte(0x44), U256::from(1_u8)),
            ),
            step(2, other, vec![0xde, 0xad, 0xbe, 0xef]),
        ];
        assert_eq!(plan_token_targets(&steps).await, vec![token]);
    }

    #[tokio::test]
    async fn clear_signed_steps_take_precedence_over_standard_decoding() {
        // A VeToken stake call on its deployed chain and address must render
        // through the vendored ERC-7730 descriptor: intent naming the
        // protocol plus labeled fields, and no standard-decode fallback.
        let (chain_id, target, calldata) = crate::clear_signing::stake_fixture();
        let mut staked = step(1, target, calldata);
        staked.transaction.chain_id = DecimalU256::new(chain_id.to_string()).unwrap();
        let interpretations = interpret_steps(&[staked], &TokenMetadataMap::new()).await;
        let interpretation = &interpretations[0];
        let description = interpretation.description.as_deref().unwrap();
        assert!(description.contains("Ekubo"), "{description}");
        let joined = interpretation.details.join("\n");
        assert!(joined.contains("Amount"), "{joined}");
        assert!(joined.contains("Stake end"), "{joined}");

        // The same calldata on a chain without that deployment falls back to
        // the unrecognized-selector path rather than borrowing the reading.
        let (_, target, calldata) = crate::clear_signing::stake_fixture();
        let elsewhere = step(1, target, calldata);
        let fallback = interpret_steps(&[elsewhere], &TokenMetadataMap::new()).await;
        assert_eq!(fallback[0].description, None);
        assert!(fallback[0].details.is_empty());
    }

    #[test]
    fn fixed_point_rendering_never_rounds() {
        assert_eq!(format_fixed_point("1", 18), "0.000000000000000001");
        assert_eq!(format_fixed_point("0", 6), "0");
        assert_eq!(format_fixed_point("1000000", 6), "1");
        assert_eq!(format_fixed_point("1234567", 6), "1.234567");
        assert_eq!(format_fixed_point("42", 0), "42");
    }

    #[test]
    fn signed_amounts_keep_sign_and_base_units() {
        assert_eq!(
            format_signed_amount(&BigInt::from(-1_500_000), Some(6), Some("USDC")),
            "-1.5 USDC (-1500000 base units)"
        );
        assert_eq!(
            format_signed_amount(&BigInt::from(25), None, None),
            "+25 base units"
        );
    }

    #[test]
    fn balance_deltas_beyond_fixed_width_integers_stay_exact() {
        // A delta is the difference of two uint256 balances, so it can exceed
        // any fixed-width type. Rendering it as zero, saturated, or wrapped
        // would show a reviewer a number other than the one being approved.
        let huge = "-".to_string() + &"9".repeat(60);
        let delta = parse_signed(&huge).expect("arbitrary precision parses");
        let rendered = format_signed_amount(&delta, Some(18), Some("TKN"));
        assert!(
            rendered.contains(&format!("({huge} base units)")),
            "{rendered}"
        );
        assert!(rendered.starts_with('-'), "{rendered}");
        assert_eq!(
            parse_signed(&format!("-{}", U256::MAX)).map(|value| value.sign()),
            Some(Sign::Minus)
        );
    }

    #[test]
    fn unparseable_deltas_are_reported_rather_than_shown_as_zero() {
        assert!(parse_signed("not-a-number").is_none());
        let simulation = simulation_with_native_delta("not-a-number");
        let network = crate::config::default_networks().remove(0);
        let lines = render_balance_changes(&simulation, &network, &TokenMetadataMap::new());
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("unparseable"), "{lines:?}");
    }

    #[test]
    fn an_exactly_zero_native_delta_is_omitted() {
        let simulation = simulation_with_native_delta("0");
        let network = crate::config::default_networks().remove(0);
        assert!(render_balance_changes(&simulation, &network, &TokenMetadataMap::new()).is_empty());
    }

    #[test]
    fn token_symbols_cannot_forge_review_structure() {
        assert_eq!(
            display_symbol("US\u{1b}[31mDC\n(spoof)").as_deref(),
            Some("US31mDCspoof")
        );
        assert_eq!(display_symbol("   ").as_deref(), None);
        assert_eq!(display_symbol(&"A".repeat(64)).unwrap().len(), 32);
        // The symbols real token lists carry survive intact.
        for symbol in ["USDC", "WETH", "USDC.e", "wstETH", "1INCH", "USD+", "sDAI"] {
            assert_eq!(display_symbol(symbol).as_deref(), Some(symbol), "{symbol}");
        }
    }

    /// A symbol that carries its own parenthesized address must not be able to
    /// impersonate the real `SYMBOL (0xaddress)` suffix and point a reviewer at
    /// a contract the plan never names.
    #[test]
    fn a_stored_symbol_cannot_forge_the_address_suffix() {
        let real = Address::repeat_byte(0x11);
        let decoy = Address::repeat_byte(0x22);
        let label = token_label(
            real,
            &TokenMetadata {
                symbol: Some(format!("USDC ({decoy:#x})")),
                decimals: Some(6),
            },
        );
        // A symbol that tries to carry an address is refused outright, so the
        // token falls back to being named by its own address and nothing else.
        assert!(label.starts_with(&format!("{real:#x}")), "{label}");
        assert!(!label.contains("2222"), "{label}");
        assert_eq!(label.matches("0x").count(), 1, "{label}");
    }

    /// The whole point of the change: a token the owner never confirmed is
    /// never given a name, however convincingly its contract answers.
    #[test]
    fn an_unlisted_token_is_named_by_address_alone() {
        let token = Address::repeat_byte(0xab);
        let label = token_label(token, &TokenMetadata::default());
        assert_eq!(label, format!("{token:#x} (unlisted token)"));

        // And its amounts stay in base units rather than being scaled by a
        // decimals value no confirmed list vouched for.
        let amount =
            format_token_amount(U256::from(1_000_000_u64), token, &TokenMetadata::default());
        assert!(amount.starts_with("1000000 base units of"), "{amount}");
    }
}
