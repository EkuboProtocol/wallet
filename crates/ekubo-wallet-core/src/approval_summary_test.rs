//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::core::execution_plan::{DecimalU256, ExecutionStepKind, PlannedTransaction};

fn step(step_number: u32, to: Address, data: Vec<u8>) -> ExecutionStep {
    ExecutionStep {
        step: step_number,
        kind: ExecutionStepKind::Execution,
        transaction: PlannedTransaction {
            chain_id: DecimalU256::new("1").unwrap(),
            from: Address::repeat_byte(0x11),
            to,
            data: data.into(),
            value: DecimalU256::new("0").unwrap(),
            gas: None,
        },
        revert_decode: None,
    }
}

fn approve_calldata(spender: Address, amount: U256) -> Vec<u8> {
    let mut data = APPROVE_SELECTOR.to_vec();
    data.extend_from_slice(&spender.into_word().0);
    data.extend_from_slice(&amount.to_be_bytes::<32>());
    data
}

#[tokio::test]
async fn a_descriptor_does_not_silence_the_unlimited_allowance_warning() {
    // stETH ships a vendored ERC-7730 descriptor for `approve`, so this
    // call is read through the descriptor path. What it grants is a fact
    // about the call, not about how the call reads — and a token popular
    // enough to have a descriptor is exactly one worth approving
    // carefully.
    let steth: Address = "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84"
        .parse()
        .unwrap();
    let interpretation = interpret_step(
        &step(
            1,
            steth,
            approve_calldata(Address::repeat_byte(0x22), U256::MAX),
        ),
        &TokenMetadataMap::new(),
    )
    .await;
    let description = interpretation.description.clone().unwrap_or_default();
    assert!(
        !description.starts_with("approve spender"),
        "the descriptor did not match, so this proves nothing: {description}"
    );
    assert!(
        interpretation
            .warnings
            .iter()
            .any(|warning| warning.contains("unlimited")),
        "descriptor reading dropped the warning: {:?}",
        interpretation.warnings
    );
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
    let interpretation = interpret_step(&step(2, token, calldata), &TokenMetadataMap::new()).await;
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
    let amount = format_token_amount(U256::from(1_000_000_u64), token, &TokenMetadata::default());
    assert!(amount.starts_with("1000000 base units of"), "{amount}");
}
