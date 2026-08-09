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

fn set_approval_for_all_calldata(operator: Address, approved: bool) -> Vec<u8> {
    let mut data = SET_APPROVAL_FOR_ALL_SELECTOR.to_vec();
    data.extend_from_slice(&operator.into_word().0);
    data.extend_from_slice(&U256::from(u8::from(approved)).to_be_bytes::<32>());
    data
}

#[tokio::test]
async fn a_descriptor_does_not_silence_the_operator_grant_warning() {
    // The Ekubo Positions contract ships a descriptor for
    // `setApprovalForAll`, whose intent line — "Manage operator rights for" —
    // reads the same whether the grant is being made or revoked. Only the
    // wallet's own warning distinguishes them, so the descriptor path has to
    // carry it.
    let positions: Address = "0x02D9876A21AF7545f8632C3af76eC90b5ad4b66D"
        .parse()
        .unwrap();
    let operator = Address::repeat_byte(0x33);
    let granted = interpret_step(
        &step(1, positions, set_approval_for_all_calldata(operator, true)),
        &TokenMetadataMap::new(),
    )
    .await;
    let description = granted.description.clone().unwrap_or_default();
    assert!(
        !description.starts_with("setApprovalForAll:"),
        "the descriptor did not match, so this proves nothing: {description}"
    );
    assert!(
        granted
            .warnings
            .iter()
            .any(|warning| warning.contains("blanket operator control")),
        "descriptor reading dropped the warning: {:?}",
        granted.warnings
    );

    // A revocation reads through the same descriptor and must stay quiet:
    // a warning on every operator call would say nothing about this one.
    let revoked = interpret_step(
        &step(1, positions, set_approval_for_all_calldata(operator, false)),
        &TokenMetadataMap::new(),
    )
    .await;
    assert!(revoked.warnings.is_empty(), "{:?}", revoked.warnings);
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
        policy_outcome: crate::core::policy::PolicyOutcome::Allowed,
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

/// `n` distinct, equally-unsubstantiated token changes — no queried balance,
/// so `render_balance_changes`'s substantiation sort leaves them in address
/// order and none is picked over another when only the count at the
/// [`MAX_DISPLAYED_BALANCE_CHANGES`] boundary is under test.
fn simulation_with_n_token_changes(n: u8) -> SimulationResult {
    use crate::simulation::TokenBalanceChange;
    let mut simulation = simulation_with_native_delta("0");
    let changes = &mut simulation.balance_changes.as_mut().unwrap().tokens;
    for index in 0..n {
        changes.insert(
            format!("{:#x}", Address::repeat_byte(index)),
            TokenBalanceChange {
                before: None,
                after: None,
                delta: None,
                incoming_transfers: "1".into(),
                outgoing_transfers: "0".into(),
            },
        );
    }
    simulation
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
async fn an_unlimited_allowance_nested_in_a_multicall_still_warns() {
    // The same grant a standalone `approve` makes, packed as the second of
    // two nested calls inside a `multicall(bytes[])` wrapper — the shape a
    // router batches an approval alongside an unrelated action in.
    let spender = Address::repeat_byte(0x44);
    let inner = DynSolValue::Array(vec![
        DynSolValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        DynSolValue::Bytes(approve_calldata(spender, U256::MAX)),
    ]);
    let mut calldata = MULTICALL_SELECTOR.to_vec();
    calldata.extend_from_slice(&inner.abi_encode_params());
    let token = Address::repeat_byte(0x33);
    let interpretation = interpret_step(&step(1, token, calldata), &TokenMetadataMap::new()).await;
    assert!(
        interpretation
            .warnings
            .iter()
            .any(|warning| warning.contains("unlimited") && warning.contains("0x4444")),
        "multicall wrapper silenced the allowance warning: {:?}",
        interpretation.warnings
    );
}

#[tokio::test]
async fn an_operator_grant_nested_in_a_multicall_still_warns() {
    let operator = Address::repeat_byte(0x55);
    let inner = DynSolValue::Array(vec![DynSolValue::Bytes(set_approval_for_all_calldata(
        operator, true,
    ))]);
    let mut calldata = MULTICALL_SELECTOR.to_vec();
    calldata.extend_from_slice(&inner.abi_encode_params());
    let token = Address::repeat_byte(0x33);
    let interpretation = interpret_step(&step(1, token, calldata), &TokenMetadataMap::new()).await;
    assert!(
        interpretation
            .warnings
            .iter()
            .any(|warning| warning.contains("blanket operator control")),
        "multicall wrapper silenced the operator-grant warning: {:?}",
        interpretation.warnings
    );
}

/// Wrap `innermost` in `layers` nested `multicall(bytes[])` calls, each
/// carrying the previous as its one entry — `layers == 1` is a single
/// `multicall([innermost])`.
fn wrap_in_multicalls(innermost: Vec<u8>, layers: u8) -> Vec<u8> {
    let mut calldata = innermost;
    for _ in 0..layers {
        let wrapped = DynSolValue::Array(vec![DynSolValue::Bytes(calldata)]);
        let mut next = MULTICALL_SELECTOR.to_vec();
        next.extend_from_slice(&wrapped.abi_encode_params());
        calldata = next;
    }
    calldata
}

#[tokio::test]
async fn a_grant_at_the_maximum_scanned_multicall_depth_still_warns() {
    let spender = Address::repeat_byte(0x44);
    let calldata = wrap_in_multicalls(approve_calldata(spender, U256::MAX), MAX_WARNING_SCAN_DEPTH);
    let token = Address::repeat_byte(0x33);
    let interpretation = interpret_step(&step(1, token, calldata), &TokenMetadataMap::new()).await;
    assert!(
        interpretation
            .warnings
            .iter()
            .any(|warning| warning.contains("unlimited") && warning.contains("0x4444")),
        "a grant at the maximum scanned depth went unwarned: {:?}",
        interpretation.warnings
    );
}

#[tokio::test]
async fn a_multicall_nested_past_the_maximum_scanned_depth_does_not_warn() {
    // One layer deeper than the previous test's maximum: the scan is bounded
    // on purpose (see `MAX_WARNING_SCAN_DEPTH`'s doc comment) rather than a
    // recursion that walks as deep as a plan cares to nest, so a grant this
    // far down is invisible to it. Documented behavior, not a regression.
    let approve = approve_calldata(Address::repeat_byte(0x44), U256::MAX);
    let calldata = wrap_in_multicalls(approve, MAX_WARNING_SCAN_DEPTH + 1);
    let token = Address::repeat_byte(0x33);
    let interpretation = interpret_step(&step(1, token, calldata), &TokenMetadataMap::new()).await;
    assert!(
        interpretation.warnings.is_empty(),
        "{:?}",
        interpretation.warnings
    );
}

#[tokio::test]
async fn grant_warnings_beyond_the_cap_are_summarized_not_flooded() {
    // A `multicall` packing far more grants than `MAX_GRANT_WARNINGS` must
    // not turn into one warning line per grant: that would bury the first
    // warning under a wall of near-identical text just as surely as no
    // warning at all would hide it.
    let extra = 5;
    let calls: Vec<DynSolValue> = (0..MAX_GRANT_WARNINGS + extra)
        .map(|index| {
            DynSolValue::Bytes(approve_calldata(
                Address::repeat_byte(u8::try_from(index).unwrap()),
                U256::MAX,
            ))
        })
        .collect();
    let inner = DynSolValue::Array(calls);
    let mut calldata = MULTICALL_SELECTOR.to_vec();
    calldata.extend_from_slice(&inner.abi_encode_params());
    let token = Address::repeat_byte(0x33);
    let interpretation = interpret_step(&step(1, token, calldata), &TokenMetadataMap::new()).await;
    assert_eq!(
        interpretation.warnings.len(),
        MAX_GRANT_WARNINGS + 1,
        "expected the cap plus one summary line: {:?}",
        interpretation.warnings
    );
    assert!(
        interpretation
            .warnings
            .last()
            .unwrap()
            .contains(&format!("{extra} further grant")),
        "{:?}",
        interpretation.warnings
    );
}

#[tokio::test]
async fn a_grant_past_the_displayed_nested_call_count_still_warns() {
    // `MAX_DISPLAYED_NESTED_CALLS` (16) bounds how many nested calls the
    // description prints, not how many are checked for a grant: every
    // nested call executes regardless of whether its selector is shown, so
    // a malicious approve placed after the sixteenth harmless call must
    // still warn even though the description text never names it.
    let mut nested =
        vec![DynSolValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]); MAX_DISPLAYED_NESTED_CALLS];
    let spender = Address::repeat_byte(0x66);
    nested.push(DynSolValue::Bytes(approve_calldata(spender, U256::MAX)));
    let inner = DynSolValue::Array(nested);
    let mut calldata = MULTICALL_SELECTOR.to_vec();
    calldata.extend_from_slice(&inner.abi_encode_params());
    let token = Address::repeat_byte(0x33);
    let interpretation = interpret_step(&step(1, token, calldata), &TokenMetadataMap::new()).await;
    let description = interpretation.description.clone().unwrap_or_default();
    assert!(
        description.contains("further calls not shown"),
        "test setup: expected the display cap to actually be exceeded: {description}"
    );
    assert!(
        interpretation
            .warnings
            .iter()
            .any(|warning| warning.contains("unlimited") && warning.contains("0x6666")),
        "a grant past the display cap went unwarned: {:?}",
        interpretation.warnings
    );
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
async fn token_targets_see_through_a_multicall_wrapper() {
    // A token named only inside a nested multicall call must still resolve:
    // otherwise the warning `standard_call_warnings` now emits for it (see
    // `an_unlimited_allowance_nested_in_a_multicall_still_warns`) renders
    // the token as unlisted even when the local database names it.
    let token = Address::repeat_byte(0x33);
    let inner = DynSolValue::Array(vec![DynSolValue::Bytes(approve_calldata(
        Address::repeat_byte(0x44),
        U256::from(1_u8),
    ))]);
    let mut calldata = MULTICALL_SELECTOR.to_vec();
    calldata.extend_from_slice(&inner.abi_encode_params());
    let steps = vec![step(1, token, calldata)];
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
    assert!(lines[0].1.contains("unparseable"), "{lines:?}");
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

#[test]
fn a_real_outflow_survives_a_flood_of_forged_transfer_logs() {
    use crate::simulation::TokenBalanceChange;

    // Any contract can emit a `Transfer` log naming this wallet, and every
    // emitter enters the change list. While the list truncated in address
    // order, deploying contracts whose addresses sort early pushed the
    // transaction's real outflow past the cut and left the reviewer a screen
    // of noise plus a "further token(s)" footnote.
    //
    // The genuine token is given the highest address there is, so address
    // order alone would place it dead last.
    let real = Address::repeat_byte(0xff);
    let mut simulation = simulation_with_native_delta("0");
    let changes = &mut simulation.balance_changes.as_mut().unwrap().tokens;

    for index in 0..64_u8 {
        changes.insert(
            format!("{:#x}", Address::repeat_byte(index)),
            TokenBalanceChange {
                before: None,
                after: None,
                delta: None,
                incoming_transfers: "1".into(),
                outgoing_transfers: "0".into(),
            },
        );
    }
    changes.insert(
        format!("{real:#x}"),
        TokenBalanceChange {
            before: Some("1000".into()),
            after: Some("0".into()),
            delta: Some("-1000".into()),
            incoming_transfers: "0".into(),
            outgoing_transfers: "1000".into(),
        },
    );

    let network = crate::config::default_networks().remove(0);
    let lines = render_balance_changes(&simulation, &network, &usdc_metadata(real));
    let rendered = lines
        .iter()
        .map(|(label, value)| format!("{label} {value}"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        rendered.contains("-1000") || rendered.contains("-0.001"),
        "the measured outflow must be on screen: {rendered}"
    );
    // And it leads, because nothing else here was measured at all.
    assert_eq!(
        lines[0].0,
        token_label(
            real,
            &usdc_metadata(real).get(&real).cloned().unwrap_or_default()
        ),
        "the measured change must come first: {rendered}"
    );
    assert!(
        rendered.contains("not shown"),
        "the truncation notice must still appear: {rendered}"
    );
}

#[test]
fn exactly_at_the_cap_shows_every_change_with_no_truncation_notice() {
    let simulation =
        simulation_with_n_token_changes(u8::try_from(MAX_DISPLAYED_BALANCE_CHANGES).unwrap());
    let network = crate::config::default_networks().remove(0);
    let lines = render_balance_changes(&simulation, &network, &TokenMetadataMap::new());

    assert!(
        !lines.iter().any(|(label, _)| label == "…"),
        "a list exactly at the cap must not claim anything is unshown: {lines:?}"
    );
}

#[test]
fn one_past_the_cap_reports_exactly_one_unshown() {
    let simulation =
        simulation_with_n_token_changes(u8::try_from(MAX_DISPLAYED_BALANCE_CHANGES).unwrap() + 1);
    let network = crate::config::default_networks().remove(0);
    let lines = render_balance_changes(&simulation, &network, &TokenMetadataMap::new());

    let (_, footer) = lines
        .iter()
        .find(|(label, _)| label == "…")
        .expect("one entry past the cap must produce a truncation notice");
    assert!(
        footer.contains("and 1 further token(s)"),
        "exactly one entry is past the cap, not more or fewer: {footer}"
    );
}
