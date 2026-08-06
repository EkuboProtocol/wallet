//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::approval_summary::TokenMetadata;
use crate::fullscreen::{display_width, lines_to_text};
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
        plan_source: None,
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
        updated_at: now - chrono::TimeDelta::minutes(7),
        approved_at: None,
        rejected_at: None,
        serialized_transaction: None,
        signed_transaction_hash: None,
        broadcast_transaction_hash: None,
        block_number: None,
        mined_fee: None,
        cancel_serialized_transaction: None,
        cancel_transaction_hashes: Vec::new(),
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
    // Columns: id, age, status, wallet, network, calls.
    assert_eq!(rows[0].cells[4], Span::plain("ethereum"));
    assert_eq!(rows[0].cells[5], Span::plain("1"));
    // The haystack finds what the truncated row never showed: the full
    // request ID, the hash, and the counterparty address.
    let haystack = &rows[0].haystack;
    assert!(haystack.contains(&uuid::Uuid::nil().to_string()));
    assert!(haystack.contains(&format!("0x{}", "ab".repeat(32))));
    assert!(haystack.contains("0x2222222222222222222222222222222222222222"));
}

#[test]
fn an_unconfigured_chain_falls_back_to_the_stored_name_then_the_id() {
    let networks = BTreeMap::new();
    let mut record = record();
    record.chain_id = "424242".into();
    let rows = list_rows(&networks, std::slice::from_ref(&record));
    assert_eq!(
        rows[0].cells[4],
        Span::plain("ethereum"),
        "the stored name still applies"
    );
    record.network_name = String::new();
    let rows = list_rows(&networks, std::slice::from_ref(&record));
    assert_eq!(rows[0].cells[4], Span::plain("chain 424242"));
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
    // Queued requests no longer expire, so the detail view has no deadline
    // to show and must not imply one.
    assert!(!text.contains("Expires"));
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
        Some(&ReceiptSection::Ready {
            receipt,
            metadata,
            native_delta: Some(BigInt::from(-71_000_000_000_000_i64)),
        }),
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
    // The native change shares the table, scaled by the network currency,
    // and states that it is a block-wide diff that includes gas.
    assert!(text.contains("ETH (native)"));
    assert!(text.contains("-0.000071"));
    assert!(text.contains("net change across the block, gas fee included"));
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
fn an_unavailable_native_delta_is_said_not_shown_as_zero() {
    let receipt = ReceiptDetails {
        succeeded: true,
        block_number: 123,
        gas_used: 21_000,
        effective_gas_price: 1_000_000_000,
        logs: Vec::new(),
    };
    let mut record = record();
    record.status = PendingStatus::Confirmed;
    record.broadcast_transaction_hash = Some(format!("0x{}", "aa".repeat(32)));
    let lines = detail_lines(
        &record,
        Some(&ethereum()),
        Some(&ReceiptSection::Ready {
            receipt,
            metadata: TokenMetadataMap::new(),
            native_delta: None,
        }),
    );
    let text = text_of(&lines);
    assert!(
        text.contains("native change unavailable"),
        "a failed lookup is reported, never rendered as no change: {text}"
    );
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
fn detail_keys_scroll_and_leave() {
    let mut detail = DetailView {
        title: "Request".into(),
        lines: Vec::new(),
        explorer: None,
        offset: 0,
        index: 0,
        confirm_cancel: false,
    };
    let press = |code| KeyEvent::new(code, crossterm::event::KeyModifiers::NONE);
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
fn cancellation_takes_two_presses_and_any_other_key_withdraws_it() {
    let mut detail = DetailView {
        title: "Request".into(),
        lines: Vec::new(),
        explorer: None,
        offset: 0,
        index: 0,
        confirm_cancel: false,
    };
    let press = |code| KeyEvent::new(code, crossterm::event::KeyModifiers::NONE);
    assert!(matches!(
        handle_detail_key(&mut detail, press(KeyCode::Char('c')), 10),
        DetailOutcome::RequestCancel
    ));
    // The browser arms the confirmation only for an eligible record.
    detail.confirm_cancel = true;
    assert!(matches!(
        handle_detail_key(&mut detail, press(KeyCode::Char('c')), 10),
        DetailOutcome::ConfirmCancel
    ));
    // Any other key withdraws an armed confirmation.
    detail.confirm_cancel = true;
    handle_detail_key(&mut detail, press(KeyCode::Down), 10);
    assert!(!detail.confirm_cancel);
    assert!(matches!(
        handle_detail_key(&mut detail, press(KeyCode::Char('c')), 10),
        DetailOutcome::RequestCancel
    ));
}
