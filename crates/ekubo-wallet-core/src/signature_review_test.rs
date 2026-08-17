use super::*;
use crate::approval::ApprovalSection;
use crate::message::{MessageEncoding, MessageStatus};
use crate::typed_data::TypedDataStatus;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

const WALLET: &str = "0x1111111111111111111111111111111111111111";
const SPENDER: &str = "0x2222222222222222222222222222222222222222";
const TOKEN: &str = "0x3333333333333333333333333333333333333333";
const PERMIT2: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

fn wallet_address() -> Address {
    Address::from_str(WALLET).unwrap()
}

fn section<'a>(document: &'a ReviewDocument, heading: &str) -> &'a ApprovalSection {
    document
        .request
        .sections
        .iter()
        .find(|section| section.heading == heading)
        .unwrap_or_else(|| {
            panic!(
                "no section {heading:?} among {:?}",
                document
                    .request
                    .sections
                    .iter()
                    .map(|section| &section.heading)
                    .collect::<Vec<_>>()
            )
        })
}

fn fact<'a>(document: &'a ReviewDocument, heading: &str, label: &str) -> &'a str {
    section(document, heading)
        .facts
        .iter()
        .find(|fact| fact.label == label)
        .map_or_else(
            || panic!("no fact {label:?} in section {heading:?}"),
            |fact| fact.value.as_str(),
        )
}

fn typed_data_request(payload: serde_json::Value) -> PendingTypedData {
    PendingTypedData {
        request_id: Uuid::new_v4(),
        wallet_instance_id: Uuid::new_v4(),
        wallet_id: "trading".into(),
        wallet_address: wallet_address(),
        chain_id: "1".into(),
        typed_data: payload,
        digest: "0xabc".into(),
        status: TypedDataStatus::AwaitingApproval,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        approved_at: None,
        rejected_at: None,
        signature: None,
        requester: Some("app.example (app.example)".into()),
    }
}

fn erc2612_permit(value: &str, deadline: &str) -> serde_json::Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"}
            ]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Example Token",
            "version": "1",
            "chainId": 1,
            "verifyingContract": TOKEN
        },
        "message": {
            "owner": WALLET,
            "spender": SPENDER,
            "value": value,
            "nonce": "0",
            "deadline": deadline
        }
    })
}

fn metadata_for(token: &str, symbol: &str, decimals: u8) -> TokenMetadataMap {
    let mut map = TokenMetadataMap::new();
    map.insert(
        Address::from_str(token).unwrap(),
        TokenMetadata {
            symbol: Some(symbol.to_owned()),
            decimals: Some(decimals),
        },
    );
    map
}

fn build(request: &PendingTypedData, metadata: &TokenMetadataMap) -> ReviewDocument {
    let interpretation = PermitInterpretation::of(&request.typed_data, request.wallet_address);
    typed_data_review_document(
        request,
        &interpretation,
        metadata,
        "exact payload".into(),
        false,
    )
}

#[test]
fn a_recognized_permit_states_the_approval_it_grants_in_the_effects_section() {
    // `wallet_sign_typed_data` has always told agents that recognized permits
    // are "decoded into the token approvals they grant and shown to the user".
    // The review screen never decoded anything: it printed the raw JSON and
    // left a permit indistinguishable from any other structured message.
    let request = typed_data_request(erc2612_permit("1500000", "1767225600"));
    let document = build(&request, &metadata_for(TOKEN, "USDC", 6));

    assert_eq!(
        fact(&document, "What signing this grants", "Permit"),
        "ERC-2612 token permit"
    );
    assert_eq!(
        fact(&document, "What signing this grants", "Allows spending"),
        format!("1.5 USDC ({TOKEN})")
    );
    assert_eq!(
        fact(&document, "What signing this grants", "To"),
        Address::from_str(SPENDER).unwrap().to_checksum(None)
    );
    assert_eq!(
        section(&document, "What signing this grants").kind,
        ApprovalSectionKind::Effects
    );
}

#[test]
fn a_permit_deadline_is_shown_as_a_date_rather_than_a_unix_second_count() {
    let request = typed_data_request(erc2612_permit("1500000", "1767225600"));
    let document = build(&request, &metadata_for(TOKEN, "USDC", 6));

    assert_eq!(
        fact(
            &document,
            "What signing this grants",
            "Signature usable until"
        ),
        "2026-01-01 00:00:00 UTC"
    );
}

#[test]
fn an_unbounded_deadline_is_named_rather_than_printed_as_a_sentinel() {
    // `type(uint256).max` seconds is not a date. Rendered as digits it reads
    // like any other deadline, which is the reading that makes a signature
    // that never expires look like one that expires soon.
    let request = typed_data_request(erc2612_permit("1500000", &U256::MAX.to_string()));
    let document = build(&request, &metadata_for(TOKEN, "USDC", 6));

    let deadline = fact(
        &document,
        "What signing this grants",
        "Signature usable until",
    );
    assert!(
        deadline.starts_with("never"),
        "{deadline} does not say the signature never expires"
    );
}

#[test]
fn an_unlimited_allowance_is_named_and_warned_about() {
    let request = typed_data_request(erc2612_permit(&U256::MAX.to_string(), "1767225600"));
    let document = build(&request, &metadata_for(TOKEN, "USDC", 6));

    assert_eq!(
        fact(&document, "What signing this grants", "Allows spending"),
        format!("Unlimited USDC ({TOKEN})")
    );
    assert!(
        document
            .request
            .warnings
            .iter()
            .any(|warning| warning.contains("effectively unlimited")),
        "no unlimited-allowance warning among {:?}",
        document.request.warnings
    );
}

#[test]
fn an_unlisted_token_is_shown_by_address_in_base_units_rather_than_given_a_name() {
    // The same rule the transaction path follows: a token the owner has not
    // confirmed is never named, and its amount is never scaled by decimals the
    // wallet does not have.
    let request = typed_data_request(erc2612_permit("1500000", "1767225600"));
    let document = build(&request, &TokenMetadataMap::new());

    assert_eq!(
        fact(&document, "What signing this grants", "Allows spending"),
        format!("1500000 base units of {TOKEN} (unlisted token)")
    );
}

#[test]
fn a_permit_naming_another_owner_is_reported_to_the_reviewer_rather_than_hiding_the_review() {
    // A dapp reaching in over WalletConnect never passes through the MCP
    // tool's owner check, so this payload can reach the queue. The review is
    // the last place it can be caught, and refusing to render one would leave
    // the owner deciding from raw JSON.
    let mut payload = erc2612_permit("1500000", "1767225600");
    payload["message"]["owner"] = json!(SPENDER);
    let request = typed_data_request(payload);
    let document = build(&request, &metadata_for(TOKEN, "USDC", 6));

    assert!(
        fact(&document, "What signing this grants", "Token approvals").contains("refused"),
        "the refusal is not stated in the effects section"
    );
    assert!(
        document
            .request
            .warnings
            .iter()
            .any(|warning| warning.contains("somebody")),
        "no owner-mismatch warning among {:?}",
        document.request.warnings
    );
}

#[test]
fn an_unrecognized_payload_never_claims_it_grants_nothing() {
    // "No token approvals" and "no approvals this wallet can recognize" are
    // different claims, and only the second one is true.
    let request = typed_data_request(json!({
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}],
            "Vote": [{"name": "proposal", "type": "uint256"}]
        },
        "primaryType": "Vote",
        "domain": {"name": "Governance"},
        "message": {"proposal": "7"}
    }));
    let document = build(&request, &TokenMetadataMap::new());

    let stated = fact(&document, "What signing this grants", "Token approvals");
    assert!(
        stated.contains("None that this wallet recognizes"),
        "{stated} overstates what recognition proves"
    );
    assert!(stated.contains("not a promise"));
}

#[test]
fn the_structured_message_section_names_the_type_the_domain_and_the_fields() {
    let request = typed_data_request(erc2612_permit("1500000", "1767225600"));
    let document = build(&request, &metadata_for(TOKEN, "USDC", 6));

    assert_eq!(fact(&document, "Structured message", "Type"), "Permit");
    assert_eq!(
        fact(&document, "Structured message", "Domain name"),
        "Example Token"
    );
    assert_eq!(
        fact(&document, "Structured message", "Domain verifyingContract"),
        TOKEN
    );
    assert_eq!(fact(&document, "Structured message", "spender"), SPENDER);
    assert_eq!(
        section(&document, "Structured message").kind,
        ApprovalSectionKind::Action
    );
}

#[test]
fn the_exact_payload_still_travels_with_the_reading() {
    // Every fact above is an interpretation. The bytes are the thing being
    // signed, and they are never replaced by a reading of them.
    let request = typed_data_request(erc2612_permit("1500000", "1767225600"));
    let document = build(&request, &metadata_for(TOKEN, "USDC", 6));

    assert_eq!(document.exact_payloads, vec!["exact payload".to_owned()]);
}

#[test]
fn a_permit2_batch_shows_each_tokens_own_expiration() {
    // Permit2 puts `expiration` per entry and `sigDeadline` on the whole
    // signature. Showing only the deadline lets a permit look like it lapses
    // this hour while granting an allowance that lasts until uint48 max.
    let payload = json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "PermitBatch": [
                {"name": "details", "type": "PermitDetails[]"},
                {"name": "spender", "type": "address"},
                {"name": "sigDeadline", "type": "uint256"}
            ],
            "PermitDetails": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint160"},
                {"name": "expiration", "type": "uint48"},
                {"name": "nonce", "type": "uint48"}
            ]
        },
        "primaryType": "PermitBatch",
        "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2},
        "message": {
            "details": [{
                "token": TOKEN,
                "amount": "1500000",
                "expiration": "281474976710655",
                "nonce": "0"
            }],
            "spender": SPENDER,
            "sigDeadline": "1767225600"
        }
    });
    let request = typed_data_request(payload);
    let document = build(&request, &metadata_for(TOKEN, "USDC", 6));

    assert_eq!(
        fact(&document, "What signing this grants", "Permit"),
        "Permit2 allowance"
    );
    let expiration = fact(
        &document,
        "What signing this grants",
        "Allowance usable until",
    );
    assert!(
        expiration.starts_with("never"),
        "{expiration} does not say the allowance never lapses"
    );
    assert_eq!(
        fact(
            &document,
            "What signing this grants",
            "Signature usable until"
        ),
        "2026-01-01 00:00:00 UTC"
    );
}

fn message_request(text: &str) -> PendingMessage {
    PendingMessage {
        request_id: Uuid::new_v4(),
        wallet_instance_id: Uuid::new_v4(),
        wallet_id: "trading".into(),
        wallet_address: wallet_address(),
        chain_id: None,
        message_hex: format!("0x{}", hex::encode(text.as_bytes())),
        encoding: MessageEncoding::Text,
        digest: "0xdef".into(),
        status: MessageStatus::AwaitingApproval,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        approved_at: None,
        rejected_at: None,
        signature: None,
        requester: Some("app.example".into()),
    }
}

fn siwe_text(address: &str) -> String {
    format!(
        "app.example wants you to sign in with your Ethereum account:\n\
         {address}\n\
         \n\
         Accept the terms of service.\n\
         \n\
         URI: https://app.example/login\n\
         Version: 1\n\
         Chain ID: 1\n\
         Nonce: abcd1234\n\
         Issued At: 2026-08-17T00:00:00Z\n\
         Expiration Time: 2026-08-18T00:00:00Z"
    )
}

#[test]
fn a_message_review_leads_with_what_signing_does_rather_than_a_byte_count() {
    let request = message_request("hello world");
    let document = message_review_document(&request, b"hello world");

    assert_eq!(
        section(&document, "What signing this does").kind,
        ApprovalSectionKind::Effects
    );
    assert!(
        fact(&document, "What signing this does", "Balances").starts_with("Nothing moves"),
        "the effects section does not say that nothing moves"
    );
    assert!(fact(&document, "What signing this does", "Proves").contains(WALLET));
}

#[test]
fn a_sign_in_message_is_read_field_by_field_instead_of_left_as_prose() {
    let checksummed = wallet_address().to_checksum(None);
    let text = siwe_text(&checksummed);
    let request = message_request(&text);
    let document = message_review_document(&request, text.as_bytes());

    assert_eq!(
        fact(&document, "Sign-in request (ERC-4361)", "Site"),
        "app.example"
    );
    assert_eq!(
        fact(&document, "Sign-in request (ERC-4361)", "URI"),
        "https://app.example/login"
    );
    assert_eq!(
        fact(&document, "Sign-in request (ERC-4361)", "Nonce"),
        "abcd1234"
    );
    assert_eq!(
        fact(&document, "Sign-in request (ERC-4361)", "Statement"),
        "Accept the terms of service."
    );
    assert_eq!(
        fact(&document, "What signing this does", "Signs you in to"),
        "app.example"
    );
    assert_eq!(
        fact(&document, "What signing this does", "Session expires"),
        "2026-08-18T00:00:00Z"
    );
}

#[test]
fn a_sign_in_message_naming_another_account_is_warned_about() {
    let text = siwe_text(SPENDER);
    let request = message_request(&text);
    let document = message_review_document(&request, text.as_bytes());

    assert!(
        document
            .request
            .warnings
            .iter()
            .any(|warning| warning.contains("of no use to you")),
        "no account-mismatch warning among {:?}",
        document.request.warnings
    );
}

#[test]
fn a_plain_message_gets_no_sign_in_section_it_did_not_earn() {
    // Recognition is structural. A message that merely mentions signing in
    // must never be dressed up with a login's framing.
    let text = "please sign in to app.example";
    let request = message_request(text);
    let document = message_review_document(&request, text.as_bytes());

    assert!(
        !document
            .request
            .sections
            .iter()
            .any(|section| section.heading.starts_with("Sign-in request")),
        "an unrecognized message was given a login section"
    );
}

#[test]
fn the_exact_message_bytes_still_travel_with_the_reading() {
    let request = message_request("hello world");
    let document = message_review_document(&request, b"hello world");

    assert!(
        document
            .exact_payloads
            .iter()
            .any(|payload| payload.contains(&request.message_hex)),
        "the exact bytes are missing from {:?}",
        document.exact_payloads
    );
}

#[test]
fn exact_review_payloads_escape_invisible_and_bidirectional_text() {
    let rendered = escape_review_payload("safe\namount\u{202e}123\u{200b}");
    assert!(rendered.starts_with("safe\namount"));
    assert!(rendered.contains("\\u{202e}"));
    assert!(rendered.contains("\\u{200b}"));
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains('\u{200b}'));
}

#[test]
fn message_display_warnings_survive_the_move_into_sections() {
    // A message carrying bidirectional controls is the case the whole escaped
    // rendering exists for; adding sections must not drop it.
    let text = "transfer \u{202e}drowssap\u{202c} now";
    let request = message_request(text);
    let document = message_review_document(&request, text.as_bytes());

    assert!(
        document
            .request
            .warnings
            .iter()
            .any(|warning| warning.contains("bidirectional")),
        "no bidirectional warning among {:?}",
        document.request.warnings
    );
}
