//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::policy_store::DatabaseKey;

pub(crate) fn siwe_payload() -> String {
    [
        "example.com wants you to sign in with your Ethereum account:",
        "0x1111111111111111111111111111111111111111",
        "",
        "Sign in to Example.",
        "",
        "URI: https://example.com/login",
        "Version: 1",
        "Chain ID: 1",
        "Nonce: 32891756",
        "Issued At: 2026-08-04T16:25:24Z",
    ]
    .join("\n")
}

fn store() -> (tempfile::TempDir, MessageStore) {
    let directory = tempfile::tempdir().unwrap();
    let database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([9; 32]),
    )
    .unwrap();
    (directory, MessageStore::new(database))
}

#[test]
fn digest_matches_known_eip191_vectors() {
    // keccak256("\x19Ethereum Signed Message:\n12Hello World")
    assert_eq!(
        format!("{:#x}", message_digest(b"Hello World")),
        "0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
    );
    // The empty message still carries a length prefix of "0".
    assert_eq!(
        format!("{:#x}", message_digest(b"")),
        "0x5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad"
    );
    // Multi-byte UTF-8: the prefix counts bytes, not characters.
    assert_eq!(
        format!("{:#x}", message_digest("é".as_bytes())),
        format!("{:#x}", message_digest(&[0xc3, 0xa9]))
    );
}

#[test]
fn a_real_signature_over_the_digest_recovers_to_the_signer() {
    use alloy::signers::{SignerSync, local::PrivateKeySigner};

    let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x07)).unwrap();
    let digest = message_digest(b"gm");
    let signature = signer.sign_hash_sync(&digest).unwrap();
    assert_eq!(
        signature.recover_address_from_prehash(&digest).unwrap(),
        signer.address()
    );
    // The digest this module builds is exactly what a `personal_sign`
    // signer produces for the same bytes.
    assert_eq!(signer.sign_message_sync(b"gm").unwrap(), signature);
    crate::signature_requests::parse_signature(&format!("0x{}", hex::encode(signature.as_bytes())))
        .unwrap();
}

#[test]
fn text_and_hex_inputs_describe_the_same_bytes() {
    let (text, encoding) = parse_message_input(Some("gm"), None).unwrap();
    assert_eq!(encoding, MessageEncoding::Text);
    let (bytes, encoding) = parse_message_input(None, Some("0x676d")).unwrap();
    assert_eq!(encoding, MessageEncoding::Hex);
    assert_eq!(text, bytes);
    assert_eq!(message_digest(&text), message_digest(&bytes));
}

#[test]
fn bare_thirty_two_byte_requests_are_refused() {
    let digest_shaped = format!("0x{}", "ab".repeat(32));
    let error = parse_message_input(None, Some(&digest_shaped)).unwrap_err();
    assert!(error.to_string().contains("eth_sign is not supported"));

    // A 32-character sentence is not a digest, and stays signable.
    let sentence = "Please sign in to example.com!!!";
    assert_eq!(sentence.len(), 32);
    assert!(parse_message_input(Some(sentence), None).is_ok());
}

#[test]
fn input_requires_exactly_one_encoding_and_a_reviewable_size() {
    assert!(parse_message_input(None, None).is_err());
    assert!(parse_message_input(Some("gm"), Some("0x676d")).is_err());
    assert!(parse_message_input(Some(""), None).is_err());
    assert!(parse_message_input(None, Some("676d")).is_err());
    assert!(parse_message_input(None, Some("0x6")).is_err());
    assert!(parse_message_input(None, Some("0xzz")).is_err());
    assert!(parse_message_input(Some(&"a".repeat(MAX_MESSAGE_BYTES + 1)), None).is_err());
}

#[test]
fn display_flags_everything_that_can_mislead_a_reader() {
    let plain = describe_message(b"gm");
    assert_eq!(plain.text.as_deref(), Some("gm"));
    assert!(plain.warnings.is_empty());

    let ansi = describe_message(b"safe\x1b[31m\ntext");
    assert_eq!(
        ansi.escaped_text.as_deref(),
        Some("safe\\u{001b}[31m\\u{000a}text")
    );
    assert!(
        ansi.warnings
            .iter()
            .any(|warning| warning.contains("control characters"))
    );

    let bidi = describe_message("send \u{202e}yenom".as_bytes());
    assert!(
        bidi.warnings
            .iter()
            .any(|warning| warning.contains("bidirectional"))
    );
    assert!(bidi.escaped_text.unwrap().contains("\\u{202e}"));

    let hexish = describe_message(format!("0x{}", "cd".repeat(32)).as_bytes());
    assert!(
        hexish
            .warnings
            .iter()
            .any(|warning| warning.contains("bare hexadecimal"))
    );

    let binary = describe_message(&[0xff, 0xfe, 0x00]);
    assert!(binary.text.is_none());
    assert_eq!(binary.byte_length, 3);
    assert!(
        binary
            .warnings
            .iter()
            .any(|warning| warning.contains("not valid UTF-8"))
    );
}

#[test]
fn parses_siwe_with_and_without_a_statement() {
    let siwe = parse_siwe(&siwe_payload()).unwrap();
    assert_eq!(siwe.domain, "example.com");
    assert_eq!(siwe.address, "0x1111111111111111111111111111111111111111");
    assert_eq!(siwe.statement.as_deref(), Some("Sign in to Example."));
    assert_eq!(siwe.uri, "https://example.com/login");
    assert_eq!(siwe.chain_id, "1");
    assert_eq!(siwe.nonce, "32891756");
    assert!(siwe.resources.is_empty());

    let statementless = siwe_payload().replace("Sign in to Example.\n\n", "");
    let siwe = parse_siwe(&statementless).unwrap();
    assert!(siwe.statement.is_none());
    assert_eq!(siwe.uri, "https://example.com/login");
}

#[test]
fn a_siwe_message_has_one_reading_or_none() {
    // A repeated field used to be accepted with the last value winning, so
    // this wallet showed one expiry and a stricter verifier could read the
    // other — the owner approving a description nobody else shares.
    let repeated = format!(
        "{}\nExpiration Time: 2026-08-04T17:25:24Z\nExpiration Time: 2099-01-01T00:00:00Z",
        siwe_payload()
    );
    assert!(parse_siwe(&repeated).is_none());

    // Out of order is the same ambiguity: ERC-4361 fixes the sequence, so
    // a message that does not follow it is one two parsers may disagree
    // about.
    let reordered = format!(
        "{}\nRequest ID: abc\nExpiration Time: 2026-08-04T17:25:24Z",
        siwe_payload()
    );
    assert!(parse_siwe(&reordered).is_none());

    // Resources must still come last, and nothing may follow them.
    let after_resources = format!(
        "{}\nResources:\n- https://example.com/terms\nRequest ID: abc",
        siwe_payload()
    );
    assert!(parse_siwe(&after_resources).is_none());

    // The ordered form is unaffected.
    let ordered = format!(
        "{}\nExpiration Time: 2026-08-04T17:25:24Z\nNot Before: 2026-08-01T00:00:00Z\nRequest \
             ID: abc",
        siwe_payload()
    );
    assert!(parse_siwe(&ordered).is_some());
}

#[test]
fn parses_optional_siwe_fields_and_resources() {
    let payload = format!(
        "{}\nExpiration Time: 2026-08-04T17:25:24Z\nRequest ID: abc\nResources:\n- \
             https://example.com/terms\n- ipfs://bafy",
        siwe_payload()
    );
    let siwe = parse_siwe(&payload).unwrap();
    assert_eq!(
        siwe.expiration_time.as_deref(),
        Some("2026-08-04T17:25:24Z")
    );
    assert_eq!(siwe.request_id.as_deref(), Some("abc"));
    assert_eq!(siwe.resources.len(), 2);
}

#[test]
fn near_miss_messages_are_not_recognized_as_siwe() {
    assert!(parse_siwe("gm").is_none());
    // Missing the blank line after the address.
    assert!(parse_siwe(&siwe_payload().replace("1111\n\n", "1111\n")).is_none());
    // Not an address.
    assert!(
        parse_siwe(&siwe_payload().replace("0x1111111111111111111111111111111111111111", "me"))
            .is_none()
    );
    // Unknown version.
    assert!(parse_siwe(&siwe_payload().replace("Version: 1", "Version: 2")).is_none());
    // Non-numeric chain.
    assert!(parse_siwe(&siwe_payload().replace("Chain ID: 1", "Chain ID: mainnet")).is_none());
    // An unexpected trailing field.
    assert!(parse_siwe(&format!("{}\nAlso: everything", siwe_payload())).is_none());
}

#[test]
fn siwe_warnings_cover_chain_time_and_domain_disagreements() {
    let now = DateTime::parse_from_rfc3339("2026-08-04T16:30:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let siwe = parse_siwe(&siwe_payload()).unwrap();
    assert!(siwe_warnings(&siwe, Some("1"), true, now).is_empty());

    let warnings = siwe_warnings(&siwe, Some("8453"), false, now);
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("chain 8453"))
    );
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("not a configured network"))
    );

    let expired = parse_siwe(&format!(
        "{}\nExpiration Time: 2026-08-04T16:29:00Z",
        siwe_payload()
    ))
    .unwrap();
    assert!(
        siwe_warnings(&expired, None, true, now)
            .iter()
            .any(|warning| warning.contains("expired"))
    );

    let postdated = parse_siwe(&format!(
        "{}\nNot Before: 2026-09-04T16:29:00Z",
        siwe_payload()
    ))
    .unwrap();
    assert!(
        siwe_warnings(&postdated, None, true, now)
            .iter()
            .any(|warning| warning.contains("post-dated"))
    );

    let impostor = parse_siwe(&siwe_payload().replace(
        "URI: https://example.com/login",
        "URI: https://phish.example.net/login",
    ))
    .unwrap();
    assert!(
        siwe_warnings(&impostor, None, true, now)
            .iter()
            .any(|warning| warning.contains("phish.example.net"))
    );

    let resourced = parse_siwe(&format!(
        "{}\nResources:\n- https://example.com/everything",
        siwe_payload()
    ))
    .unwrap();
    assert!(
        siwe_warnings(&resourced, None, true, now)
            .iter()
            .any(|warning| warning.contains("listed resource"))
    );
}

#[test]
fn lifecycle_persists_exact_bytes_and_signature() {
    let (_directory, mut store) = store();
    let message = b"gm".to_vec();
    let request = store
        .create("primary", Some("1"), &message, MessageEncoding::Text, None)
        .unwrap();
    assert_eq!(request.status, MessageStatus::AwaitingApproval);
    assert_eq!(request.message_bytes().unwrap(), message);
    assert_eq!(request.chain_id.as_deref(), Some("1"));
    assert_eq!(request.digest, format!("{:#x}", message_digest(&message)));

    // The identical message reuses the pending request.
    let duplicate = store
        .create("primary", Some("1"), &message, MessageEncoding::Text, None)
        .unwrap();
    assert_eq!(duplicate.request_id, request.request_id);
    assert_eq!(store.awaiting_approval(None).unwrap().len(), 1);

    let signature = format!("0x{}", "11".repeat(65));
    let signed = store
        .store_signature(
            request.request_id,
            "primary",
            message_digest(b"gm"),
            &signature,
        )
        .unwrap();
    assert_eq!(signed.status, MessageStatus::Signed);
    assert_eq!(signed.signature.as_deref(), Some(signature.as_str()));
    assert!(signed.approved_at.is_some());
    assert!(store.awaiting_approval(None).unwrap().is_empty());

    // A signed request cannot be re-signed or rejected.
    assert!(
        store
            .store_signature(
                request.request_id,
                "primary",
                message_digest(b"gm"),
                &signature
            )
            .is_err()
    );
    assert!(store.reject(request.request_id).is_err());
}

#[test]
fn recent_activity_lists_every_status_with_limits_and_wallet_filters() {
    let (_directory, mut store) = store();
    let signed = store
        .create("primary", None, b"first", MessageEncoding::Text, None)
        .unwrap();
    let rejected = store
        .create("primary", None, b"second", MessageEncoding::Text, None)
        .unwrap();
    let awaiting = store
        .create("primary", None, b"third", MessageEncoding::Text, None)
        .unwrap();
    let other = store
        .create("secondary", None, b"other", MessageEncoding::Text, None)
        .unwrap();

    store
        .store_signature(
            signed.request_id,
            "primary",
            message_digest(b"first"),
            &format!("0x{}", "11".repeat(65)),
        )
        .unwrap();
    store.reject(rejected.request_id).unwrap();
    for (request_id, created_at) in [
        (signed.request_id, 1_000_i64),
        (rejected.request_id, 2_000),
        (awaiting.request_id, 3_000),
        (other.request_id, 4_000),
    ] {
        store
            .database
            .connection
            .execute(
                "UPDATE pending_messages SET created_at = ?2 WHERE request_id = ?1",
                params![request_id, created_at],
            )
            .unwrap();
    }

    let primary = store.list(Some("primary"), 3).unwrap();
    assert_eq!(
        primary
            .iter()
            .map(|request| (request.request_id, request.status))
            .collect::<Vec<_>>(),
        vec![
            (awaiting.request_id, MessageStatus::AwaitingApproval),
            (rejected.request_id, MessageStatus::Rejected),
            (signed.request_id, MessageStatus::Signed),
        ]
    );
    assert_eq!(store.list(None, 1).unwrap()[0].request_id, other.request_id);
    assert!(store.list(Some("not a wallet id"), 10).is_err());
    assert!(store.list(None, 0).is_err());
    assert!(store.list(None, 1_001).is_err());
}

#[test]
fn chainless_requests_deduplicate_and_stay_distinct_from_chained_ones() {
    let (_directory, mut store) = store();
    let message = b"gm".to_vec();
    let first = store
        .create("primary", None, &message, MessageEncoding::Text, None)
        .unwrap();
    assert!(first.chain_id.is_none());
    let repeated = store
        .create("primary", None, &message, MessageEncoding::Text, None)
        .unwrap();
    assert_eq!(first.request_id, repeated.request_id);

    let chained = store
        .create("primary", Some("1"), &message, MessageEncoding::Text, None)
        .unwrap();
    assert_ne!(first.request_id, chained.request_id);
    assert_eq!(store.awaiting_approval(None).unwrap().len(), 2);
}

#[test]
fn rejection_is_terminal_and_digest_is_bound() {
    let (_directory, mut store) = store();
    let request = store
        .create("primary", None, b"gm", MessageEncoding::Text, None)
        .unwrap();
    assert!(
        store
            .store_signature(
                request.request_id,
                "primary",
                B256::repeat_byte(0xEE),
                &format!("0x{}", "22".repeat(65)),
            )
            .is_err()
    );
    assert_eq!(
        store.reject(request.request_id).unwrap().status,
        MessageStatus::Rejected
    );
    assert!(store.reject(request.request_id).is_err());
}

#[test]
fn a_signature_cannot_be_written_into_another_wallets_row() {
    // The caller names the wallet whose key signed, and the row names the
    // wallet that asked. A signature from one written into the other's row
    // would leave the database claiming an approval that wallet never gave.
    let (_directory, mut store) = store();
    let request = store
        .create("primary", None, b"gm", MessageEncoding::Text, None)
        .unwrap();
    assert!(
        store
            .store_signature(
                request.request_id,
                "secondary",
                message_digest(b"gm"),
                &format!("0x{}", "11".repeat(65)),
            )
            .is_err()
    );
    assert_eq!(
        store.get(request.request_id).unwrap().status,
        MessageStatus::AwaitingApproval
    );
}

#[test]
fn a_tampered_message_row_never_binds_a_signature_to_other_bytes() {
    let (_directory, mut store) = store();
    let request = store
        .create("primary", None, b"gm", MessageEncoding::Text, None)
        .unwrap();
    store
        .database
        .connection
        .execute(
            "UPDATE pending_messages SET message = ?2 WHERE request_id = ?1",
            params![request.request_id, b"send everything".as_slice()],
        )
        .unwrap();
    assert!(store.get(request.request_id).is_err());
}

#[test]
fn two_dapps_asking_for_the_same_bytes_get_two_decisions() {
    // Deduplication exists so an agent re-asking does not queue twice. Keyed
    // on wallet, chain, and digest alone, it also merged two *different*
    // dapps' identical requests into one row -- so one approval served both,
    // whichever was in front of the person named the row, and either could
    // reject or consume the other's request.
    let (_directory, mut store) = store();
    let first = store
        .create(
            "primary",
            Some("1"),
            b"gm",
            MessageEncoding::Text,
            Some("app.example"),
        )
        .unwrap();
    let repeat = store
        .create(
            "primary",
            Some("1"),
            b"gm",
            MessageEncoding::Text,
            Some("app.example"),
        )
        .unwrap();
    assert_eq!(first.request_id, repeat.request_id, "one dapp, one row");
    assert_eq!(first.requester.as_deref(), Some("app.example"));

    let other = store
        .create(
            "primary",
            Some("1"),
            b"gm",
            MessageEncoding::Text,
            Some("evil.example"),
        )
        .unwrap();
    assert_ne!(first.request_id, other.request_id);
    assert_eq!(other.requester.as_deref(), Some("evil.example"));
    assert_eq!(store.awaiting_approval(None).unwrap().len(), 2);

    // An unnamed asker is still deduplicated against another unnamed one: two
    // MCP agents are indistinguishable, and the queue is a list of decisions a
    // person has to make.
    let agent = store
        .create("primary", Some("1"), b"gm", MessageEncoding::Text, None)
        .unwrap();
    let again = store
        .create("primary", Some("1"), b"gm", MessageEncoding::Text, None)
        .unwrap();
    assert_eq!(agent.request_id, again.request_id);
    assert!(agent.requester.is_none());
    assert_eq!(store.awaiting_approval(None).unwrap().len(), 3);
}

/// `escape_for_display` tested controls and bidi only -- a narrower copy of
/// part of the shared predicate -- so every invisible-format character passed
/// through unescaped into the text a person reads before signing it.
#[test]
fn invisible_characters_are_escaped_in_the_message_a_person_reads() {
    let hidden = "send 1\u{200b}0 ETH\u{fe0f}";
    let escaped = escape_for_display(hidden);
    assert!(
        escaped.contains("\\u{200b}"),
        "a zero-width space between digits has to be visible: {escaped}"
    );
    assert!(
        escaped.contains("\\u{fe0f}"),
        "so does a glyph-changing selector: {escaped}"
    );
    assert!(
        !escaped.contains('\u{200b}') && !escaped.contains('\u{fe0f}'),
        "and neither survives raw: {escaped}"
    );

    // Ordinary text is untouched, so the escaping stays readable.
    assert_eq!(escape_for_display("send 10 ETH"), "send 10 ETH");
}
