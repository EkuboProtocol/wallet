//! Tests for [`super`].

use super::*;

const SYM_KEY: &str = "cfe64b3a58371451aa931b549552ee76ba01b9e87e196eb7fe91ad4594913244";
const TOPIC: &str = "7ea0d8e3085cce12bf0ce3d9f6e832632dce2a10232d8b950c3ff9fee3fd9732";

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 0).unwrap()
}

fn valid() -> String {
    format!("wc:{TOPIC}@2?relay-protocol=irn&symKey={SYM_KEY}")
}

#[test]
fn a_well_formed_link_parses() {
    let pairing = PairingUri::parse(&valid(), now()).unwrap();
    assert_eq!(pairing.topic, TOPIC);
    assert_eq!(pairing.sym_key.to_hex(), SYM_KEY);
    assert_eq!(pairing.relay_protocol, "irn");
    assert!(pairing.expiry.is_none());
}

#[test]
fn surrounding_whitespace_from_a_paste_is_tolerated() {
    let pasted = format!("  {}\n", valid());
    assert!(PairingUri::parse(&pasted, now()).is_ok());
}

#[test]
fn unknown_query_parameters_are_ignored_rather_than_refused() {
    // `methods` is real and this wallet does not use it; the rest stands in
    // for whatever a later revision adds. Refusing them would break pairing
    // against newer dapps and buy nothing, since nothing unknown is acted on.
    let uri = format!(
        "wc:{TOPIC}@2?relay-protocol=irn&symKey={SYM_KEY}&methods=[wc_sessionPropose]&somethingNew=1"
    );
    assert!(PairingUri::parse(&uri, now()).is_ok());
}

#[test]
fn an_expired_link_is_refused_with_advice_rather_than_a_parse_error() {
    let expiry = now().timestamp() - 1;
    let uri = format!("wc:{TOPIC}@2?relay-protocol=irn&symKey={SYM_KEY}&expiryTimestamp={expiry}");
    let error = PairingUri::parse(&uri, now()).expect_err("an expired link was accepted");
    let message = format!("{error}");
    assert!(message.contains("expired"), "{message}");
    assert!(message.contains("paste the new one"), "{message}");
}

#[test]
fn a_link_expiring_later_is_accepted_and_keeps_its_expiry() {
    let expiry = now().timestamp() + 300;
    let uri = format!("wc:{TOPIC}@2?relay-protocol=irn&symKey={SYM_KEY}&expiryTimestamp={expiry}");
    let pairing = PairingUri::parse(&uri, now()).unwrap();
    assert_eq!(pairing.expiry.map(|value| value.timestamp()), Some(expiry));
}

#[test]
fn a_version_1_link_says_so_instead_of_failing_obscurely() {
    let uri = format!("wc:{TOPIC}@1?bridge=https%3A%2F%2Fbridge.example&key={SYM_KEY}");
    let error = PairingUri::parse(&uri, now()).expect_err("a v1 link was accepted");
    assert!(format!("{error}").contains("v1"), "{error}");
}

#[test]
fn a_truncated_paste_is_diagnosed_as_one() {
    // Half a symKey: the single most likely way for a copy to go wrong, and
    // the error has to say which half is missing rather than "invalid URI".
    let short = &SYM_KEY[..40];
    let uri = format!("wc:{TOPIC}@2?relay-protocol=irn&symKey={short}");
    let error = PairingUri::parse(&uri, now()).expect_err("a truncated key was accepted");
    assert!(format!("{error}").contains("32 bytes"), "{error}");

    let uri = format!("wc:{TOPIC}@2?relay-protocol=irn");
    let error = PairingUri::parse(&uri, now()).expect_err("a keyless link was accepted");
    assert!(format!("{error}").contains("truncated"), "{error}");

    let error = PairingUri::parse(&format!("wc:{TOPIC}"), now())
        .expect_err("a link with no version was accepted");
    assert!(format!("{error}").contains("truncated"), "{error}");
}

#[test]
fn a_topic_that_is_not_32_bytes_of_hex_is_refused() {
    let uri = format!("wc:not-a-topic@2?relay-protocol=irn&symKey={SYM_KEY}");
    assert!(PairingUri::parse(&uri, now()).is_err());
}

#[test]
fn an_unimplemented_relay_protocol_is_refused_by_name() {
    let uri = format!("wc:{TOPIC}@2?relay-protocol=waku&symKey={SYM_KEY}");
    let error = PairingUri::parse(&uri, now()).expect_err("an unknown relay was accepted");
    assert!(format!("{error}").contains("waku"), "{error}");
}

#[test]
fn something_that_is_not_a_pairing_link_is_told_where_to_find_one() {
    for input in ["", "   ", "https://example.com", "ethereum:0xabc"] {
        let error = PairingUri::parse(input, now()).expect_err("{input} was accepted");
        let message = format!("{error}");
        assert!(
            message.contains("wc:") || message.contains("no pairing URI"),
            "{message}"
        );
    }
}

#[test]
fn the_paste_guard_only_admits_wc_links() {
    assert!(looks_like_pairing_uri("wc:abc@2"));
    assert!(looks_like_pairing_uri("   wc:abc@2  "));
    assert!(!looks_like_pairing_uri("https://example.com"));
    assert!(!looks_like_pairing_uri(""));
}
