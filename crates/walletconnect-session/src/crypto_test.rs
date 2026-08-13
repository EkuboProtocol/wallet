//! Tests for [`super`].
//!
//! The vectors below were produced by an independent implementation — Node's
//! built-in `diffieHellman`, `hkdfSync`, and `chacha20-poly1305` — rather than
//! by this code. That is the whole point of having them: a round-trip test
//! passes just as happily when both halves are wrong in the same way, and the
//! failure mode this module actually has to avoid is being self-consistently
//! incompatible with every dapp in the world.

use super::*;

/// Fixed X25519 secret for the wallet side of the vector.
const WALLET_SECRET: [u8; 32] = [1; 32];
/// The dapp's public key, derived from the secret `[2; 32]`.
const DAPP_PUBLIC: &str = "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59";
/// What an independent implementation derives from that pair.
const EXPECTED_SYM_KEY: &str = "cfe64b3a58371451aa931b549552ee76ba01b9e87e196eb7fe91ad4594913244";
const EXPECTED_TOPIC: &str = "7ea0d8e3085cce12bf0ce3d9f6e832632dce2a10232d8b950c3ff9fee3fd9732";
const PLAINTEXT: &str = r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}"#;
const ENVELOPE_TYPE_0_VECTOR: &str = "AAsLCwsLCwsLCwsLC9eJsVz5phnYj6wtsR0o6r/QcZmyyKVJJILp71IrgPDaQcViPeeBOcpIAgVQMQO7fIwwNKnSnB+u1CV1SYVpHHiOItjWvlyLWmA9AbK3Sg==";
const ENVELOPE_TYPE_1_VECTOR: &str = "Ac6NOtHMtjPse3DBeBSlx27NApaFBQ00R0W6BYcOWH1ZCwsLCwsLCwsLCwsL14mxXPmmGdiPrC2xHSjqv9BxmbLIpUkkgunvUiuA8NpBxWI954E5ykgCBVAxA7t8jDA0qdKcH67UJXVJhWkceI4i2Na+XItaYD0BsrdK";

fn wallet_agreement() -> KeyAgreement {
    KeyAgreement {
        secret: WALLET_SECRET,
    }
}

#[test]
fn the_session_key_matches_an_independent_implementation() {
    let derived = wallet_agreement().derive(DAPP_PUBLIC).unwrap();
    // The topic is the hash of the key's *bytes*. Hashing its hex spelling
    // instead produces a perfectly plausible 64-character topic that no peer
    // is ever listening on, and nothing else in the protocol would complain.
    assert_eq!(derived.topic(), EXPECTED_TOPIC);
}

#[test]
fn the_public_key_matches_an_independent_implementation() {
    assert_eq!(
        wallet_agreement().public_key_hex(),
        "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209"
    );
}

#[test]
fn an_envelope_sealed_elsewhere_opens_here() {
    let key = SymKey::from_hex(EXPECTED_SYM_KEY).unwrap();
    let envelope = Envelope::decode(ENVELOPE_TYPE_0_VECTOR).unwrap();
    assert!(envelope.sender_public_key().is_none());
    assert_eq!(envelope.open(&key).unwrap(), PLAINTEXT);
}

#[test]
fn a_type_1_envelope_exposes_its_sender_key_and_still_opens() {
    let key = SymKey::from_hex(EXPECTED_SYM_KEY).unwrap();
    let envelope = Envelope::decode(ENVELOPE_TYPE_1_VECTOR).unwrap();
    assert_eq!(
        envelope.sender_public_key().map(hex::encode),
        Some(DAPP_PUBLIC.to_owned())
    );
    assert_eq!(envelope.open(&key).unwrap(), PLAINTEXT);
}

#[test]
fn sealing_round_trips_and_never_repeats_a_nonce() {
    let key = SymKey::from_hex(EXPECTED_SYM_KEY).unwrap();
    let first = seal(&key, PLAINTEXT).unwrap();
    let second = seal(&key, PLAINTEXT).unwrap();
    assert_ne!(
        first, second,
        "the same plaintext sealed twice produced identical bytes, so the nonce was reused"
    );
    for envelope in [&first, &second] {
        assert_eq!(
            Envelope::decode(envelope).unwrap().open(&key).unwrap(),
            PLAINTEXT
        );
    }
}

#[test]
fn a_tampered_envelope_does_not_open() {
    let key = SymKey::from_hex(EXPECTED_SYM_KEY).unwrap();
    let sealed = seal(&key, PLAINTEXT).unwrap();
    let mut bytes = BASE64.decode(&sealed).unwrap();
    // Flip a bit inside the ciphertext, past the type byte and the nonce.
    let last = bytes.len() - 20;
    bytes[last] ^= 0x01;
    let tampered = BASE64.encode(&bytes);
    assert!(Envelope::decode(&tampered).unwrap().open(&key).is_err());
}

#[test]
fn the_wrong_key_does_not_open_an_envelope() {
    let key = SymKey::from_hex(EXPECTED_SYM_KEY).unwrap();
    let other = SymKey::from_hex(&"ab".repeat(32)).unwrap();
    let sealed = seal(&key, PLAINTEXT).unwrap();
    assert!(Envelope::decode(&sealed).unwrap().open(&other).is_err());
}

#[test]
fn a_low_order_peer_key_is_refused() {
    // The all-zero point drives every X25519 shared secret to zero, whatever
    // this side's secret is. A peer that sends it is choosing the session key
    // unilaterally, so the derivation must fail rather than produce one.
    let error = wallet_agreement()
        .derive(&"00".repeat(32))
        .expect_err("an all-zero peer key was accepted");
    assert!(format!("{error}").contains("low-order"), "{error}");
}

#[test]
fn a_truncated_envelope_is_refused_rather_than_indexed_into() {
    // Everything shorter than a type byte, a nonce, and a tag. Each of these
    // would be an out-of-bounds slice if the lengths were not checked first,
    // and all of them are three characters of base64 to send.
    for bytes in [vec![], vec![0], vec![0, 1, 2], vec![1; 20], vec![1; 44]] {
        let envelope = BASE64.encode(&bytes);
        assert!(
            Envelope::decode(&envelope).is_err(),
            "a {}-byte envelope was accepted",
            bytes.len()
        );
    }
}

#[test]
fn an_unknown_envelope_type_is_refused() {
    // Type 2 is link mode: the payload travels unencrypted. Treating it as
    // authenticated because it parsed would accept an unsigned instruction.
    let mut bytes = vec![2u8];
    bytes.extend_from_slice(&[0; 40]);
    let error = Envelope::decode(&BASE64.encode(&bytes)).expect_err("type 2 was accepted");
    assert!(format!("{error}").contains("envelope type 2"), "{error}");
}

#[test]
fn an_all_zero_symmetric_key_is_refused() {
    assert!(SymKey::from_hex(&"00".repeat(32)).is_err());
    assert!(
        SymKey::from_hex("abcd").is_err(),
        "a short key was accepted"
    );
    assert!(SymKey::from_hex(&"zz".repeat(32)).is_err());
}

#[test]
fn the_client_identity_matches_the_did_key_encoding() {
    let identity = ClientIdentity { seed: [3; 32] };
    // Produced independently; an ed25519 did:key always renders as z6Mk… ,
    // which is the cheap check that the multicodec prefix is right.
    assert_eq!(
        identity.did_key(),
        "did:key:z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZc8rHPrf2"
    );
}

#[test]
fn the_relay_token_is_a_signed_jwt_the_relay_can_verify() {
    use ed25519_dalek::Verifier as _;

    let identity = ClientIdentity { seed: [3; 32] };
    let token = identity
        .relay_jwt("wss://relay.example.org", 1_700_000_000, 86_400)
        .unwrap();
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3);

    let header: serde_json::Value =
        serde_json::from_slice(&BASE64URL.decode(segments[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "JWT");

    let payload: serde_json::Value =
        serde_json::from_slice(&BASE64URL.decode(segments[1]).unwrap()).unwrap();
    assert_eq!(payload["iss"], identity.did_key());
    assert_eq!(payload["aud"], "wss://relay.example.org");
    assert_eq!(payload["iat"], 1_700_000_000_i64);
    assert_eq!(payload["exp"], 1_700_086_400_i64);

    // The relay checks the signature against the key named in `iss`, so this
    // test does the same rather than trusting that the bytes were assembled in
    // the right order.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
    let signature =
        ed25519_dalek::Signature::from_slice(&BASE64URL.decode(segments[2]).unwrap()).unwrap();
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    signing_key
        .verifying_key()
        .verify(signing_input.as_bytes(), &signature)
        .expect("the relay token did not verify against its own issuer key");
}

#[test]
fn two_relay_tokens_never_share_a_subject() {
    let identity = ClientIdentity { seed: [3; 32] };
    let subject = |token: String| -> String {
        let payload = token.split('.').nth(1).unwrap().to_owned();
        let payload: serde_json::Value =
            serde_json::from_slice(&BASE64URL.decode(payload).unwrap()).unwrap();
        payload["sub"].as_str().unwrap().to_owned()
    };
    let first = subject(identity.relay_jwt("wss://relay", 1, 10).unwrap());
    let second = subject(identity.relay_jwt("wss://relay", 1, 10).unwrap());
    assert_ne!(first, second);
}
