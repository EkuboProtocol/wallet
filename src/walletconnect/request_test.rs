//! Tests for [`super`].

use super::*;
use serde_json::json;

const WALLET: &str = "0x1111111111111111111111111111111111111111";
const TARGET: &str = "0x2222222222222222222222222222222222222222";

#[test]
fn an_ordinary_transaction_parses() {
    let request = parse_send_transaction(&json!([{
        "from": WALLET,
        "to": TARGET,
        "data": "0xa9059cbb",
        "value": "0x2386f26fc10000",
        "gas": "0x5208",
    }]))
    .unwrap();
    assert_eq!(request.from, WALLET.parse::<Address>().unwrap());
    assert_eq!(request.to, TARGET.parse::<Address>().unwrap());
    assert_eq!(request.data.as_ref(), hex::decode("a9059cbb").unwrap());
    assert_eq!(request.value, U256::from(10_000_000_000_000_000_u64));
    assert_eq!(request.suggested_gas, Some(U256::from(21_000)));
    assert!(request.overridden.is_empty());
}

#[test]
fn a_missing_value_or_calldata_means_zero_and_empty() {
    let request = parse_send_transaction(&json!([{ "from": WALLET, "to": TARGET }])).unwrap();
    assert_eq!(request.value, U256::ZERO);
    assert!(request.data.is_empty());
    assert_eq!(request.suggested_gas, None);
}

#[test]
fn the_fields_the_wallet_decides_itself_are_named_rather_than_dropped() {
    // A dapp that pinned a nonce and a gas price asked for something specific
    // and is not getting it. The reviewer is told, because a wallet that
    // silently disagrees with the request it is showing is lying by omission.
    let request = parse_send_transaction(&json!([{
        "from": WALLET,
        "to": TARGET,
        "nonce": "0x5",
        "gasPrice": "0x3b9aca00",
        "chainId": "0x1",
    }]))
    .unwrap();
    assert_eq!(request.overridden, ["nonce", "gasPrice", "chainId"]);
}

#[test]
fn a_null_field_is_not_treated_as_a_field_that_was_set() {
    let request = parse_send_transaction(&json!([{
        "from": WALLET, "to": TARGET, "nonce": null, "value": null, "data": null,
    }]))
    .unwrap();
    assert!(request.overridden.is_empty());
    assert_eq!(request.value, U256::ZERO);
}

#[test]
fn input_is_accepted_as_a_spelling_of_data() {
    let request =
        parse_send_transaction(&json!([{ "from": WALLET, "to": TARGET, "input": "0xdeadbeef" }]))
            .unwrap();
    assert_eq!(request.data.as_ref(), hex::decode("deadbeef").unwrap());

    // The same value under both names is not a conflict.
    let agreed = parse_send_transaction(&json!([{
        "from": WALLET, "to": TARGET, "data": "0xdeadbeef", "input": "0xdeadbeef",
    }]))
    .unwrap();
    assert_eq!(agreed.data.as_ref(), hex::decode("deadbeef").unwrap());
}

#[test]
fn data_and_input_disagreeing_is_refused_rather_than_resolved() {
    let error = parse_send_transaction(&json!([{
        "from": WALLET, "to": TARGET, "data": "0xdeadbeef", "input": "0xfeedface",
    }]))
    .expect_err("a self-contradicting transaction was accepted");
    assert!(format!("{error}").contains("ambiguous"), "{error}");
}

#[test]
fn a_contract_deployment_is_refused_by_name() {
    // `to` absent means creation. Dropping the field would silently turn this
    // into a call to the zero address, which is a real way to burn funds.
    for transaction in [
        json!([{ "from": WALLET, "data": "0x60806040" }]),
        json!([{ "from": WALLET, "to": null, "data": "0x60806040" }]),
    ] {
        let error = parse_send_transaction(&transaction).expect_err("a deployment was accepted");
        assert!(format!("{error}").contains("deploys a contract"), "{error}");
    }
}

#[test]
fn a_decimal_quantity_is_refused_rather_than_guessed_at() {
    // "100" is 256 to a hex reader and 100 to a decimal one. For a value in
    // wei that is a 2.56x error in the amount leaving the account, so there is
    // no safe way to accept it.
    let error = parse_send_transaction(&json!([{
        "from": WALLET, "to": TARGET, "value": "1000000000000000000",
    }]))
    .expect_err("a decimal value was accepted");
    assert!(format!("{error:#}").contains("hex"), "{error:#}");

    let error = parse_send_transaction(&json!([{ "from": WALLET, "to": TARGET, "value": 1000 }]))
        .expect_err("a JSON number value was accepted");
    assert!(format!("{error:#}").contains("hex"), "{error:#}");
}

#[test]
fn malformed_calldata_is_refused() {
    for data in ["deadbeef", "0xnothex", "0xabc"] {
        assert!(
            parse_send_transaction(&json!([{ "from": WALLET, "to": TARGET, "data": data }]))
                .is_err(),
            "{data} was accepted as calldata"
        );
    }
    // The two spellings of "no calldata" both work.
    for data in ["", "0x"] {
        let request =
            parse_send_transaction(&json!([{ "from": WALLET, "to": TARGET, "data": data }]))
                .unwrap();
        assert!(request.data.is_empty());
    }
}

#[test]
fn personal_sign_accepts_both_parameter_orders() {
    let expected = WALLET.parse::<Address>().unwrap();
    let hex_message = format!("0x{}", hex::encode("hello"));

    let (message, address, was_hex) = parse_personal_sign(&json!([hex_message, WALLET])).unwrap();
    assert_eq!(message, b"hello");
    assert_eq!(address, expected);
    assert!(was_hex);

    // Reversed, as several dapps send it.
    let (message, address, _) = parse_personal_sign(&json!([WALLET, hex_message])).unwrap();
    assert_eq!(message, b"hello");
    assert_eq!(address, expected);
}

#[test]
fn a_personal_sign_message_that_is_not_hex_is_taken_literally() {
    let (message, _, was_hex) =
        parse_personal_sign(&json!(["Sign in to Example", WALLET])).unwrap();
    assert_eq!(message, b"Sign in to Example");
    assert!(!was_hex);

    // A message that starts with 0x but is not valid hex is text that happens
    // to start with those two characters, not malformed hex.
    let (message, _, was_hex) = parse_personal_sign(&json!(["0xZZ not hex", WALLET])).unwrap();
    assert_eq!(message, b"0xZZ not hex");
    assert!(!was_hex);

    // Odd digit count is likewise not hex.
    let (message, _, was_hex) = parse_personal_sign(&json!(["0xabc", WALLET])).unwrap();
    assert_eq!(message, b"0xabc");
    assert!(!was_hex);
}

#[test]
fn personal_sign_without_an_address_is_refused() {
    let error = parse_personal_sign(&json!(["hello", "world"]))
        .expect_err("a signer-less request was accepted");
    assert!(format!("{error}").contains("address"), "{error}");
    assert!(parse_personal_sign(&json!(["hello"])).is_err());
    assert!(parse_personal_sign(&json!({})).is_err());
}

#[test]
fn typed_data_arrives_as_a_string_or_an_object_in_either_order() {
    let payload = json!({
        "types": { "EIP712Domain": [] },
        "primaryType": "Order",
        "domain": { "chainId": 1 },
        "message": {},
    });
    let expected = WALLET.parse::<Address>().unwrap();

    let (address, parsed) = parse_sign_typed_data(&json!([WALLET, payload])).unwrap();
    assert_eq!(address, expected);
    assert_eq!(parsed["primaryType"], "Order");

    let as_string = serde_json::to_string(&payload).unwrap();
    let (address, parsed) = parse_sign_typed_data(&json!([WALLET, as_string])).unwrap();
    assert_eq!(address, expected);
    assert_eq!(parsed["primaryType"], "Order");

    let (address, parsed) = parse_sign_typed_data(&json!([payload, WALLET])).unwrap();
    assert_eq!(address, expected);
    assert_eq!(parsed["primaryType"], "Order");
}

#[test]
fn a_typed_data_payload_that_is_not_an_object_is_refused() {
    assert!(parse_sign_typed_data(&json!([WALLET, "not json"])).is_err());
    assert!(parse_sign_typed_data(&json!([WALLET, "[1,2,3]"])).is_err());
    assert!(parse_sign_typed_data(&json!([WALLET])).is_err());
}

#[test]
fn switching_chains_reads_the_hex_id() {
    assert_eq!(
        parse_switch_chain(&json!([{ "chainId": "0xa4b1" }])).unwrap(),
        42_161
    );
    assert!(parse_switch_chain(&json!([{ "chainId": "1" }])).is_err());
    assert!(parse_switch_chain(&json!([{}])).is_err());
    assert!(parse_switch_chain(&json!([])).is_err());
}
