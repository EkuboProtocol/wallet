//! Tests for [`super`].

use super::*;
use serde_json::json;

const WALLET: &str = "0x1111111111111111111111111111111111111111";

/// The account the session signs for, which is what settles the parameter
/// order when both parameters are address-shaped.
fn wallet() -> Address {
    WALLET.parse().expect("the fixture address parses")
}
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

    let (message, address, was_hex) =
        parse_personal_sign(&json!([hex_message, WALLET]), wallet()).unwrap();
    assert_eq!(message, b"hello");
    assert_eq!(address, expected);
    assert!(was_hex);

    // Reversed, as several dapps send it.
    let (message, address, _) =
        parse_personal_sign(&json!([WALLET, hex_message]), wallet()).unwrap();
    assert_eq!(message, b"hello");
    assert_eq!(address, expected);
}

#[test]
fn a_personal_sign_message_that_is_not_hex_is_taken_literally() {
    let (message, _, was_hex) =
        parse_personal_sign(&json!(["Sign in to Example", WALLET]), wallet()).unwrap();
    assert_eq!(message, b"Sign in to Example");
    assert!(!was_hex);

    // A message that starts with 0x but is not valid hex is text that happens
    // to start with those two characters, not malformed hex.
    let (message, _, was_hex) =
        parse_personal_sign(&json!(["0xZZ not hex", WALLET]), wallet()).unwrap();
    assert_eq!(message, b"0xZZ not hex");
    assert!(!was_hex);

    // Odd digit count is likewise not hex.
    let (message, _, was_hex) = parse_personal_sign(&json!(["0xabc", WALLET]), wallet()).unwrap();
    assert_eq!(message, b"0xabc");
    assert!(!was_hex);
}

#[test]
fn personal_sign_without_an_address_is_refused() {
    let error = parse_personal_sign(&json!(["hello", "world"]), wallet())
        .expect_err("a signer-less request was accepted");
    assert!(format!("{error}").contains("address"), "{error}");
    assert!(parse_personal_sign(&json!(["hello"]), wallet()).is_err());
    assert!(parse_personal_sign(&json!({}), wallet()).is_err());
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

fn batch(calls: &Value) -> Value {
    json!([{
        "version": "2.0.0",
        "from": WALLET,
        "chainId": "0x1",
        "atomicRequired": true,
        "calls": calls,
    }])
}

#[test]
fn a_batch_of_calls_parses_in_the_order_it_was_given() {
    let request = parse_send_calls(&batch(&json!([
        { "to": TARGET, "data": "0xa9059cbb", "value": "0x1" },
        { "to": WALLET },
    ])))
    .unwrap();
    assert_eq!(request.from, Some(WALLET.parse::<Address>().unwrap()));
    assert_eq!(request.chain_id, 1);
    assert!(request.atomic_required);
    assert_eq!(request.calls.len(), 2);
    // Order is the whole point of a batch: an approval and a swap in the other
    // order is a different transaction.
    assert_eq!(request.calls[0].to, TARGET.parse::<Address>().unwrap());
    assert_eq!(request.calls[0].value, U256::from(1));
    // A call may carry neither data nor value; it is a bare native send.
    assert_eq!(request.calls[1].to, WALLET.parse::<Address>().unwrap());
    assert!(request.calls[1].data.is_empty());
    assert_eq!(request.calls[1].value, U256::ZERO);
}

/// `from` is optional in EIP-5792 — the wallet may pick the account — so an
/// absent one means "the connected account", not a malformed request.
#[test]
fn a_batch_without_a_from_is_for_the_connected_account() {
    let request = parse_send_calls(&json!([{
        "version": "2.0.0",
        "chainId": "0xa",
        "atomicRequired": false,
        "calls": [{ "to": TARGET }],
    }]))
    .unwrap();
    assert_eq!(request.from, None);
    assert_eq!(request.chain_id, 10);
    assert!(!request.atomic_required);
}

#[test]
fn a_batch_this_wallet_cannot_answer_is_refused_rather_than_trimmed() {
    // The 1.0.0 response was a bare string where 2.0.0 is an object, so
    // answering an older caller would hand it a shape it cannot read.
    assert!(
        parse_send_calls(&json!([{
            "version": "1.0.0",
            "chainId": "0x1",
            "atomicRequired": true,
            "calls": [{ "to": TARGET }],
        }]))
        .is_err()
    );

    for missing in [
        json!([{ "chainId": "0x1", "atomicRequired": true, "calls": [{ "to": TARGET }] }]),
        json!([{ "version": "2.0.0", "atomicRequired": true, "calls": [{ "to": TARGET }] }]),
        json!([{ "version": "2.0.0", "chainId": "0x1", "calls": [{ "to": TARGET }] }]),
        json!([{ "version": "2.0.0", "chainId": "0x1", "atomicRequired": true }]),
    ] {
        assert!(
            parse_send_calls(&missing).is_err(),
            "{missing} was accepted"
        );
    }

    // A decimal chain id and an empty batch are both refusals, not guesses.
    assert!(
        parse_send_calls(&json!([{
            "version": "2.0.0",
            "chainId": "1",
            "atomicRequired": true,
            "calls": [{ "to": TARGET }],
        }]))
        .is_err()
    );
    assert!(parse_send_calls(&batch(&json!([]))).is_err());

    // A call with no target deploys a contract, which no plan step expresses.
    let error = parse_send_calls(&batch(&json!([{ "to": TARGET }, { "data": "0x60" }])))
        .expect_err("a deployment was accepted");
    assert!(format!("{error}").contains("call 2"), "{error}");
}

/// A capability the dapp did not mark optional is one the wallet has to refuse
/// by name; silently not honoring it is the failure mode the field exists to
/// prevent.
#[test]
fn required_capabilities_are_collected_and_optional_ones_ignored() {
    let request = parse_send_calls(&json!([{
        "version": "2.0.0",
        "chainId": "0x1",
        "atomicRequired": true,
        "capabilities": {
            "paymasterService": { "url": "https://example.com" },
            "auxiliaryFunds": { "optional": true },
        },
        "calls": [{ "to": TARGET, "capabilities": { "flowControl": {} } }],
    }]))
    .unwrap();
    assert_eq!(
        request.required_capabilities,
        vec!["flowControl".to_owned(), "paymasterService".to_owned()]
    );

    let plain = parse_send_calls(&batch(&json!([{ "to": TARGET }]))).unwrap();
    assert!(plain.required_capabilities.is_empty());
}

#[test]
fn a_capabilities_query_reads_the_address_and_any_chain_filter() {
    let (address, chains) = parse_get_capabilities(&json!([WALLET, ["0x1", "0xa4b1"]])).unwrap();
    assert_eq!(address, WALLET.parse::<Address>().unwrap());
    assert_eq!(chains, vec![1, 42_161]);

    // No filter means every chain, which is what an absent second parameter
    // asks for.
    let (_, chains) = parse_get_capabilities(&json!([WALLET])).unwrap();
    assert!(chains.is_empty());

    assert!(parse_get_capabilities(&json!([])).is_err());
    assert!(parse_get_capabilities(&json!(["not an address"])).is_err());
}

#[test]
fn a_status_query_reads_one_batch_id() {
    assert_eq!(parse_get_calls_status(&json!(["0xabc"])).unwrap(), "0xabc");
    assert!(parse_get_calls_status(&json!([])).is_err());
    assert!(parse_get_calls_status(&json!([""])).is_err());
    assert!(parse_get_calls_status(&json!([5])).is_err());
}

#[test]
fn an_address_shaped_message_does_not_become_the_signer() {
    // A 20-byte message is a perfectly good EIP-191 input, and one that is
    // address-shaped makes both parameters parse as addresses. Taking the
    // second regardless read the message as the signer for the `[address,
    // message]` order half the ecosystem sends, and the foreign-signer check
    // then refused the request every time.
    let message = "0x2222222222222222222222222222222222222222";

    let (bytes, signer, _) = parse_personal_sign(&json!([WALLET, message]), wallet()).unwrap();
    assert_eq!(signer, wallet());
    assert_eq!(
        bytes,
        hex::decode(message.trim_start_matches("0x")).unwrap()
    );

    // The documented order still reads the documented way.
    let (bytes, signer, _) = parse_personal_sign(&json!([message, WALLET]), wallet()).unwrap();
    assert_eq!(signer, wallet());
    assert_eq!(
        bytes,
        hex::decode(message.trim_start_matches("0x")).unwrap()
    );

    // Neither one is this session's account, so the reading does not matter:
    // whichever is chosen, the request is refused downstream. The second
    // stands, as it always did.
    let stranger: Address = "0x3333333333333333333333333333333333333333"
        .parse()
        .unwrap();
    let (_, signer, _) = parse_personal_sign(&json!([WALLET, message]), stranger).unwrap();
    assert_eq!(
        signer.to_checksum(None),
        message.parse::<Address>().unwrap().to_checksum(None)
    );
}
