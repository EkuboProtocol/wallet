use super::*;
use alloy::{
    dyn_abi::DynSolValue,
    primitives::{Address, U256, keccak256},
};

fn encode(signature: &str, values: &[DynSolValue]) -> Vec<u8> {
    Function::parse(signature)
        .unwrap()
        .abi_encode_input(values)
        .unwrap()
}

fn matches(signature: &str, body: &[u8]) -> bool {
    let selector = keccak256(signature.as_bytes());
    decode_candidate(signature, selector[..4].try_into().unwrap(), body).is_some()
}

#[test]
fn public_directory_supplies_real_functions_and_arguments() {
    let data = encode(
        "balanceOf(address)",
        &[DynSolValue::Address(Address::repeat_byte(0x11))],
    );
    let candidates = calldata_candidates(&data);
    let candidate = candidates
        .iter()
        .find(|c| c.signature == "balanceOf(address)")
        .unwrap();
    assert!(!candidate.contract_match);
    assert!(
        candidate.arguments[0]
            .1
            .contains("1111111111111111111111111111111111111111")
    );
    assert!(details(&candidates)[0].starts_with("Possible function: "));
}

#[test]
fn missing_extra_and_non_word_arguments_are_rejected() {
    let data = encode("balanceOf(address)", &[DynSolValue::Address(Address::ZERO)]);
    assert!(calldata_candidates(&data[..4]).is_empty());
    assert!(calldata_candidates(&data[..data.len() - 1]).is_empty());
    let mut extra = data;
    extra.extend_from_slice(&[0; 32]);
    assert!(calldata_candidates(&extra).is_empty());
    assert!(calldata_candidates(&[0; 3]).is_empty());
    assert!(calldata_candidates(&vec![0; MAX_BODY + 36]).is_empty());
}

#[test]
fn fixed_width_values_and_padding_must_be_canonical() {
    let mut word = [0_u8; 32];
    word[31] = 2;
    assert!(!matches("f(bool)", &word));
    word[31] = 1;
    assert!(matches("f(bool)", &word));
    word[0] = 1;
    for signature in ["f(address)", "f(uint8)", "f(int8)", "f(bytes4)"] {
        assert!(!matches(signature, &word), "{signature}");
    }
    assert!(matches("f(int8)", &[255; 32]));
    assert!(!matches(
        "f(int8)",
        &[0; 31].into_iter().chain([255]).collect::<Vec<_>>()
    ));
}

#[test]
fn dynamic_offsets_lengths_padding_and_trailing_bytes_are_checked() {
    let data = encode("f(bytes)", &[DynSolValue::Bytes(vec![42])]);
    assert!(matches("f(bytes)", &data[4..]));
    let mut body = data[4..].to_vec();
    body[31] = 64;
    assert!(!matches("f(bytes)", &body));
    let mut body = data[4..].to_vec();
    body[32..64].fill(255);
    assert!(!matches("f(bytes)", &body));
    let mut body = data[4..].to_vec();
    *body.last_mut().unwrap() = 1;
    assert!(!matches("f(bytes)", &body));
    let mut body = data[4..].to_vec();
    body.extend_from_slice(&[0; 32]);
    assert!(!matches("f(bytes)", &body));
}

#[test]
fn selector_collisions_remain_candidates_not_contract_matches() {
    let first = "burn(uint256)";
    let second = "collate_propagate_storage(bytes16)";
    let selector: [u8; 4] = Function::parse(first).unwrap().selector().into();
    assert_eq!(
        Function::parse(second).unwrap().selector().as_slice(),
        selector
    );
    for signature in [first, second] {
        let candidate = decode_candidate(signature, selector, &[0; 32]).unwrap();
        assert!(!candidate.contract_match);
    }
    assert!(decode_candidate("balanceOf(address)", selector, &[0; 32]).is_none());
}

#[test]
fn tuples_and_arrays_require_a_complete_canonical_encoding() {
    let data = encode(
        "f((uint256,address)[])",
        &[DynSolValue::Array(vec![DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from(42), 256),
            DynSolValue::Address(Address::ZERO),
        ])])],
    );
    assert!(matches("f((uint256,address)[])", &data[4..]));
    assert!(!matches(
        "f((uint256,address)[])",
        &data[4..data.len() - 32]
    ));
}

#[test]
fn snapshot_blocks_are_ordered_bounded_and_cover_the_recorded_count() {
    assert_eq!(&DATA[..8], b"EK4BYTE1");
    let count = word(DATA, 8).unwrap();
    let mut total = 0;
    let mut previous = None;
    for index in 0..count {
        let bytes = block(index, count).unwrap();
        let rows = word(&bytes, 0).unwrap();
        assert!(rows <= 128);
        assert_eq!(word(DATA, 12 + index * 12), word(&bytes, 4));
        for row in 0..rows {
            let key = word(&bytes, 4 + row * 12).unwrap();
            assert!(previous.is_none_or(|p| key > p));
            previous = Some(key);
            let start = 4 + rows * 12 + word(&bytes, 8 + row * 12).unwrap();
            let length = word(&bytes, 12 + row * 12).unwrap();
            assert!(std::str::from_utf8(&bytes[start..start + length]).is_ok());
        }
        total += rows;
    }
    let metadata: serde_json::Value =
        serde_json::from_str(include_str!("../fourbyte/snapshot.json")).unwrap();
    assert_eq!(metadata["selectors"].as_u64().unwrap(), total as u64);
}
