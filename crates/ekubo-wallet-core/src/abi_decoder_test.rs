//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{Address, I256};
use alloy::sol_types::SolError;

alloy::sol! {
    error TestFailure(uint256 amount);
}

fn parameter(ty: &str) -> AbiParameterInput {
    AbiParameterInput {
        name: None,
        ty: ty.into(),
        internal_type: None,
        components: None,
    }
}

#[test]
fn a_parameter_descriptor_is_bounded_by_bytes_as_well_as_count() {
    // Few enough entries to pass MAX_COLLECTION_ITEMS, large enough to
    // exceed MAX_ABI_BYTES: the count says nothing about how much each
    // entry carries, which is the gap the named-ABI path already closed.
    let bulky = AbiParameterInput {
        name: Some("n".repeat(4_096)),
        ty: "uint256".into(),
        internal_type: None,
        components: None,
    };
    let input = vec![bulky; 32];
    assert!(serde_json::to_vec(&input).unwrap().len() > MAX_ABI_BYTES);
    assert!(input.len() < MAX_COLLECTION_ITEMS);

    let mut budget = DecodeBudget {
        collection_items_remaining: MAX_COLLECTION_ITEMS,
        decodes_remaining: MAX_TOTAL_DECODES,
    };
    let Err(failure) = decode_parameters("0x", &input, &mut budget) else {
        panic!("an oversized parameter descriptor must be refused");
    };
    assert_eq!(failure.0.code, "resource_limit");
}

#[test]
fn oversized_return_data_is_refused_without_being_scanned() {
    // Not hexadecimal past the prefix, so the old order would have run the
    // whole scan first and reported malformed. The length settles it, and
    // the answer is the ceiling that was actually exceeded.
    let oversized = format!("0x{}", "z".repeat(MAX_RETURN_DATA_BYTES * 2 + 2));
    let failure = validate_return_data(&oversized).unwrap_err();
    assert_eq!(failure.0.code, "resource_limit");
    assert!(!preservable_raw(&oversized));

    // A short non-hex value is still reported as malformed, not as a limit.
    assert_eq!(
        validate_return_data("0xzz").unwrap_err().0.code,
        "malformed_return_data"
    );
}

fn encode(values: &[DynSolValue]) -> String {
    format!(
        "0x{}",
        hex::encode(DynSolValue::Tuple(values.to_vec()).abi_encode_params())
    )
}

#[test]
fn decodes_bounded_custom_error_payloads() {
    let payload = TestFailure {
        amount: U256::from(42),
    }
    .abi_encode();
    let decoded = decode_abi_error(
        &payload,
        &[json!({
            "type": "error",
            "name": "TestFailure",
            "inputs": [{"name": "amount", "type": "uint256"}]
        })],
    )
    .unwrap();
    assert_eq!(decoded.name, "TestFailure");
    assert_eq!(decoded.args, vec![Value::String("42".into())]);
}

#[test]
fn decodes_scalar_parameters_and_rejects_trailing_data() {
    let plan = AbiDecodePlan::AbiParameters {
        parameters: vec![parameter("uint256"), parameter("int128"), parameter("bool")],
        semantic_codecs: Vec::new(),
        required: true,
    };
    let raw = encode(&[
        DynSolValue::Uint(U256::from(9_007_199_254_740_993_u64), 256),
        DynSolValue::Int(I256::try_from(-42_i64).unwrap(), 128),
        DynSolValue::Bool(true),
    ]);
    let decoded = decode_abi_result(&raw, &plan, false);
    assert_eq!(decoded.decode_status, DecodeStatus::Decoded);
    assert_eq!(
        decoded.decoded,
        Some(json!(["9007199254740993", "-42", true]))
    );
    assert!(decoded.return_data.is_none());

    let malformed = decode_abi_result(&format!("{raw}00"), &plan, false);
    assert_eq!(malformed.decode_status, DecodeStatus::Failed);
    assert_eq!(
        malformed
            .decode_error
            .as_ref()
            .map(|error| error.code.as_str()),
        Some("malformed_return_data")
    );
}

#[test]
fn rejects_ambiguous_functions_and_accepts_canonical_signature() {
    let abi = serde_json::from_value::<Vec<Value>>(json!([
            {"type":"function","name":"positions","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
            {"type":"function","name":"positions","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"bool"}]}
        ])).unwrap();
    let ambiguous = AbiDecodePlan::FunctionResult {
        abi: abi.clone(),
        function_name: "positions".into(),
        semantic_codecs: Vec::new(),
        required: true,
    };
    let raw = encode(&[DynSolValue::Bool(true)]);
    assert_eq!(
        decode_abi_result(&raw, &ambiguous, true)
            .decode_error
            .unwrap()
            .code,
        "ambiguous_function"
    );
    let canonical = AbiDecodePlan::FunctionResult {
        abi,
        function_name: "positions(uint256)".into(),
        semantic_codecs: Vec::new(),
        required: false,
    };
    assert_eq!(
        decode_abi_result(&raw, &canonical, true).decoded,
        Some(json!(true))
    );
}

#[test]
fn applies_only_the_exact_pinned_ekubo_codec() {
    let implementation = CodecImplementation {
        ecosystem: "npm".into(),
        registry: ALLOWED_REGISTRY.into(),
        package_url: ALLOWED_PACKAGE_URL.into(),
        export_name: ALLOWED_EXPORT.into(),
        integrity: ALLOWED_INTEGRITY.into(),
    };
    let codec = CodecIdentity {
        id: ALLOWED_CODEC_ID.into(),
        version: 1,
        implementations: vec![implementation],
    };
    let encoded = (U256::from(2_u8) << 94) | (U256::from(1_u8) << 62);
    let raw = format!("0x{encoded:x}");
    let plan = AbiDecodePlan::SemanticValue {
        semantic_type: ALLOWED_SEMANTIC_TYPE.into(),
        codec: codec.clone(),
        required: true,
    };
    assert_eq!(
        decode_abi_result(&raw, &plan, false).decoded.unwrap()["semantic_value"],
        Value::String((U256::from(1_u8) << 128_usize).to_string())
    );
    let mut rejected = codec;
    rejected.implementations[0].integrity = "sha512-untrusted".into();
    let rejected_plan = AbiDecodePlan::SemanticValue {
        semantic_type: ALLOWED_SEMANTIC_TYPE.into(),
        codec: rejected,
        required: true,
    };
    assert_eq!(
        decode_abi_result(&raw, &rejected_plan, false)
            .decode_error
            .unwrap()
            .code,
        "unsupported_codec"
    );
}

#[test]
fn an_out_of_domain_sqrt_ratio_fails_the_decode_rather_than_panicking() {
    // A 32-byte word from `wallet_decode_abi_result`, or a `uint256` a contract
    // returned through `wallet_batch_eth_call`, is not bounded by the codec's
    // 96-bit domain. `(encoded >> 89).to::<u8>()` used to panic on one, taking
    // the request — and the stdio task — with it, where every other malformed
    // input on this path is a structured failure.
    let codec = CodecIdentity {
        id: ALLOWED_CODEC_ID.into(),
        version: 1,
        implementations: vec![CodecImplementation {
            ecosystem: "npm".into(),
            registry: ALLOWED_REGISTRY.into(),
            package_url: ALLOWED_PACKAGE_URL.into(),
            export_name: ALLOWED_EXPORT.into(),
            integrity: ALLOWED_INTEGRITY.into(),
        }],
    };
    let plan = AbiDecodePlan::SemanticValue {
        semantic_type: ALLOWED_SEMANTIC_TYPE.into(),
        codec: codec.clone(),
        required: true,
    };
    for word in [U256::MAX, U256::from(1_u8) << 96_usize] {
        let decoded = decode_abi_result(&format!("0x{word:064x}"), &plan, false);
        assert_eq!(decoded.decode_status, DecodeStatus::Failed);
        assert_eq!(decoded.decode_error.unwrap().code, "codec_failure");
    }

    // The same expression reached from an inline decode plan, where the value
    // is whatever the contract — or the configured RPC — returned.
    let named = |name: &str, ty: &str| AbiParameterInput {
        name: Some(name.into()),
        ty: ty.into(),
        internal_type: None,
        components: None,
    };
    let at_a_path = AbiDecodePlan::AbiParameters {
        parameters: vec![named("sqrt_ratio", "uint256"), named("tick", "int32")],
        semantic_codecs: vec![SemanticCodec {
            path: "sqrt_ratio".into(),
            semantic_type: ALLOWED_SEMANTIC_TYPE.into(),
            codec,
            required: true,
        }],
        required: true,
    };
    let returned = encode(&[
        DynSolValue::Uint(U256::MAX, 256),
        DynSolValue::Int(I256::ZERO, 32),
    ]);
    let decoded = decode_abi_result(&returned, &at_a_path, false);
    assert_eq!(decoded.decode_status, DecodeStatus::Failed);
    assert_eq!(decoded.decode_error.unwrap().code, "codec_failure");

    // The widest value the domain does contain still decodes: every mantissa
    // bit set under the largest exponent, which the guard must not exclude.
    let widest = (U256::from(1_u8) << 96_usize) - U256::from(1_u8);
    let decoded = decode_abi_result(&format!("0x{widest:x}"), &plan, false);
    assert_eq!(decoded.decode_status, DecodeStatus::Decoded);
    assert_eq!(
        decoded.decoded.unwrap()["semantic_value"],
        Value::String(
            (((U256::from(1_u8) << 89_usize) - U256::from(1_u8)) << 129_usize).to_string()
        )
    );
}

#[test]
fn serializes_named_tuple_as_object() {
    let plan: AbiDecodePlan = serde_json::from_value(json!({
        "kind": "abi_parameters",
        "parameters": [{
            "name": "state",
            "type": "tuple",
            "components": [
                {"name":"owner","type":"address"},
                {"name":"amount","type":"uint256"}
            ]
        }]
    }))
    .unwrap();
    let address = Address::repeat_byte(0x11);
    let raw = encode(&[DynSolValue::Tuple(vec![
        DynSolValue::Address(address),
        DynSolValue::Uint(U256::from(7), 256),
    ])]);
    assert_eq!(
        decode_abi_result(&raw, &plan, true).decoded,
        Some(json!({"owner": address.to_checksum(None), "amount": "7"}))
    );
}

mod shared_budget_tests {
    //! The total is a total, on the route that can send many plans at once.

    use super::*;

    /// `decode_abi_result` mints a fresh allowance every call, and the batch
    /// route sends up to `MAX_BATCH_CALLS` of them, so the documented
    /// request-wide ceiling was multiplied by the number of calls rather than
    /// shared between them. The budget's own doc comment says a shared budget
    /// "is what makes the two caps compose instead of multiply" -- true of one
    /// call, and not of a batch.
    #[test]
    fn a_shared_budget_is_spent_across_calls_rather_than_reset() {
        let plan = AbiDecodePlan::AbiParameters {
            parameters: Vec::new(),
            semantic_codecs: Vec::new(),
            required: false,
        };

        // Every decode charges the shared allowance, so the total is reached
        // by enough calls even though no single one comes near it.
        let mut shared = DecodeBudget::for_request();
        for _ in 0..MAX_TOTAL_DECODES {
            let _ = decode_abi_result_within("0x", &plan, false, &mut shared);
        }
        let exhausted = decode_abi_result_within("0x", &plan, false, &mut shared);
        assert!(
            exhausted
                .decode_error
                .as_ref()
                .is_some_and(|error| error.message.contains("decode budget")),
            "the allowance runs out: {:?}",
            exhausted.decode_error
        );

        // A fresh request starts with its own, which is what every call in a
        // batch used to get for free.
        let mut fresh = DecodeBudget::for_request();
        let first = decode_abi_result_within("0x", &plan, false, &mut fresh);
        assert!(
            first
                .decode_error
                .as_ref()
                .is_none_or(|error| !error.message.contains("decode budget")),
            "a new request has its own allowance"
        );
    }

    /// Exhaustion is a reported decode failure rather than an error for the
    /// request: the reads still happened, and their raw results still come
    /// back.
    #[test]
    fn running_out_reports_rather_than_fails() {
        let plan = AbiDecodePlan::AbiParameters {
            parameters: Vec::new(),
            semantic_codecs: Vec::new(),
            required: false,
        };
        let mut spent = DecodeBudget::for_request();
        for _ in 0..=MAX_TOTAL_DECODES {
            let _ = decode_abi_result_within("0x", &plan, true, &mut spent);
        }
        let result = decode_abi_result_within("0x", &plan, true, &mut spent);
        assert!(
            result
                .decode_error
                .as_ref()
                .is_some_and(|error| error.message.contains("decode budget")),
            "the refusal is reported on the result"
        );
        // And the read itself is still returned. Running out of decode
        // allowance is not a reason to withhold what the endpoint answered:
        // `usable` stays true for an optional decode, which is the decoder's
        // existing semantics rather than anything this changed.
        assert!(
            result.return_data.is_some(),
            "the raw result survives a decode that could not run"
        );
    }
}
