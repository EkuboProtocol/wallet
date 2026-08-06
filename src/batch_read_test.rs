//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use alloy::{primitives::U256, sol_types::SolValue};

fn call() -> BatchReadCall {
    BatchReadCall {
        id: Some("balance".into()),
        to: Address::repeat_byte(0x11).to_checksum(None),
        data: "0x1234".into(),
        decode: None,
        include_raw: true,
    }
}

#[test]
fn validates_canonical_block_parameters() {
    for valid in [
        "latest",
        "pending",
        "safe",
        "finalized",
        "earliest",
        "0x0",
        "0x1a",
    ] {
        assert!(validate_block_parameter(valid).is_ok(), "{valid}");
    }
    for invalid in ["0x", "0x00", "0X1", "1", "head"] {
        assert!(validate_block_parameter(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn aggregate3_encoding_and_decoding_preserve_order() {
    let calls = [
        NormalizedCall {
            id: Some("first".into()),
            to: Address::repeat_byte(0x11),
            data: Bytes::from_static(&[0xaa]),
            decode: None,
            include_raw: true,
        },
        NormalizedCall {
            id: Some("second".into()),
            to: Address::repeat_byte(0x22),
            data: Bytes::from_static(&[0xbb]),
            decode: None,
            include_raw: true,
        },
    ];
    let request = aggregate3Call {
        calls: calls
            .iter()
            .map(|call| Call3 {
                target: call.to,
                allowFailure: true,
                callData: call.data.clone(),
            })
            .collect(),
    };
    assert!(!request.abi_encode().is_empty());

    let encoded = vec![
        Result3 {
            success: true,
            returnData: Bytes::from_static(&[0xaa]),
        },
        Result3 {
            success: false,
            returnData: Bytes::from_static(&[0xbb]),
        },
    ]
    .abi_encode();
    let decoded = aggregate3Call::abi_decode_returns(&encoded).unwrap();
    assert_eq!(decoded.len(), 2);
    assert!(decoded[0].success);
    assert!(!decoded[1].success);
}

#[test]
fn inline_decoder_omits_raw_only_after_success() {
    let raw = U256::from(7).abi_encode();
    let normalized = NormalizedCall {
        id: None,
        to: Address::ZERO,
        data: Bytes::new(),
        decode: Some(AbiDecodePlan::AbiParameters {
            parameters: vec![crate::abi_decoder::AbiParameterInput {
                name: None,
                ty: "uint256".into(),
                internal_type: None,
                components: None,
            }],
            semantic_codecs: Vec::new(),
            required: true,
        }),
        include_raw: false,
    };
    let result = format_result(&normalized, 0, true, &raw.into(), None);
    assert_eq!(result.decode_status, BatchDecodeStatus::Decoded);
    assert_eq!(result.decoded, Some(Value::String("7".into())));
    assert!(result.return_data.is_none());
}

fn inline_input() -> BatchEthCallInput {
    BatchEthCallInput {
        chain_id: "1".into(),
        block_parameter: "latest".into(),
        from: None,
        calls: vec![call()],
        reference: None,
        fork_id: None,
    }
}

fn reference_for(url: impl Into<String>, body: Option<&str>) -> ArtifactReference {
    ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ArtifactType::ReadCalls,
        url: url.into(),
        integrity: body.map(|body| crate::plan_fetch::ArtifactIntegrity {
            algorithm: "keccak256".into(),
            value: format!("0x{:x}", alloy::primitives::keccak256(body.as_bytes())),
        }),
        bytes: body.map(|body| body.len() as u64),
        instruction: None,
    }
}

#[test]
fn validates_batch_bounds_before_rpc() {
    let input = inline_input();
    assert!(validate_input(&input).is_ok());
    let mut empty = input;
    empty.calls.clear();
    assert!(validate_input(&empty).is_err());
}

#[test]
fn read_calls_body_rejects_anything_beyond_the_inline_surface() {
    let minimal = "{\"chain_id\":\"1\",\"calls\":[{\"to\":\
                       \"0x1111111111111111111111111111111111111111\",\"data\":\"0x1234\"}]}";
    let body: ReadCallsBody = serde_json::from_str(minimal).unwrap();
    assert_eq!(body.block_parameter, "latest");
    assert_eq!(body.calls.len(), 1);

    let digest_field = format!("\"expected_content_keccak256\":\"0x{}\"", "11".repeat(32));
    for smuggled in [
        "\"fork_id\":\"00000000-0000-4000-8000-000000000000\"",
        "\"calls_url\":\"https://mcp.example.org/read/x\"",
        digest_field.as_str(),
        "\"anything_future\":1",
    ] {
        let raw = format!("{{\"chain_id\":\"1\",\"calls\":[],{smuggled}}}");
        assert!(
            serde_json::from_str::<ReadCallsBody>(&raw).is_err(),
            "body must reject {smuggled}"
        );
    }
}

#[tokio::test]
async fn resolve_read_input_enforces_reference_exclusivity_before_fetching() {
    // A URL that would fail loudly if it were ever fetched: every case
    // below must error on exclusivity alone.
    let url = "https://never.fetched.invalid/read/x";

    let mut both = inline_input();
    both.reference = Some(reference_for(url, Some("{}")));
    let error = resolve_read_input(both, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exactly one of calls"));

    let mut with_from = inline_input();
    with_from.calls.clear();
    with_from.reference = Some(reference_for(url, Some("{}")));
    with_from.from = Some("0x1111111111111111111111111111111111111111".into());
    let error = resolve_read_input(with_from, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("its own from"));

    let mut with_block = inline_input();
    with_block.calls.clear();
    with_block.reference = Some(reference_for(url, Some("{}")));
    with_block.block_parameter = "pending".into();
    let error = resolve_read_input(with_block, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("its own block_parameter"));
}

#[tokio::test]
async fn resolve_read_input_applies_a_data_uri_bundle_without_the_network() {
    use base64::Engine as _;
    let body = serde_json::json!({
        "chain_id": "1",
        "block_parameter": "pending",
        "calls": [{
            "to": "0x1111111111111111111111111111111111111111",
            "data": "0x1234",
        }],
    })
    .to_string();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&body);

    let mut input = inline_input();
    input.calls.clear();
    input.reference = Some(reference_for(
        format!("data:application/json;base64,{encoded}"),
        Some(&body),
    ));
    let resolved = resolve_read_input(input, FetchPolicy::production())
        .await
        .unwrap();
    assert!(resolved.reference.is_none());
    assert_eq!(resolved.block_parameter, "pending");
    assert_eq!(resolved.calls.len(), 1);
    assert!(validate_input(&resolved).is_ok());
}

#[tokio::test]
async fn resolve_read_input_refuses_a_bundle_for_another_chain() {
    use base64::Engine as _;
    let body = "{\"chain_id\":\"8453\",\"calls\":[{\"to\":\
                    \"0x1111111111111111111111111111111111111111\",\"data\":\"0x1234\"}]}";
    let encoded = base64::engine::general_purpose::STANDARD.encode(body);
    let mut input = inline_input();
    input.calls.clear();
    input.reference = Some(reference_for(
        format!("data:application/json;base64,{encoded}"),
        Some(body),
    ));
    let error = resolve_read_input(input, FetchPolicy::production())
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("targets chain 8453"));
    assert!(message.contains("selected chain 1"));
}

#[tokio::test]
#[ignore = "explicit live Ethereum RPC conformance check"]
async fn live_multicall_is_block_pinned_and_decoded_locally() {
    let network = crate::config::default_networks()
        .into_iter()
        .find(|network| network.chain_id == 1)
        .unwrap();
    let input = BatchEthCallInput {
        chain_id: "1".into(),
        block_parameter: "latest".into(),
        from: None,
        reference: None,
        fork_id: None,
        calls: vec![BatchReadCall {
            id: Some("weth-total-supply".into()),
            to: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".into(),
            data: "0x18160ddd".into(),
            decode: Some(AbiDecodePlan::AbiParameters {
                parameters: vec![crate::abi_decoder::AbiParameterInput {
                    name: None,
                    ty: "uint256".into(),
                    internal_type: None,
                    components: None,
                }],
                semantic_codecs: Vec::new(),
                required: true,
            }),
            include_raw: false,
        }],
    };
    let output = batch_eth_call(&network, &input, None).await.unwrap();
    assert_eq!(output.strategy, BatchStrategy::Multicall3);
    assert!(output.block_number.parse::<u64>().unwrap() > 0);
    assert_eq!(output.results[0].decode_status, BatchDecodeStatus::Decoded);
    assert!(output.results[0].return_data.is_none());
    assert!(
        output.results[0]
            .decoded
            .as_ref()
            .and_then(Value::as_str)
            .unwrap()
            .parse::<U256>()
            .is_ok()
    );
}
