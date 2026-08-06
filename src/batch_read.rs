use crate::{
    abi_decoder::{
        AbiDecodePlan, AbiDecodeResult, DecodeStatus, StructuredDecodeError, decode_abi_result,
    },
    config::NetworkConfig,
    fork::{ForkContext, ForkPreface, MAX_FORK_READ_CALLS, execute_reads},
    plan_fetch::{ArtifactReference, ArtifactType, FetchPolicy, fetch_reference},
    rpc::{MULTICALL3_ADDRESS, sanitized_rpc_error},
};
use alloy::{
    consensus::BlockHeader,
    eips::{BlockId, BlockNumberOrTag},
    network::{TransactionBuilder, primitives::BlockResponse},
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall,
};
use anyhow::{Context, Result, ensure};
use futures::future::join_all;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{str::FromStr, time::Duration};

const MAX_BATCH_CALLS: usize = 128;
const RPC_TIMEOUT: Duration = Duration::from_secs(15);

sol! {
    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct Result3 {
        bool success;
        bytes returnData;
    }

    function aggregate3(Call3[] calls) external payable returns (Result3[] returnData);
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchReadCall {
    #[serde(default)]
    pub id: Option<String>,
    pub to: String,
    pub data: String,
    #[serde(default)]
    pub decode: Option<AbiDecodePlan>,
    #[serde(default = "default_true")]
    pub include_raw: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchEthCallInput {
    pub chain_id: String,
    #[serde(default = "default_block_parameter")]
    pub block_parameter: String,
    #[serde(default)]
    pub from: Option<String>,
    /// Inline read calls. Pass exactly one of `calls` and `reference`.
    #[serde(default)]
    pub calls: Vec<BatchReadCall>,
    /// A producer `read_calls_reference` envelope, passed through VERBATIM,
    /// whose stored body is the exact call bundle: the same JSON object as
    /// this tool's inline arguments minus `fork_id` (`chain_id`, optional
    /// `block_parameter` and `from`, `calls`). Fetched under the
    /// execution-plan admission policy — public https on the default port or
    /// a `data:application/json` URI — then verified against the envelope's
    /// integrity digest and byte count. The body's `chain_id` must equal
    /// `chain_id` above, and the body alone supplies `block_parameter`,
    /// `from`, and `calls`.
    #[serde(default)]
    pub reference: Option<ArtifactReference>,
    /// Read the hypothetical state of this temporary simulation fork instead
    /// of real chain state. A fork pins its own parent block, so
    /// `block_parameter` must be left at `latest`, and at most
    /// 64 calls may be sent because they share the pinned block's gas limit.
    #[serde(default)]
    pub fork_id: Option<uuid::Uuid>,
}

/// The exact stored body of a read-calls reference: this tool's inline
/// argument surface and nothing else. `deny_unknown_fields` is the smuggling
/// boundary — a fetched body cannot carry a `fork_id`, a nested reference,
/// a digest, or any future top-level field this tool grows, so a producer's
/// bundle can never widen what the tool call itself declared.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCallsBody {
    pub chain_id: String,
    #[serde(default = "default_block_parameter")]
    pub block_parameter: String,
    #[serde(default)]
    pub from: Option<String>,
    pub calls: Vec<BatchReadCall>,
}

/// Settle the `reference` envelope surface into an effective inline input.
///
/// Exclusivity is checked before any fetch, so a malformed tool call never
/// becomes an outbound request to a caller-chosen URL. The resolved input
/// then flows through the same validation as an inline one.
pub async fn resolve_read_input(
    input: BatchEthCallInput,
    policy: FetchPolicy,
) -> Result<BatchEthCallInput> {
    let Some(reference) = input.reference.clone() else {
        return Ok(input);
    };
    ensure!(
        input.calls.is_empty(),
        "pass exactly one of calls and reference"
    );
    ensure!(
        input.from.is_none(),
        "a referenced bundle carries its own from; leave it unset"
    );
    ensure!(
        input.block_parameter == default_block_parameter(),
        "a referenced bundle carries its own block_parameter; leave it at latest"
    );
    if let Some(summary_chain) = &reference.summary.chain_id {
        ensure!(
            *summary_chain == input.chain_id,
            "the reference summary says chain {summary_chain} but this call names chain {}",
            input.chain_id
        );
    }
    let fetched = fetch_reference(&reference, ArtifactType::ReadCalls, policy).await?;
    let body: ReadCallsBody = serde_json::from_slice(&fetched.bytes)
        .context("read-call bundle is not a valid wallet_batch_eth_call argument object")?;
    ensure!(
        body.chain_id == input.chain_id,
        "read-call bundle targets chain {} but the tool call selected chain {}; \
         pass the reference's chain_id unchanged",
        body.chain_id,
        input.chain_id
    );
    if let Some(call_count) = reference.summary.call_count {
        ensure!(
            call_count as usize == body.calls.len(),
            "the reference summary says {call_count} calls but the bundle has {}",
            body.calls.len()
        );
    }
    Ok(BatchEthCallInput {
        chain_id: input.chain_id,
        block_parameter: body.block_parameter,
        from: body.from,
        calls: body.calls,
        reference: None,
        fork_id: input.fork_id,
    })
}

#[derive(Clone, Copy, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BatchStrategy {
    Multicall3,
    Individual,
}

#[derive(Clone, Copy, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BatchDecodeStatus {
    NotRequested,
    Decoded,
    Failed,
}

impl From<DecodeStatus> for BatchDecodeStatus {
    fn from(status: DecodeStatus) -> Self {
        match status {
            DecodeStatus::Decoded => Self::Decoded,
            DecodeStatus::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BatchCallResult {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<String>,
    pub decode_status: BatchDecodeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::abi_decoder::any_json_schema")]
    pub decoded: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_error: Option<StructuredDecodeError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_errors: Option<Vec<StructuredDecodeError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_errors: Option<Vec<StructuredDecodeError>>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BatchEthCallOutput {
    pub network: String,
    pub chain_id: String,
    pub block_parameter: String,
    pub block_number: String,
    pub strategy: BatchStrategy,
    pub caller: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multicall3_address: Option<String>,
    pub results: Vec<BatchCallResult>,
    /// Present only when these reads ran on a temporary simulation fork. Its
    /// presence means every value returned here is hypothetical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkContext>,
}

#[derive(Clone)]
struct NormalizedCall {
    id: Option<String>,
    to: Address,
    data: Bytes,
    decode: Option<AbiDecodePlan>,
    include_raw: bool,
}

struct ResolvedBlock {
    number: u64,
    call_id: BlockId,
}

pub async fn batch_eth_call(
    network: &NetworkConfig,
    input: &BatchEthCallInput,
    fork: Option<&ForkPreface>,
) -> Result<BatchEthCallOutput> {
    validate_input(input)?;
    ensure!(
        input.chain_id == network.chain_id.to_string(),
        "requested chain does not match selected network"
    );
    let calls = input
        .calls
        .iter()
        .map(normalize_call)
        .collect::<Result<Vec<_>>>()?;
    let requested_caller = input
        .from
        .as_deref()
        .map(Address::from_str)
        .transpose()
        .context("from must be a 20-byte EVM address")?;
    if let Some(preface) = fork {
        return fork_batch_eth_call(network, input, &calls, requested_caller, preface).await;
    }
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let setup = tokio::time::timeout(RPC_TIMEOUT, async {
        let (chain_id, block) = tokio::try_join!(
            provider.get_chain_id(),
            resolve_block(&provider, &input.block_parameter),
        )?;
        Ok::<_, alloy::transports::TransportError>((chain_id, block))
    })
    .await
    .context("batch read RPC setup timed out")?
    .map_err(|error| sanitized_rpc_error(network, &error))?;
    ensure!(
        setup.0 == network.chain_id,
        "RPC reports chain {}, not {}",
        setup.0,
        network.chain_id
    );
    let block = setup.1;

    if requested_caller.is_none()
        && let Some(results) = try_multicall(&provider, &calls, block.call_id).await
    {
        return Ok(BatchEthCallOutput {
            network: network.name.clone(),
            chain_id: network.chain_id.to_string(),
            block_parameter: input.block_parameter.clone(),
            block_number: block.number.to_string(),
            strategy: BatchStrategy::Multicall3,
            caller: MULTICALL3_ADDRESS.to_checksum(None),
            multicall3_address: Some(MULTICALL3_ADDRESS.to_checksum(None)),
            results,
            fork: None,
        });
    }

    let caller = requested_caller.unwrap_or(MULTICALL3_ADDRESS);
    let futures = calls.iter().enumerate().map(|(index, call)| {
        let provider = &provider;
        async move {
            let request = TransactionRequest::default()
                .with_from(caller)
                .with_to(call.to)
                .with_input(call.data.clone());
            match tokio::time::timeout(RPC_TIMEOUT, provider.call(request).block(block.call_id))
                .await
            {
                Ok(Ok(bytes)) => format_result(call, index, true, &bytes, None),
                Ok(Err(_)) | Err(_) => format_result(
                    call,
                    index,
                    false,
                    &Bytes::new(),
                    Some("eth_call failed or reverted".into()),
                ),
            }
        }
    });
    Ok(BatchEthCallOutput {
        network: network.name.clone(),
        chain_id: network.chain_id.to_string(),
        block_parameter: input.block_parameter.clone(),
        block_number: block.number.to_string(),
        strategy: BatchStrategy::Individual,
        caller: caller.to_checksum(None),
        multicall3_address: None,
        results: join_all(futures).await,
        fork: None,
    })
}

/// Run the same batch on top of a temporary simulation fork.
///
/// Every call lands in one `SimBlock` layered after the fork's applied plans
/// and is then discarded, so a read can never change what the fork holds. The
/// Multicall3 wrapper is used for exactly the same reason as on real state —
/// it isolates per-call reverts — and the aggregate is one simulated
/// transaction, so it gets the whole block's gas rather than a share of it.
async fn fork_batch_eth_call(
    network: &NetworkConfig,
    input: &BatchEthCallInput,
    calls: &[NormalizedCall],
    requested_caller: Option<Address>,
    preface: &ForkPreface,
) -> Result<BatchEthCallOutput> {
    ensure!(
        input.block_parameter == default_block_parameter(),
        "a fork read is pinned to the fork's own parent block; leave block_parameter at latest"
    );
    ensure!(
        calls.len() <= MAX_FORK_READ_CALLS,
        "a fork read accepts at most {MAX_FORK_READ_CALLS} calls because they share the pinned block's gas limit"
    );
    let multicall = requested_caller.is_none();
    let requests = if multicall {
        vec![
            TransactionRequest::default()
                .with_to(MULTICALL3_ADDRESS)
                .with_input(
                    aggregate3Call {
                        calls: calls
                            .iter()
                            .map(|call| Call3 {
                                target: call.to,
                                allowFailure: true,
                                callData: call.data.clone(),
                            })
                            .collect(),
                    }
                    .abi_encode(),
                ),
        ]
    } else {
        let caller = requested_caller.expect("checked above");
        calls
            .iter()
            .map(|call| {
                TransactionRequest::default()
                    .with_from(caller)
                    .with_to(call.to)
                    .with_input(call.data.clone())
            })
            .collect()
    };
    let outcome = execute_reads(network, preface, requests).await?;
    let results = if multicall {
        let result = outcome
            .results
            .first()
            .context("fork Multicall3 read returned no result")?;
        ensure!(
            result.status,
            "Multicall3 failed on this fork; the canonical Multicall3 may not be deployed on chain {}",
            network.chain_id
        );
        let decoded = aggregate3Call::abi_decode_returns(&result.return_data)
            .context("fork Multicall3 returned undecodable data")?;
        ensure!(
            decoded.len() == calls.len(),
            "fork Multicall3 returned an unexpected result count"
        );
        decoded
            .iter()
            .zip(calls)
            .enumerate()
            .map(|(index, (result, call))| {
                format_result(call, index, result.success, &result.returnData, None)
            })
            .collect()
    } else {
        ensure!(
            outcome.results.len() == calls.len(),
            "fork eth_simulateV1 returned an unexpected result count"
        );
        outcome
            .results
            .iter()
            .zip(calls)
            .enumerate()
            .map(|(index, (result, call))| {
                format_result(
                    call,
                    index,
                    result.status,
                    &result.return_data,
                    (!result.status).then(|| "call failed or reverted on the fork".into()),
                )
            })
            .collect()
    };
    Ok(BatchEthCallOutput {
        network: network.name.clone(),
        chain_id: network.chain_id.to_string(),
        block_parameter: input.block_parameter.clone(),
        block_number: outcome.simulated_block.to_string(),
        strategy: if multicall {
            BatchStrategy::Multicall3
        } else {
            BatchStrategy::Individual
        },
        caller: requested_caller
            .unwrap_or(MULTICALL3_ADDRESS)
            .to_checksum(None),
        multicall3_address: multicall.then(|| MULTICALL3_ADDRESS.to_checksum(None)),
        results,
        fork: None,
    })
}

async fn resolve_block<P: Provider>(
    provider: &P,
    block_parameter: &str,
) -> std::result::Result<ResolvedBlock, alloy::transports::TransportError> {
    if let Some(quantity) = block_parameter.strip_prefix("0x") {
        let number = u64::from_str_radix(quantity, 16).expect("validated block quantity");
        return Ok(ResolvedBlock {
            number,
            call_id: BlockId::number(number),
        });
    }
    let tag = match block_parameter {
        "latest" => BlockNumberOrTag::Latest,
        "pending" => BlockNumberOrTag::Pending,
        "safe" => BlockNumberOrTag::Safe,
        "finalized" => BlockNumberOrTag::Finalized,
        "earliest" => BlockNumberOrTag::Earliest,
        _ => unreachable!("validated block parameter"),
    };
    if tag == BlockNumberOrTag::Latest {
        let number = provider.get_block_number().await?;
        return Ok(ResolvedBlock {
            number,
            call_id: BlockId::number(number),
        });
    }
    let block = provider.get_block_by_number(tag).await?;
    if tag == BlockNumberOrTag::Pending {
        let number = if let Some(block) = block {
            block.header().number()
        } else {
            provider.get_block_number().await?
        };
        return Ok(ResolvedBlock {
            number,
            call_id: BlockId::pending(),
        });
    }
    let number = block.map(|block| block.header().number()).ok_or_else(|| {
        alloy::transports::TransportErrorKind::custom_str(&format!(
            "eth_call block tag {block_parameter} did not resolve to a block"
        ))
    })?;
    Ok(ResolvedBlock {
        number,
        call_id: BlockId::number(number),
    })
}

async fn try_multicall<P: Provider>(
    provider: &P,
    calls: &[NormalizedCall],
    block_id: BlockId,
) -> Option<Vec<BatchCallResult>> {
    let encoded = aggregate3Call {
        calls: calls
            .iter()
            .map(|call| Call3 {
                target: call.to,
                allowFailure: true,
                callData: call.data.clone(),
            })
            .collect(),
    }
    .abi_encode();
    let request = TransactionRequest::default()
        .with_to(MULTICALL3_ADDRESS)
        .with_input(encoded);
    let response = tokio::time::timeout(RPC_TIMEOUT, provider.call(request).block(block_id))
        .await
        .ok()?
        .ok()?;
    if response.is_empty() {
        return None;
    }
    let decoded = aggregate3Call::abi_decode_returns(&response).ok()?;
    if decoded.len() != calls.len() {
        return None;
    }
    Some(
        decoded
            .iter()
            .zip(calls)
            .enumerate()
            .map(|(index, (result, call))| {
                format_result(call, index, result.success, &result.returnData, None)
            })
            .collect(),
    )
}

fn format_result(
    call: &NormalizedCall,
    index: usize,
    success: bool,
    bytes: &Bytes,
    error: Option<String>,
) -> BatchCallResult {
    let raw = format!("0x{}", hex::encode(bytes));
    if !success || call.decode.is_none() {
        return BatchCallResult {
            index,
            id: call.id.clone(),
            success,
            error,
            return_data: Some(raw),
            decode_status: BatchDecodeStatus::NotRequested,
            usable: None,
            decoded: None,
            decode_error: None,
            decode_errors: None,
            semantic_errors: None,
        };
    }
    let AbiDecodeResult {
        decode_status,
        usable,
        decoded,
        decode_error,
        decode_errors,
        semantic_errors,
        return_data,
    } = decode_abi_result(
        &raw,
        call.decode.as_ref().expect("checked above"),
        call.include_raw,
    );
    BatchCallResult {
        index,
        id: call.id.clone(),
        success,
        error,
        return_data,
        decode_status: decode_status.into(),
        usable: Some(usable),
        decoded,
        decode_error,
        decode_errors,
        semantic_errors,
    }
}

fn validate_input(input: &BatchEthCallInput) -> Result<()> {
    ensure!(
        input.reference.is_none(),
        "resolve the reference into inline calls before executing the batch"
    );
    ensure!(
        !input.chain_id.is_empty()
            && !input.chain_id.starts_with('0')
            && input.chain_id.bytes().all(|byte| byte.is_ascii_digit()),
        "chain_id must be a canonical positive decimal integer"
    );
    ensure!(
        (1..=MAX_BATCH_CALLS).contains(&input.calls.len()),
        "calls must contain between 1 and {MAX_BATCH_CALLS} entries"
    );
    validate_block_parameter(&input.block_parameter)?;
    if let Some(from) = &input.from {
        ensure!(
            from.len() == 42 && from.starts_with("0x"),
            "from must be a 20-byte EVM address"
        );
    }
    for call in &input.calls {
        if let Some(id) = &call.id {
            ensure!(
                !id.is_empty() && id.len() <= 128,
                "call id must be 1-128 bytes"
            );
        }
        ensure!(
            call.to.len() == 42 && call.to.starts_with("0x"),
            "call target must be a 20-byte EVM address"
        );
        validate_hex_bytes(&call.data, "call data")?;
    }
    Ok(())
}

fn validate_block_parameter(value: &str) -> Result<()> {
    if matches!(
        value,
        "latest" | "pending" | "safe" | "finalized" | "earliest"
    ) {
        return Ok(());
    }
    let quantity = value
        .strip_prefix("0x")
        .context("invalid eth_call block_parameter")?;
    ensure!(
        quantity == "0"
            || (!quantity.is_empty()
                && !quantity.starts_with('0')
                && quantity.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "block_parameter must be a named tag or canonical hexadecimal quantity"
    );
    u64::from_str_radix(quantity, 16).context("block quantity does not fit uint64")?;
    Ok(())
}

fn normalize_call(call: &BatchReadCall) -> Result<NormalizedCall> {
    Ok(NormalizedCall {
        id: call.id.clone(),
        to: Address::from_str(&call.to).context("call target must be a 20-byte EVM address")?,
        data: Bytes::from(hex::decode(&call.data[2..]).context("call data is not hexadecimal")?),
        decode: call.decode.clone(),
        include_raw: call.include_raw,
    })
}

fn validate_hex_bytes(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.starts_with("0x")
            && value.len().is_multiple_of(2)
            && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} must be 0x-prefixed whole bytes"
    );
    Ok(())
}

fn default_block_parameter() -> String {
    "latest".into()
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
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
            summary: crate::plan_fetch::ArtifactSummary::default(),
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

        // A summary that names a different chain is refused before any fetch.
        let mut wrong_chain = inline_input();
        wrong_chain.calls.clear();
        let mut reference = reference_for(url, Some("{}"));
        reference.summary.chain_id = Some("8453".into());
        wrong_chain.reference = Some(reference);
        let error = resolve_read_input(wrong_chain, FetchPolicy::production())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("chain 8453"));
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
}
