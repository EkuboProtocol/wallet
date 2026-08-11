use crate::{
    abi_decoder::{
        AbiDecodePlan, AbiDecodeResult, DecodeStatus, MAX_RETURN_DATA_BYTES, StructuredDecodeError,
    },
    config::NetworkConfig,
    fork::{ForkContext, ForkPreface, MAX_FORK_READ_CALLS, execute_reads},
    plan_fetch::{ArtifactReference, ArtifactType, FetchPolicy, fetch_reference},
    rpc::MULTICALL3_ADDRESS,
};
use alloy::{
    consensus::BlockHeader,
    eips::{BlockId, BlockNumberOrTag},
    network::{TransactionBuilder, primitives::BlockResponse},
    primitives::{Address, Bytes},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall,
};
use anyhow::{Context, Result, ensure};
use ekubo_wallet_core::chain_client::ChainClient;
use futures::future::join_all;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{str::FromStr, time::Duration};

const MAX_BATCH_CALLS: usize = 128;

/// Individual `eth_call` requests one batch may hold in flight at once.
///
/// The aggregate path is a single request; the fallback is one per call, and
/// letting `MAX_BATCH_CALLS` of them leave together turns one tool call into a
/// burst against an endpoint that agreed to no such thing — and which the
/// threat model does not let this wallet assume anything about. Eight finishes
/// a full batch in a handful of round trips without being that burst.
const MAX_CONCURRENT_INDIVIDUAL_CALLS: usize = 8;

/// Calldata bytes one read may carry. A read is a function selector and its
/// arguments; nothing legitimate approaches this, and the cap keeps a single
/// entry from being the whole budget.
const MAX_CALL_DATA_BYTES: usize = 128 * 1024;

/// Calldata bytes one batch may carry across every read. Bounds the request as
/// a whole, which the per-call cap multiplied by `MAX_BATCH_CALLS` would not
/// do usefully on its own.
const MAX_BATCH_CALL_DATA_BYTES: usize = 1024 * 1024;
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
    /// execution-plan admission policy — public https on the default port, a
    /// `data:application/json` URI, or a `file:` URL naming a bundle you
    /// wrote yourself and described with `ekubo-wallet mcp reference <path>` —
    /// then verified against the envelope's
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
    #[serde(deserialize_with = "bounded_calls")]
    pub calls: Vec<BatchReadCall>,
}

/// Stop reading the array at the limit rather than after it.
///
/// The transport cap bounds a fetched bundle's *bytes*, and 16 MiB of small
/// calls is a great many calls. `validate_input` refuses anything over
/// `MAX_BATCH_CALLS` -- but only once `serde_json::from_slice` has built the
/// whole vector, so a bundle destined to be refused was materialized in full
/// first, every time it was offered.
///
/// Bounded here instead, which is the same move the policy types made: the
/// limit belongs to the type, so no parse can produce a value that breaks it
/// and `validate_input`'s check becomes a restatement rather than the only
/// enforcement. Deserialization now stops on the call after the limit, so the
/// work is proportional to the limit rather than to the body.
fn bounded_calls<'de, D>(deserializer: D) -> std::result::Result<Vec<BatchReadCall>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error as _, SeqAccess, Visitor};

    struct Bounded;

    impl<'de> Visitor<'de> for Bounded {
        type Value = Vec<BatchReadCall>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {MAX_BATCH_CALLS} read calls")
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut calls = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or_default()
                    .min(MAX_BATCH_CALLS),
            );
            while let Some(call) = sequence.next_element()? {
                if calls.len() == MAX_BATCH_CALLS {
                    return Err(A::Error::custom(format!(
                        "read-call bundle carries more than {MAX_BATCH_CALLS} calls"
                    )));
                }
                calls.push(call);
            }
            Ok(calls)
        }
    }

    deserializer.deserialize_seq(Bounded)
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
    ekubo_wallet_core::rpc::try_clients(network, |client| {
        let calls = &calls;
        async move {
            batch_eth_call_through(network, input, calls, requested_caller, client.as_ref()).await
        }
    })
    .await
}

/// The batch itself, against one endpoint.
///
/// Whole-batch failover rather than per-call: every call in a batch is
/// resolved at the same pinned block, and a batch whose calls came from
/// different endpoints at different blocks is not a consistent read of
/// anything.
async fn batch_eth_call_through(
    network: &NetworkConfig,
    input: &BatchEthCallInput,
    calls: &[NormalizedCall],
    requested_caller: Option<Address>,
    client: &dyn ChainClient,
) -> Result<BatchEthCallOutput> {
    let setup = tokio::time::timeout(RPC_TIMEOUT, async {
        let (chain_id, block) = tokio::try_join!(
            client.chain_id(),
            resolve_block(client, &input.block_parameter),
        )?;
        Ok::<_, anyhow::Error>((chain_id, block))
    })
    .await
    .context("batch read RPC setup timed out")??;
    ensure!(
        setup.0 == network.chain_id,
        "RPC reports chain {}, not {}",
        setup.0,
        network.chain_id
    );
    let block = setup.1;

    if requested_caller.is_none()
        && let Some(results) = try_multicall(client, calls, block.call_id).await
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
    // One tool call must not become MAX_BATCH_CALLS simultaneous connections.
    // This path is taken whenever Multicall3 is unavailable *or* the caller
    // named a `from` address — the second is not an error condition, so the
    // fan-out is reachable on demand rather than only when something fails.
    // Throttled rather than refused: a legitimate 128-call batch on a chain
    // without Multicall3 still completes, in a handful of round trips instead
    // of one burst the configured endpoint never agreed to.
    let mut results = Vec::with_capacity(calls.len());
    // One allowance for the request, not one per call. `decode_abi_result`
    // mints a fresh budget every time, and this route sends up to
    // `MAX_BATCH_CALLS` plans, so the documented total was multiplied by the
    // number of calls instead of shared between them.
    let mut budget = ekubo_wallet_core::abi_decoder::DecodeBudget::for_request();
    for (chunk_index, chunk) in calls.chunks(MAX_CONCURRENT_INDIVIDUAL_CALLS).enumerate() {
        let offset = chunk_index * MAX_CONCURRENT_INDIVIDUAL_CALLS;
        results.extend(
            join_all(chunk.iter().enumerate().map(|(position, call)| {
                let index = offset + position;
                async move {
                    let request = TransactionRequest::default()
                        .with_from(caller)
                        .with_to(call.to)
                        .with_input(call.data.clone());
                    match tokio::time::timeout(RPC_TIMEOUT, client.call(request, block.call_id))
                        .await
                    {
                        // Fetched concurrently, decoded afterwards: the
                        // decode budget is one allowance for the whole
                        // request, and a `&mut` to it cannot cross a
                        // `join_all`. Separating them also puts the network
                        // fan-out and the CPU work in the right shapes --
                        // parallel and sequential respectively.
                        Ok(Ok(bytes)) => (index, true, bytes, None),
                        Ok(Err(_)) | Err(_) => (
                            index,
                            false,
                            Bytes::new(),
                            Some("eth_call failed or reverted".into()),
                        ),
                    }
                }
            }))
            .await
            .into_iter()
            .map(|(index, success, bytes, error)| {
                format_result(&calls[index], index, success, &bytes, error, &mut budget)
            })
            .collect::<Vec<_>>(),
        );
    }
    Ok(BatchEthCallOutput {
        network: network.name.clone(),
        chain_id: network.chain_id.to_string(),
        block_parameter: input.block_parameter.clone(),
        block_number: block.number.to_string(),
        strategy: BatchStrategy::Individual,
        caller: caller.to_checksum(None),
        multicall3_address: None,
        results,
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
        let mut budget = ekubo_wallet_core::abi_decoder::DecodeBudget::for_request();
        decoded
            .iter()
            .zip(calls)
            .enumerate()
            .map(|(index, (result, call))| {
                format_result(
                    call,
                    index,
                    result.success,
                    &result.returnData,
                    None,
                    &mut budget,
                )
            })
            .collect()
    } else {
        ensure!(
            outcome.results.len() == calls.len(),
            "fork eth_simulateV1 returned an unexpected result count"
        );
        let mut budget = ekubo_wallet_core::abi_decoder::DecodeBudget::for_request();
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
                    &mut budget,
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

async fn resolve_block(client: &dyn ChainClient, block_parameter: &str) -> Result<ResolvedBlock> {
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
        let number = client.block_number().await?;
        return Ok(ResolvedBlock {
            number,
            call_id: BlockId::number(number),
        });
    }
    let block = client.block_by_number(tag).await?;
    if tag == BlockNumberOrTag::Pending {
        let number = if let Some(block) = block {
            block.header().number()
        } else {
            client.block_number().await?
        };
        return Ok(ResolvedBlock {
            number,
            call_id: BlockId::pending(),
        });
    }
    let number = block
        .map(|block| block.header().number())
        .with_context(|| {
            format!("eth_call block tag {block_parameter} did not resolve to a block")
        })?;
    Ok(ResolvedBlock {
        number,
        call_id: BlockId::number(number),
    })
}

async fn try_multicall(
    client: &dyn ChainClient,
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
    let response = tokio::time::timeout(RPC_TIMEOUT, client.call(request, block_id))
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
    let mut budget = ekubo_wallet_core::abi_decoder::DecodeBudget::for_request();
    Some(
        decoded
            .iter()
            .zip(calls)
            .enumerate()
            .map(|(index, (result, call))| {
                format_result(
                    call,
                    index,
                    result.success,
                    &result.returnData,
                    None,
                    &mut budget,
                )
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
    budget: &mut ekubo_wallet_core::abi_decoder::DecodeBudget,
) -> BatchCallResult {
    // The endpoint chooses this length, and hex-encoding doubles it before it
    // is handed back. `validate_return_data` applies the same ceiling on the
    // decode path, but an undecoded or failed call never reaches it — which is
    // the path an endpoint controls by simply failing.
    if bytes.len() > MAX_RETURN_DATA_BYTES {
        return BatchCallResult {
            index,
            id: call.id.clone(),
            success: false,
            error: Some(format!(
                "return data is {} bytes and exceeds the {MAX_RETURN_DATA_BYTES}-byte maximum",
                bytes.len()
            )),
            return_data: None,
            decode_status: BatchDecodeStatus::NotRequested,
            usable: None,
            decoded: None,
            decode_error: None,
            decode_errors: None,
            semantic_errors: None,
        };
    }
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
    } = ekubo_wallet_core::abi_decoder::decode_abi_result_within(
        &raw,
        call.decode.as_ref().expect("checked above"),
        call.include_raw,
        budget,
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
    // Bytes as well as count. `MAX_BATCH_CALLS` bounds how many calls arrive
    // and says nothing about their size, and `MAX_TOTAL_CALLDATA_BYTES` guards
    // execution plans rather than this path — so 128 calls of a megabyte each
    // were admitted, hex-decoded, and sent. Checked on the encoded length,
    // before `normalize_call` decodes anything, since hex only ever shrinks.
    let mut total = 0_usize;
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
        let bytes = call.data.len().saturating_sub(2) / 2;
        ensure!(
            bytes <= MAX_CALL_DATA_BYTES,
            "call data is {bytes} bytes and exceeds the {MAX_CALL_DATA_BYTES}-byte maximum \
             for one read"
        );
        total = total.saturating_add(bytes);
        ensure!(
            total <= MAX_BATCH_CALL_DATA_BYTES,
            "batch calldata exceeds the {MAX_BATCH_CALL_DATA_BYTES}-byte maximum across \
             all reads"
        );
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
#[path = "batch_read_test.rs"]
mod tests;
