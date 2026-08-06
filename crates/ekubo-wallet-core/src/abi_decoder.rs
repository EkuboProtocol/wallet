use alloy::{
    dyn_abi::{DynSolType, DynSolValue, ErrorExt, FunctionExt, Specifier},
    json_abi::{Function, JsonAbi, Param},
    primitives::U256,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Schemars renders `serde_json::Value` as the bare boolean schema `true`,
/// which some MCP clients (Claude Code among them) reject when validating
/// tool schemas. These helpers emit equivalent object-form schemas instead.
#[must_use]
pub fn any_json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({})
}

#[must_use]
pub fn any_json_array_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "array", "items": {}})
}

#[must_use]
pub fn any_json_object_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "object"})
}

pub const MAX_ABI_ENTRIES: usize = 128;
pub const MAX_ABI_BYTES: usize = 65_536;
pub const MAX_RETURN_DATA_BYTES: usize = 1_048_576;
pub const MAX_RECURSION_DEPTH: usize = 16;
pub const MAX_COLLECTION_ITEMS: usize = 2_048;
pub const MAX_MULTICALL_CHILDREN: usize = 128;
/// Nested decodes one request may perform in total, across every level.
///
/// Generous against anything a real multicall produces — a batch of a hundred
/// calls each decoding a handful of nested results stays far below it — and
/// finite, which the depth and width caps are not when combined.
pub const MAX_TOTAL_DECODES: usize = 4_096;
pub const MAX_SEMANTIC_TRANSFORMATIONS: usize = 32;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AbiParameterInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(
        default,
        rename = "internalType",
        skip_serializing_if = "Option::is_none"
    )]
    pub internal_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<AbiParameterInput>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodecImplementation {
    pub ecosystem: String,
    pub registry: String,
    pub package_url: String,
    pub export_name: String,
    pub integrity: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodecIdentity {
    pub id: String,
    pub version: u32,
    pub implementations: Vec<CodecImplementation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticCodec {
    pub path: String,
    pub semantic_type: String,
    pub codec: CodecIdentity,
    #[serde(default = "default_true")]
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MulticallSelection {
    pub index: usize,
    #[serde(default)]
    pub required_success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decode: Option<Box<AbiDecodePlan>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BytesArraySelection {
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decode: Option<Box<AbiDecodePlan>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AbiDecodePlan {
    FunctionResult {
        #[schemars(schema_with = "any_json_array_schema")]
        abi: Vec<Value>,
        function_name: String,
        #[serde(default)]
        semantic_codecs: Vec<SemanticCodec>,
        #[serde(default)]
        required: bool,
    },
    AbiParameters {
        parameters: Vec<AbiParameterInput>,
        #[serde(default)]
        semantic_codecs: Vec<SemanticCodec>,
        #[serde(default)]
        required: bool,
    },
    SemanticValue {
        semantic_type: String,
        codec: CodecIdentity,
        #[serde(default)]
        required: bool,
    },
    Multicall3 {
        #[schemars(schema_with = "any_json_array_schema")]
        abi: Vec<Value>,
        function_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_result_count: Option<usize>,
        #[serde(default)]
        results: Vec<MulticallSelection>,
        #[serde(default)]
        required: bool,
    },
    FunctionResultBytesArray {
        #[schemars(schema_with = "any_json_array_schema")]
        abi: Vec<Value>,
        function_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_result_count: Option<usize>,
        #[serde(default)]
        results: Vec<BytesArraySelection>,
        #[serde(default)]
        required: bool,
    },
}

impl AbiDecodePlan {
    const fn required(&self) -> bool {
        match self {
            Self::FunctionResult { required, .. }
            | Self::AbiParameters { required, .. }
            | Self::SemanticValue { required, .. }
            | Self::Multicall3 { required, .. }
            | Self::FunctionResultBytesArray { required, .. } => *required,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecodeStatus {
    Decoded,
    Failed,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StructuredDecodeError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "any_json_object_schema")]
    pub details: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AbiDecodeResult {
    pub decode_status: DecodeStatus,
    pub usable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "any_json_schema")]
    pub decoded: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_error: Option<StructuredDecodeError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_errors: Option<Vec<StructuredDecodeError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_errors: Option<Vec<StructuredDecodeError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_data: Option<String>,
}

struct RawDecoded {
    parameters: Vec<Param>,
    values: Vec<DynSolValue>,
    serialized: Value,
}

#[derive(Debug)]
struct DecodeFailure(StructuredDecodeError);

struct DecodeBudget {
    collection_items_remaining: usize,
    /// Nested decodes left before the whole request is abandoned.
    ///
    /// Depth and per-level width were both capped, and their product was not:
    /// `MAX_MULTICALL_CHILDREN` children at each of `MAX_RECURSION_DEPTH`
    /// levels is 128^16 decodes, every one of them legal by the existing
    /// limits. A budget shared across the entire request is what makes the two
    /// caps compose instead of multiply.
    decodes_remaining: usize,
}

pub(crate) struct DecodedAbiError {
    pub(crate) name: String,
    pub(crate) args: Vec<Value>,
}

/// Decode a complete Solidity revert payload against a bounded JSON ABI.
///
/// This is intentionally diagnostic-only: failure to decode never changes
/// simulation success or policy evaluation.
pub(crate) fn decode_abi_error(data: &[u8], input_abi: &[Value]) -> Option<DecodedAbiError> {
    if data.len() < 4 || input_abi.is_empty() || input_abi.len() > MAX_ABI_ENTRIES {
        return None;
    }
    let encoded = serde_json::to_vec(input_abi).ok()?;
    if encoded.len() > MAX_ABI_BYTES {
        return None;
    }
    let abi: JsonAbi = serde_json::from_slice(&encoded).ok()?;
    let mut matches = abi
        .errors
        .values()
        .flatten()
        .filter(|error| data.starts_with(error.selector().as_slice()));
    let error = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    validate_parameter_tree(&error.inputs, 0).ok()?;
    let decoded = error.decode_error(data).ok()?;
    if DynSolValue::Tuple(decoded.body.clone()).abi_encode_params() != data[4..] {
        return None;
    }
    let mut budget = DecodeBudget {
        collection_items_remaining: MAX_COLLECTION_ITEMS,
        decodes_remaining: MAX_TOTAL_DECODES,
    };
    let args = error
        .inputs
        .iter()
        .zip(&decoded.body)
        .map(|(parameter, value)| serialize_value(parameter, value, 0, &mut budget))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    Some(DecodedAbiError {
        name: error.name.clone(),
        args,
    })
}

#[must_use]
pub fn decode_abi_result(
    return_data: &str,
    plan: &AbiDecodePlan,
    include_raw: bool,
) -> AbiDecodeResult {
    let mut budget = DecodeBudget {
        collection_items_remaining: MAX_COLLECTION_ITEMS,
        decodes_remaining: MAX_TOTAL_DECODES,
    };
    decode_at_depth(return_data, plan, include_raw, 0, &mut budget)
}

/// One decode, charged against the request's shared budget.
fn decode_at_depth(
    return_data: &str,
    plan: &AbiDecodePlan,
    include_raw: bool,
    plan_depth: usize,
    budget: &mut DecodeBudget,
) -> AbiDecodeResult {
    // Charged before any work, including the hex scan below, so exhausting the
    // budget costs one comparison rather than another pass over a megabyte.
    let Some(remaining) = budget.decodes_remaining.checked_sub(1) else {
        return failed_result(
            plan.required(),
            detail(
                "decode_budget_exhausted",
                format!(
                    "decoding this result would exceed the {MAX_TOTAL_DECODES}-decode budget \
                     for one request"
                ),
            ),
            include_raw.then(|| return_data.to_owned()),
        );
    };
    budget.decodes_remaining = remaining;
    let raw = match validate_return_data(return_data) {
        Ok(raw) => raw,
        Err(error) => {
            return failed_result(
                plan.required(),
                error.0,
                preservable_raw(return_data).then(|| return_data.to_owned()),
            );
        }
    };
    if plan_depth > MAX_RECURSION_DEPTH {
        return failed_result(
            plan.required(),
            detail(
                "resource_limit",
                format!("decode plan nesting exceeds depth {MAX_RECURSION_DEPTH}"),
            ),
            Some(raw),
        );
    }

    let outcome = match plan {
        AbiDecodePlan::Multicall3 { .. } => {
            decode_multicall(&raw, plan, include_raw, plan_depth, budget)
        }
        AbiDecodePlan::FunctionResultBytesArray { .. } => {
            decode_bytes_array(&raw, plan, include_raw, plan_depth, budget)
        }
        AbiDecodePlan::SemanticValue {
            semantic_type,
            codec,
            required,
        } => Ok(decode_semantic_value(&raw, semantic_type, codec, *required)),
        AbiDecodePlan::FunctionResult {
            abi,
            function_name,
            semantic_codecs,
            required,
        } => decode_plain(
            decode_function(&raw, abi, function_name, budget),
            semantic_codecs,
            *required,
            include_raw,
            &raw,
        ),
        AbiDecodePlan::AbiParameters {
            parameters,
            semantic_codecs,
            required,
        } => decode_plain(
            decode_parameters(&raw, parameters, budget),
            semantic_codecs,
            *required,
            include_raw,
            &raw,
        ),
    };
    outcome.unwrap_or_else(|error| failed_result(plan.required(), error.0, Some(raw)))
}

fn decode_plain(
    decoded: Result<RawDecoded, DecodeFailure>,
    codecs: &[SemanticCodec],
    _required: bool,
    include_raw: bool,
    raw: &str,
) -> Result<AbiDecodeResult, DecodeFailure> {
    let decoded = decoded?;
    let (value, semantic_failures) = apply_semantic_codecs(decoded.serialized, codecs)?;
    let required_error = semantic_failures
        .iter()
        .find(|failure| failure.required)
        .map(|failure| failure.error.clone());
    let errors = (!semantic_failures.is_empty()).then(|| {
        semantic_failures
            .into_iter()
            .map(|failure| failure.error)
            .collect()
    });
    Ok(AbiDecodeResult {
        decode_status: if required_error.is_some() {
            DecodeStatus::Failed
        } else {
            DecodeStatus::Decoded
        },
        usable: required_error.is_none(),
        decoded: Some(value),
        decode_error: required_error,
        decode_errors: None,
        semantic_errors: errors.clone(),
        return_data: (include_raw || errors.is_some()).then(|| raw.to_owned()),
    })
}

fn decode_function(
    data: &str,
    input_abi: &[Value],
    function_name: &str,
    budget: &mut DecodeBudget,
) -> Result<RawDecoded, DecodeFailure> {
    if input_abi.is_empty() {
        return fail("invalid_abi", "ABI must contain at least one entry");
    }
    if input_abi.len() > MAX_ABI_ENTRIES {
        return fail(
            "resource_limit",
            format!("ABI exceeds {MAX_ABI_ENTRIES} entries"),
        );
    }
    let encoded = serde_json::to_vec(input_abi)
        .map_err(|error| failure("invalid_abi", format!("ABI is not valid JSON: {error}")))?;
    if encoded.len() > MAX_ABI_BYTES {
        return fail(
            "resource_limit",
            format!("serialized ABI exceeds {MAX_ABI_BYTES} bytes"),
        );
    }
    let abi: JsonAbi = serde_json::from_slice(&encoded)
        .map_err(|error| failure("invalid_abi", format!("ABI is malformed: {error}")))?;
    let mut matches: Vec<&Function> = abi
        .functions
        .values()
        .flatten()
        .filter(|function| {
            if function_name.contains('(') {
                function.signature() == function_name
            } else {
                function.name == function_name
            }
        })
        .collect();
    if matches.is_empty() {
        return fail(
            "function_not_found",
            format!("ABI does not contain function {function_name}"),
        );
    }
    if matches.len() > 1 {
        let signatures = matches
            .iter()
            .map(|function| Value::String(function.signature()))
            .collect();
        return Err(DecodeFailure(StructuredDecodeError {
            code: "ambiguous_function".into(),
            message: format!(
                "function {function_name} is overloaded; use an unambiguous canonical signature"
            ),
            path: None,
            details: Some(BTreeMap::from([(
                "signatures".into(),
                Value::Array(signatures),
            )])),
        }));
    }
    let function = matches.pop().expect("checked non-empty");
    validate_parameter_tree(&function.outputs, 0)?;
    let bytes = decode_hex(data)?;
    let values = function.abi_decode_output(&bytes).map_err(|error| {
        failure(
            "malformed_return_data",
            format!("return data does not match the requested ABI: {error}"),
        )
    })?;
    let canonical = function.abi_encode_output(&values).map_err(|error| {
        failure(
            "malformed_return_data",
            format!("decoded values cannot be re-encoded: {error}"),
        )
    })?;
    if canonical != bytes {
        return fail(
            "malformed_return_data",
            "return data contains trailing bytes or non-canonical ABI encoding",
        );
    }
    raw_decoded(function.outputs.clone(), values, budget)
}

fn decode_parameters(
    data: &str,
    input: &[AbiParameterInput],
    budget: &mut DecodeBudget,
) -> Result<RawDecoded, DecodeFailure> {
    if input.len() > MAX_COLLECTION_ITEMS {
        return fail("resource_limit", "too many ABI parameters");
    }
    let parameters: Vec<Param> = input
        .iter()
        .map(|parameter| {
            serde_json::from_value(serde_json::to_value(parameter).map_err(|error| {
                failure(
                    "invalid_abi",
                    format!("ABI parameter is malformed: {error}"),
                )
            })?)
            .map_err(|error| {
                failure(
                    "invalid_abi",
                    format!("ABI parameters are malformed: {error}"),
                )
            })
        })
        .collect::<Result<_, _>>()?;
    validate_parameter_tree(&parameters, 0)?;
    let types = parameters
        .iter()
        .map(Specifier::resolve)
        .collect::<Result<Vec<DynSolType>, _>>()
        .map_err(|error| {
            failure(
                "invalid_abi",
                format!("ABI parameters are malformed: {error}"),
            )
        })?;
    let bytes = decode_hex(data)?;
    let tuple = DynSolType::Tuple(types);
    let decoded = tuple.abi_decode_params(&bytes).map_err(|error| {
        failure(
            "malformed_return_data",
            format!("return data does not match the requested ABI: {error}"),
        )
    })?;
    let DynSolValue::Tuple(values) = decoded else {
        return fail("malformed_return_data", "decoded result is not a tuple");
    };
    if DynSolValue::Tuple(values.clone()).abi_encode_params() != bytes {
        return fail(
            "malformed_return_data",
            "return data contains trailing bytes or non-canonical ABI encoding",
        );
    }
    raw_decoded(parameters, values, budget)
}

fn raw_decoded(
    parameters: Vec<Param>,
    values: Vec<DynSolValue>,
    budget: &mut DecodeBudget,
) -> Result<RawDecoded, DecodeFailure> {
    let serialized = serialize_outputs(&parameters, &values, budget)?;
    Ok(RawDecoded {
        parameters,
        values,
        serialized,
    })
}

fn serialize_outputs(
    parameters: &[Param],
    values: &[DynSolValue],
    budget: &mut DecodeBudget,
) -> Result<Value, DecodeFailure> {
    if parameters.is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    if parameters.len() == 1 {
        return serialize_value(&parameters[0], &values[0], 0, budget);
    }
    if all_named(parameters) {
        let mut object = Map::new();
        for (parameter, value) in parameters.iter().zip(values) {
            object.insert(
                parameter.name.clone(),
                serialize_value(parameter, value, 0, budget)?,
            );
        }
        return Ok(Value::Object(object));
    }
    parameters
        .iter()
        .zip(values)
        .map(|(parameter, value)| serialize_value(parameter, value, 0, budget))
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn serialize_value(
    parameter: &Param,
    value: &DynSolValue,
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<Value, DecodeFailure> {
    if depth > MAX_RECURSION_DEPTH {
        return fail(
            "resource_limit",
            format!("decoded value nesting exceeds depth {MAX_RECURSION_DEPTH}"),
        );
    }
    match value {
        DynSolValue::Array(values) | DynSolValue::FixedArray(values) => {
            if values.len() > MAX_COLLECTION_ITEMS {
                return fail("resource_limit", "decoded array is too large");
            }
            values
                .iter()
                .map(|value| serialize_value(parameter, value, depth + 1, budget))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        DynSolValue::Tuple(values) => {
            if values.len() != parameter.components.len() {
                return fail(
                    "malformed_return_data",
                    "decoded tuple has the wrong component count",
                );
            }
            if all_named(&parameter.components) {
                let mut object = Map::new();
                for (component, value) in parameter.components.iter().zip(values) {
                    object.insert(
                        component.name.clone(),
                        serialize_value(component, value, depth + 1, budget)?,
                    );
                }
                Ok(Value::Object(object))
            } else {
                parameter
                    .components
                    .iter()
                    .zip(values)
                    .map(|(component, value)| serialize_value(component, value, depth + 1, budget))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Value::Array)
            }
        }
        _ => {
            budget.collection_items_remaining = budget
                .collection_items_remaining
                .checked_sub(1)
                .ok_or_else(|| {
                    failure(
                        "resource_limit",
                        "decoded values contain too many collection items",
                    )
                })?;
            match value {
                DynSolValue::Bool(value) => Ok(Value::Bool(*value)),
                DynSolValue::Int(value, _) => Ok(Value::String(value.to_string())),
                DynSolValue::Uint(value, _) => Ok(Value::String(value.to_string())),
                DynSolValue::FixedBytes(value, length) => Ok(Value::String(format!(
                    "0x{}",
                    hex::encode(&value[..*length])
                ))),
                DynSolValue::Address(value) => Ok(Value::String(value.to_checksum(None))),
                DynSolValue::Function(value) => {
                    Ok(Value::String(format!("0x{}", hex::encode(value))))
                }
                DynSolValue::Bytes(value) => Ok(Value::String(format!("0x{}", hex::encode(value)))),
                DynSolValue::String(value) => Ok(Value::String(value.clone())),
                DynSolValue::Array(_) | DynSolValue::FixedArray(_) | DynSolValue::Tuple(_) => {
                    unreachable!("handled above")
                }
                // CustomStruct exists only with the dyn-abi eip712 feature;
                // ABI decoding of return data never produces it.
                DynSolValue::CustomStruct { .. } => {
                    fail("invalid_abi", "unsupported ABI value type")
                }
            }
        }
    }
}

fn decode_multicall(
    data: &str,
    plan: &AbiDecodePlan,
    include_raw: bool,
    plan_depth: usize,
    budget: &mut DecodeBudget,
) -> Result<AbiDecodeResult, DecodeFailure> {
    let AbiDecodePlan::Multicall3 {
        abi,
        function_name,
        expected_result_count,
        results,
        ..
    } = plan
    else {
        unreachable!()
    };
    validate_child_plan(
        results.iter().map(|selection| selection.index),
        *expected_result_count,
    )?;
    let outer = decode_function(data, abi, function_name, budget)?;
    if outer.parameters.len() != 1
        || !outer.parameters[0].ty.starts_with("tuple[")
        || !outer.parameters[0].ty.ends_with(']')
    {
        return fail(
            "invalid_multicall_abi",
            "Multicall function must return exactly one tuple array",
        );
    }
    let components = &outer.parameters[0].components;
    let success_index = components
        .iter()
        .position(|entry| entry.name == "success" && entry.ty == "bool");
    let data_index = components
        .iter()
        .position(|entry| entry.name == "returnData" && entry.ty == "bytes");
    let (Some(success_index), Some(data_index)) = (success_index, data_index) else {
        return fail(
            "invalid_multicall_abi",
            "Multicall result tuple must contain bool success and bytes returnData",
        );
    };
    let Some(DynSolValue::Array(entries) | DynSolValue::FixedArray(entries)) = outer.values.first()
    else {
        return fail(
            "malformed_multicall_result",
            "decoded Multicall result is not an array",
        );
    };
    if entries.len() > MAX_MULTICALL_CHILDREN {
        return fail("resource_limit", "Multicall returned too many children");
    }

    let selected: BTreeMap<_, _> = results
        .iter()
        .map(|selection| (selection.index, selection))
        .collect();
    let mut structural = Vec::new();
    if expected_result_count.is_some_and(|expected| expected != entries.len()) {
        structural.push(StructuredDecodeError {
            code: "multicall_result_count".into(),
            message: format!(
                "Multicall returned {} results; expected {}",
                entries.len(),
                expected_result_count.expect("checked")
            ),
            path: None,
            details: Some(BTreeMap::from([
                (
                    "expected".into(),
                    json!(expected_result_count.expect("checked").to_string()),
                ),
                ("actual".into(), json!(entries.len().to_string())),
            ])),
        });
    }
    for selection in results {
        if selection.index >= entries.len()
            && (selection.required_success
                || selection
                    .decode
                    .as_deref()
                    .is_some_and(AbiDecodePlan::required))
        {
            structural.push(with_path(
                detail(
                    "missing_required_result",
                    format!("Multicall result {} is missing", selection.index),
                ),
                format!("results.{}", selection.index),
            ));
        }
    }

    let mut children = Vec::with_capacity(entries.len());
    let mut child_decode_failed = false;
    for (index, entry) in entries.iter().enumerate() {
        let DynSolValue::Tuple(values) = entry else {
            return fail(
                "malformed_multicall_result",
                format!("Multicall result {index} is malformed"),
            );
        };
        let Some(DynSolValue::Bool(success)) = values.get(success_index) else {
            return fail(
                "malformed_multicall_result",
                format!("Multicall result {index} success is malformed"),
            );
        };
        let Some(DynSolValue::Bytes(child_bytes)) = values.get(data_index) else {
            return fail(
                "malformed_multicall_result",
                format!("Multicall result {index} returnData is malformed"),
            );
        };
        let child_raw = format!("0x{}", hex::encode(child_bytes));
        let selection = selected.get(&index).copied();
        if !success {
            if selection.is_some_and(|selection| selection.required_success) {
                structural.push(with_path(
                    detail(
                        "required_inner_call_failed",
                        format!("required Multicall result {index} failed"),
                    ),
                    format!("results.{index}"),
                ));
            }
            children.push(json!({
                "index": index,
                "success": false,
                "return_data": child_raw,
                "decode_status": "not_requested",
                "usable": false,
            }));
            continue;
        }
        let Some(child_plan) = selection.and_then(|selection| selection.decode.as_deref()) else {
            children.push(json!({
                "index": index,
                "success": true,
                "return_data": child_raw,
                "decode_status": "not_requested",
                "usable": true,
            }));
            continue;
        };
        let child = decode_at_depth(&child_raw, child_plan, true, plan_depth + 1, budget);
        if child.decode_status == DecodeStatus::Failed {
            child_decode_failed = true;
            if child_plan.required() {
                let mut error = with_path(
                    detail(
                        "required_inner_decode_failed",
                        format!("required decoding for Multicall result {index} failed"),
                    ),
                    format!("results.{index}"),
                );
                if let Some(child_error) = &child.decode_error {
                    error.details = Some(BTreeMap::from([(
                        "child_error".into(),
                        serde_json::to_value(child_error).expect("serializable error"),
                    )]));
                }
                structural.push(error);
            }
        }
        children.push(merge_child(index, Some(*success), child));
    }
    Ok(finish_nested(
        &outer.serialized,
        &children,
        structural,
        include_raw || child_decode_failed,
        data,
    ))
}

fn decode_bytes_array(
    data: &str,
    plan: &AbiDecodePlan,
    include_raw: bool,
    plan_depth: usize,
    budget: &mut DecodeBudget,
) -> Result<AbiDecodeResult, DecodeFailure> {
    let AbiDecodePlan::FunctionResultBytesArray {
        abi,
        function_name,
        expected_result_count,
        results,
        ..
    } = plan
    else {
        unreachable!()
    };
    validate_child_plan(
        results.iter().map(|selection| selection.index),
        *expected_result_count,
    )?;
    let outer = decode_function(data, abi, function_name, budget)?;
    if outer.parameters.len() != 1 || outer.parameters[0].ty != "bytes[]" {
        return fail(
            "invalid_bytes_array_abi",
            "function must return exactly one bytes[] value",
        );
    }
    let Some(DynSolValue::Array(entries) | DynSolValue::FixedArray(entries)) = outer.values.first()
    else {
        return fail(
            "malformed_bytes_array_result",
            "decoded function result is not a bytes array",
        );
    };
    if entries.len() > MAX_MULTICALL_CHILDREN {
        return fail(
            "resource_limit",
            "function returned too many byte-array children",
        );
    }
    let selected: BTreeMap<_, _> = results
        .iter()
        .map(|selection| (selection.index, selection))
        .collect();
    let mut structural = Vec::new();
    if expected_result_count.is_some_and(|expected| expected != entries.len()) {
        structural.push(StructuredDecodeError {
            code: "bytes_array_result_count".into(),
            message: format!(
                "function returned {} byte-array results; expected {}",
                entries.len(),
                expected_result_count.expect("checked")
            ),
            path: None,
            details: Some(BTreeMap::from([
                (
                    "expected".into(),
                    json!(expected_result_count.expect("checked").to_string()),
                ),
                ("actual".into(), json!(entries.len().to_string())),
            ])),
        });
    }
    for selection in results {
        if selection.index >= entries.len()
            && selection
                .decode
                .as_deref()
                .is_some_and(AbiDecodePlan::required)
        {
            structural.push(with_path(
                detail(
                    "missing_required_result",
                    format!("byte-array result {} is missing", selection.index),
                ),
                format!("results.{}", selection.index),
            ));
        }
    }
    let mut children = Vec::with_capacity(entries.len());
    let mut child_decode_failed = false;
    for (index, entry) in entries.iter().enumerate() {
        let DynSolValue::Bytes(child_bytes) = entry else {
            return fail(
                "malformed_bytes_array_result",
                format!("byte-array result {index} is not bytes"),
            );
        };
        let child_raw = format!("0x{}", hex::encode(child_bytes));
        let Some(child_plan) = selected
            .get(&index)
            .and_then(|selection| selection.decode.as_deref())
        else {
            children.push(json!({
                "index": index,
                "return_data": child_raw,
                "decode_status": "not_requested",
                "usable": true,
            }));
            continue;
        };
        let child = decode_at_depth(&child_raw, child_plan, true, plan_depth + 1, budget);
        if child.decode_status == DecodeStatus::Failed {
            child_decode_failed = true;
            if child_plan.required() {
                let mut error = with_path(
                    detail(
                        "required_inner_decode_failed",
                        format!("required decoding for byte-array result {index} failed"),
                    ),
                    format!("results.{index}"),
                );
                if let Some(child_error) = &child.decode_error {
                    error.details = Some(BTreeMap::from([(
                        "child_error".into(),
                        serde_json::to_value(child_error).expect("serializable error"),
                    )]));
                }
                structural.push(error);
            }
        }
        children.push(merge_child(index, None, child));
    }
    Ok(finish_nested(
        &outer.serialized,
        &children,
        structural,
        include_raw || child_decode_failed,
        data,
    ))
}

fn validate_child_plan(
    indexes: impl IntoIterator<Item = usize>,
    expected: Option<usize>,
) -> Result<(), DecodeFailure> {
    if expected.is_some_and(|count| count > MAX_MULTICALL_CHILDREN) {
        return fail(
            "resource_limit",
            "expected result count is outside the supported range",
        );
    }
    let mut seen = BTreeSet::new();
    for index in indexes {
        if index >= MAX_MULTICALL_CHILDREN {
            return fail(
                "invalid_multicall_plan",
                format!("result index {index} is outside the supported range"),
            );
        }
        if !seen.insert(index) {
            return fail(
                "invalid_multicall_plan",
                format!("duplicate result index {index}"),
            );
        }
    }
    Ok(())
}

fn finish_nested(
    outer: &Value,
    children: &[Value],
    errors: Vec<StructuredDecodeError>,
    include_raw: bool,
    data: &str,
) -> AbiDecodeResult {
    let first = errors.first().cloned();
    let has_errors = !errors.is_empty();
    AbiDecodeResult {
        decode_status: if has_errors {
            DecodeStatus::Failed
        } else {
            DecodeStatus::Decoded
        },
        usable: !has_errors,
        decoded: Some(json!({ "outer_result": outer, "results": children })),
        decode_error: first,
        decode_errors: (errors.len() > 1).then_some(errors),
        semantic_errors: None,
        return_data: (include_raw || has_errors).then(|| data.to_owned()),
    }
}

fn merge_child(index: usize, success: Option<bool>, child: AbiDecodeResult) -> Value {
    let mut object = Map::new();
    object.insert("index".into(), json!(index));
    if let Some(success) = success {
        object.insert("success".into(), json!(success));
    }
    let Value::Object(fields) = serde_json::to_value(child).expect("serializable child") else {
        unreachable!()
    };
    object.extend(fields);
    Value::Object(object)
}

struct SemanticFailure {
    error: StructuredDecodeError,
    required: bool,
}

fn apply_semantic_codecs(
    mut value: Value,
    codecs: &[SemanticCodec],
) -> Result<(Value, Vec<SemanticFailure>), DecodeFailure> {
    if codecs.len() > MAX_SEMANTIC_TRANSFORMATIONS {
        return fail("resource_limit", "too many semantic transformations");
    }
    let paths = codecs
        .iter()
        .map(|codec| parse_path(&codec.path))
        .collect::<Result<Vec<_>, _>>()?;
    for left in 0..paths.len() {
        for right in left + 1..paths.len() {
            let shared = paths[left].len().min(paths[right].len());
            if paths[left][..shared] == paths[right][..shared] {
                return fail(
                    "duplicate_semantic_path",
                    format!(
                        "semantic codec paths {} and {} conflict",
                        codecs[left].path, codecs[right].path
                    ),
                );
            }
        }
    }
    let mut errors = Vec::new();
    for (codec, path) in codecs.iter().zip(paths) {
        let current = match read_path(&value, &path) {
            Ok(value) => value.clone(),
            Err(error) => {
                errors.push(SemanticFailure {
                    error: error.0,
                    required: codec.required,
                });
                continue;
            }
        };
        match execute_semantic_codec(
            &codec.semantic_type,
            &codec.codec,
            &current,
            Some(&codec.path),
        ) {
            Ok(semantic) => {
                let replacement = json!({
                    "abi_value": current,
                    "semantic_value": semantic,
                    "semantic_type": ALLOWED_SEMANTIC_TYPE,
                    "codec": { "id": ALLOWED_CODEC_ID, "version": ALLOWED_CODEC_VERSION },
                });
                write_path(&mut value, &path, replacement)?;
            }
            Err(error) => errors.push(SemanticFailure {
                error: error.0,
                required: codec.required,
            }),
        }
    }
    Ok((value, errors))
}

fn decode_semantic_value(
    raw: &str,
    semantic_type: &str,
    codec: &CodecIdentity,
    required: bool,
) -> AbiDecodeResult {
    match execute_semantic_codec(semantic_type, codec, &Value::String(raw.into()), None) {
        Ok(value) => AbiDecodeResult {
            decode_status: DecodeStatus::Decoded,
            usable: true,
            decoded: Some(json!({
                "raw_value": raw,
                "semantic_value": value,
                "semantic_type": ALLOWED_SEMANTIC_TYPE,
                "codec": { "id": ALLOWED_CODEC_ID, "version": ALLOWED_CODEC_VERSION },
            })),
            decode_error: None,
            decode_errors: None,
            semantic_errors: None,
            return_data: Some(raw.into()),
        },
        Err(error) => {
            let detail = error.0;
            AbiDecodeResult {
                decode_status: DecodeStatus::Failed,
                usable: !required,
                decoded: Some(json!({ "raw_value": raw })),
                decode_error: Some(detail.clone()),
                decode_errors: None,
                semantic_errors: Some(vec![detail]),
                return_data: Some(raw.into()),
            }
        }
    }
}

const ALLOWED_SEMANTIC_TYPE: &str = "ekubo.sqrt_ratio_float";
const ALLOWED_CODEC_ID: &str = "ekubo.sqrt_ratio_float_to_q128";
const ALLOWED_CODEC_VERSION: u32 = 1;
const ALLOWED_REGISTRY: &str = "https://registry.npmjs.org";
const ALLOWED_PACKAGE_URL: &str = "pkg:npm/%40ekubo/sdk@0.0.10-alpha.0";
const ALLOWED_EXPORT: &str = "floatSqrtRatioToFixed";
const ALLOWED_INTEGRITY: &str = "sha512-1koNXODon0kaQBX5CbYRyfvj5viEBmyxZFlOTWPlK79gItDoIEeJIUYM8IlTu3YTT8m2xb3XcvNXUCEXuCi0rw==";

fn execute_semantic_codec(
    semantic_type: &str,
    codec: &CodecIdentity,
    value: &Value,
    path: Option<&str>,
) -> Result<String, DecodeFailure> {
    let allowed = codec.id == ALLOWED_CODEC_ID
        && codec.version == ALLOWED_CODEC_VERSION
        && codec.implementations.len() == 1
        && codec.implementations.first().is_some_and(|implementation| {
            implementation.ecosystem == "npm"
                && implementation.registry == ALLOWED_REGISTRY
                && implementation.package_url == ALLOWED_PACKAGE_URL
                && implementation.export_name == ALLOWED_EXPORT
                && implementation.integrity == ALLOWED_INTEGRITY
        })
        && semantic_type == ALLOWED_SEMANTIC_TYPE;
    if !allowed {
        return Err(DecodeFailure(StructuredDecodeError {
            code: "unsupported_codec".into(),
            message: "semantic codec identity or implementation does not match the local allowlist"
                .into(),
            path: path.map(str::to_owned),
            details: None,
        }));
    }
    let encoded = match value {
        Value::String(value) if value.starts_with("0x") => U256::from_str_radix(&value[2..], 16),
        Value::String(value) => U256::from_str_radix(value, 10),
        _ => return codec_failure("semantic codec input is not an integer string", path),
    }
    .map_err(|error| {
        DecodeFailure(StructuredDecodeError {
            code: "codec_failure".into(),
            message: format!("semantic codec failed: {error}"),
            path: path.map(str::to_owned),
            details: None,
        })
    })?;
    let mantissa_mask = (U256::from(1_u8) << 89) - U256::from(1_u8);
    let exponent = ((encoded >> 89_usize).to::<u8>()) & 0x7f;
    let shift = usize::from(exponent) + 2;
    let fixed: U256 = (encoded & mantissa_mask) << shift;
    Ok(fixed.to_string())
}

fn codec_failure<T>(message: &str, path: Option<&str>) -> Result<T, DecodeFailure> {
    Err(DecodeFailure(StructuredDecodeError {
        code: "codec_failure".into(),
        message: format!("semantic codec failed: {message}"),
        path: path.map(str::to_owned),
        details: None,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PathSegment {
    Key(String),
    Index(usize),
}

fn parse_path(path: &str) -> Result<Vec<PathSegment>, DecodeFailure> {
    if path == "$" {
        return Ok(Vec::new());
    }
    if path.is_empty() {
        return path_failure(path);
    }
    let mut result = Vec::new();
    for segment in path.split('.') {
        if segment.bytes().all(|byte| byte.is_ascii_digit()) {
            let index = segment.parse().map_err(|_| {
                failure(
                    "invalid_output_path",
                    format!("invalid semantic output path {path}"),
                )
            })?;
            result.push(PathSegment::Index(index));
        } else if valid_identifier(segment)
            && !matches!(segment, "__proto__" | "prototype" | "constructor")
        {
            result.push(PathSegment::Key(segment.into()));
        } else {
            return path_failure(path);
        }
    }
    if result.len() > MAX_RECURSION_DEPTH {
        return Err(DecodeFailure(with_path(
            detail("resource_limit", "semantic output path is too deep"),
            path,
        )));
    }
    Ok(result)
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn path_failure<T>(path: &str) -> Result<T, DecodeFailure> {
    Err(DecodeFailure(with_path(
        detail(
            "invalid_output_path",
            format!("invalid semantic output path {path}"),
        ),
        path,
    )))
}

fn read_path<'a>(mut value: &'a Value, path: &[PathSegment]) -> Result<&'a Value, DecodeFailure> {
    for segment in path {
        value = match segment {
            PathSegment::Key(key) => value.get(key),
            PathSegment::Index(index) => value.get(*index),
        }
        .ok_or_else(|| failure("invalid_output_path", "semantic output path does not exist"))?;
    }
    Ok(value)
}

fn write_path(
    value: &mut Value,
    path: &[PathSegment],
    replacement: Value,
) -> Result<(), DecodeFailure> {
    if path.is_empty() {
        *value = replacement;
        return Ok(());
    }
    let (last, parents) = path.split_last().expect("non-empty");
    let mut current = value;
    for segment in parents {
        current = match segment {
            PathSegment::Key(key) => current.get_mut(key),
            PathSegment::Index(index) => current.get_mut(*index),
        }
        .ok_or_else(|| failure("invalid_output_path", "semantic output path does not exist"))?;
    }
    let target = match last {
        PathSegment::Key(key) => current.get_mut(key),
        PathSegment::Index(index) => current.get_mut(*index),
    }
    .ok_or_else(|| failure("invalid_output_path", "semantic output path does not exist"))?;
    *target = replacement;
    Ok(())
}

fn validate_parameter_tree(parameters: &[Param], depth: usize) -> Result<usize, DecodeFailure> {
    if depth > MAX_RECURSION_DEPTH {
        return fail(
            "resource_limit",
            format!("ABI nesting exceeds depth {MAX_RECURSION_DEPTH}"),
        );
    }
    let mut count = 0_usize;
    for parameter in parameters {
        let dimensions = array_dimensions(&parameter.ty)?;
        if depth + dimensions.len() > MAX_RECURSION_DEPTH {
            return fail("resource_limit", "ABI array nesting is too deep");
        }
        let mut product = 1_usize;
        for dimension in dimensions.into_iter().flatten() {
            if dimension > MAX_COLLECTION_ITEMS {
                return fail("resource_limit", "fixed ABI array is too large");
            }
            product = product
                .checked_mul(dimension)
                .filter(|product| *product <= MAX_COLLECTION_ITEMS)
                .unwrap_or(MAX_COLLECTION_ITEMS + 1);
        }
        let nested = if parameter
            .ty
            .trim_end_matches(array_suffix)
            .ends_with("tuple")
        {
            if parameter.components.is_empty() {
                return fail("invalid_abi", "tuple parameter is missing components");
            }
            validate_parameter_tree(&parameter.components, depth + 1)?
        } else {
            1
        };
        count = count
            .checked_add(nested.saturating_mul(product))
            .filter(|count| *count <= MAX_COLLECTION_ITEMS)
            .unwrap_or(MAX_COLLECTION_ITEMS + 1);
        if count > MAX_COLLECTION_ITEMS {
            return fail("resource_limit", "ABI contains too many nested parameters");
        }
    }
    Ok(count)
}

fn array_suffix(character: char) -> bool {
    character == ']' || character == '[' || character.is_ascii_digit()
}

fn array_dimensions(ty: &str) -> Result<Vec<Option<usize>>, DecodeFailure> {
    let mut dimensions = Vec::new();
    let mut remainder = ty;
    while remainder.ends_with(']') {
        let Some(open) = remainder.rfind('[') else {
            return fail("invalid_abi", "malformed ABI array type");
        };
        let dimension = &remainder[open + 1..remainder.len() - 1];
        dimensions.push(if dimension.is_empty() {
            None
        } else {
            Some(
                dimension
                    .parse()
                    .map_err(|_| failure("invalid_abi", "malformed ABI array dimension"))?,
            )
        });
        remainder = &remainder[..open];
    }
    Ok(dimensions)
}

fn validate_return_data(value: &str) -> Result<String, DecodeFailure> {
    if !value.starts_with("0x")
        || !value.len().is_multiple_of(2)
        || !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return fail(
            "malformed_return_data",
            "return_data must be 0x-prefixed whole bytes",
        );
    }
    if (value.len() - 2) / 2 > MAX_RETURN_DATA_BYTES {
        return fail(
            "resource_limit",
            format!("return_data exceeds {MAX_RETURN_DATA_BYTES} bytes"),
        );
    }
    Ok(value.to_owned())
}

fn preservable_raw(value: &str) -> bool {
    value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.len().saturating_sub(2) / 2 <= MAX_RETURN_DATA_BYTES
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DecodeFailure> {
    hex::decode(&value[2..]).map_err(|error| {
        failure(
            "malformed_return_data",
            format!("return_data is not valid hexadecimal: {error}"),
        )
    })
}

fn all_named(parameters: &[Param]) -> bool {
    let names: BTreeSet<_> = parameters
        .iter()
        .filter(|parameter| !parameter.name.is_empty())
        .map(|parameter| parameter.name.as_str())
        .collect();
    names.len() == parameters.len()
}

fn failed_result(
    required: bool,
    error: StructuredDecodeError,
    raw: Option<String>,
) -> AbiDecodeResult {
    AbiDecodeResult {
        decode_status: DecodeStatus::Failed,
        usable: !required,
        decoded: None,
        decode_error: Some(error),
        decode_errors: None,
        semantic_errors: None,
        return_data: raw,
    }
}

fn detail(code: impl Into<String>, message: impl Into<String>) -> StructuredDecodeError {
    StructuredDecodeError {
        code: code.into(),
        message: message.into(),
        path: None,
        details: None,
    }
}

fn with_path(mut error: StructuredDecodeError, path: impl Into<String>) -> StructuredDecodeError {
    error.path = Some(path.into());
    error
}

fn failure(code: impl Into<String>, message: impl Into<String>) -> DecodeFailure {
    DecodeFailure(detail(code, message))
}

fn fail<T>(code: impl Into<String>, message: impl Into<String>) -> Result<T, DecodeFailure> {
    Err(failure(code, message))
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
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
}
