//! ERC-7730 clear signing for the approval review.
//!
//! Descriptors are vendored in `clearsign/` and embedded at compile time; the
//! wallet never fetches display metadata from the network. They are display
//! metadata only: matching is by exact chain ID, contract address, and
//! function selector, every rendered string is sanitized, and any mismatch
//! falls back to the generic selector display. The approval digest binds the
//! exact calldata, so a wrong descriptor can never change what is signed.

use crate::approval_summary::{TokenMetadataMap, format_token_amount};
use alloy::{
    dyn_abi::{DynSolType, DynSolValue},
    primitives::{Address, Bytes, keccak256},
};
use anyhow::{Context, Result, anyhow, ensure};
use chrono::DateTime;
use serde::Deserialize;
use std::{collections::BTreeMap, fmt::Write as _, str::FromStr, sync::OnceLock};

/// Nested `calldata` fields recurse at most this deep.
const MAX_NESTED_DEPTH: usize = 2;
/// A `bytes[]` action list renders at most this many elements.
const MAX_ARRAY_ITEMS: usize = 16;
/// Descriptor-supplied text (labels, intents, enum values) is capped here.
const MAX_TEXT_LEN: usize = 120;

/// Embedded verbatim copies of the vendored registry files.
static DESCRIPTOR_SOURCES: &[(&str, &str)] = &[
    (
        "ekubo/calldata-MEVCaptureRouter.json",
        include_str!("../clearsign/ekubo/calldata-MEVCaptureRouter.json"),
    ),
    (
        "ekubo/calldata-Orders.json",
        include_str!("../clearsign/ekubo/calldata-Orders.json"),
    ),
    (
        "ekubo/calldata-Positions.json",
        include_str!("../clearsign/ekubo/calldata-Positions.json"),
    ),
    (
        "ekubo/calldata-Ve33Periphery.json",
        include_str!("../clearsign/ekubo/calldata-Ve33Periphery.json"),
    ),
    (
        "ekubo/calldata-Ve33Positions.json",
        include_str!("../clearsign/ekubo/calldata-Ve33Positions.json"),
    ),
    (
        "ekubo/calldata-VeToken.json",
        include_str!("../clearsign/ekubo/calldata-VeToken.json"),
    ),
];

#[derive(Debug, Deserialize)]
struct RawDescriptor {
    context: RawContext,
    metadata: RawMetadata,
    display: RawDisplay,
}

#[derive(Debug, Deserialize)]
struct RawContext {
    contract: RawContract,
}

#[derive(Debug, Deserialize)]
struct RawContract {
    deployments: Vec<RawDeployment>,
}

#[derive(Debug, Deserialize)]
struct RawDeployment {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    owner: Option<String>,
    #[serde(rename = "contractName")]
    contract_name: Option<String>,
    #[serde(default)]
    constants: BTreeMap<String, String>,
    #[serde(default)]
    enums: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct RawDisplay {
    formats: BTreeMap<String, RawFormat>,
}

#[derive(Debug, Deserialize)]
struct RawFormat {
    intent: Option<String>,
    #[serde(rename = "interpolatedIntent")]
    interpolated_intent: Option<String>,
    #[serde(default)]
    fields: Vec<RawField>,
}

#[derive(Debug, Deserialize)]
struct RawField {
    path: String,
    label: String,
    format: String,
    #[serde(default)]
    params: BTreeMap<String, serde_json::Value>,
}

/// One vendored descriptor, parsed and selector-indexed.
pub struct Descriptor {
    owner: String,
    contract_name: String,
    deployments: Vec<(u64, Address)>,
    constants: BTreeMap<String, String>,
    enums: BTreeMap<String, BTreeMap<String, String>>,
    formats: BTreeMap<[u8; 4], FunctionFormat>,
}

/// A display format bound to one parsed function signature.
struct FunctionFormat {
    signature: FunctionSignature,
    intent: Option<String>,
    interpolated_intent: Option<String>,
    fields: Vec<RawField>,
}

/// A function signature parsed into named, typed parameters.
struct FunctionSignature {
    name: String,
    params: Vec<Param>,
}

/// One parameter: its canonical Solidity type, its name, and named children
/// when the type is a tuple (possibly behind array suffixes).
struct Param {
    name: String,
    canonical: String,
    components: Vec<Param>,
}

impl FunctionSignature {
    fn canonical(&self) -> String {
        let mut out = String::new();
        let _ = write!(out, "{}(", self.name);
        for (index, param) in self.params.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&param.canonical);
        }
        out.push(')');
        out
    }

    fn selector(&self) -> [u8; 4] {
        let hash = keccak256(self.canonical().as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }

    fn decode_type(&self) -> Result<DynSolType> {
        let types = self
            .params
            .iter()
            .map(|param| DynSolType::parse(&param.canonical).map_err(|error| anyhow!("{error}")))
            .collect::<Result<Vec<_>>>()?;
        Ok(DynSolType::Tuple(types))
    }
}

/// Parse `name(type1 name1, (a x, b y) name2, ...)` into a signature tree.
fn parse_signature(text: &str) -> Result<FunctionSignature> {
    let open = text.find('(').context("signature has no parameter list")?;
    ensure!(text.ends_with(')'), "signature does not end with ')'");
    let name = text[..open].trim();
    ensure!(
        !name.is_empty()
            && name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_'),
        "invalid function name {name:?}"
    );
    let body = &text[open + 1..text.len() - 1];
    Ok(FunctionSignature {
        name: name.into(),
        params: parse_params(body)?,
    })
}

fn parse_params(body: &str) -> Result<Vec<Param>> {
    let mut params = Vec::new();
    for piece in split_top_level(body) {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        params.push(parse_param(piece)?);
    }
    Ok(params)
}

/// Split on commas that are not nested inside parentheses.
fn split_top_level(body: &str) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0_usize;
    for (index, character) in body.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                pieces.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    pieces.push(&body[start..]);
    pieces
}

fn parse_param(piece: &str) -> Result<Param> {
    if let Some(rest) = piece.strip_prefix('(') {
        // Tuple: find the matching close parenthesis in the original piece.
        let mut depth = 1_usize;
        let mut close = None;
        for (index, character) in rest.char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(index);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.context("unbalanced parentheses in signature")?;
        let inner = &rest[..close];
        let tail = rest[close + 1..].trim();
        let (suffix, name) = split_array_suffix_and_name(tail)?;
        let components = parse_params(inner)?;
        let mut canonical = String::from("(");
        for (index, component) in components.iter().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            canonical.push_str(&component.canonical);
        }
        canonical.push(')');
        canonical.push_str(suffix);
        Ok(Param {
            name,
            canonical,
            components,
        })
    } else {
        let mut parts = piece.split_whitespace();
        let ty = parts.next().context("empty parameter")?;
        let name = parts.next().unwrap_or("").to_string();
        ensure!(
            parts.next().is_none(),
            "unexpected token in parameter {piece:?}"
        );
        Ok(Param {
            name,
            canonical: normalize_type(ty),
            components: Vec::new(),
        })
    }
}

/// Split `[]... name` into the array suffix and the parameter name.
fn split_array_suffix_and_name(tail: &str) -> Result<(&str, String)> {
    let end = tail
        .char_indices()
        .find(|(_, character)| !matches!(character, '[' | ']' | '0'..='9'))
        .map_or(tail.len(), |(index, _)| index);
    let suffix = &tail[..end];
    ensure!(
        suffix.chars().all(|c| matches!(c, '[' | ']' | '0'..='9')),
        "invalid array suffix {suffix:?}"
    );
    Ok((suffix, tail[end..].trim().to_string()))
}

fn normalize_type(ty: &str) -> String {
    // `uint`/`int` aliases expand; every other type is already canonical.
    let (base, suffix) = ty
        .find('[')
        .map_or((ty, ""), |index| (&ty[..index], &ty[index..]));
    let base = match base {
        "uint" => "uint256",
        "int" => "int256",
        other => other,
    };
    format!("{base}{suffix}")
}

impl Descriptor {
    fn parse(source_name: &str, source: &str) -> Result<Self> {
        let raw: RawDescriptor = serde_json::from_str(source)
            .with_context(|| format!("descriptor {source_name} is not valid JSON"))?;
        let deployments = raw
            .context
            .contract
            .deployments
            .iter()
            .map(|deployment| {
                Ok((
                    deployment.chain_id,
                    Address::from_str(&deployment.address)
                        .with_context(|| format!("bad address in {source_name}"))?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!deployments.is_empty(), "{source_name} has no deployments");
        let mut formats = BTreeMap::new();
        for (signature_text, format) in raw.display.formats {
            let signature = parse_signature(&signature_text)
                .with_context(|| format!("bad signature in {source_name}: {signature_text}"))?;
            // Reject descriptors whose paths or references do not resolve, so
            // a vendoring mistake fails tests instead of silently degrading.
            for field in &format.fields {
                validate_path(&signature, &field.path)
                    .with_context(|| format!("{source_name}: field {}", field.path))?;
                validate_params(&raw.metadata, &signature, field)
                    .with_context(|| format!("{source_name}: field {}", field.path))?;
            }
            signature
                .decode_type()
                .with_context(|| format!("{source_name}: undecodable {signature_text}"))?;
            let selector = signature.selector();
            ensure!(
                !formats.contains_key(&selector),
                "{source_name}: duplicate selector for {signature_text}"
            );
            formats.insert(
                selector,
                FunctionFormat {
                    signature,
                    intent: format.intent,
                    interpolated_intent: format.interpolated_intent,
                    fields: format.fields,
                },
            );
        }
        Ok(Self {
            owner: raw.metadata.owner.clone().unwrap_or_default(),
            contract_name: raw
                .metadata
                .contract_name
                .clone()
                .unwrap_or_else(|| source_name.into()),
            deployments,
            constants: raw.metadata.constants,
            enums: raw.metadata.enums,
            formats,
        })
    }
}

/// Validate that a dotted field path resolves within the signature tree, or
/// is a supported `@.` transaction-container reference.
fn validate_path(signature: &FunctionSignature, path: &str) -> Result<()> {
    if let Some(container) = path.strip_prefix("@.") {
        ensure!(
            matches!(container, "from" | "to"),
            "unsupported container path @.{container}"
        );
        return Ok(());
    }
    let mut current: &[Param] = &signature.params;
    for segment in path.split('.') {
        if segment == "[]" {
            // Array iteration keeps the same component shape.
            continue;
        }
        let found = current
            .iter()
            .find(|param| param.name == segment)
            .with_context(|| format!("path segment {segment} not found"))?;
        current = &found.components;
    }
    Ok(())
}

fn validate_params(
    metadata: &RawMetadata,
    signature: &FunctionSignature,
    field: &RawField,
) -> Result<()> {
    match field.format.as_str() {
        "enum" => {
            let reference = field
                .params
                .get("$ref")
                .and_then(|value| value.as_str())
                .context("enum field without $ref")?;
            let name = reference
                .strip_prefix("$.metadata.enums.")
                .context("unsupported enum $ref")?;
            ensure!(metadata.enums.contains_key(name), "unknown enum {name}");
        }
        "tokenAmount" => {
            if let Some(token) = field.params.get("token").and_then(|value| value.as_str()) {
                resolve_constant_address(&metadata.constants, token)
                    .context("tokenAmount token does not resolve")?;
            }
            if let Some(token_path) = field
                .params
                .get("tokenPath")
                .and_then(|value| value.as_str())
            {
                validate_path(signature, token_path).context("bad tokenPath")?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve_constant_address(
    constants: &BTreeMap<String, String>,
    reference: &str,
) -> Result<Address> {
    let literal = reference
        .strip_prefix("$.metadata.constants.")
        .map_or_else(
            || Ok(reference.to_string()),
            |name| {
                constants
                    .get(name)
                    .cloned()
                    .with_context(|| format!("unknown constant {name}"))
            },
        )?;
    Address::from_str(&literal).context("constant is not an address")
}

fn registry() -> &'static Vec<Descriptor> {
    static REGISTRY: OnceLock<Vec<Descriptor>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        DESCRIPTOR_SOURCES
            .iter()
            .map(|(name, source)| {
                Descriptor::parse(name, source).expect("vendored descriptor is test-verified")
            })
            .collect()
    })
}

fn lookup(chain_id: u64, target: Address) -> Option<&'static Descriptor> {
    registry().iter().find(|descriptor| {
        descriptor
            .deployments
            .iter()
            .any(|(chain, address)| *chain == chain_id && *address == target)
    })
}

/// The transaction fields a descriptor may reference through `@.` container
/// paths, alongside the calldata itself.
#[derive(Clone, Copy)]
pub struct CallEnvelope {
    pub from: Address,
    pub to: Address,
}

/// A clear-signed reading of one call: an intent line plus labeled fields.
pub struct ClearSigned {
    pub intent: String,
    pub fields: Vec<String>,
    /// Token contracts the rendering wants symbol/decimals for.
    pub token_references: Vec<Address>,
}

/// Collect token contracts referenced by descriptors matching a call, so the
/// caller can fetch their display metadata before rendering.
#[must_use]
pub fn token_references(chain_id: u64, envelope: CallEnvelope, calldata: &Bytes) -> Vec<Address> {
    interpret(chain_id, envelope, calldata, &TokenMetadataMap::new())
        .map(|reading| reading.token_references)
        .unwrap_or_default()
}

/// Render a call through its vendored descriptor, if one matches exactly.
#[must_use]
pub fn interpret(
    chain_id: u64,
    envelope: CallEnvelope,
    calldata: &Bytes,
    metadata: &TokenMetadataMap,
) -> Option<ClearSigned> {
    interpret_at_depth(chain_id, envelope, calldata, metadata, 0)
}

fn interpret_at_depth(
    chain_id: u64,
    envelope: CallEnvelope,
    calldata: &Bytes,
    metadata: &TokenMetadataMap,
    depth: usize,
) -> Option<ClearSigned> {
    let target = envelope.to;
    let descriptor = lookup(chain_id, target)?;
    let selector: [u8; 4] = calldata.get(..4)?.try_into().ok()?;
    let format = descriptor.formats.get(&selector)?;
    let decode_type = format.signature.decode_type().ok()?;
    let decoded = decode_type.abi_decode_params(&calldata[4..]).ok()?;
    // Reject non-canonical encodings exactly like the generic decoder.
    if decoded.abi_encode_params() != calldata[4..] {
        return None;
    }
    let DynSolValue::Tuple(values) = decoded else {
        return None;
    };

    let mut token_references = Vec::new();
    let mut fields = Vec::new();
    for field in &format.fields {
        render_field(
            descriptor,
            format,
            &values,
            field,
            metadata,
            depth,
            chain_id,
            envelope,
            &mut fields,
            &mut token_references,
        );
    }

    let intent = format
        .interpolated_intent
        .as_deref()
        .map(|template| interpolate(template, format, &values))
        .or_else(|| format.intent.clone())
        .unwrap_or_else(|| format.signature.name.clone());
    let context = if descriptor.owner.is_empty() {
        descriptor.contract_name.clone()
    } else {
        format!("{} — {}", descriptor.owner, descriptor.contract_name)
    };
    Some(ClearSigned {
        intent: sanitize(&format!("{intent} [{context}]")),
        fields,
        token_references,
    })
}

#[allow(clippy::too_many_arguments)] // Internal renderer threading shared context.
fn render_field(
    descriptor: &Descriptor,
    format: &FunctionFormat,
    values: &[DynSolValue],
    field: &RawField,
    metadata: &TokenMetadataMap,
    depth: usize,
    chain_id: u64,
    envelope: CallEnvelope,
    fields: &mut Vec<String>,
    token_references: &mut Vec<Address>,
) {
    let label = sanitize(&field.label);
    // Container paths reference the transaction envelope rather than the
    // decoded calldata; both addresses render checksummed.
    if let Some(container) = field.path.strip_prefix("@.") {
        let rendered = match container {
            "from" => envelope.from.to_checksum(None),
            "to" => envelope.to.to_checksum(None),
            other => format!("<container path @.{other} unsupported>"),
        };
        fields.push(format!("{label}: {rendered}"));
        return;
    }
    let Some(resolved) = resolve_path(&format.signature.params, values, &field.path) else {
        fields.push(format!("{label}: <path {} did not resolve>", field.path));
        return;
    };
    for (index, value) in resolved.iter().enumerate() {
        let position = if resolved.len() > 1 {
            format!("{label} {}", index + 1)
        } else {
            label.clone()
        };
        match field.format.as_str() {
            "calldata" => {
                // The vendored descriptors only self-reference (`@.to`), so
                // nested actions decode against the same contract.
                let callee_is_self = field
                    .params
                    .get("calleePath")
                    .and_then(|value| value.as_str())
                    == Some("@.to");
                if let DynSolValue::Bytes(inner) = value {
                    let inner = Bytes::from(inner.clone());
                    let nested = (callee_is_self && depth < MAX_NESTED_DEPTH)
                        .then(|| {
                            interpret_at_depth(chain_id, envelope, &inner, metadata, depth + 1)
                        })
                        .flatten();
                    if let Some(nested) = nested {
                        fields.push(format!("{position}: {}", nested.intent));
                        token_references.extend(nested.token_references);
                        for line in nested.fields {
                            fields.push(format!("{position} · {line}"));
                        }
                    } else {
                        fields.push(format!(
                            "{position}: nested call, selector {}, {} bytes",
                            selector_text(&inner),
                            inner.len()
                        ));
                    }
                } else {
                    fields.push(format!("{position}: <not bytes>"));
                }
            }
            "tokenAmount" => {
                let token = field
                    .params
                    .get("token")
                    .and_then(|value| value.as_str())
                    .and_then(|reference| {
                        resolve_constant_address(&descriptor.constants, reference).ok()
                    })
                    .or_else(|| {
                        field
                            .params
                            .get("tokenPath")
                            .and_then(|value| value.as_str())
                            .and_then(|path| resolve_path(&format.signature.params, values, path))
                            .and_then(|resolved| match resolved.first() {
                                Some(DynSolValue::Address(address)) => Some(*address),
                                _ => None,
                            })
                    });
                match (token, integer_magnitude(value)) {
                    (Some(token), Some((negative, magnitude))) => {
                        token_references.push(token);
                        let display = metadata.get(&token).cloned().unwrap_or_default();
                        let sign = if negative { "-" } else { "" };
                        fields.push(format!(
                            "{position}: {sign}{}",
                            format_token_amount(magnitude, token, &display)
                        ));
                    }
                    _ => fields.push(format!("{position}: {}", render_raw(value))),
                }
            }
            "enum" => {
                let rendered = field
                    .params
                    .get("$ref")
                    .and_then(|value| value.as_str())
                    .and_then(|reference| reference.strip_prefix("$.metadata.enums."))
                    .and_then(|name| descriptor.enums.get(name))
                    .and_then(|mapping| mapping.get(&enum_key(value)))
                    .map(|text| sanitize(text));
                fields.push(format!(
                    "{position}: {}",
                    rendered.unwrap_or_else(|| render_raw(value))
                ));
            }
            "date" => {
                let rendered = match integer_magnitude(value) {
                    Some((false, seconds)) => i64::try_from(seconds)
                        .ok()
                        .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
                        .map(|moment| moment.to_rfc3339()),
                    _ => None,
                };
                fields.push(format!(
                    "{position}: {}",
                    rendered.unwrap_or_else(|| render_raw(value))
                ));
            }
            "duration" => {
                let rendered = integer_magnitude(value)
                    .filter(|(negative, _)| !negative)
                    .map(|(_, seconds)| render_duration(seconds));
                fields.push(format!(
                    "{position}: {}",
                    rendered.unwrap_or_else(|| render_raw(value))
                ));
            }
            // `raw`, `addressName`, and anything unrecognized all render the
            // decoded value directly; addressName's name sources are a
            // hardware-wallet concern and the checksummed address is already
            // the trustworthy representation here.
            _ => fields.push(format!("{position}: {}", render_raw(value))),
        }
    }
}

/// Resolve a dotted path against decoded values. `[]` fans out over arrays,
/// so the result is a list of leaf values.
fn resolve_path<'a>(
    params: &[Param],
    values: &'a [DynSolValue],
    path: &str,
) -> Option<Vec<&'a DynSolValue>> {
    let mut current: Vec<(&[Param], &DynSolValue)> = Vec::new();
    let mut shape = params;
    // Seed with a virtual tuple over the top-level parameters.
    let segments: Vec<&str> = path.split('.').collect();
    let first = segments.first()?;
    let index = shape.iter().position(|param| param.name == *first)?;
    current.push((&shape[index].components, values.get(index)?));
    shape = &shape[index].components;
    for segment in &segments[1..] {
        let mut next = Vec::new();
        for (components, value) in current {
            if *segment == "[]" {
                match value {
                    DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
                        for item in items.iter().take(MAX_ARRAY_ITEMS) {
                            next.push((components, item));
                        }
                    }
                    _ => return None,
                }
            } else {
                let index = components.iter().position(|param| param.name == *segment)?;
                let DynSolValue::Tuple(inner) = value else {
                    return None;
                };
                next.push((&components[index].components, inner.get(index)?));
            }
        }
        current = next;
        if let Some((components, _)) = current.first() {
            shape = components;
        }
    }
    let _ = shape;
    Some(current.into_iter().map(|(_, value)| value).collect())
}

fn integer_magnitude(value: &DynSolValue) -> Option<(bool, alloy::primitives::U256)> {
    match value {
        DynSolValue::Uint(value, _) => Some((false, *value)),
        DynSolValue::Int(value, _) => {
            let negative = value.is_negative();
            Some((negative, value.unsigned_abs()))
        }
        _ => None,
    }
}

fn enum_key(value: &DynSolValue) -> String {
    match value {
        DynSolValue::Bool(flag) => flag.to_string(),
        other => render_raw(other),
    }
}

fn render_raw(value: &DynSolValue) -> String {
    match value {
        DynSolValue::Address(address) => address.to_checksum(None),
        DynSolValue::Bool(flag) => flag.to_string(),
        DynSolValue::Uint(number, _) => number.to_string(),
        DynSolValue::Int(number, _) => number.to_string(),
        DynSolValue::FixedBytes(bytes, length) => format!("0x{}", hex::encode(&bytes[..*length])),
        DynSolValue::Bytes(bytes) => {
            if bytes.len() > 64 {
                format!("0x{}… ({} bytes)", hex::encode(&bytes[..32]), bytes.len())
            } else {
                format!("0x{}", hex::encode(bytes))
            }
        }
        DynSolValue::String(text) => sanitize(text),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
            let rendered: Vec<String> = items.iter().take(8).map(render_raw).collect();
            let suffix = if items.len() > 8 { ", …" } else { "" };
            format!("[{}{suffix}]", rendered.join(", "))
        }
        DynSolValue::Tuple(items) => {
            let rendered: Vec<String> = items.iter().take(8).map(render_raw).collect();
            format!("({})", rendered.join(", "))
        }
        // CustomStruct exists only with the dyn-abi eip712 feature; ABI
        // decoding of calldata never produces it.
        DynSolValue::CustomStruct { tuple, .. } => {
            let rendered: Vec<String> = tuple.iter().take(8).map(render_raw).collect();
            format!("({})", rendered.join(", "))
        }
        DynSolValue::Function(_) => "<unsupported>".into(),
    }
}

fn render_duration(total_seconds: alloy::primitives::U256) -> String {
    let seconds = u64::try_from(total_seconds).unwrap_or(u64::MAX);
    let (days, rem) = (seconds / 86_400, seconds % 86_400);
    let (hours, rem) = (rem / 3_600, rem % 3_600);
    let (minutes, secs) = (rem / 60, rem % 60);
    let mut out = String::new();
    for (amount, unit) in [(days, "d"), (hours, "h"), (minutes, "m"), (secs, "s")] {
        if amount > 0 || (unit == "s" && out.is_empty()) {
            let _ = write!(out, "{amount}{unit} ");
        }
    }
    format!("{} ({seconds} seconds)", out.trim_end())
}

/// Substitute `{path}` templates in an interpolated intent with raw-rendered
/// values; a path that fails to resolve keeps its literal placeholder.
fn interpolate(template: &str, format: &FunctionFormat, values: &[DynSolValue]) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let Some(close) = rest[open..].find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let path = &rest[open + 1..open + close];
        match resolve_path(&format.signature.params, values, path) {
            Some(resolved) if resolved.len() == 1 => out.push_str(&render_raw(resolved[0])),
            _ => {
                out.push('{');
                out.push_str(path);
                out.push('}');
            }
        }
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    out
}

fn selector_text(data: &Bytes) -> String {
    if data.len() < 4 {
        "none".into()
    } else {
        format!("0x{}", hex::encode(&data[..4]))
    }
}

/// Descriptor text is reviewed at vendoring time, but it still shapes what a
/// human approves, so control characters are stripped and length is capped as
/// defense in depth.
fn sanitize(text: &str) -> String {
    crate::sanitize::stripped_capped(text, MAX_TEXT_LEN)
}

/// Test fixture shared with the approval-summary tests: a `VeToken`
/// `stake(amount, end)` call on its first deployed chain.
#[cfg(test)]
pub(crate) fn stake_fixture() -> (u64, Address, Vec<u8>) {
    use alloy::primitives::U256;
    let descriptor = registry()
        .iter()
        .find(|descriptor| descriptor.contract_name.contains("Vote-Escrow"))
        .expect("vetoken descriptor vendored");
    let (chain, address) = descriptor.deployments[0];
    let (selector, _) = descriptor
        .formats
        .iter()
        .find(|(_, format)| format.signature.name == "stake" && format.signature.params.len() == 2)
        .expect("stake(amount, end) format");
    let value = DynSolValue::Tuple(vec![
        DynSolValue::Uint(U256::from(1_000_000_u64), 128),
        DynSolValue::Uint(U256::from(1_900_000_000_u64), 64),
    ]);
    let mut calldata = selector.to_vec();
    calldata.extend(value.abi_encode_params());
    (chain, address, calldata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    #[test]
    fn every_vendored_descriptor_parses_and_validates() {
        // Descriptor::parse validates signatures, selectors, paths, enum and
        // constant references; registry() panics on any failure.
        let descriptors = registry();
        assert_eq!(descriptors.len(), DESCRIPTOR_SOURCES.len());
        let total_formats: usize = descriptors
            .iter()
            .map(|descriptor| descriptor.formats.len())
            .sum();
        assert!(total_formats > 100, "expected a substantial format corpus");
    }

    #[test]
    fn signature_parsing_produces_canonical_selectors() {
        let signature = parse_signature(
            "swap((address token0, address token1, bytes32 config) poolKey, bool isToken1, \
             int128 amount, uint96 sqrtRatioLimit, uint256 skipAhead, int256 calculatedAmountThreshold)",
        )
        .unwrap();
        assert_eq!(
            signature.canonical(),
            "swap((address,address,bytes32),bool,int128,uint96,uint256,int256)"
        );
        assert_eq!(signature.params[0].components[1].name, "token1");
    }

    fn envelope(target: Address) -> CallEnvelope {
        CallEnvelope {
            from: Address::repeat_byte(0xAA),
            to: target,
        }
    }

    fn router() -> (&'static Descriptor, u64, Address) {
        let descriptor = registry()
            .iter()
            .find(|descriptor| descriptor.contract_name.contains("Router"))
            .expect("router descriptor vendored");
        let (chain, address) = descriptor.deployments[0];
        (descriptor, chain, address)
    }

    fn encode_swap() -> Bytes {
        let signature = parse_signature(
            "swap((address token0, address token1, bytes32 config) poolKey, bool isToken1, \
             int128 amount, uint96 sqrtRatioLimit, uint256 skipAhead, int256 calculatedAmountThreshold)",
        )
        .unwrap();
        let value = DynSolValue::Tuple(vec![
            DynSolValue::Tuple(vec![
                DynSolValue::Address(Address::repeat_byte(0x11)),
                DynSolValue::Address(Address::repeat_byte(0x22)),
                DynSolValue::FixedBytes(alloy::primitives::B256::ZERO, 32),
            ]),
            DynSolValue::Bool(true),
            DynSolValue::Int(alloy::primitives::I256::try_from(1_000_000).unwrap(), 128),
            DynSolValue::Uint(U256::from(0_u8), 96),
            DynSolValue::Uint(U256::ZERO, 256),
            DynSolValue::Int(alloy::primitives::I256::try_from(-5).unwrap(), 256),
        ]);
        let mut calldata = signature.selector().to_vec();
        calldata.extend(value.abi_encode_params());
        calldata.into()
    }

    #[test]
    fn renders_a_router_swap_with_enum_and_intent() {
        let (_descriptor, chain, address) = router();
        let reading = interpret(
            chain,
            envelope(address),
            &encode_swap(),
            &TokenMetadataMap::new(),
        )
        .expect("swap matches the vendored descriptor");
        assert!(reading.intent.contains("Swap"), "{}", reading.intent);
        assert!(
            reading.intent.contains("Ekubo"),
            "intent names the protocol: {}",
            reading.intent
        );
        let joined = reading.fields.join("\n");
        assert!(joined.contains("Pool token 0"), "{joined}");
        assert!(
            joined.contains(&Address::repeat_byte(0x11).to_checksum(None)),
            "{joined}"
        );
        assert!(joined.contains("Specified pool token: Token 1"), "{joined}");
        assert!(joined.contains("Specified amount: 1000000"), "{joined}");
    }

    #[test]
    fn unknown_chain_address_or_selector_yields_none() {
        let (_descriptor, chain, address) = router();
        assert!(
            interpret(
                999_999,
                envelope(address),
                &encode_swap(),
                &TokenMetadataMap::new()
            )
            .is_none()
        );
        assert!(
            interpret(
                chain,
                envelope(Address::repeat_byte(0x99)),
                &encode_swap(),
                &TokenMetadataMap::new()
            )
            .is_none()
        );
        assert!(
            interpret(
                chain,
                envelope(address),
                &Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
                &TokenMetadataMap::new()
            )
            .is_none()
        );
    }

    #[test]
    fn non_canonical_calldata_is_rejected() {
        let mut padded = encode_swap().to_vec();
        padded.push(0);
        let (_descriptor, chain, address) = router();
        assert!(
            interpret(
                chain,
                envelope(address),
                &padded.into(),
                &TokenMetadataMap::new()
            )
            .is_none()
        );
    }

    #[test]
    fn vetoken_lock_renders_token_amount_and_date() {
        let descriptor = registry()
            .iter()
            .find(|descriptor| descriptor.contract_name.contains("Vote-Escrow"))
            .expect("vetoken descriptor vendored");
        let (chain, address) = descriptor.deployments[0];
        let (selector, format) = descriptor
            .formats
            .iter()
            .find(|(_, format)| {
                format.signature.name == "stake" && format.signature.params.len() == 2
            })
            .expect("stake(amount, end) format");
        let names: Vec<&str> = format
            .signature
            .params
            .iter()
            .map(|param| param.name.as_str())
            .collect();
        assert_eq!(names, ["amount", "end"]);
        let value = DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from(1_500_000_000_000_000_000_u128), 128),
            DynSolValue::Uint(U256::from(1_900_000_000_u64), 64),
        ]);
        let mut calldata = selector.to_vec();
        calldata.extend(value.abi_encode_params());

        let stake_token =
            resolve_constant_address(&descriptor.constants, "$.metadata.constants.stakeToken")
                .unwrap();
        let metadata = TokenMetadataMap::from([(
            stake_token,
            crate::approval_summary::TokenMetadata {
                symbol: Some("STONX".into()),
                decimals: Some(18),
            },
        )]);
        let reading = interpret(chain, envelope(address), &calldata.into(), &metadata).unwrap();
        let joined = reading.fields.join("\n");
        assert!(joined.contains("1.5 STONX"), "{joined}");
        assert!(joined.contains("2030-"), "date rendered: {joined}");
        assert!(reading.token_references.contains(&stake_token));
    }

    #[test]
    fn multicall_actions_render_nested_intents() {
        let descriptor = registry()
            .iter()
            .find(|descriptor| descriptor.contract_name.contains("Vote-Escrow"))
            .expect("vetoken descriptor vendored");
        let (chain, address) = descriptor.deployments[0];
        let (lock_selector, _) = descriptor
            .formats
            .iter()
            .find(|(_, format)| {
                format.signature.name == "stake" && format.signature.params.len() == 2
            })
            .unwrap();
        let lock_value = DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from(7_u8), 128),
            DynSolValue::Uint(U256::from(1_900_000_000_u64), 64),
        ]);
        let mut lock_call = lock_selector.to_vec();
        lock_call.extend(lock_value.abi_encode_params());

        let (multicall_selector, _) = descriptor
            .formats
            .iter()
            .find(|(_, format)| format.signature.name == "multicall")
            .expect("multicall format");
        let outer = DynSolValue::Tuple(vec![DynSolValue::Array(vec![DynSolValue::Bytes(
            lock_call,
        )])]);
        let mut calldata = multicall_selector.to_vec();
        calldata.extend(outer.abi_encode_params());

        let reading = interpret(
            chain,
            envelope(address),
            &calldata.into(),
            &TokenMetadataMap::new(),
        )
        .unwrap();
        let joined = reading.fields.join("\n");
        assert!(
            joined.contains("Action") && joined.to_lowercase().contains("stake"),
            "{joined}"
        );
    }

    #[test]
    fn descriptor_text_cannot_forge_review_lines() {
        assert_eq!(sanitize("a\u{1b}[31m\nb"), "a[31mb");
        assert_eq!(sanitize(&"x".repeat(500)).len(), MAX_TEXT_LEN);
    }
}
