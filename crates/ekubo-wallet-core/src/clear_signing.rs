//! The vendored ERC-7730 clear-signing registry and its interpretation
//! adapter.
//!
//! Every descriptor ships inside the binary: the complete upstream registry
//! snapshot (calldata and EIP-712 descriptors across all published
//! protocols) plus the Ekubo descriptors, embedded by `build.rs`. Nothing is
//! fetched at runtime, and a descriptor can never change what is signed —
//! interpretation is review content only, and the approval digest binds the
//! exact calldata.
//!
//! Interpretation itself is the pinned `clear-signing` crate (the ERC-7730
//! v2 engine). Everything it produces is treated as untrusted display text:
//! each line passes through [`crate::sanitize`] with a length cap, the field
//! list is count-capped, and the fixed facts in the review document remain
//! authoritative over any descriptor reading.

use crate::{approval_summary::TokenMetadataMap, sanitize::stripped_capped};
use alloy::primitives::{Address, Bytes, U256};
use clear_signing::{
    DataProvider, FormatOutcome, ResolvedDescriptor, TokenMeta, TransactionContext,
    engine::{DisplayEntry, DisplayModel},
    merge_descriptors,
    types::{context::DescriptorContext, descriptor::Descriptor},
};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{LazyLock, Mutex},
};

/// Descriptor text is reviewed at vendoring time, but it still shapes what a
/// human approves, so every rendered line is capped as defense in depth.
const MAX_TEXT_LEN: usize = 120;
/// A descriptor reading never floods the review: past this many lines the
/// remainder collapses into a count.
const MAX_FIELD_LINES: usize = 48;
/// `includes` chains resolve through at most this many hops.
const MAX_INCLUDE_DEPTH: usize = 4;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/clearsign_embedded.rs"));
}
pub(crate) use embedded::CLEARSIGN_FILES;

/// Every vendored descriptor, parsed once, includes resolved, split by kind.
pub(crate) struct VendoredRegistry {
    pub calldata: Vec<ResolvedDescriptor>,
    pub eip712: Vec<ResolvedDescriptor>,
    /// Files that failed to resolve or parse. A test asserts this is empty,
    /// so at runtime a failure only means one descriptor is unavailable.
    pub failures: Vec<(&'static str, String)>,
}

pub(crate) fn registry() -> &'static VendoredRegistry {
    static REGISTRY: LazyLock<VendoredRegistry> = LazyLock::new(build_registry);
    &REGISTRY
}

fn build_registry() -> VendoredRegistry {
    let by_path: BTreeMap<&str, &str> = CLEARSIGN_FILES.iter().copied().collect();
    let mut registry = VendoredRegistry {
        calldata: Vec::new(),
        eip712: Vec::new(),
        failures: Vec::new(),
    };
    for (path, contents) in CLEARSIGN_FILES {
        // Only calldata-* and eip712-* files are standalone descriptors;
        // ercs/ files and the per-protocol common-* files exist to be
        // included by them.
        let standalone = path.starts_with("registry/")
            && path
                .rsplit('/')
                .next()
                .is_some_and(|name| name.starts_with("calldata-") || name.starts_with("eip712-"));
        if !standalone {
            continue;
        }
        match resolve_vendored(path, contents, &by_path) {
            Ok(descriptor) => {
                let Some(deployment) = descriptor.context.deployments().first().cloned() else {
                    registry
                        .failures
                        .push((path, "descriptor has no deployments".into()));
                    continue;
                };
                let resolved = ResolvedDescriptor {
                    chain_id: deployment.chain_id,
                    address: deployment.address.to_lowercase(),
                    descriptor,
                };
                match resolved.descriptor.context {
                    DescriptorContext::Contract(_) => registry.calldata.push(resolved),
                    DescriptorContext::Eip712(_) => registry.eip712.push(resolved),
                }
            }
            Err(error) => registry.failures.push((path, error)),
        }
    }
    registry
}

/// Parses one vendored file, resolving its `includes` chain against the
/// embedded tree. Include paths are relative to the including file, exactly
/// as the registry publishes them (`../../ercs/….json`).
fn resolve_vendored(
    path: &str,
    contents: &str,
    by_path: &BTreeMap<&str, &str>,
) -> Result<Descriptor, String> {
    let resolved = resolve_includes(path, contents, by_path, 0)?;
    serde_json::from_str(&resolved).map_err(|error| format!("invalid descriptor: {error}"))
}

/// Resolves a file's `includes` chain depth-first: an included file's own
/// includes resolve before the merge, because the merge consumes the field.
fn resolve_includes(
    path: &str,
    contents: &str,
    by_path: &BTreeMap<&str, &str>,
    depth: usize,
) -> Result<String, String> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(format!("include chain deeper than {MAX_INCLUDE_DEPTH}"));
    }
    let value: serde_json::Value =
        serde_json::from_str(contents).map_err(|error| format!("invalid JSON: {error}"))?;
    let Some(include) = value.get("includes").and_then(serde_json::Value::as_str) else {
        return Ok(contents.to_owned());
    };
    let target = resolve_relative(path, include)
        .ok_or_else(|| format!("include path {include} escapes the vendored tree"))?;
    let included = by_path
        .get(target.as_str())
        .ok_or_else(|| format!("include target {target} is not vendored"))?;
    let included = resolve_includes(&target, included, by_path, depth + 1)?;
    merge_descriptors(contents, &included).map_err(|error| format!("include merge failed: {error}"))
}

/// Joins a relative include path against the directory of `from`, refusing
/// to step above the vendored root.
fn resolve_relative(from: &str, include: &str) -> Option<String> {
    let mut segments: Vec<&str> = from.split('/').collect();
    segments.pop();
    for segment in include.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    Some(segments.join("/"))
}

/// The sender and target of one call, for descriptor matching.
pub struct CallEnvelope {
    pub from: Address,
    pub to: Address,
}

/// A clear-signed reading of one call: an intent line plus labeled fields.
pub struct ClearSigned {
    pub intent: String,
    pub fields: Vec<String>,
}

/// Token metadata provider bridging the plan's already-fetched display
/// metadata into the engine's formatting.
struct MapProvider<'a>(&'a TokenMetadataMap);

impl DataProvider for MapProvider<'_> {
    /// A stored symbol reaches this through the same door it reaches
    /// [`crate::approval_summary::token_label`] through — a token list, which
    /// is only as careful as whoever wrote it, and which a fresh database
    /// seeds from an aggregated upstream feed without asking the owner about
    /// each row. That renderer answers the danger by keeping only the
    /// characters real symbols use, refusing anything still containing `0x`,
    /// and printing the resolved address beside the symbol it found.
    ///
    /// This bridge did none of it, so a descriptor rendered `1000 USDC
    /// (0x<the real USDC>)` for a swap whose calldata named an attacker's
    /// token, with the address that would have given it away left in the
    /// calldata the descriptor exists to save the reviewer from reading. Both
    /// halves are applied here now: the same symbol rule, and the address
    /// bound to the symbol rather than trusted to appear somewhere else.
    ///
    /// A symbol the rule refuses answers `None`, which leaves the engine
    /// rendering the bare address — the same conservative fallback an unlisted
    /// token already gets.
    fn resolve_token(
        &self,
        _chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Option<TokenMeta>> + Send + '_>> {
        let meta = address
            .parse::<Address>()
            .ok()
            .and_then(|address| Some((address, self.0.get(&address)?)))
            .and_then(|(address, metadata)| {
                let symbol = crate::approval_summary::display_symbol(metadata.symbol.as_deref()?)?;
                let bound = format!("{symbol} ({address:#x})");
                Some(TokenMeta {
                    symbol: bound.clone(),
                    decimals: metadata.decimals?,
                    name: bound,
                })
            });
        Box::pin(async move { meta })
    }
}

/// Records every token the engine asks about instead of answering, so the
/// caller can fetch metadata before the real rendering pass.
#[derive(Default)]
struct RecordingProvider(Mutex<Vec<Address>>);

impl DataProvider for RecordingProvider {
    fn resolve_token(
        &self,
        _chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Option<TokenMeta>> + Send + '_>> {
        if let Ok(address) = address.parse::<Address>()
            && let Ok(mut recorded) = self.0.lock()
        {
            recorded.push(address);
        }
        Box::pin(async { None })
    }
}

async fn run_format(
    chain_id: u64,
    envelope: &CallEnvelope,
    calldata: &Bytes,
    value: U256,
    provider: &dyn DataProvider,
) -> Option<FormatOutcome> {
    if calldata.len() < 4 {
        return None;
    }
    let from = format!("{:#x}", envelope.from);
    let to = format!("{:#x}", envelope.to);
    let value_bytes = value.to_be_bytes_trimmed_vec();
    let context = TransactionContext {
        chain_id,
        to: &to,
        calldata,
        value: (!value_bytes.is_empty()).then_some(value_bytes.as_slice()),
        from: Some(&from),
        implementation_address: None,
    };
    clear_signing::format_calldata(&registry().calldata, &context, provider)
        .await
        .ok()
}

/// Token contracts a matching descriptor's rendering would want display
/// metadata for, so the caller can fetch symbols and decimals first.
pub async fn token_references(
    chain_id: u64,
    envelope: CallEnvelope,
    calldata: &Bytes,
) -> Vec<Address> {
    let recorder = RecordingProvider::default();
    let _ = run_format(chain_id, &envelope, calldata, U256::ZERO, &recorder).await;
    recorder.0.into_inner().unwrap_or_default()
}

/// Render a call through its vendored descriptor, if one matches exactly.
pub async fn interpret(
    chain_id: u64,
    envelope: CallEnvelope,
    calldata: &Bytes,
    value: U256,
    metadata: &TokenMetadataMap,
) -> Option<ClearSigned> {
    let provider = MapProvider(metadata);
    match run_format(chain_id, &envelope, calldata, value, &provider).await? {
        FormatOutcome::ClearSigned { model, .. } => Some(clear_signed(&model)),
        FormatOutcome::Fallback { .. } => None,
    }
}

/// A clear-signed reading of one EIP-712 payload, matched by the domain's
/// chain and verifying contract.
pub struct TypedDataReading {
    pub intent: String,
    pub fields: Vec<String>,
}

/// Render a typed-data payload through its vendored descriptor, if one
/// matches the domain exactly. Display-only, like every descriptor reading:
/// the complete payload the CLI prints remains the authoritative review.
pub async fn interpret_typed_data(typed_data: &serde_json::Value) -> Option<TypedDataReading> {
    let data: clear_signing::eip712::TypedData = serde_json::from_value(typed_data.clone()).ok()?;
    let outcome = clear_signing::format_typed_data(
        &registry().eip712,
        &data,
        &clear_signing::EmptyDataProvider,
    )
    .await
    .ok()?;
    match outcome {
        FormatOutcome::ClearSigned { model, .. } => {
            let reading = clear_signed(&model);
            Some(TypedDataReading {
                intent: reading.intent,
                fields: reading.fields,
            })
        }
        FormatOutcome::Fallback { .. } => None,
    }
}

/// Flattens the engine's display model into capped, sanitized lines.
fn clear_signed(model: &DisplayModel) -> ClearSigned {
    let intent = model.interpolated_intent.as_ref().unwrap_or(&model.intent);
    let intent = match &model.owner {
        Some(owner) => stripped_capped(&format!("{owner} — {intent}"), MAX_TEXT_LEN),
        None => stripped_capped(intent, MAX_TEXT_LEN),
    };
    let mut fields = Vec::new();
    let mut dropped = 0_usize;
    for entry in &model.entries {
        flatten_entry(entry, None, &mut fields, &mut dropped);
    }
    if dropped > 0 {
        fields.push(format!("… ({dropped} more fields)"));
    }
    ClearSigned { intent, fields }
}

fn push_line(fields: &mut Vec<String>, dropped: &mut usize, line: String) {
    if fields.len() < MAX_FIELD_LINES {
        fields.push(line);
    } else {
        *dropped += 1;
    }
}

fn labeled(prefix: Option<&str>, label: &str, value: &str) -> String {
    let label = match prefix {
        Some(prefix) => format!("{prefix} · {label}"),
        None => label.to_owned(),
    };
    format!(
        "{}: {}",
        stripped_capped(&label, MAX_TEXT_LEN),
        stripped_capped(value, MAX_TEXT_LEN)
    )
}

fn flatten_entry(
    entry: &DisplayEntry,
    prefix: Option<&str>,
    fields: &mut Vec<String>,
    dropped: &mut usize,
) {
    match entry {
        DisplayEntry::Item(item) => {
            push_line(fields, dropped, labeled(prefix, &item.label, &item.value));
        }
        DisplayEntry::Group { label, items, .. } => {
            for item in items {
                let group = match prefix {
                    Some(prefix) => format!("{prefix} · {label}"),
                    None => label.clone(),
                };
                push_line(
                    fields,
                    dropped,
                    labeled(Some(&group), &item.label, &item.value),
                );
            }
        }
        DisplayEntry::Nested {
            label,
            intent,
            entries,
        } => {
            push_line(fields, dropped, labeled(prefix, label, intent));
            // One level of nesting is plenty for a review; deeper structure
            // collapses into the count so the exact facts stay dominant.
            if prefix.is_none() {
                for nested in entries {
                    flatten_entry(nested, Some(label), fields, dropped);
                }
            } else {
                *dropped += entries.len();
            }
        }
    }
}

/// Test fixture shared with the approval-summary tests: a `VeToken`
/// `stake(amount, end)` call on its first deployed chain, derived from the
/// vendored descriptor itself.
#[cfg(test)]
pub(crate) fn stake_fixture() -> (u64, Address, Vec<u8>) {
    use alloy::dyn_abi::DynSolValue;
    use alloy::primitives::keccak256;
    let (_, contents) = CLEARSIGN_FILES
        .iter()
        .find(|(path, _)| path.ends_with("registry/ekubo/calldata-VeToken.json"))
        .expect("vetoken descriptor vendored");
    let descriptor: serde_json::Value = serde_json::from_str(contents).expect("valid JSON");
    let deployment = &descriptor["context"]["contract"]["deployments"][0];
    let chain = deployment["chainId"].as_u64().expect("chain id");
    let address = deployment["address"]
        .as_str()
        .expect("address")
        .parse::<Address>()
        .expect("valid address");
    // Canonical selector for the two-parameter stake format the descriptor
    // documents: the format key with parameter names stripped.
    assert!(
        descriptor["display"]["formats"]
            .as_object()
            .expect("formats")
            .contains_key("stake(uint128 amount, uint64 end)"),
        "stake format vendored"
    );
    let selector = &keccak256("stake(uint128,uint64)".as_bytes())[..4];
    let value = DynSolValue::Tuple(vec![
        DynSolValue::Uint(U256::from(1_000_000_u64), 128),
        DynSolValue::Uint(U256::from(1_900_000_000_u64), 64),
    ]);
    let mut calldata = selector.to_vec();
    calldata.extend(value.abi_encode_params());
    (chain, address, calldata)
}

#[cfg(test)]
#[path = "clear_signing_test.rs"]
mod tests;
