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
use alloy::{
    dyn_abi::{DynSolValue, JsonAbiExt},
    json_abi::Function,
    primitives::{Address, Bytes, I256, U256},
};
use clear_signing::{
    DataProvider, FormatOutcome, ResolvedDescriptor, TokenMeta, TransactionContext,
    engine::{DisplayEntry, DisplayModel},
    merge_descriptors,
    types::{context::DescriptorContext, descriptor::Descriptor},
};
use std::{
    collections::{BTreeMap, BTreeSet},
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
    calldata_formats: Vec<CanonicalFormat>,
    /// Files that failed to resolve or parse. A test asserts this is empty,
    /// so at runtime a failure only means one descriptor is unavailable.
    pub failures: Vec<(&'static str, String)>,
}

struct CanonicalFormat {
    chain_id: u64,
    address: String,
    function: Function,
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
        calldata_formats: Vec::new(),
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
            Ok((descriptor, resolved_json)) => {
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
                    DescriptorContext::Contract(_) => {
                        let formats = match parse_calldata_formats(&resolved_json) {
                            Ok(formats) => formats,
                            Err(error) => {
                                registry.failures.push((path, error));
                                continue;
                            }
                        };
                        registry
                            .calldata_formats
                            .extend(formats.into_iter().map(|function| CanonicalFormat {
                                chain_id: resolved.chain_id,
                                address: resolved.address.clone(),
                                function,
                            }));
                        registry.calldata.push(resolved);
                    }
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
) -> Result<(Descriptor, String), String> {
    let resolved = resolve_includes(path, contents, by_path, 0)?;
    let descriptor =
        serde_json::from_str(&resolved).map_err(|error| format!("invalid descriptor: {error}"))?;
    Ok((descriptor, resolved))
}

fn parse_calldata_formats(contents: &str) -> Result<Vec<Function>, String> {
    let value: serde_json::Value =
        serde_json::from_str(contents).map_err(|error| format!("invalid JSON: {error}"))?;
    let formats = value
        .pointer("/display/formats")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "calldata descriptor has no display formats".to_string())?;
    formats
        .keys()
        .map(|signature| {
            let canonical = canonical_human_signature(signature)?;
            Function::parse(&canonical)
                .map_err(|error| format!("invalid calldata format {signature:?}: {error}"))
        })
        .collect()
}

/// Alloy's human-readable ABI parser accepts names on top-level parameters,
/// but not the names ERC-7730 places inside tuple parameters. Reduce the
/// registry spelling to the type-only signature that determines the selector
/// and ABI layout before handing it to Alloy.
fn canonical_human_signature(signature: &str) -> Result<String, String> {
    fn skip_space(bytes: &[u8], cursor: &mut usize) {
        while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
            *cursor += 1;
        }
    }

    fn identifier(bytes: &[u8], cursor: &mut usize) -> Option<String> {
        let start = *cursor;
        while bytes
            .get(*cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            *cursor += 1;
        }
        (*cursor > start).then(|| String::from_utf8_lossy(&bytes[start..*cursor]).into_owned())
    }

    fn parameter_type(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
        skip_space(bytes, cursor);
        let mut output = if bytes.get(*cursor) == Some(&b'(') {
            *cursor += 1;
            format!("({})", parameter_list(bytes, cursor)?)
        } else {
            identifier(bytes, cursor).ok_or_else(|| "expected ABI parameter type".to_string())?
        };
        skip_space(bytes, cursor);
        while bytes.get(*cursor) == Some(&b'[') {
            let start = *cursor;
            *cursor += 1;
            while bytes.get(*cursor).is_some_and(u8::is_ascii_digit) {
                *cursor += 1;
            }
            if bytes.get(*cursor) != Some(&b']') {
                return Err("unterminated ABI array suffix".to_string());
            }
            *cursor += 1;
            output.push_str(&String::from_utf8_lossy(&bytes[start..*cursor]));
            skip_space(bytes, cursor);
        }
        // A parameter name has no effect on the selector or encoding.
        let _ = identifier(bytes, cursor);
        skip_space(bytes, cursor);
        Ok(output)
    }

    fn parameter_list(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
        let mut types = Vec::new();
        skip_space(bytes, cursor);
        if bytes.get(*cursor) == Some(&b')') {
            *cursor += 1;
            return Ok(String::new());
        }
        loop {
            types.push(parameter_type(bytes, cursor)?);
            match bytes.get(*cursor) {
                Some(b',') => {
                    *cursor += 1;
                    skip_space(bytes, cursor);
                }
                Some(b')') => {
                    *cursor += 1;
                    return Ok(types.join(","));
                }
                _ => return Err("expected `,` or `)` after ABI parameter".to_string()),
            }
        }
    }

    let bytes = signature.as_bytes();
    let mut cursor = 0;
    skip_space(bytes, &mut cursor);
    let name =
        identifier(bytes, &mut cursor).ok_or_else(|| "expected function name".to_string())?;
    skip_space(bytes, &mut cursor);
    if bytes.get(cursor) != Some(&b'(') {
        return Err("expected `(` after function name".to_string());
    }
    cursor += 1;
    let parameters = parameter_list(bytes, &mut cursor)?;
    skip_space(bytes, &mut cursor);
    if cursor != bytes.len() {
        return Err("unexpected text after function signature".to_string());
    }
    Ok(format!("{name}({parameters})"))
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
    pub warnings: Vec<String>,
}

/// Token metadata provider bridging the plan's already-fetched display
/// metadata into the engine's formatting, and the owner's own accounts into
/// the names it puts on addresses.
///
/// Both answer from maps the caller already holds, so a descriptor reading
/// still contacts no network -- which is the invariant this module is built
/// on, not a convenience.
struct MapProvider<'a> {
    metadata: &'a TokenMetadataMap,
    own: &'a crate::approval_summary::OwnAccounts,
}

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
            .and_then(|address| Some((address, self.metadata.get(&address)?)))
            .and_then(|(address, metadata)| {
                let symbol = crate::approval_summary::display_symbol(metadata.symbol.as_deref()?)?;
                let bound = format!("{symbol} ({})", address.to_checksum(None));
                Some(TokenMeta {
                    symbol: bound.clone(),
                    decimals: metadata.decimals?,
                    name: bound,
                })
            });
        Box::pin(async move { meta })
    }

    /// Name an address the owner's own account, and say the address while
    /// doing it.
    ///
    /// This hook *substitutes*: whatever it answers replaces the address in
    /// the rendered field, and answering `None` leaves the engine to print the
    /// EIP-55 checksum it would have printed anyway. So the answer carries the
    /// address itself -- an account name alone would take the forty characters
    /// being authorized off the screen, which is the opposite of the point.
    ///
    /// Only the wallet's own account list is consulted. The `types` hint the
    /// descriptor supplies is ignored: whether an address is one the owner
    /// holds is a fact about this wallet, not a guess a descriptor makes about
    /// its parameter.
    fn resolve_local_name(
        &self,
        address: &str,
        _chain_id: u64,
        _types: Option<&[String]>,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        let labelled = address.parse::<Address>().ok().and_then(|address| {
            self.own
                .contains_key(&address)
                .then(|| crate::approval_summary::address_label(address, self.own))
        });
        Box::pin(async move { labelled })
    }
}

/// Records the tokens the engine asks about instead of answering, so the
/// caller can fetch metadata before the real rendering pass.
///
/// A set, not a list. The caller deduplicates anyway -- `plan_token_targets`
/// collects into a `BTreeSet` -- so recording the same address a thousand
/// times was work with no output, and the deduplication happened after the
/// allocation rather than instead of it.
#[derive(Default)]
struct RecordingProvider(Mutex<BTreeSet<Address>>);

impl DataProvider for RecordingProvider {
    fn resolve_token(
        &self,
        _chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Option<TokenMeta>> + Send + '_>> {
        if let Ok(address) = address.parse::<Address>()
            && let Ok(mut recorded) = self.0.lock()
        {
            recorded.insert(address);
        }
        Box::pin(async { None })
    }
}

fn is_canonical_descriptor_calldata(chain_id: u64, to: Address, calldata: &[u8]) -> bool {
    let Some((selector, body)) = calldata.split_at_checked(4) else {
        return false;
    };
    registry().calldata_formats.iter().any(|format| {
        format.chain_id == chain_id
            && format.address == format!("{to:#x}")
            && selector == format.function.selector().as_slice()
            && format
                .function
                .abi_decode_input(body)
                .ok()
                .and_then(|values| {
                    values
                        .iter()
                        .all(within_declared_width)
                        .then(|| format.function.abi_encode_input_raw(&values).ok())
                        .flatten()
                })
                .is_some_and(|canonical| canonical == body)
    })
}

fn within_declared_width(value: &DynSolValue) -> bool {
    match value {
        DynSolValue::Uint(word, bits) => *bits >= 256 || *word < (U256::from(1) << *bits),
        DynSolValue::Int(word, bits) => {
            *bits >= 256 || (*word >= min_int(*bits) && *word <= max_int(*bits))
        }
        DynSolValue::FixedBytes(word, size) => word[*size..].iter().all(|byte| *byte == 0),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) | DynSolValue::Tuple(items) => {
            items.iter().all(within_declared_width)
        }
        _ => true,
    }
}

fn max_int(bits: usize) -> I256 {
    I256::try_from((U256::from(1) << (bits - 1)) - U256::from(1)).unwrap_or(I256::MAX)
}

fn min_int(bits: usize) -> I256 {
    max_int(bits).wrapping_neg().wrapping_sub(I256::ONE)
}

async fn run_format(
    chain_id: u64,
    envelope: &CallEnvelope,
    calldata: &Bytes,
    value: U256,
    provider: &dyn DataProvider,
) -> Option<FormatOutcome> {
    if !is_canonical_descriptor_calldata(chain_id, envelope.to, calldata) {
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
    recorder
        .0
        .into_inner()
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Render a call through its vendored descriptor, if one matches exactly.
pub async fn interpret(
    chain_id: u64,
    envelope: CallEnvelope,
    calldata: &Bytes,
    value: U256,
    metadata: &TokenMetadataMap,
    own: &crate::approval_summary::OwnAccounts,
) -> Option<ClearSigned> {
    let provider = MapProvider { metadata, own };
    match run_format(chain_id, &envelope, calldata, value, &provider).await? {
        FormatOutcome::ClearSigned { model, diagnostics } => {
            Some(clear_signed(&model, &diagnostics))
        }
        FormatOutcome::Fallback { .. } => None,
    }
}

/// Flattens the engine's display model into capped, sanitized lines.
fn clear_signed(
    model: &DisplayModel,
    diagnostics: &[clear_signing::FormatDiagnostic],
) -> ClearSigned {
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
    let warnings = diagnostics
        .iter()
        .map(|diagnostic| {
            stripped_capped(
                &format!(
                    "Clear-signing diagnostic ({}): {}",
                    diagnostic.code, diagnostic.message
                ),
                MAX_TEXT_LEN,
            )
        })
        .collect();
    ClearSigned {
        intent,
        fields,
        warnings,
    }
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

/// Test fixture for the signed-parameter rendering: a `Positions`
/// `collectFees` call whose lower tick is negative, derived from the vendored
/// descriptor itself. A tick below the price of token1 in token0 is the
/// ordinary case, so this is what a real review shows.
#[cfg(test)]
pub(crate) fn negative_tick_fixture() -> (u64, Address, Vec<u8>) {
    use alloy::dyn_abi::DynSolValue;
    use alloy::primitives::{FixedBytes, keccak256};
    let (_, contents) = CLEARSIGN_FILES
        .iter()
        .find(|(path, _)| path.ends_with("registry/ekubo/calldata-Positions.json"))
        .expect("positions descriptor vendored");
    let descriptor: serde_json::Value = serde_json::from_str(contents).expect("valid JSON");
    let deployment = &descriptor["context"]["contract"]["deployments"][0];
    let chain = deployment["chainId"].as_u64().expect("chain id");
    let address = deployment["address"]
        .as_str()
        .expect("address")
        .parse::<Address>()
        .expect("valid address");
    assert!(
        descriptor["display"]["formats"]
            .as_object()
            .expect("formats")
            .contains_key(
                "collectFees(uint256 id, (address token0, address token1, bytes32 config) \
                 poolKey, int32 tickLower, int32 tickUpper)"
            ),
        "collectFees format vendored"
    );
    let selector =
        &keccak256("collectFees(uint256,(address,address,bytes32),int32,int32)".as_bytes())[..4];
    let value = DynSolValue::Tuple(vec![
        DynSolValue::Uint(U256::from(4_242_u64), 256),
        DynSolValue::Tuple(vec![
            DynSolValue::Address(Address::repeat_byte(0xA0)),
            DynSolValue::Address(Address::repeat_byte(0xB0)),
            DynSolValue::FixedBytes(FixedBytes::default(), 32),
        ]),
        DynSolValue::Int(I256::unchecked_from(-140), 32),
        DynSolValue::Int(I256::ZERO, 32),
    ]);
    let mut calldata = selector.to_vec();
    calldata.extend(value.abi_encode_params());
    (chain, address, calldata)
}

#[cfg(test)]
#[path = "clear_signing_test.rs"]
mod tests;
