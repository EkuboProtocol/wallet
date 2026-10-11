//! ERC-8410 typed-data signature requests.
//!
//! The second document type beside `execution_plan`: one concrete EIP-712
//! message and the account expected to sign it, sharing the reference
//! envelope but keeping a separate body and request digest. Supporting this
//! type is optional for consumers; the rules below apply wherever it is
//! supported, and the execution-plan format is unchanged by it.
//!
//! A request that passes validation still authorizes nothing. Like a plan,
//! it is attacker-controlled input in the general case: it queues for
//! explicit human review, and the signature is released to the MCP caller
//! only after the owner approves. Three commitments are kept apart:
//!
//! 1. **Artifact integrity** is the envelope's keccak256 over the exact
//!    retrieved bytes, checked in [`crate::plan_fetch`] before parsing.
//! 2. **Signing digest** is the EIP-712
//!    `keccak256(0x1901 || domainSeparator || hashStruct(message))` — the
//!    only thing the account signs. The request digest below is never signed
//!    in its place.
//! 3. **Request digest** identifies the wallet request, including the signer
//!    and the release constraints, and is what authorization binds to.
//!
//! Controlled delivery (`delivery`) is rejected: this wallet has no
//! same-origin HTTPS delivery implementation, and a consumer that cannot
//! enforce that profile must reject the request rather than fall back to
//! returning the signature to the caller. Requests without `delivery`
//! release raw signature bytes to the caller on approval, which is treated
//! as release to the caller with no constraint on where they forward them.
//!
//! The domain must pin the chain the caller claims. The format permits
//! chainless messages, but this wallet requires a domain chain ID as policy,
//! so a signature can never be silently valid on a different chain than the
//! one the user reviewed.

use crate::typed_data::MAX_TYPED_DATA_BYTES;
use alloy::primitives::{Address, B256, I256, U256, keccak256};
use alloy_dyn_abi::TypedData;
use anyhow::{Context, Result, bail, ensure};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

/// Nesting of struct/array values, per the specification's recommended limit.
const MAX_VALUE_NESTING: usize = 64;
/// Array elements across the whole value, per the recommended limit.
const MAX_ARRAY_ELEMENTS: usize = 4_096;
/// Declared types in `types`, per the schema limit.
const MAX_TYPES: usize = 128;
/// Members per declared type, per the schema limit.
const MAX_TYPE_MEMBERS: usize = 128;
/// Characters in one type expression, per the specification.
const MAX_TYPE_EXPRESSION: usize = 128;

/// Standard EIP-712 domain fields, in standard order, with their types.
const DOMAIN_MEMBERS: [(&str, &str); 5] = [
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
    ("salt", "bytes32"),
];

/// One validated request: the parsed EIP-712 payload plus both digests and
/// the release constraint the wallet enforces.
#[derive(Debug)]
pub struct ValidatedSignatureRequest {
    /// Account whose authorization the verifier expects; must equal the
    /// signing wallet, never silently replaced.
    pub signer: Address,
    /// The exact EIP-712 payload (`types`, `primaryType`, `domain`,
    /// `message`), as validated.
    pub typed_data_json: serde_json::Value,
    /// The same payload parsed for hashing and permit recognition.
    pub typed: TypedData,
    /// Domain chain ID, required by wallet policy.
    pub chain_id: u64,
    /// EIP-712 signing digest: the only thing the account signs.
    pub signing_digest: B256,
    /// Wallet request digest, binding signer, message, cutoff, and
    /// destination. Authorization binds to this.
    pub request_digest: B256,
    /// Exclusive wallet signing and release cutoff, Unix seconds. `None`
    /// when the producer set none; protocol expiry still has to come from
    /// the signed message and its verifier.
    pub valid_until: Option<u64>,
}

/// Parse raw request bytes: size check, duplicate-key rejection, then
/// structural and semantic validation.
pub fn parse_signature_request_bytes(bytes: &[u8]) -> Result<ValidatedSignatureRequest> {
    ensure!(
        bytes.len() <= MAX_TYPED_DATA_BYTES,
        "typed-data signature request exceeds the {MAX_TYPED_DATA_BYTES}-byte maximum"
    );
    reject_duplicate_keys(bytes)?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("typed-data signature request is not valid JSON")?;
    validate_signature_request_value(&value)
}

/// Validate an already-parsed request body. The duplicate-key check needs
/// the raw bytes and is the caller's responsibility; see
/// [`parse_signature_request_bytes`].
pub fn validate_signature_request_value(
    value: &serde_json::Value,
) -> Result<ValidatedSignatureRequest> {
    let body = value
        .as_object()
        .context("typed-data signature request must be a JSON object")?;
    for key in body.keys() {
        ensure!(
            matches!(
                key.as_str(),
                "schema_version" | "kind" | "signer" | "typed_data" | "valid_until" | "delivery"
            ),
            "typed-data signature request carries unknown member {key:?}"
        );
    }
    let schema_version = body
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .context("typed-data signature request has no schema_version")?;
    ensure!(
        schema_version == "1",
        "unsupported typed-data signature request schema version"
    );
    let kind = body
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .context("typed-data signature request has no kind")?;
    ensure!(
        kind == "typed_data_signature_request",
        "typed-data signature request kind is {kind:?}, not \"typed_data_signature_request\""
    );
    for optional in ["valid_until", "delivery"] {
        ensure!(
            !body.get(optional).is_some_and(serde_json::Value::is_null),
            "typed-data signature request member {optional:?} must be omitted when absent; explicit nulls are invalid"
        );
    }
    let signer = body
        .get("signer")
        .and_then(serde_json::Value::as_str)
        .context("typed-data signature request has no signer")?;
    let signer = Address::from_str(signer)
        .context("typed-data signature request signer is not an address")?;
    let typed_data = body
        .get("typed_data")
        .context("typed-data signature request has no typed_data")?;
    let valid_until = match body.get("valid_until") {
        None => None,
        Some(raw) => Some(parse_valid_until(raw)?),
    };
    if body.contains_key("delivery") {
        bail!(
            "typed-data signature requests with controlled delivery are not supported by this \
             wallet: it cannot enforce the same-origin HTTPS delivery profile, so the request \
             is rejected rather than releasing the signature to the caller"
        );
    }

    let typed = validate_typed_data(typed_data)?;
    let chain_id: u64 = typed
        .domain
        .chain_id
        .context("typed-data signature request domain must include chainId")?
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!("typed-data signature request domain chainId does not fit uint64")
        })?;
    ensure!(
        chain_id > 0,
        "typed-data signature request domain chainId must be positive"
    );
    let signing_digest = typed
        .eip712_signing_hash()
        .context("failed to compute the EIP-712 signing hash")?;
    let request_digest = request_digest(&signer, &signing_digest, valid_until, None);
    Ok(ValidatedSignatureRequest {
        signer,
        typed_data_json: typed_data.clone(),
        typed,
        chain_id,
        signing_digest,
        request_digest,
        valid_until,
    })
}

/// `valid_until` is Unix seconds as a canonical unsigned decimal string
/// fitting `uint64`.
fn parse_valid_until(raw: &serde_json::Value) -> Result<u64> {
    let text = raw
        .as_str()
        .context("typed-data signature request valid_until must be a decimal string")?;
    ensure!(
        is_canonical_uint(text),
        "typed-data signature request valid_until must be a canonical unsigned decimal integer"
    );
    text.parse::<u64>().map_err(|_| {
        anyhow::anyhow!("typed-data signature request valid_until does not fit uint64")
    })
}

/// Whether now (Unix seconds) is at or past an exclusive cutoff. A missing
/// cutoff never expires on its own; protocol expiry is the signed message's
/// job.
#[must_use]
pub fn valid_until_expired(valid_until: Option<u64>, now_secs: i64) -> bool {
    match valid_until {
        None => false,
        Some(cutoff) => u64::try_from(now_secs).is_ok_and(|now| now >= cutoff),
    }
}

/// The wallet request digest: keccak256 over the fixed-order projection.
/// Member order is normative and is not lexicographic; absent `valid_until`
/// and `delivery` are JSON null in the projection even though null is not
/// accepted in the input artifact.
#[must_use]
pub fn request_digest(
    signer: &Address,
    signing_digest: &B256,
    valid_until: Option<u64>,
    delivery: Option<(&str, &str)>,
) -> B256 {
    let valid_until =
        valid_until.map_or_else(|| "null".to_owned(), |cutoff| format!("\"{cutoff}\""));
    let delivery = delivery.map_or_else(
        || "null".to_owned(),
        |(url, request_id)| format!("{{\"url\":\"{url}\",\"request_id\":\"{request_id}\"}}"),
    );
    let canonical = format!(
        "{{\"kind\":\"typed_data_signature_request\",\"schema_version\":\"1\",\
         \"signer\":\"{signer:#x}\",\"signing_digest\":\"{signing_digest:#x}\",\
         \"valid_until\":{valid_until},\"delivery\":{delivery}}}"
    );
    keccak256(canonical.as_bytes())
}

/// One declared struct member.
struct MemberDecl<'a> {
    name: &'a str,
    ty: &'a str,
}

/// Validate the EIP-712 payload strictly: declaration shape, canonical value
/// encodings, resource limits, and reachability. Returns the parsed payload
/// for hashing.
fn validate_typed_data(value: &serde_json::Value) -> Result<TypedData> {
    let object = value
        .as_object()
        .context("typed_data must be a JSON object with types, primaryType, domain, and message")?;
    for key in object.keys() {
        ensure!(
            matches!(key.as_str(), "types" | "primaryType" | "domain" | "message"),
            "typed_data carries {key:?}, which EIP-712 does not define; \
             it would be displayed but not signed"
        );
    }
    let types_value = value
        .get("types")
        .and_then(serde_json::Value::as_object)
        .context("typed_data has no types object")?;
    ensure!(
        (1..=MAX_TYPES).contains(&types_value.len()),
        "typed_data declares {} types; at most {MAX_TYPES} are accepted",
        types_value.len()
    );
    let mut declarations: HashMap<&str, Vec<MemberDecl<'_>>> = HashMap::new();
    for (name, members) in types_value {
        ensure!(
            is_identifier(name),
            "typed_data declares type {name:?}, which is not a valid identifier"
        );
        let members = members
            .as_array()
            .with_context(|| format!("typed_data type {name} is not an array of members"))?;
        ensure!(
            members.len() <= MAX_TYPE_MEMBERS,
            "typed_data type {name} declares {} members; at most {MAX_TYPE_MEMBERS} are accepted",
            members.len()
        );
        if name != "EIP712Domain" {
            ensure!(
                !members.is_empty(),
                "typed_data type {name} declares no members"
            );
        }
        let mut seen = HashSet::new();
        let mut parsed = Vec::with_capacity(members.len());
        for member in members {
            let member = member.as_object().with_context(|| {
                format!("typed_data type {name} declares a member that is not an object")
            })?;
            ensure!(
                member.len() == 2 && member.contains_key("name") && member.contains_key("type"),
                "typed_data type {name} declares a member with keys outside name and type; \
                 extra declaration keys would be displayed but not signed"
            );
            let member_name = member["name"]
                .as_str()
                .context("typed_data member name is not a string")?;
            let member_type = member["type"]
                .as_str()
                .context("typed_data member type is not a string")?;
            ensure!(
                is_identifier(member_name),
                "typed_data type {name} declares member {member_name:?}, which is not a valid identifier"
            );
            ensure!(
                seen.insert(member_name),
                "typed_data type {name} declares member {member_name:?} twice"
            );
            ensure!(
                (1..=MAX_TYPE_EXPRESSION).contains(&member_type.len()),
                "typed_data type expression exceeds {MAX_TYPE_EXPRESSION} characters"
            );
            ensure!(
                is_valid_type_expression(member_type),
                "typed_data type {name} declares invalid type {member_type:?}"
            );
            parsed.push(MemberDecl {
                name: member_name,
                ty: member_type,
            });
        }
        declarations.insert(name.as_str(), parsed);
    }
    let primary_type = value
        .get("primaryType")
        .and_then(serde_json::Value::as_str)
        .context("typed_data has no primaryType")?;
    ensure!(
        is_identifier(primary_type),
        "typed_data primaryType {primary_type:?} is not a valid identifier"
    );
    ensure!(
        primary_type != "EIP712Domain",
        "refusing to sign a bare EIP712Domain payload"
    );
    ensure!(
        declarations.contains_key(primary_type),
        "typed_data primaryType {primary_type:?} names a type that is not declared"
    );

    // The domain is checked against the standard member set, and only against
    // it: a payload's own `EIP712Domain` declaration decides nothing about
    // what gets signed.
    let domain = value
        .get("domain")
        .and_then(serde_json::Value::as_object)
        .context("typed_data has no domain object")?;
    for key in domain.keys() {
        ensure!(
            DOMAIN_MEMBERS.iter().any(|(member, _)| *member == key),
            "typed_data domain carries {key:?}, which EIP712Domain does not define; \
             it would be displayed but not signed"
        );
    }
    // The declaration is display text and nothing more, so it must be exactly
    // the declaration the domain's own fields imply: the same members, each
    // under the type EIP-712 fixes for it, in the standard's order.
    let declared = types_value
        .get("EIP712Domain")
        .and_then(serde_json::Value::as_array)
        .context("typed_data does not declare EIP712Domain")?;
    let expected: Vec<(&str, &str)> = DOMAIN_MEMBERS
        .iter()
        .filter(|(member, _)| domain.contains_key(*member))
        .copied()
        .collect();
    let declared_json: Vec<serde_json::Value> = expected
        .iter()
        .map(|(member, kind)| serde_json::json!({"name": member, "type": kind}))
        .collect();
    ensure!(
        declared == &declared_json,
        "typed_data declares EIP712Domain as {declared:?}, but the domain it carries is \
         hashed differently; the declaration is displayed and not signed"
    );
    let mut budget = ArrayBudget::new();
    for (member, kind) in &expected {
        check_value_by_type(
            &domain[*member],
            kind,
            &declarations,
            &mut budget,
            0,
            &format!("domain.{member}"),
        )?;
    }

    reject_unreachable_types(types_value, &declarations, primary_type)?;

    let message = value
        .get("message")
        .and_then(serde_json::Value::as_object)
        .context("typed_data has no message object")?;
    check_struct_value(
        message,
        &declarations[primary_type],
        &declarations,
        &mut budget,
        0,
        "message",
    )?;

    serde_json::from_value(value.clone()).context("typed_data is not a valid EIP-712 payload")
}

/// Refuse a type declaration nothing reaches from the primary type. EIP-712
/// hashes a struct under a type string naming only the types actually
/// referenced, so an unreachable declaration contributes nothing to the
/// signature while sitting in the `types` map the reviewer reads.
fn reject_unreachable_types(
    types_value: &serde_json::Map<String, serde_json::Value>,
    declarations: &HashMap<&str, Vec<MemberDecl<'_>>>,
    primary_type: &str,
) -> Result<()> {
    let mut reached: HashSet<&str> = HashSet::from(["EIP712Domain"]);
    let mut pending: Vec<&str> = vec![primary_type];
    while let Some(name) = pending.pop() {
        if !reached.insert(name) {
            continue;
        }
        if let Some(members) = declarations.get(name) {
            for member in members {
                // An array member repeats its element type; `Foo[2]` and
                // `Foo[]` alike.
                let (element, _) = strip_array_suffixes(member.ty);
                if declarations.contains_key(element) {
                    pending.push(element);
                }
            }
        }
    }
    for name in types_value.keys() {
        ensure!(
            reached.contains(name.as_str()),
            "typed_data declares type {name}, which {primary_type} does not reach; \
             it would be displayed but not signed"
        );
    }
    Ok(())
}

/// Array-element budget shared across one value walk.
struct ArrayBudget {
    elements: usize,
}

impl ArrayBudget {
    fn new() -> Self {
        Self { elements: 0 }
    }

    fn consume(&mut self, count: usize, path: &str) -> Result<()> {
        self.elements = self
            .elements
            .checked_add(count)
            .context("typed-data array budget overflow")?;
        ensure!(
            self.elements <= MAX_ARRAY_ELEMENTS,
            "typed_data {path} exceeds the {MAX_ARRAY_ELEMENTS}-element array budget"
        );
        Ok(())
    }
}

/// Check an object value against its struct's declared members: no missing
/// members, no undeclared ones, every value fitting its type.
fn check_struct_value(
    object: &serde_json::Map<String, serde_json::Value>,
    members: &[MemberDecl<'_>],
    declarations: &HashMap<&str, Vec<MemberDecl<'_>>>,
    budget: &mut ArrayBudget,
    depth: usize,
    path: &str,
) -> Result<()> {
    ensure!(
        depth <= MAX_VALUE_NESTING,
        "typed_data {path} exceeds the {MAX_VALUE_NESTING}-level nesting limit"
    );
    ensure!(
        object.len() == members.len(),
        "typed_data {path} carries {} members but its type declares {}; \
         missing members hash as zero and extra members are not signed",
        object.len(),
        members.len()
    );
    for member in members {
        let child = object
            .get(member.name)
            .with_context(|| format!("typed_data {path} is missing member {:?}", member.name))?;
        check_value_by_type(
            child,
            member.ty,
            declarations,
            budget,
            depth + 1,
            &format!("{path}.{}", member.name),
        )?;
    }
    Ok(())
}

/// Check one value against one type expression, recursing through array
/// dimensions outside in: in `T[2][3]` the outer `[3]` sizes this array and
/// each item is checked against `T[2]`.
fn check_value_by_type(
    value: &serde_json::Value,
    ty: &str,
    declarations: &HashMap<&str, Vec<MemberDecl<'_>>>,
    budget: &mut ArrayBudget,
    depth: usize,
    path: &str,
) -> Result<()> {
    ensure!(
        depth <= MAX_VALUE_NESTING,
        "typed_data {path} exceeds the {MAX_VALUE_NESTING}-level nesting limit"
    );
    let (element, lengths) = strip_array_suffixes(ty);
    check_dimensions(value, element, &lengths, declarations, budget, depth, path)
}

/// Check one value against an element type with the remaining array
/// dimensions still to consume.
fn check_dimensions(
    value: &serde_json::Value,
    element: &str,
    lengths: &[Option<usize>],
    declarations: &HashMap<&str, Vec<MemberDecl<'_>>>,
    budget: &mut ArrayBudget,
    depth: usize,
    path: &str,
) -> Result<()> {
    let Some((last, rest)) = lengths.split_last() else {
        return check_single_value(value, element, declarations, budget, depth, path);
    };
    let _ = rest;
    let items = value
        .as_array()
        .with_context(|| format!("typed_data {path} must be an array"))?;
    if let Some(fixed) = last {
        ensure!(
            items.len() == *fixed,
            "typed_data {path} has {} items but its type requires {fixed}",
            items.len()
        );
    }
    budget.consume(items.len(), path)?;
    // The outer dimension is consumed here; inner dimensions belong to the
    // items. Rebuild the inner type expression for the recursive call.
    let inner = rebuild_inner_type(element, &lengths[..lengths.len() - 1]);
    for (index, item) in items.iter().enumerate() {
        check_value_by_type(
            item,
            &inner,
            declarations,
            budget,
            depth + 1,
            &format!("{path}[{index}]"),
        )?;
    }
    Ok(())
}

/// Rebuild the type expression for the inner dimensions after consuming the
/// outermost one.
fn rebuild_inner_type(element: &str, inner_lengths: &[Option<usize>]) -> String {
    use std::fmt::Write as _;
    let mut rebuilt = String::from(element);
    for length in inner_lengths {
        match length {
            Some(fixed) => {
                let _ = write!(rebuilt, "[{fixed}]");
            }
            None => rebuilt.push_str("[]"),
        }
    }
    rebuilt
}

/// Check one non-array value against its element type.
fn check_single_value(
    value: &serde_json::Value,
    element: &str,
    declarations: &HashMap<&str, Vec<MemberDecl<'_>>>,
    budget: &mut ArrayBudget,
    depth: usize,
    path: &str,
) -> Result<()> {
    if element == "bool" {
        ensure!(
            value.is_boolean(),
            "typed_data {path} must be a JSON boolean for bool"
        );
        return Ok(());
    }
    if element == "string" {
        ensure!(
            value.is_string(),
            "typed_data {path} must be a JSON string for string"
        );
        return Ok(());
    }
    if element == "address" {
        check_hex_bytes(value, Some(20), path)?;
        return Ok(());
    }
    if element == "bytes" {
        check_hex_bytes(value, None, path)?;
        return Ok(());
    }
    if let Some(width) = element.strip_prefix("bytes") {
        let width: usize = width
            .parse()
            .map_err(|_| anyhow::anyhow!("typed_data {path} has invalid type {element:?}"))?;
        check_hex_bytes(value, Some(width), path)?;
        return Ok(());
    }
    if let Some(width) = element.strip_prefix("uint") {
        let text = require_canonical_string(value, path)?;
        ensure!(
            is_canonical_uint(text),
            "typed_data {path} must be a canonical unsigned decimal string, never a JSON number"
        );
        let width: u32 = width
            .parse()
            .map_err(|_| anyhow::anyhow!("typed_data {path} has invalid type {element:?}"))?;
        let parsed = U256::from_str(text)
            .map_err(|_| anyhow::anyhow!("typed_data {path} does not fit uint{width}"))?;
        let max = if width >= 256 {
            U256::MAX
        } else {
            (U256::from(1) << (width as usize)) - U256::from(1)
        };
        ensure!(parsed <= max, "typed_data {path} does not fit uint{width}");
        return Ok(());
    }
    if let Some(width) = element.strip_prefix("int") {
        let text = require_canonical_string(value, path)?;
        ensure!(
            is_canonical_int(text),
            "typed_data {path} must be a canonical decimal string, never a JSON number"
        );
        let width: u32 = width
            .parse()
            .map_err(|_| anyhow::anyhow!("typed_data {path} has invalid type {element:?}"))?;
        let parsed = I256::from_str(text)
            .map_err(|_| anyhow::anyhow!("typed_data {path} does not fit int{width}"))?;
        let half = I256::try_from(U256::from(1) << ((width - 1) as usize))
            .map_err(|_| anyhow::anyhow!("typed_data {path} has invalid type {element:?}"))?;
        ensure!(
            parsed >= -half && parsed <= half - I256::ONE,
            "typed_data {path} does not fit int{width}"
        );
        return Ok(());
    }
    let members = declarations
        .get(element)
        .with_context(|| format!("typed_data {path} references undeclared type {element:?}"))?;
    let object = value
        .as_object()
        .with_context(|| format!("typed_data {path} must be an object for type {element:?}"))?;
    check_struct_value(object, members, declarations, budget, depth, path)
}

/// Require a JSON string (canonical encodings are strings, never numbers).
fn require_canonical_string<'a>(value: &'a serde_json::Value, path: &str) -> Result<&'a str> {
    value
        .as_str()
        .with_context(|| format!("typed_data {path} must be a JSON string, never a JSON number"))
}

/// Addresses and fixed/dynamic byte strings: `0x` plus even hexadecimal
/// digits of the required length. Any letter case is accepted and normalized
/// by the parser for hashing; producers must emit lowercase.
fn check_hex_bytes(
    value: &serde_json::Value,
    expected_len: Option<usize>,
    path: &str,
) -> Result<()> {
    let text = require_canonical_string(value, path)?;
    let digits = text
        .strip_prefix("0x")
        .with_context(|| format!("typed_data {path} must be 0x-prefixed hexadecimal"))?;
    ensure!(
        digits.len() % 2 == 0,
        "typed_data {path} must have an even number of hexadecimal digits"
    );
    ensure!(
        digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "typed_data {path} must be hexadecimal"
    );
    if let Some(expected) = expected_len {
        ensure!(
            digits.len() == expected * 2,
            "typed_data {path} must be {expected} bytes"
        );
    }
    Ok(())
}

/// Whether a member type expression is well-formed: a known base type (with
/// array suffixes) or an identifier that may name a struct declared
/// elsewhere in the same payload.
fn is_valid_type_expression(ty: &str) -> bool {
    let (element, _) = strip_array_suffixes(ty);
    is_base_type(element) || is_identifier(element)
}

/// Whether an element type is a primitive EIP-712 base type.
fn is_base_type(element: &str) -> bool {
    match element {
        "bool" | "string" | "address" | "bytes" => true,
        _ if let Some(width) = element.strip_prefix("bytes") => width
            .parse::<usize>()
            .is_ok_and(|width| (1..=32).contains(&width)),
        _ if let Some(width) = element.strip_prefix("uint") => width
            .parse::<u32>()
            .is_ok_and(|width| (8..=256).contains(&width) && width % 8 == 0),
        _ if let Some(width) = element.strip_prefix("int") => width
            .parse::<u32>()
            .is_ok_and(|width| (8..=256).contains(&width) && width % 8 == 0),
        _ => false,
    }
}

/// Split `uint256[2][]` into `("uint256", [Some(2), None])`, outside in. A
/// trailing fragment that is not a well-formed bracket pair ends the split,
/// leaving residue on the element that fails the validity check.
fn strip_array_suffixes(ty: &str) -> (&str, Vec<Option<usize>>) {
    let mut element = ty;
    let mut lengths = Vec::new();
    while let Some(inner) = element.strip_suffix(']') {
        let Some(open) = inner.rfind('[') else {
            break;
        };
        let digits = &inner[open + 1..];
        if digits.is_empty() {
            lengths.push(None);
        } else if let Ok(fixed) = digits.parse::<usize>() {
            lengths.push(Some(fixed));
        } else {
            break;
        }
        element = &inner[..open];
    }
    lengths.reverse();
    (element, lengths)
}

/// Type and member identifiers: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() || first == b'_' => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Canonical unsigned decimal: `0`, or digits with no leading zero.
fn is_canonical_uint(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
}

/// Canonical signed decimal: unsigned form, or a leading minus on nonzero.
fn is_canonical_int(text: &str) -> bool {
    match text.strip_prefix('-') {
        None => is_canonical_uint(text),
        Some(rest) => !rest.is_empty() && is_canonical_uint(rest) && rest != "0",
    }
}

/// Reject duplicate JSON object keys before the document becomes a map.
/// `serde_json` keeps the last of two identical keys, so without this a
/// payload could display one value while signing another. Iterative rather
/// than recursive: the input is attacker-controlled and may nest deeper
/// than any call stack tolerates.
fn reject_duplicate_keys(bytes: &[u8]) -> Result<()> {
    #[derive(PartialEq, Eq)]
    enum State {
        ArrayEmpty,
        ArrayAfterValue,
        ArrayAfterComma,
        ObjectEmpty,
        ObjectNeedValue,
        ObjectAfterValue,
        ObjectNeedKey,
    }

    struct Frame {
        state: State,
        keys: HashSet<Vec<u8>>,
    }

    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0;
    let mut finished = false;

    // Whether a value may start in the current frame.
    let value_slot = |stack: &[Frame]| -> bool {
        match stack.last() {
            None => true,
            Some(frame) => matches!(
                frame.state,
                State::ArrayEmpty | State::ArrayAfterComma | State::ObjectNeedValue
            ),
        }
    };
    // Record one complete value in the enclosing frame.
    let consume_value = |stack: &mut Vec<Frame>| -> Result<()> {
        match stack.last_mut() {
            None => Ok(()),
            Some(frame) => match frame.state {
                State::ArrayEmpty | State::ArrayAfterComma => {
                    frame.state = State::ArrayAfterValue;
                    Ok(())
                }
                State::ObjectNeedValue => {
                    frame.state = State::ObjectAfterValue;
                    Ok(())
                }
                _ => bail!("typed-data signature request is not valid JSON: unexpected value"),
            },
        }
    };

    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Anything after the top-level value is trailing data.
        ensure!(!finished, "typed-data signature request has trailing data");
        match bytes[i] {
            b'{' => {
                ensure!(
                    value_slot(&stack),
                    "typed-data signature request has a value where an object key belongs"
                );
                stack.push(Frame {
                    state: State::ObjectEmpty,
                    keys: HashSet::new(),
                });
                i += 1;
            }
            b'[' => {
                ensure!(
                    value_slot(&stack),
                    "typed-data signature request has a value where an object key belongs"
                );
                stack.push(Frame {
                    state: State::ArrayEmpty,
                    keys: HashSet::new(),
                });
                i += 1;
            }
            b'}' => {
                i += 1;
                match stack.pop() {
                    Some(frame)
                        if matches!(frame.state, State::ObjectEmpty | State::ObjectAfterValue) => {}
                    _ => bail!("typed-data signature request is not valid JSON: mismatched close"),
                }
                if stack.is_empty() {
                    finished = true;
                } else {
                    consume_value(&mut stack)?;
                }
            }
            b']' => {
                i += 1;
                match stack.pop() {
                    Some(frame)
                        if matches!(frame.state, State::ArrayEmpty | State::ArrayAfterValue) => {}
                    _ => bail!("typed-data signature request is not valid JSON: mismatched close"),
                }
                if stack.is_empty() {
                    finished = true;
                } else {
                    consume_value(&mut stack)?;
                }
            }
            b',' => {
                i += 1;
                match stack.last_mut() {
                    Some(frame) => match frame.state {
                        State::ArrayAfterValue => frame.state = State::ArrayAfterComma,
                        State::ObjectAfterValue => frame.state = State::ObjectNeedKey,
                        _ => bail!(
                            "typed-data signature request is not valid JSON: unexpected comma"
                        ),
                    },
                    None => bail!("typed-data signature request has trailing data"),
                }
            }
            b'"' => {
                let (key, next) = parse_json_string(bytes, i)?;
                i = next;
                match stack.last_mut() {
                    Some(frame)
                        if matches!(frame.state, State::ObjectEmpty | State::ObjectNeedKey) =>
                    {
                        ensure!(
                            frame.keys.insert(key),
                            "typed-data signature request has a duplicate object key"
                        );
                        skip_expect_colon(bytes, &mut i)?;
                        frame.state = State::ObjectNeedValue;
                    }
                    _ => {
                        ensure!(
                            value_slot(&stack),
                            "typed-data signature request has a value where an object key belongs"
                        );
                        consume_value(&mut stack)?;
                        if stack.is_empty() {
                            finished = true;
                        }
                    }
                }
            }
            b't' => {
                i = skip_literal(bytes, i, b"true")?;
                ensure!(
                    value_slot(&stack),
                    "typed-data signature request has a value where an object key belongs"
                );
                consume_value(&mut stack)?;
                if stack.is_empty() {
                    finished = true;
                }
            }
            b'f' => {
                i = skip_literal(bytes, i, b"false")?;
                ensure!(
                    value_slot(&stack),
                    "typed-data signature request has a value where an object key belongs"
                );
                consume_value(&mut stack)?;
                if stack.is_empty() {
                    finished = true;
                }
            }
            b'n' => {
                i = skip_literal(bytes, i, b"null")?;
                ensure!(
                    value_slot(&stack),
                    "typed-data signature request has a value where an object key belongs"
                );
                consume_value(&mut stack)?;
                if stack.is_empty() {
                    finished = true;
                }
            }
            _ => {
                // Numbers and the errors they contain belong to the real
                // parser; here they are only skipped.
                i = skip_number(bytes, i)?;
                ensure!(
                    value_slot(&stack),
                    "typed-data signature request has a value where an object key belongs"
                );
                consume_value(&mut stack)?;
                if stack.is_empty() {
                    finished = true;
                }
            }
        }
    }
    ensure!(finished, "typed-data signature request is empty");
    ensure!(
        stack.is_empty(),
        "typed-data signature request is truncated"
    );
    Ok(())
}

/// Parse one JSON string starting at the opening quote, returning its
/// unescaped bytes (object keys differing only by escapes still collide) and
/// the index past the closing quote.
fn parse_json_string(bytes: &[u8], start: usize) -> Result<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut i = start + 1;
    loop {
        let byte = *bytes
            .get(i)
            .context("typed-data signature request has an unterminated string")?;
        match byte {
            b'"' => return Ok((out, i + 1)),
            b'\\' => {
                i += 1;
                let escaped = *bytes
                    .get(i)
                    .context("typed-data signature request has an unterminated escape")?;
                match escaped {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => {
                        let high = parse_hex4(bytes, i + 1)?;
                        // `i` still names the `u`; the arm's trailing advance
                        // moves past the final digit.
                        i += 4;
                        let scalar = if (0xD800..0xDC00).contains(&high) {
                            ensure!(
                                bytes.get(i + 1) == Some(&b'\\') && bytes.get(i + 2) == Some(&b'u'),
                                "typed-data signature request has a lone surrogate"
                            );
                            let low = parse_hex4(bytes, i + 3)?;
                            i += 6;
                            ensure!(
                                (0xDC00..0xE000).contains(&low),
                                "typed-data signature request has a lone surrogate"
                            );
                            0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                        } else {
                            ensure!(
                                !(0xDC00..0xE000).contains(&high),
                                "typed-data signature request has a lone surrogate"
                            );
                            high
                        };
                        let scalar = char::from_u32(scalar).context(
                            "typed-data signature request has an invalid unicode escape",
                        )?;
                        let mut encoded = [0_u8; 4];
                        out.extend_from_slice(scalar.encode_utf8(&mut encoded).as_bytes());
                    }
                    _ => bail!("typed-data signature request has an invalid escape"),
                }
                i += 1;
            }
            0x00..=0x1F => {
                bail!("typed-data signature request has a control character in a string")
            }
            _ => {
                out.push(byte);
                i += 1;
            }
        }
    }
}

/// Expect (after whitespace) the colon following an object key.
fn skip_expect_colon(bytes: &[u8], i: &mut usize) -> Result<()> {
    while *i < bytes.len() && bytes[*i].is_ascii_whitespace() {
        *i += 1;
    }
    ensure!(
        bytes.get(*i) == Some(&b':'),
        "typed-data signature request is not valid JSON: expected a colon"
    );
    *i += 1;
    Ok(())
}

/// Skip one JSON literal keyword.
fn skip_literal(bytes: &[u8], i: usize, keyword: &[u8]) -> Result<usize> {
    ensure!(
        bytes[i..].starts_with(keyword),
        "typed-data signature request is not valid JSON"
    );
    Ok(i + keyword.len())
}

/// Skip one JSON number; strictness belongs to the real parser.
fn skip_number(bytes: &[u8], mut i: usize) -> Result<usize> {
    if bytes.get(i) == Some(&b'-') {
        i += 1;
    }
    let mut digits = 0;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        digits += 1;
        i += 1;
    }
    ensure!(digits > 0, "typed-data signature request is not valid JSON");
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        let mut fraction = 0;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
            fraction += 1;
            i += 1;
        }
        ensure!(
            fraction > 0,
            "typed-data signature request is not valid JSON"
        );
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(bytes.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let mut exponent = 0;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
            exponent += 1;
            i += 1;
        }
        ensure!(
            exponent > 0,
            "typed-data signature request is not valid JSON"
        );
    }
    Ok(i)
}

/// Four hexadecimal digits of a `\u` escape.
fn parse_hex4(bytes: &[u8], i: usize) -> Result<u32> {
    let digits = bytes
        .get(i..i + 4)
        .context("typed-data signature request has a truncated unicode escape")?;
    let text =
        std::str::from_utf8(digits).context("typed-data signature request has a bad escape")?;
    u32::from_str_radix(text, 16)
        .map_err(|_| anyhow::anyhow!("typed-data signature request has a bad unicode escape"))
}

#[cfg(test)]
#[path = "typed_data_request_test.rs"]
mod tests;
