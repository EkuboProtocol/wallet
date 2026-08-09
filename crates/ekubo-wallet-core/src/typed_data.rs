//! EIP-712 typed-data signing requests.
//!
//! Typed-data signatures can be as powerful as transactions (token permits,
//! order authorizations, delegations), but the wallet policy language and
//! simulation cannot evaluate their effects. Every typed-data request
//! therefore queues for explicit human review: the MCP tool only creates a
//! pending request, and the separate CLI displays the complete typed data,
//! requires terminal approval plus OS owner authentication, and only then
//! signs. The signature is persisted in the encrypted database and handed
//! back to the waiting agent.

use crate::{
    policy_store::PolicyStore,
    signature_requests::{SignatureQueue, encode_signature, split_decision},
    sql::{Blob, Millis, RowExt},
};
use alloy::primitives::{Address, B256, U256, address};
use alloy_dyn_abi::TypedData;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr};
use uuid::Uuid;

/// The canonical Permit2 deployment, identical on every chain.
pub const PERMIT2_ADDRESS: Address = address!("0x000000000022D473030F116dDEE9F6B43aC78BA3");

const ERC2612_PERMIT_TYPE: &str =
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
const DAI_PERMIT_TYPE: &str =
    "Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)";
const PERMIT2_SINGLE_TYPE: &str = "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
const PERMIT2_BATCH_TYPE: &str = "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
const PERMIT2_TRANSFER_TYPE: &str = "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";
const PERMIT2_BATCH_TRANSFER_TYPE: &str = "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";

const QUEUE: SignatureQueue = SignatureQueue {
    table: "pending_typed_data",
    noun: "typed-data request",
};
/// Serialized typed data larger than this is rejected before parsing.
pub const MAX_TYPED_DATA_BYTES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TypedDataStatus {
    AwaitingApproval,
    Rejected,
    Signed,
}

impl TypedDataStatus {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "awaiting_approval" => Ok(Self::AwaitingApproval),
            "rejected" => Ok(Self::Rejected),
            "signed" => Ok(Self::Signed),
            _ => anyhow::bail!("stored typed-data request has invalid status {value}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct PendingTypedData {
    pub request_id: Uuid,
    pub wallet_id: String,
    pub chain_id: String,
    /// The exact EIP-712 payload: `types`, `primaryType`, `domain`, `message`.
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    pub typed_data: serde_json::Value,
    /// The EIP-712 signing hash of the exact payload.
    pub digest: String,
    pub status: TypedDataStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_at: Option<DateTime<Utc>>,
    /// The 65-byte r||s||v signature, present only once signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Parse and canonicalize an EIP-712 payload, returning the parsed typed data
/// and its signing hash. The domain must pin the chain the caller claims, so
/// a signature can never be silently valid on a different chain than the one
/// the user reviewed.
pub fn parse_typed_data(value: &serde_json::Value) -> Result<(TypedData, u64, B256)> {
    let serialized = serde_json::to_string(value)?;
    ensure!(
        serialized.len() <= MAX_TYPED_DATA_BYTES,
        "typed data exceeds the {MAX_TYPED_DATA_BYTES}-byte maximum"
    );
    let typed: TypedData = serde_json::from_value(value.clone())
        .context("typed data is not a valid EIP-712 payload")?;
    let chain_id: u64 = typed
        .domain
        .chain_id
        .context("typed data domain must include chainId")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("typed data domain chainId does not fit uint64"))?;
    ensure!(chain_id > 0, "typed data domain chainId must be positive");
    ensure!(
        typed.primary_type != "EIP712Domain",
        "refusing to sign a bare EIP712Domain payload"
    );
    reject_unsigned_members(value, &typed)?;
    let digest = typed
        .eip712_signing_hash()
        .context("failed to compute the EIP-712 signing hash")?;
    Ok((typed, chain_id, digest))
}

/// Refuse a payload carrying members its own type definition does not declare.
///
/// EIP-712 hashes exactly the members listed for a type, in that order.
/// Anything else in the `message` or `domain` object is ignored by the hash —
/// and displayed to the reviewer, because the review screen shows the payload
/// as submitted. That gap is writable: a `"note": "Approving 10 USDC"` beside
/// a `value` of 2^256-1, or a second `deadline` shadowing the real one, reads
/// as part of what is being authorized and is signed by nothing.
///
/// Refusing is the right shape rather than rendering only the signed members.
/// A payload with an extra member is not a payload whose display needs fixing;
/// it is one whose author is describing something other than what they are
/// asking for, and the wallet has no way to know which half was the mistake.
/// The members EIP-712 defines for a domain, and the type each one hashes
/// under, in the order the standard lists them. The domain hash is built from
/// these and only these, so a payload's own `EIP712Domain` declaration decides
/// nothing about what is signed.
const DOMAIN_MEMBERS: [(&str, &str); 5] = [
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
    ("salt", "bytes32"),
];

fn is_domain_member(name: &str) -> bool {
    DOMAIN_MEMBERS.iter().any(|(member, _)| *member == name)
}

fn reject_unsigned_members(value: &serde_json::Value, typed: &TypedData) -> Result<()> {
    // The payload has to be an object before any of the checks below can look
    // inside it — and a payload that is not one is not merely unusual. Alloy
    // accepts a JSON *string* holding the whole payload and unwraps it to
    // parse, while every `get` here misses on the string and reports nothing
    // wrong. That combination skipped this function entirely: the reviewer was
    // shown a blob of text with no member covered by anything.
    let object = value
        .as_object()
        .context("typed data must be a JSON object with types, primaryType, domain, and message")?;

    // Nothing outside those four is hashed, so nothing outside them may be
    // present to be read. A `"note": "only $1 will move"` beside them sits in
    // the reviewed payload looking exactly as authoritative as `message` does,
    // and is signed by nothing.
    for key in object.keys() {
        ensure!(
            matches!(key.as_str(), "types" | "primaryType" | "domain" | "message"),
            "typed data carries \"{key}\", which EIP-712 does not define; \
             it would be displayed but not signed"
        );
    }

    let declarations = value.get("types");

    // The domain is checked against the standard member set, and only against
    // it. EIP-712 fixes what a domain may hold and the hash is built from the
    // fields the standard defines, so a payload's own `EIP712Domain`
    // declaration decides nothing about what gets signed — preferring it here
    // meant an attacker could declare `note`, satisfy this check with it, and
    // have the member displayed and ignored by the hash all the same.
    let domain = value.get("domain").and_then(serde_json::Value::as_object);
    if let Some(domain) = domain {
        for key in domain.keys() {
            ensure!(
                is_domain_member(key),
                "typed data domain carries \"{key}\", which EIP712Domain does not define; \
                 it would be displayed but not signed"
            );
        }
    }
    // The declaration itself is display text and nothing more, so it is
    // required to be exactly the declaration the domain's own fields imply:
    // the same members, each under the type EIP-712 fixes for it, in the
    // standard's order and no more than once.
    //
    // Allowlisting the member *names* was not enough. `{"name": "chainId",
    // "type": "string"}` passed it while telling the reviewer this signature
    // is not chain-bound; so did declaring `verifyingContract` that the domain
    // never carries, or listing `name` twice with two different renderings of
    // the same field. None of that reaches the hash, all of it reaches the
    // review transcript, and the transcript is what the person approves.
    if let Some(declared) = declarations.and_then(|types| types.get("EIP712Domain")) {
        let expected = DOMAIN_MEMBERS
            .iter()
            .filter(|(member, _)| domain.is_some_and(|domain| domain.contains_key(*member)))
            .map(|(member, kind)| serde_json::json!({"name": member, "type": kind}))
            .collect::<Vec<_>>();
        ensure!(
            declared.as_array() == Some(&expected),
            "typed data declares EIP712Domain as {declared}, but the domain it carries is \
             hashed as {}; the declaration is displayed and not signed",
            serde_json::Value::from(expected)
        );
    }

    reject_unsigned_declarations(declarations)?;
    reject_unreachable_types(declarations, &typed.primary_type)?;

    if let Some(message) = value.get("message") {
        reject_unsigned_within(message, &typed.primary_type, declarations, "message")?;
    }
    Ok(())
}

/// Refuse a member declaration carrying anything but the name and type that
/// EIP-712 defines.
///
/// The type string a struct hashes under is built from exactly those two per
/// member. A third key is free text sitting inside the `types` map, which the
/// reviewer reads as the payload's own account of what each field means —
/// `{"name": "value", "type": "uint256", "label": "at most $1"}` beside a
/// `value` of 2^256-1 — and which the hash never sees.
fn reject_unsigned_declarations(types: Option<&serde_json::Value>) -> Result<()> {
    let Some(types) = types.and_then(serde_json::Value::as_object) else {
        return Ok(());
    };
    for (name, members) in types {
        let Some(members) = members.as_array() else {
            continue;
        };
        for member in members {
            let Some(member) = member.as_object() else {
                continue;
            };
            for key in member.keys() {
                ensure!(
                    matches!(key.as_str(), "name" | "type"),
                    "typed data type {name} declares a member with \"{key}\", which EIP-712 does \
                     not define; it would be displayed but not signed"
                );
            }
        }
    }
    Ok(())
}

/// Refuse a type declaration nothing reaches from the primary type.
///
/// EIP-712 hashes a struct under a type string naming only the types actually
/// referenced, so a declaration the primary type cannot reach contributes
/// nothing to the signature. It is still in the `types` map the reviewer
/// reads, which is the whole of the problem: a `"Reassurance": [{"name":
/// "capped", "type": "string"}]` describes the payload without being part of
/// it.
fn reject_unreachable_types(types: Option<&serde_json::Value>, primary_type: &str) -> Result<()> {
    let Some(types) = types.and_then(serde_json::Value::as_object) else {
        return Ok(());
    };
    let mut reached = std::collections::BTreeSet::from(["EIP712Domain"]);
    let mut pending = vec![primary_type];
    while let Some(name) = pending.pop() {
        if !reached.insert(name) {
            continue;
        }
        let Some(members) = types.get(name).and_then(serde_json::Value::as_array) else {
            continue;
        };
        for member in members {
            if let Some(member_type) = member.get("type").and_then(serde_json::Value::as_str) {
                let element = member_type.split('[').next().unwrap_or(member_type);
                if types.contains_key(element) {
                    pending.push(element);
                }
            }
        }
    }
    for name in types.keys() {
        ensure!(
            reached.contains(name.as_str()),
            "typed data declares type {name}, which {primary_type} does not reach; \
             it would be displayed but not signed"
        );
    }
    Ok(())
}

/// Apply the same rule to a struct value at any depth.
///
/// EIP-712 structs nest, and the hash of a nested struct covers exactly the
/// members its own type declares — so every level has the gap the top level
/// has. Checking only `message`'s immediate keys left `message.details.note`
/// as free text: displayed to the reviewer as part of what they are
/// authorizing, and covered by no signature.
///
/// Recursion follows the *value*, not the type graph, so a payload declaring
/// mutually recursive types cannot make this loop: each step consumes one
/// level of JSON nesting, which `serde_json` has already bounded.
fn reject_unsigned_within(
    value: &serde_json::Value,
    type_name: &str,
    types: Option<&serde_json::Value>,
    path: &str,
) -> Result<()> {
    // An array member repeats its element type; `Foo[2]` and `Foo[]` alike.
    if let serde_json::Value::Array(items) = value {
        for (index, item) in items.iter().enumerate() {
            reject_unsigned_within(item, type_name, types, &format!("{path}[{index}]"))?;
        }
        return Ok(());
    }
    // Not an object, or not a struct this payload defines: nothing declares
    // members for it, so there is nothing here that could go unsigned.
    let (Some(object), Some(members)) = (
        value.as_object(),
        types
            .and_then(|types| types.get(type_name))
            .and_then(serde_json::Value::as_array),
    ) else {
        return Ok(());
    };
    let declared: std::collections::BTreeSet<&str> = members
        .iter()
        .filter_map(|member| member.get("name").and_then(serde_json::Value::as_str))
        .collect();
    for key in object.keys() {
        ensure!(
            declared.contains(key.as_str()),
            "typed data {path} carries \"{key}\", which type {type_name} does not declare; it \
             would be displayed but not signed"
        );
    }
    for member in members {
        let (Some(name), Some(member_type)) = (
            member.get("name").and_then(serde_json::Value::as_str),
            member.get("type").and_then(serde_json::Value::as_str),
        ) else {
            continue;
        };
        if let Some(child) = object.get(name) {
            let element = member_type.split('[').next().unwrap_or(member_type);
            reject_unsigned_within(child, element, types, &format!("{path}.{name}"))?;
        }
    }
    Ok(())
}

/// One token approval a recognized permit payload grants when signed.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PermitApproval {
    /// Which permit shape was recognized: `erc2612_permit`, `dai_permit`,
    /// `permit2_permit`, or `permit2_signature_transfer`.
    pub kind: String,
    pub token: String,
    pub spender: String,
    /// The approved or transferable amount in the token's smallest unit.
    pub amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<String>,
}

impl PermitApproval {
    pub fn tuple(&self) -> Result<(Address, Address, U256)> {
        Ok((
            Address::from_str(&self.token).context("permit token address is invalid")?,
            Address::from_str(&self.spender).context("permit spender address is invalid")?,
            U256::from_str_radix(&self.amount, 10).context("permit amount is invalid")?,
        ))
    }
}

/// Recognize permit-style payloads whose signature grants token approvals.
///
/// Recognition matches the complete EIP-712 type encoding, not just the
/// primary type name, so a look-alike type with different semantics is never
/// treated as a permit. Returns `None` for payloads that are not a recognized
/// permit shape; those always require human review. For recognized shapes the
/// signer-side identity field (ERC-2612 `owner`, DAI `holder`) must match the
/// signing wallet.
pub fn interpret_permit_approvals(
    typed: &TypedData,
    wallet: Address,
) -> Result<Option<Vec<PermitApproval>>> {
    let encoded = typed
        .encode_type()
        .context("failed to encode the typed-data primary type")?;
    let verifying_contract = typed.domain.verifying_contract;
    let message = &typed.message;

    if encoded == ERC2612_PERMIT_TYPE {
        let token = verifying_contract.context("permit domain has no verifyingContract")?;
        ensure!(
            field_address(message, "owner")? == wallet,
            "permit owner does not match the signing wallet"
        );
        return Ok(Some(vec![PermitApproval {
            kind: "erc2612_permit".into(),
            token: token.to_checksum(None),
            spender: field_address(message, "spender")?.to_checksum(None),
            amount: field_u256(message, "value")?.to_string(),
            deadline: Some(field_u256(message, "deadline")?.to_string()),
        }]));
    }
    if encoded == DAI_PERMIT_TYPE {
        let token = verifying_contract.context("permit domain has no verifyingContract")?;
        ensure!(
            field_address(message, "holder")? == wallet,
            "permit holder does not match the signing wallet"
        );
        let allowed = message
            .get("allowed")
            .and_then(serde_json::Value::as_bool)
            .context("DAI permit is missing the allowed flag")?;
        return Ok(Some(vec![PermitApproval {
            kind: "dai_permit".into(),
            token: token.to_checksum(None),
            spender: field_address(message, "spender")?.to_checksum(None),
            amount: if allowed { U256::MAX } else { U256::ZERO }.to_string(),
            deadline: Some(field_u256(message, "expiry")?.to_string()),
        }]));
    }

    let permit2 = |kind: &str,
                   entries: Vec<(Address, U256)>,
                   spender: Address,
                   deadline: U256|
     -> Result<Option<Vec<PermitApproval>>> {
        ensure!(
            verifying_contract == Some(PERMIT2_ADDRESS),
            "Permit2-shaped typed data does not verify against the canonical Permit2 contract"
        );
        Ok(Some(
            entries
                .into_iter()
                .map(|(token, amount)| PermitApproval {
                    kind: kind.into(),
                    token: token.to_checksum(None),
                    spender: spender.to_checksum(None),
                    amount: amount.to_string(),
                    deadline: Some(deadline.to_string()),
                })
                .collect(),
        ))
    };

    match encoded.as_str() {
        PERMIT2_SINGLE_TYPE => {
            let details = message
                .get("details")
                .context("PermitSingle has no details")?;
            permit2(
                "permit2_permit",
                vec![(
                    field_address(details, "token")?,
                    field_u256(details, "amount")?,
                )],
                field_address(message, "spender")?,
                field_u256(message, "sigDeadline")?,
            )
        }
        PERMIT2_BATCH_TYPE => {
            let details = message
                .get("details")
                .and_then(serde_json::Value::as_array)
                .context("PermitBatch has no details array")?;
            let entries = details
                .iter()
                .map(|entry| Ok((field_address(entry, "token")?, field_u256(entry, "amount")?)))
                .collect::<Result<Vec<_>>>()?;
            ensure!(!entries.is_empty(), "PermitBatch approves no tokens");
            permit2(
                "permit2_permit",
                entries,
                field_address(message, "spender")?,
                field_u256(message, "sigDeadline")?,
            )
        }
        PERMIT2_TRANSFER_TYPE => {
            let permitted = message
                .get("permitted")
                .context("PermitTransferFrom has no permitted token")?;
            permit2(
                "permit2_signature_transfer",
                vec![(
                    field_address(permitted, "token")?,
                    field_u256(permitted, "amount")?,
                )],
                field_address(message, "spender")?,
                field_u256(message, "deadline")?,
            )
        }
        PERMIT2_BATCH_TRANSFER_TYPE => {
            let permitted = message
                .get("permitted")
                .and_then(serde_json::Value::as_array)
                .context("PermitBatchTransferFrom has no permitted array")?;
            let entries = permitted
                .iter()
                .map(|entry| Ok((field_address(entry, "token")?, field_u256(entry, "amount")?)))
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                !entries.is_empty(),
                "PermitBatchTransferFrom permits no tokens"
            );
            permit2(
                "permit2_signature_transfer",
                entries,
                field_address(message, "spender")?,
                field_u256(message, "deadline")?,
            )
        }
        _ => Ok(None),
    }
}

fn field_address(value: &serde_json::Value, field: &str) -> Result<Address> {
    let raw = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("typed-data message field {field} is missing or not a string"))?;
    Address::from_str(raw).with_context(|| format!("typed-data field {field} is not an address"))
}

fn field_u256(value: &serde_json::Value, field: &str) -> Result<U256> {
    let raw = value
        .get(field)
        .with_context(|| format!("typed-data message field {field} is missing"))?;
    match raw {
        serde_json::Value::Number(number) => {
            let number = number
                .as_u64()
                .with_context(|| format!("typed-data field {field} is not an unsigned integer"))?;
            Ok(U256::from(number))
        }
        serde_json::Value::String(text) => {
            let parsed = if let Some(hexadecimal) = text.strip_prefix("0x") {
                U256::from_str_radix(hexadecimal, 16)
            } else {
                U256::from_str_radix(text, 10)
            };
            parsed.with_context(|| format!("typed-data field {field} is not a uint256"))
        }
        _ => anyhow::bail!("typed-data field {field} has an unsupported JSON type"),
    }
}

pub struct TypedDataStore {
    database: PolicyStore,
}

impl TypedDataStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            database: PolicyStore::production(data_dir)?,
        })
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    /// Queue one typed-data payload for human review. An identical payload
    /// already awaiting approval for the same wallet is reused.
    pub fn create(
        &mut self,
        wallet_id: &str,
        chain_id: u64,
        typed_data: &serde_json::Value,
        digest: B256,
    ) -> Result<PendingTypedData> {
        let stored_chain_id = i64::try_from(chain_id).context("chain ID out of range")?;
        let request_id = QUEUE.create_or_reuse(
            &mut self.database.connection,
            wallet_id,
            chain_id,
            digest,
            |transaction, request_id, now| {
                transaction.execute(
                    "INSERT INTO pending_typed_data(
                        request_id, wallet_id, chain_id, typed_data_json, digest,
                        status, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'awaiting_approval', ?6, ?6)",
                    params![
                        request_id,
                        wallet_id,
                        stored_chain_id,
                        serde_json::to_string(typed_data)?,
                        Blob(digest),
                        Millis(now),
                    ],
                )?;
                Ok(())
            },
        )?;
        self.get(request_id)
    }

    pub fn get(&self, request_id: Uuid) -> Result<PendingTypedData> {
        self.read(request_id)
    }

    pub fn reject(&mut self, request_id: Uuid) -> Result<PendingTypedData> {
        let current = self.get(request_id)?;
        ensure!(
            current.status == TypedDataStatus::AwaitingApproval,
            "typed-data request is not awaiting approval"
        );
        QUEUE.reject(&self.database.connection, request_id)?;
        self.get(request_id)
    }

    /// Atomically record approval and the exact signature. The stored payload
    /// digest must still match what the approver reviewed.
    pub fn store_signature(
        &mut self,
        request_id: Uuid,
        signer_wallet_id: &str,
        expected_digest: B256,
        signature: &str,
    ) -> Result<PendingTypedData> {
        QUEUE.store_signature(
            &mut self.database.connection,
            request_id,
            signer_wallet_id,
            expected_digest,
            signature,
        )?;
        self.get(request_id)
    }

    pub fn awaiting_approval(&self, wallet_id: Option<&str>) -> Result<Vec<PendingTypedData>> {
        QUEUE
            .awaiting_ids(&self.database.connection, wallet_id)?
            .into_iter()
            .map(|id| self.get(id))
            .filter(|result| {
                result.as_ref().map_or(true, |record| {
                    record.status == TypedDataStatus::AwaitingApproval
                })
            })
            .collect()
    }

    /// Read one request. The `approval_required` and `policy_revision` columns
    /// are deliberately not selected: they exist only for rows a previous
    /// version signed automatically, and nothing signs typed data without a
    /// human any more.
    fn read(&self, request_id: Uuid) -> Result<PendingTypedData> {
        let row = self
            .database
            .connection
            .query_row(
                "SELECT wallet_id, chain_id, typed_data_json, digest, status,
                        created_at, updated_at, decided_at, signature
                 FROM pending_typed_data WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.blob::<B256>(3)?,
                        row.get::<_, String>(4)?,
                        row.time(5)?,
                        row.time(6)?,
                        row.time_opt(7)?,
                        row.blob_opt::<[u8; 65]>(8)?,
                    ))
                },
            )
            .with_context(|| format!("unknown typed-data request {request_id}"))?;
        let (
            wallet_id,
            chain_id,
            typed_data_json,
            digest,
            status,
            created_at,
            updated_at,
            decided_at,
            signature,
        ) = row;
        crate::config::validate_wallet_id(&wallet_id)?;
        let typed_data: serde_json::Value =
            serde_json::from_str(&typed_data_json).context("stored typed data is invalid JSON")?;
        // Re-derive the digest so a corrupted or edited row can never present
        // one payload while binding a signature to another.
        let (_, stored_chain_id, actual_digest) = parse_typed_data(&typed_data)?;
        ensure!(actual_digest == digest, "stored typed-data digest mismatch");
        ensure!(
            i64::try_from(stored_chain_id).is_ok_and(|declared| declared == chain_id),
            "stored typed-data chain mismatch"
        );
        let status = TypedDataStatus::parse(&status)?;
        let (approved_at, rejected_at) =
            split_decision(decided_at, status == TypedDataStatus::Rejected);
        Ok(PendingTypedData {
            request_id,
            wallet_id,
            chain_id: chain_id.to_string(),
            typed_data,
            digest: format!("{digest:#x}"),
            status,
            created_at,
            updated_at,
            approved_at,
            rejected_at,
            signature: signature.map(encode_signature),
        })
    }
}

#[cfg(test)]
#[path = "typed_data_test.rs"]
mod tests;
