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
    signature_requests::{SignatureQueue, parse_time, validate_signature_hex},
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
fn reject_unsigned_members(value: &serde_json::Value, typed: &TypedData) -> Result<()> {
    for (object_name, declared_type) in [
        ("message", typed.primary_type.as_str()),
        ("domain", "EIP712Domain"),
    ] {
        let Some(object) = value
            .get(object_name)
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        // Read from the payload's own `types` map, which is the same thing
        // the hash is derived from. A type absent there is left alone:
        // `EIP712Domain` is commonly omitted and its members are fixed by the
        // standard, and a missing `primaryType` has already failed above.
        let Some(members) = value
            .get("types")
            .and_then(|types| types.get(declared_type))
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        let declared: std::collections::BTreeSet<&str> = members
            .iter()
            .filter_map(|member| member.get("name").and_then(serde_json::Value::as_str))
            .collect();
        for key in object.keys() {
            ensure!(
                declared.contains(key.as_str()),
                "typed data {object_name} carries \"{key}\", which type {declared_type} does not \
                 declare; it would be displayed but not signed"
            );
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
        let digest = format!("{digest:#x}");
        let request_id = QUEUE.create_or_reuse(
            &mut self.database.connection,
            wallet_id,
            &chain_id.to_string(),
            &digest,
            |transaction, request_id, now| {
                transaction.execute(
                    "INSERT INTO pending_typed_data(
                        request_id, wallet_id, chain_id, typed_data_json, digest,
                        status, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'awaiting_approval', ?6, ?6)",
                    params![
                        request_id.to_string(),
                        wallet_id,
                        chain_id.to_string(),
                        serde_json::to_string(typed_data)?,
                        digest,
                        now,
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
        expected_digest: &str,
        signature: &str,
    ) -> Result<PendingTypedData> {
        QUEUE.store_signature(
            &mut self.database.connection,
            request_id,
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
                        created_at, updated_at, approved_at, rejected_at,
                        signature
                 FROM pending_typed_data WHERE request_id = ?1",
                [request_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<String>>(9)?,
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
            approved_at,
            rejected_at,
            signature,
        ) = row;
        crate::config::validate_wallet_id(&wallet_id)?;
        let typed_data: serde_json::Value =
            serde_json::from_str(&typed_data_json).context("stored typed data is invalid JSON")?;
        // Re-derive the digest so a corrupted or edited row can never present
        // one payload while binding a signature to another.
        let (_, stored_chain_id, actual_digest) = parse_typed_data(&typed_data)?;
        ensure!(
            format!("{actual_digest:#x}") == digest,
            "stored typed-data digest mismatch"
        );
        ensure!(
            stored_chain_id.to_string() == chain_id,
            "stored typed-data chain mismatch"
        );
        if let Some(signature) = &signature {
            validate_signature_hex(signature)?;
        }
        Ok(PendingTypedData {
            request_id,
            wallet_id,
            chain_id,
            typed_data,
            digest,
            status: TypedDataStatus::parse(&status)?,
            created_at: parse_time(&created_at)?,
            updated_at: parse_time(&updated_at)?,
            approved_at: approved_at.as_deref().map(parse_time).transpose()?,
            rejected_at: rejected_at.as_deref().map(parse_time).transpose()?,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_store::DatabaseKey;
    use serde_json::json;

    #[test]
    fn a_member_the_type_does_not_declare_is_refused() {
        // EIP-712 hashes only the members listed for the type. Anything else
        // in `message` is displayed to the reviewer and signed by nothing, so
        // it can describe a transaction other than the one being authorized.
        let mut payload = permit_payload();
        payload["message"]["note"] = json!("Approving 10 USDC");
        let error = parse_typed_data(&payload).unwrap_err().to_string();
        assert!(error.contains("\"note\""), "{error}");
        assert!(error.contains("not signed"), "{error}");

        // A member shadowing a declared one is the same problem wearing the
        // right name, and is caught by the type not declaring it.
        let mut shadowed = permit_payload();
        shadowed["message"]["Deadline"] = json!(1);
        assert!(parse_typed_data(&shadowed).is_err());

        // The domain is checked the same way.
        let mut domain = permit_payload();
        domain["domain"]["salt"] = json!("0x01");
        assert!(parse_typed_data(&domain).is_err());

        // And an untouched payload still parses.
        assert!(parse_typed_data(&permit_payload()).is_ok());
    }

    pub(crate) fn permit_payload() -> serde_json::Value {
        json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Permit": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "USD Coin",
                "version": "2",
                "chainId": 1,
                "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            },
            "message": {
                "owner": "0x1111111111111111111111111111111111111111",
                "spender": "0x2222222222222222222222222222222222222222",
                "value": "1000000",
                "nonce": "0",
                "deadline": "1900000000"
            }
        })
    }

    fn store() -> (tempfile::TempDir, TypedDataStore) {
        let directory = tempfile::tempdir().unwrap();
        let database = PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([9; 32]),
        )
        .unwrap();
        (directory, TypedDataStore::new(database))
    }

    #[test]
    fn parses_and_digests_typed_data_with_pinned_chain() {
        let (_, chain_id, digest) = parse_typed_data(&permit_payload()).unwrap();
        assert_eq!(chain_id, 1);
        assert_ne!(digest, B256::ZERO);

        let mut chainless = permit_payload();
        chainless["domain"]
            .as_object_mut()
            .unwrap()
            .remove("chainId");
        assert!(parse_typed_data(&chainless).is_err());

        let mut domain_only = permit_payload();
        domain_only["primaryType"] = json!("EIP712Domain");
        assert!(parse_typed_data(&domain_only).is_err());
    }

    #[test]
    fn lifecycle_persists_exact_payload_and_signature() {
        let (_directory, mut store) = store();
        let payload = permit_payload();
        let (_, chain_id, digest) = parse_typed_data(&payload).unwrap();
        let request = store.create("primary", chain_id, &payload, digest).unwrap();
        assert_eq!(request.status, TypedDataStatus::AwaitingApproval);
        assert_eq!(request.typed_data, payload);

        // The identical payload reuses the pending request.
        let duplicate = store.create("primary", chain_id, &payload, digest).unwrap();
        assert_eq!(duplicate.request_id, request.request_id);
        assert_eq!(store.awaiting_approval(None).unwrap().len(), 1);

        let signature = format!("0x{}", "11".repeat(65));
        let signed = store
            .store_signature(request.request_id, &request.digest, &signature)
            .unwrap();
        assert_eq!(signed.status, TypedDataStatus::Signed);
        assert_eq!(signed.signature.as_deref(), Some(signature.as_str()));
        assert!(signed.approved_at.is_some());
        assert!(store.awaiting_approval(None).unwrap().is_empty());

        // A signed request cannot be re-signed or rejected.
        assert!(
            store
                .store_signature(request.request_id, &request.digest, &signature)
                .is_err()
        );
        assert!(store.reject(request.request_id).is_err());
    }

    #[test]
    fn recognizes_erc2612_permits_only_for_the_signing_wallet() {
        let payload = permit_payload();
        let (typed, _, _) = parse_typed_data(&payload).unwrap();
        let wallet = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let approvals = interpret_permit_approvals(&typed, wallet).unwrap().unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].kind, "erc2612_permit");
        assert_eq!(
            approvals[0].token,
            Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
                .unwrap()
                .to_checksum(None)
        );
        assert_eq!(approvals[0].amount, "1000000");

        let stranger = Address::repeat_byte(0x77);
        assert!(interpret_permit_approvals(&typed, stranger).is_err());
    }

    #[test]
    fn lookalike_permit_types_are_not_treated_as_approvals() {
        let mut payload = permit_payload();
        // Same primary type name, different fields: must not be recognized.
        payload["types"]["Permit"] = json!([
            {"name": "owner", "type": "address"},
            {"name": "spender", "type": "address"},
            {"name": "data", "type": "bytes32"}
        ]);
        payload["message"] = json!({
            "owner": "0x1111111111111111111111111111111111111111",
            "spender": "0x2222222222222222222222222222222222222222",
            "data": "0x1111111111111111111111111111111111111111111111111111111111111111"
        });
        let (typed, _, _) = parse_typed_data(&payload).unwrap();
        let wallet = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        assert!(
            interpret_permit_approvals(&typed, wallet)
                .unwrap()
                .is_none()
        );
    }

    fn permit2_payload(verifying_contract: &str) -> serde_json::Value {
        json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "PermitSingle": [
                    {"name": "details", "type": "PermitDetails"},
                    {"name": "spender", "type": "address"},
                    {"name": "sigDeadline", "type": "uint256"}
                ],
                "PermitDetails": [
                    {"name": "token", "type": "address"},
                    {"name": "amount", "type": "uint160"},
                    {"name": "expiration", "type": "uint48"},
                    {"name": "nonce", "type": "uint48"}
                ]
            },
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": 1,
                "verifyingContract": verifying_contract
            },
            "message": {
                "details": {
                    "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                    "amount": "1461501637330902918203684832716283019655932542975",
                    "expiration": "1900000000",
                    "nonce": "0"
                },
                "spender": "0x3333333333333333333333333333333333333333",
                "sigDeadline": "1900000000"
            }
        })
    }

    #[test]
    fn permit2_is_recognized_only_at_the_canonical_deployment() {
        let (typed, _, _) = parse_typed_data(&permit2_payload(
            "0x000000000022d473030f116ddee9f6b43ac78ba3",
        ))
        .unwrap();
        let wallet = Address::repeat_byte(0x11);
        let approvals = interpret_permit_approvals(&typed, wallet).unwrap().unwrap();
        assert_eq!(approvals[0].kind, "permit2_permit");
        assert_eq!(
            approvals[0].spender,
            Address::from_str("0x3333333333333333333333333333333333333333")
                .unwrap()
                .to_checksum(None)
        );

        let (impostor, _, _) = parse_typed_data(&permit2_payload(
            "0x4444444444444444444444444444444444444444",
        ))
        .unwrap();
        assert!(interpret_permit_approvals(&impostor, wallet).is_err());
    }

    #[test]
    fn a_signature_can_only_come_from_an_approved_request() {
        // The store offers exactly one way to attach a signature, and it works
        // only on a request that is awaiting approval. There is no path that
        // records a signed payload without a human having approved it.
        let (_directory, mut store) = store();
        let payload = permit_payload();
        let (_, chain_id, digest) = parse_typed_data(&payload).unwrap();
        let request = store.create("primary", chain_id, &payload, digest).unwrap();
        store.reject(request.request_id).unwrap();
        assert!(
            store
                .store_signature(
                    request.request_id,
                    &request.digest,
                    &format!("0x{}", "33".repeat(65)),
                )
                .is_err()
        );
    }

    #[test]
    fn rejection_is_terminal_and_digest_is_bound() {
        let (_directory, mut store) = store();
        let payload = permit_payload();
        let (_, chain_id, digest) = parse_typed_data(&payload).unwrap();
        let request = store.create("primary", chain_id, &payload, digest).unwrap();
        assert!(
            store
                .store_signature(
                    request.request_id,
                    &format!("{:#x}", B256::repeat_byte(0xEE)),
                    &format!("0x{}", "22".repeat(65)),
                )
                .is_err()
        );
        assert_eq!(
            store.reject(request.request_id).unwrap().status,
            TypedDataStatus::Rejected
        );
        assert!(store.reject(request.request_id).is_err());
    }
}
