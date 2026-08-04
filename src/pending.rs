//! Encrypted pending approval and transaction lifecycle persistence.
//!
//! These records bind exact plans and signed bytes. They are not spending
//! counters, policy reservations, or rolling-limit state.

use crate::{
    config::validate_wallet_id, core::execution_plan::ExecutionPlan, policy_store::PolicyStore,
};
use alloy::primitives::B256;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr};
use uuid::Uuid;

const MAX_AWAITING_APPROVALS_PER_WALLET: i64 = 64;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PendingStatus {
    AwaitingApproval,
    Rejected,
    Signed,
    Submitting,
    Broadcast,
    Confirmed,
    Reverted,
    Expired,
    Cancelled,
}

impl PendingStatus {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "awaiting_approval" => Ok(Self::AwaitingApproval),
            "rejected" => Ok(Self::Rejected),
            "signed" => Ok(Self::Signed),
            "submitting" => Ok(Self::Submitting),
            "broadcast" => Ok(Self::Broadcast),
            "confirmed" => Ok(Self::Confirmed),
            "reverted" => Ok(Self::Reverted),
            "expired" => Ok(Self::Expired),
            "cancelled" => Ok(Self::Cancelled),
            _ => anyhow::bail!("stored pending transaction has invalid status {value}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct PendingTransaction {
    pub request_id: Uuid,
    pub wallet_id: String,
    pub network_name: String,
    pub chain_id: String,
    pub execution_plan: ExecutionPlan,
    pub digest: String,
    /// Digest of exact nonce, gas, fee, call, and delegation fields reviewed
    /// for an exceptional approval. Automatic transactions do not have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_digest: Option<String>,
    pub policy_revision: u64,
    pub approval_required: bool,
    pub status: PendingStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serialized_transaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_transaction_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broadcast_transaction_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<String>,
}

pub struct PendingStore {
    database: PolicyStore,
}

impl PendingStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            database: PolicyStore::production(data_dir)?,
        })
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    pub fn create(
        &mut self,
        wallet_id: &str,
        network_name: &str,
        plan: &ExecutionPlan,
        policy_revision: u64,
        approval_expiry_seconds: u32,
    ) -> Result<PendingTransaction> {
        validate_wallet_id(wallet_id)?;
        ensure!(
            !network_name.trim().is_empty(),
            "network name cannot be empty"
        );
        ensure!(
            approval_expiry_seconds > 0,
            "approval expiry must be positive"
        );
        plan.validate()?;
        let policy_revision =
            i64::try_from(policy_revision).context("policy revision is too large")?;
        let transaction = self.database.connection.transaction()?;
        let stored_revision: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM wallet_policies WHERE wallet_id = ?1",
                [wallet_id],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            stored_revision == Some(policy_revision),
            "active policy revision changed before pending request creation"
        );

        let created_at = Utc::now();
        let digest = format!("{:#x}", plan.digest());
        transaction.execute(
            "UPDATE pending_transactions SET status = 'expired', updated_at = ?1
             WHERE status = 'awaiting_approval' AND expires_at <= ?1",
            [created_at.to_rfc3339()],
        )?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT request_id FROM pending_transactions
                 WHERE wallet_id = ?1 AND chain_id = ?2 AND plan_digest = ?3
                   AND status = 'awaiting_approval'",
                params![wallet_id, plan.chain_id.as_str(), digest],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            transaction.commit()?;
            return self.get(Uuid::parse_str(&existing).context("stored request ID is invalid")?);
        }
        let awaiting: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM pending_transactions
             WHERE wallet_id = ?1 AND status = 'awaiting_approval'",
            [wallet_id],
            |row| row.get(0),
        )?;
        ensure!(
            awaiting < MAX_AWAITING_APPROVALS_PER_WALLET,
            "wallet already has {MAX_AWAITING_APPROVALS_PER_WALLET} requests awaiting approval"
        );

        let request_id = Uuid::new_v4();
        let expires_at = created_at + TimeDelta::seconds(i64::from(approval_expiry_seconds));
        let plan_json = serde_json::to_string(plan)?;
        transaction.execute(
            "INSERT INTO pending_transactions(
                request_id, wallet_id, network_name, chain_id, plan_json,
                plan_digest, policy_revision, status, created_at, expires_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'awaiting_approval', ?8, ?9, ?8)",
            params![
                request_id.to_string(),
                wallet_id,
                network_name,
                plan.chain_id.as_str(),
                plan_json,
                digest,
                policy_revision,
                created_at.to_rfc3339(),
                expires_at.to_rfc3339(),
            ],
        )?;
        transaction.commit()?;
        self.get(request_id)
    }

    /// Persist an automatically authorized signature before the first RPC
    /// submission. It is recorded in the same lifecycle table but never
    /// appears in the exceptional-approval queue.
    pub fn record_automatic_signed(
        &mut self,
        wallet_id: &str,
        network_name: &str,
        plan: &ExecutionPlan,
        policy_revision: u64,
        serialized_transaction: &str,
        transaction_hash: &str,
    ) -> Result<PendingTransaction> {
        validate_wallet_id(wallet_id)?;
        ensure!(
            !network_name.trim().is_empty(),
            "network name cannot be empty"
        );
        plan.validate()?;
        validate_hex(serialized_transaction, None)?;
        validate_hex(transaction_hash, Some(32))?;
        let policy_revision =
            i64::try_from(policy_revision).context("policy revision is too large")?;
        let transaction = self.database.connection.transaction()?;
        let active_revision: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM wallet_policies WHERE wallet_id = ?1",
                [wallet_id],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            active_revision == Some(policy_revision),
            "active policy revision changed before signed transaction persistence"
        );

        let request_id = Uuid::new_v4();
        let created_at = Utc::now();
        transaction
            .execute(
                "INSERT INTO pending_transactions(
                request_id, wallet_id, network_name, chain_id, plan_json,
                plan_digest, policy_revision, status, created_at, expires_at, updated_at,
                serialized_transaction, signed_transaction_hash, approval_required
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'signed', ?8, ?8, ?8, ?9, ?10, 0)",
                params![
                    request_id.to_string(),
                    wallet_id,
                    network_name,
                    plan.chain_id.as_str(),
                    serde_json::to_string(plan)?,
                    format!("{:#x}", plan.digest()),
                    policy_revision,
                    created_at.to_rfc3339(),
                    serialized_transaction,
                    transaction_hash,
                ],
            )
            .context("another signed transaction is already in flight for this wallet and chain")?;
        transaction.commit()?;
        self.get(request_id)
    }

    pub fn get(&self, request_id: Uuid) -> Result<PendingTransaction> {
        let mut record = self.read(request_id)?;
        if record.status == PendingStatus::AwaitingApproval && record.expires_at <= Utc::now() {
            let updated_at = Utc::now();
            self.database.connection.execute(
                "UPDATE pending_transactions SET status = 'expired', updated_at = ?2
                 WHERE request_id = ?1 AND status = 'awaiting_approval'",
                params![request_id.to_string(), updated_at.to_rfc3339()],
            )?;
            record = self.read(request_id)?;
        }
        Ok(record)
    }

    pub fn reject(&mut self, request_id: Uuid) -> Result<PendingTransaction> {
        let transaction = self.database.connection.transaction()?;
        let (status, expires_at, approval_required): (String, String, i64) = transaction
            .query_row(
                "SELECT status, expires_at, approval_required
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .with_context(|| format!("unknown pending request {request_id}"))?;
        ensure!(
            approval_required == 1,
            "transaction did not require approval"
        );
        ensure!(
            PendingStatus::parse(&status)? == PendingStatus::AwaitingApproval,
            "pending request is not awaiting approval"
        );
        ensure!(
            parse_time(&expires_at)? > Utc::now(),
            "pending request expired"
        );
        let now = Utc::now().to_rfc3339();
        transaction.execute(
            "UPDATE pending_transactions
             SET status = 'rejected', rejected_at = ?2, updated_at = ?2
             WHERE request_id = ?1 AND status = 'awaiting_approval'",
            params![request_id.to_string(), now],
        )?;
        transaction.commit()?;
        self.get(request_id)
    }

    /// Atomically records owner approval and the exact locally validated signed
    /// bytes. Approval without a complete signed transaction is never stored.
    pub fn store_signed(
        &mut self,
        request_id: Uuid,
        expected_digest: &str,
        review_digest: &str,
        serialized_transaction: &str,
        transaction_hash: &str,
    ) -> Result<PendingTransaction> {
        validate_hex(review_digest, Some(32))?;
        validate_hex(serialized_transaction, None)?;
        validate_hex(transaction_hash, Some(32))?;
        let transaction = self.database.connection.transaction()?;
        let (wallet_id, digest, policy_revision, status, expires_at, approval_required): (
            String,
            String,
            i64,
            String,
            String,
            i64,
        ) = transaction
            .query_row(
                "SELECT wallet_id, plan_digest, policy_revision, status, expires_at,
                        approval_required
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .with_context(|| format!("unknown pending request {request_id}"))?;
        ensure!(
            approval_required == 1,
            "transaction did not require approval"
        );
        ensure!(digest == expected_digest, "pending request digest mismatch");
        ensure!(
            PendingStatus::parse(&status)? == PendingStatus::AwaitingApproval,
            "pending request is not awaiting approval"
        );
        ensure!(
            parse_time(&expires_at)? > Utc::now(),
            "pending request expired"
        );
        let active_revision: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM wallet_policies WHERE wallet_id = ?1",
                [&wallet_id],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            active_revision == Some(policy_revision),
            "active policy changed while approval was pending"
        );
        let now = Utc::now().to_rfc3339();
        transaction
            .execute(
                "UPDATE pending_transactions SET
                status = 'signed', approved_at = ?2, updated_at = ?2,
                serialized_transaction = ?3, signed_transaction_hash = ?4,
                review_digest = ?5
             WHERE request_id = ?1 AND status = 'awaiting_approval'",
                params![
                    request_id.to_string(),
                    now,
                    serialized_transaction,
                    transaction_hash,
                    review_digest,
                ],
            )
            .context("another signed transaction is already in flight for this wallet and chain")?;
        transaction.commit()?;
        self.get(request_id)
    }

    /// Claims signed bytes for one submission attempt. Callers must reconcile
    /// the exact signed hash with the chain before invoking this method.
    pub fn claim_for_submission(&mut self, request_id: Uuid) -> Result<PendingTransaction> {
        let transaction = self.database.connection.transaction()?;
        let (wallet_id, policy_revision, status): (String, i64, String) = transaction
            .query_row(
                "SELECT wallet_id, policy_revision, status
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .with_context(|| format!("unknown pending request {request_id}"))?;
        ensure!(
            PendingStatus::parse(&status)? == PendingStatus::Signed,
            "pending transaction is not ready for submission"
        );
        let active_revision: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM wallet_policies WHERE wallet_id = ?1",
                [&wallet_id],
                |row| row.get(0),
            )
            .optional()?;
        if active_revision != Some(policy_revision) {
            transaction.execute(
                "UPDATE pending_transactions SET status = 'cancelled', updated_at = ?2
                 WHERE request_id = ?1 AND status = 'signed'",
                params![request_id.to_string(), Utc::now().to_rfc3339()],
            )?;
            transaction.commit()?;
            anyhow::bail!("active policy changed after this transaction was signed");
        }
        transaction.execute(
            "UPDATE pending_transactions SET status = 'submitting', updated_at = ?2
             WHERE request_id = ?1 AND status = 'signed'",
            params![request_id.to_string(), Utc::now().to_rfc3339()],
        )?;
        transaction.commit()?;
        self.get(request_id)
    }

    pub fn release_submission(&mut self, request_id: Uuid) -> Result<PendingTransaction> {
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = 'signed', updated_at = ?2
             WHERE request_id = ?1 AND status = 'submitting'",
            params![request_id.to_string(), Utc::now().to_rfc3339()],
        )?;
        ensure!(changed == 1, "pending transaction is not being submitted");
        self.get(request_id)
    }

    pub fn mark_broadcast(
        &mut self,
        request_id: Uuid,
        transaction_hash: &str,
    ) -> Result<PendingTransaction> {
        validate_hex(transaction_hash, Some(32))?;
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET
                status = 'broadcast', broadcast_transaction_hash = ?2, updated_at = ?3
             WHERE request_id = ?1 AND status = 'submitting'
               AND signed_transaction_hash = ?2",
            params![
                request_id.to_string(),
                transaction_hash,
                Utc::now().to_rfc3339()
            ],
        )?;
        ensure!(changed == 1, "broadcast hash or transaction state mismatch");
        self.get(request_id)
    }

    /// Claim a previously attempted transaction for an exact-byte
    /// rebroadcast. Policy changes do not invalidate this transition: once a
    /// submission may have reached the network, rebroadcasting the identical
    /// signed envelope cannot expand what was already authorized.
    pub fn claim_broadcast_retry(&mut self, request_id: Uuid) -> Result<PendingTransaction> {
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = 'submitting', updated_at = ?2
             WHERE request_id = ?1 AND status = 'broadcast'
               AND serialized_transaction IS NOT NULL
               AND signed_transaction_hash IS NOT NULL
               AND signed_transaction_hash = broadcast_transaction_hash",
            params![request_id.to_string(), Utc::now().to_rfc3339()],
        )?;
        ensure!(
            changed == 1,
            "pending transaction is not available for an exact-byte rebroadcast"
        );
        self.get(request_id)
    }

    pub fn finalize(
        &mut self,
        request_id: Uuid,
        succeeded: bool,
        block_number: &str,
    ) -> Result<PendingTransaction> {
        ensure!(
            block_number == "0"
                || (!block_number.starts_with('0')
                    && block_number.bytes().all(|byte| byte.is_ascii_digit())),
            "block number must be canonical decimal"
        );
        let status = if succeeded { "confirmed" } else { "reverted" };
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = ?2, block_number = ?3, updated_at = ?4
             WHERE request_id = ?1 AND status = 'broadcast'",
            params![
                request_id.to_string(),
                status,
                block_number,
                Utc::now().to_rfc3339()
            ],
        )?;
        ensure!(
            changed == 1,
            "pending transaction is not awaiting a receipt"
        );
        self.get(request_id)
    }

    pub fn awaiting_approval(&self, wallet_id: Option<&str>) -> Result<Vec<PendingTransaction>> {
        if let Some(wallet_id) = wallet_id {
            validate_wallet_id(wallet_id)?;
        }
        let mut statement = self.database.connection.prepare(
            "SELECT request_id FROM pending_transactions
             WHERE status = 'awaiting_approval' AND approval_required = 1
               AND (?1 IS NULL OR wallet_id = ?1)
             ORDER BY created_at DESC",
        )?;
        let request_ids = statement
            .query_map([wallet_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        request_ids
            .into_iter()
            .map(|value| {
                let id = Uuid::parse_str(&value).context("stored request ID is invalid")?;
                self.get(id)
            })
            .filter(|result| {
                result.as_ref().map_or(true, |record| {
                    record.status == PendingStatus::AwaitingApproval
                })
            })
            .collect()
    }

    pub fn list(&self, wallet_id: Option<&str>, limit: u16) -> Result<Vec<PendingTransaction>> {
        if let Some(wallet_id) = wallet_id {
            validate_wallet_id(wallet_id)?;
        }
        ensure!(
            (1..=1_000).contains(&limit),
            "limit must be between 1 and 1000"
        );
        let mut statement = self.database.connection.prepare(
            "SELECT request_id FROM pending_transactions
             WHERE (?1 IS NULL OR wallet_id = ?1)
             ORDER BY created_at DESC LIMIT ?2",
        )?;
        let request_ids = statement
            .query_map(params![wallet_id, i64::from(limit)], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        request_ids
            .into_iter()
            .map(|value| self.get(Uuid::parse_str(&value).context("stored request ID is invalid")?))
            .collect()
    }

    pub fn get_by_identifier(&self, identifier: &str) -> Result<PendingTransaction> {
        if let Ok(request_id) = Uuid::parse_str(identifier) {
            return self.get(request_id);
        }
        validate_hex(identifier, Some(32))?;
        let request_id: String = self
            .database
            .connection
            .query_row(
                "SELECT request_id FROM pending_transactions
                 WHERE signed_transaction_hash = ?1 OR broadcast_transaction_hash = ?1
                 ORDER BY created_at DESC LIMIT 1",
                [identifier],
                |row| row.get(0),
            )
            .with_context(|| format!("unknown transaction {identifier}"))?;
        self.get(Uuid::parse_str(&request_id).context("stored request ID is invalid")?)
    }

    fn read(&self, request_id: Uuid) -> Result<PendingTransaction> {
        let raw = self
            .database
            .connection
            .query_row(
                "SELECT wallet_id, network_name, chain_id, plan_json, plan_digest,
                        policy_revision, status, created_at, expires_at, updated_at,
                        approved_at, rejected_at, serialized_transaction,
                        signed_transaction_hash, broadcast_transaction_hash, block_number,
                        approval_required, review_digest
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id.to_string()],
                |row| {
                    Ok(PendingRow {
                        wallet_id: row.get(0)?,
                        network_name: row.get(1)?,
                        chain_id: row.get(2)?,
                        plan_json: row.get(3)?,
                        digest: row.get(4)?,
                        policy_revision: row.get(5)?,
                        status: row.get(6)?,
                        created_at: row.get(7)?,
                        expires_at: row.get(8)?,
                        updated_at: row.get(9)?,
                        approved_at: row.get(10)?,
                        rejected_at: row.get(11)?,
                        serialized_transaction: row.get(12)?,
                        signed_transaction_hash: row.get(13)?,
                        broadcast_transaction_hash: row.get(14)?,
                        block_number: row.get(15)?,
                        approval_required: row.get(16)?,
                        review_digest: row.get(17)?,
                    })
                },
            )
            .with_context(|| format!("unknown pending request {request_id}"))?;
        raw.parse(request_id)
    }
}

struct PendingRow {
    wallet_id: String,
    network_name: String,
    chain_id: String,
    plan_json: String,
    digest: String,
    policy_revision: i64,
    status: String,
    created_at: String,
    expires_at: String,
    updated_at: String,
    approved_at: Option<String>,
    rejected_at: Option<String>,
    serialized_transaction: Option<String>,
    signed_transaction_hash: Option<String>,
    broadcast_transaction_hash: Option<String>,
    block_number: Option<String>,
    approval_required: i64,
    review_digest: Option<String>,
}

impl PendingRow {
    fn parse(self, request_id: Uuid) -> Result<PendingTransaction> {
        validate_wallet_id(&self.wallet_id)?;
        let value = serde_json::from_str(&self.plan_json).context("stored plan is invalid JSON")?;
        let execution_plan = ExecutionPlan::parse(value).context("stored plan is invalid")?;
        let actual_digest = format!("{:#x}", execution_plan.digest());
        ensure!(actual_digest == self.digest, "stored plan digest mismatch");
        ensure!(
            execution_plan.chain_id.as_str() == self.chain_id,
            "stored pending chain ID mismatch"
        );
        validate_hex(&self.digest, Some(32))?;
        if let Some(bytes) = &self.serialized_transaction {
            validate_hex(bytes, None)?;
        }
        if let Some(hash) = &self.signed_transaction_hash {
            validate_hex(hash, Some(32))?;
        }
        if let Some(hash) = &self.broadcast_transaction_hash {
            validate_hex(hash, Some(32))?;
        }
        if let Some(digest) = &self.review_digest {
            validate_hex(digest, Some(32))?;
        }
        ensure!(
            self.serialized_transaction.is_some() == self.signed_transaction_hash.is_some(),
            "stored signed transaction is incomplete"
        );
        let policy_revision =
            u64::try_from(self.policy_revision).context("stored policy revision is invalid")?;
        let approval_required = match self.approval_required {
            0 => false,
            1 => true,
            _ => anyhow::bail!("stored approval requirement is invalid"),
        };
        ensure!(
            approval_required || self.review_digest.is_none(),
            "automatic transaction unexpectedly has a review digest"
        );
        ensure!(
            self.review_digest.is_none() || self.approved_at.is_some(),
            "stored review digest has no exceptional approval timestamp"
        );
        Ok(PendingTransaction {
            request_id,
            wallet_id: self.wallet_id,
            network_name: self.network_name,
            chain_id: self.chain_id,
            execution_plan,
            digest: self.digest,
            review_digest: self.review_digest,
            policy_revision,
            approval_required,
            status: PendingStatus::parse(&self.status)?,
            created_at: parse_time(&self.created_at)?,
            expires_at: parse_time(&self.expires_at)?,
            updated_at: parse_time(&self.updated_at)?,
            approved_at: self.approved_at.as_deref().map(parse_time).transpose()?,
            rejected_at: self.rejected_at.as_deref().map(parse_time).transpose()?,
            serialized_transaction: self.serialized_transaction,
            signed_transaction_hash: self.signed_transaction_hash,
            broadcast_transaction_hash: self.broadcast_transaction_hash,
            block_number: self.block_number,
        })
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .context("stored timestamp is invalid")?
        .with_timezone(&Utc))
}

fn validate_hex(value: &str, expected_bytes: Option<usize>) -> Result<()> {
    let encoded = value
        .strip_prefix("0x")
        .context("hex value must start with 0x")?;
    ensure!(
        !encoded.is_empty()
            && encoded.len().is_multiple_of(2)
            && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid hexadecimal value"
    );
    if let Some(expected_bytes) = expected_bytes {
        ensure!(
            encoded.len() == expected_bytes * 2,
            "hex value must contain {expected_bytes} bytes"
        );
        B256::from_str(value).context("invalid 32-byte hash")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core::policy::WalletPolicy, policy_store::DatabaseKey};
    use serde_json::json;

    fn plan() -> ExecutionPlan {
        plan_with_value("1")
    }

    fn plan_with_value(value: &str) -> ExecutionPlan {
        ExecutionPlan::parse(json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "submit_condition": "always",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0x",
                    "value": value
                }
            }]
        }))
        .unwrap()
    }

    fn store() -> (tempfile::TempDir, PendingStore) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policies.db");
        let mut database = PolicyStore::open(&path, &DatabaseKey::new([9; 32])).unwrap();
        database
            .put("primary", &WalletPolicy::allow_all_with_approval(), None)
            .unwrap();
        (directory, PendingStore::new(database))
    }

    #[test]
    fn persists_exact_plan_and_lifecycle_without_spend_state() {
        let (_directory, mut store) = store();
        let request = store.create("primary", "ethereum", &plan(), 1, 60).unwrap();
        assert_eq!(request.status, PendingStatus::AwaitingApproval);
        let hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let signed = store
            .store_signed(
                request.request_id,
                &request.digest,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0x0102",
                hash,
            )
            .unwrap();
        assert_eq!(signed.status, PendingStatus::Signed);
        assert_eq!(
            store
                .claim_for_submission(request.request_id)
                .unwrap()
                .status,
            PendingStatus::Submitting
        );
        assert_eq!(
            store
                .mark_broadcast(request.request_id, hash)
                .unwrap()
                .status,
            PendingStatus::Broadcast
        );
        assert_eq!(
            store
                .finalize(request.request_id, true, "123")
                .unwrap()
                .status,
            PendingStatus::Confirmed
        );
    }

    #[test]
    fn automatic_signatures_are_recorded_but_never_enter_approval_queue() {
        let (_directory, mut store) = store();
        let hash = "0x3333333333333333333333333333333333333333333333333333333333333333";
        let signed = store
            .record_automatic_signed("primary", "ethereum", &plan(), 1, "0x0102", hash)
            .unwrap();
        assert_eq!(signed.status, PendingStatus::Signed);
        assert!(!signed.approval_required);
        assert!(signed.approved_at.is_none());
        assert!(store.awaiting_approval(None).unwrap().is_empty());
        assert_eq!(
            store.list(Some("primary"), 10).unwrap(),
            std::slice::from_ref(&signed)
        );
        assert_eq!(store.get_by_identifier(hash).unwrap(), signed);
    }

    #[test]
    fn only_one_signed_transaction_can_be_in_flight_per_wallet_and_chain() {
        let (_directory, mut store) = store();
        let first_hash = "0x3333333333333333333333333333333333333333333333333333333333333333";
        let second_hash = "0x5555555555555555555555555555555555555555555555555555555555555555";
        let first = store
            .record_automatic_signed("primary", "ethereum", &plan(), 1, "0x0102", first_hash)
            .unwrap();
        assert!(
            store
                .record_automatic_signed("primary", "ethereum", &plan(), 1, "0x0304", second_hash,)
                .is_err()
        );

        store.claim_for_submission(first.request_id).unwrap();
        store.mark_broadcast(first.request_id, first_hash).unwrap();
        store.finalize(first.request_id, true, "123").unwrap();
        assert!(
            store
                .record_automatic_signed("primary", "ethereum", &plan(), 1, "0x0304", second_hash,)
                .is_ok()
        );
    }

    #[test]
    fn ambiguous_broadcast_can_only_reclaim_the_same_signed_bytes() {
        let (_directory, mut store) = store();
        let hash = "0x4444444444444444444444444444444444444444444444444444444444444444";
        let signed = store
            .record_automatic_signed("primary", "ethereum", &plan(), 1, "0x0102", hash)
            .unwrap();
        store.claim_for_submission(signed.request_id).unwrap();
        store.mark_broadcast(signed.request_id, hash).unwrap();

        let current = store.database.get("primary").unwrap().unwrap();
        store
            .database
            .put("primary", &current.policy, Some(current.revision))
            .unwrap();
        let reclaimed = store.claim_broadcast_retry(signed.request_id).unwrap();
        assert_eq!(reclaimed.status, PendingStatus::Submitting);
        assert_eq!(reclaimed.serialized_transaction.as_deref(), Some("0x0102"));
        assert_eq!(reclaimed.signed_transaction_hash.as_deref(), Some(hash));
        assert!(store.claim_broadcast_retry(signed.request_id).is_err());
    }

    #[test]
    fn policy_change_cancels_signed_transaction_before_submission() {
        let (_directory, mut store) = store();
        let request = store.create("primary", "ethereum", &plan(), 1, 60).unwrap();
        let hash = "0x2222222222222222222222222222222222222222222222222222222222222222";
        store
            .store_signed(
                request.request_id,
                &request.digest,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0x0102",
                hash,
            )
            .unwrap();
        let current = store.database.get("primary").unwrap().unwrap();
        store
            .database
            .put("primary", &current.policy, Some(current.revision))
            .unwrap();
        assert_eq!(
            store.get(request.request_id).unwrap().status,
            PendingStatus::Cancelled
        );
        assert!(store.claim_for_submission(request.request_id).is_err());
        assert!(
            store
                .record_automatic_signed("primary", "ethereum", &plan(), 2, "0x0304", hash)
                .is_ok()
        );
    }

    #[test]
    fn policy_change_preserves_a_claimed_submission_for_hash_reconciliation() {
        let (_directory, mut store) = store();
        let hash = "0x6666666666666666666666666666666666666666666666666666666666666666";
        let signed = store
            .record_automatic_signed("primary", "ethereum", &plan(), 1, "0x0102", hash)
            .unwrap();
        store.claim_for_submission(signed.request_id).unwrap();

        let current = store.database.get("primary").unwrap().unwrap();
        store
            .database
            .put("primary", &current.policy, Some(current.revision))
            .unwrap();
        assert_eq!(
            store.get(signed.request_id).unwrap().status,
            PendingStatus::Submitting
        );
    }

    #[test]
    fn rejection_is_terminal() {
        let (_directory, mut store) = store();
        let request = store.create("primary", "ethereum", &plan(), 1, 60).unwrap();
        assert_eq!(
            store.reject(request.request_id).unwrap().status,
            PendingStatus::Rejected
        );
        assert!(store.reject(request.request_id).is_err());
    }

    #[test]
    fn duplicate_pending_plan_reuses_request_and_queue_is_bounded() {
        let (_directory, mut store) = store();
        let first = store.create("primary", "ethereum", &plan(), 1, 60).unwrap();
        let duplicate = store.create("primary", "ethereum", &plan(), 1, 60).unwrap();
        assert_eq!(duplicate.request_id, first.request_id);

        for value in 2..=MAX_AWAITING_APPROVALS_PER_WALLET {
            store
                .create(
                    "primary",
                    "ethereum",
                    &plan_with_value(&value.to_string()),
                    1,
                    60,
                )
                .unwrap();
        }
        assert!(
            store
                .create(
                    "primary",
                    "ethereum",
                    &plan_with_value(&(MAX_AWAITING_APPROVALS_PER_WALLET + 1).to_string()),
                    1,
                    60,
                )
                .is_err()
        );
    }

    #[test]
    fn policy_change_replaces_stale_duplicate_approval_request() {
        let (_directory, mut store) = store();
        let stale = store.create("primary", "ethereum", &plan(), 1, 60).unwrap();
        let current = store.database.get("primary").unwrap().unwrap();
        store
            .database
            .put("primary", &current.policy, Some(current.revision))
            .unwrap();

        assert_eq!(
            store.get(stale.request_id).unwrap().status,
            PendingStatus::Cancelled
        );
        let replacement = store.create("primary", "ethereum", &plan(), 2, 60).unwrap();
        assert_ne!(replacement.request_id, stale.request_id);
        assert_eq!(replacement.policy_revision, 2);
    }

    #[test]
    fn wallet_state_removal_cancels_pending_requests() {
        let (_directory, mut store) = store();
        let request = store.create("primary", "ethereum", &plan(), 1, 60).unwrap();
        store.database.delete("primary", 1).unwrap();
        assert_eq!(
            store.get(request.request_id).unwrap().status,
            PendingStatus::Cancelled
        );
    }
}
