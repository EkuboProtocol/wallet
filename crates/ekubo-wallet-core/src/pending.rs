//! Encrypted pending approval and transaction lifecycle persistence.
//!
//! These records bind exact plans and signed bytes. They are not spending
//! counters, policy reservations, or rolling-limit state.

use crate::{
    config::validate_wallet_id, core::execution_plan::ExecutionPlan, policy_store::PolicyStore,
    rpc::MinedFee,
};
use alloy::primitives::B256;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
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
    Cancelled,
    /// The envelope's nonce was consumed on chain by a different transaction
    /// (for example one sent from the same key imported on another device),
    /// so these exact signed bytes can never mine.
    Replaced,
    /// An owner-requested 0-value self-send is racing the broadcast envelope
    /// at its own nonce. The record still holds the wallet+chain in-flight
    /// slot: the pair is one logical transaction until the chain settles the
    /// race as `Cancelled`, `Confirmed`/`Reverted`, or `Replaced`.
    Cancelling,
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
            "cancelled" => Ok(Self::Cancelled),
            "replaced" => Ok(Self::Replaced),
            "cancelling" => Ok(Self::Cancelling),
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
    /// Where the plan's bytes came from — the TLS-vetted https host that
    /// served them or "inline data URI" — shown as an approval fact. None for
    /// plans this process built itself (transfers, CLI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_source: Option<String>,
    pub digest: String,
    /// Digest of exact nonce, gas, fee, call, and delegation fields reviewed
    /// for an exceptional approval. Automatic transactions do not have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_digest: Option<String>,
    pub policy_revision: u64,
    pub approval_required: bool,
    pub status: PendingStatus,
    pub created_at: DateTime<Utc>,
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
    /// What the mined transaction actually cost, taken from its receipt at
    /// settlement. Absent while unsettled, on records that never mined, and on
    /// rows settled before this was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mined_fee: Option<MinedFee>,
    /// The exact bytes of the newest owner-requested cancellation envelope: a
    /// 0-value self-send at the original envelope's nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_serialized_transaction: Option<String>,
    /// Every cancellation hash ever broadcast for this record, oldest first.
    /// Earlier attempts may still mine after a repricing, so reconciliation
    /// recognizes all of them as "cancelled by this wallet".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cancel_transaction_hashes: Vec<String>,
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
        plan_source: Option<&str>,
        policy_revision: u64,
    ) -> Result<PendingTransaction> {
        validate_plan_source(plan_source)?;
        validate_wallet_id(wallet_id)?;
        ensure!(
            !network_name.trim().is_empty(),
            "network name cannot be empty"
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
        let plan_json = serde_json::to_string(plan)?;
        transaction.execute(
            "INSERT INTO pending_transactions(
                request_id, wallet_id, network_name, chain_id, plan_json,
                plan_digest, plan_source, policy_revision, status, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'awaiting_approval', ?9, ?9)",
            params![
                request_id.to_string(),
                wallet_id,
                network_name,
                plan.chain_id.as_str(),
                plan_json,
                digest,
                plan_source,
                policy_revision,
                created_at.to_rfc3339(),
            ],
        )?;
        transaction.commit()?;
        self.get(request_id)
    }

    /// Persist an automatically authorized signature before the first RPC
    /// submission. It is recorded in the same lifecycle table but never
    /// appears in the exceptional-approval queue.
    #[allow(clippy::too_many_arguments)]
    pub fn record_automatic_signed(
        &mut self,
        wallet_id: &str,
        network_name: &str,
        plan: &ExecutionPlan,
        plan_source: Option<&str>,
        policy_revision: u64,
        serialized_transaction: &str,
        transaction_hash: &str,
    ) -> Result<PendingTransaction> {
        validate_plan_source(plan_source)?;
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
                plan_digest, plan_source, policy_revision, status, created_at, updated_at,
                serialized_transaction, signed_transaction_hash, approval_required
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'signed', ?9, ?9, ?10, ?11, 0)",
                params![
                    request_id.to_string(),
                    wallet_id,
                    network_name,
                    plan.chain_id.as_str(),
                    serde_json::to_string(plan)?,
                    format!("{:#x}", plan.digest()),
                    plan_source,
                    policy_revision,
                    created_at.to_rfc3339(),
                    serialized_transaction,
                    transaction_hash,
                ],
            )
            .with_context(|| in_flight_conflict(&transaction, wallet_id, plan.chain_id.as_str()))?;
        transaction.commit()?;
        self.get(request_id)
    }

    /// The one record occupying this wallet and chain's in-flight slot, if
    /// any: the unique index allows at most one row in a signed, submitting,
    /// broadcast, or cancelling state. Senders reconcile this record against
    /// the chain before creating a new signature, so a predecessor that
    /// already mined (or was replaced) never blocks the next transaction.
    pub fn in_flight(&self, wallet_id: &str, chain_id: &str) -> Result<Option<PendingTransaction>> {
        validate_wallet_id(wallet_id)?;
        let request_id: Option<String> = self
            .database
            .connection
            .query_row(
                "SELECT request_id FROM pending_transactions
                 WHERE wallet_id = ?1 AND chain_id = ?2
                   AND status IN ('signed', 'submitting', 'broadcast', 'cancelling')",
                params![wallet_id, chain_id],
                |row| row.get(0),
            )
            .optional()?;
        request_id
            .map(|value| self.get(Uuid::parse_str(&value).context("stored request ID is invalid")?))
            .transpose()
    }

    /// Discard a signed envelope that was never submitted: the bytes exist
    /// nowhere but this database, so marking the record cancelled is honest
    /// and frees the wallet+chain in-flight slot. Anything that may have
    /// reached the network is refused — cancel that on chain instead.
    pub fn discard_unsent(&mut self, request_id: Uuid) -> Result<PendingTransaction> {
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = 'cancelled', updated_at = ?2
             WHERE request_id = ?1 AND status = 'signed'",
            params![request_id.to_string(), Utc::now().to_rfc3339()],
        )?;
        ensure!(
            changed == 1,
            "only a signed but never-submitted transaction can be discarded locally"
        );
        self.get(request_id)
    }

    pub fn get(&self, request_id: Uuid) -> Result<PendingTransaction> {
        self.read(request_id)
    }

    pub fn reject(&mut self, request_id: Uuid) -> Result<PendingTransaction> {
        let transaction = self.database.connection.transaction()?;
        let (status, approval_required): (String, i64) = transaction
            .query_row(
                "SELECT status, approval_required
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
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
        let (wallet_id, chain_id, digest, policy_revision, status, approval_required): (
            String,
            String,
            String,
            i64,
            String,
            i64,
        ) = transaction
            .query_row(
                "SELECT wallet_id, chain_id, plan_digest, policy_revision, status,
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
            .with_context(|| in_flight_conflict(&transaction, &wallet_id, &chain_id))?;
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

    /// Hand the submission lease back, but only the lease `leased_at` names.
    ///
    /// `status = 'submitting'` is not enough to identify a lease. Recovery
    /// observes a record outside any lock, decides its lease has expired, and
    /// releases it — and between those two moments another process can release
    /// and re-claim the same request, because the CLI and the MCP server share
    /// this database without sharing a lock. The row is still `submitting`, so
    /// the stale release lands on the *new* lease and the live submitter's own
    /// `mark_broadcast` then fails after the RPC already accepted the envelope.
    ///
    /// `claim_for_submission` stamps `updated_at` when it claims, so that value
    /// names one lease. Comparing it makes this a compare-and-set.
    pub fn release_submission(
        &mut self,
        request_id: Uuid,
        leased_at: DateTime<Utc>,
    ) -> Result<PendingTransaction> {
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = 'signed', updated_at = ?2
             WHERE request_id = ?1 AND status = 'submitting' AND updated_at = ?3",
            params![
                request_id.to_string(),
                Utc::now().to_rfc3339(),
                leased_at.to_rfc3339()
            ],
        )?;
        ensure!(
            changed == 1,
            "the submission lease was reclaimed while it was being released"
        );
        self.get(request_id)
    }

    /// Record that the lease `leased_at` names put this envelope on the wire.
    ///
    /// Leased for the same reason as `release_submission`: the hash guard
    /// cannot tell two leases apart, because a rebroadcast is the same bytes
    /// under the same hash. Without it, a reconciliation acting on an
    /// observation it made outside the lock could mark broadcast a lease
    /// another process now holds, and that holder's own call then fails after
    /// the RPC has already accepted the envelope.
    pub fn mark_broadcast(
        &mut self,
        request_id: Uuid,
        transaction_hash: &str,
        leased_at: DateTime<Utc>,
    ) -> Result<PendingTransaction> {
        validate_hex(transaction_hash, Some(32))?;
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET
                status = 'broadcast', broadcast_transaction_hash = ?2, updated_at = ?3
             WHERE request_id = ?1 AND status = 'submitting'
               AND signed_transaction_hash = ?2 AND updated_at = ?4",
            params![
                request_id.to_string(),
                transaction_hash,
                Utc::now().to_rfc3339(),
                leased_at.to_rfc3339()
            ],
        )?;
        ensure!(
            changed == 1,
            "broadcast hash or transaction state mismatch, or the submission lease was reclaimed"
        );
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

    /// Record one broadcast owner-requested cancellation attempt: the exact
    /// bytes and hash of a 0-value self-send racing the stuck envelope at its
    /// own nonce. Repricing appends to the hash history — an earlier attempt
    /// may still mine — while only the newest bytes stay rebroadcastable. The
    /// record keeps its in-flight slot; the pair is one logical transaction.
    /// Record a cancellation envelope, replacing the incumbent it was priced
    /// against.
    ///
    /// `priced_against` is the newest cancellation hash the caller saw when it
    /// computed this envelope's fees, or `None` if there was none. It has to
    /// still be the newest, because a replacement is only a replacement of the
    /// thing it outbid: the MCP server and the CLI share this database but not
    /// a lock, so two processes can both bump over generation N, and whichever
    /// writes second would install its lower-priced envelope as the newest.
    /// The next reprice then bumps from that demoted baseline, and the
    /// cancellation the owner is trying to push through loses to the original.
    pub fn store_cancellation(
        &mut self,
        request_id: Uuid,
        priced_against: Option<&str>,
        cancel_serialized_transaction: &str,
        cancel_transaction_hash: &str,
    ) -> Result<PendingTransaction> {
        validate_hex(cancel_serialized_transaction, None)?;
        validate_hex(cancel_transaction_hash, Some(32))?;
        let transaction = self.database.connection.transaction()?;
        let (status, hashes): (String, Option<String>) = transaction
            .query_row(
                "SELECT status, cancel_transaction_hashes
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .with_context(|| format!("unknown pending request {request_id}"))?;
        ensure!(
            matches!(
                PendingStatus::parse(&status)?,
                PendingStatus::Broadcast | PendingStatus::Cancelling
            ),
            "pending transaction is not awaiting a receipt"
        );
        let mut hashes = hashes
            .as_deref()
            .map(parse_cancel_hashes)
            .transpose()?
            .unwrap_or_default();
        ensure!(
            hashes.last().map(String::as_str) == priced_against,
            "another cancellation was recorded while this one was being priced; \
             re-read the request and reprice against the newest envelope"
        );
        ensure!(
            !hashes.contains(&cancel_transaction_hash.to_owned()),
            "this exact cancellation was already recorded"
        );
        ensure!(
            hashes.len() < MAX_CANCELLATION_ATTEMPTS,
            "too many cancellation attempts for this transaction"
        );
        hashes.push(cancel_transaction_hash.to_owned());
        transaction.execute(
            "UPDATE pending_transactions SET
                status = 'cancelling', cancel_serialized_transaction = ?2,
                cancel_transaction_hashes = ?3, updated_at = ?4
             WHERE request_id = ?1 AND status IN ('broadcast', 'cancelling')",
            params![
                request_id.to_string(),
                cancel_serialized_transaction,
                serde_json::to_string(&hashes).expect("hash list serializes"),
                Utc::now().to_rfc3339(),
            ],
        )?;
        transaction.commit()?;
        self.get(request_id)
    }

    /// Record that one of this wallet's own cancellation envelopes consumed
    /// the nonce: the original plan will never execute. A reverted
    /// cancellation still cancels — the nonce is consumed either way.
    pub fn mark_cancelled(
        &mut self,
        request_id: Uuid,
        block_number: &str,
        fee: Option<&MinedFee>,
    ) -> Result<PendingTransaction> {
        validate_block_number(block_number)?;
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET
                status = 'cancelled', block_number = ?2, updated_at = ?3,
                gas_used = ?4, effective_gas_price = ?5
             WHERE request_id = ?1 AND status = 'cancelling'",
            params![
                request_id.to_string(),
                block_number,
                Utc::now().to_rfc3339(),
                fee.map(|fee| fee.gas_used.as_str()),
                fee.map(|fee| fee.effective_gas_price.as_str()),
            ],
        )?;
        ensure!(changed == 1, "pending transaction is not being cancelled");
        self.get(request_id)
    }

    /// Record that this envelope's nonce was consumed by a different mined
    /// transaction: the exact signed bytes can never mine, so the record
    /// leaves the in-flight slot without ever getting a receipt. Callers must
    /// have verified against the chain that the mined account nonce passed the
    /// envelope's nonce while no receipt exists for its hash.
    pub fn mark_replaced(&mut self, request_id: Uuid) -> Result<PendingTransaction> {
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = 'replaced', updated_at = ?2
             WHERE request_id = ?1 AND status IN ('submitting', 'broadcast', 'cancelling')",
            params![request_id.to_string(), Utc::now().to_rfc3339()],
        )?;
        ensure!(changed == 1, "pending transaction is not in flight");
        self.get(request_id)
    }

    /// Record the original envelope's mined receipt. Also reachable from
    /// `cancelling`: the original winning the race against its own
    /// cancellation is still simply the original executing.
    pub fn finalize(
        &mut self,
        request_id: Uuid,
        succeeded: bool,
        block_number: &str,
        fee: Option<&MinedFee>,
    ) -> Result<PendingTransaction> {
        validate_block_number(block_number)?;
        let status = if succeeded { "confirmed" } else { "reverted" };
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = ?2, block_number = ?3, updated_at = ?4,
                gas_used = ?5, effective_gas_price = ?6
             WHERE request_id = ?1 AND status IN ('broadcast', 'cancelling')",
            params![
                request_id.to_string(),
                status,
                block_number,
                Utc::now().to_rfc3339(),
                fee.map(|fee| fee.gas_used.as_str()),
                fee.map(|fee| fee.effective_gas_price.as_str()),
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
                        policy_revision, status, created_at, updated_at,
                        approved_at, rejected_at, serialized_transaction,
                        signed_transaction_hash, broadcast_transaction_hash, block_number,
                        approval_required, review_digest, cancel_serialized_transaction,
                        cancel_transaction_hashes, gas_used, effective_gas_price, plan_source
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
                        updated_at: row.get(8)?,
                        approved_at: row.get(9)?,
                        rejected_at: row.get(10)?,
                        serialized_transaction: row.get(11)?,
                        signed_transaction_hash: row.get(12)?,
                        broadcast_transaction_hash: row.get(13)?,
                        block_number: row.get(14)?,
                        approval_required: row.get(15)?,
                        review_digest: row.get(16)?,
                        cancel_serialized_transaction: row.get(17)?,
                        cancel_transaction_hashes: row.get(18)?,
                        gas_used: row.get(19)?,
                        effective_gas_price: row.get(20)?,
                        plan_source: row.get(21)?,
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
    updated_at: String,
    approved_at: Option<String>,
    rejected_at: Option<String>,
    serialized_transaction: Option<String>,
    signed_transaction_hash: Option<String>,
    broadcast_transaction_hash: Option<String>,
    block_number: Option<String>,
    approval_required: i64,
    review_digest: Option<String>,
    cancel_serialized_transaction: Option<String>,
    cancel_transaction_hashes: Option<String>,
    gas_used: Option<String>,
    effective_gas_price: Option<String>,
    plan_source: Option<String>,
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
        validate_plan_source(self.plan_source.as_deref())?;
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
        // The pair has to agree, not merely both be present. Reconciliation
        // decodes these bytes to recover the envelope's nonce, and a row whose
        // bytes do not decode makes that fail — while the row keeps the one
        // in-flight slot its wallet and chain are allowed. `reconcile_all`
        // swallows the error to keep a listing rendering, so the slot is held
        // for good and no further transaction can be signed for that wallet on
        // that chain. Refusing the row here turns a permanent wedge into a
        // read that fails loudly and names the request.
        if let (Some(serialized), Some(hash)) =
            (&self.serialized_transaction, &self.signed_transaction_hash)
        {
            let bytes = hex::decode(serialized.trim_start_matches("0x"))
                .context("stored signed transaction is not hexadecimal")?;
            ensure!(
                format!("{:#x}", alloy::primitives::keccak256(&bytes)) == *hash,
                "stored signed transaction does not hash to its recorded hash"
            );
        }
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
        if let Some(bytes) = &self.cancel_serialized_transaction {
            validate_hex(bytes, None)?;
        }
        let cancel_transaction_hashes = self
            .cancel_transaction_hashes
            .as_deref()
            .map(parse_cancel_hashes)
            .transpose()?
            .unwrap_or_default();
        ensure!(
            self.cancel_serialized_transaction.is_some() != cancel_transaction_hashes.is_empty(),
            "stored cancellation is incomplete"
        );
        ensure!(
            self.cancel_serialized_transaction.is_none() || self.serialized_transaction.is_some(),
            "stored cancellation has no original signed transaction"
        );
        ensure!(
            self.status != "cancelling" || self.cancel_serialized_transaction.is_some(),
            "cancelling transaction has no cancellation envelope"
        );
        // Both columns are written together at settlement, so either both are
        // present or the row predates fee recording.
        let mined_fee = match (&self.gas_used, &self.effective_gas_price) {
            (Some(gas_used), Some(price)) => Some(mined_fee(gas_used, price)?),
            (None, None) => None,
            _ => anyhow::bail!("stored transaction fee is incomplete"),
        };
        Ok(PendingTransaction {
            request_id,
            wallet_id: self.wallet_id,
            network_name: self.network_name,
            chain_id: self.chain_id,
            execution_plan,
            plan_source: self.plan_source,
            digest: self.digest,
            review_digest: self.review_digest,
            policy_revision,
            approval_required,
            status: PendingStatus::parse(&self.status)?,
            created_at: parse_time(&self.created_at)?,
            updated_at: parse_time(&self.updated_at)?,
            approved_at: self.approved_at.as_deref().map(parse_time).transpose()?,
            rejected_at: self.rejected_at.as_deref().map(parse_time).transpose()?,
            serialized_transaction: self.serialized_transaction,
            signed_transaction_hash: self.signed_transaction_hash,
            broadcast_transaction_hash: self.broadcast_transaction_hash,
            block_number: self.block_number,
            mined_fee,
            cancel_serialized_transaction: self.cancel_serialized_transaction,
            cancel_transaction_hashes,
        })
    }
}

/// Distinct cancellation envelopes one record may accumulate.
///
/// Every one of them can still mine, so reconciliation has to recognize all of
/// them and the list is stored forever. Eight is generous for a fee war and
/// small enough that the history stays readable. Reaching it does not end the
/// attempt: [`crate::reconcile::attempt_cancellation`] falls back to
/// rebroadcasting the newest stored envelope, which adds no hash.
pub const MAX_CANCELLATION_ATTEMPTS: usize = 8;

/// A stored plan source must be exactly what the fetch layer produces — the
/// literal "inline data URI" or a lowercase vetted hostname — so a tampered
/// database cannot inject terminal escapes or misleading text into the
/// approval screen.
fn validate_plan_source(value: Option<&str>) -> Result<()> {
    let Some(value) = value else { return Ok(()) };
    ensure!(value.len() <= 255, "stored plan source exceeds 255 bytes");
    ensure!(
        value == "inline data URI"
            || (!value.is_empty()
                && value.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'.'
                    || byte == b'-'
                    || byte == b':')),
        "stored plan source is not a vetted host name"
    );
    Ok(())
}

fn parse_cancel_hashes(value: &str) -> Result<Vec<String>> {
    let hashes: Vec<String> =
        serde_json::from_str(value).context("stored cancellation hashes are invalid JSON")?;
    ensure!(
        !hashes.is_empty() && hashes.len() <= MAX_CANCELLATION_ATTEMPTS,
        "stored cancellation hash list has an invalid length"
    );
    for hash in &hashes {
        validate_hex(hash, Some(32))?;
    }
    Ok(hashes)
}

fn validate_block_number(block_number: &str) -> Result<()> {
    ensure!(
        block_number == "0"
            || (!block_number.starts_with('0')
                && block_number.bytes().all(|byte| byte.is_ascii_digit())),
        "block number must be canonical decimal"
    );
    Ok(())
}

/// Explain an in-flight slot conflict by naming the record that holds it.
///
/// The unique index reports only that a conflict happened, and every tool that
/// could resolve one — status, wait, cancel — is keyed by `request_id`. A
/// caller whose earlier send was interrupted after signing never received that
/// ID, so without it here the slot is unrecoverable through this server and
/// every later send on the wallet and chain keeps failing. Naming the blocker
/// discloses nothing the caller could not already read for its own wallet.
fn in_flight_conflict(
    transaction: &rusqlite::Transaction<'_>,
    wallet_id: &str,
    chain_id: &str,
) -> String {
    let blocker: Option<(String, String)> = transaction
        .query_row(
            "SELECT request_id, status FROM pending_transactions
             WHERE wallet_id = ?1 AND chain_id = ?2
               AND status IN ('signed', 'submitting', 'broadcast', 'cancelling')",
            params![wallet_id, chain_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .ok()
        .flatten();
    let resolution = blocker.map_or_else(
        || {
            "reconcile it with wallet_get_execution_status, wait for it with \
            wallet_wait_for_execution, or cancel it with wallet_attempt_cancel"
                .to_owned()
        },
        |(blocking_request_id, status)| {
            format!(
                "request {blocking_request_id} is {status}. Reconcile it with \
                 wallet_get_execution_status, wait for it with wallet_wait_for_execution, \
                 or cancel it with wallet_attempt_cancel, passing that request_id"
            )
        },
    );
    format!("another transaction is already in flight for this wallet and chain: {resolution}")
}

/// Rebuild a stored fee, recomputing the product rather than persisting it so
/// the reported total can never disagree with its own components.
fn mined_fee(gas_used: &str, effective_gas_price: &str) -> Result<MinedFee> {
    let gas: u128 = gas_used.parse().context("stored gas usage is invalid")?;
    let price: u128 = effective_gas_price
        .parse()
        .context("stored effective gas price is invalid")?;
    Ok(MinedFee {
        gas_used: gas.to_string(),
        effective_gas_price: price.to_string(),
        transaction_fee_wei: gas.saturating_mul(price).to_string(),
    })
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
        let request = store
            .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
            .unwrap();
        assert_eq!(request.status, PendingStatus::AwaitingApproval);
        let hash = hash_of(ORIGINAL_BYTES);
        let hash = hash.as_str();
        let signed = store
            .store_signed(
                request.request_id,
                &request.digest,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ORIGINAL_BYTES,
                hash,
            )
            .unwrap();
        assert_eq!(signed.status, PendingStatus::Signed);
        let claimed = store.claim_for_submission(request.request_id).unwrap();
        assert_eq!(claimed.status, PendingStatus::Submitting);
        assert_eq!(
            store
                .mark_broadcast(request.request_id, hash, claimed.updated_at)
                .unwrap()
                .status,
            PendingStatus::Broadcast
        );
        assert_eq!(
            store
                .finalize(request.request_id, true, "123", None)
                .unwrap()
                .status,
            PendingStatus::Confirmed
        );
    }

    #[test]
    fn automatic_signatures_are_recorded_but_never_enter_approval_queue() {
        let (_directory, mut store) = store();
        let hash = hash_of(ORIGINAL_BYTES);
        let hash = hash.as_str();
        let signed = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash,
            )
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
        let first_hash = hash_of(ORIGINAL_BYTES);
        let first_hash = first_hash.as_str();
        let second_hash = hash_of(CANCEL_BYTES_ONE);
        let second_hash = second_hash.as_str();
        let first = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                first_hash,
            )
            .unwrap();
        assert!(
            store
                .record_automatic_signed(
                    "primary",
                    "ethereum",
                    &plan(),
                    None,
                    1,
                    CANCEL_BYTES_ONE,
                    second_hash,
                )
                .is_err()
        );

        let leased = store.claim_for_submission(first.request_id).unwrap();
        store
            .mark_broadcast(first.request_id, first_hash, leased.updated_at)
            .unwrap();
        store.finalize(first.request_id, true, "123", None).unwrap();
        assert!(
            store
                .record_automatic_signed(
                    "primary",
                    "ethereum",
                    &plan(),
                    None,
                    1,
                    CANCEL_BYTES_ONE,
                    second_hash,
                )
                .is_ok()
        );
    }

    /// A send interrupted after signing leaves the caller without the
    /// `request_id`, and every tool that could clear the slot needs one. The
    /// rejection has to hand it back or the wallet is stuck on that chain.
    #[test]
    fn the_in_flight_rejection_names_the_request_holding_the_slot() {
        let (_directory, mut store) = store();
        let blocker = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash_of(ORIGINAL_BYTES).as_str(),
            )
            .unwrap();
        let error = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                CANCEL_BYTES_ONE,
                hash_of(CANCEL_BYTES_ONE).as_str(),
            )
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains(&blocker.request_id.to_string()),
            "rejection must name the blocking request: {message}"
        );
        assert!(message.contains("signed"), "{message}");
        assert!(message.contains("wallet_attempt_cancel"), "{message}");
    }

    /// The receipt is the only place the price paid exists, so settlement has
    /// to capture it: a caller pricing gas from its own history reads this
    /// rather than reconstructing it from balance deltas.
    #[test]
    fn a_stale_observer_cannot_release_a_lease_that_was_reclaimed() {
        let (_directory, mut store) = store();
        let hash = hash_of(ORIGINAL_BYTES);
        let hash = hash.as_str();
        let signed = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash,
            )
            .unwrap();

        // What reconciliation observes, outside any lock.
        let observed = store.claim_for_submission(signed.request_id).unwrap();

        // What happens in the meantime: the lease is released and taken again
        // by someone else. The row is `submitting` either way, so status alone
        // cannot tell the two leases apart.
        store
            .release_submission(signed.request_id, observed.updated_at)
            .unwrap();
        let live = store.claim_for_submission(signed.request_id).unwrap();
        assert_ne!(live.updated_at, observed.updated_at);

        // The stale release must not land on the live lease, and must not
        // steal the broadcast either.
        assert!(
            store
                .release_submission(signed.request_id, observed.updated_at)
                .is_err()
        );
        assert!(
            store
                .mark_broadcast(signed.request_id, hash, observed.updated_at)
                .is_err()
        );
        assert_eq!(
            store.get(signed.request_id).unwrap().status,
            PendingStatus::Submitting
        );

        // The holder of the live lease still gets its envelope on the wire.
        assert_eq!(
            store
                .mark_broadcast(signed.request_id, hash, live.updated_at)
                .unwrap()
                .status,
            PendingStatus::Broadcast
        );
    }

    #[test]
    fn settlement_records_what_the_transaction_actually_cost() {
        let (_directory, mut store) = store();
        let hash = hash_of(ORIGINAL_BYTES);
        let hash = hash.as_str();
        let signed = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash,
            )
            .unwrap();
        assert!(signed.mined_fee.is_none());
        let leased = store.claim_for_submission(signed.request_id).unwrap();
        store
            .mark_broadcast(signed.request_id, hash, leased.updated_at)
            .unwrap();
        let fee = MinedFee {
            gas_used: "447730".into(),
            effective_gas_price: "320000000".into(),
            transaction_fee_wei: "143273600000000".into(),
        };
        let settled = store
            .finalize(signed.request_id, true, "123", Some(&fee))
            .unwrap();
        assert_eq!(settled.mined_fee.as_ref(), Some(&fee));
        // Survives a reload: the fee is persisted, not just returned.
        assert_eq!(store.get(signed.request_id).unwrap().mined_fee, Some(fee));
    }

    #[test]
    fn ambiguous_broadcast_can_only_reclaim_the_same_signed_bytes() {
        let (_directory, mut store) = store();
        let hash = hash_of(ORIGINAL_BYTES);
        let hash = hash.as_str();
        let signed = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash,
            )
            .unwrap();
        let leased = store.claim_for_submission(signed.request_id).unwrap();
        store
            .mark_broadcast(signed.request_id, hash, leased.updated_at)
            .unwrap();

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
    fn replacement_is_terminal_and_frees_the_in_flight_slot() {
        let (_directory, mut store) = store();
        let first_hash = hash_of(ORIGINAL_BYTES);
        let first_hash = first_hash.as_str();
        let second_hash = hash_of(CANCEL_BYTES_ONE);
        let second_hash = second_hash.as_str();
        let first = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                first_hash,
            )
            .unwrap();

        // Not yet in flight: a signed-but-never-submitted envelope cannot have
        // been replaced on chain.
        assert!(store.mark_replaced(first.request_id).is_err());

        let leased = store.claim_for_submission(first.request_id).unwrap();
        store
            .mark_broadcast(first.request_id, first_hash, leased.updated_at)
            .unwrap();
        let replaced = store.mark_replaced(first.request_id).unwrap();
        assert_eq!(replaced.status, PendingStatus::Replaced);

        // Terminal: no rebroadcast, no receipt, no second replacement.
        assert!(store.claim_broadcast_retry(first.request_id).is_err());
        assert!(store.finalize(first.request_id, true, "123", None).is_err());
        assert!(store.mark_replaced(first.request_id).is_err());

        // The wallet+chain in-flight slot is free for the next transaction.
        assert!(
            store
                .record_automatic_signed(
                    "primary",
                    "ethereum",
                    &plan(),
                    None,
                    1,
                    CANCEL_BYTES_ONE,
                    second_hash,
                )
                .is_ok()
        );
    }

    /// The hash of some serialized bytes, as the store now requires the pair
    /// to agree. Hard-coded constants would have to be recomputed by hand
    /// every time a fixture's bytes change, and a fixture whose hash does not
    /// match its bytes is a fixture that cannot occur in production.
    fn hash_of(serialized: &str) -> String {
        let bytes = hex::decode(serialized.trim_start_matches("0x")).expect("fixture hex");
        format!("{:#x}", alloy::primitives::keccak256(bytes))
    }

    const ORIGINAL_BYTES: &str = "0x0102";
    const CANCEL_BYTES_ONE: &str = "0x0304";
    const CANCEL_BYTES_TWO: &str = "0x0506";
    const CANCEL_BYTES_THREE: &str = "0x0708";

    fn broadcast_original(store: &mut PendingStore) -> Uuid {
        let signed = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash_of(ORIGINAL_BYTES).as_str(),
            )
            .unwrap();
        let leased = store.claim_for_submission(signed.request_id).unwrap();
        store
            .mark_broadcast(
                signed.request_id,
                hash_of(ORIGINAL_BYTES).as_str(),
                leased.updated_at,
            )
            .unwrap();
        signed.request_id
    }

    #[test]
    fn cancellation_reprices_on_one_row_until_an_attempt_mines() {
        let (_directory, mut store) = store();

        // A cancellation may only race an envelope that reached the network.
        let signed = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash_of(ORIGINAL_BYTES).as_str(),
            )
            .unwrap();
        assert!(
            store
                .store_cancellation(
                    signed.request_id,
                    None,
                    CANCEL_BYTES_ONE,
                    hash_of(CANCEL_BYTES_ONE).as_str()
                )
                .is_err()
        );
        let leased = store.claim_for_submission(signed.request_id).unwrap();
        store
            .mark_broadcast(
                signed.request_id,
                hash_of(ORIGINAL_BYTES).as_str(),
                leased.updated_at,
            )
            .unwrap();
        let request_id = signed.request_id;

        // Repricing appends to the hash history, keeps only the newest bytes,
        // and refuses duplicates.
        let cancelling = store
            .store_cancellation(
                request_id,
                None,
                CANCEL_BYTES_ONE,
                hash_of(CANCEL_BYTES_ONE).as_str(),
            )
            .unwrap();
        assert_eq!(cancelling.status, PendingStatus::Cancelling);
        assert!(
            store
                .store_cancellation(
                    request_id,
                    Some(hash_of(CANCEL_BYTES_ONE).as_str()),
                    CANCEL_BYTES_ONE,
                    hash_of(CANCEL_BYTES_ONE).as_str()
                )
                .is_err()
        );
        let repriced = store
            .store_cancellation(
                request_id,
                Some(hash_of(CANCEL_BYTES_ONE).as_str()),
                CANCEL_BYTES_TWO,
                hash_of(CANCEL_BYTES_TWO).as_str(),
            )
            .unwrap();
        assert_eq!(
            repriced.cancel_serialized_transaction.as_deref(),
            Some("0x0506")
        );
        assert_eq!(
            repriced.cancel_transaction_hashes,
            [
                hash_of(CANCEL_BYTES_ONE).as_str(),
                hash_of(CANCEL_BYTES_TWO).as_str()
            ]
        );

        // A replacement is a replacement of the thing it outbid. This one was
        // priced against the first hash while the second is already newest, so
        // its fee came from a superseded baseline — storing it would install a
        // cheaper envelope as the newest and the next reprice would bump from
        // there, handing the race back to the transaction being cancelled.
        let stale = store
            .store_cancellation(
                request_id,
                Some(hash_of(CANCEL_BYTES_ONE).as_str()),
                CANCEL_BYTES_THREE,
                "0x3333333333333333333333333333333333333333333333333333333333333333",
            )
            .unwrap_err()
            .to_string();
        assert!(stale.contains("while this one was being priced"), "{stale}");

        let cancelled = store.mark_cancelled(request_id, "123", None).unwrap();
        assert_eq!(cancelled.status, PendingStatus::Cancelled);
        assert_eq!(cancelled.block_number.as_deref(), Some("123"));
        assert!(store.mark_cancelled(request_id, "124", None).is_err());
        assert!(store.finalize(request_id, true, "124", None).is_err());

        // Terminal: the wallet+chain in-flight slot is free again.
        broadcast_original(&mut store);
    }

    #[test]
    fn the_in_flight_slot_is_queryable_and_unsent_signatures_can_be_discarded() {
        let (_directory, mut store) = store();
        assert!(store.in_flight("primary", "1").unwrap().is_none());

        let signed = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash_of(ORIGINAL_BYTES).as_str(),
            )
            .unwrap();
        assert_eq!(
            store
                .in_flight("primary", "1")
                .unwrap()
                .expect("signed row holds the slot")
                .request_id,
            signed.request_id
        );

        // Never broadcast: discarding locally is honest and frees the slot.
        let discarded = store.discard_unsent(signed.request_id).unwrap();
        assert_eq!(discarded.status, PendingStatus::Cancelled);
        assert!(store.in_flight("primary", "1").unwrap().is_none());

        // Anything that may have reached the network is refused.
        let request_id = broadcast_original(&mut store);
        assert!(store.discard_unsent(request_id).is_err());
        assert!(store.in_flight("primary", "1").unwrap().is_some());
    }

    #[test]
    fn original_can_still_win_the_race_against_its_own_cancellation() {
        let (_directory, mut store) = store();
        let request_id = broadcast_original(&mut store);
        store
            .store_cancellation(
                request_id,
                None,
                CANCEL_BYTES_ONE,
                hash_of(CANCEL_BYTES_ONE).as_str(),
            )
            .unwrap();
        assert_eq!(
            store
                .finalize(request_id, true, "123", None)
                .unwrap()
                .status,
            PendingStatus::Confirmed
        );
    }

    #[test]
    fn foreign_replacement_can_win_the_race_against_a_cancellation() {
        // An envelope this wallet never signed consumed the nonce, for
        // example one sent from the same key imported on another device.
        let (_directory, mut store) = store();
        let request_id = broadcast_original(&mut store);
        store
            .store_cancellation(
                request_id,
                None,
                CANCEL_BYTES_ONE,
                hash_of(CANCEL_BYTES_ONE).as_str(),
            )
            .unwrap();
        assert_eq!(
            store.mark_replaced(request_id).unwrap().status,
            PendingStatus::Replaced
        );
    }

    #[test]
    fn policy_change_cancels_signed_transaction_before_submission() {
        let (_directory, mut store) = store();
        let request = store
            .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
            .unwrap();
        let hash = hash_of(ORIGINAL_BYTES);
        let hash = hash.as_str();
        store
            .store_signed(
                request.request_id,
                &request.digest,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ORIGINAL_BYTES,
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
                .record_automatic_signed(
                    "primary",
                    "ethereum",
                    &plan(),
                    None,
                    2,
                    CANCEL_BYTES_ONE,
                    hash_of(CANCEL_BYTES_ONE).as_str(),
                )
                .is_ok()
        );
    }

    #[test]
    fn policy_change_preserves_a_claimed_submission_for_hash_reconciliation() {
        let (_directory, mut store) = store();
        let hash = hash_of(ORIGINAL_BYTES);
        let hash = hash.as_str();
        let signed = store
            .record_automatic_signed(
                "primary",
                "ethereum",
                &plan(),
                None,
                1,
                ORIGINAL_BYTES,
                hash,
            )
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
        let request = store
            .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
            .unwrap();
        assert_eq!(
            store.reject(request.request_id).unwrap().status,
            PendingStatus::Rejected
        );
        assert!(store.reject(request.request_id).is_err());
    }

    #[test]
    fn duplicate_pending_plan_reuses_request_and_queue_is_bounded() {
        let (_directory, mut store) = store();
        let first = store
            .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
            .unwrap();
        // Provenance round-trips: the vetted producer host survives storage
        // so the approval screen can display it.
        assert_eq!(first.plan_source.as_deref(), Some("mcp.ekubo.org"));
        let duplicate = store
            .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
            .unwrap();
        assert_eq!(duplicate.request_id, first.request_id);
        // A source that is neither the inline literal nor a plain host is
        // refused before it can reach a terminal.
        assert!(
            store
                .create(
                    "primary",
                    "ethereum",
                    &plan_with_value("999"),
                    Some("evil\u{1b}[31mhost"),
                    1,
                )
                .is_err()
        );

        for value in 2..=MAX_AWAITING_APPROVALS_PER_WALLET {
            store
                .create(
                    "primary",
                    "ethereum",
                    &plan_with_value(&value.to_string()),
                    None,
                    1,
                )
                .unwrap();
        }
        assert!(
            store
                .create(
                    "primary",
                    "ethereum",
                    &plan_with_value(&(MAX_AWAITING_APPROVALS_PER_WALLET + 1).to_string()),
                    None,
                    1,
                )
                .is_err()
        );
    }

    #[test]
    fn policy_change_replaces_stale_duplicate_approval_request() {
        let (_directory, mut store) = store();
        let stale = store
            .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
            .unwrap();
        let current = store.database.get("primary").unwrap().unwrap();
        store
            .database
            .put("primary", &current.policy, Some(current.revision))
            .unwrap();

        assert_eq!(
            store.get(stale.request_id).unwrap().status,
            PendingStatus::Cancelled
        );
        let replacement = store
            .create("primary", "ethereum", &plan(), None, 2)
            .unwrap();
        assert_ne!(replacement.request_id, stale.request_id);
        assert_eq!(replacement.policy_revision, 2);
    }

    #[test]
    fn wallet_state_removal_cancels_pending_requests() {
        let (_directory, mut store) = store();
        let request = store
            .create("primary", "ethereum", &plan(), Some("mcp.ekubo.org"), 1)
            .unwrap();
        store.database.delete("primary", 1).unwrap();
        assert_eq!(
            store.get(request.request_id).unwrap().status,
            PendingStatus::Cancelled
        );
    }
}
