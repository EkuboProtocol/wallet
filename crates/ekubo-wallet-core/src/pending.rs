//! Encrypted pending approval and transaction lifecycle persistence.
//!
//! These records bind exact plans and signed bytes. They are not spending
//! counters, policy reservations, or rolling-limit state.

use crate::{
    config::validate_wallet_id,
    core::execution_plan::{DecimalU256, ExecutionPlan},
    policy_store::PolicyStore,
    rpc::MinedFee,
    signature_requests::split_decision,
    sql::{self, Blob, Millis, RowExt},
};
use alloy::primitives::{B256, Bytes, keccak256};
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
    /// served them, "inline data URI", or "a file on this machine" — shown as
    /// an approval fact. None for plans this process built itself (transfers,
    /// CLI).
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

        let created_at = sql::now();
        let digest = plan.digest();
        let chain_id = chain_id_column(&plan.chain_id)?;
        let existing: Option<Uuid> = transaction
            .query_row(
                "SELECT request_id FROM pending_transactions
                 WHERE wallet_id = ?1 AND chain_id = ?2 AND plan_digest = ?3
                   AND status = 'awaiting_approval'",
                params![wallet_id, chain_id, Blob(digest)],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            transaction.commit()?;
            return self.get(existing);
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
                request_id,
                wallet_id,
                network_name,
                chain_id,
                plan_json,
                Blob(digest),
                plan_source,
                policy_revision,
                Millis(created_at),
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
        let serialized_transaction = parse_envelope(serialized_transaction)?;
        let transaction_hash = parse_hash(transaction_hash)?;
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
        let created_at = sql::now();
        let chain_id = chain_id_column(&plan.chain_id)?;
        transaction
            .execute(
                "INSERT INTO pending_transactions(
                request_id, wallet_id, network_name, chain_id, plan_json,
                plan_digest, plan_source, policy_revision, status, created_at, updated_at,
                serialized_transaction, signed_transaction_hash, approval_required
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'signed', ?9, ?9, ?10, ?11, 0)",
                params![
                    request_id,
                    wallet_id,
                    network_name,
                    chain_id,
                    serde_json::to_string(plan)?,
                    Blob(plan.digest()),
                    plan_source,
                    policy_revision,
                    Millis(created_at),
                    Blob(serialized_transaction),
                    Blob(transaction_hash),
                ],
            )
            .with_context(|| in_flight_conflict(&transaction, wallet_id, chain_id))?;
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
        let request_id: Option<Uuid> = self
            .database
            .connection
            .query_row(
                "SELECT request_id FROM pending_transactions
                 WHERE wallet_id = ?1 AND chain_id = ?2
                   AND status IN ('signed', 'submitting', 'broadcast', 'cancelling')",
                params![wallet_id, parse_chain_id(chain_id)?],
                |row| row.get(0),
            )
            .optional()?;
        request_id.map(|value| self.get(value)).transpose()
    }

    /// Discard a signed envelope, freeing the wallet+chain in-flight slot.
    ///
    /// `signed` usually means the bytes exist nowhere but this database, and
    /// then marking the record cancelled is simply honest. It does not always
    /// mean that: recovering a submission whose process died mid-send returns
    /// the row here, and that recovery rests on `transaction_known` answering
    /// no — which a node that evicted the envelope, or never saw it, says
    /// exactly as one that was never offered it.
    ///
    /// The status alone therefore cannot carry the claim, and this method does
    /// not make it. Callers settle the record against the chain and ask the
    /// node about the hash before reaching here, and say only what those
    /// answers support. Anything still in a submitted state is refused
    /// outright — cancel that on chain instead.
    pub fn discard_unsent(&mut self, request_id: Uuid) -> Result<PendingTransaction> {
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = 'cancelled', updated_at = ?2
             WHERE request_id = ?1 AND status = 'signed'",
            params![request_id, Millis(sql::now())],
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
                [request_id],
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
        transaction.execute(
            "UPDATE pending_transactions
             SET status = 'rejected', decided_at = ?2, updated_at = ?2
             WHERE request_id = ?1 AND status = 'awaiting_approval'",
            params![request_id, Millis(sql::now())],
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
        let review_digest = parse_hash(review_digest)?;
        let serialized_transaction = parse_envelope(serialized_transaction)?;
        let transaction_hash = parse_hash(transaction_hash)?;
        let expected_digest = parse_hash(expected_digest)?;
        let transaction = self.database.connection.transaction()?;
        let (wallet_id, chain_id, digest, policy_revision, status, approval_required): (
            String,
            i64,
            Blob<B256>,
            i64,
            String,
            i64,
        ) = transaction
            .query_row(
                "SELECT wallet_id, chain_id, plan_digest, policy_revision, status,
                        approval_required
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id],
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
        ensure!(
            digest.0 == expected_digest,
            "pending request digest mismatch"
        );
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
        transaction
            .execute(
                "UPDATE pending_transactions SET
                status = 'signed', decided_at = ?2, updated_at = ?2,
                serialized_transaction = ?3, signed_transaction_hash = ?4,
                review_digest = ?5
             WHERE request_id = ?1 AND status = 'awaiting_approval'",
                params![
                    request_id,
                    Millis(sql::now()),
                    Blob(serialized_transaction),
                    Blob(transaction_hash),
                    Blob(review_digest),
                ],
            )
            .with_context(|| in_flight_conflict(&transaction, &wallet_id, chain_id))?;
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
                [request_id],
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
                params![request_id, Millis(sql::now())],
            )?;
            transaction.commit()?;
            anyhow::bail!("active policy changed after this transaction was signed");
        }
        transaction.execute(
            "UPDATE pending_transactions SET status = 'submitting', updated_at = ?2
             WHERE request_id = ?1 AND status = 'signed'",
            params![request_id, Millis(sql::now())],
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
            params![request_id, Millis(sql::now()), Millis(leased_at)],
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
        let transaction_hash = parse_hash(transaction_hash)?;
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET
                status = 'broadcast', broadcast_transaction_hash = ?2, updated_at = ?3
             WHERE request_id = ?1 AND status = 'submitting'
               AND signed_transaction_hash = ?2 AND updated_at = ?4",
            params![
                request_id,
                Blob(transaction_hash),
                Millis(sql::now()),
                Millis(leased_at)
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
            params![request_id, Millis(sql::now())],
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
        let cancel_serialized_transaction = parse_envelope(cancel_serialized_transaction)?;
        let cancel_transaction_hash = parse_hash(cancel_transaction_hash)?;
        let priced_against = priced_against.map(parse_hash).transpose()?;
        let transaction = self.database.connection.transaction()?;
        let (status, hashes): (String, Option<Vec<u8>>) = transaction
            .query_row(
                "SELECT status, cancel_transaction_hashes
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id],
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
            hashes.last().copied() == priced_against,
            "another cancellation was recorded while this one was being priced; \
             re-read the request and reprice against the newest envelope"
        );
        ensure!(
            !hashes.contains(&cancel_transaction_hash),
            "this exact cancellation was already recorded"
        );
        ensure!(
            hashes.len() < MAX_CANCELLATION_ATTEMPTS,
            "too many cancellation attempts for this transaction"
        );
        hashes.push(cancel_transaction_hash);
        transaction.execute(
            "UPDATE pending_transactions SET
                status = 'cancelling', cancel_serialized_transaction = ?2,
                cancel_transaction_hashes = ?3, updated_at = ?4
             WHERE request_id = ?1 AND status IN ('broadcast', 'cancelling')",
            params![
                request_id,
                Blob(cancel_serialized_transaction),
                encode_cancel_hashes(&hashes),
                Millis(sql::now()),
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
        block_number: u64,
        fee: Option<&MinedFee>,
    ) -> Result<PendingTransaction> {
        let fee = fee.map(stored_fee).transpose()?;
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET
                status = 'cancelled', block_number = ?2, updated_at = ?3,
                gas_used = ?4, effective_gas_price = ?5
             WHERE request_id = ?1 AND status IN ('cancelling', 'replaced')",
            params![
                request_id,
                block_number_column(block_number)?,
                Millis(sql::now()),
                fee.map(|(gas_used, _)| gas_used),
                fee.map(|(_, price)| Blob(price)),
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
    /// Record that a different envelope consumed this one's nonce.
    ///
    /// A verdict, not a fact. It is inferred from two independent RPC reads —
    /// a consumed nonce and no receipt for our hash — and a node whose receipt
    /// index lags its nonce reports exactly that about a transaction of ours
    /// that did mine. So `replaced` is reachable in error, and `finalize` and
    /// `mark_cancelled` both accept it as an origin: a receipt that turns up
    /// later corrects the verdict rather than being ignored by it.
    /// Retire the envelope the caller observed at `observed_at`.
    ///
    /// Leased for the same reason as `release_submission` and `mark_broadcast`:
    /// a replacement verdict is reached from a snapshot read outside the lock,
    /// against a node that answered about the state of the chain some moments
    /// ago. Without the guard that verdict applied to whatever the row held by
    /// the time it landed — including a submission lease taken since, whose
    /// holder is at that moment putting the envelope on the wire. Retiring
    /// that row frees the wallet's in-flight slot for a transaction that is
    /// about to exist.
    pub fn mark_replaced(
        &mut self,
        request_id: Uuid,
        observed_at: DateTime<Utc>,
    ) -> Result<PendingTransaction> {
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = 'replaced', updated_at = ?2
             WHERE request_id = ?1 AND status IN ('submitting', 'broadcast', 'cancelling')
               AND updated_at = ?3",
            params![request_id, Millis(sql::now()), Millis(observed_at)],
        )?;
        ensure!(
            changed == 1,
            "pending transaction is not in flight, or it moved after the observation that \
             judged it replaced"
        );
        self.get(request_id)
    }

    /// Record the original envelope's mined receipt. Also reachable from
    /// `cancelling`: the original winning the race against its own
    /// cancellation is still simply the original executing.
    pub fn finalize(
        &mut self,
        request_id: Uuid,
        succeeded: bool,
        block_number: u64,
        fee: Option<&MinedFee>,
    ) -> Result<PendingTransaction> {
        let fee = fee.map(stored_fee).transpose()?;
        let status = if succeeded { "confirmed" } else { "reverted" };
        let changed = self.database.connection.execute(
            "UPDATE pending_transactions SET status = ?2, block_number = ?3, updated_at = ?4,
                gas_used = ?5, effective_gas_price = ?6
             WHERE request_id = ?1 AND status IN ('broadcast', 'cancelling', 'replaced')",
            params![
                request_id,
                status,
                block_number_column(block_number)?,
                Millis(sql::now()),
                fee.map(|(gas_used, _)| gas_used),
                fee.map(|(_, price)| Blob(price)),
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
            .query_map([wallet_id], |row| row.get::<_, Uuid>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        request_ids
            .into_iter()
            .map(|id| self.get(id))
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
                row.get::<_, Uuid>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        request_ids.into_iter().map(|id| self.get(id)).collect()
    }

    pub fn get_by_identifier(&self, identifier: &str) -> Result<PendingTransaction> {
        if let Ok(request_id) = Uuid::parse_str(identifier) {
            return self.get(request_id);
        }
        let hash = parse_hash(identifier)?;
        let request_id: Uuid = self
            .database
            .connection
            .query_row(
                "SELECT request_id FROM pending_transactions
                 WHERE signed_transaction_hash = ?1 OR broadcast_transaction_hash = ?1
                 ORDER BY created_at DESC LIMIT 1",
                [Blob(hash)],
                |row| row.get(0),
            )
            .with_context(|| format!("unknown transaction {identifier}"))?;
        self.get(request_id)
    }

    fn read(&self, request_id: Uuid) -> Result<PendingTransaction> {
        let raw = self
            .database
            .connection
            .query_row(
                "SELECT wallet_id, network_name, chain_id, plan_json, plan_digest,
                        policy_revision, status, created_at, updated_at,
                        decided_at, serialized_transaction,
                        signed_transaction_hash, broadcast_transaction_hash, block_number,
                        approval_required, review_digest, cancel_serialized_transaction,
                        cancel_transaction_hashes, gas_used, effective_gas_price, plan_source
                 FROM pending_transactions WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok(PendingRow {
                        wallet_id: row.get(0)?,
                        network_name: row.get(1)?,
                        chain_id: row.get(2)?,
                        plan_json: row.get(3)?,
                        digest: row.blob(4)?,
                        policy_revision: row.get(5)?,
                        status: row.get(6)?,
                        created_at: row.time(7)?,
                        updated_at: row.time(8)?,
                        decided_at: row.time_opt(9)?,
                        serialized_transaction: row.blob_opt(10)?,
                        signed_transaction_hash: row.blob_opt(11)?,
                        broadcast_transaction_hash: row.blob_opt(12)?,
                        block_number: row.get(13)?,
                        approval_required: row.get(14)?,
                        review_digest: row.blob_opt(15)?,
                        cancel_serialized_transaction: row.blob_opt(16)?,
                        cancel_transaction_hashes: row.get(17)?,
                        gas_used: row.get(18)?,
                        effective_gas_price: row.blob_opt(19)?,
                        plan_source: row.get(20)?,
                    })
                },
            )
            .with_context(|| format!("unknown pending request {request_id}"))?;
        raw.parse(request_id)
    }
}

/// One row exactly as the columns hold it. Every field is already the type its
/// column declares, so [`PendingRow::parse`] checks how the values relate to
/// each other rather than re-checking what each one is.
struct PendingRow {
    wallet_id: String,
    network_name: String,
    chain_id: i64,
    plan_json: String,
    digest: B256,
    policy_revision: i64,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    decided_at: Option<DateTime<Utc>>,
    serialized_transaction: Option<Bytes>,
    signed_transaction_hash: Option<B256>,
    broadcast_transaction_hash: Option<B256>,
    block_number: Option<i64>,
    approval_required: i64,
    review_digest: Option<B256>,
    cancel_serialized_transaction: Option<Bytes>,
    cancel_transaction_hashes: Option<Vec<u8>>,
    gas_used: Option<i64>,
    effective_gas_price: Option<u128>,
    plan_source: Option<String>,
}

impl PendingRow {
    fn parse(self, request_id: Uuid) -> Result<PendingTransaction> {
        validate_wallet_id(&self.wallet_id)?;
        let value = serde_json::from_str(&self.plan_json).context("stored plan is invalid JSON")?;
        let execution_plan = ExecutionPlan::parse(value).context("stored plan is invalid")?;
        ensure!(
            execution_plan.digest() == self.digest,
            "stored plan digest mismatch"
        );
        ensure!(
            chain_id_column(&execution_plan.chain_id)
                .is_ok_and(|declared| declared == self.chain_id),
            "stored pending chain ID mismatch"
        );
        validate_plan_source(self.plan_source.as_deref())?;
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
            ensure!(
                keccak256(serialized) == *hash,
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
        let status = PendingStatus::parse(&self.status)?;
        let (approved_at, rejected_at) =
            split_decision(self.decided_at, status == PendingStatus::Rejected);
        ensure!(
            self.review_digest.is_none() || approved_at.is_some(),
            "stored review digest has no exceptional approval timestamp"
        );
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
        // The pair has to agree, exactly as the original envelope's does. A
        // ceiling resend rebroadcasts these bytes under the newest recorded
        // hash without re-deriving one, so a disagreement was caught only at
        // broadcast — by which point the row holds the wallet's one in-flight
        // slot and the owner is trying to stop a transaction.
        if let (Some(serialized), Some(hash)) = (
            &self.cancel_serialized_transaction,
            cancel_transaction_hashes.last(),
        ) {
            ensure!(
                keccak256(serialized) == *hash,
                "stored cancellation transaction does not hash to its newest recorded hash"
            );
        }
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
        let mined_fee = match (self.gas_used, self.effective_gas_price) {
            (Some(gas_used), Some(price)) => Some(mined_fee(gas_used, price)?),
            (None, None) => None,
            _ => anyhow::bail!("stored transaction fee is incomplete"),
        };
        let block_number = self
            .block_number
            .map(|number| u64::try_from(number).context("stored block number is invalid"))
            .transpose()?;
        Ok(PendingTransaction {
            request_id,
            wallet_id: self.wallet_id,
            network_name: self.network_name,
            chain_id: self.chain_id.to_string(),
            execution_plan,
            plan_source: self.plan_source,
            digest: format!("{:#x}", self.digest),
            review_digest: self.review_digest.map(|digest| format!("{digest:#x}")),
            policy_revision,
            approval_required,
            status,
            created_at: self.created_at,
            updated_at: self.updated_at,
            approved_at,
            rejected_at,
            serialized_transaction: self.serialized_transaction.map(|bytes| bytes.to_string()),
            signed_transaction_hash: self
                .signed_transaction_hash
                .map(|hash| format!("{hash:#x}")),
            broadcast_transaction_hash: self
                .broadcast_transaction_hash
                .map(|hash| format!("{hash:#x}")),
            block_number: block_number.map(|number| number.to_string()),
            mined_fee,
            cancel_serialized_transaction: self
                .cancel_serialized_transaction
                .map(|bytes| bytes.to_string()),
            cancel_transaction_hashes: cancel_transaction_hashes
                .iter()
                .map(|hash| format!("{hash:#x}"))
                .collect(),
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

/// What a plan built from a connected dapp's request carries in front of the
/// dapp's own account of itself.
///
/// Everywhere else this field is evidence: a host TLS proved, or a literal
/// naming where local bytes came from. A dapp's name and URL are neither —
/// they are strings it typed about itself, and one serving from
/// `claim-rewards.xyz` is free to call itself `ekubo.org`. The prefix is what
/// keeps the field honest with both kinds of value in it: `ekubo.org` alone
/// means TLS proved that host, and `WalletConnect: Ekubo (ekubo.org)` means a
/// dapp said so. A reviewer can tell the two apart at a glance, which is the
/// whole point of the field.
pub const DAPP_PLAN_SOURCE_PREFIX: &str = "WalletConnect: ";

/// The longest a stored plan source may be. Public so a producer can cut its
/// value to fit rather than discover the limit when the owner tries to sign.
pub const MAX_PLAN_SOURCE_BYTES: usize = 255;

/// A stored plan source must be exactly what its producer is allowed to
/// produce — the literal "inline data URI", the literal "a file on this
/// machine", a lowercase vetted hostname, or [`DAPP_PLAN_SOURCE_PREFIX`]
/// followed by the dapp's claim — so a tampered database cannot inject
/// terminal escapes or misleading text into the approval screen. No form with
/// a space in it can be mistaken for a host name.
///
/// The claim after the prefix is the one part authored by someone else, so it
/// is held to being already sanitized: it must equal its own
/// [`crate::sanitize::terminal_safe_line`], which is what rules out the
/// control, bidirectional, and zero-width characters that let stored text draw
/// the wallet's own chrome.
pub fn validate_plan_source(value: Option<&str>) -> Result<()> {
    let Some(value) = value else { return Ok(()) };
    ensure!(
        value.len() <= MAX_PLAN_SOURCE_BYTES,
        "stored plan source exceeds {MAX_PLAN_SOURCE_BYTES} bytes"
    );
    if let Some(claim) = value.strip_prefix(DAPP_PLAN_SOURCE_PREFIX) {
        ensure!(
            !claim.trim().is_empty(),
            "stored plan source names no dapp after its prefix"
        );
        ensure!(
            crate::sanitize::terminal_safe_line(claim) == claim,
            "stored plan source carries characters no rendered surface accepts"
        );
        return Ok(());
    }
    ensure!(
        value == "inline data URI"
            || value == "a file on this machine"
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

/// The cancellation history, oldest first, from the concatenated bytes stored.
///
/// The column's own `CHECK` already refuses a length that is not a whole
/// number of hashes within the attempt cap, so this splits rather than
/// validates — but it still checks, because a `CHECK` constrains what this
/// process writes and the point of re-deriving anything here is a file that
/// was edited by something else.
fn parse_cancel_hashes(bytes: &[u8]) -> Result<Vec<B256>> {
    ensure!(
        !bytes.is_empty()
            && bytes.len().is_multiple_of(32)
            && bytes.len() / 32 <= MAX_CANCELLATION_ATTEMPTS,
        "stored cancellation hash list has an invalid length"
    );
    Ok(bytes.chunks_exact(32).map(B256::from_slice).collect())
}

fn encode_cancel_hashes(hashes: &[B256]) -> Vec<u8> {
    hashes.iter().flat_map(|hash| hash.0).collect()
}

/// One hash from the `0x`-prefixed hex a caller passed across the API.
fn parse_hash(value: &str) -> Result<B256> {
    B256::from_str(value).context("value must be a 0x-prefixed 32-byte hash")
}

/// One signed envelope from the `0x`-prefixed hex a caller passed.
fn parse_envelope(value: &str) -> Result<Bytes> {
    let bytes = Bytes::from_str(value).context("value must be 0x-prefixed hexadecimal")?;
    ensure!(!bytes.is_empty(), "signed transaction bytes are empty");
    Ok(bytes)
}

/// A plan's chain as the column holds it.
///
/// A plan carries its chain as a full uint256 because that is what EIP-155
/// allows it to say, while `SQLite`'s `INTEGER` is signed 63-bit and no EVM chain
/// needs more. A plan naming a chain outside that range is refused at
/// persistence rather than silently truncated into a different chain.
fn chain_id_column(chain_id: &DecimalU256) -> Result<i64> {
    parse_chain_id(chain_id.as_str())
}

fn parse_chain_id(value: &str) -> Result<i64> {
    value
        .parse::<i64>()
        .ok()
        .filter(|chain_id| *chain_id > 0)
        .context("chain ID must be a positive integer below 2^63")
}

fn block_number_column(block_number: u64) -> Result<i64> {
    i64::try_from(block_number).context("block number out of range")
}

/// A receipt's fee as the two columns hold it: gas units as an integer, and
/// wei per gas as sixteen big-endian bytes, since a uint128 price does not fit
/// a signed 64-bit integer.
fn stored_fee(fee: &MinedFee) -> Result<(i64, u128)> {
    let gas_used: u64 = fee.gas_used.parse().context("gas usage is invalid")?;
    let price: u128 = fee
        .effective_gas_price
        .parse()
        .context("effective gas price is invalid")?;
    Ok((
        i64::try_from(gas_used).context("gas usage out of range")?,
        price,
    ))
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
    chain_id: i64,
) -> String {
    let blocker: Option<(Uuid, String)> = transaction
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
fn mined_fee(gas_used: i64, effective_gas_price: u128) -> Result<MinedFee> {
    let gas = u128::try_from(gas_used).context("stored gas usage is invalid")?;
    Ok(MinedFee {
        gas_used: gas.to_string(),
        effective_gas_price: effective_gas_price.to_string(),
        transaction_fee_wei: gas.saturating_mul(effective_gas_price).to_string(),
    })
}

#[cfg(test)]
#[path = "pending_test.rs"]
mod tests;
