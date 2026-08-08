//! The shared lifecycle of the two human-only signature queues.
//!
//! EIP-712 typed data and EIP-191 messages queue, reject, and sign through
//! byte-identical SQL: the tables differ only in their payload columns. One
//! implementation of the state machine keeps the two queues from drifting;
//! each store keeps only its payload encoding and its integrity
//! re-derivation of the stored digest.

use crate::sql::{self, Blob, Millis};
use alloy::primitives::B256;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

/// Requests one wallet may hold awaiting approval in each queue.
pub(crate) const MAX_AWAITING_PER_WALLET: i64 = 64;

/// One signature queue: a table whose rows move
/// `awaiting_approval → rejected | signed` and never again.
pub(crate) struct SignatureQueue {
    pub table: &'static str,
    /// The noun used in every error message, so a caller can tell which
    /// queue refused.
    pub noun: &'static str,
}

impl SignatureQueue {
    /// Queue a payload, reusing an identical one already awaiting approval
    /// for the same wallet and chain key. `insert` runs inside the same
    /// transaction that checked for duplicates and capacity, receiving the
    /// new request ID and the moment to store as both `created_at` and
    /// `updated_at`.
    ///
    /// `chain_key` is 0 for a request that declares no chain, which only
    /// `personal_sign` does. NULL would read better and would silently break
    /// the deduplication below, because `SQLite` counts NULLs as distinct in a
    /// unique index.
    pub fn create_or_reuse(
        &self,
        connection: &mut Connection,
        wallet_id: &str,
        chain_key: u64,
        digest: B256,
        insert: impl FnOnce(&rusqlite::Transaction<'_>, Uuid, DateTime<Utc>) -> Result<()>,
    ) -> Result<Uuid> {
        crate::config::validate_wallet_id(wallet_id)?;
        let chain_key = i64::try_from(chain_key).context("chain ID out of range")?;
        let transaction = connection.transaction()?;
        let existing: Option<Uuid> = transaction
            .query_row(
                &format!(
                    "SELECT request_id FROM {} WHERE wallet_id = ?1 AND chain_id = ?2 \
                     AND digest = ?3 AND status = 'awaiting_approval'",
                    self.table
                ),
                params![wallet_id, chain_key, Blob(digest)],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            transaction.commit()?;
            return Ok(existing);
        }
        let awaiting: i64 = transaction.query_row(
            &format!(
                "SELECT COUNT(*) FROM {} WHERE wallet_id = ?1 AND status = 'awaiting_approval'",
                self.table
            ),
            [wallet_id],
            |row| row.get(0),
        )?;
        ensure!(
            awaiting < MAX_AWAITING_PER_WALLET,
            "wallet already has {MAX_AWAITING_PER_WALLET} {}s awaiting approval",
            self.noun
        );
        let request_id = Uuid::new_v4();
        insert(&transaction, request_id, sql::now())?;
        transaction.commit()?;
        Ok(request_id)
    }

    /// Marks an awaiting request rejected; refuses when the row moved.
    pub fn reject(&self, connection: &Connection, request_id: Uuid) -> Result<()> {
        let changed = connection.execute(
            &format!(
                "UPDATE {} SET status = 'rejected', decided_at = ?2, updated_at = ?2 \
                 WHERE request_id = ?1 AND status = 'awaiting_approval'",
                self.table
            ),
            params![request_id, Millis(sql::now())],
        )?;
        ensure!(changed == 1, "{} changed during rejection", self.noun);
        Ok(())
    }

    /// Atomically records approval and the exact signature. Inside one
    /// transaction: the stored digest must still match what the approver
    /// reviewed, and the row must still be awaiting approval.
    pub fn store_signature(
        &self,
        connection: &mut Connection,
        request_id: Uuid,
        expected_digest: B256,
        signature: &str,
    ) -> Result<()> {
        let signature = parse_signature(signature)?;
        let transaction = connection.transaction()?;
        let (digest, status): (Blob<B256>, String) = transaction
            .query_row(
                &format!(
                    "SELECT digest, status FROM {} WHERE request_id = ?1",
                    self.table
                ),
                [request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .with_context(|| format!("unknown {} {request_id}", self.noun))?;
        ensure!(digest.0 == expected_digest, "{} digest mismatch", self.noun);
        ensure!(
            status == "awaiting_approval",
            "{} is not awaiting approval",
            self.noun
        );
        transaction.execute(
            &format!(
                "UPDATE {} SET status = 'signed', decided_at = ?2, updated_at = ?2, \
                 signature = ?3 WHERE request_id = ?1 AND status = 'awaiting_approval'",
                self.table
            ),
            params![request_id, Millis(sql::now()), Blob(signature)],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// IDs of every awaiting request, newest first, optionally for one wallet.
    pub fn awaiting_ids(
        &self,
        connection: &Connection,
        wallet_id: Option<&str>,
    ) -> Result<Vec<Uuid>> {
        if let Some(wallet_id) = wallet_id {
            crate::config::validate_wallet_id(wallet_id)?;
        }
        let mut statement = connection.prepare(&format!(
            "SELECT request_id FROM {} WHERE status = 'awaiting_approval' \
             AND (?1 IS NULL OR wallet_id = ?1) ORDER BY created_at DESC",
            self.table
        ))?;
        Ok(statement
            .query_map([wallet_id], |row| row.get::<_, Uuid>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

/// Split one stored decision into the two moments the API reports.
///
/// The database keeps a single `decided_at`, because a request gets one
/// decision and two nullable timestamps could claim it got both. Callers still
/// ask "when was this approved" and "when was this rejected" as separate
/// questions, so the status that names the decision splits it back apart —
/// here, once, rather than at each of the three stores, so the two answers
/// cannot come apart.
pub(crate) fn split_decision(
    decided_at: Option<DateTime<Utc>>,
    rejected: bool,
) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    if rejected {
        (None, decided_at)
    } else {
        (decided_at, None)
    }
}

/// The 65 bytes of an `r ‖ s ‖ v` signature, from the hex a caller passed.
///
/// Callers hand signatures across the API as hex strings, and the column holds
/// the bytes, so exactly one place converts between them and it is the same
/// place that decides what a valid signature looks like.
pub(crate) fn parse_signature(value: &str) -> Result<[u8; 65]> {
    let encoded = value
        .strip_prefix("0x")
        .context("signature must start with 0x")?;
    let mut bytes = [0_u8; 65];
    ensure!(
        encoded.len() == 130 && hex::decode_to_slice(encoded, &mut bytes).is_ok(),
        "signature must be 65 hexadecimal bytes"
    );
    Ok(bytes)
}

#[must_use]
pub(crate) fn encode_signature(signature: [u8; 65]) -> String {
    format!("0x{}", hex::encode(signature))
}
