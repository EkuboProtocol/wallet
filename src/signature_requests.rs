//! The shared lifecycle of the two human-only signature queues.
//!
//! EIP-712 typed data and EIP-191 messages queue, reject, and sign through
//! byte-identical SQL: the tables differ only in their payload columns. One
//! implementation of the state machine keeps the two queues from drifting;
//! each store keeps only its payload encoding and its integrity
//! re-derivation of the stored digest.

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
    /// new request ID and the RFC 3339 timestamp to store as both
    /// `created_at` and `updated_at`.
    pub fn create_or_reuse(
        &self,
        connection: &mut Connection,
        wallet_id: &str,
        chain_key: &str,
        digest: &str,
        insert: impl FnOnce(&rusqlite::Transaction<'_>, Uuid, &str) -> Result<()>,
    ) -> Result<Uuid> {
        crate::config::validate_wallet_id(wallet_id)?;
        let transaction = connection.transaction()?;
        let existing: Option<String> = transaction
            .query_row(
                &format!(
                    "SELECT request_id FROM {} WHERE wallet_id = ?1 AND chain_id = ?2 \
                     AND digest = ?3 AND status = 'awaiting_approval'",
                    self.table
                ),
                params![wallet_id, chain_key, digest],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            transaction.commit()?;
            return Uuid::parse_str(&existing).context("stored request ID is invalid");
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
        insert(&transaction, request_id, &Utc::now().to_rfc3339())?;
        transaction.commit()?;
        Ok(request_id)
    }

    /// Marks an awaiting request rejected; refuses when the row moved.
    pub fn reject(&self, connection: &Connection, request_id: Uuid) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let changed = connection.execute(
            &format!(
                "UPDATE {} SET status = 'rejected', rejected_at = ?2, updated_at = ?2 \
                 WHERE request_id = ?1 AND status = 'awaiting_approval'",
                self.table
            ),
            params![request_id.to_string(), now],
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
        expected_digest: &str,
        signature: &str,
    ) -> Result<()> {
        validate_signature_hex(signature)?;
        let transaction = connection.transaction()?;
        let (digest, status): (String, String) = transaction
            .query_row(
                &format!(
                    "SELECT digest, status FROM {} WHERE request_id = ?1",
                    self.table
                ),
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .with_context(|| format!("unknown {} {request_id}", self.noun))?;
        ensure!(digest == expected_digest, "{} digest mismatch", self.noun);
        ensure!(
            status == "awaiting_approval",
            "{} is not awaiting approval",
            self.noun
        );
        let now = Utc::now().to_rfc3339();
        transaction.execute(
            &format!(
                "UPDATE {} SET status = 'signed', approved_at = ?2, updated_at = ?2, \
                 signature = ?3 WHERE request_id = ?1 AND status = 'awaiting_approval'",
                self.table
            ),
            params![request_id.to_string(), now, signature],
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
        let ids = statement
            .query_map([wallet_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.into_iter()
            .map(|value| Uuid::parse_str(&value).context("stored request ID is invalid"))
            .collect()
    }
}

pub(crate) fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .context("stored timestamp is invalid")?
        .with_timezone(&Utc))
}

pub(crate) fn validate_signature_hex(value: &str) -> Result<()> {
    use alloy::primitives::B256;
    use std::str::FromStr;
    let encoded = value
        .strip_prefix("0x")
        .context("signature must start with 0x")?;
    ensure!(
        encoded.len() == 130 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "signature must be 65 hexadecimal bytes"
    );
    B256::from_str(&format!("0x{}", &encoded[..64])).context("invalid signature encoding")?;
    Ok(())
}
