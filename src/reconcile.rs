//! Chain reconciliation for post-signature lifecycle records.
//!
//! A stored status is a cache of the last observation, never the authority.
//! Nonces are chain-assigned at signing time and the same key may be imported
//! on other devices, so nothing local can know a broadcast envelope's fate
//! without asking the chain: it may have mined, still be pending, or have had
//! its nonce consumed by a different transaction entirely. Every reader of an
//! in-flight record funnels through here — the MCP status tools, the CLI list
//! and show commands, and the interactive browser — so the record converges on
//! chain truth wherever it is observed.
//!
//! Reconciliation cost is bounded by construction, not by list length: only
//! `submitting` and `broadcast` rows need chain lookups, and the in-flight
//! unique index allows at most one such row per wallet and chain.

use crate::{
    config::{ConfigStore, NetworkConfig},
    execution::signed_transaction_nonce,
    pending::{PendingStatus, PendingStore, PendingTransaction},
    rpc::{ReceiptStatus, mined_transaction_count, transaction_known, transaction_receipt},
};
use anyhow::{Context, Result};
use chrono::{TimeDelta, Utc};
use std::sync::{Mutex, MutexGuard};

/// How long a `submitting` lease may go untouched before a reader may assume
/// the submitting process died mid-send and reclaim the record.
pub const SUBMISSION_LEASE_SECONDS: i64 = 120;

fn lock(pending: &Mutex<PendingStore>) -> Result<MutexGuard<'_, PendingStore>> {
    pending
        .lock()
        .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))
}

/// What the chain says about one exact signed envelope. Pure decision input:
/// the RPC lookups happen in [`observe`], the classification here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChainObservation {
    Mined(ReceiptStatus),
    /// The mined account nonce passed the envelope's nonce while no receipt
    /// exists for its hash: a different transaction consumed the nonce.
    Replaced,
    StillPending,
}

fn classify(
    envelope_nonce: u64,
    mined_nonce: u64,
    receipt: Option<ReceiptStatus>,
) -> ChainObservation {
    match receipt {
        Some(receipt) => ChainObservation::Mined(receipt),
        None if mined_nonce > envelope_nonce => ChainObservation::Replaced,
        None => ChainObservation::StillPending,
    }
}

/// Look the envelope up on chain and classify what happened to it.
///
/// Lookup order matters for the replaced verdict: the receipt lookup runs
/// AFTER the nonce read, so a nonce observed as consumed with still no receipt
/// for our hash can only mean a different envelope consumed it. (Read the
/// other way around, our transaction mining between the two lookups would
/// masquerade as a replacement.) The cheap common cases — mined, or nonce not
/// yet consumed — settle on the first receipt lookup alone.
async fn observe(
    network: &NetworkConfig,
    record: &PendingTransaction,
    transaction_hash: &str,
) -> Result<ChainObservation> {
    if let Some(receipt) = transaction_receipt(network, transaction_hash).await? {
        return Ok(ChainObservation::Mined(receipt));
    }
    let envelope_nonce = signed_transaction_nonce(
        record
            .serialized_transaction
            .as_deref()
            .context("submitted transaction is missing its signed bytes")?,
    )?;
    let mined_nonce = mined_transaction_count(network, record.execution_plan.sender).await?;
    if mined_nonce <= envelope_nonce {
        return Ok(ChainObservation::StillPending);
    }
    Ok(classify(
        envelope_nonce,
        mined_nonce,
        transaction_receipt(network, transaction_hash).await?,
    ))
}

/// Reconcile one lifecycle record against the chain, persisting whatever the
/// chain settled: a receipt finalizes to confirmed or reverted, a consumed
/// nonce without a receipt marks the record replaced, and a stale submission
/// lease is recovered when `recover_stale_submission` allows it.
pub async fn reconcile_record(
    pending: &Mutex<PendingStore>,
    network: &NetworkConfig,
    mut record: PendingTransaction,
    recover_stale_submission: bool,
) -> Result<PendingTransaction> {
    if !matches!(
        record.status,
        PendingStatus::Broadcast | PendingStatus::Submitting
    ) {
        return Ok(record);
    }
    let transaction_hash = record
        .broadcast_transaction_hash
        .as_ref()
        .or(record.signed_transaction_hash.as_ref())
        .cloned()
        .context("submitted transaction is missing its hash")?;
    match observe(network, &record, &transaction_hash).await? {
        ChainObservation::Mined(receipt) => {
            let mut pending = lock(pending)?;
            if record.status == PendingStatus::Submitting {
                record = pending.mark_broadcast(record.request_id, &transaction_hash)?;
            }
            pending.finalize(
                record.request_id,
                receipt.succeeded,
                &receipt.block_number.to_string(),
            )
        }
        ChainObservation::Replaced => {
            // A submitting lease still within its window is left alone even
            // though the envelope looks dead: the holder may be acting on it,
            // and the next reconcile settles it the moment the lease lapses.
            if record.status == PendingStatus::Submitting
                && !(recover_stale_submission && submission_lease_expired(&record))
            {
                return Ok(record);
            }
            lock(pending)?.mark_replaced(record.request_id)
        }
        ChainObservation::StillPending => {
            if record.status == PendingStatus::Submitting
                && recover_stale_submission
                && submission_lease_expired(&record)
            {
                let known = transaction_known(network, &transaction_hash).await?;
                let mut pending = lock(pending)?;
                record = if known {
                    pending.mark_broadcast(record.request_id, &transaction_hash)?
                } else {
                    pending.release_submission(record.request_id)?
                };
            }
            Ok(record)
        }
    }
}

fn submission_lease_expired(record: &PendingTransaction) -> bool {
    Utc::now() - record.updated_at >= TimeDelta::seconds(SUBMISSION_LEASE_SECONDS)
}

/// Reconcile every in-flight record in a listing, returning the refreshed
/// rows in their original order. Display-path work: an unreachable RPC or an
/// unconfigured network degrades that row to its stored state rather than
/// failing the listing.
pub async fn reconcile_all(
    config: &ConfigStore,
    pending: &Mutex<PendingStore>,
    records: Vec<PendingTransaction>,
) -> Vec<PendingTransaction> {
    let mut reconciled = Vec::with_capacity(records.len());
    for record in records {
        if !matches!(
            record.status,
            PendingStatus::Broadcast | PendingStatus::Submitting
        ) {
            reconciled.push(record);
            continue;
        }
        let Ok(network) = config.network_by_chain_id(&record.chain_id) else {
            reconciled.push(record);
            continue;
        };
        match reconcile_record(pending, &network, record.clone(), true).await {
            Ok(updated) => reconciled.push(updated),
            Err(_) => reconciled.push(record),
        }
    }
    reconciled
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn receipt(succeeded: bool) -> ReceiptStatus {
        ReceiptStatus {
            succeeded,
            block_number: 100,
        }
    }

    #[test]
    fn a_receipt_settles_the_envelope_regardless_of_nonce() {
        assert_eq!(
            classify(5, 6, Some(receipt(true))),
            ChainObservation::Mined(receipt(true))
        );
        assert_eq!(
            classify(5, 5, Some(receipt(false))),
            ChainObservation::Mined(receipt(false))
        );
    }

    #[test]
    fn a_consumed_nonce_without_a_receipt_is_a_replacement() {
        assert_eq!(classify(5, 6, None), ChainObservation::Replaced);
        assert_eq!(classify(0, 3, None), ChainObservation::Replaced);
    }

    #[test]
    fn an_unconsumed_nonce_without_a_receipt_is_still_pending() {
        assert_eq!(classify(5, 5, None), ChainObservation::StillPending);
        assert_eq!(classify(5, 0, None), ChainObservation::StillPending);
    }
}
