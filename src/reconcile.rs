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
//! `submitting`, `broadcast`, and `cancelling` rows need chain lookups, and
//! the in-flight unique index allows at most one such row per wallet and
//! chain.

use crate::{
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    custody::KeyStore,
    execution::{
        BroadcastResult, ReceiptStatus as BroadcastReceiptStatus, broadcast_signed_cancellation,
        sign_cancellation, signed_transaction_nonce,
    },
    pending::{PendingStatus, PendingStore, PendingTransaction},
    rpc::{ReceiptStatus, mined_transaction_count, transaction_known, transaction_receipt},
};
use anyhow::{Context, Result, bail};
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
    if record.status == PendingStatus::Cancelling {
        return reconcile_cancelling(pending, network, record).await;
    }
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

/// Settle the race between a broadcast envelope and its own cancellation
/// attempts. Both sides sit at one nonce, so the mined account nonce says
/// whether the race is over, and the receipts say who won: the original
/// finalizes as confirmed or reverted, any of this wallet's cancellation
/// hashes marks the record cancelled (a reverted cancellation still consumed
/// the nonce), and an envelope this wallet never signed marks it replaced.
async fn reconcile_cancelling(
    pending: &Mutex<PendingStore>,
    network: &NetworkConfig,
    record: PendingTransaction,
) -> Result<PendingTransaction> {
    let original_hash = record
        .broadcast_transaction_hash
        .as_ref()
        .or(record.signed_transaction_hash.as_ref())
        .cloned()
        .context("cancelling transaction is missing its hash")?;
    if let Some(receipt) = transaction_receipt(network, &original_hash).await? {
        return lock(pending)?.finalize(
            record.request_id,
            receipt.succeeded,
            &receipt.block_number.to_string(),
        );
    }
    let envelope_nonce = signed_transaction_nonce(
        record
            .serialized_transaction
            .as_deref()
            .context("cancelling transaction is missing its signed bytes")?,
    )?;
    let mined_nonce = mined_transaction_count(network, record.execution_plan.sender).await?;
    if mined_nonce <= envelope_nonce {
        return Ok(record);
    }
    // The nonce is consumed. Newest cancellation first: it is the most likely
    // winner, and every hash in the history is equally "cancelled by us".
    for cancel_hash in record.cancel_transaction_hashes.iter().rev() {
        if let Some(receipt) = transaction_receipt(network, cancel_hash).await? {
            return lock(pending)?
                .mark_cancelled(record.request_id, &receipt.block_number.to_string());
        }
    }
    // Close the race window: the original may have mined between the nonce
    // read and here, exactly like the plain broadcast path.
    if let Some(receipt) = transaction_receipt(network, &original_hash).await? {
        return lock(pending)?.finalize(
            record.request_id,
            receipt.succeeded,
            &receipt.block_number.to_string(),
        );
    }
    lock(pending)?.mark_replaced(record.request_id)
}

/// Attempt to cancel a broadcast but unmined transaction: reconcile it
/// against the chain first — failing if the chain already settled it — then
/// sign a 0-value self-send outbidding it at its own nonce, persist the exact
/// cancellation envelope before submission, and broadcast it. Also the
/// repricing path: called again while `cancelling`, it outbids the newest
/// cancellation attempt too.
///
/// Cancellation consults no policy and queues no approval: every envelope
/// field derives from the stored record and the chain, so like an exact-byte
/// rebroadcast it cannot expand what was already authorized — it can only
/// narrow an in-flight authorization to nothing, at the cost of gas.
pub async fn attempt_cancellation<K: KeyStore>(
    pending: &Mutex<PendingStore>,
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    record: PendingTransaction,
    keys: &K,
) -> Result<(PendingTransaction, BroadcastResult)> {
    let record = reconcile_record(pending, network, record, true).await?;
    let block = |record: &PendingTransaction| {
        record
            .block_number
            .clone()
            .unwrap_or_else(|| "unknown".into())
    };
    match record.status {
        PendingStatus::Broadcast | PendingStatus::Cancelling => {}
        PendingStatus::Confirmed => bail!(
            "nothing to cancel: the transaction already mined in block {}",
            block(&record)
        ),
        PendingStatus::Reverted => bail!(
            "nothing to cancel: the transaction already mined (reverted) in block {}",
            block(&record)
        ),
        PendingStatus::Cancelled => bail!(
            "nothing to cancel: a cancellation already consumed the nonce in block {}",
            block(&record)
        ),
        PendingStatus::Replaced => {
            bail!("nothing to cancel: a different transaction already consumed this nonce on chain")
        }
        PendingStatus::Submitting => {
            bail!("a submission attempt holds this transaction's lease; retry in a moment")
        }
        PendingStatus::Signed
        | PendingStatus::AwaitingApproval
        | PendingStatus::Rejected
        | PendingStatus::Expired => {
            bail!("nothing to cancel on chain: the request has no broadcast transaction")
        }
    }
    let signed = sign_cancellation(
        wallet,
        network,
        record
            .serialized_transaction
            .as_deref()
            .context("broadcast transaction is missing its signed bytes")?,
        record.cancel_serialized_transaction.as_deref(),
        keys,
    )
    .await?;
    // Persist the exact envelope before first submission, mirroring the
    // automatic signing path: recovery must know every hash that may reach
    // the chain.
    let stored = lock(pending)?.store_cancellation(
        record.request_id,
        &signed.serialized_transaction,
        &signed.transaction_hash,
    )?;
    let broadcast = broadcast_signed_cancellation(&signed, wallet, network).await?;
    let record = match broadcast.receipt_status {
        // The receipt belongs to the cancellation hash: it mined immediately.
        BroadcastReceiptStatus::Success | BroadcastReceiptStatus::Reverted => lock(pending)?
            .mark_cancelled(
                stored.request_id,
                broadcast
                    .block_number
                    .as_deref()
                    .context("mined cancellation is missing a block number")?,
            )?,
        // An outright rejection usually means the race is already over —
        // "nonce too low" for a just-mined original — so ask the chain what
        // the rejection actually meant instead of reporting limbo.
        BroadcastReceiptStatus::Pending if broadcast.broadcast_error.is_some() => {
            reconcile_record(pending, network, stored, false).await?
        }
        BroadcastReceiptStatus::Pending => stored,
    };
    Ok((record, broadcast))
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
            PendingStatus::Broadcast | PendingStatus::Submitting | PendingStatus::Cancelling
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
