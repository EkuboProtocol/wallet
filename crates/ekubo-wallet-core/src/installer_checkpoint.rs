//! Shared data-only installer evidence. No transport, keys, or activation authority.
use crate::{custody_staging::CredentialStage, database_staging::DatabaseTransfer};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) const MAX_ACCOUNTS: u64 = 100_000;

pub(crate) const MAX_DATABASE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Public identity obtained from protected installer configuration. These strings
/// bind the transfer to its destination; they cannot establish peer provenance.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub owner: String,
    pub service: String,
    pub profile: Uuid,
}

/// Durable evidence that an installer was about to forward this exact transfer.
/// It contains no key, relay, or staging result. Without a completed checkpoint,
/// this is an incomplete attempt, never permission to replay, activate or delete.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferIntent {
    pub(crate) version: u8,
    pub(crate) destination: Destination,
    pub(crate) session: Uuid,
    pub(crate) source: DatabaseTransfer,
}

impl TransferIntent {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn journal_bytes(&self, destination: &Destination) -> Result<Vec<u8>> {
        ensure!(
            self.version == 1 && &self.destination == destination,
            "transfer intent destination or version mismatch"
        );
        ensure!(
            !self.session.is_nil()
                && !destination.profile.is_nil()
                && self.source.bytes > 0
                && self.source.bytes <= MAX_DATABASE_BYTES,
            "invalid transfer intent"
        );
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= 4096, "transfer intent is oversized");
        Ok(bytes)
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn from_journal(bytes: &[u8], destination: &Destination) -> Result<Self> {
        ensure!(bytes.len() <= 4096, "transfer intent is oversized");
        let intent: Self = serde_json::from_slice(bytes)?;
        intent.journal_bytes(destination)?;
        Ok(intent)
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn validate_checkpoint(&self, checkpoint: &RecoveryCheckpoint) -> Result<()> {
        ensure!(
            self.destination == checkpoint.destination
                && self.session == checkpoint.session
                && self.source == checkpoint.source,
            "checkpoint differs from recorded transfer intent"
        );
        Ok(())
    }
}

/// Persist only in protected installer storage. The login relay must be retained
/// separately under the actual owner. Deserialization does not authenticate this
/// evidence; native peer authentication and service candidate validation remain
/// mandatory. A missing staging reply cannot create this checkpoint.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCheckpoint {
    pub(crate) version: u8,
    pub(crate) destination: Destination,
    pub(crate) session: Uuid,
    pub(crate) stage: Uuid,
    pub(crate) source: DatabaseTransfer,
    pub(crate) source_fingerprint: [u8; 32],
    pub(crate) canonical: DatabaseTransfer,
    pub(crate) relay_digest: [u8; 32],
}

impl RecoveryCheckpoint {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn journal_bytes(&self, destination: &Destination) -> Result<Vec<u8>> {
        ensure!(
            self.version == 1 && &self.destination == destination,
            "checkpoint journal destination or version mismatch"
        );
        ensure!(
            !self.session.is_nil() && !self.stage.is_nil() && !destination.profile.is_nil(),
            "invalid checkpoint identity"
        );
        for database in [&self.source, &self.canonical] {
            ensure!(
                database.bytes > 0 && database.bytes <= MAX_DATABASE_BYTES,
                "invalid checkpoint database size"
            );
        }
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= 4096, "installer checkpoint is oversized");
        Ok(bytes)
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn from_journal(bytes: &[u8], destination: &Destination) -> Result<Self> {
        ensure!(bytes.len() <= 4096, "installer checkpoint is oversized");
        let checkpoint: Self = serde_json::from_slice(bytes)?;
        checkpoint.journal_bytes(destination)?;
        Ok(checkpoint)
    }
}

/// Durable staging evidence. Recovery must revalidate protected storage and its
/// contents; this record does not prove live source validity or authorize cutover.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CandidateRecord {
    pub(crate) version: u8,
    pub(crate) session: Uuid,
    pub(crate) destination: Destination,
    pub(crate) source: DatabaseTransfer,
    pub(crate) credentials: CredentialStage,
    pub(crate) canonical: DatabaseTransfer,
    // Persist only the digest. The envelope must stay in the login keyring,
    // separate from the service's wrapping key, including during recovery.
    pub(crate) relay_digest: [u8; 32],
}
