//! Shared data-only installer evidence. No transport, keys, or activation authority.
use crate::database_staging::DatabaseTransfer;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
