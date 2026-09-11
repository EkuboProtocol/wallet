//! Installer journal payload, never an activation or legacy-deletion receipt.
use super::{Destination, INSTALLER_LIMITS, MigrationDatabaseSnapshot, StagingReply};
use crate::{
    config::WalletMetadata, custody_envelope::WrappedDataKey, database_staging::DatabaseTransfer,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use uuid::Uuid;

/// Persist only in protected installer storage. The login relay must be retained
/// separately under the actual owner. Deserialization does not authenticate this
/// evidence; native peer authentication and service candidate validation remain
/// mandatory. A missing staging reply cannot create this checkpoint.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCheckpoint {
    version: u8,
    destination: Destination,
    session: Uuid,
    stage: Uuid,
    source: DatabaseTransfer,
    source_fingerprint: [u8; 32],
    canonical: DatabaseTransfer,
    relay_digest: [u8; 32],
}

impl RecoveryCheckpoint {
    #[cfg(target_os = "linux")]
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
                database.bytes > 0 && database.bytes <= INSTALLER_LIMITS.database_bytes,
                "invalid checkpoint database size"
            );
        }
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= 4096, "installer checkpoint is oversized");
        Ok(bytes)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_journal(bytes: &[u8], destination: &Destination) -> Result<Self> {
        ensure!(bytes.len() <= 4096, "installer checkpoint is oversized");
        let checkpoint: Self = serde_json::from_slice(bytes)?;
        checkpoint.journal_bytes(destination)?;
        Ok(checkpoint)
    }

    pub(crate) fn capture(
        destination: Destination,
        reply: &StagingReply,
        snapshot: &mut MigrationDatabaseSnapshot,
    ) -> Result<Self> {
        Ok(Self {
            version: 1,
            destination,
            session: reply.session(),
            stage: reply.stage(),
            source: snapshot.transfer()?,
            source_fingerprint: snapshot.source_fingerprint()?,
            canonical: reply.canonical().clone(),
            relay_digest: reply.relay().digest(),
        })
    }

    pub(crate) fn exchange(
        &self,
        stream: &mut (impl Read + Write),
        destination: Destination,
        snapshot: &MigrationDatabaseSnapshot,
        relay: WrappedDataKey,
        expected: &[WalletMetadata],
    ) -> Result<StagingReply> {
        ensure!(self.version == 1, "unsupported recovery checkpoint version");
        ensure!(
            destination == self.destination,
            "recovery checkpoint destination changed"
        );
        ensure!(
            relay.digest() == self.relay_digest,
            "recovery checkpoint relay changed"
        );
        ensure!(
            snapshot.source_fingerprint()? == self.source_fingerprint,
            "legacy source changed since staging"
        );
        let request = super::RecoveryRequest {
            destination,
            session: self.session,
            stage: self.stage,
            // Keep the ORIGINAL ciphertext identity. The newly frozen source
            // has a fresh salt and is used only for live logical revalidation.
            source: self.source.clone(),
            relay,
        };
        super::send_recovery(stream, &request, expected, INSTALLER_LIMITS)?;
        let reply = super::read_reply(stream, self.session)?;
        ensure!(
            reply.stage() == self.stage
                && reply.canonical() == &self.canonical
                && reply.relay().digest() == self.relay_digest,
            "recovery reply changed the checkpoint candidate"
        );
        Ok(reply)
    }
}

#[cfg(test)]
#[path = "migration_checkpoint_test.rs"]
mod tests;
