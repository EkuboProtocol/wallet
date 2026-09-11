//! Installer journal payload, never an activation or legacy-deletion receipt.
use super::{Destination, INSTALLER_LIMITS, MigrationDatabaseSnapshot, StagingReply};
use crate::{config::WalletMetadata, custody_envelope::WrappedDataKey};
use anyhow::{Result, ensure};
use std::io::{Read, Write};

use crate::installer_checkpoint::RecoveryCheckpoint;

impl RecoveryCheckpoint {
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
