//! Bounded request forwarding for the owner -> installer -> service path.
//! No credential lookup, peer authentication, recovery or activation occurs here.
use super::{
    Destination, Header, MAGIC, MAX_HEADER_BYTES, RecoveryCheckpoint, StagingReply, TransferIntent,
    TransferLimits, encode, read_frame, read_key, read_reply, write_frame,
};
use crate::{config::WalletMetadata, database_staging::DatabaseTransfer};
use anyhow::{Result, ensure};
use std::io::{Read, Write};
use uuid::Uuid;

/// Public source evidence from one forwarded request. This establishes neither
/// source provenance nor durable staging; the service must still validate it.
pub struct RelayedRequest {
    destination: Destination,
    session: Uuid,
    source: DatabaseTransfer,
    wallets: Vec<WalletMetadata>,
}

impl RelayedRequest {
    /// Finish the staging handshake on the same authenticated channels. Forward
    /// the validated service reply, then require owner checkpoint evidence bound
    /// to that reply and the original request. Consuming self prevents accidental
    /// repetition of this phase. No retry is safe after a missing reply.
    ///
    /// The owner supplies the logical fingerprint; this function cannot verify
    /// a remote SQLite fence. Native callers must retain and monitor that owner
    /// connection. Neither this result nor checkpoint persistence permits cutover.
    pub fn finish(
        self,
        service: &mut impl Read,
        owner: &mut (impl Read + Write),
    ) -> Result<(StagingReply, RecoveryCheckpoint)> {
        let reply = read_reply(service, self.session)?;
        reply.write_to(owner)?;
        let mut remaining = u64::from(MAX_HEADER_BYTES);
        let checkpoint: RecoveryCheckpoint = read_frame(owner, MAX_HEADER_BYTES, &mut remaining)?;
        ensure!(
            checkpoint.version == 1
                && checkpoint.destination == self.destination
                && checkpoint.session == self.session
                && checkpoint.source == self.source
                && checkpoint.stage == reply.stage()
                && checkpoint.canonical == *reply.canonical()
                && checkpoint.relay_digest == reply.relay().digest(),
            "owner checkpoint does not match forwarded staging"
        );
        Ok((reply, checkpoint))
    }

    #[must_use]
    pub const fn session(&self) -> Uuid {
        self.session
    }
    #[must_use]
    pub const fn source(&self) -> &DatabaseTransfer {
        &self.source
    }
    #[must_use]
    pub fn wallets(&self) -> &[WalletMetadata] {
        &self.wallets
    }
}

/// Forward only caller-supplied bytes between already authenticated transports.
/// The native installer must authenticate BOTH peers, derive `destination` from
/// protected configuration, enforce cancellation/deadlines and retain the owner
/// connection/source fence through commit. This is not a raw-key collector or an
/// arbitrary writer capability for opaque core keys. No owner/MCP endpoint uses it.
///
/// Validate destination and header limits before writing anything. Metadata is
/// bounded per frame and in aggregate; keys use zeroizing fixed-size buffers and
/// ciphertext is streamed with a length/digest check. Service-side account/SQL
/// validation remains mandatory. Failure can leave a partial service request;
/// never retry automatically or interpret this return as activation authority.
pub fn relay_request(
    input: &mut impl Read,
    output: &mut impl Write,
    destination: &Destination,
    limits: TransferLimits,
) -> Result<RelayedRequest> {
    relay_request_with_intent(input, output, destination, limits, |_| Ok(()))
}

/// Native source adapters use this form to durably record intent before any
/// transfer byte reaches the service. The callback receives only public evidence;
/// no key or stream capability is supplied. A callback error consumes the bounded
/// header only, leaving the output untouched. This codec does not select storage
/// or confer authority on a callback; native callers supply the protected journal.
pub fn relay_request_with_intent(
    input: &mut impl Read,
    output: &mut impl Write,
    destination: &Destination,
    limits: TransferLimits,
    persist: impl FnOnce(&TransferIntent) -> Result<()>,
) -> Result<RelayedRequest> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    ensure!(&magic == MAGIC, "unsupported source forwarding protocol");
    let mut remaining = u64::from(MAX_HEADER_BYTES);
    let header: Header = read_frame(input, MAX_HEADER_BYTES, &mut remaining)?;
    header.validate(limits)?;
    ensure!(
        &header.destination == destination,
        "source forwarding destination mismatch"
    );
    persist(&TransferIntent {
        version: 1,
        destination: header.destination.clone(),
        session: header.session,
        source: header.database.clone(),
    })?;
    output.write_all(MAGIC)?;
    write_frame(output, &encode(&header, MAX_HEADER_BYTES)?)?;
    copy_key(input, output)?;
    let mut remaining = limits.total_metadata_bytes;
    let mut wallets = Vec::new();
    for _ in 0..header.accounts {
        let wallet: WalletMetadata = read_frame(input, limits.metadata_bytes, &mut remaining)?;
        write_frame(output, &encode(&wallet, limits.metadata_bytes)?)?;
        copy_key(input, output)?;
        wallets.push(wallet);
    }
    crate::database_staging::copy_checked(&header.database, input, output)?;
    output.flush()?;
    Ok(RelayedRequest {
        destination: header.destination,
        session: header.session,
        source: header.database,
        wallets,
    })
}

fn copy_key(input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    let key = read_key(input)?;
    output.write_all(key.as_slice())?;
    Ok(())
}

#[cfg(test)]
#[path = "migration_forward_test.rs"]
mod tests;
