//! Bounded request forwarding for the owner -> installer -> service path.
//! No credential lookup, peer authentication, recovery or activation occurs here.
use super::{
    Destination, Header, MAGIC, MAX_HEADER_BYTES, TransferLimits, encode, read_frame, read_key,
    write_frame,
};
use crate::{config::WalletMetadata, database_staging::DatabaseTransfer};
use anyhow::{Result, ensure};
use std::io::{Read, Write};
use uuid::Uuid;

/// Public source evidence from one forwarded request. This establishes neither
/// source provenance nor durable staging; the service must still validate it.
pub struct RelayedRequest {
    session: Uuid,
    source: DatabaseTransfer,
    wallets: Vec<WalletMetadata>,
}

impl RelayedRequest {
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
