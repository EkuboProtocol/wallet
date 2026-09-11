//! Recovery shares the privileged provisioning admission and transport. No raw
//! account/database keys are transmitted and no records are created or activated.
use super::{
    Destination, MAX_HEADER_BYTES, ReceivedCandidate, TransferLimits, consume_budget, encode,
    read_frame, recover, write_frame,
};
use crate::{
    config::WalletMetadata,
    custody_envelope::WrappedDataKey,
    custody_staging::CredentialStagingStore,
    database_staging::{DatabaseStagingStore, DatabaseTransfer},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use uuid::Uuid;

pub(super) const MAGIC: &[u8; 8] = b"EKUBORC1";

/// Original transfer evidence plus the separately retained login relay. None of
/// these fields authenticates a caller or authorizes activation/legacy deletion.
pub struct RecoveryRequest {
    pub destination: Destination,
    pub session: Uuid,
    pub stage: Uuid,
    pub source: DatabaseTransfer,
    pub relay: WrappedDataKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    destination: Destination,
    session: Uuid,
    stage: Uuid,
    source: DatabaseTransfer,
    accounts: u64,
    relay: String,
}

impl Header {
    fn validate(&self, limits: TransferLimits) -> Result<()> {
        ensure!(
            !self.session.is_nil() && !self.stage.is_nil() && !self.destination.profile.is_nil(),
            "invalid recovery identity"
        );
        ensure!(
            self.accounts <= limits.accounts
                && self.source.bytes != 0
                && self.source.bytes <= limits.database_bytes,
            "recovery admission limit exceeded"
        );
        ensure!(
            self.relay.len() == crate::custody_envelope::SEALED_KEY_BYTES * 2,
            "invalid recovery relay length"
        );
        Ok(())
    }
}

/// Authenticate the protected destination before calling this codec. Preflight
/// all bounded metadata before sending the relay. Read the reply on the same
/// connection using the returned original session; recovery revalidates that
/// same immutable stage, not a new transfer. No retry/reconnect occurs here.
pub fn send_recovery(
    output: &mut impl Write,
    request: &RecoveryRequest,
    expected: &[WalletMetadata],
    limits: TransferLimits,
) -> Result<Uuid> {
    let header = Header {
        destination: request.destination.clone(),
        session: request.session,
        stage: request.stage,
        source: request.source.clone(),
        accounts: u64::try_from(expected.len())?,
        relay: hex::encode(request.relay.as_bytes()),
    };
    header.validate(limits)?;
    let header = encode(&header, MAX_HEADER_BYTES)?;
    let mut remaining = limits.total_metadata_bytes;
    for wallet in expected {
        consume_budget(&mut remaining, encode(wallet, limits.metadata_bytes)?.len())?;
    }
    output.write_all(MAGIC)?;
    write_frame(output, &header)?;
    for wallet in expected {
        write_frame(output, &encode(wallet, limits.metadata_bytes)?)?;
    }
    output.flush()?;
    Ok(request.session)
}

/// Platform workers retain ownership of the snapshot through this entire call,
/// including cancellation. The caller retains the original destination binding.
pub(crate) fn exchange(
    stream: &mut (impl Read + Write),
    destination: Destination,
    previous: &super::StagingReply,
    snapshot: &mut super::MigrationDatabaseSnapshot,
    expected: &[WalletMetadata],
) -> Result<super::StagingReply> {
    let request = RecoveryRequest {
        destination,
        session: previous.session(),
        stage: previous.stage(),
        source: snapshot.transfer()?,
        relay: previous.relay().clone(),
    };
    let session = send_recovery(stream, &request, expected, super::INSTALLER_LIMITS)?;
    let reply = super::read_reply(stream, session)?;
    validate_reply(previous, &reply)?;
    Ok(reply)
}

fn validate_reply(previous: &super::StagingReply, reply: &super::StagingReply) -> Result<()> {
    ensure!(
        reply.session() == previous.session()
            && reply.stage() == previous.stage()
            && reply.canonical() == previous.canonical()
            && reply.relay().as_bytes() == previous.relay().as_bytes(),
        "recovery reply changed the staged candidate"
    );
    Ok(())
}

pub(super) fn receive<'a, S: CredentialStagingStore + DatabaseStagingStore>(
    store: &'a S,
    input: &mut impl Read,
    limits: TransferLimits,
) -> Result<ReceivedCandidate<'a, S>> {
    let header: Header = read_frame(input, MAX_HEADER_BYTES, &mut u64::from(MAX_HEADER_BYTES))?;
    header.validate(limits)?;
    let (owner, service, profile) = store.identity();
    ensure!(
        header.destination
            == Destination {
                owner,
                service,
                profile
            },
        "recovery destination mismatch"
    );
    let relay =
        hex::decode(&header.relay).map_err(|_| anyhow::anyhow!("invalid recovery relay"))?;
    let relay = WrappedDataKey::from_bytes(&relay)?;
    let mut remaining = limits.total_metadata_bytes;
    let mut expected = Vec::new();
    // Never allocate from the remote account count before reading bounded frames.
    for _ in 0..header.accounts {
        expected.push(read_frame(input, limits.metadata_bytes, &mut remaining)?);
    }
    recover(
        store,
        header.stage,
        header.session,
        &header.source,
        relay,
        &expected,
    )
}

#[cfg(test)]
#[path = "migration_recovery_transfer_test.rs"]
mod tests;
