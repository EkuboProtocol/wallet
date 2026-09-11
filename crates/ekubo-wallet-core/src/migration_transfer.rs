//! Shared provisioning stream for protected pending Linux/Windows stores.
//!
//! This codec does not authenticate a transport. Platform hosts must establish
//! the actual OS peer, authorize provisioning, bound admission and enforce an
//! overall deadline before calling it. Senders must authenticate the protected
//! destination before sending ANY bytes: matching a header is not authentication.
//! No ordinary owner RPC or MCP endpoint exposes this stream.
use crate::{
    config::WalletMetadata,
    custody_envelope::WrappedDataKey,
    custody_provisioning::{MigrationAccount, PreparedServiceCredentials, validate_accounts},
    custody_staging::{CredentialStage, CredentialStagingStore, StagedRecord},
    database_staging::{DatabaseStagingStore, DatabaseTransfer},
    policy_store::migration_database::MigrationDatabaseSnapshot,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::{Read, Write};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"EKUBOPR1";
const MAX_HEADER_BYTES: u32 = 4096;

#[path = "migration_recovery_transfer.rs"]
mod recovery_transfer;
pub(crate) use recovery_transfer::exchange as recover_exchange;
pub use recovery_transfer::{RecoveryRequest, send_recovery};

/// Admission policy comes from the host, never from the incoming stream.
/// Separate account-count and aggregate-metadata bounds avoid many small frames
/// defeating the per-frame limit. Database bytes are streamed, not accumulated.
#[derive(Clone, Copy)]
pub struct TransferLimits {
    pub accounts: u64,
    pub metadata_bytes: u32,
    pub total_metadata_bytes: u64,
    pub database_bytes: u64,
}

/// Shared installer admission policy for native Linux and Windows hosts.
pub const INSTALLER_LIMITS: TransferLimits = TransferLimits {
    accounts: 100_000,
    metadata_bytes: 16 * 1024,
    total_metadata_bytes: 64 * 1024 * 1024,
    database_bytes: 16 * 1024 * 1024 * 1024,
};
/// Native adapters must cancel I/O on expiry, not merely abandon an async waiter.
pub const INSTALLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Public identity obtained from protected installer configuration. These strings
/// bind the transfer to its destination; they cannot establish peer provenance.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub owner: String,
    pub service: String,
    pub profile: Uuid,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    session: Uuid,
    destination: Destination,
    accounts: u64,
    database: DatabaseTransfer,
}

impl Header {
    fn validate(&self, limits: TransferLimits) -> Result<()> {
        ensure!(!self.session.is_nil(), "invalid provisioning session");
        ensure!(
            !self.destination.profile.is_nil(),
            "invalid provisioning profile"
        );
        ensure!(
            self.accounts <= limits.accounts,
            "provisioning account limit exceeded"
        );
        ensure!(
            self.database.bytes != 0 && self.database.bytes <= limits.database_bytes,
            "provisioning database limit exceeded"
        );
        Ok(())
    }
}

/// Data transfer only. The caller retains the source fence and lifecycle lock
/// until the later durable commit/abort, including after this function returns.
/// Raw input is deliberate: no opaque core key can be exported through this API.
pub fn send(
    output: &mut impl Write,
    destination: Destination,
    database_key: Zeroizing<[u8; 32]>,
    expected: &[WalletMetadata],
    accounts: Vec<MigrationAccount>,
    snapshot: &mut MigrationDatabaseSnapshot,
    limits: TransferLimits,
) -> Result<Uuid> {
    validate_accounts(expected, &accounts)?;
    let header = Header {
        session: Uuid::new_v4(),
        destination,
        accounts: u64::try_from(accounts.len())?,
        database: snapshot.transfer()?,
    };
    header.validate(limits)?;
    // Preflight every metadata frame before any key is transmitted. The small
    // temporary JSON buffers contain public metadata only, never key bytes.
    let mut remaining = limits.total_metadata_bytes;
    for account in &accounts {
        let bytes = encode(&account.wallet, limits.metadata_bytes)?;
        consume_budget(&mut remaining, bytes.len())?;
    }
    let encoded_header = encode(&header, MAX_HEADER_BYTES)?;
    output.write_all(MAGIC)?;
    write_frame(output, &encoded_header)?;
    output.write_all(database_key.as_slice())?;
    drop(database_key);
    for account in accounts {
        write_frame(output, &encode(&account.wallet, limits.metadata_bytes)?)?;
        output.write_all(account.key.as_slice())?;
    }
    ensure!(
        snapshot.write_to(output)? == header.database.bytes,
        "snapshot length changed"
    );
    output.flush()?;
    Ok(header.session)
}

/// Holds prepared custody inside the service and borrows the protected pending
/// root through the next installer phase. No raw key, wrapping key or enrollment
/// records are exposed. This is not an activation or legacy-deletion receipt.
pub struct ReceivedCandidate<'a, S> {
    _store: &'a S,
    prepared: PreparedServiceCredentials,
    stage: CredentialStage,
    session: Uuid,
    canonical: DatabaseTransfer,
}

/// Durable staging evidence for later recovery. No field authorizes activation:
/// recovery must revalidate protected storage, credentials and database contents.
/// The source descriptor binds the frozen transfer, not a live source pathname.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRecord {
    version: u8,
    session: Uuid,
    destination: Destination,
    source: DatabaseTransfer,
    credentials: CredentialStage,
    canonical: DatabaseTransfer,
    // Persist only the digest. The envelope must stay in the login keyring,
    // separate from the service's wrapping key, including during recovery.
    relay_digest: [u8; 32],
}

fn persist_candidate(store: &impl CredentialStagingStore, record: &CandidateRecord) -> Result<()> {
    let bytes = encode(record, MAX_HEADER_BYTES)?;
    let stage = record.credentials.id();
    store.create_new(stage, StagedRecord::Candidate, &bytes)?;
    ensure!(
        store.read(stage, StagedRecord::Candidate)?.as_slice() == bytes,
        "migration candidate readback mismatch"
    );
    Ok(())
}

/// Revalidate an existing stage after losing in-memory preparation. The host must
/// authenticate the installer and hold the native pending root lock. Session and
/// source describe the original transfer; this does not fence/revalidate the live
/// legacy wallet, persist the login relay, activate custody, or authorize deletion.
/// The relay must be supplied separately, never recovered from service storage.
pub fn recover<'a, S: CredentialStagingStore + DatabaseStagingStore>(
    store: &'a S,
    stage: Uuid,
    session: Uuid,
    source: &DatabaseTransfer,
    relay: WrappedDataKey,
    expected: &[WalletMetadata],
) -> Result<ReceivedCandidate<'a, S>> {
    ensure!(
        !stage.is_nil()
            && !session.is_nil()
            && u64::try_from(expected.len())? <= INSTALLER_LIMITS.accounts,
        "invalid recovery request"
    );
    let bytes = store.read(stage, StagedRecord::Candidate)?;
    ensure!(
        bytes.len() <= MAX_HEADER_BYTES as usize,
        "recovery record is oversized"
    );
    let record: CandidateRecord = serde_json::from_slice(&bytes)?;
    let (owner, service, profile) = store.identity();
    ensure!(
        record.version == 1
            && record.session == session
            && record.credentials.id() == stage
            && record.destination
                == Destination {
                    owner,
                    service,
                    profile
                }
            && record.source == *source
            && record.source.bytes != 0
            && record.canonical.bytes != 0
            && record.relay_digest == relay.digest(),
        "recovery candidate binding mismatch"
    );
    ensure!(
        store.staged_database(stage)?.transfer()? == record.source,
        "recovery source snapshot changed"
    );
    let prepared = PreparedServiceCredentials::restore(
        store,
        &record.credentials,
        relay,
        expected,
        &record.canonical,
    )?;
    Ok(ReceivedCandidate {
        _store: store,
        prepared,
        stage: record.credentials,
        session,
        canonical: record.canonical,
    })
}

impl<S> ReceivedCandidate<'_, S> {
    /// Send only a staged result over the same authenticated provisioning stream.
    /// A successful reply is not permission to activate or delete legacy keys.
    pub fn write_reply(&self, output: &mut impl Write) -> Result<()> {
        let reply = Reply {
            session: self.session,
            stage: self.stage.id(),
            canonical: self.canonical.clone(),
            relay: hex::encode(self.prepared.relay().as_bytes()),
        };
        write_frame(output, &encode(&reply, MAX_HEADER_BYTES)?)?;
        output.flush()?;
        Ok(())
    }
    #[must_use]
    pub const fn session(&self) -> Uuid {
        self.session
    }
    #[must_use]
    pub const fn stage(&self) -> Uuid {
        self.stage.id()
    }
    #[must_use]
    pub const fn canonical(&self) -> &DatabaseTransfer {
        &self.canonical
    }
    /// Enrolled ciphertext for separate persistence in the desktop login keyring.
    #[must_use]
    pub fn relay(&self) -> &WrappedDataKey {
        self.prepared.relay()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    session: Uuid,
    stage: Uuid,
    canonical: DatabaseTransfer,
    relay: String,
}

/// Installer-visible staged result. Contains only relay ciphertext, never a
/// usable key. Not an activation, recovery or legacy-credential deletion proof.
pub struct StagingReply {
    session: Uuid,
    stage: Uuid,
    canonical: DatabaseTransfer,
    relay: WrappedDataKey,
}

impl StagingReply {
    /// Original authenticated transfer identity for the installer's journal.
    /// Retaining it grants no recovery, activation or legacy-deletion authority.
    #[must_use]
    pub const fn session(&self) -> Uuid {
        self.session
    }

    #[must_use]
    pub const fn stage(&self) -> Uuid {
        self.stage
    }
    #[must_use]
    pub const fn canonical(&self) -> &DatabaseTransfer {
        &self.canonical
    }
    #[must_use]
    pub const fn relay(&self) -> &WrappedDataKey {
        &self.relay
    }
}

/// Read the reply from the already authenticated destination, binding it to the
/// exact session returned by send. A missing reply leaves an ambiguous stage.
pub fn read_reply(input: &mut impl Read, session: Uuid) -> Result<StagingReply> {
    let mut budget = u64::from(MAX_HEADER_BYTES);
    let reply: Reply = read_frame(input, MAX_HEADER_BYTES, &mut budget)?;
    ensure!(
        !session.is_nil() && reply.session == session,
        "provisioning reply session mismatch"
    );
    ensure!(
        !reply.stage.is_nil() && reply.canonical.bytes != 0,
        "invalid provisioning reply"
    );
    ensure!(
        reply.relay.len() == crate::custody_envelope::SEALED_KEY_BYTES * 2,
        "invalid provisioning relay length"
    );
    let relay = WrappedDataKey::from_bytes(&hex::decode(reply.relay)?)?;
    Ok(StagingReply {
        session: reply.session,
        stage: reply.stage,
        canonical: reply.canonical,
        relay,
    })
}

/// Consume one transfer or recovery request from an already authorized transport.
/// Trailing protocol bytes remain unread. Errors may leave immutable pending
/// records, which require recovery; they never create active wallet state.
pub fn receive<'a, S: CredentialStagingStore + DatabaseStagingStore>(
    store: &'a S,
    input: &mut impl Read,
    limits: TransferLimits,
) -> Result<ReceivedCandidate<'a, S>> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if &magic == recovery_transfer::MAGIC {
        return recovery_transfer::receive(store, input, limits);
    }
    ensure!(&magic == MAGIC, "unsupported provisioning protocol");
    let mut header_budget = u64::from(MAX_HEADER_BYTES);
    let header: Header = read_frame(input, MAX_HEADER_BYTES, &mut header_budget)?;
    header.validate(limits)?;
    let (owner, service, profile) = store.identity();
    ensure!(
        header.destination
            == Destination {
                owner: owner.clone(),
                service: service.clone(),
                profile
            },
        "provisioning destination mismatch"
    );
    let database_key = read_key(input)?;
    let mut remaining = limits.total_metadata_bytes;
    let mut accounts = Vec::new();
    // Do not reserve from a remote count. Each allocation follows a bounded,
    // successfully read frame; limits cover accumulated metadata and keys.
    for _ in 0..header.accounts {
        accounts.push(MigrationAccount {
            wallet: read_frame(input, limits.metadata_bytes, &mut remaining)?,
            key: read_key(input)?,
        });
    }
    let expected: Vec<_> = accounts
        .iter()
        .map(|account| account.wallet.clone())
        .collect();
    let prepared = PreparedServiceCredentials::prepare(
        &owner,
        &service,
        profile,
        database_key,
        &expected,
        accounts,
    )?;
    let stage = prepared.stage(store)?;
    store.receive_database(stage.id(), &header.database, input)?;
    let canonical = prepared.rebuild_staged_database(store, &stage)?;
    // Publish last, only after credential and database validation. A lost reply
    // then leaves a durable session-to-candidate mapping. Publication/readback
    // failure is ambiguous and must not produce a successful staging reply.
    persist_candidate(
        store,
        &CandidateRecord {
            version: 1,
            session: header.session,
            destination: header.destination.clone(),
            source: header.database.clone(),
            credentials: stage.clone(),
            canonical: canonical.clone(),
            relay_digest: prepared.relay().digest(),
        },
    )?;
    Ok(ReceivedCandidate {
        _store: store,
        prepared,
        stage,
        session: header.session,
        canonical,
    })
}

fn read_key(input: &mut impl Read) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    input.read_exact(key.as_mut())?;
    Ok(key)
}

fn consume_budget(remaining: &mut u64, bytes: usize) -> Result<()> {
    *remaining = remaining
        .checked_sub(u64::try_from(bytes)?)
        .ok_or_else(|| anyhow::anyhow!("provisioning metadata budget exceeded"))?;
    Ok(())
}

fn encode(value: &impl Serialize, limit: u32) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= usize::try_from(limit)?,
        "provisioning frame limit exceeded"
    );
    Ok(bytes)
}

fn write_frame(output: &mut impl Write, bytes: &[u8]) -> Result<()> {
    output.write_all(&u32::try_from(bytes.len())?.to_le_bytes())?;
    output.write_all(bytes)?;
    Ok(())
}

fn read_frame<T: DeserializeOwned>(
    input: &mut impl Read,
    limit: u32,
    remaining: &mut u64,
) -> Result<T> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length);
    ensure!(
        length != 0 && length <= limit,
        "invalid provisioning frame length"
    );
    let length = usize::try_from(length)?;
    consume_budget(remaining, length)?;
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    // Never reflect potentially hostile frame contents in diagnostics.
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid provisioning frame"))
}

#[cfg(test)]
#[path = "migration_transfer_test.rs"]
mod tests;
