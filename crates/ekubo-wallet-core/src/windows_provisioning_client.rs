//! Privileged Windows installer transfer. No elevation, credential lookup,
//! service activation, or legacy deletion occurs here.
use crate::{
    config::WalletMetadata,
    custody_provisioning::MigrationAccount,
    migration_transfer::{self, Destination, StagingReply},
    policy_store::migration_database::MigrationDatabaseSnapshot,
    provisioning_io, windows_provisioning_pipe, windows_service_config,
};
use anyhow::Result;
use std::io::Write as _;
use zeroize::Zeroizing;

/// Retains the source database fence through the installer's later commit/abort.
/// The caller must retain its lifecycle lock too. A staging reply grants no
/// activation or legacy deletion authority and is not a durable commit receipt.
pub struct StagedSource {
    _snapshot: MigrationDatabaseSnapshot,
    reply: StagingReply,
}

impl StagedSource {
    #[must_use]
    pub const fn reply(&self) -> &StagingReply {
        &self.reply
    }
}

/// Transfer keys already supplied to the privileged installer. Protected
/// pending metadata and the connected native pipe are checked before writing
/// even the nonsecret preface. Errors never reconnect or replay the transfer.
pub async fn transfer(
    owner_sid: &str,
    database_key: Zeroizing<[u8; 32]>,
    expected: Vec<WalletMetadata>,
    accounts: Vec<MigrationAccount>,
    mut snapshot: MigrationDatabaseSnapshot,
) -> Result<StagedSource> {
    let identity = windows_service_config::pending_installer_identity(owner_sid)?;
    let pipe = windows_provisioning_pipe::connect(&identity).await?;
    let destination = Destination {
        owner: format!("windows:sid:{}", identity.owner_sid()),
        service: format!("windows:sid:{}", identity.service_sid()),
        profile: identity.profile_id(),
    };
    let (mut stream, _cancel) =
        provisioning_io::bridge(pipe, migration_transfer::INSTALLER_TIMEOUT);
    // The worker owns the source fence. Dropping the awaiting future cancels
    // native I/O, but the fence remains held until the worker actually exits.
    tokio::task::spawn_blocking(move || {
        stream.write_all(windows_provisioning_pipe::PREFACE)?;
        let session = migration_transfer::send(
            &mut stream,
            destination,
            database_key,
            &expected,
            accounts,
            &mut snapshot,
            migration_transfer::INSTALLER_LIMITS,
        )?;
        let reply = migration_transfer::read_reply(&mut stream, session)?;
        Ok(StagedSource {
            _snapshot: snapshot,
            reply,
        })
    })
    .await?
}
