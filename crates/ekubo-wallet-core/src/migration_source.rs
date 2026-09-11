//! Legacy credential collection, confined to core's authenticated native source
//! endpoints. Never expose this module, a collected key bundle, or its writer to
//! presentation/MCP. Run before local authority and background workers start.
use crate::{
    config::ConfigStore,
    custody_provisioning::MigrationAccount,
    migration_transfer::{self, Destination, INSTALLER_LIMITS, RecoveryCheckpoint},
    policy_store::{self, migration_database::MigrationDatabaseSnapshot},
};
use anyhow::{Result, ensure};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

fn destination() -> Result<Destination> {
    #[cfg(target_os = "linux")]
    {
        let identity = crate::service_storage::pending_owner_identity()?;
        Ok(Destination {
            owner: format!("linux:uid:{}", identity.owner_uid()),
            service: format!("linux:uid:{}", identity.service_uid()),
            profile: identity.profile_id(),
        })
    }
    #[cfg(target_os = "windows")]
    {
        let identity = crate::windows_service_config::pending_owner_identity()?;
        Ok(Destination {
            owner: format!("windows:sid:{}", identity.owner_sid()),
            service: format!("windows:sid:{}", identity.service_sid()),
            profile: identity.profile_id(),
        })
    }
}

fn existing_key(service: &str, user: &str) -> Result<Zeroizing<[u8; 32]>> {
    let entry = crate::credential_store::entry(service, user)?;
    ensure!(
        matches!(&entry, crate::credential_store::Entry::Platform(_)),
        "migration source requires the owner's platform credential store"
    );
    let bytes = Zeroizing::new(entry.get_secret()?);
    ensure!(bytes.len() == 32, "invalid legacy credential length");
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Only native endpoints call this, after authenticating the connected installer.
/// No source path or writer is accepted by the public native endpoint. The path
/// follows the existing desktop configuration, including its supported home
/// override. Missing credentials fail; no database/key initialization or upgrade.
pub(crate) fn serve(stream: &mut (impl Read + Write)) -> Result<()> {
    let destination = destination()?;
    let config = ConfigStore::production()?;
    config.with_lifecycle_lock(|| {
        // Revalidate protected pending metadata after acquiring lifecycle exclusion.
        ensure!(
            self::destination()? == destination,
            "pending source profile changed"
        );
        let directory = config.data_dir().canonicalize()?;
        let mut command = [0; 1];
        stream.read_exact(&mut command)?;
        match command[0] {
            0 => collect_and_transfer(
                stream,
                // Resolve the directory before freezing, without opening another
                // source file descriptor. Existing relative home overrides work too.
                &directory,
                destination,
                existing_key,
                crate::custody_relay::persist_pending,
            ),
            1 => {
                let checkpoint = RecoveryCheckpoint::read_source_request(stream, &destination)?;
                let relay = crate::custody_relay::load(destination.profile)?;
                recover_source(
                    stream,
                    &directory,
                    destination,
                    &checkpoint,
                    relay,
                    existing_key,
                )
            }
            _ => anyhow::bail!("unsupported source request"),
        }
    })
}

/// Called only by authenticated native installer adapters. This request selects
/// staging or recovery; it grants neither source access nor commit authority.
pub(crate) fn request(
    stream: &mut impl Write,
    checkpoint: Option<&RecoveryCheckpoint>,
) -> Result<()> {
    if let Some(checkpoint) = checkpoint {
        stream.write_all(&[1])?;
        checkpoint.write_source_request(stream)?;
    } else {
        stream.write_all(&[0])?;
        stream.flush()?;
    }
    Ok(())
}

fn recover_source(
    stream: &mut (impl Read + Write),
    data_dir: &Path,
    destination: Destination,
    checkpoint: &RecoveryCheckpoint,
    relay: crate::custody_envelope::WrappedDataKey,
    mut read: impl FnMut(&str, &str) -> Result<Zeroizing<[u8; 32]>>,
) -> Result<()> {
    checkpoint.journal_bytes(&destination)?;
    let database_key = read(policy_store::KEYRING_SERVICE, policy_store::KEYRING_USER)?;
    let snapshot = MigrationDatabaseSnapshot::freeze(
        &data_dir.join(policy_store::DATABASE_FILE),
        database_key,
    )?;
    let expected = snapshot.wallet_inventory()?;
    // The existing checkpoint exchange checks the live logical fingerprint
    // before sending any relay, preserving the original ciphertext descriptor.
    checkpoint.exchange(stream, destination, &snapshot, relay, &expected)?;
    checkpoint.write_source_request(stream)?;
    retain_until_abort(stream)
}

// Dependency injection stays private to core. Tests use synthetic keys and an
// isolated database; no public callback can observe production credentials.
fn collect_and_transfer(
    stream: &mut (impl Read + Write),
    data_dir: &Path,
    destination: Destination,
    mut read: impl FnMut(&str, &str) -> Result<Zeroizing<[u8; 32]>>,
    persist: impl FnOnce(uuid::Uuid, &crate::custody_envelope::WrappedDataKey) -> Result<()>,
) -> Result<()> {
    let database_key = read(policy_store::KEYRING_SERVICE, policy_store::KEYRING_USER)?;
    let mut snapshot = MigrationDatabaseSnapshot::freeze(
        &data_dir.join(policy_store::DATABASE_FILE),
        database_key.clone(),
    )?;
    let expected = snapshot.wallet_inventory()?;
    ensure!(
        u64::try_from(expected.len())? <= INSTALLER_LIMITS.accounts,
        "source account limit exceeded"
    );
    let accounts = expected
        .iter()
        .map(|wallet| {
            Ok(MigrationAccount {
                wallet: wallet.clone(),
                key: read(
                    crate::custody::KEYRING_SERVICE,
                    &wallet.instance_id.to_string(),
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let session = migration_transfer::send(
        stream,
        destination.clone(),
        database_key,
        &expected,
        accounts,
        &mut snapshot,
        INSTALLER_LIMITS,
    )?;
    let reply = migration_transfer::read_reply(stream, session)?;
    persist(destination.profile, reply.relay())?;
    reply.write_source_checkpoint(stream, destination, &mut snapshot)?;
    // Staging is not cutover. Retain both locks until explicit abort, stream
    // failure or the native deadline. No commit command exists yet, and the
    // installer must not promote a profile using this temporary retention.
    retain_until_abort(stream)
}

fn retain_until_abort(stream: &mut impl Read) -> Result<()> {
    let mut command = [0; 1];
    stream.read_exact(&mut command)?;
    ensure!(command == [0], "unsupported source control command");
    Ok(())
}

#[cfg(test)]
#[path = "migration_source_test.rs"]
mod tests;
