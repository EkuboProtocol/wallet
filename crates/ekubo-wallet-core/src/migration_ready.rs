//! Quiescent runtime-file verification for the privileged installer. Native
//! callers hold installer/service locks and validate every opened file handle.
//! This checks preparation evidence, not live source validity or cutover authority.
use crate::{
    custody_staging::CredentialStage,
    installer_checkpoint::{CandidateRecord, MAX_ACCOUNTS, RecoveryCheckpoint},
};
use crate::{
    custody_staging::{ServiceCredentialRecord, StagedRecord},
    database_staging::DatabaseTransfer,
};
use anyhow::{Result, ensure};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, fs::File, io::Read as _};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
    Pending,
    Promoted,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u8,
    session: Uuid,
    credentials: CredentialStage,
    canonical: DatabaseTransfer,
}

/// Names come from an OS-pinned private directory, never IPC. Only canonical
/// runtime account names contribute to the inventory; staging files stay separate.
pub(crate) fn account_instances(
    names: impl IntoIterator<Item = Result<std::ffi::OsString>>,
) -> Result<BTreeSet<Uuid>> {
    let mut accounts = BTreeSet::new();
    let mut entries = 0u64;
    for name in names {
        entries += 1;
        // A full candidate has both staged and runtime credentials. Refuse an
        // unbounded directory even when most names do not describe accounts.
        ensure!(
            entries <= MAX_ACCOUNTS * 3 + 64,
            "pending profile has too many entries"
        );
        let name = name?;
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid pending file name"))?;
        // Every service-generated name is ASCII. Reject aliases that a
        // case-insensitive filesystem could resolve through a different spelling.
        ensure!(name.is_ascii(), "noncanonical pending file name");
        let folded = name.to_ascii_lowercase();
        if folded.starts_with("wallet.db") {
            ensure!(name == "wallet.db", "unexpected runtime database sidecar");
        }
        let Some(instance) = name.strip_prefix("key-account-") else {
            ensure!(
                !folded.starts_with("key-account-"),
                "noncanonical account file name"
            );
            continue;
        };
        let id: Uuid = instance.parse()?;
        ensure!(
            !id.is_nil() && id.to_string() == instance,
            "invalid runtime account file name"
        );
        ensure!(accounts.insert(id), "duplicate runtime account identity");
        ensure!(
            u64::try_from(accounts.len())? <= MAX_ACCOUNTS,
            "too many runtime accounts"
        );
    }
    Ok(accounts)
}

pub(crate) fn verify_ready(
    checkpoint: &RecoveryCheckpoint,
    accounts: &BTreeSet<Uuid>,
    mut open: impl FnMut(&str) -> Result<File>,
) -> Result<()> {
    checkpoint.journal_bytes(&checkpoint.destination)?;
    let candidate: CandidateRecord = serde_json::from_slice(&small(
        &mut open,
        &StagedRecord::Candidate.file_name(checkpoint.stage)?,
    )?)?;
    ensure!(
        candidate.version == 1
            && candidate.destination == checkpoint.destination
            && candidate.session == checkpoint.session
            && candidate.credentials.id() == checkpoint.stage
            && candidate.source == checkpoint.source
            && candidate.canonical == checkpoint.canonical
            && candidate.relay_digest == checkpoint.relay_digest,
        "prepared candidate differs from installer checkpoint"
    );
    let complete: CredentialStage = serde_json::from_slice(&small(
        &mut open,
        &StagedRecord::Complete.file_name(checkpoint.stage)?,
    )?)?;
    let ready: Ready = serde_json::from_slice(&small(&mut open, "profile-ready.json")?)?;
    ensure!(
        complete == candidate.credentials
            && complete.version == 1
            && complete.records == u64::try_from(accounts.len())? + 3
            && ready.version == 1
            && ready.session == checkpoint.session
            && ready.credentials == complete
            && ready.canonical == checkpoint.canonical,
        "runtime preparation markers disagree"
    );
    let mut digest = Sha256::new();
    let records = [
        ServiceCredentialRecord::WrappingKey,
        ServiceCredentialRecord::Enrollment,
        ServiceCredentialRecord::DatabaseKey,
    ]
    .into_iter()
    .chain(
        accounts
            .iter()
            .copied()
            .map(ServiceCredentialRecord::AccountKey),
    );
    for record in records {
        let bytes = small(&mut open, &record.file_name())?;
        let staged = small(
            &mut open,
            &StagedRecord::Credential(record).file_name(checkpoint.stage)?,
        )?;
        ensure!(bytes == staged, "runtime credential differs from staging");
        crate::custody_staging::digest_record(&mut digest, record, &bytes)?;
    }
    let actual: [u8; 32] = digest.finalize().into();
    ensure!(
        actual == complete.digest,
        "runtime credential inventory changed"
    );
    for (name, expected) in [
        ("wallet.db".to_owned(), &checkpoint.canonical),
        (
            crate::database_staging::canonical_file_name(checkpoint.stage)?,
            &checkpoint.canonical,
        ),
        (
            crate::database_staging::file_name(checkpoint.stage)?,
            &checkpoint.source,
        ),
    ] {
        let mut file = open(&name)?;
        ensure!(
            file.metadata()?.len() == expected.bytes,
            "prepared database length changed"
        );
        ensure!(
            DatabaseTransfer::describe(&mut file)? == *expected,
            "prepared database bytes changed"
        );
    }
    Ok(())
}

fn small(open: &mut impl FnMut(&str) -> Result<File>, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let file = open(name)?;
    ensure!(
        file.metadata()?.len() <= 4096,
        "prepared record is oversized"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "prepared record is oversized");
    Ok(bytes)
}

#[cfg(test)]
#[path = "migration_ready_test.rs"]
mod tests;
