//! Runtime file preparation inside a protected pending directory. These records
//! do not publish an installed profile or authorize legacy credential deletion.
use crate::{custody_staging::ServiceCredentialRecord, database_staging::DatabaseTransfer};
use anyhow::{Result, ensure};
use std::{
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
};
use zeroize::Zeroizing;

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// Only protected native pending roots can receive these opaque write requests.
pub trait PendingProfileStore: sealed::Sealed {
    fn prepare_record(&self, record: ProfileRecord<'_>) -> Result<()>;
}

/// An unforgeable-in-safe-code request constructed by core after verification.
/// No public constructor, path, or raw-key accessor is provided.
pub struct ProfileRecord<'a> {
    pub(crate) name: String,
    contents: Contents<'a>,
}

enum Contents<'a> {
    Bytes(&'a [u8]),
    Database {
        source: File,
        expected: &'a DatabaseTransfer,
    },
}

impl<'a> ProfileRecord<'a> {
    pub(crate) fn credential(record: ServiceCredentialRecord, bytes: &'a [u8]) -> Self {
        Self {
            name: record.file_name(),
            contents: Contents::Bytes(bytes),
        }
    }
    pub(crate) fn marker(bytes: &'a [u8]) -> Self {
        Self {
            name: "profile-ready.json".into(),
            contents: Contents::Bytes(bytes),
        }
    }
    pub(crate) fn database(source: File, expected: &'a DatabaseTransfer) -> Self {
        Self {
            name: "wallet.db".into(),
            contents: Contents::Database { source, expected },
        }
    }
    pub(crate) fn populate(&mut self, target: &mut File) -> Result<()> {
        match &mut self.contents {
            Contents::Bytes(bytes) => {
                target.write_all(bytes)?;
                Ok(())
            }
            Contents::Database { source, expected } => {
                source.seek(SeekFrom::Start(0))?;
                crate::database_staging::receive(expected, source, target)
            }
        }
    }
    pub(crate) fn verify(&self, target: &mut File) -> Result<()> {
        target.seek(SeekFrom::Start(0))?;
        match &self.contents {
            Contents::Bytes(expected) => {
                let mut bytes = Zeroizing::new(Vec::new());
                target
                    .take(u64::try_from(expected.len())? + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(
                    bytes.as_slice() == *expected,
                    "pending profile record differs from verified candidate"
                );
            }
            Contents::Database { expected, .. } => {
                ensure!(
                    DatabaseTransfer::describe(target)? == **expected,
                    "pending profile database differs from verified candidate"
                );
            }
        }
        Ok(())
    }
}
