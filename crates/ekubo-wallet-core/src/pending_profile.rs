//! Closed, core-constructed records for a fresh protected profile.
use crate::custody_staging::ServiceCredentialRecord;
use anyhow::{Result, ensure};
use std::{
    fs::File,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
};
use zeroize::Zeroizing;

pub(crate) mod sealed {
    pub trait Sealed {}
}
pub trait PendingProfileStore: sealed::Sealed {
    fn prepare_record(&self, record: ProfileRecord<'_>) -> Result<()>;
}
pub struct ProfileRecord<'a> {
    pub(crate) name: String,
    bytes: &'a [u8],
}
impl<'a> ProfileRecord<'a> {
    pub(crate) fn credential(record: ServiceCredentialRecord, bytes: &'a [u8]) -> Self {
        Self {
            name: record.file_name(),
            bytes,
        }
    }
    pub(crate) fn marker(bytes: &'a [u8]) -> Self {
        Self {
            name: "fresh-profile-ready".into(),
            bytes,
        }
    }
    pub(crate) fn populate(&mut self, target: &mut File) -> Result<()> {
        target.write_all(self.bytes)?;
        Ok(())
    }
    pub(crate) fn verify(&self, target: &mut File) -> Result<()> {
        target.seek(SeekFrom::Start(0))?;
        let mut bytes = Zeroizing::new(Vec::new());
        target
            .take(u64::try_from(self.bytes.len())? + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.as_slice() == self.bytes,
            "fresh profile record changed"
        );
        Ok(())
    }
}
