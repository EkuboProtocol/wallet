//! Framed ciphertext transfer into pending protected storage. Length and digest
//! establish transfer integrity only, not `SQLCipher` validity, owner authorization,
//! activation, or permission to delete legacy credentials.
use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    io::{Read, Seek as _, SeekFrom, Write as _},
};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseTransfer {
    pub bytes: u64,
    pub sha256: [u8; 32],
}
impl DatabaseTransfer {
    /// Describe an already-encrypted stream. No key is read or exported.
    pub fn describe(input: &mut impl Read) -> Result<Self> {
        let mut sha = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0; 16 * 1024];
        loop {
            let read = match input.read(&mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if read == 0 {
                break;
            }
            bytes = bytes
                .checked_add(u64::try_from(read)?)
                .ok_or_else(|| anyhow::anyhow!("database transfer is oversized"))?;
            sha.update(&buffer[..read]);
        }
        ensure!(bytes != 0, "database transfer is empty");
        Ok(Self {
            bytes,
            sha256: sha.finalize().into(),
        })
    }
}

/// Only native pending roots implement this production interface. A staged file
/// is still untrusted until database and credential inventory verification.
pub trait DatabaseStagingStore {
    fn receive_database(
        &self,
        stage: Uuid,
        transfer: &DatabaseTransfer,
        input: &mut dyn Read,
    ) -> Result<()>;
    fn open_staged_database(&self, stage: Uuid) -> Result<File>;
    fn staged_database(&self, stage: Uuid) -> Result<StagedDatabase<'_>>;
    fn create_canonical_database(&self, stage: Uuid) -> Result<CanonicalDatabase<'_>>;
    fn canonical_database(&self, stage: Uuid) -> Result<StagedDatabase<'_>>;
}

/// A native-validated read-only file pin and its protected pathname. Its borrow
/// keeps the pending root (including Windows ancestor pins) alive during use.
pub struct StagedDatabase<'a> {
    path: std::path::PathBuf,
    file: File,
    _root: std::marker::PhantomData<&'a ()>,
}
impl<'a> StagedDatabase<'a> {
    pub(crate) fn new(
        path: std::path::PathBuf,
        file: File,
        _root: &'a impl DatabaseStagingStore,
    ) -> Self {
        Self {
            path,
            file,
            _root: std::marker::PhantomData,
        }
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub(crate) fn reader(&self) -> Result<File> {
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
    pub(crate) fn transfer(&self) -> Result<DatabaseTransfer> {
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        DatabaseTransfer::describe(&mut file)
    }
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

type Publish<'a> = Box<dyn FnOnce(&File, &mut bool) -> Result<()> + 'a>;
type Discard<'a> = Box<dyn Fn(&File) -> Result<()> + 'a>;

/// An unpublished native file. Only core can populate/publish it; dropping an
/// unfinished build discards its temporary name. This is not activation authority.
pub struct CanonicalDatabase<'a> {
    path: std::path::PathBuf,
    file: File,
    publish: Option<Publish<'a>>,
    discard: Discard<'a>,
    published: bool,
    _root: std::marker::PhantomData<&'a ()>,
}
impl<'a> CanonicalDatabase<'a> {
    pub(crate) fn new(
        path: std::path::PathBuf,
        file: File,
        publish: impl FnOnce(&File, &mut bool) -> Result<()> + 'a,
        discard: impl Fn(&File) -> Result<()> + 'a,
        _root: &'a impl DatabaseStagingStore,
    ) -> Self {
        Self {
            path,
            file,
            publish: Some(Box::new(publish)),
            discard: Box::new(discard),
            published: false,
            _root: std::marker::PhantomData,
        }
    }
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
    pub(crate) fn file(&self) -> &File {
        &self.file
    }
    pub(crate) fn publish(mut self) -> Result<()> {
        self.file.sync_all()?;
        self.publish.take().expect("publication is single-use")(&self.file, &mut self.published)
    }
}
impl Drop for CanonicalDatabase<'_> {
    fn drop(&mut self) {
        if !self.published {
            let _ = (self.discard)(&self.file);
        }
    }
}

pub(crate) fn canonical_file_name(stage: Uuid) -> Result<String> {
    ensure!(!stage.is_nil(), "invalid canonical database stage identity");
    Ok(format!("custody-stage-{stage}-canonical.db"))
}

pub(crate) fn file_name(stage: Uuid) -> Result<String> {
    ensure!(!stage.is_nil(), "invalid database stage identity");
    Ok(format!("custody-stage-{stage}-wallet.db"))
}

/// Consume exactly the declared frame length, leaving subsequent protocol bytes
/// unread. The transport must bound admission/time and authenticate the sender.
/// Verify the actual temporary handle before the native store publishes its name.
pub(crate) fn receive(
    transfer: &DatabaseTransfer,
    input: &mut dyn Read,
    output: &mut File,
) -> Result<()> {
    ensure!(transfer.bytes != 0, "database transfer is empty");
    let mut remaining = transfer.bytes;
    let mut sha = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    while remaining != 0 {
        let length = usize::try_from(remaining.min(buffer.len() as u64))?;
        input.read_exact(&mut buffer[..length])?;
        output.write_all(&buffer[..length])?;
        sha.update(&buffer[..length]);
        remaining -= u64::try_from(length)?;
    }
    ensure!(
        <[u8; 32]>::from(sha.finalize()) == transfer.sha256,
        "database transfer digest mismatch"
    );
    output.sync_all()?;
    output.seek(SeekFrom::Start(0))?;
    ensure!(
        DatabaseTransfer::describe(output)? == *transfer,
        "database transfer readback mismatch"
    );
    Ok(())
}

#[cfg(test)]
#[path = "database_staging_test.rs"]
mod tests;
