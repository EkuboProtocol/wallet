//! Native no-replace publication of one service-created `SQLCipher` database.
use anyhow::{Result, ensure};
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub trait DatabaseStagingStore {
    fn create_canonical_database(&self, profile: Uuid) -> Result<CanonicalDatabase<'_>>;
}
type Publish<'a> = Box<dyn FnOnce(&File, &mut bool) -> Result<()> + 'a>;
type Discard<'a> = Box<dyn Fn(&File) -> Result<()> + 'a>;
pub struct CanonicalDatabase<'a> {
    path: PathBuf,
    file: File,
    publish: Option<Publish<'a>>,
    discard: Discard<'a>,
    published: bool,
}
impl<'a> CanonicalDatabase<'a> {
    pub(crate) fn new(
        path: PathBuf,
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
        }
    }
    pub(crate) fn path(&self) -> &Path {
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
pub(crate) fn canonical_file_name(profile: Uuid) -> Result<String> {
    ensure!(!profile.is_nil(), "invalid fresh profile identity");
    Ok("wallet.db".into())
}
