//! Process-lifetime exclusion shared by protected Linux and Windows profiles.
//! The platform must validate the file and its ancestry before acquiring this
//! guard. Lock-file contents and process IDs never establish ownership.

use anyhow::{Context as _, Result};
use std::fs::File;

pub(crate) struct ProfileLock(File);

impl ProfileLock {
    pub(crate) fn acquire(file: File) -> Result<Self> {
        fs2::FileExt::try_lock_exclusive(&file)
            .context("could not exclusively lock the wallet service profile")?;
        Ok(Self(file))
    }
}

impl Drop for ProfileLock {
    fn drop(&mut self) {
        // Explicit release avoids waiting for delayed OS cleanup on shutdown.
        // Closing the owned file remains the fallback if unlock fails.
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

#[cfg(test)]
#[path = "service_profile_lock_test.rs"]
mod tests;
