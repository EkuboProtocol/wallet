//! A throwaway session whose database key never reaches the OS credential
//! store.
//!
//! The credential store is machine-wide: the database key lives under one
//! service and account name, not under the data directory that happens to be
//! in use. `--data-dir` therefore gives a separate *database* while still
//! reaching for the same key, which on a locked keychain blocks on a dialog —
//! so a non-interactive shell cannot start the server at all, and a scratch
//! directory is not actually isolated from the real wallet's credential.
//!
//! Enabling this keeps the key in the scratch directory instead, so a session
//! can be created, used, and discarded with `rm -rf` leaving no trace in the
//! credential store.
//!
//! This entire module is compiled out of release builds, and that is the whole
//! of the safety argument — the same one `test-hooks` makes one file over. A
//! key sitting beside the database it decrypts is not protection; it is a
//! convenience for a directory that holds nothing worth protecting. Two things
//! keep it that way: the CLI refuses to enable it without an explicit
//! `--data-dir`, so it can never fall back to the real wallet's directory, and
//! [`crate::custody`] refuses the credential store entirely while it is on, so
//! a scratch session cannot leave an orphaned private key behind either.

use crate::config::{create_private_dir, set_private_handle_permissions};
use crate::policy_store::DatabaseKey;
use anyhow::{Context, Result, ensure};
use rand::TryRng as _;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize as _;

/// The database key, beside the database it opens.
pub(crate) const KEY_FILE: &str = "ephemeral-db.key";

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Turn this session ephemeral. Called once, from argument parsing, before
/// anything opens a store.
pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

#[must_use]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// The database key for an ephemeral session, or `None` when this is an
/// ordinary session and the credential store is the right place to look.
pub(crate) fn database_key(data_dir: &Path, database_exists: bool) -> Result<Option<DatabaseKey>> {
    if !is_enabled() {
        return Ok(None);
    }
    key_in_dir(data_dir, database_exists).map(Some)
}

/// The whole of the behaviour, separated from the flag that selects it.
///
/// [`ENABLED`] is process-global, so a test that switched it on would switch
/// it on for every test sharing the process — including the custody ones that
/// assert the credential store *is* reached. Tests call this instead and never
/// touch the flag.
fn key_in_dir(data_dir: &Path, database_exists: bool) -> Result<DatabaseKey> {
    create_private_dir(data_dir)?;
    let path = data_dir.join(KEY_FILE);

    match OpenOptions::new().read(true).open(&path) {
        Ok(mut file) => {
            // Length-checked here rather than through `DatabaseKey::from_slice`,
            // which is private: a debug convenience has no business widening
            // the kernel's surface to make itself work.
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let sized = <[u8; 32]>::try_from(bytes.as_slice());
            bytes.zeroize();
            let mut sized =
                sized.with_context(|| format!("{} is not a 32-byte key", path.display()))?;
            let key = DatabaseKey::new(sized);
            sized.zeroize();
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The same rule the credential-store path enforces: a database
            // that exists without its key is state loss, not a reason to
            // generate a fresh one and report a working empty wallet.
            ensure!(
                !database_exists,
                "{} holds a policy database but no {KEY_FILE}; this session cannot open it and it \
was never recoverable — delete the directory and start a new one",
                data_dir.display()
            );
            let mut bytes = [0_u8; 32];
            // ThreadRng's error type is Infallible, so Ok is irrefutable.
            let Ok(()) = rand::rng().try_fill_bytes(&mut bytes);
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            set_private_handle_permissions(&file)?;
            let written = file
                .write_all(&bytes)
                .and_then(|()| file.sync_all())
                .with_context(|| format!("failed to write {}", path.display()));
            let key = DatabaseKey::new(bytes);
            bytes.zeroize();
            written.map(|()| key)
        }
        Err(error) => Err(error).with_context(|| format!("failed to open {}", path.display())),
    }
}

#[cfg(test)]
#[path = "ephemeral_test.rs"]
mod tests;
