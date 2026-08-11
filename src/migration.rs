//! One-way boundary between the terminal-era and desktop-era data layouts.

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use fs2::FileExt as _;
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

const DESKTOP_MARKER: &str = ".desktop-schema-v1";
const LEGACY_MARKERS: &[&str] = &["policies.db", "config.json", "policies.lock"];

/// Archive an existing terminal-era directory and create a clean desktop one.
///
/// The rename is atomic within the parent directory. No file is copied and no
/// legacy database is opened, so failure cannot produce a partially imported
/// wallet. Credential-store entries are deliberately outside this operation.
pub fn prepare_desktop_data_dir(data_dir: &Path) -> Result<Option<PathBuf>> {
    let parent = data_dir
        .parent()
        .context("wallet data directory has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let lock_path = parent.join(".ekubo-wallet-desktop-migration.lock");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open {}", lock_path.display()))?;
    lock.lock_exclusive()
        .with_context(|| format!("failed to lock {}", lock_path.display()))?;

    let result = prepare_locked(data_dir, parent);
    let _ = lock.unlock();
    result
}

fn prepare_locked(data_dir: &Path, parent: &Path) -> Result<Option<PathBuf>> {
    if data_dir.join(DESKTOP_MARKER).is_file()
        || data_dir
            .join(ekubo_wallet_core::policy_store::DATABASE_FILE)
            .is_file()
    {
        return Ok(None);
    }
    let legacy = data_dir.is_dir()
        && LEGACY_MARKERS
            .iter()
            .any(|marker| data_dir.join(marker).exists());

    let archived = if legacy {
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
        let mut suffix = 0_u16;
        let target = loop {
            let name = if suffix == 0 {
                format!("legacy-pre-desktop-{stamp}")
            } else {
                format!("legacy-pre-desktop-{stamp}-{suffix}")
            };
            let candidate = parent.join(name);
            if !candidate.exists() {
                break candidate;
            }
            suffix = suffix.checked_add(1).context("too many legacy archives")?;
        };
        fs::rename(data_dir, &target).with_context(|| {
            format!(
                "failed to archive legacy wallet directory {} as {}",
                data_dir.display(),
                target.display()
            )
        })?;
        Some(target)
    } else {
        None
    };

    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;
    let marker_path = data_dir.join(DESKTOP_MARKER);
    let mut marker = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker_path)
        .with_context(|| format!("failed to create {}", marker_path.display()))?;
    marker.write_all(b"1\n")?;
    marker.sync_all()?;
    ensure!(
        marker_path.is_file(),
        "desktop migration marker was not created"
    );
    Ok(archived)
}

#[cfg(test)]
#[path = "migration_test.rs"]
mod tests;
