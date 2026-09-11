//! Source-side encrypted database transfer. This is not service activation or
//! authority to delete credentials. Callers must already hold the raw database
//! key, quiesce application workers, and hold the account lifecycle lock for the
//! entire migration. The `SQLCipher` connection fences database writes until drop.
//! Do not open/close raw file descriptors for the source while fenced: on POSIX,
//! closing one can release the process-wide advisory locks SQLite relies upon.

use super::{DatabaseKey, SCHEMA_VERSION, schema_version, verify_integrity};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OpenFlags};
use std::{
    io::{Seek as _, SeekFrom, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

/// Owns an encrypted snapshot and the live source database fence. Neither this
/// value nor successful transfer is a durable migration/deletion receipt.
/// Raw key input is deliberate: an opaque core key cannot be re-encrypted into
/// caller-readable material through this API. No credential store is accessed.
pub struct MigrationDatabaseSnapshot {
    // Keep the fence until after the temporary snapshot is cleaned up.
    snapshot: NamedTempFile,
    _source: Connection,
}

impl MigrationDatabaseSnapshot {
    /// Open an existing source without creating or upgrading it. The destination
    /// is a fresh private temporary file encrypted under the supplied source key.
    /// Source locking is connection-local and released on error or drop. Path
    /// provenance and account-lifecycle exclusion remain installer responsibilities.
    pub fn freeze(source: &Path, source_key: Zeroizing<[u8; 32]>) -> Result<Self> {
        ensure!(source.is_absolute(), "migration source must be absolute");
        let key = DatabaseKey::new(*source_key);
        drop(source_key);
        let connection = open_existing(source, &key)?;
        connection.execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE")?;
        let journal: String = connection.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        ensure!(
            journal == "delete",
            "migration requires a rollback-journal source"
        );
        ensure!(
            schema_version(&connection)? == Some(SCHEMA_VERSION),
            "migration source schema is not current"
        );
        verify_integrity(&connection)?;
        let snapshot =
            NamedTempFile::new().context("failed to create encrypted migration snapshot")?;
        if let Err(error) = prepare_snapshot(&connection, &snapshot, &key) {
            // Windows may deny removal while SQLite has the snapshot attached.
            // Close all SQLite handles before NamedTempFile attempts cleanup.
            drop(connection);
            return Err(error);
        }
        Ok(Self {
            snapshot,
            _source: connection,
        })
    }

    /// Length and digest for the transfer frame, not an activation receipt.
    pub fn transfer(&mut self) -> Result<crate::database_staging::DatabaseTransfer> {
        self.snapshot.as_file_mut().seek(SeekFrom::Start(0))?;
        crate::database_staging::DatabaseTransfer::describe(self.snapshot.as_file_mut())
    }

    /// Stream the complete encrypted snapshot while retaining the source fence.
    /// On failure the receiver may contain a prefix; callers must never activate
    /// it. Retrying starts at byte zero and requires a fresh receiver.
    pub fn write_to(&mut self, destination: &mut impl Write) -> Result<u64> {
        self.snapshot.as_file_mut().seek(SeekFrom::Start(0))?;
        Ok(std::io::copy(self.snapshot.as_file_mut(), destination)?)
    }
}

fn prepare_snapshot(
    connection: &Connection,
    snapshot: &NamedTempFile,
    key: &DatabaseKey,
) -> Result<()> {
    export(connection, snapshot, key)?;
    snapshot.as_file().sync_all()?;
    // Reopen with the real codec after detaching, while the source is still
    // fenced. Verification never creates or upgrades the imported database.
    let copied = open_existing(snapshot.path(), key)?;
    verify_integrity(&copied)?;
    ensure!(
        schema_version(&copied)? == Some(SCHEMA_VERSION),
        "migration snapshot schema changed"
    );
    Ok(())
}

fn open_existing(path: &Path, key: &DatabaseKey) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.pragma_update(None, "cipher_log_level", "NONE")?;
    key.with_sqlcipher_literal(|literal| connection.pragma_update(None, "key", literal))?;
    connection.pragma_update(None, "cipher_memory_security", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(connection)
}

fn export(source: &Connection, snapshot: &NamedTempFile, key: &DatabaseKey) -> Result<()> {
    let destination = snapshot
        .path()
        .to_str()
        .context("migration snapshot path is not UTF-8")?;
    key.with_sqlcipher_literal(|literal| {
        source.execute(
            "ATTACH DATABASE ?1 AS migration KEY ?2",
            (destination, literal),
        )
    })?;
    let user_version: i64 = source.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let application_id: i64 = source.pragma_query_value(None, "application_id", |r| r.get(0))?;
    source.query_row("SELECT sqlcipher_export('migration')", [], |_| Ok(()))?;
    // sqlcipher_export copies schema/data, not these two database-header fields.
    source.execute_batch(&format!("PRAGMA migration.user_version={user_version}; PRAGMA migration.application_id={application_id}; COMMIT; DETACH DATABASE migration"))?;
    Ok(())
}

/// Called only with the native pending root's retained, read-only file pin.
pub(crate) fn verify_received(
    path: &Path,
    key: &DatabaseKey,
    expected: &std::collections::BTreeMap<uuid::Uuid, crate::config::WalletMetadata>,
) -> Result<()> {
    use rusqlite::OptionalExtension as _;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.pragma_update(None, "cipher_log_level", "NONE")?;
    key.with_sqlcipher_literal(|literal| connection.pragma_update(None, "key", literal))?;
    connection.pragma_update(None, "cipher_memory_security", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch("BEGIN")?;
    let executable_schema: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type IN ('view','trigger')",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        executable_schema == 0,
        "received database contains unsupported views or triggers"
    );
    ensure!(
        schema_version(&connection)? == Some(SCHEMA_VERSION),
        "received database schema is not current"
    );
    verify_integrity(&connection)?;
    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
    ensure!(
        foreign_keys.query([])?.next()?.is_none(),
        "received database has broken references"
    );
    let encoded: Option<String> = connection
        .query_row(
            "SELECT value_json FROM application_settings WHERE key=?1",
            [crate::config::WALLET_CONFIGURATION_SETTING],
            |row| row.get(0),
        )
        .optional()?;
    let wallets = if let Some(encoded) = encoded {
        let config: crate::config::WalletConfig = serde_json::from_str(&encoded)?;
        crate::config::validate_config(&config)?;
        config.wallets
    } else {
        Vec::new()
    };
    let actual: std::collections::BTreeMap<_, _> = wallets
        .into_iter()
        .map(|wallet| (wallet.instance_id, wallet))
        .collect();
    ensure!(
        actual == *expected,
        "received database wallet metadata does not match credentials"
    );
    verify_instances(&connection, expected)
}

fn verify_instances(
    connection: &Connection,
    expected: &std::collections::BTreeMap<uuid::Uuid, crate::config::WalletMetadata>,
) -> Result<()> {
    let mut statement = connection.prepare("SELECT instance_id,wallet_id,wallet_address,created_at FROM wallet_instances WHERE retired_at IS NULL")?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let instance: String = row.get(0)?;
        let wallet = expected
            .get(&instance.parse()?)
            .context("received database has an unexpected active account")?;
        ensure!(
            instance == wallet.instance_id.to_string()
                && row.get::<_, String>(1)? == wallet.id
                && row.get::<_, String>(2)? == format!("{:#x}", wallet.address)
                && row.get::<_, i64>(3)? == wallet.created_at.timestamp_millis(),
            "received database signing identity changed"
        );
        count += 1;
    }
    ensure!(
        count == expected.len(),
        "received database is missing an active account"
    );
    Ok(())
}

#[cfg(test)]
#[path = "migration_database_test.rs"]
mod tests;
