//! SQLCipher-backed wallet security database.
//!
//! Transaction counters and rolling limits deliberately do not live here. A
//! restored database cannot restore consumed allowance and make it spendable
//! again. Pending approvals and transaction lifecycle records use separate
//! tables so exact signed bytes can be recovered without becoming spend state.

use crate::{config::validate_wallet_id, core::policy::WalletPolicy};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use keyring::{Entry, Error as KeyringError};
use rand::RngCore;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{fs, fs::OpenOptions, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SCHEMA_VERSION: i64 = 5;
const DATABASE_FILE: &str = "policies.db";
const DATABASE_LOCK_FILE: &str = "policies.lock";
const KEYRING_SERVICE: &str = "org.ekubo.wallet-mcp.policy-database-key.v1";
const KEYRING_USER: &str = "default";

/// A raw 256-bit `SQLCipher` key. Debug output never exposes its contents.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DatabaseKey([u8; 32]);

impl DatabaseKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == 32,
            "stored policy database key is not 32 bytes"
        );
        let mut key = [0_u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    fn sqlcipher_literal(&self) -> String {
        // SQLCipher's x'...' form consumes the bytes directly rather than
        // applying a password KDF to a textual secret.
        format!("x'{}'", hex::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPolicy {
    pub wallet_id: String,
    pub policy: WalletPolicy,
    pub revision: u64,
    pub updated_at: DateTime<Utc>,
}

pub struct PolicyStore {
    pub(crate) connection: Connection,
}

impl PolicyStore {
    /// Opens the production policy database, creating its credential-store key
    /// only when no database exists. A missing key for an existing database is
    /// treated as state loss and fails closed.
    pub fn production(data_dir: &Path) -> Result<Self> {
        create_private_dir(data_dir)?;
        let lock_path = data_dir.join(DATABASE_LOCK_FILE);
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        set_private_file_permissions(&lock_path)?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;
        let path = data_dir.join(DATABASE_FILE);
        let key = load_or_create_database_key(path.exists())?;
        let result = Self::open(&path, &key);
        FileExt::unlock(&lock)
            .with_context(|| format!("failed to unlock {}", lock_path.display()))?;
        result
    }

    pub fn open(path: &Path, key: &DatabaseKey) -> Result<Self> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("failed to open policy database {}", path.display()))?;

        // Must precede any allocation-heavy work. SQLCipher's Windows log sink
        // allocates through sqlite3_malloc, which cipher_memory_security wraps
        // with VirtualLock; when VirtualLock fails under the working-set quota
        // it logs the failure, and that log allocates again, recursing until
        // the stack is exhausted. Level NONE makes the logger return before it
        // allocates, breaking the cycle while memory locking stays enabled;
        // see docs/windows-sqlcipher-overflow.md.
        connection.pragma_update(None, "cipher_log_level", "NONE")?;
        connection.pragma_update(None, "key", key.sqlcipher_literal())?;
        connection.pragma_update(None, "cipher_memory_security", "ON")?;
        let cipher_version: String = connection
            .pragma_query_value(None, "cipher_version", |row| row.get(0))
            .context("linked SQLite library does not provide SQLCipher")?;
        ensure!(!cipher_version.is_empty(), "SQLCipher is unavailable");
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        // A delete-mode rollback journal avoids leaving committed security
        // state in a second long-lived WAL file. SQLCipher encrypts the
        // transient rollback journal, and FULL synchronization makes each
        // lifecycle transition durable before the caller can submit bytes.
        connection.pragma_update(None, "journal_mode", "DELETE")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;

        if path.metadata().is_ok_and(|metadata| metadata.len() > 0) {
            verify_integrity(&connection)?;
        }

        // Every statement runs individually. Passing one multi-statement
        // string to execute_batch overflows the stack on Windows against the
        // bundled SQLCipher, while the identical statements executed one at a
        // time succeed; see docs/windows-sqlcipher-overflow.md.
        run_transaction(
            &connection,
            &[
                "CREATE TABLE IF NOT EXISTS schema_metadata (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     version INTEGER NOT NULL
                 ) STRICT",
                "INSERT OR IGNORE INTO schema_metadata(singleton, version) VALUES (1, 0)",
                "CREATE TABLE IF NOT EXISTS wallet_policies (
                     wallet_id TEXT PRIMARY KEY NOT NULL,
                     policy_json TEXT NOT NULL,
                     revision INTEGER NOT NULL CHECK (revision > 0),
                     updated_at TEXT NOT NULL
                 ) STRICT",
                "CREATE TABLE IF NOT EXISTS pending_transactions (
                     request_id TEXT PRIMARY KEY NOT NULL,
                     wallet_id TEXT NOT NULL,
                     network_name TEXT NOT NULL,
                     chain_id TEXT NOT NULL,
                     plan_json TEXT NOT NULL,
                     plan_digest TEXT NOT NULL,
                     policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
                     status TEXT NOT NULL CHECK (status IN (
                         'awaiting_approval', 'rejected', 'signed', 'submitting',
                         'broadcast', 'confirmed', 'reverted', 'expired', 'cancelled'
                     )),
                     created_at TEXT NOT NULL,
                     expires_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL,
                     approved_at TEXT,
                     rejected_at TEXT,
                     serialized_transaction TEXT,
                     signed_transaction_hash TEXT,
                     broadcast_transaction_hash TEXT,
                     block_number TEXT,
                     CHECK (
                         (status = 'awaiting_approval' AND approved_at IS NULL AND rejected_at IS NULL
                             AND serialized_transaction IS NULL AND signed_transaction_hash IS NULL)
                         OR status <> 'awaiting_approval'
                     ),
                     CHECK (
                         (serialized_transaction IS NULL AND signed_transaction_hash IS NULL)
                         OR (serialized_transaction IS NOT NULL AND signed_transaction_hash IS NOT NULL)
                     )
                 ) STRICT",
                "CREATE INDEX IF NOT EXISTS pending_transactions_wallet_created
                     ON pending_transactions(wallet_id, created_at DESC)",
                "UPDATE schema_metadata SET version = 2 WHERE singleton = 1 AND version < 2",
            ],
        )?;
        let mut version: i64 = connection.query_row(
            "SELECT version FROM schema_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if version == 2 {
            run_transaction(
                &connection,
                &[
                    "ALTER TABLE pending_transactions
                         ADD COLUMN approval_required INTEGER NOT NULL DEFAULT 1
                         CHECK (approval_required IN (0, 1))",
                    "CREATE INDEX IF NOT EXISTS pending_transactions_signed_hash
                         ON pending_transactions(signed_transaction_hash)
                         WHERE signed_transaction_hash IS NOT NULL",
                    "UPDATE schema_metadata SET version = 3 WHERE singleton = 1",
                ],
            )?;
            version = 3;
        }
        if version == 3 {
            run_transaction(
                &connection,
                &[
                    "CREATE UNIQUE INDEX pending_transactions_wallet_chain_in_flight
                         ON pending_transactions(wallet_id, chain_id)
                         WHERE status IN ('signed', 'submitting', 'broadcast')",
                    "UPDATE schema_metadata SET version = 4 WHERE singleton = 1",
                ],
            )?;
            version = 4;
        }
        if version == 4 {
            run_transaction(
                &connection,
                &[
                    "ALTER TABLE pending_transactions
                         ADD COLUMN review_digest TEXT",
                    "CREATE UNIQUE INDEX pending_transactions_unique_pending_plan
                         ON pending_transactions(wallet_id, chain_id, plan_digest)
                         WHERE status = 'awaiting_approval'",
                    "UPDATE schema_metadata SET version = 5 WHERE singleton = 1",
                ],
            )?;
            version = 5;
        }
        ensure!(
            version == SCHEMA_VERSION,
            "unsupported policy database schema {version}"
        );
        verify_integrity(&connection)?;
        set_private_file_permissions(path)?;
        Ok(Self { connection })
    }

    pub fn get(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        validate_wallet_id(wallet_id)?;
        let row = self
            .connection
            .query_row(
                "SELECT policy_json, revision, updated_at
                 FROM wallet_policies WHERE wallet_id = ?1",
                [wallet_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(json, revision, updated_at)| {
            let revision = u64::try_from(revision).context("stored policy revision is invalid")?;
            let value = serde_json::from_str(&json).context("stored policy is invalid JSON")?;
            let policy = WalletPolicy::parse(value).context("stored policy is invalid")?;
            let updated_at = DateTime::parse_from_rfc3339(&updated_at)
                .context("stored policy timestamp is invalid")?
                .with_timezone(&Utc);
            Ok(StoredPolicy {
                wallet_id: wallet_id.into(),
                policy,
                revision,
                updated_at,
            })
        })
        .transpose()
    }

    /// Replaces a wallet's policy only when the caller observed the current
    /// revision. `None` is valid only for the first policy.
    pub fn put(
        &mut self,
        wallet_id: &str,
        policy: &WalletPolicy,
        expected_revision: Option<u64>,
    ) -> Result<StoredPolicy> {
        validate_wallet_id(wallet_id)?;
        // Round-trip through the strict parser before persisting, including
        // policies constructed directly by Rust callers.
        let canonical = serde_json::to_value(policy)?;
        let policy = WalletPolicy::parse(canonical)?;
        let policy_json = serde_json::to_string(&policy)?;
        let updated_at = Utc::now();
        let transaction = self.connection.transaction()?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM wallet_policies WHERE wallet_id = ?1",
                [wallet_id],
                |row| row.get(0),
            )
            .optional()?;
        let expected_revision = expected_revision
            .map(i64::try_from)
            .transpose()
            .context("expected policy revision is too large")?;
        ensure!(
            current == expected_revision,
            "policy revision conflict: expected {expected_revision:?}, found {current:?}"
        );
        let revision = current.map_or(1, |value| value + 1);
        transaction.execute(
            "INSERT INTO wallet_policies(wallet_id, policy_json, revision, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(wallet_id) DO UPDATE SET
                 policy_json = excluded.policy_json,
                 revision = excluded.revision,
                 updated_at = excluded.updated_at",
            params![wallet_id, policy_json, revision, updated_at.to_rfc3339()],
        )?;
        transaction.execute(
            "UPDATE pending_transactions SET status = 'cancelled', updated_at = ?3
             WHERE wallet_id = ?1 AND policy_revision <> ?2
               AND status IN ('awaiting_approval', 'signed')",
            params![wallet_id, revision, updated_at.to_rfc3339()],
        )?;
        transaction.commit()?;
        Ok(StoredPolicy {
            wallet_id: wallet_id.into(),
            policy,
            revision: u64::try_from(revision).expect("positive policy revision"),
            updated_at,
        })
    }

    /// Deletes a policy only if it still has the revision reviewed by the
    /// caller. This is used when removing the corresponding wallet.
    pub fn delete(&mut self, wallet_id: &str, expected_revision: u64) -> Result<()> {
        validate_wallet_id(wallet_id)?;
        let expected_revision =
            i64::try_from(expected_revision).context("expected policy revision is too large")?;
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "DELETE FROM wallet_policies WHERE wallet_id = ?1 AND revision = ?2",
            params![wallet_id, expected_revision],
        )?;
        ensure!(
            changed == 1,
            "policy revision conflict or missing policy for wallet {wallet_id}"
        );
        transaction.execute(
            "UPDATE pending_transactions SET status = 'cancelled', updated_at = ?2
             WHERE wallet_id = ?1
               AND status IN ('awaiting_approval', 'signed')",
            params![wallet_id, Utc::now().to_rfc3339()],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

/// Run `statements` inside one `BEGIN IMMEDIATE` transaction, one statement
/// per `execute_batch` call.
///
/// Deliberately not one multi-statement string: preparing such a string
/// against the bundled `SQLCipher` build overflows the stack on Windows MSVC,
/// while the identical statements executed individually succeed. The failed
/// transaction is rolled back so an error never leaves the connection inside
/// an open transaction.
fn run_transaction(connection: &Connection, statements: &[&str]) -> Result<()> {
    connection.execute_batch("BEGIN IMMEDIATE")?;
    for statement in statements {
        if let Err(error) = connection.execute_batch(statement) {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(error).context("schema statement failed");
        }
    }
    if let Err(error) = connection.execute_batch("COMMIT") {
        let _ = connection.execute_batch("ROLLBACK");
        return Err(error).context("schema commit failed");
    }
    Ok(())
}

fn verify_integrity(connection: &Connection) -> Result<()> {
    let mut cipher_statement = connection
        .prepare("PRAGMA cipher_integrity_check")
        .context("failed to start SQLCipher integrity check")?;
    let cipher_issues = cipher_statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        cipher_issues.is_empty(),
        "SQLCipher page authentication failed: {}",
        cipher_issues.join("; ")
    );

    let mut logical_statement = connection
        .prepare("PRAGMA integrity_check")
        .context("failed to start SQLite integrity check")?;
    let logical = logical_statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        logical.as_slice() == ["ok"],
        "policy database integrity check failed: {}",
        logical.join("; ")
    );
    Ok(())
}

fn load_or_create_database_key(database_exists: bool) -> Result<DatabaseKey> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .context("platform credential store is unavailable")?;
    match entry.get_secret() {
        Ok(mut bytes) => {
            let result = DatabaseKey::from_slice(&bytes);
            bytes.zeroize();
            result.context("policy database credential is invalid")
        }
        Err(KeyringError::NoEntry) => {
            ensure!(
                !database_exists,
                "policy database exists but its credential-store key is missing"
            );
            let mut bytes = [0_u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            entry
                .set_secret(&bytes)
                .context("failed to save policy database key")?;
            Ok(DatabaseKey::new(bytes))
        }
        Err(error) => Err(error).context("failed to load policy database key"),
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn key(byte: u8) -> DatabaseKey {
        DatabaseKey::new([byte; 32])
    }

    #[test]
    fn stores_only_current_policy_with_optimistic_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policies.db");
        let mut store = PolicyStore::open(&path, &key(7)).unwrap();
        let first = store
            .put("primary", &WalletPolicy::allow_all_with_approval(), None)
            .unwrap();
        assert_eq!(first.revision, 1);
        assert!(store.put("primary", &first.policy, None).is_err());
        let second = store
            .put("primary", &first.policy, Some(first.revision))
            .unwrap();
        assert_eq!(second.revision, 2);
        assert_eq!(store.get("primary").unwrap().unwrap(), second);
    }

    #[test]
    fn wrong_key_cannot_open_existing_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policies.db");
        drop(PolicyStore::open(&path, &key(1)).unwrap());
        assert!(PolicyStore::open(&path, &key(2)).is_err());
    }

    #[test]
    fn plaintext_sqlite_header_is_not_present() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policies.db");
        drop(PolicyStore::open(&path, &key(3)).unwrap());
        let bytes = fs::read(path).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3\0"));
    }

    #[test]
    fn authenticated_page_corruption_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policies.db");
        let mut store = PolicyStore::open(&path, &key(4)).unwrap();
        store
            .put("primary", &WalletPolicy::allow_all_with_approval(), None)
            .unwrap();
        drop(store);

        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(file.metadata().unwrap().len() > 4_224);
        file.seek(SeekFrom::Start(4_224)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(SeekFrom::Start(4_224)).unwrap();
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(PolicyStore::open(&path, &key(4)).is_err());
    }

    #[test]
    fn committed_state_does_not_depend_on_a_persistent_wal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policies.db");
        let mut store = PolicyStore::open(&path, &key(5)).unwrap();
        store
            .put("primary", &WalletPolicy::allow_all_with_approval(), None)
            .unwrap();
        drop(store);
        assert!(!path.with_extension("db-wal").exists());
        assert!(
            PolicyStore::open(&path, &key(5))
                .unwrap()
                .get("primary")
                .unwrap()
                .is_some()
        );
    }
}
