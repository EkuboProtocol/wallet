//! SQLCipher-backed wallet security database.
//!
//! Transaction counters and rolling limits deliberately do not live here. A
//! restored database cannot restore consumed allowance and make it spendable
//! again. Pending approvals and transaction lifecycle records use separate
//! tables so exact signed bytes can be recovered without becoming spend state.

use crate::{
    config::{
        NetworkConfig, WalletMetadata, create_private_dir, open_private_file, validate_network,
        validate_wallet_id,
    },
    core::policy::WalletPolicy,
    human_presence::{OwnerAuthorization, OwnerAuthorizationScope},
    sql::{Blob, Millis, RowExt},
};
use alloy::primitives::Address;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use keyring::{Entry, Error as KeyringError};
use rand::TryRng;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
#[cfg(any(test, feature = "test-hooks"))]
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{LazyLock, Mutex},
};
use std::{path::Path, str::FromStr};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The encrypted database schema understood by this build.
const SCHEMA_VERSION: i64 = 10;
pub const DATABASE_FILE: &str = "wallet.db";
const DATABASE_LOCK_FILE: &str = "wallet.lock";
/// The credential-store entry holding this database's key.
///
/// Named for the database rather than for policies, because policies are only
/// one of the things it protects: the same file holds the pending signing
/// queues and the token names a reviewer reads before
/// approving a transfer. A name that says "policy" invites the reading that
/// everything else in there is incidental, and none of it is.
const KEYRING_SERVICE: &str = "org.ekubo.wallet.db";
const KEYRING_USER: &str = "default";

#[cfg(any(test, feature = "test-hooks"))]
static TEST_DATABASE_KEYS: LazyLock<Mutex<HashMap<PathBuf, [u8; 32]>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Route production-style store opens for one test directory to an explicit
/// key, without touching the machine-wide credential store.
///
/// A release build cannot contain this function: `test-hooks` is refused when
/// debug assertions are disabled. Keeping the override keyed by data directory
/// also lets otherwise unrelated tests continue to exercise the real
/// production routing in the same process.
#[cfg(any(test, feature = "test-hooks"))]
pub fn register_test_database_key(data_dir: &Path, key: [u8; 32]) -> Result<()> {
    let mut keys = TEST_DATABASE_KEYS
        .lock()
        .map_err(|_| anyhow::anyhow!("test database-key registry was poisoned"))?;
    if let Some(existing) = keys.get(data_dir) {
        ensure!(
            existing == &key,
            "test data directory already has a different database key"
        );
    } else {
        keys.insert(data_dir.to_path_buf(), key);
    }
    Ok(())
}

#[cfg(any(test, feature = "test-hooks"))]
fn registered_test_database_key(data_dir: &Path) -> Result<Option<DatabaseKey>> {
    Ok(TEST_DATABASE_KEYS
        .lock()
        .map_err(|_| anyhow::anyhow!("test database-key registry was poisoned"))?
        .get(data_dir)
        .copied()
        .map(DatabaseKey::new))
}

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

    /// Run `use_literal` with the `SQLCipher` `x'...'` form of this key, and
    /// zeroize the rendering afterwards.
    ///
    /// The key itself is zeroized on drop, but hex-encoding it produced a
    /// plain `String` that was not — a second copy of the database key, freed
    /// without being cleared, left wherever the allocator put it. That copy
    /// outlived every protection the `DatabaseKey` type provides, which is the
    /// whole reason the type exists.
    ///
    /// A closure rather than a returned `String`, so there is no way to call
    /// this and forget to clear the result.
    fn with_sqlcipher_literal<T>(&self, use_literal: impl FnOnce(&str) -> T) -> T {
        // SQLCipher's x'...' form consumes the bytes directly rather than
        // applying a password KDF to a textual secret.
        let mut literal = format!("x'{}'", hex::encode(self.0));
        let outcome = use_literal(&literal);
        literal.zeroize();
        outcome
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPolicy {
    pub wallet_instance_id: Uuid,
    pub wallet_id: String,
    pub wallet_address: Address,
    pub policy: WalletPolicy,
    pub revision: u64,
    pub updated_at: DateTime<Utc>,
}

/// An agent-proposed replacement policy awaiting human review. At most one
/// proposal exists per wallet — a newer proposal replaces the previous one —
/// and it binds the exact policy revision it was written against, so it can
/// never apply over a policy the agent has not seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyProposal {
    pub wallet_instance_id: Uuid,
    pub wallet_id: String,
    pub wallet_address: Address,
    pub source_revision: u64,
    pub policy: WalletPolicy,
    /// Agent-authored free text shown to the reviewer; untrusted display data.
    pub rationale: String,
    pub created_at: DateTime<Utc>,
}

pub const MAX_PROPOSAL_RATIONALE_LEN: usize = 2_000;

/// A serialized policy document that could not plausibly describe a wallet's
/// permissions.
///
/// Every field inside one is already validated; this bounds the document as a
/// whole. Without it the only limit on a policy was how many allowlist entries
/// an agent cared to write — and each one is a row the database keeps, a diff
/// line the owner has to read, and work every `parse` repeats. Generous: a real
/// policy naming a few hundred tokens and spenders is a few tens of kilobytes.
pub const MAX_POLICY_BYTES: usize = 262_144;

/// A serialized network profile that could not plausibly describe a network.
/// Every field is already length-validated; this bounds the document so a
/// proposal cannot grow the database by the size of its aliases.
pub const MAX_NETWORK_PROFILE_BYTES: usize = 8_192;

/// Network suggestions that may await review at once.
///
/// The queue is a list of decisions a person has to make, and an agent that
/// can lengthen it without bound does not gain a network — it makes the screen
/// where networks are granted unreadable, which is the same thing. Small
/// because a wallet needs a handful of chains, not a catalogue.
pub const MAX_PENDING_NETWORK_PROPOSALS: u64 = 32;

pub struct PolicyStore {
    pub(crate) connection: Connection,
}

/// Whether creating a schema also installs the compiled-in curated token list.
///
/// Only [`PolicyStore::production`] says yes. Every production store opens
/// through it, so whichever one finds the database missing is the one that
/// creates *and* seeds it — there is no ordering in which a real installation
/// ends up with a schema nobody seeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeedDefaults {
    Yes,
    No,
}

/// The statuses in which an envelope may still reach the chain.
///
/// The same set the `pending_transactions_wallet_chain_in_flight` index uses,
/// and held to it by a test: a status that counts as in flight for the
/// uniqueness rule but not for this one would let a wallet be removed out from
/// under a transaction the schema considers live.
pub(crate) const IN_FLIGHT_STATUSES: [&str; 4] =
    ["signed", "submitting", "broadcast", "cancelling"];

/// One transaction that may still execute, named well enough for a person to
/// go and settle it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InFlightTransaction {
    pub request_id: uuid::Uuid,
    pub chain_id: String,
    pub status: String,
}

impl PolicyStore {
    /// Opens the production policy database, creating its credential-store key
    /// only when no database exists. A missing key for an existing database is
    /// treated as state loss and fails closed.
    pub fn production(data_dir: &Path) -> Result<Self> {
        create_private_dir(data_dir)?;
        let lock_path = data_dir.join(DATABASE_LOCK_FILE);
        // `open_private_file`, not a bare `OpenOptions`: it carries
        // `O_NOFOLLOW`, so this handle refers to that name or to nothing.
        //
        // A lock taken by pathname serializes two processes only if both of
        // them locked the same inode. A symlink at `policies.lock` gives them
        // different ones, and the first-use path below is what that costs:
        // both see no database, both generate a key, the second `set_secret`
        // wins, and the first creates a database encrypted under a key the
        // credential store no longer holds. The readback there is the
        // arbiter for the residual window; this removes the way the two locks
        // came apart in the first place.
        let lock = open_private_file(&lock_path)?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;
        let path = data_dir.join(DATABASE_FILE);
        // Whether a database exists decides whether a missing credential-store
        // key is state loss or a first run, so it must not be a separate
        // question from the one the open below answers. `path.exists()`
        // resolved the name a second time and followed a link, which let a
        // replacement between the two calls turn "this database exists and its
        // key is gone" into "there is no database, mint a key" — and the
        // original wallet database is then unopenable forever.
        //
        // Asking a handle instead binds the answer to an inode. Size rather
        // than presence is the test SQLite itself applies: a zero-length file
        // is a database with nothing in it yet, and a stray empty file left by
        // a failed first run must not brick the next one.
        let database = open_private_file(&path)?;
        let database_exists = database
            .metadata()
            .with_context(|| format!("failed to inspect {}", path.display()))?
            .len()
            > 0;
        let key = load_or_create_database_key(data_dir, database_exists)?;
        drop(database);
        let result = Self::open_with(&path, &key, SeedDefaults::Yes);
        // The work's own error is the one worth reporting. Unlocking after a
        // failure and propagating *that* replaces "the database key is wrong"
        // or "the schema is unrecognized" with "failed to unlock a lock file",
        // which tells the owner nothing about why their wallet did not open —
        // and the lock is released either way when this process exits.
        let unlocked = FileExt::unlock(&lock)
            .with_context(|| format!("failed to unlock {}", lock_path.display()));
        result.and_then(|store| unlocked.map(|()| store))
    }

    /// Opens a database with a bare schema, seeding nothing.
    ///
    /// This is the storage primitive. Which tokens a *product* trusts on a new
    /// installation is not a property of the schema, so it is decided by
    /// [`Self::production`] instead — otherwise every test that touches storage
    /// would inherit the curated list and start asserting against its contents.
    pub fn open(path: &Path, key: &DatabaseKey) -> Result<Self> {
        Self::open_with(path, key, SeedDefaults::No)
    }

    pub(crate) fn open_with(
        path: &Path,
        key: &DatabaseKey,
        seed_defaults: SeedDefaults,
    ) -> Result<Self> {
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
        key.with_sqlcipher_literal(|literal| connection.pragma_update(None, "key", literal))?;
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

        // Schema management happens before any write: the version is read
        // first, so a database this build refuses is left byte-identical.
        //
        let version = match schema_version(&connection)? {
            None => {
                let objects: i64 =
                    connection
                        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))?;
                ensure!(
                    objects == 0,
                    "policy database has tables but no schema version, so it was not created \
                     by ekubo-wallet"
                );
                create_current_schema(&connection)?;
                // The one moment a database is new. Seeding here rather than at
                // startup is what makes the default list a starting point
                // instead of a policy: after this, a token the owner removed
                // stays removed.
                //
                // Which is also why a half-created database must not survive.
                // The schema and its version marker are committed by the line
                // above, and the seed is a second transaction; a failure
                // between them — a disk that holds the small schema and not
                // the large insert — leaves a database that opens cleanly
                // forever after, takes the existing-version branch, and never
                // seeds again. Every ERC-20 the defaults would have named goes
                // unnamed and unlisted, and a portfolio reads as holding none
                // of them, permanently and without saying so.
                //
                // So the file goes with the error. Removing it is safe here
                // and nowhere else: the branch is reached only when the
                // database had no tables at all, which means this call created
                // it moments ago and there is nothing in it that was not just
                // written. The journal mode is DELETE rather than WAL, so the
                // one file is the whole database.
                if seed_defaults == SeedDefaults::Yes
                    && let Err(error) = crate::default_tokens::seed(&connection)
                {
                    drop(connection);
                    let _ = std::fs::remove_file(path);
                    return Err(error).with_context(|| {
                        format!(
                            "removed the partly created policy database {} so the next start \
                             creates a complete one",
                            path.display()
                        )
                    });
                }
                SCHEMA_VERSION
            }
            Some(version) => migrate(&connection, version)?,
        };
        ensure!(
            version == SCHEMA_VERSION,
            "policy database schema {version} is not the schema this build understands \
             ({SCHEMA_VERSION})"
        );
        verify_integrity(&connection)?;
        // Narrowed through a handle that refuses to follow a link, not through
        // the name. This runs after the connection is open, which is exactly
        // the window in which a by-path chmod could be pointed at some other
        // reachable file.
        drop(open_private_file(path)?);
        Ok(Self { connection })
    }

    /// Re-reads the schema version through this connection. The long-running
    /// wallet process keeps its stores open, so replacing a database underneath
    /// it would otherwise leave the process writing against a stale schema.
    /// Refusing here turns that into an explicit restart error on every request.
    pub fn assert_schema_current(&self) -> Result<()> {
        let version = schema_version(&self.connection)?
            .context("policy database lost its schema version; restart Ekubo Wallet")?;
        ensure!(
            version == SCHEMA_VERSION,
            "policy database schema changed from {SCHEMA_VERSION} to {version} underneath \
             this process; restart Ekubo Wallet"
        );
        Ok(())
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn get(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        validate_wallet_id(wallet_id)?;
        let row = self
            .connection
            .query_row(
                "SELECT wallet_instance_id, wallet_address, policy_json, revision, updated_at
                 FROM wallet_policies WHERE wallet_id = ?1
                 ORDER BY updated_at DESC, revision DESC LIMIT 1",
                [wallet_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.time(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(
            |(wallet_instance_id, wallet_address, json, revision, updated_at)| {
                let revision =
                    u64::try_from(revision).context("stored policy revision is invalid")?;
                let value = serde_json::from_str(&json).context("stored policy is invalid JSON")?;
                let policy = WalletPolicy::parse(value).context("stored policy is invalid")?;
                Ok(StoredPolicy {
                    wallet_instance_id: Uuid::parse_str(&wallet_instance_id)
                        .context("stored policy wallet instance is invalid")?,
                    wallet_id: wallet_id.into(),
                    wallet_address: Address::from_str(&wallet_address)
                        .context("stored policy wallet identity is invalid")?,
                    policy,
                    revision,
                    updated_at,
                })
            },
        )
        .transpose()
    }

    /// Resolve authority only for the immutable address currently attached to
    /// a wallet name. A predecessor row is not an active policy for a
    /// replacement wallet.
    pub fn get_for_wallet(
        &self,
        wallet_id: &str,
        wallet_instance_id: Uuid,
        wallet_address: Address,
    ) -> Result<Option<StoredPolicy>> {
        validate_wallet_id(wallet_id)?;
        let active: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM wallet_instances
                 WHERE instance_id = ?1 AND wallet_id = ?2 AND wallet_address = ?3
                   AND retired_at IS NULL",
                params![
                    wallet_instance_id.to_string(),
                    wallet_id,
                    format!("{wallet_address:#x}")
                ],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            active.is_some(),
            "wallet {wallet_id} instance {wallet_instance_id} is not active"
        );
        let row = self
            .connection
            .query_row(
                "SELECT policy_json, revision, updated_at FROM wallet_policies
                 WHERE wallet_instance_id = ?1 ORDER BY revision DESC LIMIT 1",
                [wallet_instance_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.time(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(json, revision, updated_at)| {
            let value = serde_json::from_str(&json).context("stored policy is invalid JSON")?;
            Ok(StoredPolicy {
                wallet_instance_id,
                wallet_id: wallet_id.into(),
                wallet_address,
                policy: WalletPolicy::parse(value).context("stored policy is invalid")?,
                revision: u64::try_from(revision).context("stored policy revision is invalid")?,
                updated_at,
            })
        })
        .transpose()
    }

    /// Read the immutable policy revisions belonging to the active wallet
    /// identity, oldest first. A retired wallet that once used the same name
    /// is deliberately excluded.
    pub fn history_for_wallet(
        &self,
        wallet_id: &str,
        wallet_instance_id: Uuid,
        wallet_address: Address,
    ) -> Result<Vec<StoredPolicy>> {
        validate_wallet_id(wallet_id)?;
        let active: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM wallet_instances
                 WHERE instance_id = ?1 AND wallet_id = ?2 AND wallet_address = ?3
                   AND retired_at IS NULL",
                params![
                    wallet_instance_id.to_string(),
                    wallet_id,
                    format!("{wallet_address:#x}")
                ],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            active.is_some(),
            "wallet {wallet_id} instance {wallet_instance_id} is not active"
        );
        let mut statement = self.connection.prepare(
            "SELECT policy_json, revision, updated_at FROM wallet_policies
             WHERE wallet_instance_id = ?1 ORDER BY revision ASC",
        )?;
        let rows = statement.query_map([wallet_instance_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.time(2)?,
            ))
        })?;
        rows.map(|row| {
            let (json, revision, updated_at) = row?;
            let value = serde_json::from_str(&json).context("stored policy is invalid JSON")?;
            Ok(StoredPolicy {
                wallet_instance_id,
                wallet_id: wallet_id.into(),
                wallet_address,
                policy: WalletPolicy::parse(value).context("stored policy is invalid")?,
                revision: u64::try_from(revision).context("stored policy revision is invalid")?,
                updated_at,
            })
        })
        .collect()
    }

    /// Test-only raw policy insertion. Production callers must use
    /// [`Self::install_policy`], which enforces the authorization direction in
    /// this crate immediately before committing.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn put(
        &mut self,
        wallet_id: &str,
        policy: &WalletPolicy,
        expected_revision: Option<u64>,
    ) -> Result<StoredPolicy> {
        self.put_for_wallet(wallet_id, Address::ZERO, policy, expected_revision)
    }

    /// Test-only identity-aware raw policy insertion.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn put_for_wallet(
        &mut self,
        wallet_id: &str,
        wallet_address: Address,
        policy: &WalletPolicy,
        expected_revision: Option<u64>,
    ) -> Result<StoredPolicy> {
        let transaction = self.connection.transaction()?;
        let wallet_instance_id: String = transaction
            .query_row(
                "SELECT instance_id FROM wallet_instances
                 WHERE wallet_id = ?1 AND wallet_address = ?2 AND retired_at IS NULL",
                params![wallet_id, format!("{wallet_address:#x}")],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        transaction.execute(
            "INSERT OR IGNORE INTO wallet_instances(
                 instance_id, wallet_id, wallet_address, created_at, retired_at
             ) VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                wallet_instance_id,
                wallet_id,
                format!("{wallet_address:#x}"),
                Millis(crate::sql::now())
            ],
        )?;
        let stored = Self::apply_policy(
            &transaction,
            wallet_id,
            Uuid::parse_str(&wallet_instance_id)?,
            wallet_address,
            policy,
            expected_revision,
        )?;

        transaction.commit()?;
        Ok(stored)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn put_for_instance(
        &mut self,
        wallet: &WalletMetadata,
        policy: &WalletPolicy,
        expected_revision: Option<u64>,
    ) -> Result<StoredPolicy> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT OR IGNORE INTO wallet_instances(
                 instance_id, wallet_id, wallet_address, created_at, retired_at
             ) VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                wallet.instance_id.to_string(),
                wallet.id,
                format!("{:#x}", wallet.address),
                Millis(wallet.created_at)
            ],
        )?;
        let stored = Self::apply_policy(
            &transaction,
            &wallet.id,
            wallet.instance_id,
            wallet.address,
            policy,
            expected_revision,
        )?;
        transaction.commit()?;
        Ok(stored)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn register_wallet_without_policy(&mut self, wallet: &WalletMetadata) -> Result<()> {
        self.connection.execute(
            "INSERT INTO wallet_instances(
                 instance_id, wallet_id, wallet_address, created_at, retired_at
             ) VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                wallet.instance_id.to_string(),
                wallet.id,
                format!("{:#x}", wallet.address),
                Millis(wallet.created_at)
            ],
        )?;
        Ok(())
    }

    /// Install a policy transition after re-reading the active policy inside
    /// the write transaction. Tightening is authorization-free; widening or
    /// an incomparable edit requires a fresh policy-scoped capability.
    pub fn install_policy_for_instance(
        &mut self,
        wallet_id: &str,
        wallet_instance_id: Uuid,
        wallet_address: Address,
        policy: &WalletPolicy,
        expected_revision: Option<u64>,
        authorization: Option<&OwnerAuthorization>,
    ) -> Result<StoredPolicy> {
        let transaction = self.connection.transaction()?;
        Self::authorize_policy_transition(
            &transaction,
            wallet_id,
            wallet_instance_id,
            wallet_address,
            policy,
            authorization,
        )?;
        let stored = Self::apply_policy(
            &transaction,
            wallet_id,
            wallet_instance_id,
            wallet_address,
            policy,
            expected_revision,
        )?;
        transaction.commit()?;
        Ok(stored)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn install_policy(
        &mut self,
        wallet_id: &str,
        wallet_address: Address,
        policy: &WalletPolicy,
        expected_revision: Option<u64>,
        authorization: Option<&OwnerAuthorization>,
    ) -> Result<StoredPolicy> {
        let instance_id: String = self.connection.query_row(
            "SELECT instance_id FROM wallet_instances
             WHERE wallet_id = ?1 AND wallet_address = ?2 AND retired_at IS NULL",
            params![wallet_id, format!("{wallet_address:#x}")],
            |row| row.get(0),
        )?;
        self.install_policy_for_instance(
            wallet_id,
            Uuid::parse_str(&instance_id)?,
            wallet_address,
            policy,
            expected_revision,
            authorization,
        )
    }

    /// Initialize a newly created identity with no ability to widen beyond
    /// the fail-closed baseline. Custody calls this while it holds the wallet
    /// lifecycle lock; a permissive initial policy must be installed later by
    /// the authenticated owner path.
    pub(crate) fn initialize_policy(
        &mut self,
        wallet: &WalletMetadata,
        policy: &WalletPolicy,
    ) -> Result<StoredPolicy> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO wallet_instances(
                 instance_id, wallet_id, wallet_address, created_at, retired_at
             ) VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                wallet.instance_id.to_string(),
                wallet.id,
                format!("{:#x}", wallet.address),
                Millis(wallet.created_at)
            ],
        )?;
        Self::authorize_policy_transition(
            &transaction,
            &wallet.id,
            wallet.instance_id,
            wallet.address,
            policy,
            None,
        )?;
        let stored = Self::apply_policy(
            &transaction,
            &wallet.id,
            wallet.instance_id,
            wallet.address,
            policy,
            None,
        )?;
        transaction.commit()?;
        Ok(stored)
    }

    /// Apply the exact proposal that was reviewed, and consume that same row.
    ///
    /// `put` plus `delete_proposal` could not express this: the revision check
    /// guards the *active* policy, which does not move while a proposal sits
    /// pending, so a proposal replaced during the human review passed every
    /// check and was then deleted by wallet ID — applied never, seen never.
    /// Matching on `created_at`, which `put_proposal` refreshes on every
    /// replacement, makes the delete identify the row rather than the wallet.
    ///
    /// `created_at` alone is a weak name for a row, though. It is a clock
    /// reading, and two writes that land in one tick of it are the same name
    /// for different proposals — so the whole reviewed content is matched
    /// instead. That needs no schema change and no better clock, and it fails
    /// in the safe direction: a replacement that matches every column *is* the
    /// proposal that was reviewed, so consuming it applies what the human saw.
    ///
    /// One transaction, so a proposal is applied exactly when it is consumed.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn consume_proposal(&mut self, proposal: &PolicyProposal) -> Result<StoredPolicy> {
        let authorization = OwnerAuthorization::for_test(OwnerAuthorizationScope::PolicySettings);
        self.apply_proposal(proposal, Some(&authorization))
    }

    /// Apply the exact reviewed proposal. As with direct installation, core
    /// decides from the current policy whether authentication is necessary.
    pub fn apply_proposal(
        &mut self,
        proposal: &PolicyProposal,
        authorization: Option<&OwnerAuthorization>,
    ) -> Result<StoredPolicy> {
        validate_wallet_id(&proposal.wallet_id)?;
        let policy_json = serde_json::to_string(&proposal.policy)?;
        let transaction = self.connection.transaction()?;
        let consumed = transaction.execute(
            "DELETE FROM policy_proposals
             WHERE wallet_instance_id = ?1 AND wallet_id = ?2 AND wallet_address = ?3 AND created_at = ?4
               AND source_revision = ?5 AND policy_json = ?6 AND rationale = ?7",
            params![
                proposal.wallet_instance_id.to_string(),
                proposal.wallet_id,
                format!("{:#x}", proposal.wallet_address),
                Millis(proposal.created_at),
                i64::try_from(proposal.source_revision).context("source revision out of range")?,
                policy_json,
                proposal.rationale
            ],
        )?;
        ensure!(
            consumed == 1,
            "the proposal you reviewed was replaced by a newer one; nothing was applied. \
             Run the review again to decide on the current proposal."
        );
        Self::authorize_policy_transition(
            &transaction,
            &proposal.wallet_id,
            proposal.wallet_instance_id,
            proposal.wallet_address,
            &proposal.policy,
            authorization,
        )?;
        let stored = Self::apply_policy(
            &transaction,
            &proposal.wallet_id,
            proposal.wallet_instance_id,
            proposal.wallet_address,
            &proposal.policy,
            Some(proposal.source_revision),
        )?;
        transaction.commit()?;
        Ok(stored)
    }

    fn authorize_policy_transition(
        transaction: &rusqlite::Transaction<'_>,
        wallet_id: &str,
        wallet_instance_id: Uuid,
        wallet_address: Address,
        proposed: &WalletPolicy,
        authorization: Option<&OwnerAuthorization>,
    ) -> Result<()> {
        validate_wallet_id(wallet_id)?;
        let active: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM wallet_instances
                 WHERE instance_id = ?1 AND wallet_id = ?2 AND wallet_address = ?3
                   AND retired_at IS NULL",
                params![
                    wallet_instance_id.to_string(),
                    wallet_id,
                    format!("{wallet_address:#x}")
                ],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(active.is_some(), "wallet instance is not active");
        let current_json: Option<String> = transaction
            .query_row(
                "SELECT policy_json FROM wallet_policies
                 WHERE wallet_instance_id = ?1 ORDER BY revision DESC LIMIT 1",
                [wallet_instance_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let current = current_json
            .map(|json| {
                let value = serde_json::from_str(&json).context("stored policy is invalid JSON")?;
                WalletPolicy::parse(value).context("stored policy is invalid")
            })
            .transpose()?
            .unwrap_or_else(WalletPolicy::require_approval_for_everything);
        if !crate::core::policy::is_tightening(&current, proposed) {
            authorization
                .context("this policy change widens or ambiguously changes signing authority")?
                .require(OwnerAuthorizationScope::PolicySettings)?;
        }
        Ok(())
    }

    /// The policy write both entry points share, run inside a transaction the
    /// caller owns. That is what lets `consume_proposal` make applying a
    /// proposal and consuming it one step: two separate calls could not be
    /// made atomic from outside.
    fn apply_policy(
        transaction: &rusqlite::Transaction<'_>,
        wallet_id: &str,
        wallet_instance_id: Uuid,
        wallet_address: Address,
        policy: &WalletPolicy,
        expected_revision: Option<u64>,
    ) -> Result<StoredPolicy> {
        validate_wallet_id(wallet_id)?;
        // Round-trip through the strict parser before persisting, including
        // policies constructed directly by Rust callers.
        let canonical = serde_json::to_value(policy)?;
        let policy = WalletPolicy::parse(canonical)?;
        let policy_json = serde_json::to_string(&policy)?;
        ensure!(
            policy_json.len() <= MAX_POLICY_BYTES,
            "policy document exceeds {MAX_POLICY_BYTES} bytes"
        );
        let updated_at = crate::sql::now();
        let current_revision: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM wallet_policies
                 WHERE wallet_instance_id = ?1 ORDER BY revision DESC LIMIT 1",
                [wallet_instance_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let expected_revision = expected_revision
            .map(i64::try_from)
            .transpose()
            .context("expected policy revision is too large")?;
        ensure!(
            current_revision == expected_revision,
            "policy revision conflict: expected {expected_revision:?}, found {current_revision:?}"
        );
        let revision = current_revision.map_or(1, |value| value + 1);
        transaction.execute(
            "INSERT INTO wallet_policies(
                 wallet_instance_id, wallet_id, wallet_address, policy_json, revision, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                wallet_instance_id.to_string(),
                wallet_id,
                format!("{wallet_address:#x}"),
                policy_json,
                revision,
                Millis(updated_at)
            ],
        )?;
        transaction.execute(
            "UPDATE pending_transactions SET status = 'cancelled', updated_at = ?4
             WHERE wallet_instance_id = ?1 AND wallet_address = ?2 AND policy_revision <> ?3
               AND status IN ('awaiting_approval', 'signed')",
            params![
                wallet_instance_id.to_string(),
                format!("{wallet_address:#x}"),
                revision,
                Millis(updated_at)
            ],
        )?;
        Ok(StoredPolicy {
            wallet_instance_id,
            wallet_id: wallet_id.into(),
            wallet_address,
            policy,
            revision: u64::try_from(revision).expect("positive policy revision"),
            updated_at,
        })
    }

    /// Store or replace the wallet's single pending policy proposal. The
    /// insert re-checks that `source_revision` is the active revision inside
    /// the transaction, so a proposal can never be recorded against a policy
    /// the proposer did not read. The latest proposal always prevails.
    pub fn put_proposal_for_wallet(
        &mut self,
        wallet_id: &str,
        wallet_instance_id: Uuid,
        wallet_address: Address,
        source_revision: u64,
        policy: &WalletPolicy,
        rationale: &str,
    ) -> Result<PolicyProposal> {
        validate_wallet_id(wallet_id)?;
        let rationale = rationale.trim();
        ensure!(
            !rationale.is_empty() && rationale.len() <= MAX_PROPOSAL_RATIONALE_LEN,
            "proposal rationale must contain 1-{MAX_PROPOSAL_RATIONALE_LEN} bytes"
        );
        // Round-trip through the strict parser, exactly like put().
        let canonical = serde_json::to_value(policy)?;
        let policy = WalletPolicy::parse(canonical)?;
        let policy_json = serde_json::to_string(&policy)?;
        ensure!(
            policy_json.len() <= MAX_POLICY_BYTES,
            "policy document exceeds {MAX_POLICY_BYTES} bytes"
        );
        let source = i64::try_from(source_revision).context("source revision is too large")?;
        let transaction = self.connection.transaction()?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT policies.revision FROM wallet_policies AS policies
                 INNER JOIN wallet_instances AS instances
                    ON instances.instance_id = policies.wallet_instance_id
                 WHERE policies.wallet_instance_id = ?1
                   AND instances.wallet_id = ?2
                   AND instances.wallet_address = ?3
                   AND instances.retired_at IS NULL
                 ORDER BY policies.revision DESC LIMIT 1",
                params![
                    wallet_instance_id.to_string(),
                    wallet_id,
                    format!("{wallet_address:#x}")
                ],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            current == Some(source),
            "the proposal references policy revision {source_revision}, but the active revision \
             is {current:?}; read the current policy with wallet_get_policy and propose again"
        );
        let created_at = crate::sql::now();
        transaction.execute(
            "INSERT INTO policy_proposals(
                wallet_instance_id, wallet_id, wallet_address, source_revision, policy_json,
                rationale, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(wallet_instance_id) DO UPDATE SET
                 wallet_address = excluded.wallet_address,
                 wallet_id = excluded.wallet_id,
                 source_revision = excluded.source_revision,
                 policy_json = excluded.policy_json,
                 rationale = excluded.rationale,
                 created_at = excluded.created_at",
            params![
                wallet_instance_id.to_string(),
                wallet_id,
                format!("{wallet_address:#x}"),
                source,
                policy_json,
                rationale,
                Millis(created_at)
            ],
        )?;
        transaction.commit()?;
        Ok(PolicyProposal {
            wallet_instance_id,
            wallet_id: wallet_id.into(),
            wallet_address,
            source_revision,
            policy,
            rationale: rationale.into(),
            created_at,
        })
    }

    /// Test-only proposal helper for minimal fixtures that do not model a
    /// custody identity. Production proposals bind the current UUID and address.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn put_proposal(
        &mut self,
        wallet_id: &str,
        source_revision: u64,
        policy: &WalletPolicy,
        rationale: &str,
    ) -> Result<PolicyProposal> {
        let current = self
            .get(wallet_id)?
            .context("wallet has no active test policy")?;
        self.put_proposal_for_wallet(
            wallet_id,
            current.wallet_instance_id,
            current.wallet_address,
            source_revision,
            policy,
            rationale,
        )
    }

    pub fn proposal_for_instance(
        &self,
        wallet_instance_id: Uuid,
    ) -> Result<Option<PolicyProposal>> {
        self.connection
            .query_row(
                "SELECT wallet_id, wallet_address, source_revision, policy_json, rationale, created_at
                 FROM policy_proposals WHERE wallet_instance_id = ?1",
                [wallet_instance_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.time(5)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(wallet_id, wallet_address, source_revision, policy_json, rationale, created_at)| {
                    parse_proposal(
                        wallet_instance_id,
                        &wallet_id,
                        &wallet_address,
                        source_revision,
                        &policy_json,
                        rationale,
                        created_at,
                    )
                },
            )
            .transpose()
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn proposal(&self, wallet_id: &str) -> Result<Option<PolicyProposal>> {
        let Some(policy) = self.get(wallet_id)? else {
            return Ok(None);
        };
        self.proposal_for_instance(policy.wallet_instance_id)
    }

    pub fn list_proposals(&self) -> Result<Vec<PolicyProposal>> {
        let mut statement = self.connection.prepare(
            "SELECT wallet_instance_id, wallet_id, wallet_address, source_revision, policy_json, rationale, created_at
             FROM policy_proposals ORDER BY wallet_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.time(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        rows.into_iter()
            .map(
                |(
                    wallet_instance_id,
                    wallet_id,
                    wallet_address,
                    source_revision,
                    policy_json,
                    rationale,
                    created_at,
                )| {
                    parse_proposal(
                        Uuid::parse_str(&wallet_instance_id)
                            .context("stored proposal wallet instance is invalid")?,
                        &wallet_id,
                        &wallet_address,
                        source_revision,
                        &policy_json,
                        rationale,
                        created_at,
                    )
                },
            )
            .collect()
    }

    /// Discard exactly `proposal`, if it is still the pending one. Returns
    /// whether it was.
    ///
    /// Identified the same way `consume_proposal` identifies its row, and for
    /// the same reason. The caller that discards a proposal has read it and
    /// the active policy separately and found them inconsistent; a newer
    /// proposal written in between may reference the current revision and be
    /// perfectly applicable. Deleting by wallet ID threw that one away while
    /// telling the owner a stale proposal had been cleaned up.
    pub fn delete_proposal(&mut self, proposal: &PolicyProposal) -> Result<bool> {
        validate_wallet_id(&proposal.wallet_id)?;
        let policy_json = serde_json::to_string(&proposal.policy)?;
        let changed = self.connection.execute(
            "DELETE FROM policy_proposals
             WHERE wallet_instance_id = ?1 AND wallet_id = ?2 AND wallet_address = ?3
               AND created_at = ?4 AND source_revision = ?5 AND policy_json = ?6
               AND rationale = ?7",
            params![
                proposal.wallet_instance_id.to_string(),
                proposal.wallet_id,
                format!("{:#x}", proposal.wallet_address),
                Millis(proposal.created_at),
                i64::try_from(proposal.source_revision).context("source revision out of range")?,
                policy_json,
                proposal.rationale
            ],
        )?;
        Ok(changed == 1)
    }

    /// Queue a network profile for the owner to confirm, replacing any earlier
    /// suggestion for the same chain. The latest suggestion is the only one
    /// worth reviewing: an agent that has changed its mind has not left two
    /// decisions to make.
    pub fn put_network_proposal(&mut self, profile: &NetworkConfig) -> Result<()> {
        validate_network(profile)?;
        ensure!(profile.chain_id > 0, "network chain ID must be positive");
        let profile_json = serde_json::to_string(profile)?;
        ensure!(
            profile_json.len() <= MAX_NETWORK_PROFILE_BYTES,
            "network profile exceeds {MAX_NETWORK_PROFILE_BYTES} bytes"
        );
        let pending = self.count_network_proposals()?;
        let replacing = self.network_proposal(profile.chain_id)?.is_some();
        ensure!(
            replacing || pending < MAX_PENDING_NETWORK_PROPOSALS,
            "{pending} network suggestions already await review; the owner must resolve them in the Networks screen before more can be suggested"
        );
        self.connection.execute(
            "INSERT INTO network_proposals(chain_id, profile_json, proposed_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(chain_id) DO UPDATE SET
                 profile_json = excluded.profile_json,
                 proposed_at = excluded.proposed_at",
            params![
                i64::try_from(profile.chain_id).context("chain ID out of range")?,
                profile_json,
                Millis(crate::sql::now()),
            ],
        )?;
        Ok(())
    }

    pub fn network_proposal(&self, chain_id: u64) -> Result<Option<NetworkConfig>> {
        let chain_id = i64::try_from(chain_id).context("chain ID out of range")?;
        let row: Option<String> = self
            .connection
            .query_row(
                "SELECT profile_json FROM network_proposals WHERE chain_id = ?1",
                [chain_id],
                |row| row.get(0),
            )
            .optional()?;
        row.map(|json| {
            serde_json::from_str(&json).context("stored network proposal is invalid JSON")
        })
        .transpose()
    }

    /// Every network suggestion awaiting the owner, oldest first so review
    /// order matches the order they arrived in.
    pub fn network_proposals(&self) -> Result<Vec<NetworkConfig>> {
        let mut statement = self
            .connection
            .prepare("SELECT profile_json FROM network_proposals ORDER BY proposed_at, chain_id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut proposals = Vec::new();
        for row in rows {
            proposals.push(
                serde_json::from_str(&row?).context("stored network proposal is invalid JSON")?,
            );
        }
        Ok(proposals)
    }

    pub fn count_network_proposals(&self) -> Result<u64> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM network_proposals", [], |row| {
                    row.get(0)
                })?;
        u64::try_from(count).context("network proposal count is negative")
    }

    /// Remove a suggestion once it has been decided, either way.
    /// Discard exactly the profile that was reviewed, if it is still the
    /// pending one for its chain. Returns whether it was.
    ///
    /// `network review` snapshots the queue, shows the owner what would be
    /// stored, and then waits — on a confirmation, a chain-ID probe, and an OS
    /// presence check. An agent may replace the suggestion for that chain at
    /// any point in there, pointing it at a different endpoint. Deleting by
    /// chain ID alone consumed that replacement under a decision made about
    /// its predecessor, so a profile the owner never saw disappeared without
    /// being reviewed or stored.
    pub fn discard_network_proposal(&mut self, profile: &NetworkConfig) -> Result<bool> {
        let profile_json = serde_json::to_string(profile)?;
        let changed = self.connection.execute(
            "DELETE FROM network_proposals WHERE chain_id = ?1 AND profile_json = ?2",
            params![
                i64::try_from(profile.chain_id).context("chain ID out of range")?,
                profile_json
            ],
        )?;
        Ok(changed == 1)
    }

    /// Retire exactly one wallet lifecycle while retaining its audit history.
    /// Pending approvals and locally signed-but-unsubmitted bytes are made
    /// unusable; broadcast/cancelling rows remain reconcilable by address.
    pub(crate) fn retire_wallet(&mut self, wallet: &WalletMetadata) -> Result<()> {
        let transaction = self.connection.transaction()?;
        let retired_at = crate::sql::now();
        let changed = transaction.execute(
            "UPDATE wallet_instances SET retired_at = ?4
             WHERE instance_id = ?1 AND wallet_id = ?2 AND wallet_address = ?3
               AND retired_at IS NULL",
            params![
                wallet.instance_id.to_string(),
                wallet.id,
                format!("{:#x}", wallet.address),
                Millis(retired_at)
            ],
        )?;
        if changed == 0 {
            let already_retired: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM wallet_instances
                    WHERE instance_id = ?1 AND wallet_id = ?2 AND wallet_address = ?3
                      AND retired_at IS NOT NULL
                 )",
                params![
                    wallet.instance_id.to_string(),
                    wallet.id,
                    format!("{:#x}", wallet.address)
                ],
                |row| row.get(0),
            )?;
            if !already_retired {
                let state: Option<(String, Option<String>, Option<i64>)> = transaction
                    .query_row(
                        "SELECT wallet_id, wallet_address, retired_at FROM wallet_instances
                         WHERE instance_id = ?1",
                        [wallet.instance_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                anyhow::bail!("wallet instance is not active (stored state: {state:?})");
            }
        }
        transaction.execute(
            "DELETE FROM policy_proposals WHERE wallet_instance_id = ?1",
            [wallet.instance_id.to_string()],
        )?;
        transaction.execute(
            "UPDATE pending_transactions SET status = 'cancelled', updated_at = ?2,
                    generation = generation + 1
             WHERE wallet_instance_id = ?1 AND status IN ('awaiting_approval', 'signed')",
            params![wallet.instance_id.to_string(), Millis(retired_at)],
        )?;
        transaction.execute(
            "UPDATE pending_typed_data SET status = 'rejected', decided_at = ?2, updated_at = ?2
             WHERE wallet_instance_id = ?1 AND status = 'awaiting_approval'",
            params![wallet.instance_id.to_string(), Millis(retired_at)],
        )?;
        transaction.execute(
            "UPDATE pending_messages SET status = 'rejected', decided_at = ?2, updated_at = ?2
             WHERE wallet_instance_id = ?1 AND status = 'awaiting_approval'",
            params![wallet.instance_id.to_string(), Millis(retired_at)],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Roll back a wallet instance that was never published in configuration.
    /// This is the only destructive instance cleanup: no caller can name an
    /// already-active predecessor by display name.
    pub(crate) fn abandon_unpublished(&mut self, instance_id: Uuid) -> Result<()> {
        let transaction = self.connection.transaction()?;
        for table in [
            "policy_proposals",
            "pending_transactions",
            "pending_typed_data",
            "pending_messages",
            "wallet_policies",
        ] {
            transaction.execute(
                &format!("DELETE FROM {table} WHERE wallet_instance_id = ?1"),
                [instance_id.to_string()],
            )?;
        }
        transaction.execute(
            "DELETE FROM wallet_instances WHERE instance_id = ?1",
            [instance_id.to_string()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Test-only erasure helper for fixtures written against the pre-history
    /// store. Production retirement is append-only via [`Self::retire_wallet`].
    ///
    /// A wallet ID is a name the owner chose, and names get reused. Everything
    /// here is keyed on that name rather than on the key it stood for: the
    /// policy that decides what signs without asking, the proposal waiting to
    /// replace it, and every queued transaction, message, and typed-data
    /// request. A wallet's key exists once and cannot come back, so when it
    /// goes, all of that describes a wallet that no longer exists — and a
    /// later wallet created under the same name would otherwise inherit it
    /// while holding a completely different key.
    ///
    /// One transaction: either the name is clear or nothing was touched.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn purge(&mut self, wallet_id: &str) -> Result<()> {
        validate_wallet_id(wallet_id)?;
        let transaction = self.connection.transaction()?;
        for table in [
            "policy_proposals",
            "pending_transactions",
            "pending_typed_data",
            "pending_messages",
        ] {
            transaction.execute(
                &format!("DELETE FROM {table} WHERE wallet_id = ?1"),
                params![wallet_id],
            )?;
        }
        transaction.execute(
            "DELETE FROM wallet_policies WHERE wallet_id = ?1",
            [wallet_id],
        )?;
        transaction.execute(
            "DELETE FROM wallet_instances WHERE wallet_id = ?1",
            [wallet_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Every transaction under this wallet whose bytes may still reach the
    /// chain.
    ///
    /// Removal consults this *before* destroying the credential. `purge`
    /// deletes these rows unconditionally, which is right where it is called
    /// at creation time -- the previous wallet's key is already gone and the
    /// name has to become usable again -- and wrong as the second half of a
    /// removal: it throws away the exact signed envelope, the hashes, and the
    /// cancellation state that are the only means of observing, rebroadcasting
    /// or cancelling something already authorized and possibly already sent.
    ///
    /// So this is not a check inside `purge`. The two callers want different
    /// things, and the one that must refuse is the one that is about to
    /// destroy a key.
    pub fn in_flight_transactions_for_wallet(
        &self,
        wallet: &WalletMetadata,
    ) -> Result<Vec<InFlightTransaction>> {
        self.in_flight_transactions_for_address(wallet.address)
    }

    fn in_flight_transactions_for_address(
        &self,
        address: Address,
    ) -> Result<Vec<InFlightTransaction>> {
        let placeholders = IN_FLIGHT_STATUSES
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement = self.connection.prepare(&format!(
            "SELECT request_id, chain_id, status FROM pending_transactions
             WHERE wallet_address = ?1 AND (
                 status IN ({placeholders})
                 OR (status IN ('confirmed', 'reverted', 'cancelled')
                     AND settlement_transaction_hash IS NOT NULL
                     AND finalized_at IS NULL)
             )
             ORDER BY created_at"
        ))?;
        let wallet_address = format!("{address:#x}");
        let mut parameters: Vec<&dyn rusqlite::ToSql> = vec![&wallet_address];
        for status in &IN_FLIGHT_STATUSES {
            parameters.push(status);
        }
        let rows = statement
            .query_map(parameters.as_slice(), |row| {
                Ok(InFlightTransaction {
                    request_id: row.get(0)?,
                    chain_id: row.get::<_, i64>(1)?.to_string(),
                    status: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn in_flight_transactions(&self, wallet_id: &str) -> Result<Vec<InFlightTransaction>> {
        validate_wallet_id(wallet_id)?;
        let address: Option<String> = self
            .connection
            .query_row(
                "SELECT wallet_address FROM wallet_instances
             WHERE wallet_id = ?1 AND retired_at IS NULL",
                [wallet_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(address) = address else {
            return Ok(Vec::new());
        };
        self.in_flight_transactions_for_address(Address::from_str(&address)?)
    }

    /// Deletes a policy only if it still has the revision reviewed by the
    /// caller. This is used when removing the corresponding wallet.
    #[cfg(any(test, feature = "test-hooks"))]
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
            params![wallet_id, Millis(crate::sql::now())],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn policy_history_count(&self, wallet_id: &str) -> Result<u64> {
        validate_wallet_id(wallet_id)?;
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM wallet_policies WHERE wallet_id = ?1",
            [wallet_id],
            |row| row.get(0),
        )?;
        u64::try_from(count).context("policy history count is negative")
    }
}

fn parse_proposal(
    wallet_instance_id: Uuid,
    wallet_id: &str,
    wallet_address: &str,
    source_revision: i64,
    policy_json: &str,
    rationale: String,
    created_at: DateTime<Utc>,
) -> Result<PolicyProposal> {
    let value = serde_json::from_str(policy_json).context("stored proposal is invalid JSON")?;
    Ok(PolicyProposal {
        wallet_instance_id,
        wallet_id: wallet_id.into(),
        wallet_address: Address::from_str(wallet_address)
            .context("stored proposal wallet identity is invalid")?,
        source_revision: u64::try_from(source_revision)
            .context("stored proposal revision is invalid")?,
        policy: WalletPolicy::parse(value).context("stored proposal policy is invalid")?,
        rationale,
        created_at,
    })
}

/// Run `statements` inside one `BEGIN IMMEDIATE` transaction, one statement
/// per `execute_batch` call.
///
/// Deliberately not one multi-statement string: preparing such a string
/// against the bundled `SQLCipher` build overflows the stack on Windows MSVC,
/// while the identical statements executed individually succeed. The failed
/// transaction is rolled back so an error never leaves the connection inside
/// an open transaction.
/// The schema version recorded in the database, or `None` when the
/// `schema_metadata` table does not exist. A present table without its
/// singleton row is corruption, not absence, and fails.
fn schema_version(connection: &Connection) -> Result<Option<i64>> {
    let table: Option<String> = connection
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_metadata'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if table.is_none() {
        return Ok(None);
    }
    let version: Option<i64> = connection
        .query_row(
            "SELECT version FROM schema_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let version = version.context("policy database schema_metadata holds no version row")?;
    Ok(Some(version))
}

/// One step from the schema version below it to the version it names.
///
/// Every step is additive — a new table, a new index, a new column with a
/// default — and that is a rule rather than a coincidence of the steps written
/// so far. A migration that dropped or rewrote a column would be a migration
/// that can lose signing history or, worse, silently reinterpret it, on a
/// database whose only copy is the owner's. Anything genuinely destructive
/// belongs in an explicit, owner-visible operation, not in a startup path that
/// runs before the window opens.
struct Migration {
    to_version: i64,
    statements: &'static [&'static str],
    /// Data this step writes, for a migration whose content is a table the
    /// build ships rather than a change to the schema.
    ///
    /// Runs after the statements and inside the same transaction as the
    /// version bump, so a step that seeds is as all-or-nothing as one that
    /// only adds a column.
    seed: Option<fn(&Connection) -> Result<()>>,
}

/// The ordered path from any schema this build can upgrade to the current one.
///
/// Before this existed, a version other than the current one was refused
/// outright, which is the correct answer for a *newer* database — this build
/// cannot know what a later schema means — and the wrong one for an older
/// database, where refusing bricks a wallet whose keys are fine.
const MIGRATIONS: &[Migration] = &[
    Migration {
        to_version: 4,
        statements: &[
            AUTOMATIONS_TABLE,
            AUTOMATIONS_WALLET_INDEX,
            AUTOMATIONS_KEY_INDEX,
        ],
        seed: None,
    },
    Migration {
        to_version: 5,
        statements: &[
            "ALTER TABLE pending_transactions ADD COLUMN hidden_at INTEGER",
            AUTOMATION_RUNS_TABLE,
            AUTOMATION_RUNS_INDEX,
        ],
        seed: None,
    },
    // Every row that existed before this column did was queued because the
    // policy would not sign it, which is exactly what the default says, so
    // the added column needs no backfill to be true of the history it joins.
    Migration {
        to_version: 6,
        statements: &[
            "ALTER TABLE pending_transactions ADD COLUMN requested_review INTEGER NOT NULL
                 DEFAULT 0 CHECK (requested_review IN (0, 1))",
        ],
        seed: None,
    },
    // Display data of the weakest kind: roughly what one whole token is worth,
    // as the owner has said, read by nothing but the order and the default
    // visibility of rows on the portfolio tab. Every token that predates the
    // column has no price, which is exactly what a null says.
    Migration {
        to_version: 7,
        statements: &["ALTER TABLE tokens ADD COLUMN approximate_usd_price REAL
                 CHECK (approximate_usd_price IS NULL OR approximate_usd_price >= 0.0)"],
        seed: None,
    },
    // A column nobody has filled in orders nothing, so the values this build
    // ships are written into the rows that have none. A database created after
    // this seeds the same values as it inserts the default token list, which is
    // why this step exists only for the databases that came before it.
    //
    // Where a row already carries a value, it is the owner's and is left alone.
    Migration {
        to_version: 8,
        statements: &[],
        seed: Some(seed_token_prices),
    },
    // A chain's own currency needed somewhere of its own to be worth
    // something: it has no token row, and the shipped snapshot covers the
    // chains it covers.
    Migration {
        to_version: 9,
        statements: &[NATIVE_TOKEN_PRICES_TABLE],
        seed: None,
    },
    // Which channel delivered a plan, and what that channel knew about who
    // asked, as the closed structure `RequestSource` serializes to. Policy
    // rules may match on it, so it is kept apart from the `plan_source` line
    // beside it, which is display text a requester half-authored.
    //
    // Deliberately not backfilled. Every row that predates the column was
    // decided by a policy that had no source matcher in it, so there is no
    // value that would make the history more true than a null does — and a
    // guess written here would be a guess a rule could later match on. Null
    // reads back as `RequestSource::Unknown`, which no matcher covers.
    Migration {
        to_version: 10,
        statements: &["ALTER TABLE pending_transactions ADD COLUMN request_source TEXT"],
        seed: None,
    },
];

/// Write the shipped approximate values into confirmed tokens that have none.
///
/// Display data of the weakest kind — it orders the portfolio tab and decides
/// which of its rows are dust, and is read by nothing else — so a token the
/// snapshot has never heard of is left unpriced rather than guessed at.
fn seed_token_prices(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "UPDATE tokens SET approximate_usd_price = ?3
         WHERE chain_id = ?1 AND address = ?2 AND approximate_usd_price IS NULL",
    )?;
    for price in crate::token_prices::seeded_prices() {
        let chain_id = i64::try_from(price.chain_id).context("chain ID out of range")?;
        statement.execute(params![chain_id, Blob(price.address), price.usd_price])?;
    }
    Ok(())
}

/// Brings an existing database up to [`SCHEMA_VERSION`], returning the version
/// it ends at.
///
/// A newer database is returned untouched for the caller's check to refuse: it
/// is not this build's to interpret, and writing to it would be worse than
/// failing to open it. Each step commits with its own version bump, so an
/// interruption between two steps leaves a database that is consistently at the
/// earlier version and resumes from there on the next start.
fn migrate(connection: &Connection, from_version: i64) -> Result<i64> {
    let mut version = from_version;
    for migration in MIGRATIONS {
        if migration.to_version <= version {
            continue;
        }
        ensure!(
            migration.to_version == version + 1,
            "no migration path from policy database schema {version}"
        );
        let record_version = format!(
            "UPDATE schema_metadata SET version = {} WHERE singleton = 1",
            migration.to_version
        );
        let mut statements = migration.statements.to_vec();
        statements.push(record_version.as_str());
        run_transaction_with(connection, &statements, migration.seed).with_context(|| {
            format!(
                "failed to migrate the policy database from schema {version} to {}",
                migration.to_version
            )
        })?;
        version = migration.to_version;
    }
    Ok(version)
}

/// Creates the complete current schema in one transaction on an empty
/// database. Every statement runs individually: passing one multi-statement
/// string to `execute_batch` overflows the stack on Windows against the
/// bundled `SQLCipher`, while the identical statements executed one at a time
/// succeed; see docs/windows-sqlcipher-overflow.md.
///
/// No queue carries a deadline column, and no status is time-derived: nothing
/// about what may be signed is decided by reading this machine's clock, which
/// anything running as the owner can set. A transaction that must not execute
/// after some moment carries that deadline in the calldata the user approved,
/// where the chain enforces it and simulation surfaces it.
fn create_current_schema(connection: &Connection) -> Result<()> {
    let record_version =
        format!("INSERT INTO schema_metadata(singleton, version) VALUES (1, {SCHEMA_VERSION})");
    run_transaction(
        connection,
        &[
            "CREATE TABLE schema_metadata (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 version INTEGER NOT NULL
             ) STRICT",
            "CREATE TABLE application_settings (
                 key TEXT PRIMARY KEY NOT NULL,
                 value_json TEXT NOT NULL,
                 updated_at INTEGER NOT NULL
             ) STRICT",
            "CREATE TABLE wallet_instances (
                 instance_id TEXT PRIMARY KEY NOT NULL CHECK (length(instance_id) = 36),
                 wallet_id TEXT NOT NULL,
                 wallet_address TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 retired_at INTEGER
             ) STRICT",
            "CREATE UNIQUE INDEX wallet_instances_active_name
                 ON wallet_instances(wallet_id) WHERE retired_at IS NULL",
            "CREATE UNIQUE INDEX wallet_instances_active_address
                 ON wallet_instances(wallet_address) WHERE retired_at IS NULL",
            "CREATE TABLE wallet_policies (
                 wallet_instance_id TEXT NOT NULL CHECK (length(wallet_instance_id) = 36),
                 wallet_id TEXT NOT NULL,
                 wallet_address TEXT NOT NULL,
                 policy_json TEXT NOT NULL,
                 revision INTEGER NOT NULL CHECK (revision > 0),
                 updated_at INTEGER NOT NULL,
                 PRIMARY KEY (wallet_instance_id, revision),
                 FOREIGN KEY (wallet_instance_id) REFERENCES wallet_instances(instance_id)
             ) STRICT",
            // Transaction lifecycle. 'replaced' marks an envelope whose nonce
            // was consumed by a different transaction (for example the same
            // key imported on another device), so those exact bytes can never
            // mine. 'cancelling' plus the cancel_* columns carry an
            // owner-requested 0-value self-send racing the stuck envelope at
            // its own nonce; the cancel lives on the same row and the
            // in-flight unique index counts the pair as one slot, so one
            // wallet and chain never has two logical transactions in flight.
            "CREATE TABLE pending_transactions (
                 request_id BLOB PRIMARY KEY NOT NULL CHECK (length(request_id) = 16),
                 wallet_instance_id TEXT NOT NULL CHECK (length(wallet_instance_id) = 36),
                 wallet_id TEXT NOT NULL,
                 wallet_address TEXT NOT NULL,
                 network_name TEXT NOT NULL,
                 chain_id INTEGER NOT NULL CHECK (chain_id > 0),
                 plan_json TEXT NOT NULL,
                 plan_digest BLOB NOT NULL CHECK (length(plan_digest) = 32),
                 plan_source TEXT,
                 requesting_harness_kind TEXT CHECK (requesting_harness_kind IS NULL OR requesting_harness_kind IN ('codex','claude_code','claude_desktop','gemini_cli','cursor','opencode')),
                 request_source TEXT,
                 policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
                 status TEXT NOT NULL CHECK (status IN (
                     'awaiting_approval', 'rejected', 'signed', 'submitting',
                     'broadcast', 'confirmed', 'reverted', 'cancelled',
                     'replaced', 'cancelling'
                 )),
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL,
                 -- The lease generation. Every lifecycle write increments it,
                 -- and the compare-and-set transitions match on it rather than
                 -- on `updated_at`: a wall clock at millisecond resolution
                 -- gives two writes in the same millisecond the same name, and
                 -- a lease whose name repeats is not a lease.
                 generation INTEGER NOT NULL DEFAULT 0,
                 -- When a human decided, whichever way they decided. One
                 -- column because a request gets one decision: two nullable
                 -- timestamps could say a row was both approved and rejected,
                 -- and the schema had nothing to say about that. `status`
                 -- names which decision it was — rejection is terminal, so a
                 -- decided row that is not 'rejected' was approved.
                 decided_at INTEGER,
                 serialized_transaction BLOB
                     CHECK (serialized_transaction IS NULL
                         OR length(serialized_transaction) > 0),
                 signed_transaction_hash BLOB
                     CHECK (signed_transaction_hash IS NULL
                         OR length(signed_transaction_hash) = 32),
                 broadcast_transaction_hash BLOB
                     CHECK (broadcast_transaction_hash IS NULL
                         OR length(broadcast_transaction_hash) = 32),
                 block_number INTEGER CHECK (block_number IS NULL OR block_number >= 0),
                 block_hash BLOB CHECK (block_hash IS NULL OR length(block_hash) = 32),
                 settlement_transaction_hash BLOB
                     CHECK (settlement_transaction_hash IS NULL
                         OR length(settlement_transaction_hash) = 32),
                 finalized_at INTEGER,
                 approval_required INTEGER NOT NULL DEFAULT 1
                     CHECK (approval_required IN (0, 1)),
                 -- Whoever submitted the plan asked for a human to look at it,
                 -- rather than the policy having refused to sign it. The
                 -- review document is authored fresh when the owner opens it,
                 -- by which time the policy evaluation says the plan is
                 -- allowed and nothing is left to explain why they are being
                 -- asked. This column is that explanation, and it only ever
                 -- adds a review: no writer clears it.
                 requested_review INTEGER NOT NULL DEFAULT 0
                     CHECK (requested_review IN (0, 1)),
                 review_digest BLOB
                     CHECK (review_digest IS NULL OR length(review_digest) = 32),
                 cancel_serialized_transaction BLOB
                     CHECK (cancel_serialized_transaction IS NULL
                         OR length(cancel_serialized_transaction) > 0),
                 -- The cancellation hashes concatenated, oldest first. A JSON
                 -- array of hex strings needed a parser and a length check on
                 -- every element; a blob whose length is a multiple of 32 and
                 -- within the attempt cap is the same claim, made by the
                 -- schema, and it slices apart without allocating.
                 cancel_transaction_hashes BLOB
                     CHECK (cancel_transaction_hashes IS NULL
                         OR (length(cancel_transaction_hashes) > 0
                             AND length(cancel_transaction_hashes) % 32 = 0
                             AND length(cancel_transaction_hashes) <= 256)),
                 -- When the owner cleared this row out of their activity list.
                 --
                 -- Hidden, never deleted. An automation's run history names the
                 -- transaction each tick produced, and a person auditing what
                 -- their wallet did on its own must be able to open any of them
                 -- however long ago it ran. Clearing history is about what the
                 -- inbox shows, and it would be a poor trade to answer it by
                 -- destroying the only local record of a transaction nobody
                 -- watched being made.
                 hidden_at INTEGER,
                 gas_used INTEGER CHECK (gas_used IS NULL OR gas_used >= 0),
                 effective_gas_price BLOB
                     CHECK (effective_gas_price IS NULL
                         OR length(effective_gas_price) = 16),
                 -- Exactly which rows carry a decision. An automatic
                 -- transaction has none, because nobody decided anything —
                 -- which `approval_required` and the decision timestamps,
                 -- being unrelated columns, could not say before. A queued
                 -- request has none yet. Anything further along was decided.
                 --
                 -- 'cancelled' is the one status that genuinely does not say:
                 -- it is reached both by discarding a request the owner had
                 -- already approved and by the system dropping a queued one
                 -- when a policy is replaced or a wallet purged, and only the
                 -- first of those involved a person. Leaving it open is the
                 -- honest reading; every other status is pinned.
                 CHECK (
                     CASE
                         WHEN approval_required = 0 THEN decided_at IS NULL
                         WHEN status = 'awaiting_approval' THEN decided_at IS NULL
                         WHEN status = 'cancelled' THEN 1
                         ELSE decided_at IS NOT NULL
                     END
                 ),
                 CHECK (
                     status <> 'awaiting_approval'
                     OR (serialized_transaction IS NULL AND signed_transaction_hash IS NULL)
                 ),
                 CHECK (
                     (serialized_transaction IS NULL AND signed_transaction_hash IS NULL)
                     OR (serialized_transaction IS NOT NULL AND signed_transaction_hash IS NOT NULL)
                 ),
                 CHECK (
                     (cancel_serialized_transaction IS NULL AND cancel_transaction_hashes IS NULL)
                     OR (cancel_serialized_transaction IS NOT NULL
                         AND cancel_transaction_hashes IS NOT NULL
                         AND serialized_transaction IS NOT NULL)
                 )
             ) STRICT",
            "CREATE INDEX pending_transactions_wallet_created
                 ON pending_transactions(wallet_instance_id, created_at DESC)",
            "CREATE INDEX pending_transactions_signed_hash
                 ON pending_transactions(signed_transaction_hash)
                 WHERE signed_transaction_hash IS NOT NULL",
            "CREATE UNIQUE INDEX pending_transactions_wallet_chain_in_flight
                 ON pending_transactions(wallet_address, chain_id)
                 WHERE status IN ('signed', 'submitting', 'broadcast', 'cancelling')
                    OR (status IN ('confirmed', 'reverted', 'cancelled')
                        AND settlement_transaction_hash IS NOT NULL
                        AND finalized_at IS NULL)",
            "CREATE UNIQUE INDEX pending_transactions_unique_pending_plan
                 ON pending_transactions(wallet_instance_id, chain_id, plan_digest)
                 WHERE status = 'awaiting_approval'",
            "CREATE TABLE pending_typed_data (
                 request_id BLOB PRIMARY KEY NOT NULL CHECK (length(request_id) = 16),
                 wallet_instance_id TEXT NOT NULL CHECK (length(wallet_instance_id) = 36),
                 wallet_id TEXT NOT NULL,
                 wallet_address TEXT NOT NULL,
                 chain_id INTEGER NOT NULL CHECK (chain_id > 0),
                 typed_data_json TEXT NOT NULL,
                 digest BLOB NOT NULL CHECK (length(digest) = 32),
                 status TEXT NOT NULL CHECK (status IN (
                     'awaiting_approval', 'rejected', 'signed'
                 )),
                 -- Who asked, when the caller knows: a dapp reached over
                 -- WalletConnect names itself, an MCP agent does not and
                 -- stores the empty string. Stored rather than passed to the
                 -- review, because the review used to be told by whichever
                 -- caller was handling the row at the time -- which for a row
                 -- two dapps both asked for named the wrong one. It is also
                 -- part of the deduplication key below, so two dapps asking
                 -- for identical bytes get two decisions rather than sharing
                 -- one.
                 --
                 -- Empty rather than NULL because it is in a unique index, and
                 -- SQLite counts NULLs as distinct: nullable, two unnamed
                 -- agents' identical requests would each get their own row and
                 -- the deduplication that exists to keep the review short
                 -- would quietly stop working.
                 requester TEXT NOT NULL DEFAULT '',
                 requesting_harness_kind TEXT CHECK (requesting_harness_kind IS NULL OR requesting_harness_kind IN ('codex','claude_code','claude_desktop','gemini_cli','cursor','opencode')),
                 approval_required INTEGER NOT NULL DEFAULT 1
                     CHECK (approval_required IN (0, 1)),
                 policy_revision INTEGER
                     CHECK (policy_revision IS NULL OR policy_revision > 0),
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL,
                 -- One decision per request; `status` names which one it was.
                 -- Stated against `approval_required` exactly as
                 -- pending_transactions is, so the one column that could
                 -- describe a row nobody decided keeps saying so.
                 decided_at INTEGER,
                 signature BLOB CHECK (signature IS NULL OR length(signature) = 65),
                 CHECK (
                     (decided_at IS NOT NULL)
                     = (status <> 'awaiting_approval' AND approval_required = 1)
                 ),
                 CHECK ((status = 'signed') = (signature IS NOT NULL)),
                 CHECK (approval_required = 1 OR policy_revision IS NOT NULL)
             ) STRICT",
            "CREATE UNIQUE INDEX pending_typed_data_unique_awaiting
                 ON pending_typed_data(wallet_instance_id, chain_id, digest, requester)
                 WHERE status = 'awaiting_approval'",
            "CREATE INDEX pending_typed_data_wallet_created
                 ON pending_typed_data(wallet_instance_id, created_at DESC)",
            // EIP-191 message signatures queue exactly like typed data, minus
            // every automatic path: no policy can score a message, so there is
            // no approval_required or policy_revision column to carry.
            //
            // chain_id is 0 when the requester declared none — `personal_sign`
            // binds no chain — because SQLite treats NULLs as distinct in a
            // unique index, which would silently disable the awaiting-request
            // deduplication below. No chain has ID 0, so the sentinel cannot
            // collide with a declared one.
            "CREATE TABLE pending_messages (
                 request_id BLOB PRIMARY KEY NOT NULL CHECK (length(request_id) = 16),
                 wallet_instance_id TEXT NOT NULL CHECK (length(wallet_instance_id) = 36),
                 wallet_id TEXT NOT NULL,
                 wallet_address TEXT NOT NULL,
                 chain_id INTEGER NOT NULL CHECK (chain_id >= 0),
                 message BLOB NOT NULL CHECK (length(message) > 0),
                 message_encoding TEXT NOT NULL
                     CHECK (message_encoding IN ('text', 'hex')),
                 digest BLOB NOT NULL CHECK (length(digest) = 32),
                 status TEXT NOT NULL CHECK (status IN (
                     'awaiting_approval', 'rejected', 'signed'
                 )),
                 -- Who asked, when the caller knows: a dapp reached over
                 -- WalletConnect names itself, an MCP agent does not and
                 -- stores the empty string. Stored rather than passed to the
                 -- review, because the review used to be told by whichever
                 -- caller was handling the row at the time -- which for a row
                 -- two dapps both asked for named the wrong one. It is also
                 -- part of the deduplication key below, so two dapps asking
                 -- for identical bytes get two decisions rather than sharing
                 -- one.
                 --
                 -- Empty rather than NULL because it is in a unique index, and
                 -- SQLite counts NULLs as distinct: nullable, two unnamed
                 -- agents' identical requests would each get their own row and
                 -- the deduplication that exists to keep the review short
                 -- would quietly stop working.
                 requester TEXT NOT NULL DEFAULT '',
                 requesting_harness_kind TEXT CHECK (requesting_harness_kind IS NULL OR requesting_harness_kind IN ('codex','claude_code','claude_desktop','gemini_cli','cursor','opencode')),
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL,
                 -- One decision per request; `status` names which one it was.
                 -- No `approval_required` here, because every message is
                 -- decided by a human, so leaving the queue and being decided
                 -- are the same event.
                 decided_at INTEGER,
                 signature BLOB CHECK (signature IS NULL OR length(signature) = 65),
                 CHECK ((status = 'awaiting_approval') = (decided_at IS NULL)),
                 CHECK ((status = 'signed') = (signature IS NOT NULL))
             ) STRICT",
            "CREATE UNIQUE INDEX pending_messages_unique_awaiting
                 ON pending_messages(wallet_instance_id, chain_id, digest, requester)
                 WHERE status = 'awaiting_approval'",
            "CREATE INDEX pending_messages_wallet_created
                 ON pending_messages(wallet_instance_id, created_at DESC)",
            // Integrity-sensitive display and gating state lives inside the
            // authenticated database: token metadata and legal acceptance
            // must not be forgeable by editing a plain file
            // outside this process.
            "CREATE TABLE tokens (
                 chain_id INTEGER NOT NULL CHECK (chain_id > 0),
                 address BLOB NOT NULL CHECK (length(address) = 20),
                 symbol TEXT,
                 name TEXT,
                 decimals INTEGER
                     CHECK (decimals IS NULL OR (decimals >= 0 AND decimals <= 255)),
                 source TEXT NOT NULL,
                 added_at INTEGER NOT NULL,
                 approximate_usd_price REAL
                     CHECK (approximate_usd_price IS NULL
                         OR approximate_usd_price >= 0.0),
                 PRIMARY KEY (chain_id, address)
             ) STRICT",
            "CREATE TABLE legal_acceptance (
                 document TEXT PRIMARY KEY NOT NULL
                     CHECK (document IN ('terms_of_service', 'privacy_policy')),
                 digest BLOB NOT NULL CHECK (length(digest) = 32),
                 accepted_at INTEGER NOT NULL
             ) STRICT",
            "CREATE TABLE policy_proposals (
                 wallet_instance_id TEXT PRIMARY KEY NOT NULL CHECK (length(wallet_instance_id) = 36),
                 wallet_id TEXT NOT NULL,
                 wallet_address TEXT NOT NULL,
                 source_revision INTEGER NOT NULL CHECK (source_revision > 0),
                 policy_json TEXT NOT NULL,
                 rationale TEXT NOT NULL,
                 requesting_harness_kind TEXT CHECK (requesting_harness_kind IS NULL OR requesting_harness_kind IN ('codex','claude_code','claude_desktop','gemini_cli','cursor','opencode')),
                 created_at INTEGER NOT NULL,
                 FOREIGN KEY (wallet_instance_id) REFERENCES wallet_instances(instance_id)
             ) STRICT",
            TOKEN_PROPOSALS_TABLE,
            NATIVE_TOKEN_PRICES_TABLE,
            NETWORK_PROPOSALS_TABLE,
            AUTOMATIONS_TABLE,
            AUTOMATIONS_WALLET_INDEX,
            AUTOMATIONS_KEY_INDEX,
            AUTOMATION_RUNS_TABLE,
            AUTOMATION_RUNS_INDEX,
            record_version.as_str(),
        ],
    )
}

/// Agent-installed bytecode the scheduler polls, and the bookkeeping one tick
/// leaves behind.
///
/// `policy_revision` is the load-bearing column. An automation is authorized
/// against the policy active when an agent installed it or the owner relinked it,
/// and a tick reads this before it reads anything else: if the wallet's current
/// revision differs, the automation moves to `awaiting_relink` and does not
/// run. Send-time policy evaluation cannot replace that check, because it
/// answers a different question. It says whether a call may proceed; this says
/// whether this stored definition remains bound to the policy revision under
/// which it was installed or reviewed. Without it, widening a policy for an
/// unrelated reason silently re-arms dormant automations. An active agent can
/// replace a key under the current revision, but can already submit any calls
/// that revision permits directly.
///
/// `bytecode` is a `BLOB` for the same reason every other byte string here is:
/// a column of bytes is bytes, where hex `TEXT` would be a claim the schema
/// cannot check. It is bounded by `automation::MAX_BYTECODE_BYTES` before it
/// arrives; the CHECK here restates the floor, not the ceiling, because a
/// limit that lives in two places drifts.
///
/// No deadline column and no time-derived state, matching every other table:
/// `last_tick_at` records what happened, and nothing about whether an
/// automation may run is decided by reading this machine's clock. The schedule
/// picks *when* the scheduler looks; the policy decides what it may do.
const AUTOMATIONS_TABLE: &str = "CREATE TABLE automations (
     automation_id BLOB PRIMARY KEY NOT NULL CHECK (length(automation_id) = 16),
     wallet_instance_id TEXT NOT NULL CHECK (length(wallet_instance_id) = 36),
     wallet_id TEXT NOT NULL,
     wallet_address TEXT NOT NULL,
     chain_id INTEGER NOT NULL CHECK (chain_id > 0),
     -- The caller's own name for this automation, and the whole of what makes
     -- installing one idempotent. An agent that retries after a timeout, or
     -- runs the same setup twice, must end up with one automation rather than
     -- two identical ones both bidding for the signing slot. Unique per
     -- wallet, so re-installing under a key that exists replaces that
     -- automation instead of adding another.
     automation_key TEXT NOT NULL CHECK (length(automation_key) > 0),
     name TEXT NOT NULL CHECK (length(name) > 0),
     bytecode BLOB NOT NULL CHECK (length(bytecode) > 0),
     config BLOB NOT NULL,
     cron_expression TEXT NOT NULL CHECK (length(cron_expression) > 0),
     policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
     state TEXT NOT NULL CHECK (state IN ('enabled', 'disabled', 'awaiting_relink')),
     stopped_reason TEXT,
     consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
     last_tick_at INTEGER,
     last_outcome TEXT,
     -- The transaction the last tick sent, if it sent one. Deliberately not a
     -- foreign key into pending_transactions: that table's rows are purged
     -- with their wallet and pruned by history, and an automation losing its
     -- pointer must not delete the automation. An id with no row left reads
     -- as no record, which is what a caller does with it anyway.
     last_request_id BLOB
         CHECK (last_request_id IS NULL OR length(last_request_id) = 16),
     created_at INTEGER NOT NULL,
     updated_at INTEGER NOT NULL,
     -- An enabled automation is one nothing has stopped, so it carries no
     -- reason. Anything stopped carries one, because 'it is not running and
     -- the wallet will not say why' is the state this feature most has to
     -- avoid.
     CHECK ((state = 'enabled') = (stopped_reason IS NULL)),
     FOREIGN KEY (wallet_instance_id) REFERENCES wallet_instances(instance_id)
 ) STRICT";

const AUTOMATIONS_WALLET_INDEX: &str = "CREATE INDEX automations_wallet_chain
     ON automations(wallet_instance_id, chain_id)";

/// One automation per caller-chosen key per wallet.
///
/// Scoped to the wallet rather than to the whole database because the key is
/// the caller's vocabulary, not the wallet's: two wallets automated by the same
/// agent will use the same obvious names, and making one of those installs fail
/// would be a collision between things that share nothing.
const AUTOMATIONS_KEY_INDEX: &str = "CREATE UNIQUE INDEX automations_wallet_key
     ON automations(wallet_instance_id, automation_key)";

/// Every tick an automation has ever run, and what came of it.
///
/// The automations table keeps only the latest outcome, which answers "is this
/// working right now" and nothing else. A person deciding whether to keep
/// trusting a job that runs unattended needs its whole record: how often it
/// found nothing to do, when it last sent something, and which transaction that
/// was. So each tick appends here.
///
/// `request_id` is not a foreign key, deliberately. The lifecycle table's rows
/// are hidden rather than deleted precisely so this pointer keeps resolving,
/// but a wallet purge does remove them, and a run losing its transaction must
/// not take the run record with it — the history of what the automation *did*
/// is worth keeping even where the transaction detail is gone.
const AUTOMATION_RUNS_TABLE: &str = "CREATE TABLE automation_runs (
     run_id BLOB PRIMARY KEY NOT NULL CHECK (length(run_id) = 16),
     automation_id BLOB NOT NULL CHECK (length(automation_id) = 16),
     ran_at INTEGER NOT NULL,
     outcome TEXT NOT NULL
         CHECK (outcome IN ('skipped', 'idle', 'sent', 'stopped', 'failed')),
     detail TEXT NOT NULL,
     request_id BLOB CHECK (request_id IS NULL OR length(request_id) = 16),
     calls INTEGER NOT NULL DEFAULT 0 CHECK (calls >= 0),
     FOREIGN KEY (automation_id) REFERENCES automations(automation_id) ON DELETE CASCADE
 ) STRICT";

const AUTOMATION_RUNS_INDEX: &str = "CREATE INDEX automation_runs_by_automation
     ON automation_runs(automation_id, ran_at DESC)";

/// Network profiles an agent has suggested, held apart from active configuration
/// until the owner confirms them.
///
/// Keyed on chain ID because that is what identifies a network: a proposal
/// naming a chain already configured is an edit of it, and one naming a chain
/// that is not is an addition. Nothing here is ever consulted when resolving a
/// network for a request — a row becomes reachable only after the owner writes
/// it into the encrypted configuration.
///
/// The whole profile travels as JSON rather than as columns. The review screen
/// has to show the owner exactly what would be stored, and a shape that can
/// drift from `NetworkConfig` is a shape that eventually shows them something
/// else.
const NETWORK_PROPOSALS_TABLE: &str = "CREATE TABLE IF NOT EXISTS network_proposals (
     chain_id INTEGER PRIMARY KEY NOT NULL CHECK (chain_id > 0),
     profile_json TEXT NOT NULL,
     requesting_harness_kind TEXT CHECK (requesting_harness_kind IS NULL OR requesting_harness_kind IN ('codex','claude_code','claude_desktop','gemini_cli','cursor','opencode')),
     proposed_at INTEGER NOT NULL
 ) STRICT";

/// Tokens an agent has suggested, held apart from `tokens` until the owner
/// confirms them. Nothing here is ever read as a display name: a row only
/// becomes a name by being moved into `tokens` from the terminal.
///
/// `source` is the list the suggestion came from, so the review screen can
/// group a hundred suggestions into the handful of decisions they really are.
/// What the owner says a chain's own currency is roughly worth.
///
/// Its own table rather than a row in `tokens`, because a chain's currency has
/// no token contract and the zero address is a sentinel every balance read
/// uses: a row there would name that address in the one place names matter —
/// the review screen — in exchange for a number that only orders a list.
const NATIVE_TOKEN_PRICES_TABLE: &str = "CREATE TABLE IF NOT EXISTS native_token_prices (
     chain_id INTEGER PRIMARY KEY CHECK (chain_id > 0),
     approximate_usd_price REAL NOT NULL CHECK (approximate_usd_price >= 0.0)
 ) STRICT";

const TOKEN_PROPOSALS_TABLE: &str = "CREATE TABLE IF NOT EXISTS token_proposals (
     chain_id INTEGER NOT NULL CHECK (chain_id > 0),
     address BLOB NOT NULL CHECK (length(address) = 20),
     symbol TEXT NOT NULL,
     name TEXT,
     decimals INTEGER NOT NULL CHECK (decimals >= 0 AND decimals <= 255),
     source TEXT NOT NULL,
     requesting_harness_kind TEXT CHECK (requesting_harness_kind IS NULL OR requesting_harness_kind IN ('codex','claude_code','claude_desktop','gemini_cli','cursor','opencode')),
     proposed_at INTEGER NOT NULL,
     PRIMARY KEY (chain_id, address)
 ) STRICT";

fn run_transaction(connection: &Connection, statements: &[&str]) -> Result<()> {
    run_transaction_with(connection, statements, None)
}

/// The statements, then whatever data step the caller carries, then the
/// commit — one transaction over all of it, so a migration that ships a table
/// is as all-or-nothing as one that only adds a column.
fn run_transaction_with(
    connection: &Connection,
    statements: &[&str],
    seed: Option<fn(&Connection) -> Result<()>>,
) -> Result<()> {
    connection.execute_batch("BEGIN IMMEDIATE")?;
    for statement in statements {
        if let Err(error) = connection.execute_batch(statement) {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(error).context("schema statement failed");
        }
    }
    if let Some(seed) = seed
        && let Err(error) = seed(connection)
    {
        let _ = connection.execute_batch("ROLLBACK");
        return Err(error).context("schema seed failed");
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

fn load_or_create_database_key(data_dir: &Path, database_exists: bool) -> Result<DatabaseKey> {
    #[cfg(any(test, feature = "test-hooks"))]
    if let Some(key) = registered_test_database_key(data_dir)? {
        return Ok(key);
    }

    // An ephemeral session keeps its key beside its database and never reaches
    // the credential store. Absent from a release build, where neither this
    // call nor the module behind it exists.
    #[cfg(debug_assertions)]
    if let Some(key) = crate::ephemeral::database_key(data_dir, database_exists)? {
        return Ok(key);
    }
    #[cfg(not(debug_assertions))]
    let _ = data_dir;

    // `block_in_place`, not a direct call: on Linux, `keyring`'s backend
    // connects to D-Bus through `zbus`'s *blocking* API, which starts its
    // own Tokio runtime on first use. Every caller of this function runs
    // inside our own Tokio runtime already, and Tokio panics rather than
    // nest one runtime inside another ("Cannot start a runtime from within a
    // runtime") -- unconditionally, before ever checking whether a Secret
    // Service is even reachable. `block_in_place` marks this thread as
    // blocking for the rest of this call, which is exactly what lets the
    // nested runtime inside `keyring` run without Tokio refusing.
    tokio::task::block_in_place(|| {
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
                // ThreadRng's error type is Infallible, so Ok is irrefutable.
                let Ok(()) = rand::rng().try_fill_bytes(&mut bytes);
                entry
                    .set_secret(&bytes)
                    .context("failed to save policy database key")?;
                // Read it back before trusting it. `policies.lock` is locked by
                // pathname, and the filesystem is untrusted — so two processes can
                // hold locks on different inodes, both see no database, and both
                // generate a key. The second `set_secret` wins, and the first
                // process then creates a database encrypted under a key the
                // credential store no longer holds, which nothing can open.
                //
                // The readback makes the credential store itself the arbiter,
                // which does not depend on the lock file's identity.
                let mut stored = entry
                    .get_secret()
                    .context("failed to confirm the saved policy database key")?;
                let matches = stored == bytes;
                stored.zeroize();
                ensure!(
                    matches,
                    "another process initialized the policy database key at the same time; run this command again"
                );
                Ok(DatabaseKey::new(bytes))
            }
            Err(error) => Err(error).context("failed to load policy database key"),
        }
    })
}

#[cfg(test)]
#[path = "policy_store_test.rs"]
mod tests;
