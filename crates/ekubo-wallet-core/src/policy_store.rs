//! SQLCipher-backed wallet security database.
//!
//! Transaction counters and rolling limits deliberately do not live here. A
//! restored database cannot restore consumed allowance and make it spendable
//! again. Pending approvals and transaction lifecycle records use separate
//! tables so exact signed bytes can be recovered without becoming spend state.

use crate::{
    config::{
        NetworkConfig, create_private_dir, open_private_file, validate_network, validate_wallet_id,
    },
    core::policy::WalletPolicy,
    sql::{Millis, RowExt},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use keyring::{Entry, Error as KeyringError};
use rand::TryRng;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The first and only encrypted database schema shipped by the desktop wallet.
const SCHEMA_VERSION: i64 = 1;
pub const DATABASE_FILE: &str = "wallet.db";
const DATABASE_LOCK_FILE: &str = "wallet.lock";
/// The credential-store entry holding this database's key.
///
/// Named for the database rather than for policies, because policies are only
/// one of the things it protects: the same file holds the pending signing
/// queues and the token names a reviewer reads before
/// approving a transfer. A name that says "policy" invites the reading that
/// everything else in there is incidental, and none of it is.
const KEYRING_SERVICE: &str = "org.ekubo.wallet.db.v2";
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
    pub wallet_id: String,
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
    pub wallet_id: String,
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
            Some(version) => version,
        };
        ensure!(
            version == SCHEMA_VERSION,
            "policy database schema {version} is not the schema this build understands \
             ({SCHEMA_VERSION})"
        );
        if seed_defaults == SeedDefaults::Yes {
            crate::default_tokens::rename_legacy_source(&connection)?;
        }
        verify_integrity(&connection)?;
        // Narrowed through a handle that refuses to follow a link, not through
        // the name. This runs after the connection is open, which is exactly
        // the window in which a by-path chmod could be pointed at some other
        // reachable file.
        drop(open_private_file(path)?);
        Ok(Self { connection })
    }

    /// Re-reads the schema version through this connection. A long-running
    /// server holds its stores open, so a database replaced underneath it
    /// would otherwise be written to
    /// through a stale understanding of its shape. Refusing here turns that
    /// into an explicit "restart the server" error on every request.
    pub fn assert_schema_current(&self) -> Result<()> {
        let version = schema_version(&self.connection)?.context(
            "policy database lost its schema version; restart the ekubo-wallet MCP server",
        )?;
        ensure!(
            version == SCHEMA_VERSION,
            "policy database schema changed from {SCHEMA_VERSION} to {version} underneath \
             this process; restart the ekubo-wallet MCP server"
        );
        Ok(())
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
                        row.time(2)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(json, revision, updated_at)| {
            let revision = u64::try_from(revision).context("stored policy revision is invalid")?;
            let value = serde_json::from_str(&json).context("stored policy is invalid JSON")?;
            let policy = WalletPolicy::parse(value).context("stored policy is invalid")?;
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
        let transaction = self.connection.transaction()?;
        let stored = Self::apply_policy(&transaction, wallet_id, policy, expected_revision)?;

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
    pub fn consume_proposal(&mut self, proposal: &PolicyProposal) -> Result<StoredPolicy> {
        validate_wallet_id(&proposal.wallet_id)?;
        let policy_json = serde_json::to_string(&proposal.policy)?;
        let transaction = self.connection.transaction()?;
        let consumed = transaction.execute(
            "DELETE FROM policy_proposals
             WHERE wallet_id = ?1 AND created_at = ?2 AND source_revision = ?3
               AND policy_json = ?4 AND rationale = ?5",
            params![
                proposal.wallet_id,
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
        let stored = Self::apply_policy(
            &transaction,
            &proposal.wallet_id,
            &proposal.policy,
            Some(proposal.source_revision),
        )?;
        transaction.commit()?;
        Ok(stored)
    }

    /// The policy write both entry points share, run inside a transaction the
    /// caller owns. That is what lets `consume_proposal` make applying a
    /// proposal and consuming it one step: two separate calls could not be
    /// made atomic from outside.
    fn apply_policy(
        transaction: &rusqlite::Transaction<'_>,
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
        ensure!(
            policy_json.len() <= MAX_POLICY_BYTES,
            "policy document exceeds {MAX_POLICY_BYTES} bytes"
        );
        let updated_at = crate::sql::now();
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
        // Installing where there was no policy clears whatever else the name
        // still holds.
        //
        // `purge` runs at wallet creation, but only after a *successful*
        // custody create; the Accounts screen's repair route reaches here
        // through `put` without it.
        // So a removal whose purge failed, or a creation interrupted between
        // the credential and the policy, left the queues and any proposal in
        // place under a name that a different key now answers to. A wallet
        // with no policy cannot sign anything, so it has no queue of its own
        // to lose: everything here belongs to whatever held the name before.
        //
        // In the same transaction as the policy write, so the name is either
        // clear or unchanged.
        if current.is_none() {
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
        }
        let revision = current.map_or(1, |value| value + 1);
        transaction.execute(
            "INSERT INTO wallet_policies(wallet_id, policy_json, revision, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(wallet_id) DO UPDATE SET
                 policy_json = excluded.policy_json,
                 revision = excluded.revision,
                 updated_at = excluded.updated_at",
            params![wallet_id, policy_json, revision, Millis(updated_at)],
        )?;
        transaction.execute(
            "UPDATE pending_transactions SET status = 'cancelled', updated_at = ?3
             WHERE wallet_id = ?1 AND policy_revision <> ?2
               AND status IN ('awaiting_approval', 'signed')",
            params![wallet_id, revision, Millis(updated_at)],
        )?;
        Ok(StoredPolicy {
            wallet_id: wallet_id.into(),
            policy,
            revision: u64::try_from(revision).expect("positive policy revision"),
            updated_at,
        })
    }

    /// Store or replace the wallet's single pending policy proposal. The
    /// insert re-checks that `source_revision` is the active revision inside
    /// the transaction, so a proposal can never be recorded against a policy
    /// the proposer did not read. The latest proposal always prevails.
    pub fn put_proposal(
        &mut self,
        wallet_id: &str,
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
                "SELECT revision FROM wallet_policies WHERE wallet_id = ?1",
                [wallet_id],
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
                wallet_id, source_revision, policy_json, rationale, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(wallet_id) DO UPDATE SET
                 source_revision = excluded.source_revision,
                 policy_json = excluded.policy_json,
                 rationale = excluded.rationale,
                 created_at = excluded.created_at",
            params![
                wallet_id,
                source,
                policy_json,
                rationale,
                Millis(created_at)
            ],
        )?;
        transaction.commit()?;
        Ok(PolicyProposal {
            wallet_id: wallet_id.into(),
            source_revision,
            policy,
            rationale: rationale.into(),
            created_at,
        })
    }

    pub fn proposal(&self, wallet_id: &str) -> Result<Option<PolicyProposal>> {
        validate_wallet_id(wallet_id)?;
        self.connection
            .query_row(
                "SELECT source_revision, policy_json, rationale, created_at
                 FROM policy_proposals WHERE wallet_id = ?1",
                [wallet_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.time(3)?,
                    ))
                },
            )
            .optional()?
            .map(|(source_revision, policy_json, rationale, created_at)| {
                parse_proposal(
                    wallet_id,
                    source_revision,
                    &policy_json,
                    rationale,
                    created_at,
                )
            })
            .transpose()
    }

    pub fn list_proposals(&self) -> Result<Vec<PolicyProposal>> {
        let mut statement = self.connection.prepare(
            "SELECT wallet_id, source_revision, policy_json, rationale, created_at
             FROM policy_proposals ORDER BY wallet_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.time(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        rows.into_iter()
            .map(
                |(wallet_id, source_revision, policy_json, rationale, created_at)| {
                    parse_proposal(
                        &wallet_id,
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
             WHERE wallet_id = ?1 AND created_at = ?2 AND source_revision = ?3
               AND policy_json = ?4 AND rationale = ?5",
            params![
                proposal.wallet_id,
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

    /// Erase every row this database holds under a wallet ID.
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
    pub fn purge(&mut self, wallet_id: &str) -> Result<()> {
        validate_wallet_id(wallet_id)?;
        let transaction = self.connection.transaction()?;
        for table in [
            "wallet_policies",
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
    pub fn in_flight_transactions(&self, wallet_id: &str) -> Result<Vec<InFlightTransaction>> {
        validate_wallet_id(wallet_id)?;
        let placeholders = IN_FLIGHT_STATUSES
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement = self.connection.prepare(&format!(
            "SELECT request_id, chain_id, status FROM pending_transactions
             WHERE wallet_id = ?1 AND status IN ({placeholders})
             ORDER BY created_at"
        ))?;
        let mut parameters: Vec<&dyn rusqlite::ToSql> = vec![&wallet_id];
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
            params![wallet_id, Millis(crate::sql::now())],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn parse_proposal(
    wallet_id: &str,
    source_revision: i64,
    policy_json: &str,
    rationale: String,
    created_at: DateTime<Utc>,
) -> Result<PolicyProposal> {
    let value = serde_json::from_str(policy_json).context("stored proposal is invalid JSON")?;
    Ok(PolicyProposal {
        wallet_id: wallet_id.into(),
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
            "CREATE TABLE mcp_clients (
                 client_id BLOB PRIMARY KEY NOT NULL CHECK (length(client_id) = 16),
                 display_name TEXT NOT NULL,
                 agent_kind TEXT NOT NULL CHECK (agent_kind IN (
                     'codex', 'claude_code', 'gemini_cli', 'cursor', 'opencode', 'other'
                 )),
                 redirect_uris_json TEXT NOT NULL,
                 registration_json TEXT,
                 created_at INTEGER NOT NULL,
                 authorized_at INTEGER,
                 last_used_at INTEGER,
                 revoked_at INTEGER
             ) STRICT",
            "CREATE TABLE oauth_authorization_codes (
                 code_hash BLOB PRIMARY KEY NOT NULL CHECK (length(code_hash) = 32),
                 client_id BLOB NOT NULL CHECK (length(client_id) = 16),
                 redirect_uri TEXT NOT NULL,
                 code_challenge TEXT NOT NULL,
                 scope TEXT NOT NULL,
                 resource TEXT NOT NULL,
                 expires_at INTEGER NOT NULL,
                 session_expires_at INTEGER NOT NULL,
                 access_token_ttl_seconds INTEGER NOT NULL CHECK (access_token_ttl_seconds > 0),
                 used_at INTEGER,
                 FOREIGN KEY (client_id) REFERENCES mcp_clients(client_id) ON DELETE CASCADE
             ) STRICT",
            "CREATE TABLE oauth_access_tokens (
                 token_hash BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),
                 client_id BLOB NOT NULL CHECK (length(client_id) = 16),
                 scope TEXT NOT NULL,
                 resource TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 FOREIGN KEY (client_id) REFERENCES mcp_clients(client_id) ON DELETE CASCADE
             ) STRICT",
            "CREATE TABLE oauth_refresh_tokens (
                 token_hash BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),
                 family_id BLOB NOT NULL CHECK (length(family_id) = 16),
                 client_id BLOB NOT NULL CHECK (length(client_id) = 16),
                 scope TEXT NOT NULL,
                 resource TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 access_token_ttl_seconds INTEGER NOT NULL CHECK (access_token_ttl_seconds > 0),
                 consumed_at INTEGER,
                 FOREIGN KEY (client_id) REFERENCES mcp_clients(client_id) ON DELETE CASCADE
             ) STRICT",
            "CREATE TABLE wallet_policies (
                 wallet_id TEXT PRIMARY KEY NOT NULL,
                 policy_json TEXT NOT NULL,
                 revision INTEGER NOT NULL CHECK (revision > 0),
                 updated_at INTEGER NOT NULL
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
                 wallet_id TEXT NOT NULL,
                 network_name TEXT NOT NULL,
                 chain_id INTEGER NOT NULL CHECK (chain_id > 0),
                 plan_json TEXT NOT NULL,
                 plan_digest BLOB NOT NULL CHECK (length(plan_digest) = 32),
                 plan_source TEXT,
                 requesting_client_id BLOB
                     CHECK (requesting_client_id IS NULL OR length(requesting_client_id) = 16),
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
                 approval_required INTEGER NOT NULL DEFAULT 1
                     CHECK (approval_required IN (0, 1)),
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
                 ON pending_transactions(wallet_id, created_at DESC)",
            "CREATE INDEX pending_transactions_signed_hash
                 ON pending_transactions(signed_transaction_hash)
                 WHERE signed_transaction_hash IS NOT NULL",
            "CREATE UNIQUE INDEX pending_transactions_wallet_chain_in_flight
                 ON pending_transactions(wallet_id, chain_id)
                 WHERE status IN ('signed', 'submitting', 'broadcast', 'cancelling')",
            "CREATE UNIQUE INDEX pending_transactions_unique_pending_plan
                 ON pending_transactions(wallet_id, chain_id, plan_digest)
                 WHERE status = 'awaiting_approval'",
            "CREATE TABLE pending_typed_data (
                 request_id BLOB PRIMARY KEY NOT NULL CHECK (length(request_id) = 16),
                 wallet_id TEXT NOT NULL,
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
                 requesting_client_id BLOB
                     CHECK (requesting_client_id IS NULL OR length(requesting_client_id) = 16),
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
                 ON pending_typed_data(wallet_id, chain_id, digest, requester)
                 WHERE status = 'awaiting_approval'",
            "CREATE INDEX pending_typed_data_wallet_created
                 ON pending_typed_data(wallet_id, created_at DESC)",
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
                 wallet_id TEXT NOT NULL,
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
                 requesting_client_id BLOB
                     CHECK (requesting_client_id IS NULL OR length(requesting_client_id) = 16),
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
                 ON pending_messages(wallet_id, chain_id, digest, requester)
                 WHERE status = 'awaiting_approval'",
            "CREATE INDEX pending_messages_wallet_created
                 ON pending_messages(wallet_id, created_at DESC)",
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
                 PRIMARY KEY (chain_id, address)
             ) STRICT",
            "CREATE TABLE legal_acceptance (
                 document TEXT PRIMARY KEY NOT NULL
                     CHECK (document IN ('terms_of_service', 'privacy_policy')),
                 digest BLOB NOT NULL CHECK (length(digest) = 32),
                 accepted_at INTEGER NOT NULL
             ) STRICT",
            "CREATE TABLE policy_proposals (
                 wallet_id TEXT PRIMARY KEY NOT NULL,
                 source_revision INTEGER NOT NULL CHECK (source_revision > 0),
                 policy_json TEXT NOT NULL,
                 rationale TEXT NOT NULL,
                 requesting_client_id BLOB
                     CHECK (requesting_client_id IS NULL OR length(requesting_client_id) = 16),
                 created_at INTEGER NOT NULL
             ) STRICT",
            TOKEN_PROPOSALS_TABLE,
            NETWORK_PROPOSALS_TABLE,
            record_version.as_str(),
        ],
    )
}

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
     requesting_client_id BLOB
         CHECK (requesting_client_id IS NULL OR length(requesting_client_id) = 16),
     proposed_at INTEGER NOT NULL
 ) STRICT";

/// Tokens an agent has suggested, held apart from `tokens` until the owner
/// confirms them. Nothing here is ever read as a display name: a row only
/// becomes a name by being moved into `tokens` from the terminal.
///
/// `source` is the list the suggestion came from, so the review screen can
/// group a hundred suggestions into the handful of decisions they really are.
const TOKEN_PROPOSALS_TABLE: &str = "CREATE TABLE IF NOT EXISTS token_proposals (
     chain_id INTEGER NOT NULL CHECK (chain_id > 0),
     address BLOB NOT NULL CHECK (length(address) = 20),
     symbol TEXT NOT NULL,
     name TEXT,
     decimals INTEGER NOT NULL CHECK (decimals >= 0 AND decimals <= 255),
     source TEXT NOT NULL,
     requesting_client_id BLOB
         CHECK (requesting_client_id IS NULL OR length(requesting_client_id) = 16),
     proposed_at INTEGER NOT NULL,
     PRIMARY KEY (chain_id, address)
 ) STRICT";

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

fn load_or_create_database_key(data_dir: &Path, database_exists: bool) -> Result<DatabaseKey> {
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
