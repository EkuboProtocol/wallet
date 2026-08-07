//! SQLCipher-backed wallet security database.
//!
//! Transaction counters and rolling limits deliberately do not live here. A
//! restored database cannot restore consumed allowance and make it spendable
//! again. Pending approvals and transaction lifecycle records use separate
//! tables so exact signed bytes can be recovered without becoming spend state.

use crate::{
    config::{
        NetworkConfig, create_private_dir, set_private_file_permissions,
        set_private_handle_permissions, validate_network, validate_wallet_id,
    },
    core::policy::WalletPolicy,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use keyring::{Entry, Error as KeyringError};
use rand::TryRng;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{fs::OpenOptions, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The shape of the encrypted database. There is one, and this build creates
/// it: the ladder of pre-release versions that preceded 1.0.0 described
/// databases nobody outside development ever held, so carrying upgrade steps
/// for them would have been machinery for a population of zero — and it would
/// have told a first-time owner that their brand-new database had a history.
// Schema 2 (2026-08-06): execution plans dropped submit_condition /
// execution_policy / adapters / eip1193 and gained required_capabilities /
// extensions, which changes both stored plan_json parsing and plan_digest
// derivation, and pending_transactions gained plan_source. Re-hashing rows
// the owner already approved would re-label signed history, so pre-change
// databases are refused instead of migrated.
// Schema 3 (2026-08-06): network_proposals. An agent can no longer write a
// network profile; it queues one for the owner to confirm, so the table has
// to exist before the MCP surface will accept a proposal at all.
const SCHEMA_VERSION: i64 = 3;
const DATABASE_FILE: &str = "policies.db";
const DATABASE_LOCK_FILE: &str = "policies.lock";
/// The credential-store entry holding this database's key.
///
/// Named for the database rather than for policies, because policies are only
/// one of the things it protects: the same file holds the pending signing
/// queues, the address book, and the token names a reviewer reads before
/// approving a transfer. A name that says "policy" invites the reading that
/// everything else in there is incidental, and none of it is.
const KEYRING_SERVICE: &str = "org.ekubo.wallet.db";
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
        set_private_handle_permissions(&lock)?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;
        let path = data_dir.join(DATABASE_FILE);
        let key = load_or_create_database_key(path.exists())?;
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
        // The pre-release upgrade ladder (schemas 1 through 10) was retired
        // after v0.3.0-rc.0. A database predating the current schema is
        // refused with upgrade guidance rather than carried forever; future
        // migrations append below and run on every open, so a schema change
        // upgrades the database at the next startup.
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
                if seed_defaults == SeedDefaults::Yes {
                    crate::default_tokens::seed(&connection)?;
                }
                SCHEMA_VERSION
            }
            Some(version) => version,
        };
        if version < SCHEMA_VERSION {
            anyhow::bail!(
                "policy database schema {version} predates the schema this build understands \
                 ({SCHEMA_VERSION}); this pre-release build does not migrate old databases — \
                 move the database aside and let ekubo-wallet create a fresh one (any \
                 in-flight pending rows are lost with it)"
            );
        }
        ensure!(
            version == SCHEMA_VERSION,
            "policy database schema {version} is newer than the schema this build understands \
             ({SCHEMA_VERSION}); upgrade ekubo-wallet"
        );
        verify_integrity(&connection)?;
        set_private_file_permissions(path)?;
        Ok(Self { connection })
    }

    /// Re-reads the schema version through this connection. A long-running
    /// server holds its stores open, so a database migrated underneath it —
    /// for example by a newer build's CLI — would otherwise be written to
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
                proposal.created_at.to_rfc3339(),
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
        let updated_at = Utc::now();
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
        let created_at = Utc::now();
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
                created_at.to_rfc3339()
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
                        row.get::<_, String>(3)?,
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
                    &created_at,
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
                    row.get::<_, String>(4)?,
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
                        &created_at,
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
                proposal.created_at.to_rfc3339(),
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
            "{pending} network suggestions already await review; the owner must run \
             `ekubo-wallet network review` before more can be suggested"
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
                Utc::now().to_rfc3339(),
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

fn parse_proposal(
    wallet_id: &str,
    source_revision: i64,
    policy_json: &str,
    rationale: String,
    created_at: &str,
) -> Result<PolicyProposal> {
    let value = serde_json::from_str(policy_json).context("stored proposal is invalid JSON")?;
    Ok(PolicyProposal {
        wallet_id: wallet_id.into(),
        source_revision: u64::try_from(source_revision)
            .context("stored proposal revision is invalid")?,
        policy: WalletPolicy::parse(value).context("stored proposal policy is invalid")?,
        rationale,
        created_at: DateTime::parse_from_rfc3339(created_at)
            .context("stored proposal timestamp is invalid")?
            .with_timezone(&Utc),
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
            "CREATE TABLE wallet_policies (
                 wallet_id TEXT PRIMARY KEY NOT NULL,
                 policy_json TEXT NOT NULL,
                 revision INTEGER NOT NULL CHECK (revision > 0),
                 updated_at TEXT NOT NULL
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
                 request_id TEXT PRIMARY KEY NOT NULL,
                 wallet_id TEXT NOT NULL,
                 network_name TEXT NOT NULL,
                 chain_id TEXT NOT NULL,
                 plan_json TEXT NOT NULL,
                 plan_digest TEXT NOT NULL,
                 plan_source TEXT,
                 policy_revision INTEGER NOT NULL CHECK (policy_revision > 0),
                 status TEXT NOT NULL CHECK (status IN (
                     'awaiting_approval', 'rejected', 'signed', 'submitting',
                     'broadcast', 'confirmed', 'reverted', 'cancelled',
                     'replaced', 'cancelling'
                 )),
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 approved_at TEXT,
                 rejected_at TEXT,
                 serialized_transaction TEXT,
                 signed_transaction_hash TEXT,
                 broadcast_transaction_hash TEXT,
                 block_number TEXT,
                 approval_required INTEGER NOT NULL DEFAULT 1
                     CHECK (approval_required IN (0, 1)),
                 review_digest TEXT,
                 cancel_serialized_transaction TEXT,
                 cancel_transaction_hashes TEXT,
                 gas_used TEXT,
                 effective_gas_price TEXT,
                 CHECK (
                     (status = 'awaiting_approval' AND approved_at IS NULL AND rejected_at IS NULL
                         AND serialized_transaction IS NULL AND signed_transaction_hash IS NULL)
                     OR status <> 'awaiting_approval'
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
                 request_id TEXT PRIMARY KEY NOT NULL,
                 wallet_id TEXT NOT NULL,
                 chain_id TEXT NOT NULL,
                 typed_data_json TEXT NOT NULL,
                 digest TEXT NOT NULL,
                 status TEXT NOT NULL CHECK (status IN (
                     'awaiting_approval', 'rejected', 'signed'
                 )),
                 approval_required INTEGER NOT NULL DEFAULT 1
                     CHECK (approval_required IN (0, 1)),
                 policy_revision INTEGER
                     CHECK (policy_revision IS NULL OR policy_revision > 0),
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 approved_at TEXT,
                 rejected_at TEXT,
                 signature TEXT,
                 CHECK ((status = 'signed') = (signature IS NOT NULL)),
                 CHECK (approval_required = 1 OR policy_revision IS NOT NULL)
             ) STRICT",
            "CREATE UNIQUE INDEX pending_typed_data_unique_awaiting
                 ON pending_typed_data(wallet_id, chain_id, digest)
                 WHERE status = 'awaiting_approval'",
            "CREATE INDEX pending_typed_data_wallet_created
                 ON pending_typed_data(wallet_id, created_at DESC)",
            // EIP-191 message signatures queue exactly like typed data, minus
            // every automatic path: no policy can score a message, so there is
            // no approval_required or policy_revision column to carry.
            //
            // chain_id is the empty string when the requester declared none —
            // `personal_sign` binds no chain — because SQLite treats NULLs as
            // distinct in a unique index, which would silently disable the
            // awaiting-request deduplication below.
            "CREATE TABLE pending_messages (
                 request_id TEXT PRIMARY KEY NOT NULL,
                 wallet_id TEXT NOT NULL,
                 chain_id TEXT NOT NULL,
                 message_hex TEXT NOT NULL
                     CHECK (message_hex LIKE '0x%' AND length(message_hex) % 2 = 0),
                 message_encoding TEXT NOT NULL
                     CHECK (message_encoding IN ('text', 'hex')),
                 digest TEXT NOT NULL,
                 status TEXT NOT NULL CHECK (status IN (
                     'awaiting_approval', 'rejected', 'signed'
                 )),
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 approved_at TEXT,
                 rejected_at TEXT,
                 signature TEXT,
                 CHECK ((status = 'signed') = (signature IS NOT NULL))
             ) STRICT",
            "CREATE UNIQUE INDEX pending_messages_unique_awaiting
                 ON pending_messages(wallet_id, chain_id, digest)
                 WHERE status = 'awaiting_approval'",
            "CREATE INDEX pending_messages_wallet_created
                 ON pending_messages(wallet_id, created_at DESC)",
            // Integrity-sensitive display and gating state lives inside the
            // authenticated database: token metadata, address aliases, and
            // legal acceptance must not be forgeable by editing a plain file
            // outside this process.
            "CREATE TABLE tokens (
                 chain_id INTEGER NOT NULL CHECK (chain_id > 0),
                 address TEXT NOT NULL
                     CHECK (address = lower(address) AND length(address) = 42),
                 symbol TEXT,
                 name TEXT,
                 decimals INTEGER
                     CHECK (decimals IS NULL OR (decimals >= 0 AND decimals <= 255)),
                 source TEXT NOT NULL,
                 added_at TEXT NOT NULL,
                 PRIMARY KEY (chain_id, address)
             ) STRICT",
            "CREATE TABLE address_book (
                 chain_id INTEGER NOT NULL CHECK (chain_id > 0),
                 alias TEXT NOT NULL,
                 address TEXT NOT NULL
                     CHECK (address = lower(address) AND length(address) = 42),
                 note TEXT,
                 added_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 PRIMARY KEY (chain_id, alias)
             ) STRICT",
            "CREATE TABLE legal_acceptance (
                 document TEXT PRIMARY KEY NOT NULL
                     CHECK (document IN ('terms_of_service', 'privacy_policy')),
                 digest TEXT NOT NULL,
                 accepted_at TEXT NOT NULL
             ) STRICT",
            "CREATE TABLE policy_proposals (
                 wallet_id TEXT PRIMARY KEY NOT NULL,
                 source_revision INTEGER NOT NULL CHECK (source_revision > 0),
                 policy_json TEXT NOT NULL,
                 rationale TEXT NOT NULL,
                 created_at TEXT NOT NULL
             ) STRICT",
            TOKEN_PROPOSALS_TABLE,
            NETWORK_PROPOSALS_TABLE,
            record_version.as_str(),
        ],
    )
}

/// Network profiles an agent has suggested, held apart from `config.json`
/// until the owner confirms them.
///
/// Keyed on chain ID because that is what identifies a network: a proposal
/// naming a chain already configured is an edit of it, and one naming a chain
/// that is not is an addition. Nothing here is ever consulted when resolving a
/// network for a request — a row becomes reachable only by being written into
/// the configuration from the terminal.
///
/// The whole profile travels as JSON rather than as columns. The review screen
/// has to show the owner exactly what would be stored, and a shape that can
/// drift from `NetworkConfig` is a shape that eventually shows them something
/// else.
const NETWORK_PROPOSALS_TABLE: &str = "CREATE TABLE IF NOT EXISTS network_proposals (
     chain_id INTEGER PRIMARY KEY NOT NULL CHECK (chain_id > 0),
     profile_json TEXT NOT NULL,
     proposed_at TEXT NOT NULL
 ) STRICT";

/// Tokens an agent has suggested, held apart from `tokens` until the owner
/// confirms them. Nothing here is ever read as a display name: a row only
/// becomes a name by being moved into `tokens` from the terminal.
///
/// `source` is the list the suggestion came from, so the review screen can
/// group a hundred suggestions into the handful of decisions they really are.
const TOKEN_PROPOSALS_TABLE: &str = "CREATE TABLE IF NOT EXISTS token_proposals (
     chain_id INTEGER NOT NULL CHECK (chain_id > 0),
     address TEXT NOT NULL
         CHECK (address = lower(address) AND length(address) = 42),
     symbol TEXT NOT NULL,
     name TEXT,
     decimals INTEGER NOT NULL CHECK (decimals >= 0 AND decimals <= 255),
     source TEXT NOT NULL,
     proposed_at TEXT NOT NULL,
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
                "another process initialized the policy database key at the same time;                  run this command again"
            );
            Ok(DatabaseKey::new(bytes))
        }
        Err(error) => Err(error).context("failed to load policy database key"),
    }
}

#[cfg(test)]
#[path = "policy_store_test.rs"]
mod tests;
