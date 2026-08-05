//! Per-chain address aliases, stored in the authenticated encrypted database.
//!
//! Entries are lookup convenience data with no signing authority: nothing in
//! the signing or policy path reads this store, and an alias never
//! substitutes for reviewing the actual address in an approval. Entries are
//! added, updated, and removed only by the interactive CLI after OS owner
//! authentication; MCP exposes read-only lookups so an agent can resolve
//! "pay alice" to the address the user configured. The rows live inside the
//! `SQLCipher` database precisely because an agent must not be able to retarget
//! an alias by editing a plain file outside this process.

use crate::policy_store::PolicyStore;
use alloy::primitives::Address;
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Serialize;
use std::{fs, path::Path, str::FromStr};

/// Plain-SQLite file used before the table moved into the encrypted
/// database. Never trusted or imported: deleted on sight.
const LEGACY_DATABASE_FILE: &str = "address_book.db";
pub(crate) const MAX_NOTE_LEN: usize = 256;

/// One stored alias, the address rendered checksummed.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AddressBookEntry {
    pub chain_id: String,
    pub alias: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub added_at: String,
    pub updated_at: String,
}

pub struct AddressBookStore {
    database: PolicyStore,
}

impl AddressBookStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(data_dir.join(format!("{LEGACY_DATABASE_FILE}{suffix}")));
        }
        Ok(Self {
            database: PolicyStore::production(data_dir)?,
        })
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    /// Insert or replace one alias. The CLI authenticates the owner before
    /// calling this; nothing reachable from MCP does.
    pub fn upsert(
        &mut self,
        chain_id: u64,
        alias: &str,
        address: Address,
        note: Option<&str>,
    ) -> Result<AddressBookEntry> {
        validate_alias(alias)?;
        ensure!(chain_id > 0, "chain ID must be positive");
        let note = note
            .map(sanitize_note)
            .transpose()?
            .filter(|note| !note.is_empty());
        let now = Utc::now().to_rfc3339();
        self.database.connection.execute(
            "INSERT INTO address_book(chain_id, alias, address, note, added_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(chain_id, alias) DO UPDATE SET
                 address = excluded.address,
                 note = excluded.note,
                 updated_at = excluded.updated_at",
            params![
                i64::try_from(chain_id).context("chain ID out of range")?,
                alias,
                format!("{address:#x}"),
                note,
                now,
            ],
        )?;
        self.get(chain_id, alias)?
            .context("inserted address book entry missing")
    }

    pub fn remove(&mut self, chain_id: u64, alias: &str) -> Result<AddressBookEntry> {
        validate_alias(alias)?;
        let existing = self
            .get(chain_id, alias)?
            .with_context(|| format!("no address book entry {alias} on chain {chain_id}"))?;
        self.database.connection.execute(
            "DELETE FROM address_book WHERE chain_id = ?1 AND alias = ?2",
            params![
                i64::try_from(chain_id).context("chain ID out of range")?,
                alias
            ],
        )?;
        Ok(existing)
    }

    pub fn get(&self, chain_id: u64, alias: &str) -> Result<Option<AddressBookEntry>> {
        validate_alias(alias)?;
        self.database
            .connection
            .query_row(
                "SELECT chain_id, alias, address, note, added_at, updated_at
                 FROM address_book WHERE chain_id = ?1 AND alias = ?2",
                params![
                    i64::try_from(chain_id).context("chain ID out of range")?,
                    alias
                ],
                row_to_entry,
            )
            .optional()
            .context("failed to read address book entry")
    }

    /// List entries ordered deterministically, optionally scoped to one chain.
    pub fn list(
        &self,
        chain_id: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AddressBookEntry>> {
        let limit = i64::try_from(limit.min(10_000)).unwrap_or(10_000);
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        let mut rows = Vec::new();
        if let Some(chain) = chain_id {
            let mut statement = self.database.connection.prepare(
                "SELECT chain_id, alias, address, note, added_at, updated_at
                 FROM address_book WHERE chain_id = ?1
                 ORDER BY chain_id, alias LIMIT ?2 OFFSET ?3",
            )?;
            let mapped = statement.query_map(
                params![
                    i64::try_from(chain).context("chain ID out of range")?,
                    limit,
                    offset
                ],
                row_to_entry,
            )?;
            for row in mapped {
                rows.push(row?);
            }
        } else {
            let mut statement = self.database.connection.prepare(
                "SELECT chain_id, alias, address, note, added_at, updated_at
                 FROM address_book ORDER BY chain_id, alias LIMIT ?1 OFFSET ?2",
            )?;
            let mapped = statement.query_map(params![limit, offset], row_to_entry)?;
            for row in mapped {
                rows.push(row?);
            }
        }
        Ok(rows)
    }

    pub fn count(&self, chain_id: Option<u64>) -> Result<u64> {
        let count: i64 = match chain_id {
            Some(chain) => self.database.connection.query_row(
                "SELECT COUNT(*) FROM address_book WHERE chain_id = ?1",
                params![i64::try_from(chain).context("chain ID out of range")?],
                |row| row.get(0),
            )?,
            None => self.database.connection.query_row(
                "SELECT COUNT(*) FROM address_book",
                [],
                |row| row.get(0),
            )?,
        };
        Ok(u64::try_from(count).unwrap_or(0))
    }
}

pub fn validate_alias(alias: &str) -> Result<()> {
    ensure!(
        !alias.is_empty()
            && alias.len() <= 64
            && alias
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
        "alias must use 1-64 letters, numbers, underscores, hyphens, or periods"
    );
    Ok(())
}

fn sanitize_note(note: &str) -> Result<String> {
    ensure!(
        !note.chars().any(char::is_control),
        "note cannot contain control characters"
    );
    ensure!(
        note.len() <= MAX_NOTE_LEN,
        "note must be at most {MAX_NOTE_LEN} bytes"
    );
    Ok(note.trim().to_string())
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AddressBookEntry> {
    let chain_id: i64 = row.get(0)?;
    let address: String = row.get(2)?;
    let checksummed = Address::from_str(&address)
        .map(|address| address.to_checksum(None))
        .unwrap_or(address);
    Ok(AddressBookEntry {
        chain_id: chain_id.to_string(),
        alias: row.get(1)?,
        address: checksummed,
        note: row.get(3)?,
        added_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_store::DatabaseKey;

    fn open(directory: &Path) -> AddressBookStore {
        AddressBookStore::new(
            PolicyStore::open(&directory.join("policies.db"), &DatabaseKey::new([6; 32])).unwrap(),
        )
    }

    fn store() -> (tempfile::TempDir, AddressBookStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = open(directory.path());
        (directory, store)
    }

    #[test]
    fn upsert_replaces_and_remove_deletes() {
        let (_directory, mut store) = store();
        let first = Address::repeat_byte(0x11);
        let second = Address::repeat_byte(0x22);
        let entry = store.upsert(1, "alice", first, Some("payroll")).unwrap();
        assert_eq!(entry.address, first.to_checksum(None));
        assert_eq!(entry.note.as_deref(), Some("payroll"));

        let replaced = store.upsert(1, "alice", second, None).unwrap();
        assert_eq!(replaced.address, second.to_checksum(None));
        assert_eq!(replaced.note, None);
        assert_eq!(replaced.added_at, entry.added_at);
        assert_eq!(store.count(None).unwrap(), 1);

        // Same alias on another chain is a distinct entry.
        store.upsert(8453, "alice", first, None).unwrap();
        assert_eq!(store.count(None).unwrap(), 2);
        assert_eq!(store.count(Some(1)).unwrap(), 1);

        let removed = store.remove(1, "alice").unwrap();
        assert_eq!(removed.address, second.to_checksum(None));
        assert!(store.get(1, "alice").unwrap().is_none());
        assert!(store.remove(1, "alice").is_err());
    }

    #[test]
    fn listing_is_deterministic_and_scoped() {
        let (_directory, mut store) = store();
        store
            .upsert(1, "bob", Address::repeat_byte(0xB0), None)
            .unwrap();
        store
            .upsert(1, "alice", Address::repeat_byte(0xA0), None)
            .unwrap();
        let listed = store.list(Some(1), 10, 0).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].alias, "alice");
        assert!(store.list(Some(2), 10, 0).unwrap().is_empty());
        assert_eq!(store.list(None, 1, 1).unwrap().len(), 1);
    }

    #[test]
    fn hostile_aliases_and_notes_are_rejected() {
        let (_directory, mut store) = store();
        let address = Address::repeat_byte(0x33);
        assert!(store.upsert(1, "bad\nalias", address, None).is_err());
        assert!(store.upsert(1, "", address, None).is_err());
        assert!(
            store
                .upsert(1, "ok", address, Some("note\u{1b}[31m"))
                .is_err()
        );
        assert!(
            store
                .upsert(1, "ok", address, Some(&"x".repeat(300)))
                .is_err()
        );
        assert!(store.upsert(0, "ok", address, None).is_err());
    }

    #[test]
    fn reopening_preserves_rows() {
        let directory = tempfile::tempdir().unwrap();
        {
            let mut store = open(directory.path());
            store
                .upsert(10, "vault", Address::repeat_byte(0x44), None)
                .unwrap();
        }
        let store = open(directory.path());
        assert_eq!(store.count(None).unwrap(), 1);
        assert_eq!(
            store.get(10, "vault").unwrap().unwrap().address,
            Address::repeat_byte(0x44).to_checksum(None)
        );
    }
}
