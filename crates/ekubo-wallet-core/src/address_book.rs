//! Per-chain address aliases, stored in the authenticated encrypted database.
//!
//! Entries are lookup convenience data with no signing authority: nothing in
//! the signing or policy path reads this store, and an alias never
//! substitutes for reviewing the actual address in an approval. Entries are
//! added, updated, and removed only by the owner-only native UI after OS owner
//! authentication; MCP exposes read-only lookups so an agent can resolve
//! "pay alice" to the address the user configured. The rows live inside the
//! `SQLCipher` database precisely because an agent must not be able to retarget
//! an alias by editing a plain file outside this process.

use crate::{
    policy_store::PolicyStore,
    sql::{self, Blob, Millis, RowExt},
};
use alloy::primitives::Address;
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Serialize;
use std::path::Path;
pub const MAX_NOTE_LEN: usize = 256;

/// One stored alias, the address rendered checksummed.
///
/// The address is `String` rather than `Address` because this is what the MCP
/// and desktop surfaces render, and what they render is the EIP-55 checksummed
/// form — a pure function of the 20 stored bytes, derived here rather than
/// stored, so the two can never disagree.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AddressBookEntry {
    pub chain_id: String,
    pub alias: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub added_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct AddressBookStore {
    database: PolicyStore,
}

impl AddressBookStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            database: PolicyStore::production(data_dir)?,
        })
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    /// Insert or replace one alias. The native UI authenticates the owner before
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
            .map(validate_note)
            .transpose()?
            .filter(|note| !note.is_empty());
        let now = sql::now();
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
                Blob(address),
                note,
                Millis(now),
            ],
        )?;
        self.get(chain_id, alias)?
            .context("inserted address book entry missing")
    }

    /// Delete one entry.
    ///
    /// Deliberately does not validate the alias. Validation is a rule about
    /// what may be *written*, and applying it on the way out means a row that
    /// predates the rule — or arrived some other way — cannot be deleted,
    /// because every command that could remove it refuses to name it first.
    /// The owner is then stuck with an entry they can see and cannot get rid
    /// of, which is the wrong direction for a cleanup path to fail in.
    /// Deleting by exact stored text can only ever remove something.
    pub fn remove(&mut self, chain_id: u64, alias: &str) -> Result<AddressBookEntry> {
        let existing = self
            .read(chain_id, alias)?
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
        self.read(chain_id, alias)
    }

    /// Read one exact stored alias for a removal review.
    ///
    /// Unlike [`Self::get`], this deliberately does not apply the write-time
    /// alias grammar. A row remains nameable for deletion if validation rules
    /// become stricter in a future build.
    pub fn get_for_removal(&self, chain_id: u64, alias: &str) -> Result<Option<AddressBookEntry>> {
        self.read(chain_id, alias)
    }

    /// Read by exact stored alias, without the write-time validity rule. The
    /// removal path needs this so a row that no longer satisfies that rule is
    /// still reachable for deletion.
    fn read(&self, chain_id: u64, alias: &str) -> Result<Option<AddressBookEntry>> {
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

/// Rejects a note outright rather than cleaning it, unlike the crate's
/// `sanitize` module: an owner-typed label should fail visibly while they are
/// still typing it, not get silently stripped and stored as something else.
fn validate_note(note: &str) -> Result<String> {
    // The shared predicate, not `char::is_control`. A note is stored text that
    // labels an address at review time, so it is refused for the same reasons
    // every other displayed string is: a bidirectional control reorders what
    // is read, and a zero-width character makes two notes a person cannot
    // distinguish into two different notes. Rendering strips these anyway;
    // refusing them here means they are never stored to begin with, and the
    // owner finds out while typing rather than never.
    ensure!(
        !note.chars().any(crate::sanitize::is_disallowed),
        "note cannot contain control, bidirectional, or zero-width characters"
    );
    ensure!(
        note.len() <= MAX_NOTE_LEN,
        "note must be at most {MAX_NOTE_LEN} bytes"
    );
    Ok(note.trim().to_string())
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AddressBookEntry> {
    let chain_id: i64 = row.get(0)?;
    // No fallback for an unparseable address: the column holds 20 bytes or the
    // row does not exist, so checksumming cannot fail.
    let address: Address = row.blob(2)?;
    Ok(AddressBookEntry {
        chain_id: chain_id.to_string(),
        alias: row.get(1)?,
        address: address.to_checksum(None),
        note: row.get(3)?,
        added_at: row.time(4)?,
        updated_at: row.time(5)?,
    })
}

#[cfg(test)]
#[path = "address_book_test.rs"]
mod tests;
