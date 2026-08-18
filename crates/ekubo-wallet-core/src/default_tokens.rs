//! The default token list compiled into the binary and seeded once, when the
//! database is first created.
//!
//! A confirmed token is what lets an approval screen render a symbol instead
//! of a bare address, so this list decides which addresses a reviewer sees a
//! familiar name next to. That makes it security-relevant display data, and it
//! is handled the way [`crate::clear_signing`]'s registry is: vendored into the
//! repository by `contrib/vendor-default-tokens.py` and embedded at compile
//! time. Nothing here touches the network, at build time or at run time — a
//! release carries exactly the names that were vendored.
//!
//! At this size the integrity claim is provenance, not line-by-line review.
//! Seventeen thousand rows is not a diff anyone reads, so what the vendored
//! file actually pins is *which upstream bytes* a release was cut from: the
//! snapshot records the sha256 of the document it was generated from, and the
//! commit that changes the list is the commit that changes that digest. Trust
//! in an individual symbol is inherited from Ekubo's token pipeline, and the
//! list is aggregated from third-party feeds rather than hand-vetted per row.
//! A symbol here is a convenience for reading a transaction, never on its own
//! a reason to believe an address is the token it claims to be.
//!
//! Seeding runs from schema creation rather than at every startup, so it
//! happens on a genuinely new database and never again. That is what keeps it
//! from resurrecting a row the owner deliberately removed: once the schema
//! exists, this module is not consulted, and the token database is theirs.
//!
//! The embedded bytes are parsed by [`crate::token_list::parse_token_list`]'s
//! own code path — the same one that reads a list the owner imports by hand,
//! differing only in its size limits. Vendored data is still data, and a second
//! parser for it would be a second set of tolerances to keep true.

use crate::{
    sql::{Blob, Millis},
    token_list::{ParsedTokenList, parse_token_list_within},
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

/// Limits for the compiled-in list, deliberately not an import's.
///
/// An import is capped at what one owner can honestly verify in a review
/// screen. Nothing reviews this list at run time — it is checked when it is
/// vendored — so the cap here exists only to keep a corrupt or truncated
/// snapshot from being read as a valid one, and is set well above the real
/// list rather than near it.
const MAX_EMBEDDED_BYTES: usize = 16 * 1024 * 1024;
const MAX_EMBEDDED_TOKENS: usize = 100_000;

/// The vendored list, normalized to the field names
/// [`crate::token_list::parse_token_list`] accepts. Refresh it with
/// `contrib/vendor-default-tokens.py`.
const EMBEDDED: &str = include_str!("../default-tokens.json");

/// Recorded as the `source` of every seeded row, and shown wherever a token's
/// provenance is displayed. This is a stable user-facing label rather than a
/// filename or fetch URL; the exact upstream provenance stays in the vendored
/// snapshot metadata.
pub const SOURCE: &str = "Default tokens";

/// Parse the embedded list.
///
/// Public so a test can assert the vendored file is well-formed without
/// opening a database; a malformed vendored file would otherwise surface for
/// the first time on a new user's very first launch.
pub fn embedded() -> Result<ParsedTokenList> {
    parse_token_list_within(EMBEDDED.as_bytes(), MAX_EMBEDDED_BYTES, MAX_EMBEDDED_TOKENS)
        .context("the compiled-in default token list is not a valid token list")
}

/// Insert the embedded list into a freshly created `tokens` table.
///
/// Runs in its own transaction, so a database either has the complete default
/// list or none of it. Rows conflict-skip rather than overwrite for the same
/// reason [`crate::token_store::TokenStore::insert_if_absent`] does: this must
/// never be able to rename a token that is already there.
pub(crate) fn seed(connection: &Connection) -> Result<usize> {
    let parsed = embedded()?;
    let added_at = crate::sql::now();

    connection.execute_batch("BEGIN IMMEDIATE")?;
    let seeded = match insert_all(connection, &parsed, added_at) {
        Ok(seeded) => seeded,
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(error).context("failed to seed the default token list");
        }
    };
    connection.execute_batch("COMMIT")?;
    Ok(seeded)
}

fn insert_all(
    connection: &Connection,
    parsed: &ParsedTokenList,
    added_at: DateTime<Utc>,
) -> Result<usize> {
    let mut statement = connection.prepare(
        "INSERT INTO tokens(
             chain_id, address, symbol, name, decimals, source, added_at,
             approximate_usd_price
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(chain_id, address) DO NOTHING",
    )?;
    let mut seeded = 0;
    for token in &parsed.tokens {
        // Sanitized on the way in exactly as an imported list is. The vendoring
        // script cannot be the thing that guarantees this: it runs on someone's
        // workstation, and the file it writes is edited by hand often enough
        // that "it was clean when generated" is not a property of the bytes
        // that ship.
        let symbol = crate::token_store::sanitize(&token.symbol);
        if symbol.is_empty() {
            continue;
        }
        seeded += statement.execute(params![
            i64::try_from(token.chain_id).context("chain ID out of range")?,
            Blob(token.address),
            symbol,
            token.name.as_deref().map(crate::token_store::sanitize),
            token.decimals,
            SOURCE,
            Millis(added_at),
            // Roughly what it was worth when this build was cut, so a fresh
            // wallet's Portfolio tab can sort by holding size and hold back
            // the dust on the first read rather than after the owner has
            // typed a few hundred numbers. Absent for anything the snapshot
            // does not carry, which is what an unpriced row means.
            crate::token_prices::seeded_token_price(token.chain_id, token.address),
        ])?;
    }
    Ok(seeded)
}

#[cfg(test)]
#[path = "default_tokens_test.rs"]
mod tests;
