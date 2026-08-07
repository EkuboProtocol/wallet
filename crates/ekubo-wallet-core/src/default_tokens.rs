//! The curated token list compiled into the binary and seeded once, when the
//! database is first created.
//!
//! A confirmed token is what lets an approval screen render a symbol instead
//! of a bare address, so this list decides which addresses a reviewer sees a
//! familiar name next to. That makes it security-relevant display data, and it
//! is handled the way [`crate::clear_signing`]'s registry is: vendored into the
//! repository by `contrib/vendor-default-tokens.py`, reviewed in a diff, and
//! embedded at compile time. Nothing here touches the network, at build time or
//! at run time — a release carries exactly the names that were reviewed.
//!
//! Seeding runs from schema creation rather than at every startup, so it
//! happens on a genuinely new database and never again. That is what keeps it
//! from resurrecting a row the owner deliberately removed: once the schema
//! exists, this module is not consulted, and the token database is theirs.
//!
//! The embedded bytes are parsed by [`parse_token_list`] — the same code that
//! reads a list the owner imports by hand. Vendored data is still data, and a
//! second parser for it would be a second set of tolerances to keep true.

use crate::token_list::{ParsedTokenList, parse_token_list};
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, params};

/// The vendored curated list, normalized to the field names
/// [`parse_token_list`] accepts. Refresh it with
/// `contrib/vendor-default-tokens.py`.
const EMBEDDED: &str = include_str!("../default-tokens.json");

/// Recorded as the `source` of every seeded row, and shown wherever a token's
/// provenance is displayed. It names the curator rather than a file, because
/// that is the claim the owner is being asked to have accepted.
pub const SOURCE: &str = "Ekubo curated defaults";

/// Parse the embedded list.
///
/// Public so a test can assert the vendored file is well-formed without
/// opening a database; a malformed vendored file would otherwise surface for
/// the first time on a new user's very first launch.
pub fn embedded() -> Result<ParsedTokenList> {
    parse_token_list(EMBEDDED.as_bytes())
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
    let added_at = Utc::now().to_rfc3339();

    connection.execute_batch("BEGIN IMMEDIATE")?;
    let seeded = match insert_all(connection, &parsed, &added_at) {
        Ok(seeded) => seeded,
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            return Err(error).context("failed to seed the default token list");
        }
    };
    connection.execute_batch("COMMIT")?;
    Ok(seeded)
}

fn insert_all(connection: &Connection, parsed: &ParsedTokenList, added_at: &str) -> Result<usize> {
    let mut statement = connection.prepare(
        "INSERT INTO tokens(chain_id, address, symbol, name, decimals, source, added_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
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
            format!("{:#x}", token.address),
            symbol,
            token.name.as_deref().map(crate::token_store::sanitize),
            token.decimals,
            SOURCE,
            added_at,
        ])?;
    }
    Ok(seeded)
}

#[cfg(test)]
#[path = "default_tokens_test.rs"]
mod tests;
