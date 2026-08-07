//! Parsing a curated token list from bytes, whatever carried them.
//!
//! A token list reaches this wallet three ways — a file the owner points at,
//! standard input they piped, and a producer's `token_list` artifact
//! reference — and all three arrive as the same thing: bytes someone else
//! wrote. They are parsed here, once, so a list cannot mean one thing when
//! imported and another when proposed, and so the tolerances below are
//! stated in exactly one place.
//!
//! Nothing parsed here is trusted. A list is a claim about names, and names
//! are what [`crate::token_store`] exists to keep an attacker from choosing;
//! every entry still waits for the owner to confirm it. What this module
//! decides is only which claims are *expressible*, never which are true.
//!
//! The tolerances are deliberate. Real lists disagree about spelling
//! (`chainId` in the standard token-list schema, `chain_id` in Ekubo's API)
//! and about how a chain ID is written (a JSON number, a decimal string, or
//! `0x`-hex), and a wallet that rejected a list over that would push the
//! owner toward hand-editing the file — the one step that turns a curator's
//! claim into an agent's. Extra fields are ignored rather than refused for
//! the same reason: a curator adding a logo URL must not break the import.
//!
//! Entries this wallet cannot represent — anything whose address is not a
//! 20-byte EVM address, as the Starknet rows in Ekubo's canonical list are —
//! are skipped and counted rather than failing the list, because a
//! multi-ecosystem list is a normal thing to be handed and dropping the rows
//! that do not apply loses nothing. The count is reported so the skip is
//! never silent.

use crate::token_store::{ListedToken, MAX_IMPORT_TOKENS};
use alloy::primitives::Address;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::str::FromStr;

/// The largest token-list body worth parsing.
///
/// The entry cap in [`MAX_IMPORT_TOKENS`] is the real bound on what an import
/// can do; this exists so a body far too large to hold that many entries is
/// refused before it is parsed rather than after. Ekubo's full canonical list
/// is around 500 KB, so this leaves an order of magnitude of headroom for
/// lists that carry more metadata per entry.
pub const MAX_TOKEN_LIST_BYTES: usize = 4 * 1024 * 1024;

/// A chain ID as lists actually write it.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawChainId {
    Number(u64),
    Text(String),
}

impl RawChainId {
    fn value(&self) -> Result<u64> {
        match self {
            Self::Number(value) => Ok(*value),
            Self::Text(text) => {
                let trimmed = text.trim();
                let parsed = match trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    Some(hex) => u64::from_str_radix(hex, 16),
                    None => trimmed.parse::<u64>(),
                };
                parsed.with_context(|| format!("chain ID {text:?} is not a chain ID"))
            }
        }
    }
}

/// One entry as written, before anything about it is checked.
///
/// Unknown fields are ignored on purpose: see the module note.
#[derive(Debug, Deserialize)]
struct RawEntry {
    #[serde(alias = "chainId")]
    chain_id: RawChainId,
    address: String,
    symbol: String,
    #[serde(default)]
    name: Option<String>,
    decimals: u8,
}

/// Both shapes a list ships as: the standard `{ name, tokens }` wrapper, and
/// the bare array Ekubo's API returns.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawList {
    Wrapped {
        #[serde(default)]
        name: Option<String>,
        tokens: Vec<RawEntry>,
    },
    Bare(Vec<RawEntry>),
}

/// What one token-list body turned out to contain.
#[derive(Debug)]
pub struct ParsedTokenList {
    /// The list's own `name`, when it carries one. Callers prefer an explicit
    /// name over this, and this over whatever the transport suggests.
    pub declared_name: Option<String>,
    pub tokens: Vec<ListedToken>,
    /// Entries dropped because their address is not a 20-byte EVM address.
    /// Reported so a multi-ecosystem list's missing rows are explained rather
    /// than merely absent.
    pub skipped_non_evm: usize,
}

/// Parse one token-list body.
///
/// Fails when the bytes are not a token list at all, when every entry was
/// skipped, or when the list holds more entries than one import may verify.
pub fn parse_token_list(body: &[u8]) -> Result<ParsedTokenList> {
    parse_token_list_within(body, MAX_TOKEN_LIST_BYTES, MAX_IMPORT_TOKENS)
}

/// Parse one token-list body against explicit limits.
///
/// The limits are a parameter because the two callers bound different things.
/// An import's caps exist to keep the owner from being handed more rows than
/// one review can honestly verify, so they are stated in units of human
/// attention. The compiled-in list in [`crate::default_tokens`] is not
/// reviewed at run time at all — it was reviewed when it was vendored, and
/// nothing about a startup seed asks the owner to check anything — so holding
/// it to a reviewer's budget would be enforcing a limit against the wrong
/// party. Everything else about how the bytes are read stays identical, which
/// is the point: one set of tolerances, one place they are written down.
pub fn parse_token_list_within(
    body: &[u8],
    max_bytes: usize,
    max_entries: usize,
) -> Result<ParsedTokenList> {
    ensure!(
        body.len() <= max_bytes,
        "token list is larger than {max_bytes} bytes"
    );
    let parsed: RawList = serde_json::from_slice(body).context(
        "not a token list: expected a tokens array of entries with \
         chainId, address, symbol, and decimals, or a bare array of the same",
    )?;
    let (declared_name, entries) = match parsed {
        RawList::Wrapped { name, tokens } => (name, tokens),
        RawList::Bare(tokens) => (None, tokens),
    };
    ensure!(!entries.is_empty(), "the token list lists no tokens");
    ensure!(
        entries.len() <= max_entries,
        "the token list holds {} entries, over the {max_entries} one import may verify",
        entries.len()
    );

    let mut tokens = Vec::with_capacity(entries.len());
    let mut skipped_non_evm = 0;
    for entry in entries {
        // A 20-byte address is what this wallet can act on. Anything else is
        // a row for another ecosystem, not a malformed row: skip it rather
        // than refusing the list that carried it.
        let Ok(address) = Address::from_str(&entry.address) else {
            skipped_non_evm += 1;
            continue;
        };
        tokens.push(ListedToken {
            chain_id: entry.chain_id.value()?,
            address,
            symbol: entry.symbol,
            name: entry.name,
            decimals: entry.decimals,
        });
    }
    ensure!(
        !tokens.is_empty(),
        "the token list holds no entries with a 20-byte EVM address; \
         all {skipped_non_evm} were for another ecosystem"
    );
    Ok(ParsedTokenList {
        declared_name,
        tokens,
        skipped_non_evm,
    })
}

#[cfg(test)]
#[path = "token_list_test.rs"]
mod tests;
