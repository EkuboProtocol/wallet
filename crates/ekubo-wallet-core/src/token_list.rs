//! Parsing a curated token list from bytes, whatever carried them.
//!
//! A token list reaches this wallet four ways — a file the owner points at,
//! standard input they piped, a producer's `token_list` artifact reference,
//! and the published URL an agent was asked to import from — and all four
//! arrive as the same thing: bytes someone else wrote. They are parsed here,
//! once, so a list cannot mean one thing when imported and another when
//! proposed, and so the tolerances below are stated in exactly one place.
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

/// The most rows a published list may hold at all, before any are selected.
///
/// This is not the import cap — [`MAX_IMPORT_TOKENS`] is, and it is charged
/// against what an import actually proposes. This bounds the other thing: how
/// much a list may make this process hold and walk while deciding which rows
/// apply. The two differ because a real multi-chain list can be larger than
/// any one import of it, and a list is read in full before anything is
/// selected from it. Kept a small multiple of the import cap, and in the same
/// range as what [`MAX_TOKEN_LIST_BYTES`] already permits: at the ~220 bytes
/// per entry that published lists run to, 4 MiB is about eighteen thousand
/// rows, so neither bound is doing much work the other is not.
pub const MAX_LIST_ENTRIES: usize = 20_000;

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

/// A standard-schema list's semantic version, as `{ major, minor, patch }`.
///
/// Curators bump it when the list's contents change, so it is how an owner
/// tells a re-import that brought something new from one that brought the
/// same rows back. Every field defaults, because a list that writes a partial
/// version is still more informative than no version at all.
#[derive(Debug, Deserialize)]
struct RawVersion {
    #[serde(default)]
    major: u64,
    #[serde(default)]
    minor: u64,
    #[serde(default)]
    patch: u64,
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
        /// The standard schema requires this; Ekubo's API omits it. Optional
        /// here for the same reason every other tolerance is: a list that
        /// carries no version is a list, not an error.
        #[serde(default)]
        version: Option<RawVersion>,
        #[serde(default)]
        timestamp: Option<String>,
    },
    Bare(Vec<RawEntry>),
}

/// Longest publisher-authored name or timestamp this carries onward.
///
/// A list name is a few words and a timestamp is an ISO-8601 instant; this is
/// far above both, which is the point. It is a ceiling on what an untrusted
/// curator can put into a response somebody's context window has to hold, not
/// an opinion about how lists should be labelled.
const MAX_DECLARED_TEXT_CHARS: usize = 128;

/// What one token-list body turned out to contain.
#[derive(Debug)]
pub struct ParsedTokenList {
    /// The list's own `name`, when it carries one. Callers prefer an explicit
    /// name over this, and this over whatever the transport suggests.
    pub declared_name: Option<String>,
    /// The list's own `version`, rendered `major.minor.patch`, when it carries
    /// one. Reported rather than acted on: it lets an owner see which revision
    /// of a list they are being asked to accept, and lets a re-import say
    /// whether anything moved.
    pub declared_version: Option<String>,
    /// The list's own `timestamp`, verbatim, when it carries one. Passed
    /// through unparsed on purpose — nothing here decides anything by it, and
    /// a curator's malformed date should not fail an otherwise good list.
    pub declared_timestamp: Option<String>,
    pub tokens: Vec<ListedToken>,
    /// Entries dropped because their address is not a 20-byte EVM address.
    /// Reported so a multi-ecosystem list's missing rows are explained rather
    /// than merely absent.
    pub skipped_non_evm: usize,
    /// Entries dropped because they name a chain this import did not select.
    /// Zero when no chain filter was applied. Reported for the same reason as
    /// the above: an import that took 396 rows from a 1685-row list should say
    /// so rather than look like a list that was mostly empty.
    pub skipped_other_chain: usize,
}

/// Parse one token-list body.
///
/// Fails when the bytes are not a token list at all, when every entry was
/// skipped, or when the list holds more entries than one import may carry.
pub fn parse_token_list(body: &[u8]) -> Result<ParsedTokenList> {
    parse_token_list_within(body, MAX_TOKEN_LIST_BYTES, MAX_IMPORT_TOKENS)
}

/// Parse one token-list body against explicit limits.
///
/// The limits are a parameter because the two callers bound different things.
/// An import's cap exists to bound what one call can queue for the owner. The
/// compiled-in list in [`crate::default_tokens`] queues nothing at all — it
/// was reviewed when it was vendored, and nothing about a startup seed asks
/// the owner to decide anything — so holding it to an import's cap would be
/// enforcing a limit against the wrong party. Everything else about how the
/// bytes are read stays identical, which is the point: one set of tolerances,
/// one place they are written down.
pub fn parse_token_list_within(
    body: &[u8],
    max_bytes: usize,
    max_entries: usize,
) -> Result<ParsedTokenList> {
    // No selection, so the two caps coincide: bounding the rows read already
    // bounds the rows proposed, and charging the second one again would only
    // let the same list fail with two different sentences.
    parse_selecting(body, max_bytes, max_entries, usize::MAX, None)
}

/// Parse one token-list body, keeping only the entries for `chain_ids`.
///
/// This is what a published multi-chain list needs. [`MAX_IMPORT_TOKENS`]
/// bounds what one call queues for the owner, so it belongs on the rows that
/// actually reach them — and an owner taking one chain from a nine-chain list
/// is not asking for the other eight. Selecting first also keeps names for
/// chains the wallet has no network for out of the review screen entirely,
/// which is the difference between a list someone wanted and a list they have
/// to read past.
///
/// An empty `chain_ids` selects every chain, which is the right default for a
/// single-chain list and fails loudly on a list too large to import whole
/// rather than silently taking a slice of it.
pub fn parse_token_list_for_chains(body: &[u8], chain_ids: &[u64]) -> Result<ParsedTokenList> {
    parse_selecting(
        body,
        MAX_TOKEN_LIST_BYTES,
        MAX_LIST_ENTRIES,
        MAX_IMPORT_TOKENS,
        (!chain_ids.is_empty()).then_some(chain_ids),
    )
}

/// The one parse. `structural_cap` bounds the rows read; `selection_cap`
/// bounds the rows kept. Splitting them is what lets a large list yield a
/// reviewable import instead of an error.
fn parse_selecting(
    body: &[u8],
    max_bytes: usize,
    structural_cap: usize,
    selection_cap: usize,
    chain_ids: Option<&[u64]>,
) -> Result<ParsedTokenList> {
    ensure!(
        body.len() <= max_bytes,
        "token list is larger than {max_bytes} bytes"
    );
    let parsed: RawList = serde_json::from_slice(body).context(
        "not a token list: expected a tokens array of entries with \
         chainId, address, symbol, and decimals, or a bare array of the same",
    )?;
    let (declared_name, declared_version, declared_timestamp, entries) = match parsed {
        RawList::Wrapped {
            name,
            tokens,
            version,
            timestamp,
        } => (
            name,
            version.map(|version| format!("{}.{}.{}", version.major, version.minor, version.patch)),
            timestamp,
            tokens,
        ),
        RawList::Bare(tokens) => (None, None, None, tokens),
    };
    // The publisher chose these and they are returned verbatim in a successful
    // import response, which a model reads and a transcript keeps. Nothing
    // bounded them: `tool_error` caps what it hands back at
    // `MAX_TOOL_ERROR_CHARS` precisely because "an RPC or a plan producer
    // chose it", and a token list is the same kind of text on the path that
    // succeeds. A curator could put most of an allowed body into `timestamp`
    // and still ship one valid token.
    //
    // `stripped_capped` is the helper that already existed for this, and it
    // does the other half too: these strings are displayed, and the publisher
    // picked the characters as well as the length.
    //
    // Bounded here rather than at the response, so every reader of a
    // `ParsedTokenList` gets the same value -- the review that shows a list's
    // name before an owner accepts it, not only the MCP output.
    let declared_name =
        declared_name.map(|name| crate::sanitize::stripped_capped(&name, MAX_DECLARED_TEXT_CHARS));
    let declared_timestamp = declared_timestamp
        .map(|stamp| crate::sanitize::stripped_capped(&stamp, MAX_DECLARED_TEXT_CHARS));
    ensure!(!entries.is_empty(), "the token list lists no tokens");
    // The two callers bound different things with this, so it says which.
    // Without a selection the structural cap *is* the import cap; with one it
    // is only how much this process will walk before selecting.
    ensure!(
        entries.len() <= structural_cap,
        "the token list holds {} entries, over the {structural_cap} {}",
        entries.len(),
        if chain_ids.is_some() {
            "this wallet will read"
        } else {
            "one import may carry"
        }
    );

    let mut tokens = Vec::new();
    let mut skipped_non_evm = 0;
    let mut skipped_other_chain = 0;
    for entry in entries {
        // A 20-byte address is what this wallet can act on. Anything else is
        // a row for another ecosystem, not a malformed row: skip it rather
        // than refusing the list that carried it.
        let Ok(address) = Address::from_str(&entry.address) else {
            skipped_non_evm += 1;
            continue;
        };
        // Read before the filter, so a row this import does not want is still
        // a row whose chain ID has to make sense. A list that garbles one is
        // garbled whether or not the garbled part was selected.
        let chain_id = entry.chain_id.value()?;
        if chain_ids.is_some_and(|wanted| !wanted.contains(&chain_id)) {
            skipped_other_chain += 1;
            continue;
        }
        tokens.push(ListedToken {
            chain_id,
            address,
            symbol: entry.symbol,
            name: entry.name,
            decimals: entry.decimals,
        });
    }
    if chain_ids.is_some() {
        ensure!(
            !tokens.is_empty(),
            "the token list names no tokens on the {} chain{} selected; \
             it carries {skipped_other_chain} entr{} for other chains",
            chain_ids.map_or(0, <[u64]>::len),
            if chain_ids.map_or(0, <[u64]>::len) == 1 {
                ""
            } else {
                "s"
            },
            if skipped_other_chain == 1 { "y" } else { "ies" }
        );
    } else {
        ensure!(
            !tokens.is_empty(),
            "the token list holds no entries with a 20-byte EVM address; \
             all {skipped_non_evm} were for another ecosystem"
        );
    }
    // Charged against what the owner would actually be handed, rather than
    // against the whole list, so a multi-chain list stays importable for the
    // chains someone wanted.
    //
    // The advice has to match the list. Narrowing chains fixes an over-cap
    // selection only when more than one chain is in it; telling someone whose
    // overflow is all on one chain to select fewer would send them looking
    // for a filter that cannot help. So the sentence offers narrowing only
    // when there is something to narrow.
    let chains_in_selection = tokens
        .iter()
        .map(|token| token.chain_id)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    ensure!(
        tokens.len() <= selection_cap,
        "the selection holds {} entries, over the {selection_cap} one import may carry; {}",
        tokens.len(),
        if chains_in_selection > 1 {
            "select fewer chains, or point at a smaller list"
        } else {
            "point at a smaller or more specific list"
        }
    );
    Ok(ParsedTokenList {
        declared_name,
        declared_version,
        declared_timestamp,
        tokens,
        skipped_non_evm,
        skipped_other_chain,
    })
}

#[cfg(test)]
#[path = "token_list_test.rs"]
mod tests;
