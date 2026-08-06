//! Resolving the local metadata a policy is allowed to consult.
//!
//! [`crate::core::predicate::PolicyContext`] holds plain sets, never store
//! handles, so `evaluate_policy` remains a pure function of data with no I/O
//! and nothing to lock. This module is the one place those sets are read out of
//! the databases, and it lives outside `core` so the security kernel keeps no
//! dependency on storage.
//!
//! Reading these stores into a policy decision is a real promotion: until the
//! `is_token` and `is_address_book` predicates existed, a wrong row produced a
//! misleading label, and now it can produce a signature. Both write paths are
//! therefore human CLI operations — the MCP server can look tokens and aliases
//! up and propose tokens, but it cannot add either — and that has to stay true.
//! `tests/boundary.rs` holds the tripwire.

use crate::{
    address_book::AddressBookStore, core::predicate::PolicyContext, token_store::TokenStore,
};
use alloy::primitives::Address;
use anyhow::Result;
use std::{collections::BTreeSet, str::FromStr};

/// How many rows either store may contribute. Both are human-curated, so this
/// is a memory bound rather than a policy one; a wallet that somehow held more
/// confirmed tokens than this would see the excess simply not satisfy
/// `is_token`, which denies rather than admits.
const MAX_RESOLVED_ENTRIES: usize = 10_000;

/// Read the wallet's confirmed tokens and address-book entries for one chain.
pub fn resolve(
    wallet: Address,
    chain_id: u64,
    tokens: &TokenStore,
    address_book: &AddressBookStore,
) -> Result<PolicyContext> {
    let known_tokens = tokens
        .list(Some(chain_id), MAX_RESOLVED_ENTRIES, 0)?
        .iter()
        .filter_map(|token| Address::from_str(&token.address).ok())
        .collect::<BTreeSet<_>>();
    let address_book = address_book
        .list(Some(chain_id), MAX_RESOLVED_ENTRIES, 0)?
        .iter()
        .filter_map(|entry| Address::from_str(&entry.address).ok())
        .collect::<BTreeSet<_>>();
    Ok(PolicyContext {
        wallet,
        known_tokens,
        address_book,
    })
}

#[cfg(test)]
#[path = "policy_context_test.rs"]
mod tests;
