//! Tests for [`super`].
//!
//! These stand in for the compile-time check the vendored file does not get:
//! it is parsed at run time, so a malformed or truncated snapshot would
//! otherwise reach a new user's first launch before anything noticed.

use super::*;
use crate::policy_store::{DatabaseKey, PolicyStore, SeedDefaults};
use crate::token_store::TokenStore;

#[test]
fn the_vendored_list_parses() {
    let parsed = embedded().unwrap();
    assert!(
        parsed.tokens.len() > 10_000,
        "vendored list holds only {} tokens; the snapshot looks truncated",
        parsed.tokens.len()
    );
    // Every row was normalized to an EVM address by the vendoring script, so
    // the parser should have had nothing to drop. A non-zero count here means
    // the file was refreshed by something other than that script.
    assert_eq!(parsed.skipped_non_evm, 0);
}

#[test]
fn the_vendored_snapshot_accounts_for_every_upstream_row() {
    let document: serde_json::Value = serde_json::from_str(EMBEDDED).unwrap();
    let upstream = document["upstream_tokens"].as_u64().unwrap();
    let skipped = document["skipped_non_evm"].as_u64().unwrap();
    let parsed = embedded().unwrap();

    assert_eq!(upstream, parsed.tokens.len() as u64 + skipped);
    assert_eq!(upstream, 19_646);
}

#[test]
fn the_vendored_list_carries_no_logo_urls() {
    // Cheapest possible guard on the thing the wallet has no way to display
    // and no reason to ship: if a refresh ever stops stripping them, the file
    // grows by tens of kilobytes of URLs silently.
    assert!(!EMBEDDED.contains("logo_url"));
    assert!(!EMBEDDED.contains("logoURI"));
}

#[test]
fn every_vendored_row_is_representable() {
    let parsed = embedded().unwrap();
    for token in &parsed.tokens {
        assert!(token.chain_id > 0, "{token:?} has a non-positive chain ID");
        assert!(
            !crate::token_store::sanitize(&token.symbol).is_empty(),
            "{token:?} sanitizes to an empty symbol, so it could never be seeded"
        );
    }
}

#[test]
fn vendored_rows_are_unique_per_chain_and_address() {
    let parsed = embedded().unwrap();
    let mut seen = std::collections::HashSet::new();
    for token in &parsed.tokens {
        assert!(
            seen.insert((token.chain_id, token.address)),
            "{token:?} appears twice; the second row would be silently dropped"
        );
    }
}

#[test]
fn a_new_database_starts_with_the_default_list() {
    let directory = tempfile::tempdir().unwrap();
    let store = TokenStore::new(
        PolicyStore::open_with(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([9; 32]),
            SeedDefaults::Yes,
        )
        .unwrap(),
    );
    let expected = embedded().unwrap().tokens.len() as u64;
    assert_eq!(store.count(None).unwrap(), expected);

    // Seeded rows are confirmed tokens, not proposals: the owner is not asked
    // to review the list their own wallet shipped with.
    assert_eq!(store.count_proposals().unwrap(), 0);
}

/// A fresh wallet's Portfolio tab has to be able to sort its holdings and hold
/// back the dust on the very first read, which it cannot do from a column that
/// is null in every row of a list seventeen thousand long.
#[test]
fn a_new_database_carries_the_values_this_build_ships() {
    let directory = tempfile::tempdir().unwrap();
    let store = TokenStore::new(
        PolicyStore::open_with(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([9; 32]),
            SeedDefaults::Yes,
        )
        .unwrap(),
    );
    let priced = *crate::token_prices::seeded_prices()
        .iter()
        .find(|price| {
            embedded()
                .unwrap()
                .tokens
                .iter()
                .any(|token| token.chain_id == price.chain_id && token.address == price.address)
        })
        .expect("the default list and the price snapshot must overlap");
    let stored = store.get(priced.chain_id, priced.address).unwrap().unwrap();
    assert_eq!(stored.approximate_usd_price, Some(priced.usd_price));
}

#[test]
fn seeded_rows_use_the_default_tokens_source() {
    let directory = tempfile::tempdir().unwrap();
    let store = TokenStore::new(
        PolicyStore::open_with(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([9; 32]),
            SeedDefaults::Yes,
        )
        .unwrap(),
    );
    let first = embedded().unwrap().tokens.into_iter().next().unwrap();
    let stored = store.get(first.chain_id, first.address).unwrap().unwrap();
    assert_eq!(stored.source, SOURCE);
    assert_eq!(stored.symbol.as_deref(), Some(first.symbol.as_str()));
}

#[test]
fn reopening_a_database_does_not_reseed_it() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let key = DatabaseKey::new([9; 32]);

    let store = TokenStore::new(PolicyStore::open_with(&path, &key, SeedDefaults::Yes).unwrap());
    let seeded = store.count(None).unwrap();
    drop(store);

    // Removing a default is the case that matters: a wallet that re-seeded on
    // every open would hand the owner back a name they deliberately deleted.
    // There is no public API for this because nothing in the product removes a
    // confirmed token yet, so the test reaches for the connection directly.
    let first = embedded().unwrap().tokens.into_iter().next().unwrap();
    let database = PolicyStore::open_with(&path, &key, SeedDefaults::Yes).unwrap();
    database
        .connection
        .execute(
            "DELETE FROM tokens WHERE chain_id = ?1 AND address = ?2",
            rusqlite::params![
                i64::try_from(first.chain_id).unwrap(),
                crate::sql::Blob(first.address)
            ],
        )
        .unwrap();
    drop(database);

    let reopened = TokenStore::new(PolicyStore::open_with(&path, &key, SeedDefaults::Yes).unwrap());
    assert_eq!(reopened.count(None).unwrap(), seeded - 1);
    assert!(
        reopened
            .get(first.chain_id, first.address)
            .unwrap()
            .is_none(),
        "reopening resurrected a token the owner removed"
    );
}
