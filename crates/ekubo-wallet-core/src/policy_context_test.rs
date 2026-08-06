//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.

use super::*;
use crate::{policy_store::DatabaseKey, token_store::ListedToken};
use std::path::Path;

const WALLET: Address = alloy::primitives::address!("1111111111111111111111111111111111111111");
const TOKEN: Address = alloy::primitives::address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
const FRIEND: Address = alloy::primitives::address!("2222222222222222222222222222222222222222");

fn stores(directory: &Path) -> (TokenStore, AddressBookStore) {
    let open = || {
        crate::policy_store::PolicyStore::open(
            &directory.join("policies.db"),
            &DatabaseKey::new([7; 32]),
        )
        .unwrap()
    };
    (TokenStore::new(open()), AddressBookStore::new(open()))
}

#[test]
fn resolving_reads_both_stores_for_the_requested_chain() {
    let directory = tempfile::tempdir().unwrap();
    let (mut tokens, mut address_book) = stores(directory.path());
    tokens
        .add(
            &ListedToken {
                chain_id: 1,
                address: TOKEN,
                symbol: "USDC".into(),
                name: Some("USD Coin".into()),
                decimals: 6,
            },
            "test",
        )
        .expect("token is confirmed");
    address_book
        .upsert(1, "friend", FRIEND, None)
        .expect("alias saves");

    let context = resolve(WALLET, 1, &tokens, &address_book).expect("context resolves");
    assert_eq!(context.wallet, WALLET);
    assert!(context.known_tokens.contains(&TOKEN));
    assert!(context.address_book.contains(&FRIEND));
}

#[test]
fn entries_on_another_chain_do_not_leak_into_the_context() {
    // A policy predicate must never be satisfied by a row the owner recorded
    // for a different chain: the same address is a different contract there.
    let directory = tempfile::tempdir().unwrap();
    let (mut tokens, mut address_book) = stores(directory.path());
    tokens
        .add(
            &ListedToken {
                chain_id: 1,
                address: TOKEN,
                symbol: "USDC".into(),
                name: Some("USD Coin".into()),
                decimals: 6,
            },
            "test",
        )
        .expect("token is confirmed");
    address_book
        .upsert(1, "friend", FRIEND, None)
        .expect("alias saves");

    let context = resolve(WALLET, 8453, &tokens, &address_book).expect("context resolves");
    assert!(context.known_tokens.is_empty());
    assert!(context.address_book.is_empty());
}

#[test]
fn an_empty_wallet_resolves_to_an_empty_context() {
    let directory = tempfile::tempdir().unwrap();
    let (tokens, address_book) = stores(directory.path());
    let context = resolve(WALLET, 1, &tokens, &address_book).expect("context resolves");
    assert!(context.known_tokens.is_empty());
    assert!(context.address_book.is_empty());
}
