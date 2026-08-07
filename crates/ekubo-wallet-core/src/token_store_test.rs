//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::policy_store::DatabaseKey;
use rusqlite::Connection;

fn open(directory: &Path) -> TokenStore {
    TokenStore::new(
        PolicyStore::open(&directory.join("policies.db"), &DatabaseKey::new([8; 32])).unwrap(),
    )
}

#[test]
fn a_block_number_that_is_not_a_block_pins_nothing() {
    assert_eq!(
        pin(U256::from(21_000_000_u64)).unwrap(),
        BlockId::number(21_000_000)
    );
    // An endpoint chooses this number, and every later batch of the read
    // is sent against it. Truncating it would silently pin the balances to
    // a block nobody named.
    assert!(pin(U256::MAX).is_err());
}

fn store() -> (tempfile::TempDir, TokenStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = open(directory.path());
    (directory, store)
}

fn usdc(chain_id: u64, address: Address) -> ListedToken {
    ListedToken {
        chain_id,
        address,
        symbol: "USDC".into(),
        name: Some("USD Coin".into()),
        decimals: 6,
    }
}

#[test]
fn chain_and_address_conflicts_are_impossible() {
    let (_directory, mut store) = store();
    let token = Address::repeat_byte(0x11);
    store.add(&usdc(1, token), "manual").unwrap();

    // The same pair fails loudly on add and is skipped on bulk insert,
    // never overwritten.
    let error = store
        .add(
            &ListedToken {
                symbol: "IMPOSTOR".into(),
                ..usdc(1, token)
            },
            "manual",
        )
        .unwrap_err();
    assert!(error.to_string().contains("already in the database"));
    assert!(
        !store
            .insert_if_absent(
                &ListedToken {
                    symbol: "IMPOSTOR".into(),
                    ..usdc(1, token)
                },
                "list"
            )
            .unwrap()
    );
    let stored = store.get(1, token).unwrap().unwrap();
    assert_eq!(stored.source, "manual");
    // A second list cannot rename a token the owner already confirmed.
    assert_eq!(stored.symbol.as_deref(), Some("USDC"));

    // The same address on another chain is a distinct entry.
    assert!(store.insert_if_absent(&usdc(8453, token), "list").unwrap());
    assert_eq!(store.count(None).unwrap(), 2);
    assert_eq!(store.count(Some(1)).unwrap(), 1);
}

#[test]
fn listing_is_deterministic_and_checksummed() {
    let (_directory, mut store) = store();
    store
        .add(&usdc(1, Address::repeat_byte(0xB2)), "manual")
        .unwrap();
    store
        .add(&usdc(1, Address::repeat_byte(0x0A)), "manual")
        .unwrap();
    let listed = store.list(Some(1), 10, 0).unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed[0].address < listed[1].address);
    assert_eq!(
        listed[0].address,
        Address::repeat_byte(0x0A).to_checksum(None)
    );
    assert!(store.list(Some(2), 10, 0).unwrap().is_empty());
    assert_eq!(store.list(None, 1, 1).unwrap().len(), 1);
}

#[test]
fn hostile_metadata_is_sanitized_before_storage() {
    let (_directory, mut store) = store();
    let token = Address::repeat_byte(0x33);
    store
        .add(
            &ListedToken {
                chain_id: 1,
                address: token,
                symbol: "US\u{1b}[31mDC\n".into(),
                name: Some("x".repeat(500)),
                decimals: 6,
            },
            "manual",
        )
        .unwrap();
    let stored = store.get(1, token).unwrap().unwrap();
    assert_eq!(stored.symbol.as_deref(), Some("US[31mDC"));
    assert_eq!(stored.name.as_deref().map(str::len), Some(MAX_TEXT_LEN));
}

/// A list entry whose symbol is nothing but control characters would store
/// as an empty name and render as a token with no identity at all.
#[test]
fn a_symbol_that_sanitizes_away_is_refused() {
    let (_directory, mut store) = store();
    let error = store
        .add(
            &ListedToken {
                chain_id: 1,
                address: Address::repeat_byte(0x55),
                symbol: "\u{202e}\n\t".into(),
                name: None,
                decimals: 18,
            },
            "list",
        )
        .unwrap_err();
    assert!(error.to_string().contains("empty symbol"), "{error}");
    assert_eq!(store.count(None).unwrap(), 0);
}

/// The list is the authority on decimals, so a contract that would have
/// disagreed changes nothing: what is stored, and therefore what scales
/// every displayed amount, is what the owner confirmed.
#[test]
fn stored_decimals_are_the_list_s_own() {
    let (_directory, mut store) = store();
    let token = Address::repeat_byte(0x66);
    store.add(&usdc(1, token), "list").unwrap();
    assert_eq!(
        store.display_metadata(1, &[token]).unwrap()[&token].decimals,
        Some(6)
    );
}

/// A suggestion is not a name. Until the owner confirms it, nothing an
/// agent proposed may reach the review screen's display metadata.
#[test]
fn a_proposal_names_nothing_until_it_is_confirmed() {
    let (_directory, mut store) = store();
    let token = Address::repeat_byte(0x77);
    let summary = store
        .propose(
            &[ListedToken {
                symbol: "USDC".into(),
                ..usdc(1, token)
            }],
            "ekubo-default",
        )
        .unwrap();
    assert_eq!(summary.pending, 1);

    // Proposed, but the display path still refuses to name it.
    assert_eq!(store.count(None).unwrap(), 0);
    assert!(
        !store
            .display_metadata(1, &[token])
            .unwrap()
            .contains_key(&token)
    );

    // Confirming it is what turns it into a name.
    let proposals = store.proposals().unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].source, "ekubo-default");
    store.add(&proposals[0].token, "ekubo-default").unwrap();
    assert_eq!(
        store.display_metadata(1, &[token]).unwrap()[&token].symbol,
        Some("USDC".into())
    );

    // And once confirmed it is no longer a pending decision.
    assert_eq!(store.discard_proposals(&[(1, token)]).unwrap(), 1);
    assert_eq!(store.count_proposals().unwrap(), 0);
    let repeat = store.propose(&[usdc(1, token)], "another-list").unwrap();
    assert_eq!(repeat.already_confirmed, 1);
    assert_eq!(repeat.pending, 0);
}

/// Two lists suggesting the same address must not queue two decisions
/// showing the owner the same token under two different names.
#[test]
fn a_repeated_suggestion_replaces_the_earlier_one() {
    let (_directory, mut store) = store();
    let token = Address::repeat_byte(0x88);
    store.propose(&[usdc(1, token)], "first-list").unwrap();
    store
        .propose(
            &[ListedToken {
                symbol: "IMPOSTOR".into(),
                ..usdc(1, token)
            }],
            "second-list",
        )
        .unwrap();
    let proposals = store.proposals().unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].token.symbol, "IMPOSTOR");
    assert_eq!(proposals[0].source, "second-list");
}

#[test]
fn search_finds_tokens_by_symbol_name_and_address() {
    let (_directory, mut store) = store();
    let usdc_address = Address::repeat_byte(0x11);
    store.add(&usdc(1, usdc_address), "list").unwrap();
    store
        .add(
            &ListedToken {
                chain_id: 1,
                address: Address::repeat_byte(0x22),
                symbol: "WETH".into(),
                name: Some("Wrapped Ether".into()),
                decimals: 18,
            },
            "list",
        )
        .unwrap();
    store.add(&usdc(8453, usdc_address), "list").unwrap();

    // Case-insensitive symbol substring.
    assert_eq!(store.search("usd", None, 10).unwrap().len(), 2);
    // Name substring finds a token whose symbol does not match.
    let wrapped = store.search("wrapped", None, 10).unwrap();
    assert_eq!(wrapped.len(), 1);
    assert_eq!(wrapped[0].symbol.as_deref(), Some("WETH"));
    // Chain filter narrows it.
    assert_eq!(store.search("usdc", Some(8453), 10).unwrap().len(), 1);
    // Address matches exactly, in either case, on every chain it is on.
    assert_eq!(
        store
            .search(&usdc_address.to_checksum(None), None, 10)
            .unwrap()
            .len(),
        2
    );
    assert!(
        store
            .search("nothing-like-this", None, 10)
            .unwrap()
            .is_empty()
    );
}

/// A query is data, not syntax: `%` must search for a percent sign rather
/// than matching every row in the database.
#[test]
fn search_wildcards_are_literal() {
    let (_directory, mut store) = store();
    store
        .add(&usdc(1, Address::repeat_byte(0x11)), "list")
        .unwrap();
    assert!(store.search("%", None, 10).unwrap().is_empty());
    assert!(store.search("_", None, 10).unwrap().is_empty());
    assert!(store.search("   ", None, 10).is_err());
}

/// A suggestion is not a token: search must not surface something the
/// owner has not confirmed, or the answer implies a trust that is absent.
#[test]
fn search_never_returns_unconfirmed_suggestions() {
    let (_directory, mut store) = store();
    store
        .propose(&[usdc(1, Address::repeat_byte(0x99))], "some-list")
        .unwrap();
    assert!(store.search("USDC", None, 10).unwrap().is_empty());
}

#[test]
fn chain_id_input_accepts_numbers_and_canonical_strings() {
    assert_eq!(ChainIdInput::Number(4663).value().unwrap(), 4663);
    assert_eq!(ChainIdInput::Text("1".into()).value().unwrap(), 1);
    assert!(ChainIdInput::Text("01".into()).value().is_err());
    assert!(ChainIdInput::Text("0x1".into()).value().is_err());
    assert!(ChainIdInput::Number(0).value().is_err());
}

#[test]
fn reopening_preserves_rows() {
    let directory = tempfile::tempdir().unwrap();
    let token = Address::repeat_byte(0x44);
    {
        let mut store = open(directory.path());
        store.add(&usdc(10, token), "manual").unwrap();
    }
    let store = open(directory.path());
    assert_eq!(store.count(None).unwrap(), 1);
    assert_eq!(
        store.get(10, token).unwrap().unwrap().symbol.as_deref(),
        Some("USDC")
    );
}

#[test]
fn fetcher_call_encodes_the_deployed_selector() {
    use alloy::primitives::keccak256;
    let expected =
        keccak256(b"getNonzeroBalancesAndAllowances(address,address[],address[])".as_slice());
    assert_eq!(getNonzeroBalancesAndAllowancesCall::SELECTOR, expected[..4]);
    assert_eq!(
        format!("{TOKEN_DATA_FETCHER_ADDRESS:#x}"),
        "0x305cf9a34dcb265522780d1d64544d3f7c450407"
    );
}

#[test]
fn balances_read_bounds_its_input() {
    let network = crate::config::default_networks().remove(0);
    let owner = Address::repeat_byte(0x11);
    let empty: Vec<Address> = Vec::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    assert!(
        runtime
            .block_on(read_token_balances(&network, owner, &empty, None))
            .is_err()
    );
    let too_many = vec![Address::repeat_byte(0x22); MAX_BALANCE_TOKENS + 1];
    assert!(
        runtime
            .block_on(read_token_balances(&network, owner, &too_many, None))
            .is_err()
    );
}

#[tokio::test]
#[ignore = "explicit live Ethereum RPC conformance check"]
async fn live_balances_read_isolates_bad_tokens_and_filters_zeroes() {
    let network = crate::config::default_networks().remove(0);
    // Any fixed address may hold dust on mainnet, so assert the
    // structural guarantees instead of exact holdings: the bogus token
    // must not abort the batch and can never report a balance, entries
    // are nonzero and pinned to a real block, and Binance 8 definitely
    // holds USDC, exercising the nonzero path.
    let bogus = Address::repeat_byte(0x11);
    let usdc = Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap();
    let binance = Address::from_str("0xf977814e90da44bfa03b6295a0616a897441acec").unwrap();
    let result = read_token_balances(&network, binance, &[usdc, bogus, Address::ZERO], None)
        .await
        .unwrap();
    println!("source={} balances={:?}", result.source, result.balances);
    assert_eq!(result.tokens_checked, 3);
    assert!(result.block_number.parse::<u64>().unwrap() > 0);
    let bogus_checksum = bogus.to_checksum(None);
    assert!(
        result
            .balances
            .iter()
            .all(|entry| entry.token != bogus_checksum)
    );
    assert!(result.balances.iter().all(|entry| {
        entry
            .balance
            .parse::<u128>()
            .map_or(true, |value| value > 0)
    }));
    assert!(
        result
            .balances
            .iter()
            .any(|entry| entry.token == usdc.to_checksum(None))
    );
}

#[test]
fn a_legacy_plain_database_names_nothing_and_is_deleted() {
    // A file anyone can write is not a curator. Planting one must not put
    // a single name into the table the review screen trusts, however
    // well-formed its rows are.
    let directory = tempfile::tempdir().unwrap();
    let legacy_path = directory.path().join(LEGACY_DATABASE_FILE);
    let legacy = Connection::open(&legacy_path).unwrap();
    legacy
        .execute_batch(
            "CREATE TABLE tokens (
                     chain_id INTEGER NOT NULL,
                     address TEXT NOT NULL,
                     symbol TEXT, name TEXT, decimals INTEGER,
                     source TEXT NOT NULL, added_at TEXT NOT NULL,
                     PRIMARY KEY (chain_id, address)
                 );
                 INSERT INTO tokens VALUES
                     (1, '0x1111111111111111111111111111111111111111',
                      'USDC', 'USD Coin', 6, 'manual', '2026-01-01T00:00:00Z');",
        )
        .unwrap();
    drop(legacy);

    // What `production` does before it opens the encrypted database. Called
    // directly so the test does not touch the OS credential store.
    discard_legacy_database(directory.path());
    let store = open(directory.path());
    assert_eq!(store.count(None).unwrap(), 0);
    assert!(store.get(1, Address::repeat_byte(0x11)).unwrap().is_none());
    assert_eq!(store.count_proposals().unwrap(), 0);
    assert!(!legacy_path.exists());
}

#[test]
fn a_removed_token_stops_naming_its_address() {
    let (_directory, mut store) = store();
    let address = Address::repeat_byte(0x42);
    store.add(&usdc(1, address), "a list").unwrap();
    assert!(store.get(1, address).unwrap().is_some());

    assert!(store.remove(1, address).unwrap());
    assert!(store.get(1, address).unwrap().is_none());
    // Removing again is not an error, it is just nothing to do — a sweep must
    // not fail on a row someone already removed.
    assert!(!store.remove(1, address).unwrap());
}

#[test]
fn removing_a_token_leaves_the_same_address_on_other_chains() {
    // The same contract address is routinely deployed on several chains, and
    // disagreeing with a name on one of them says nothing about the others.
    let (_directory, mut store) = store();
    let address = Address::repeat_byte(0x42);
    store.add(&usdc(1, address), "a list").unwrap();
    store.add(&usdc(8453, address), "a list").unwrap();

    assert!(store.remove(1, address).unwrap());
    assert!(store.get(1, address).unwrap().is_none());
    assert!(store.get(8453, address).unwrap().is_some());
}
