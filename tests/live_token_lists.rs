//! Live conformance for importing a token list from its published URL.
//!
//! The unit tests cover the parser and the admission policy against local
//! fixtures. What needs the network is the other end of the contract: that
//! the lists people actually name at tokenlists.org still parse, still fit
//! the caps, and still carry the fields the owner is shown at review time.
//! That end is maintained by strangers and moves on its own schedule, so a
//! fixture cannot speak for it: the default list outgrew the import cap once
//! already, which is how the chain filter came to exist.
//!
//! Skipped unless `EKUBO_WALLET_LIVE_TOKEN_LIST_TESTS=1`. These read public
//! URLs and need no key, wallet, or chain access.

use ekubo_wallet::plan_fetch::{FetchPolicy, fetch_token_list_url};
use ekubo_wallet::token_store::MAX_IMPORT_TOKENS;

/// The canonical list tokenlists.org points at first.
const UNISWAP_DEFAULT: &str = "https://tokens.uniswap.org";

fn live_enabled() -> bool {
    std::env::var_os("EKUBO_WALLET_LIVE_TOKEN_LIST_TESTS").is_some_and(|value| value == "1")
}

/// The flagship case: name the URL, take one chain, get a reviewable import.
#[tokio::test]
async fn imports_ethereum_mainnet_from_the_uniswap_default_list() {
    if !live_enabled() {
        return;
    }
    let (list, host) = fetch_token_list_url(UNISWAP_DEFAULT, &[1], FetchPolicy::production())
        .await
        .expect("the Uniswap default list should import for mainnet");

    assert_eq!(host, "tokens.uniswap.org");
    assert_eq!(list.declared_name.as_deref(), Some("Uniswap Labs Default"));
    // The owner is shown which revision they are accepting, so both must
    // survive the parse rather than being dropped as unknown fields.
    assert!(list.declared_version.is_some(), "no version declared");
    assert!(list.declared_timestamp.is_some(), "no timestamp declared");

    assert!(!list.tokens.is_empty());
    assert!(
        list.tokens.len() <= MAX_IMPORT_TOKENS,
        "one chain's selection must fit the import cap, got {}",
        list.tokens.len()
    );
    assert!(
        list.tokens.iter().all(|token| token.chain_id == 1),
        "the filter must not let another chain through"
    );
    // A well-known row, to catch a list that parsed into the wrong fields.
    let usdc = list
        .tokens
        .iter()
        .find(|token| token.symbol == "USDC")
        .expect("mainnet USDC is on the default list");
    assert_eq!(usdc.decimals, 6);

    // The rest of the list is a selection, not a loss, and says so.
    assert!(
        list.skipped_other_chain > 0,
        "a multi-chain list should report the chains it did not take"
    );
}

/// With the import cap at ten thousand the whole default list fits, so an
/// unfiltered import is expected to succeed rather than be refused. This
/// pins that: the cap is the thing that has to stay ahead of a list that
/// grows on someone else's schedule, and if this starts failing the cap has
/// been outgrown again rather than the filter having broken.
#[tokio::test]
async fn the_whole_default_list_fits_one_import() {
    if !live_enabled() {
        return;
    }
    let (list, _) = fetch_token_list_url(UNISWAP_DEFAULT, &[], FetchPolicy::production())
        .await
        .expect("the whole default list should fit one import");
    assert!(list.tokens.len() <= MAX_IMPORT_TOKENS);
    // Unfiltered means every chain it names, so this must be strictly more
    // than the single-chain selection above.
    assert!(
        list.tokens.iter().any(|token| token.chain_id != 1),
        "an unfiltered import should carry more than mainnet"
    );
    assert_eq!(list.skipped_other_chain, 0);
    // The non-EVM rows are still dropped and counted, filter or no filter.
    assert!(list.skipped_non_evm > 0);
}

/// Several chains at once, since an owner usually runs more than one, and the
/// selection is still expected to fit.
#[tokio::test]
async fn imports_several_chains_at_once() {
    if !live_enabled() {
        return;
    }
    let chains = [1, 8453, 42161];
    let (list, _) = fetch_token_list_url(UNISWAP_DEFAULT, &chains, FetchPolicy::production())
        .await
        .expect("a three-chain selection should import");
    assert!(list.tokens.len() <= MAX_IMPORT_TOKENS);
    assert!(
        list.tokens
            .iter()
            .all(|token| chains.contains(&token.chain_id)),
        "the filter must not let another chain through"
    );
    for chain in chains {
        assert!(
            list.tokens.iter().any(|token| token.chain_id == chain),
            "expected entries for chain {chain}"
        );
    }
}
