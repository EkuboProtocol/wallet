//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.

use super::*;

/// The vendored snapshot is read on the first portfolio a wallet draws, from a
/// path that panics rather than degrades. This is where a bad one is caught.
#[test]
fn the_vendored_prices_are_well_formed() {
    let table = parse(EMBEDDED).expect("the vendored snapshot must parse");
    assert!(
        table.tokens.len() > 100,
        "a snapshot this small is a truncated fetch, not a price list: {}",
        table.tokens.len()
    );
    assert!(
        table.natives.contains_key(&1),
        "Ethereum's own currency must carry a value: it is what pays for \
         everything else on the chain most of these tokens live on"
    );
    for price in table.tokens.iter().map(|token| token.usd_price) {
        assert!(price.is_finite() && price > 0.0, "{price} is not a value");
    }
}

/// Three significant figures is the claim this data makes about itself: enough
/// to sort holdings, not enough to read as a quote. A regenerated snapshot
/// that started carrying fifteen digits would be making a different claim.
#[test]
fn every_vendored_value_is_rounded_to_three_significant_figures() {
    for token in seeded_prices() {
        let digits = significant_digits(token.usd_price);
        assert!(
            digits <= 3,
            "{} on chain {} carries {}, which is {digits} significant figures",
            token.address,
            token.chain_id,
            token.usd_price
        );
    }
}

/// How many significant figures a value actually carries, read off its own
/// shortest round-tripping form rather than recovered by arithmetic that would
/// have to round the same way the generator did.
fn significant_digits(value: f64) -> usize {
    let scientific = format!("{value:e}");
    let mantissa = scientific.split('e').next().unwrap_or_default();
    mantissa
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .trim_end_matches('0')
        .len()
        .max(1)
}

#[test]
fn a_chain_the_snapshot_never_heard_of_has_no_value_to_offer() {
    assert_eq!(native_usd_price(u64::MAX), None);
    assert_eq!(seeded_token_price(u64::MAX, Address::ZERO), None);
}

/// The zero address is the native sentinel every balance read uses, and the
/// snapshot carries mainnet's entry for it. A token row can legitimately name
/// it too, so the lookup has to work either way.
#[test]
fn the_native_sentinel_is_priced_on_mainnet() {
    assert!(seeded_token_price(1, Address::ZERO).is_some());
    assert_eq!(
        seeded_token_price(1, Address::ZERO),
        native_usd_price(1),
        "mainnet's own entry is what its native value comes from"
    );
}
