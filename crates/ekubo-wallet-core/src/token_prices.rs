//! What a token was roughly worth on the day this build was cut.
//!
//! The Portfolio tab sorts by what a holding is worth and holds back the dust,
//! and neither is answerable without a number per token. Nothing in this wallet
//! watches a market: this is a snapshot, vendored by
//! `contrib/generate-token-prices.py` from Ekubo's public token API and
//! compiled in, exactly the way [`crate::networks`] and
//! [`crate::default_tokens`] are. A release carries the values that were
//! vendored and asks nothing of the network, at build time or at run time.
//!
//! Every value is rounded to three significant figures, which is a statement
//! about what it is for. A price with fifteen digits looks like a quote; three
//! digits is an order of magnitude and a bit — enough to sort holdings and to
//! tell a dollar from a thousand, never enough to be mistaken for what a token
//! trades at now. Nothing in the policy, signing, or approval path reads any of
//! it, no amount is ever scaled by it, and it never appears next to a balance.
//!
//! A seeded value is a starting point, not an authority. It is written into a
//! token's row where that row has none, and the owner's own number is never
//! overwritten by it.

use alloy::primitives::Address;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, str::FromStr as _, sync::OnceLock};

/// The vendored snapshot. Regenerate with `contrib/generate-token-prices.py`.
const EMBEDDED: &str = include_str!("../token-prices.json");

#[derive(Deserialize)]
struct Snapshot {
    tokens: Vec<VendoredToken>,
    natives: Vec<VendoredNative>,
}

#[derive(Deserialize)]
struct VendoredToken {
    chain_id: u64,
    address: String,
    usd_price: f64,
}

#[derive(Deserialize)]
struct VendoredNative {
    chain_id: u64,
    usd_price: f64,
}

/// One vendored value, ready to write.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SeededPrice {
    pub chain_id: u64,
    pub address: Address,
    pub usd_price: f64,
}

pub(crate) struct Table {
    tokens: Vec<SeededPrice>,
    by_identity: BTreeMap<(u64, Address), f64>,
    natives: BTreeMap<u64, f64>,
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| {
        // A malformed vendored snapshot is a build that should never have been
        // cut rather than a condition to recover from: `the_vendored_prices_are_well_formed`
        // fails first, locally and in CI.
        parse(EMBEDDED).expect("the compiled-in token price snapshot is malformed")
    })
}

/// Parse a snapshot document. Crate-visible so a test can assert the vendored
/// file is well-formed without going through the panicking accessor.
pub(crate) fn parse(document: &str) -> Result<Table> {
    let snapshot: Snapshot =
        serde_json::from_str(document).context("token price snapshot is not valid JSON")?;
    let mut tokens = Vec::with_capacity(snapshot.tokens.len());
    let mut by_identity = BTreeMap::new();
    for token in snapshot.tokens {
        let address = Address::from_str(&token.address).with_context(|| {
            format!(
                "token price snapshot has an invalid address {}",
                token.address
            )
        })?;
        let usd_price = checked_price(token.usd_price, token.chain_id)?;
        tokens.push(SeededPrice {
            chain_id: token.chain_id,
            address,
            usd_price,
        });
        by_identity.insert((token.chain_id, address), usd_price);
    }
    let mut natives = BTreeMap::new();
    for native in snapshot.natives {
        natives.insert(
            native.chain_id,
            checked_price(native.usd_price, native.chain_id)?,
        );
    }
    Ok(Table {
        tokens,
        by_identity,
        natives,
    })
}

fn checked_price(price: f64, chain_id: u64) -> Result<f64> {
    anyhow::ensure!(
        price.is_finite() && price > 0.0,
        "token price snapshot carries {price} for chain {chain_id}, which is not a value"
    );
    Ok(price)
}

/// Every vendored token value, in the snapshot's own order.
#[must_use]
pub fn seeded_prices() -> &'static [SeededPrice] {
    &table().tokens
}

/// What one whole token of this address was worth when the snapshot was taken.
#[must_use]
pub fn seeded_token_price(chain_id: u64, address: Address) -> Option<f64> {
    table().by_identity.get(&(chain_id, address)).copied()
}

/// What one unit of a chain's own currency was worth when the snapshot was
/// taken.
///
/// A chain's gas asset has no row in the token database to carry a value, and
/// most chains' own feed entry for it carries no price — so the snapshot
/// resolves these by symbol when it is generated, from the symbol in this
/// wallet's network registry rather than from anything a token list claims.
#[must_use]
pub fn native_usd_price(chain_id: u64) -> Option<f64> {
    table().natives.get(&chain_id).copied()
}

#[cfg(test)]
#[path = "token_prices_test.rs"]
mod tests;
