//! The network registry compiled into the binary: every EVM chain this wallet
//! knows how to reach, and the endpoints to reach it through.
//!
//! # Where the endpoints come from, and what that is worth
//!
//! This registry is aggregated: the candidates come from chainlist.org
//! — the ethereum-lists registry plus `DefiLlama`'s curated extras — and are
//! then *measured*. `contrib/rpc-probe` asks every candidate for the exact
//! requests this wallet makes, including an `eth_simulateV1` pinned to a
//! block with an EIP-7702 delegation designator installed by state override,
//! and only endpoints that answered them are here. Provenance is replaced by
//! observation, and the observation is reproducible: re-run the prober and
//! the file regenerates.
//!
//! An endpoint being here is therefore a claim that it answered this wallet's
//! requests correctly on the day it was measured. It is **not** a claim that
//! its operator is trustworthy. A public RPC sees every address the wallet
//! asks about and every transaction it broadcasts, and can lie about any
//! answer it gives. That is why nothing here is a security control: balances
//! and simulation results are cross-checked structurally, a plan is validated
//! against its own digest rather than against what an endpoint says, and the
//! chain ID is re-verified on every endpoint before its answer is used. An
//! owner with funds worth protecting should still point their networks at a
//! dedicated provider in the Networks screen.
//!
//! # Defaults and the rest
//!
//! [`default_networks`] is the small set a fresh configuration starts with.
//! Each installed default uses only the registry's highest-ranked compatible
//! endpoint. The complete registry retains its measured fallbacks for owners
//! who choose to add them.
//! [`known_networks`] is everything — every chain in the registry — and backs
//! `network add`, so configuring a chain the wallet did not default to is a
//! chain ID rather than a research project.

use crate::config::{NativeCurrency, NetworkConfig};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::sync::OnceLock;
use url::Url;

/// The vendored registry. Regenerate with `contrib/rpc-probe`: `collect.mjs`
/// gathers candidates, `probe.mjs` measures them, `select.mjs` writes this.
const EMBEDDED: &str = include_str!("../networks.json");

/// One chain, as measured.
#[derive(Clone, Debug)]
pub struct NetworkProfile {
    pub config: NetworkConfig,
    /// Whether a fresh configuration starts with this network.
    pub is_default: bool,
    /// How many of this chain's endpoints answered the `eth_simulateV1`
    /// request that signing depends on. Zero means the wallet can read this
    /// chain but cannot simulate, and so will not sign on it, until the owner
    /// configures an endpoint that implements the method.
    pub simulate_endpoints: usize,
    /// How many answered the multi-block form that fork replay needs. Some
    /// chains answer the one-block form and reject this one.
    pub fork_endpoints: usize,
}

#[derive(Deserialize)]
struct Registry {
    chains: Vec<RegistryChain>,
}

#[derive(Deserialize)]
struct RegistryChain {
    chain_id: u64,
    name: String,
    display_name: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(rename = "default")]
    is_default: bool,
    testnet: bool,
    native_currency: Option<NativeCurrency>,
    block_explorer_url: Option<String>,
    documentation_url: Option<String>,
    simulate_endpoints: usize,
    fork_endpoints: usize,
    rpc_urls: Vec<String>,
}

fn parsed() -> &'static Vec<NetworkProfile> {
    static PARSED: OnceLock<Vec<NetworkProfile>> = OnceLock::new();
    PARSED.get_or_init(|| {
        // A malformed vendored registry is a build that should never have been
        // cut, not a condition to recover from at run time: every command
        // needs a network list, and there is no smaller one to fall back to.
        // `registry_is_well_formed` in the tests fails first, in CI.
        parse(EMBEDDED).expect("the compiled-in network registry is malformed")
    })
}

/// Parse a registry document. Public to the crate so a test can assert the
/// vendored file is well-formed without going through the panicking accessor.
pub(crate) fn parse(document: &str) -> Result<Vec<NetworkProfile>> {
    let registry: Registry =
        serde_json::from_str(document).context("network registry is not valid JSON")?;
    registry
        .chains
        .into_iter()
        .map(|chain| {
            let profile = NetworkProfile {
                config: NetworkConfig {
                    name: chain.name,
                    disabled: false,
                    testnet: chain.testnet,
                    display_name: chain.display_name,
                    aliases: chain.aliases,
                    chain_id: chain.chain_id,
                    rpc_urls: chain
                        .rpc_urls
                        .iter()
                        .map(|url| Url::parse(url))
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .with_context(|| {
                            format!("chain {} has an unparsable RPC URL", chain.chain_id)
                        })?,
                    // The registry never ships a strategy. Which one is right
                    // is a judgement about how much an owner's transactions
                    // are worth and how much latency they will pay, and that
                    // is theirs to make.
                    rpc_strategy: crate::config::RpcStrategy::default(),
                    finality_confirmations: crate::config::DEFAULT_FINALITY_CONFIRMATIONS,
                    native_currency: chain.native_currency,
                    block_explorer_url: chain
                        .block_explorer_url
                        .as_deref()
                        .map(Url::parse)
                        .transpose()
                        .with_context(|| {
                            format!("chain {} has an unparsable explorer URL", chain.chain_id)
                        })?,
                    documentation_url: chain
                        .documentation_url
                        .as_deref()
                        .map(Url::parse)
                        .transpose()
                        .with_context(|| {
                            format!(
                                "chain {} has an unparsable documentation URL",
                                chain.chain_id
                            )
                        })?,
                },
                is_default: chain.is_default,
                simulate_endpoints: chain.simulate_endpoints,
                fork_endpoints: chain.fork_endpoints,
            };
            // The same rules a configured network is held to. A registry entry
            // becomes a configured network verbatim, so one that could not be
            // configured by hand must not be shippable either.
            crate::config::validate_network(&profile.config).with_context(|| {
                format!(
                    "registry entry for chain {} is not a valid network",
                    chain.chain_id
                )
            })?;
            Ok(profile)
        })
        .collect()
}

/// Every chain in the registry, ordered by chain ID.
#[must_use]
pub fn known_networks() -> &'static [NetworkProfile] {
    parsed()
}

/// The registry entry for one chain, if it has one.
#[must_use]
pub fn known_network(chain_id: u64) -> Option<&'static NetworkProfile> {
    known_networks()
        .iter()
        .find(|profile| profile.config.chain_id == chain_id)
}

/// The networks a configuration starts with when there is no file yet.
///
/// Deliberately a subset. The registry knows hundreds of chains, the
/// configuration format caps how many one file may hold, and every one of them
/// is re-read and re-validated on every command — so the default is the set of
/// chains a wallet is likely to be used on, and the rest are one
/// `network add <chain-id>` away.
#[must_use]
pub fn default_networks() -> Vec<NetworkConfig> {
    known_networks()
        .iter()
        .filter(|profile| profile.is_default)
        .map(|profile| {
            let mut network = profile.config.clone();
            network.rpc_urls.truncate(1);
            network.disabled = !matches!(
                network.name.as_str(),
                "ethereum" | "base" | "arbitrum" | "robinhood"
            );
            network
        })
        .collect()
}

#[cfg(test)]
#[path = "networks_test.rs"]
mod tests;
