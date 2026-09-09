//! The hosted MCP servers this wallet offers to add to an agent's config.
//!
//! Ekubo serves one MCP endpoint per protocol. Each is credential-free, each
//! carries only that protocol's tools, and the owner chooses which of them the
//! wallet writes into a harness configuration alongside the local
//! `ekubo_wallet` bridge entry.
//!
//! Nothing here signs, authorizes, or holds a secret. It is a fixed table of
//! public URLs plus the owner's selection over it, kept in the kernel because
//! the selection is persistent wallet state and because `legal` has to name
//! the same URLs the config writer writes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One hosted server: what it is called, where it is, and the key it is
/// written under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompanionServer {
    /// The protocol, matching the `/mcp/<slug>` path the operator serves.
    pub slug: &'static str,
    /// The key in the harness's MCP configuration map.
    ///
    /// Underscores, never hyphens, for the reason
    /// [`LOCAL_SERVER_NAME`](../../../src/agent_config.rs) documents: Codex
    /// rewrites `-` to `_` when it derives the tool names the model sees,
    /// while `resources/list` still expects the unsanitized key, so a
    /// hyphenated key makes the server's own resources unreachable by name.
    pub config_key: &'static str,
    pub title: &'static str,
    /// One line saying what an agent can do with this server added.
    pub description: &'static str,
    pub url: &'static str,
    /// How many tools this server puts in an agent's context.
    ///
    /// The only reason to switch a server off is what its tools cost an
    /// agent's context, and a row that says what the protocol does without
    /// saying what it costs leaves the switch decoration: every reader's
    /// rational move is to leave all of them on.
    ///
    /// It is a shipped number, so it is pinned to this release and can drift
    /// from the deployed server between releases. That is why it is presented
    /// as approximate: it exists to make "51 against 6" a comparison the
    /// reader can act on, not as a contract about the catalog. Nothing but
    /// the label reads it. `tool_counts_cover_the_catalog` pins the total
    /// against the partition it came from.
    pub tool_count: usize,
}

/// Every server the wallet can add, in the order the settings screen lists
/// them: Ekubo's own protocol first, then the others alphabetically.
///
/// The slugs mirror the `PROTOCOL_SLUGS` partition in the MCP server
/// repository. `companion_slugs_match_endpoints` pins them so the two sides
/// cannot drift into a wallet writing a URL that answers 404.
pub const COMPANION_SERVERS: [CompanionServer; 7] = [
    CompanionServer {
        slug: "ekubo",
        config_key: "ekubo",
        title: "Ekubo",
        description: "Swaps and bridges, pools, LP positions, TWAMM, auctions, incentives, and ve(3,3) STONX voting.",
        url: "https://mcp.ekubo.org/mcp/ekubo",
        tool_count: 51,
    },
    CompanionServer {
        slug: "aave",
        config_key: "ekubo_aave",
        title: "Aave V3",
        description: "Aave V3 market discovery and supply, withdraw, borrow, repay, collateral, and eMode preparation.",
        url: "https://mcp.ekubo.org/mcp/aave",
        tool_count: 7,
    },
    CompanionServer {
        slug: "aerodrome",
        config_key: "ekubo_aerodrome",
        title: "Aerodrome",
        description: "Aerodrome Sugar lens reads and liquidity, gauge, lock, vote, and incentive-claim preparation on Base.",
        url: "https://mcp.ekubo.org/mcp/aerodrome",
        tool_count: 10,
    },
    CompanionServer {
        slug: "lido",
        config_key: "ekubo_lido",
        title: "Lido",
        description: "Lido staking, wrapping, and unstETH withdrawal preparation.",
        url: "https://mcp.ekubo.org/mcp/lido",
        tool_count: 6,
    },
    CompanionServer {
        slug: "merkl",
        config_key: "ekubo_merkl",
        title: "Merkl",
        description: "Merkl reward discovery and proof-verified claim preparation.",
        url: "https://mcp.ekubo.org/mcp/merkl",
        tool_count: 2,
    },
    CompanionServer {
        slug: "morpho",
        config_key: "ekubo_morpho",
        title: "Morpho",
        description: "Morpho Vault V2 discovery and deposit, withdraw, and redeem preparation.",
        url: "https://mcp.ekubo.org/mcp/morpho",
        tool_count: 4,
    },
    CompanionServer {
        slug: "sky",
        config_key: "ekubo_sky",
        title: "Sky",
        description: "Sky savings discovery and sUSDS deposit, withdraw, and redeem preparation.",
        url: "https://mcp.ekubo.org/mcp/sky",
        tool_count: 4,
    },
];

/// Every tool the operator serves, across all seven endpoints.
///
/// The partition is exhaustive and disjoint on the server side, so the
/// per-server counts have to add up to it. A count edited without its
/// neighbours fails `tool_counts_cover_the_catalog` rather than quietly
/// telling an owner that turning one server off saves more or less than it
/// does.
pub const TOTAL_TOOL_COUNT: usize = 84;

/// The endpoint that serves every protocol at once.
///
/// Releases before the split wrote this as the sole `ekubo` entry, and the
/// operator keeps serving it for clients configured that way. The wallet no
/// longer writes it: an agent given this *and* the per-protocol servers would
/// carry every tool twice.
///
/// Nothing has to recognize it to retarget one. Ekubo's own server kept the
/// `ekubo` key, so the ordinary managed upsert overwrites a pre-split entry
/// with `/mcp/ekubo` in place. [`is_legacy_companion`] names the URL for the
/// tests that pin that, and for anything that needs to tell a stale entry from
/// a current one without re-deriving the string.
pub const LEGACY_COMPANION_URL: &str = "https://mcp.ekubo.org/mcp";

/// The one config key that predates the split, and still names Ekubo's own
/// protocol so an owner's existing entry is updated in place rather than
/// replaced by a differently named one.
pub const LEGACY_COMPANION_KEY: &str = "ekubo";

#[must_use]
pub fn companion_by_slug(slug: &str) -> Option<&'static CompanionServer> {
    COMPANION_SERVERS.iter().find(|server| server.slug == slug)
}

/// Whether a URL is the pre-split all-protocol endpoint.
#[must_use]
pub fn is_legacy_companion(url: &str) -> bool {
    url == LEGACY_COMPANION_URL
}

/// Which hosted servers the owner wants written into agent configurations.
///
/// Stored as the set that is *off*, not the set that is on. The wallet's
/// stated default is that every Ekubo-provided server is included, and a
/// stored allow-list could not keep that promise: a protocol added in a later
/// release is absent from every selection saved before it existed, so it would
/// arrive switched off for everyone who had ever opened this screen. A
/// deny-list has the opposite and correct failure: a new server is on until
/// the owner says otherwise, and an entry naming a server that no longer
/// exists is simply ignored rather than resurrecting it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionSelection {
    /// Slugs the owner has switched off. Unknown names are kept rather than
    /// dropped, so downgrading and upgrading again does not silently re-enable
    /// a server the owner turned off under the newer build.
    #[serde(default)]
    disabled: BTreeSet<String>,
}

impl CompanionSelection {
    /// Every server enabled, which is what an owner who has never opened the
    /// screen has.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_enabled(&self, slug: &str) -> bool {
        !self.disabled.contains(slug)
    }

    pub fn set_enabled(&mut self, slug: &str, enabled: bool) {
        if enabled {
            self.disabled.remove(slug);
        } else {
            self.disabled.insert(slug.to_owned());
        }
    }

    /// The servers to write, in table order.
    pub fn enabled(&self) -> impl Iterator<Item = &'static CompanionServer> + '_ {
        COMPANION_SERVERS
            .iter()
            .filter(|server| self.is_enabled(server.slug))
    }

    /// The servers to remove from a configuration that may already hold them.
    pub fn disabled(&self) -> impl Iterator<Item = &'static CompanionServer> + '_ {
        COMPANION_SERVERS
            .iter()
            .filter(|server| !self.is_enabled(server.slug))
    }

    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.enabled().count()
    }

    /// Roughly how many tools the selection puts in an agent's context.
    ///
    /// Approximate for the same reason the per-server counts are: it is
    /// shipped rather than read from the server. It answers the question the
    /// switches are actually about — what this selection costs — which no
    /// single row can.
    #[must_use]
    pub fn enabled_tool_count(&self) -> usize {
        self.enabled().map(|server| server.tool_count).sum()
    }

    /// Whether nothing is selected.
    ///
    /// The wallet still writes its own `ekubo_wallet` bridge entry in this
    /// case — an agent that can reach the wallet but no hosted server is a
    /// coherent choice, and is what an owner who prepares plans some other way
    /// wants.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.enabled_count() == 0
    }
}

#[cfg(test)]
#[path = "mcp_companions_test.rs"]
mod tests;
