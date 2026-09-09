use super::*;

/// The cross-repository invariant. These slugs are the `/mcp/<slug>` paths the
/// MCP server partitions its tool catalog into; a slug that exists here and not
/// there is a URL the wallet writes into an owner's agent configuration that
/// answers 404, and nothing in this repository would otherwise notice.
#[test]
fn companion_slugs_match_endpoints() {
    let slugs: Vec<&str> = COMPANION_SERVERS.iter().map(|server| server.slug).collect();
    assert_eq!(
        slugs,
        [
            "ekubo",
            "aave",
            "aerodrome",
            "lido",
            "merkl",
            "morpho",
            "sky"
        ]
    );
    for server in COMPANION_SERVERS {
        assert_eq!(
            server.url,
            format!("https://mcp.ekubo.org/mcp/{}", server.slug)
        );
    }
}

#[test]
fn config_keys_are_unique_and_underscore_only() {
    let mut keys: Vec<&str> = COMPANION_SERVERS
        .iter()
        .map(|server| server.config_key)
        .collect();
    keys.sort_unstable();
    let unique = keys.len();
    keys.dedup();
    assert_eq!(keys.len(), unique, "two companions share a config key");
    for server in COMPANION_SERVERS {
        assert!(
            !server.config_key.contains('-'),
            "{} uses a hyphen, which Codex rewrites",
            server.config_key
        );
        assert!(
            server
                .config_key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        );
    }
}

/// The pre-split entry keeps its key, so an owner's existing `ekubo` entry is
/// retargeted at `/mcp/ekubo` rather than left beside a differently named one.
#[test]
fn the_legacy_key_belongs_to_ekubos_own_server() {
    assert_eq!(LEGACY_COMPANION_KEY, "ekubo");
    assert_eq!(
        companion_by_slug("ekubo").map(|server| server.config_key),
        Some(LEGACY_COMPANION_KEY)
    );
    assert!(is_legacy_companion("https://mcp.ekubo.org/mcp"));
    assert!(!is_legacy_companion("https://mcp.ekubo.org/mcp/ekubo"));
    for server in COMPANION_SERVERS {
        assert!(!is_legacy_companion(server.url));
    }
}

#[test]
fn a_fresh_selection_enables_every_server() {
    let selection = CompanionSelection::all();
    assert_eq!(selection.enabled_count(), COMPANION_SERVERS.len());
    assert_eq!(selection.disabled().count(), 0);
    assert!(!selection.is_empty());
    for server in COMPANION_SERVERS {
        assert!(selection.is_enabled(server.slug));
    }
}

#[test]
fn disabling_removes_a_server_from_the_enabled_set() {
    let mut selection = CompanionSelection::all();
    selection.set_enabled("aave", false);
    assert!(!selection.is_enabled("aave"));
    assert_eq!(selection.enabled_count(), COMPANION_SERVERS.len() - 1);
    assert_eq!(
        selection
            .disabled()
            .map(|server| server.slug)
            .collect::<Vec<_>>(),
        ["aave"]
    );
    selection.set_enabled("aave", true);
    assert_eq!(selection, CompanionSelection::all());
}

#[test]
fn everything_can_be_switched_off() {
    let mut selection = CompanionSelection::all();
    for server in COMPANION_SERVERS {
        selection.set_enabled(server.slug, false);
    }
    assert!(selection.is_empty());
    assert_eq!(selection.enabled().count(), 0);
}

/// The reason the stored shape is a deny-list. A selection saved before a
/// protocol existed must not arrive with that protocol switched off, because
/// the wallet's stated default is that every Ekubo-provided server is
/// included.
#[test]
fn a_server_the_stored_selection_never_heard_of_is_enabled() {
    let stored: CompanionSelection = serde_json::from_str(r#"{"disabled":["sky"]}"#).unwrap();
    assert!(!stored.is_enabled("sky"));
    for server in COMPANION_SERVERS {
        if server.slug != "sky" {
            assert!(stored.is_enabled(server.slug));
        }
    }
    // A slug this build has never heard of is enabled by the same rule.
    assert!(stored.is_enabled("a-protocol-from-a-later-release"));
}

/// An empty document is a valid selection, so a setting written by a build
/// that stored nothing else still reads as "everything on".
#[test]
fn an_empty_document_reads_as_every_server_enabled() {
    let stored: CompanionSelection = serde_json::from_str("{}").unwrap();
    assert_eq!(stored, CompanionSelection::all());
}

/// A slug the wallet no longer serves is kept in the stored document rather
/// than dropped, so a downgrade-then-upgrade does not re-enable it.
#[test]
fn an_unknown_disabled_slug_survives_a_round_trip() {
    let stored: CompanionSelection =
        serde_json::from_str(r#"{"disabled":["morpho","not-a-protocol"]}"#).unwrap();
    let round_tripped: CompanionSelection =
        serde_json::from_str(&serde_json::to_string(&stored).unwrap()).unwrap();
    assert_eq!(round_tripped, stored);
    assert!(!round_tripped.is_enabled("not-a-protocol"));
    assert_eq!(round_tripped.enabled_count(), COMPANION_SERVERS.len() - 1);
}

/// The counts are a shipped approximation of a partition that lives in
/// another repository, so the one thing this side can check is that they are
/// internally consistent: every tool the operator serves is on exactly one
/// endpoint, so the per-server counts must add up to the catalog.
#[test]
fn tool_counts_cover_the_catalog() {
    let summed: usize = COMPANION_SERVERS
        .iter()
        .map(|server| server.tool_count)
        .sum();
    assert_eq!(summed, TOTAL_TOOL_COUNT);
    assert_eq!(CompanionSelection::all().enabled_tool_count(), summed);
    for server in COMPANION_SERVERS {
        assert!(server.tool_count > 0, "{} serves no tools", server.title);
    }
    // Ekubo's own protocol carries most of the catalog, which is the fact
    // that makes the other six worth switching off individually.
    assert!(companion_by_slug("ekubo").unwrap().tool_count > summed / 2);
}

#[test]
fn a_narrowed_selection_costs_an_agent_fewer_tools() {
    let all = CompanionSelection::all();
    let mut ekubo_only = all.clone();
    for server in COMPANION_SERVERS {
        if server.slug != "ekubo" {
            ekubo_only.set_enabled(server.slug, false);
        }
    }
    assert_eq!(
        ekubo_only.enabled_tool_count(),
        companion_by_slug("ekubo").unwrap().tool_count
    );
    assert!(ekubo_only.enabled_tool_count() < all.enabled_tool_count());

    let mut nothing = ekubo_only.clone();
    nothing.set_enabled("ekubo", false);
    assert_eq!(nothing.enabled_tool_count(), 0);
}
