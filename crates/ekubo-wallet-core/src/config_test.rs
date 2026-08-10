//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
#[cfg(unix)]
fn a_widely_readable_configuration_is_narrowed_when_it_is_read() {
    // The file holds RPC URLs, which can carry provider credentials. A
    // restore or an older build can leave it 0644; nothing would have
    // fixed that until the next write.
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    store
        .update(|state| {
            state.networks = default_networks();
            Ok(())
        })
        .unwrap();
    std::fs::set_permissions(store.file(), std::fs::Permissions::from_mode(0o644)).unwrap();

    store.load().unwrap();

    let mode = std::fs::metadata(store.file())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "config stayed readable: {mode:o}");
}

#[test]
#[cfg(unix)]
fn an_unreadable_configuration_is_an_error_not_an_empty_one() {
    // The dangerous confusion is between "there is nothing here" and "I
    // could not look". The first starts a fresh wallet; the second, if it
    // reads as the first, gets the real file overwritten by the defaults
    // on the next save.
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    store
        .save(&WalletConfig {
            version: 2,
            wallets: Vec::new(),
            networks: default_networks(),
        })
        .unwrap();
    std::fs::set_permissions(store.file(), std::fs::Permissions::from_mode(0o000)).unwrap();

    let result = store.load();
    // Running as root defeats the permission bit, so only assert when the
    // file is genuinely unreadable.
    if std::fs::read(store.file()).is_err() {
        assert!(result.is_err(), "an unreadable configuration loaded as one");
    }
    std::fs::set_permissions(store.file(), std::fs::Permissions::from_mode(0o600)).unwrap();

    // A directory with no configuration in it still starts fresh.
    let empty = tempfile::tempdir().unwrap();
    assert!(
        ConfigStore::new(empty.path())
            .load()
            .unwrap()
            .wallets
            .is_empty()
    );
}

#[test]
fn default_networks_have_unique_chain_ids_and_identifiers() {
    validate_config(&WalletConfig {
        version: 2,
        wallets: vec![],
        networks: default_networks(),
    })
    .unwrap();
}

#[test]
fn round_trips_private_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let config = store.load().unwrap();
    store.save(&config).unwrap();
    assert_eq!(store.load().unwrap(), config);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(store.file()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

/// A configuration as 0.1.0 through 0.3.0-rc.0 wrote it: one wallet
/// carrying the retired `custody` enum.
fn legacy_store(custody: &str, exported_at: Option<&str>) -> (tempfile::TempDir, ConfigStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let mut config = store.load().unwrap();
    config.wallets.push(WalletMetadata {
        id: "primary".into(),
        address: Address::ZERO,
        created_at: "2026-01-01T00:00:00Z".parse().unwrap(),
        source: WalletSource::Created,
        exported_at: None,
    });
    store.save(&config).unwrap();

    let mut document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(store.file()).unwrap()).unwrap();
    let wallet = &mut document["wallets"][0];
    wallet["custody"] = custody.into();
    if let Some(exported_at) = exported_at {
        wallet["exported_at"] = exported_at.into();
    }
    fs::write(store.file(), serde_json::to_string(&document).unwrap()).unwrap();
    (directory, store)
}

#[test]
fn legacy_sealed_custody_loads_as_no_recorded_export() {
    let (_directory, store) = legacy_store("sealed", None);
    let wallet = store.load().unwrap().wallets.remove(0);
    assert_eq!(wallet.source, WalletSource::Created);
    assert!(wallet.exported_at.is_none());
}

#[test]
fn legacy_externally_known_custody_survives_as_its_import_source() {
    let (_directory, store) = legacy_store("externally_known", None);
    assert!(store.load().unwrap().wallets[0].exported_at.is_none());
}

#[test]
fn legacy_export_keeps_its_timestamp_and_is_rewritten_without_the_enum() {
    let (_directory, store) = legacy_store("exported", Some("2026-02-02T03:04:05Z"));
    let config = store.load().unwrap();
    assert_eq!(
        config.wallets[0].exported_at,
        Some("2026-02-02T03:04:05Z".parse().unwrap())
    );

    store.save(&config).unwrap();
    let document = fs::read_to_string(store.file()).unwrap();
    assert!(!document.contains("custody"));
    assert!(document.contains("exported_at"));
    assert_eq!(store.load().unwrap(), config);
}

/// Only a hand-edited file can disagree with itself, and resolving it in
/// favour of either field would either invent or forget an export.
#[test]
fn contradictory_legacy_custody_fails_closed() {
    let (_exported_without_timestamp, store) = legacy_store("exported", None);
    assert!(store.load().is_err());

    let (_sealed_with_timestamp, store) = legacy_store("sealed", Some("2026-02-02T03:04:05Z"));
    assert!(store.load().is_err());
}

#[test]
fn cli_replacement_takes_over_the_name_or_the_chain_id() {
    let mut networks = default_networks();
    let count = networks.len();
    let mut ethereum = networks
        .iter()
        .find(|network| network.name == "ethereum")
        .unwrap()
        .clone();
    ethereum.rpc_urls = vec!["https://rpc.example.invalid".parse().unwrap()];
    replace_configured_network(&mut networks, ethereum.clone()).unwrap();
    assert_eq!(
        networks
            .iter()
            .find(|network| network.name == "ethereum")
            .unwrap()
            .rpc_urls,
        ethereum.rpc_urls
    );

    // Chain 1 under a new name takes chain 1 over rather than failing:
    // the configuration holds one profile per chain ID either way.
    let mut renamed = ethereum;
    renamed.name = "custom".into();
    replace_configured_network(&mut networks, renamed).unwrap();
    assert_eq!(networks.len(), count, "chain 1 was replaced, not added");
    assert!(networks.iter().all(|network| network.name != "ethereum"));
    assert_eq!(
        remove_configured_network(&mut networks, "eth")
            .unwrap()
            .name,
        "custom",
        "the aliases came along with the chain"
    );
}

#[test]
fn a_replacement_never_evicts_a_chain_by_reusing_its_name() {
    // The reviewer is shown the candidate and the profile it replaces on
    // its own chain. A configured chain that merely shares the candidate's
    // name is on neither screen, so removing it would be a deletion nobody
    // saw. Refusing is the only answer that cannot surprise.
    let mut networks = default_networks();
    let mut candidate = networks
        .iter()
        .find(|network| network.name == "base")
        .unwrap()
        .clone();
    candidate.name = "ethereum".into();
    candidate.aliases = vec!["unclaimed".into()];
    candidate.chain_id = 999_999;
    assert!(replace_configured_network(&mut networks, candidate).is_err());
    assert!(networks.iter().any(|network| network.chain_id == 1));
}

#[test]
fn cli_replacement_still_rejects_an_identifier_taken_by_another_chain() {
    let mut networks = default_networks();
    let mut candidate = networks
        .iter()
        .find(|network| network.name == "base")
        .unwrap()
        .clone();
    candidate.name = "unclaimed".into();
    candidate.chain_id = 999_999;
    candidate.aliases = vec!["eth".into()];
    assert!(replace_configured_network(&mut networks, candidate).is_err());
}

#[test]
fn owner_configuration_admits_a_loopback_node() {
    // Running your own node is the one configuration with no RPC trust
    // assumption left in it, so a local endpoint an owner types must stay
    // configurable. `http` and loopback are admitted here on purpose: the
    // owner is naming a machine they already control. The stricter rules an
    // agent's proposal meets live in `plan_fetch::ensure_public_endpoint`,
    // and the two paths are deliberately not the same one.
    for endpoint in [
        "http://127.0.0.1:8545",
        "http://localhost:8545",
        "http://[::1]:8545",
    ] {
        let mut candidate = default_networks().remove(0);
        candidate.rpc_urls = vec![endpoint.parse().unwrap()];
        assert!(
            validate_network(&candidate).is_ok(),
            "owner configuration rejected {endpoint}"
        );
    }

    // The scheme is still the one thing an RPC URL must get right.
    let mut candidate = default_networks().remove(0);
    candidate.rpc_urls = vec!["file:///etc/passwd".parse().unwrap()];
    assert!(validate_network(&candidate).is_err());
}

#[test]
fn an_rpc_url_may_not_carry_a_credential_the_wallet_would_repeat() {
    // A host and an empty path, so nothing but the userinfo distinguishes it
    // from an ordinary endpoint — and the wallet quotes endpoints back to the
    // agent and onto the screen verbatim.
    for endpoint in [
        "https://apikey:secret@rpc.example.com/",
        "https://apikey@rpc.example.com/",
    ] {
        let mut candidate = default_networks().remove(0);
        candidate.rpc_urls = vec![endpoint.parse().unwrap()];
        let error = validate_network(&candidate)
            .expect_err(endpoint)
            .to_string();
        // The refusal must not publish what it is refusing.
        assert!(!error.contains("secret"), "{error}");
        assert!(!error.contains("apikey"), "{error}");
        assert!(error.contains("username or password"), "{error}");
    }

    // A key in the path is not this check's business: it is indistinguishable
    // from a path, and the owner naming one has decided to use it.
    let mut candidate = default_networks().remove(0);
    candidate.rpc_urls = vec!["https://rpc.example.com/v2/somekey".parse().unwrap()];
    assert!(validate_network(&candidate).is_ok());
}

#[test]
fn network_identifiers_cannot_inject_terminal_or_completion_controls() {
    let mut candidate = default_networks().remove(0);
    candidate.aliases.push("bad\nvalue".into());
    assert!(validate_network(&candidate).is_err());
}

#[test]
fn network_display_fields_reject_invisible_and_bidirectional_characters() {
    // `char::is_control` is false for every one of these, so the old
    // predicate admitted them — into picker labels and, for the symbol,
    // onto the line of the approval screen that names an amount.
    for injected in ["\u{202e}", "\u{200b}", "\u{feff}", "\u{2066}"] {
        let mut candidate = default_networks().remove(0);
        candidate.display_name = Some(format!("Ethereum{injected}"));
        assert!(
            validate_network(&candidate).is_err(),
            "display name accepted {injected:?}"
        );

        let mut candidate = default_networks().remove(0);
        if let Some(currency) = candidate.native_currency.as_mut() {
            currency.symbol = format!("ETH{injected}");
        }
        assert!(
            validate_network(&candidate).is_err(),
            "currency symbol accepted {injected:?}"
        );
    }

    // Ordinary non-ASCII display text is still fine.
    let mut candidate = default_networks().remove(0);
    candidate.display_name = Some("Éthereum メインネット".into());
    assert!(validate_network(&candidate).is_ok());
}

#[test]
fn rpc_strategies_round_trip_through_the_spellings_people_type() {
    use crate::config::RpcStrategy;
    for (text, expected) in [
        ("ordered", RpcStrategy::Ordered),
        ("Random", RpcStrategy::Random),
        ("m_of_n(2)", RpcStrategy::MOfN { agree: 2 }),
        // A shell eats parentheses, so the other spellings are accepted too.
        ("m_of_n:3", RpcStrategy::MOfN { agree: 3 }),
        ("m-of-n 2", RpcStrategy::MOfN { agree: 2 }),
        ("M_OF_N(4)", RpcStrategy::MOfN { agree: 4 }),
    ] {
        assert_eq!(
            text.parse::<RpcStrategy>().unwrap(),
            expected,
            "parsing {text}"
        );
    }
    // Display round-trips, so what `network list` prints can be typed back in.
    for strategy in [
        RpcStrategy::Ordered,
        RpcStrategy::Random,
        RpcStrategy::MOfN { agree: 2 },
    ] {
        assert_eq!(
            strategy.to_string().parse::<RpcStrategy>().unwrap(),
            strategy
        );
    }
    assert!("majority".parse::<RpcStrategy>().is_err());
    assert!("m_of_n".parse::<RpcStrategy>().is_err());
    assert!("m_of_n(two)".parse::<RpcStrategy>().is_err());
}

/// A threshold the network cannot reach would refuse every request on it, so
/// it is refused where the number is typed rather than at signing time.
#[test]
fn an_unreachable_agreement_threshold_is_refused() {
    use crate::config::RpcStrategy;
    let mut network = default_networks().remove(0);
    network.rpc_urls.truncate(2);

    network.rpc_strategy = RpcStrategy::MOfN { agree: 3 };
    let error = crate::config::validate_network(&network)
        .unwrap_err()
        .to_string();
    assert!(error.contains("needs 3 endpoints but"), "{error}");

    network.rpc_strategy = RpcStrategy::MOfN { agree: 1 };
    let error = crate::config::validate_network(&network)
        .unwrap_err()
        .to_string();
    assert!(error.contains("at least 2"), "{error}");

    network.rpc_strategy = RpcStrategy::MOfN { agree: 2 };
    crate::config::validate_network(&network).expect("two of two is reachable");
}

/// The setting is absent from a configuration written before it existed, and
/// is left out again when it holds the default, so upgrading and downgrading
/// do not rewrite every network.
#[test]
fn the_default_strategy_is_neither_required_nor_written() {
    use crate::config::RpcStrategy;
    let stored: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
        "name": "legacy",
        "chain_id": 1,
        "rpc_url": "https://legacy.example.invalid/rpc",
    }))
    .expect("a pre-strategy network still loads");
    assert_eq!(stored.rpc_strategy, RpcStrategy::Ordered);
    let written = serde_json::to_value(&stored).unwrap();
    assert!(
        written.get("rpc_strategy").is_none(),
        "the default is not written back: {written}"
    );

    let mut agreeing = stored.clone();
    agreeing.rpc_strategy = RpcStrategy::MOfN { agree: 2 };
    let written = serde_json::to_value(&agreeing).unwrap();
    assert_eq!(
        written["rpc_strategy"],
        serde_json::json!({"m_of_n": {"agree": 2}})
    );
    assert_eq!(
        serde_json::from_value::<crate::config::NetworkConfig>(written).unwrap(),
        agreeing
    );
}

#[test]
#[cfg(unix)]
fn a_symlinked_data_directory_is_refused_rather_than_hardened() {
    // `exists` and `metadata` both resolve the name, so a link planted at the
    // data directory answered for its target and the 0700 was applied there.
    // The wallet cannot promise privacy for a directory whose identity another
    // process picks, so it declines to try.
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("elsewhere");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o777)).unwrap();
    let link = directory.path().join("data");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let error = format!("{:#}", create_private_dir(&link).unwrap_err());
    assert!(error.contains("symbolic link"), "{error}");
    assert_eq!(
        std::fs::metadata(&real).unwrap().permissions().mode() & 0o777,
        0o777,
        "the link's target is left exactly as it was, not silently re-moded"
    );
}

#[test]
#[cfg(unix)]
fn a_private_file_is_opened_through_the_name_it_was_given() {
    // The by-path chmod this replaced could be pointed at any file the owner
    // could reach by swapping a link in after the open. O_NOFOLLOW makes the
    // swap an error instead of a redirection.
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    std::fs::write(&target, b"secret").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = directory.path().join("database");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    assert!(
        open_private_file(&link).is_err(),
        "a link standing in for the file is refused"
    );
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644,
        "and its target keeps the mode it had"
    );

    let plain = directory.path().join("plain");
    std::fs::write(&plain, b"secret").unwrap();
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
    let file = open_private_file(&plain).unwrap();
    assert_eq!(
        file.metadata().unwrap().permissions().mode() & 0o777,
        0o600,
        "a real file is narrowed through the handle that names it"
    );
}

#[test]
fn a_replacement_does_not_quietly_drop_the_owners_fee_ceiling() {
    // The MCP candidate and the CLI form both leave `max_fee_per_gas` as
    // `None`, each with a comment saying an agent does not get to choose the
    // owner's fee ceiling. Whole-profile replacement turned both into the
    // opposite: a routine endpoint edit deleted the ceiling, and an absent
    // ceiling is unbounded -- `capped_fee` returns an endpoint's estimate
    // unchanged when there is nothing to check it against, on the one path
    // where nobody reviews the fee.
    let mut networks = default_networks();
    let chain_id = networks[0].chain_id;
    networks[0].max_fee_per_gas = Some("1000000000".into());

    let mut edited = networks[0].clone();
    edited.rpc_urls = vec!["https://elsewhere.example.invalid/rpc".parse().unwrap()];
    edited.max_fee_per_gas = None;
    replace_configured_network(&mut networks, edited).unwrap();

    let stored = networks
        .iter()
        .find(|network| network.chain_id == chain_id)
        .unwrap();
    assert_eq!(
        stored.rpc_urls[0].as_str(),
        "https://elsewhere.example.invalid/rpc",
        "the edit the owner reviewed still applies"
    );
    assert_eq!(
        stored.max_fee_per_gas.as_deref(),
        Some("1000000000"),
        "and the ceiling they never agreed to remove survives it"
    );
}

#[test]
fn a_replacement_that_names_a_ceiling_sets_it() {
    // `None` means "not specified" everywhere it is constructed today, so
    // inheriting is right -- but a profile that does name a ceiling is stating
    // one, and must not be overridden by the value it replaces.
    let mut networks = default_networks();
    let chain_id = networks[0].chain_id;
    networks[0].max_fee_per_gas = Some("1000000000".into());

    let mut raised = networks[0].clone();
    raised.max_fee_per_gas = Some("2000000000".into());
    replace_configured_network(&mut networks, raised).unwrap();

    assert_eq!(
        networks
            .iter()
            .find(|network| network.chain_id == chain_id)
            .unwrap()
            .max_fee_per_gas
            .as_deref(),
        Some("2000000000")
    );

    // And a chain with no ceiling before still has none after.
    let mut fresh = default_networks();
    let mut edited = fresh[0].clone();
    edited.max_fee_per_gas = None;
    fresh[0].max_fee_per_gas = None;
    replace_configured_network(&mut fresh, edited).unwrap();
    assert!(fresh[0].max_fee_per_gas.is_none());
}
