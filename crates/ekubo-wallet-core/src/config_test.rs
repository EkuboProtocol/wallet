//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn plaintext_configuration_is_never_an_input() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let plaintext = directory.path().join("config.json");
    std::fs::write(&plaintext, r#"{"version":2,"wallets":[],"networks":[]}"#).unwrap();

    let loaded = store.load().unwrap();
    assert_eq!(loaded.networks, default_networks());
    assert_eq!(
        std::fs::read_to_string(plaintext).unwrap(),
        r#"{"version":2,"wallets":[],"networks":[]}"#,
        "the unrelated plaintext file must also be left untouched"
    );
}

#[test]
fn configuration_is_encrypted_with_the_wallet_database_key() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    store.load().unwrap();

    let wrong_key = DatabaseKey::new([0x44; 32]);
    assert!(
        DesktopStore::open(&directory.path().join(DATABASE_FILE), &wrong_key).is_err(),
        "the configuration database opened with the wrong key"
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
fn disabled_networks_are_not_resolvable_for_wallet_activity() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let mut config = store.load().unwrap();
    let disabled = config
        .networks
        .iter()
        .find(|network| network.disabled)
        .unwrap()
        .clone();
    store.save(&config).unwrap();

    assert!(store.network(&disabled.name).is_err());
    assert!(
        store
            .network_by_chain_id(&disabled.chain_id.to_string())
            .is_err()
    );
    config
        .networks
        .iter_mut()
        .find(|network| network.chain_id == disabled.chain_id)
        .unwrap()
        .disabled = false;
    store.save(&config).unwrap();
    assert_eq!(
        store.network(&disabled.name).unwrap().chain_id,
        disabled.chain_id
    );
}

#[test]
fn network_mutations_require_network_scoped_owner_authorization() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let before = store.load().unwrap();
    let wrong_scope = OwnerAuthorization::for_test(OwnerAuthorizationScope::NotificationPrivacy);
    assert!(
        store
            .set_network_disabled("ethereum", true, &wrong_scope)
            .is_err()
    );
    assert_eq!(store.load().unwrap(), before);

    let authorized = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    assert!(
        store
            .set_network_disabled("ethereum", true, &authorized)
            .unwrap()
            .disabled
    );
}

#[test]
fn network_deletion_requires_an_owner_authorized_disable_first() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let authorized = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);

    assert!(store.remove_network("ethereum", &authorized).is_err());
    assert!(
        store
            .load()
            .unwrap()
            .networks
            .iter()
            .any(|network| network.name == "ethereum" && !network.disabled)
    );

    store
        .set_network_disabled("ethereum", true, &authorized)
        .unwrap();
    let removed = store.remove_network("ethereum", &authorized).unwrap();
    assert_eq!(removed.name, "ethereum");
    assert!(
        store
            .load()
            .unwrap()
            .networks
            .iter()
            .all(|network| network.name != "ethereum")
    );
}

#[test]
fn round_trips_private_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let config = store.load().unwrap();
    store.save(&config).unwrap();
    assert_eq!(store.load().unwrap(), config);
    assert!(directory.path().join(DATABASE_FILE).is_file());
    assert!(!directory.path().join("config.json").exists());
}

#[test]
fn desktop_replacement_takes_over_the_name_or_the_chain_id() {
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
fn desktop_replacement_still_rejects_an_identifier_taken_by_another_chain() {
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
    ] {
        assert_eq!(
            text.parse::<RpcStrategy>().unwrap(),
            expected,
            "parsing {text}"
        );
    }
    // Display round-trips, so what `network list` prints can be typed back in.
    for strategy in [RpcStrategy::Ordered, RpcStrategy::Random] {
        assert_eq!(
            strategy.to_string().parse::<RpcStrategy>().unwrap(),
            strategy
        );
    }
    assert!("majority".parse::<RpcStrategy>().is_err());
    assert!("m_of_n(2)".parse::<RpcStrategy>().is_err());
}

#[test]
fn the_default_strategy_is_optional_and_not_written() {
    use crate::config::RpcStrategy;
    let stored: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
        "name": "custom",
        "disabled": false,
        "chain_id": 1,
        "rpc_urls": ["https://custom.example.invalid/rpc"],
    }))
    .expect("a network may omit the default strategy");
    assert_eq!(stored.rpc_strategy, RpcStrategy::Ordered);
    let written = serde_json::to_value(&stored).unwrap();
    assert!(
        written.get("rpc_strategy").is_none(),
        "the default is not written back: {written}"
    );

    let mut random = stored.clone();
    random.rpc_strategy = RpcStrategy::Random;
    let written = serde_json::to_value(&random).unwrap();
    assert_eq!(written["rpc_strategy"], serde_json::json!("random"));
    assert_eq!(
        serde_json::from_value::<crate::config::NetworkConfig>(written).unwrap(),
        random
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
    // The MCP candidate and the desktop form both leave `max_fee_per_gas` as
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

/// The explorer base is never fetched by the wallet; it is handed to whatever
/// the desktop registered for `http`, as an argument to a process. On Windows
/// that launcher used to be `cmd /C start`, which reparses `&` and friends as
/// command syntax -- so an agent-proposed profile could run commands the first
/// time the owner pressed `o` on a transaction. The launcher is fixed, and
/// this narrows what can reach it.
#[test]
fn an_explorer_base_is_a_base_and_nothing_else() {
    let base = |url: &str| {
        let mut network = default_networks()[0].clone();
        network.block_explorer_url = Some(url.parse().unwrap());
        validate_network(&network)
    };

    assert!(base("https://etherscan.io").is_ok());
    assert!(base("https://etherscan.io/").is_ok());

    // A query is where an `&` legitimately lives, and a base with one produces
    // nonsense once `/tx/{hash}` is appended to it regardless.
    let error = format!("{:#}", base("https://etherscan.io/?a=1&calc").unwrap_err());
    assert!(error.contains("no query string or fragment"), "{error}");
    assert!(base("https://etherscan.io/#frag").is_err());

    // And the scheme rule still stands.
    assert!(base("ftp://etherscan.io").is_err());
}

mod record_network_tests {
    //! A chain id names a chain. It does not name a set of nodes.

    use super::*;

    fn store_with(name: &str, aliases: &[&str]) -> (tempfile::TempDir, ConfigStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(directory.path());
        store
            .update(|config| {
                let mut network = config.networks[0].clone();
                network.name = name.into();
                network.aliases = aliases.iter().map(|alias| (*alias).to_string()).collect();
                network.chain_id = 1;
                config.networks.retain(|other| other.chain_id != 1);
                config.networks.push(network);
                Ok(())
            })
            .unwrap();
        (directory, store)
    }

    /// `replace_configured_network` takes a chain over, so the endpoints behind
    /// a chain id can be swapped wholesale while every pending row keeps
    /// pointing at that id. `transaction discard` then asks the new endpoints
    /// whether they know the hash, and a node that never saw a transaction
    /// answers exactly like one where it does not exist -- so a viable
    /// envelope is untracked while it can still mine and consume its nonce.
    #[test]
    fn a_replaced_profile_cannot_decide_an_earlier_transactions_fate() {
        let (_directory, store) = store_with("private-fork", &[]);
        let error = format!(
            "{:#}",
            store
                .network_for_record("1", "ethereum")
                .expect_err("these are not the endpoints it was signed against")
        );
        assert!(
            error.contains("signed against network `ethereum`"),
            "{error}"
        );
        assert!(
            error.contains("cancel it on chain"),
            "the refusal has to say what can still be done: {error}"
        );
    }

    /// The profile it was signed against still answers for it.
    #[test]
    fn the_signing_profile_still_resolves() {
        let (_directory, store) = store_with("ethereum", &[]);
        let network = store.network_for_record("1", "ethereum").unwrap();
        assert_eq!(network.chain_id, 1);
    }

    /// And an alias is the same profile under another name, so renaming a
    /// network through a name it already carried is not a replacement. Without
    /// this the check would refuse ordinary configurations.
    #[test]
    fn an_alias_is_not_a_replacement() {
        let (_directory, store) = store_with("mainnet", &["ethereum"]);
        store
            .network_for_record("1", "ethereum")
            .expect("the same profile, under a name it already answered to");
    }
}
