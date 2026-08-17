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
fn installing_a_network_proposal_updates_config_and_consumes_one_exact_row() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    store.load().unwrap();
    let mut proposal = default_networks()
        .into_iter()
        .find(|network| network.chain_id == 1)
        .unwrap();
    proposal.name = "reviewed-ethereum".into();
    proposal.aliases.clear();
    store
        .policy_store()
        .unwrap()
        .put_network_proposal(&proposal)
        .unwrap();

    let authorization = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    store
        .install_network_proposal(&proposal, &authorization)
        .unwrap();

    assert_eq!(
        store.network_by_chain_id("1").unwrap().name,
        "reviewed-ethereum"
    );
    assert!(
        store
            .policy_store()
            .unwrap()
            .network_proposal(1)
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_replaced_network_proposal_cannot_install_the_reviewed_predecessor() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let original = store.network_by_chain_id("1").unwrap();
    let mut reviewed = original.clone();
    reviewed.name = "reviewed-ethereum".into();
    reviewed.aliases.clear();
    let mut replacement = reviewed.clone();
    replacement.name = "replacement-ethereum".into();
    store
        .policy_store()
        .unwrap()
        .put_network_proposal(&reviewed)
        .unwrap();
    store
        .policy_store()
        .unwrap()
        .put_network_proposal(&replacement)
        .unwrap();

    let authorization = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    assert!(
        store
            .install_network_proposal(&reviewed, &authorization)
            .is_err()
    );
    assert_eq!(store.network_by_chain_id("1").unwrap(), original);
    assert_eq!(
        store.policy_store().unwrap().network_proposal(1).unwrap(),
        Some(replacement)
    );
}

#[test]
fn default_networks_have_unique_chain_ids_and_identifiers() {
    validate_config(&WalletConfig {
        version: 3,
        wallets: vec![],
        networks: default_networks(),
    })
    .unwrap();
}

#[test]
fn known_chain_classification_cannot_be_spoofed_by_any_network_mutator() {
    let ethereum = default_networks()
        .into_iter()
        .find(|network| network.chain_id == 1)
        .unwrap();
    let mut mislabeled = ethereum.clone();
    mislabeled.testnet = true;

    let add_error = add_configured_network(&mut Vec::new(), mislabeled.clone()).unwrap_err();
    assert!(add_error.to_string().contains("classified as a mainnet"));

    let mut configured = vec![ethereum];
    let replace_error = replace_configured_network(&mut configured, mislabeled).unwrap_err();
    assert!(
        replace_error
            .to_string()
            .contains("classified as a mainnet")
    );
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
fn disabling_a_network_is_free_but_reenabling_requires_network_authorization() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let before = store.load().unwrap();
    let ethereum = before
        .networks
        .iter()
        .find(|network| network.name == "ethereum")
        .unwrap()
        .clone();
    let wrong_scope = OwnerAuthorization::for_test(OwnerAuthorizationScope::NotificationPrivacy);
    let disabled = store.set_network_disabled(&ethereum, true, None).unwrap();
    assert!(disabled.disabled);
    assert!(
        store
            .set_network_disabled(&disabled, false, Some(&wrong_scope))
            .is_err()
    );

    let authorized = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    assert!(
        !store
            .set_network_disabled(&disabled, false, Some(&authorized))
            .unwrap()
            .disabled
    );
}

#[test]
fn network_toggle_refuses_a_stale_reviewed_row() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let authorization = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    let reviewed = store
        .load()
        .unwrap()
        .networks
        .into_iter()
        .find(|network| network.name == "ethereum")
        .unwrap();
    let mut edited = reviewed.clone();
    edited.display_name = Some("Owner Ethereum".to_owned());
    store
        .replace_network(&reviewed, edited.clone(), &authorization)
        .unwrap();

    assert!(
        store
            .set_network_disabled(&reviewed, true, None)
            .unwrap_err()
            .to_string()
            .contains("changed while the enable setting was being authenticated")
    );
    assert_eq!(
        store
            .load()
            .unwrap()
            .networks
            .into_iter()
            .find(|network| network.chain_id == edited.chain_id),
        Some(edited.clone())
    );
}

#[test]
fn network_create_never_overwrites_an_existing_chain() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let authorized = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    let before = store.load().unwrap();
    let mut conflicting = before.networks[0].clone();
    conflicting.name = "not-ethereum".into();
    conflicting.display_name = Some("Not Ethereum".into());

    assert!(store.add_network(conflicting, &authorized).is_err());
    assert_eq!(store.load().unwrap(), before);
}

#[test]
fn network_update_replaces_only_the_exact_row_the_owner_opened() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let authorized = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    let reviewed = store.load().unwrap().networks[0].clone();
    let mut replacement = reviewed.clone();
    replacement.name = "ethereum-owner".into();
    replacement.display_name = Some("Owner Ethereum".into());
    replacement.chain_id = 9_999_991;
    replacement.aliases.clear();
    replacement.rpc_urls = vec!["https://owner-rpc.example".parse().unwrap()];

    store
        .replace_network(&reviewed, replacement.clone(), &authorized)
        .unwrap();
    let networks = store.load().unwrap().networks;
    assert!(!networks.iter().any(|network| network == &reviewed));
    assert!(networks.iter().any(|network| network == &replacement));
}

#[test]
fn stale_network_update_cannot_overwrite_newer_rpc_settings() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let authorized = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    let reviewed = store.load().unwrap().networks[0].clone();
    let mut newer = reviewed.clone();
    newer.rpc_urls = vec!["https://newer-owner-rpc.example".parse().unwrap()];
    store.install_network(newer.clone(), &authorized).unwrap();

    let mut stale_edit = reviewed.clone();
    stale_edit.display_name = Some("Stale editor".into());
    assert!(
        store
            .replace_network(&reviewed, stale_edit, &authorized)
            .is_err()
    );
    assert!(
        store
            .load()
            .unwrap()
            .networks
            .iter()
            .any(|network| network == &newer)
    );
}

#[test]
fn network_reset_requires_authorization_and_the_exact_reviewed_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let reviewed = store.load().unwrap().networks;
    let wrong_scope = OwnerAuthorization::for_test(OwnerAuthorizationScope::TokenMetadata);

    assert!(
        store
            .reset_networks_to_defaults(&reviewed, &wrong_scope)
            .is_err()
    );
    assert_eq!(store.load().unwrap().networks, reviewed);

    store
        .update_for_test(|config| {
            config.networks[0].display_name = Some("Owner-edited name".into());
            Ok(())
        })
        .unwrap();
    let authorized = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    assert!(
        store
            .reset_networks_to_defaults(&reviewed, &authorized)
            .is_err()
    );
    assert_eq!(
        store.load().unwrap().networks[0].display_name.as_deref(),
        Some("Owner-edited name")
    );

    let current = store.load().unwrap().networks;
    assert_eq!(
        store
            .reset_networks_to_defaults(&current, &authorized)
            .unwrap(),
        default_networks()
    );
    assert_eq!(store.load().unwrap().networks, default_networks());
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
        "testnet": false,
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
fn a_replacement_carries_nothing_the_owner_did_not_review() {
    // A network profile used to carry the owner's fee and gas ceilings, so
    // whole-profile replacement silently deleted a bound a routine endpoint
    // edit never meant to touch, and this function had to carry it forward by
    // hand. Those ceilings are policy rules now, in a store this never writes:
    // what the owner reviewed is exactly what replaces the profile.
    let mut networks = default_networks();
    let chain_id = networks[0].chain_id;

    let mut edited = networks[0].clone();
    edited.rpc_urls = vec!["https://elsewhere.example.invalid/rpc".parse().unwrap()];
    replace_configured_network(&mut networks, edited.clone()).unwrap();

    let stored = networks
        .iter()
        .find(|network| network.chain_id == chain_id)
        .unwrap();
    assert_eq!(
        stored.rpc_urls[0].as_str(),
        "https://elsewhere.example.invalid/rpc",
        "the edit the owner reviewed still applies"
    );
    assert_eq!(stored, &edited, "and nothing else about the profile moved");
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

#[test]
fn a_network_reads_by_its_display_name_never_its_internal_handle_or_an_alias() {
    // `name` is what an agent types and `aliases` are what a person
    // abbreviates to in conversation. Neither is what the network is called.
    let mut network = default_networks().remove(0);
    network.name = "robinhood".into();
    network.aliases = vec!["rh".into(), "robinhood-mainnet".into()];
    network.display_name = Some("Robinhood Chain".into());

    assert_eq!(network.display_label(), "Robinhood Chain");

    // With nothing configured the internal handle is all there is, and that
    // is still better than showing an alias.
    network.display_name = None;
    assert_eq!(network.display_label(), "robinhood");
}
