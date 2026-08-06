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
    ethereum.rpc_url = "https://rpc.example.invalid".parse().unwrap();
    replace_configured_network(&mut networks, ethereum.clone()).unwrap();
    assert_eq!(
        networks
            .iter()
            .find(|network| network.name == "ethereum")
            .unwrap()
            .rpc_url,
        ethereum.rpc_url
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
        candidate.rpc_url = endpoint.parse().unwrap();
        assert!(
            validate_network(&candidate).is_ok(),
            "owner configuration rejected {endpoint}"
        );
    }

    // The scheme is still the one thing an RPC URL must get right.
    let mut candidate = default_networks().remove(0);
    candidate.rpc_url = "file:///etc/passwd".parse().unwrap();
    assert!(validate_network(&candidate).is_err());
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
