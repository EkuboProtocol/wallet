use super::*;

#[test]
fn incomplete_or_relative_profile_inventory_never_reaches_core_review() {
    assert!(selected_profiles("relative", "", true).is_err());
    let source = std::env::temp_dir().join("source-profile");
    let source = source.to_str().unwrap();
    assert!(selected_profiles(source, "", false).is_err());
    assert!(selected_profiles(source, "relative-preserved", true).is_err());
    assert!(selected_profiles(source, source, true).is_err());
    assert!(selected_profiles(source, "", true).is_ok());
}

#[test]
fn preserved_profiles_are_passed_exactly_without_silently_omitting_excess_entries() {
    let source = std::env::temp_dir().join("source-profile");
    let paths = (0..33)
        .map(|index| {
            std::env::temp_dir()
                .join(format!("preserved-{index}"))
                .display()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert!(selected_profiles(source.to_str().unwrap(), &paths.join("\n"), true).is_err());
    let (_, ProfileInventory::ReviewedComplete { preserve_profiles }) =
        selected_profiles(source.to_str().unwrap(), &paths[..2].join("\n"), true).unwrap()
    else {
        panic!("inventory was discarded")
    };
    assert_eq!(
        preserve_profiles,
        paths[..2].iter().map(PathBuf::from).collect::<Vec<_>>()
    );
}

#[test]
fn inventory_discloses_exact_accounts_paths_and_which_credentials_are_retained() {
    let retained = uuid::Uuid::new_v4();
    let deleted = uuid::Uuid::new_v4();
    let wallet = |id: uuid::Uuid, address: &str| -> ekubo_wallet_core::config::WalletMetadata {
        serde_json::from_value(serde_json::json!({
            "instance_id": id, "id": id.to_string(), "address": address,
            "created_at": "2026-09-12T00:00:00Z", "source": "created"
        }))
        .unwrap()
    };
    let source = std::env::temp_dir().join("legacy-source");
    let preserved = std::env::temp_dir().join("custom-preserved");
    let summary = MoveSummary {
        source: source.clone(),
        accounts: vec![
            wallet(retained, "0x1111111111111111111111111111111111111111"),
            wallet(deleted, "0x2222222222222222222222222222222222222222"),
        ],
        tables: vec![("application_settings".into(), 3)],
        retained_shared_accounts: vec![retained],
        preserved_profiles: vec![preserved.clone()],
    };
    let shown = inventory_text(&summary);
    for expected in [
        source.display().to_string(),
        preserved.display().to_string(),
        retained.to_string(),
        deleted.to_string(),
    ] {
        assert!(shown.contains(&expected));
    }
    assert!(shown.contains("0x1111111111111111111111111111111111111111"));
    assert!(shown.contains("0x2222222222222222222222222222222222222222"));
    assert!(shown.contains("Retain old credential: shared with a preserved profile"));
    assert!(shown.contains("Delete old account credential only after destination verification"));
    assert!(shown.contains("application_settings: 3 rows"));
}
