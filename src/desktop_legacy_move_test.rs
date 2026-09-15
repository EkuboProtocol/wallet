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

#[test]
fn recovery_is_offered_only_for_pending_receipts_with_absent_sources() {
    // The narrow bound-source marker offers recovery on a pending receipt.
    let missing_bound = anyhow::anyhow!(
        "legacy move source is missing at /owner/legacy; resume the exact source review or use the owner-authorized source-less recovery"
    );
    assert!(should_offer_recovery(true, &missing_bound));
    let missing_reported = anyhow::anyhow!(
        "legacy move source is missing; the 1.x profile cannot be read. Nothing was copied or deleted"
    );
    assert!(should_offer_recovery(true, &missing_reported));
    // A bare not-found — a mistyped preserved-profile path — never offers.
    let mistyped = anyhow::Error::from(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "canonicalize failed",
    ));
    assert!(!should_offer_recovery(true, &mistyped));
    let locked = anyhow::anyhow!("close the 1.x application before moving its profile");
    assert!(!should_offer_recovery(true, &locked));
    let wrong_inventory = anyhow::anyhow!(
        "cannot retire legacy credentials without an explicitly reviewed complete profile inventory"
    );
    assert!(!should_offer_recovery(true, &wrong_inventory));
    assert!(!should_offer_recovery(false, &missing_bound));
    assert!(!should_offer_recovery(false, &missing_reported));
    assert!(!should_offer_recovery(false, &mistyped));
}

#[test]
fn recovery_success_message_reports_retired_and_retained_credentials() {
    let report = ekubo_wallet_core::legacy_move::CleanupReport {
        deleted_account_credentials: vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()],
        already_absent: vec![uuid::Uuid::new_v4()],
        retained_shared_accounts: vec![uuid::Uuid::new_v4()],
        shared_database_credential_retained: false,
    };
    let shown = recovery_message(&report);
    assert!(shown.contains("Deleted 2 old account credential(s)"));
    assert!(shown.contains("1 already absent"));
    assert!(shown.contains("1 shared account credential(s) retained"));
    assert!(shown.contains("shared 1.x database credential is retained: false"));
    let retained = ekubo_wallet_core::legacy_move::CleanupReport {
        deleted_account_credentials: vec![],
        already_absent: vec![],
        retained_shared_accounts: vec![uuid::Uuid::new_v4()],
        shared_database_credential_retained: true,
    };
    assert!(
        recovery_message(&retained).contains("shared 1.x database credential is retained: true")
    );
}
