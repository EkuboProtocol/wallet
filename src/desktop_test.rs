use super::*;

#[test]
fn command_palette_matches_route_labels_as_ordered_subsequences() {
    assert_eq!(fuzzy_route_score("WalletConnect", "wc"), Some(5));
    assert!(fuzzy_route_score("Networks", "net").is_some());
    assert!(fuzzy_route_score("Portfolio", "ptf").is_some());
    assert_eq!(fuzzy_route_score("Networks", "xyz"), None);
    assert_eq!(fuzzy_route_score("Tokens", "token"), Some(0));
    assert_eq!(fuzzy_route_score("WalletConnect", "token"), None);
}

#[test]
fn serial_review_queue_never_overwrites_and_preserves_arrival_order() {
    let mut queue = SerialQueue::default();

    assert_eq!(queue.receive(false, "first"), Some("first"));
    assert_eq!(queue.receive(true, "second"), None);
    assert_eq!(queue.receive(true, "third"), None);
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.next(true), None);
    assert_eq!(queue.next(false), Some("second"));
    assert_eq!(queue.next(false), Some("third"));
    assert!(queue.is_empty());
}

#[test]
fn portfolio_amounts_preserve_every_significant_digit() {
    assert_eq!(
        format_asset_balance("123450000", Some(6), Some("USDC"), "base units"),
        "123.45 USDC"
    );
    assert_eq!(
        format_asset_balance(
            "340282366920938463463374607431768211455",
            Some(18),
            Some("TKN"),
            "base units"
        ),
        "340282366920938463463.374607431768211455 TKN"
    );
    assert_eq!(
        format_asset_balance("7", None, Some("UNKNOWN"), "base units"),
        "7 base units"
    );
}

#[test]
fn tray_artwork_tracks_both_system_appearance_families() {
    assert!(!dark_appearance(WindowAppearance::Light));
    assert!(!dark_appearance(WindowAppearance::VibrantLight));
    assert!(dark_appearance(WindowAppearance::Dark));
    assert!(dark_appearance(WindowAppearance::VibrantDark));
}

#[test]
fn command_palette_reaches_every_desktop_route() {
    assert_eq!(Route::ALL.len(), 10);
    assert!(Route::ALL.contains(&Route::Settings));
    assert!(Route::ALL.contains(&Route::WalletConnect));
    assert_eq!(Route::Overview.label(), "Portfolio");
    assert_eq!(Route::ALL.last(), Some(&Route::Settings));
}

#[test]
fn route_shortcuts_preserve_standard_text_editing_bindings() {
    #[cfg(target_os = "macos")]
    let expected = [
        ("⌘1", "cmd-1"),
        ("⌘2", "cmd-2"),
        ("⌘3", "cmd-3"),
        ("⌘4", "cmd-4"),
        ("⌘5", "cmd-5"),
        ("⌘6", "cmd-6"),
        ("⌘7", "cmd-7"),
        ("⌘8", "cmd-8"),
        ("⌘9", "cmd-9"),
        ("⌘,", "cmd-,"),
    ];
    #[cfg(not(target_os = "macos"))]
    let expected = [
        ("Ctrl+1", "ctrl-1"),
        ("Ctrl+2", "ctrl-2"),
        ("Ctrl+3", "ctrl-3"),
        ("Ctrl+4", "ctrl-4"),
        ("Ctrl+5", "ctrl-5"),
        ("Ctrl+6", "ctrl-6"),
        ("Ctrl+7", "ctrl-7"),
        ("Ctrl+8", "ctrl-8"),
        ("Ctrl+9", "ctrl-9"),
        ("Ctrl+,", "ctrl-,"),
    ];

    let actual = Route::ALL.map(|route| (route.shortcut(), route.key_binding()));
    assert_eq!(actual, expected);
}

#[test]
fn token_search_matches_metadata_address_and_chain_id() {
    let token = StoredToken {
        chain_id: "1".into(),
        address: "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
        symbol: Some("USDC".into()),
        name: Some("USD Coin".into()),
        decimals: Some(6),
        source: "test".into(),
        added_at: chrono::Utc::now(),
    };

    assert!(token_matches_search(&token, "usd coin"));
    assert!(token_matches_search(&token, "usdc"));
    assert!(token_matches_search(&token, "a0B869"));
    assert!(token_matches_search(&token, "1"));
    assert!(!token_matches_search(&token, "10"));
    assert!(!token_matches_search(&token, "wrapped ether"));
}

#[test]
fn legal_markdown_is_split_without_changing_content_or_splitting_fences() {
    let long_paragraph = "x".repeat(LEGAL_SECTION_TARGET_BYTES);
    let source = format!(
        "# Terms\n\nIntro\n\n## Details\n\n```text\n# not a heading\n{long_paragraph}\n```\n\nTail\n"
    );
    let sections = legal_markdown_sections(&source);

    assert_eq!(
        sections
            .iter()
            .map(AsRef::<str>::as_ref)
            .collect::<String>(),
        source
    );
    assert_eq!(sections.len(), 3);
    assert!(sections[1].contains("# not a heading"));
}

#[test]
fn only_disabled_networks_offer_permanent_removal() {
    let mut network = ekubo_wallet_core::networks::default_networks()
        .into_iter()
        .find(|network| network.name == "ethereum")
        .unwrap();

    assert!(!network_can_be_removed(&network));
    network.disabled = true;
    assert!(network_can_be_removed(&network));
}

#[test]
fn networks_display_enabled_first_then_by_numeric_chain_id() {
    let mut networks = ekubo_wallet_core::networks::default_networks();
    for network in &mut networks {
        network.disabled = network.chain_id != 42_161;
    }
    networks.reverse();

    let sorted = networks_for_display(&networks);
    assert_eq!(sorted[0].chain_id, 42_161);
    assert!(!sorted[0].disabled);
    assert!(sorted[1..].iter().all(|network| network.disabled));
    assert!(
        sorted[1..]
            .windows(2)
            .all(|pair| pair[0].chain_id <= pair[1].chain_id)
    );
}

#[test]
fn token_removal_confirmation_is_bound_to_the_exact_row() {
    let first = (1, alloy::primitives::Address::repeat_byte(0x11));
    let second = (1, alloy::primitives::Address::repeat_byte(0x22));

    assert!(token_removal_is_confirmed(Some(first), first));
    assert!(!token_removal_is_confirmed(Some(first), second));
    assert!(!token_removal_is_confirmed(None, first));
}

#[test]
fn token_inventory_reads_every_page_instead_of_stopping_at_ten_thousand() {
    let token = StoredToken {
        chain_id: "1".into(),
        address: "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
        symbol: Some("USDC".into()),
        name: Some("USD Coin".into()),
        decimals: Some(6),
        source: "test".into(),
        added_at: chrono::Utc::now(),
    };
    let source = vec![token; 17_286];
    let mut offsets = Vec::new();
    let loaded = collect_token_inventory(|limit, offset| {
        offsets.push(offset);
        Ok(source.iter().skip(offset).take(limit).cloned().collect())
    })
    .unwrap();

    assert_eq!(loaded.len(), 17_286);
    assert_eq!(offsets, [0, 10_000]);
}

#[test]
fn token_list_import_field_rejects_unsafe_urls_before_fetching() {
    assert_eq!(
        token_list_url_draft("  https://tokens.example.org/list.json  ").unwrap(),
        "https://tokens.example.org/list.json"
    );
    for invalid in [
        "",
        "http://tokens.example.org/list.json",
        "https://owner:secret@tokens.example.org/list.json",
        "https://tokens.example.org:8443/list.json",
        "https://tokens.example.org/list.json#other",
    ] {
        assert!(token_list_url_draft(invalid).is_err(), "accepted {invalid}");
    }
}

#[test]
fn legal_gate_requires_both_current_owner_documents_in_order() {
    use ekubo_wallet_core::legal::DocumentStatus;

    let document = |accepted| DocumentStatus {
        accepted,
        current_digest: "digest".into(),
        accepted_at: None,
        superseded_digest: None,
    };
    let mut status = LegalStatus {
        signing_allowed: false,
        terms_of_service: document(false),
        privacy_policy: document(false),
    };
    assert_eq!(
        next_required_legal(&status),
        Some(LegalDocument::TermsOfService)
    );
    status.terms_of_service.accepted = true;
    assert_eq!(
        next_required_legal(&status),
        Some(LegalDocument::PrivacyPolicy)
    );
    status.privacy_policy.accepted = true;
    assert_eq!(next_required_legal(&status), None);
}

#[test]
fn third_party_licenses_are_informational_not_acceptance_gated() {
    assert!(legal_requires_acceptance(LegalDocument::TermsOfService));
    assert!(legal_requires_acceptance(LegalDocument::PrivacyPolicy));
    assert!(!legal_requires_acceptance(
        LegalDocument::ThirdPartyLicenses
    ));
}

#[test]
fn accepted_legal_documents_reopen_read_only() {
    use ekubo_wallet_core::legal::DocumentStatus;

    let accepted = DocumentStatus {
        accepted: true,
        current_digest: "digest".into(),
        accepted_at: Some(chrono::Utc::now()),
        superseded_digest: None,
    };
    let status = LegalStatus {
        signing_allowed: true,
        terms_of_service: accepted.clone(),
        privacy_policy: accepted,
    };
    assert!(!legal_review_requires_acceptance(
        LegalDocument::TermsOfService,
        &status
    ));
    assert!(!legal_review_requires_acceptance(
        LegalDocument::PrivacyPolicy,
        &status
    ));
}

#[test]
fn legal_acceptance_shows_when_the_current_document_was_accepted() {
    let accepted_at = chrono::DateTime::parse_from_rfc3339("2026-08-11T14:30:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let status = ekubo_wallet_core::legal::DocumentStatus {
        accepted: true,
        current_digest: "digest".into(),
        accepted_at: Some(accepted_at),
        superseded_digest: None,
    };
    assert_eq!(
        legal_acceptance_label(&status),
        "Accepted 2026-08-11 14:30 UTC"
    );
}

#[test]
fn document_actions_unlock_only_at_the_end_of_the_scroll_range() {
    assert!(!scroll_reached_end(px(-98.0), px(100.0)));
    assert!(scroll_reached_end(px(-99.0), px(100.0)));
    assert!(scroll_reached_end(px(0.0), px(0.0)));
}

#[test]
fn activity_exposes_only_lifecycle_safe_owner_actions() {
    assert_eq!(
        transaction_actions(PendingStatus::Signed),
        TransactionActions {
            refresh: false,
            send: true,
            cancel: false,
            discard: true,
        }
    );
    assert_eq!(
        transaction_actions(PendingStatus::Broadcast),
        TransactionActions {
            refresh: true,
            send: true,
            cancel: true,
            discard: false,
        }
    );
    assert_eq!(
        transaction_actions(PendingStatus::Cancelling),
        TransactionActions {
            refresh: true,
            send: false,
            cancel: true,
            discard: false,
        }
    );
    assert_eq!(
        transaction_actions(PendingStatus::Confirmed),
        TransactionActions {
            refresh: false,
            send: false,
            cancel: false,
            discard: false,
        }
    );
}

#[test]
fn policy_draft_validation_canonicalizes_and_previews_permission_changes() {
    let current = WalletPolicy::require_approval_for_everything();
    let proposed = WalletPolicy::allow_all_with_approval();
    let compact = serde_json::to_string(&proposed).unwrap();
    let reviewed = review_policy_draft("primary", Some(7), Some(&current), &compact).unwrap();

    assert_eq!(reviewed.wallet_id, "primary");
    assert_eq!(reviewed.source_revision, Some(7));
    assert_eq!(reviewed.policy, proposed);
    assert!(reviewed.document.contains('\n'));
    assert!(reviewed.diff.iter().any(|line| line.starts_with('+')));
}

#[test]
fn policy_draft_validation_rejects_non_policy_json() {
    let error = review_policy_draft(
        "primary",
        Some(1),
        Some(&WalletPolicy::require_approval_for_everything()),
        r#"{"version":1,"chains":{},"unexpected":true}"#,
    )
    .unwrap_err();

    assert!(format!("{error:#}").contains("unknown field"));
}
