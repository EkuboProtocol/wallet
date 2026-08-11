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
}

#[test]
fn token_filter_combines_network_and_case_insensitive_search() {
    let token = StoredToken {
        chain_id: "1".into(),
        address: "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".into(),
        symbol: Some("USDC".into()),
        name: Some("USD Coin".into()),
        decimals: Some(6),
        source: "test".into(),
        added_at: chrono::Utc::now(),
    };

    assert!(token_matches_filter(&token, None, "usd coin"));
    assert!(token_matches_filter(&token, Some(1), "usdc"));
    assert!(token_matches_filter(&token, Some(1), "a0B869"));
    assert!(!token_matches_filter(&token, Some(10), "usdc"));
    assert!(!token_matches_filter(&token, Some(1), "wrapped ether"));
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
