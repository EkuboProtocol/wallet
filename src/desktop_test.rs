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

fn guided_chain_draft(
    chain: &str,
    native_value_mode: GuidedNativeValueMode,
    native_values: &str,
) -> GuidedPolicyChainDraft {
    GuidedPolicyChainDraft {
        chain: chain.into(),
        label: "Owner-managed chain permissions".into(),
        max_calls: "4".into(),
        native_value_mode,
        native_values: native_values.into(),
    }
}

#[test]
fn guided_policy_chain_crud_preserves_rules_and_canonicalizes_the_document() {
    let document = r#"{
        "version": 1,
        "chains": {
            "1": {
                "label": "Old label",
                "max_calls_per_batch": 2,
                "native_value": { "eq": "0" },
                "rules": [{
                    "effect": "deny",
                    "label": "Never call this address",
                    "to": { "eq": "0x1111111111111111111111111111111111111111" }
                }]
            }
        }
    }"#;
    let draft = guided_chain_draft(
        "8453",
        GuidedNativeValueMode::Exact,
        "1000000000000000000, 0, 0",
    );
    let (document, policy) = update_guided_policy_chain(document, Some("1"), &draft).unwrap();

    assert!(!policy.chains.contains_key("1"));
    let chain = policy.chains.get("8453").unwrap();
    assert_eq!(chain.max_calls_per_batch, 4);
    assert_eq!(chain.rules.len(), 1);
    assert_eq!(
        chain.rules[0].label.as_deref(),
        Some("Never call this address")
    );
    assert!(document.contains("1000000000000000000"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&document).unwrap()["version"],
        1
    );

    let (document, policy) = remove_guided_policy_chain(&document, "8453").unwrap();
    assert!(policy.chains.is_empty());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&document).unwrap()["chains"],
        serde_json::json!({})
    );
}

#[test]
fn guided_policy_chain_errors_are_attached_to_the_failing_fields() {
    let document = serde_json::to_string(&WalletPolicy::require_approval_for_everything()).unwrap();
    let mut draft = guided_chain_draft("01", GuidedNativeValueMode::Exact, "one ether");
    draft.max_calls = "5000".into();
    draft.label = "\u{202e}misleading".into();

    let errors = update_guided_policy_chain(&document, None, &draft).unwrap_err();
    assert!(errors.chain.is_some());
    assert!(errors.label.is_some());
    assert!(errors.max_calls.is_some());
    assert!(errors.native_values.is_some());
    assert!(errors.form.is_none());
}

#[test]
fn guided_policy_chain_add_refuses_to_overwrite_an_existing_chain() {
    let document = serde_json::to_string(&WalletPolicy::require_approval_for_everything()).unwrap();
    let draft = guided_chain_draft("*", GuidedNativeValueMode::None, "");

    let errors = update_guided_policy_chain(&document, None, &draft).unwrap_err();
    assert_eq!(
        errors.chain.as_deref(),
        Some("That chain already has a policy entry. Edit the existing entry.")
    );
}

fn guided_rule_draft_with_selector() -> GuidedPolicyRuleDraft {
    GuidedPolicyRuleDraft {
        effect: GuidedRuleEffect::Allow,
        label: "Send a bounded amount to named recipients".into(),
        target_mode: GuidedLiteralMode::Exact,
        targets: concat!(
            "0x1111111111111111111111111111111111111111, ",
            "0x2222222222222222222222222222222222222222"
        )
        .into(),
        sender_mode: GuidedLiteralMode::Exact,
        senders: "$self".into(),
        value_mode: GuidedLiteralMode::Exact,
        values: "0".into(),
        calldata_mode: GuidedCalldataMode::Selector,
        abi: "transfer(address to, uint256 amount)".into(),
        args: r#"{
            "to": { "in": ["0x3333333333333333333333333333333333333333"] },
            "amount": { "all": [{ "not": { "eq": "0" } }] }
        }"#
        .into(),
    }
}

#[test]
fn guided_policy_rule_crud_round_trips_through_canonical_validation() {
    let document = serde_json::to_string(&WalletPolicy::require_approval_for_everything()).unwrap();
    let draft = guided_rule_draft_with_selector();
    let (document, policy) = update_guided_policy_rule(&document, "*", None, &draft).unwrap();

    let chain = policy.chains.get("*").unwrap();
    assert_eq!(chain.rules.len(), 1);
    assert_eq!(
        chain.rules[0].label.as_deref(),
        Some("Send a bounded amount to named recipients")
    );
    assert!(chain.rules[0].describe().contains("transfer"));

    let mut replacement = draft;
    replacement.effect = GuidedRuleEffect::Deny;
    replacement.label = "Never make this transfer".into();
    replacement.calldata_mode = GuidedCalldataMode::Empty;
    let (document, policy) =
        update_guided_policy_rule(&document, "*", Some(0), &replacement).unwrap();
    assert_eq!(policy.chains["*"].rules.len(), 1);
    assert!(
        policy.chains["*"].rules[0]
            .describe()
            .starts_with("deny [Never make this transfer]")
    );

    let (document, policy) = remove_guided_policy_rule(&document, "*", 0).unwrap();
    assert!(policy.chains["*"].rules.is_empty());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&document).unwrap()["chains"]["*"]["rules"],
        serde_json::json!([])
    );
}

#[test]
fn guided_policy_rule_reports_errors_next_to_each_invalid_field() {
    let document = serde_json::to_string(&WalletPolicy::require_approval_for_everything()).unwrap();
    let draft = GuidedPolicyRuleDraft {
        effect: GuidedRuleEffect::Allow,
        label: "\u{202e}misleading".into(),
        target_mode: GuidedLiteralMode::Exact,
        targets: "not an address".into(),
        sender_mode: GuidedLiteralMode::Exact,
        senders: "0x1234".into(),
        value_mode: GuidedLiteralMode::Exact,
        values: "one ether".into(),
        calldata_mode: GuidedCalldataMode::Selector,
        abi: String::new(),
        args: "[]".into(),
    };

    let errors = update_guided_policy_rule(&document, "*", None, &draft).unwrap_err();
    assert!(errors.label.is_some());
    assert!(errors.targets.is_some());
    assert!(errors.senders.is_some());
    assert!(errors.values.is_some());
    assert!(errors.abi.is_some());
    assert!(errors.args.is_some());
    assert!(errors.form.is_none());
}

#[test]
fn allow_anything_preset_is_canonical_and_unambiguously_unrestricted() {
    let (document, policy) = allow_anything_policy_document().unwrap();
    let reparsed = WalletPolicy::parse(serde_json::from_str(&document).unwrap()).unwrap();

    assert_eq!(policy, reparsed);
    assert_eq!(policy.chains.len(), 1);
    assert_eq!(policy.chains["*"].max_calls_per_batch, 4096);
    assert_eq!(policy.chains["*"].rules.len(), 1);
    assert_eq!(policy.chains["*"].rules[0].effect, Effect::Allow);
    assert!(policy.chains["*"].rules[0].to.is_none());
    assert!(policy.chains["*"].rules[0].calldata.is_none());
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
    assert_eq!(Route::ALL.len(), 9);
    assert!(Route::ALL.contains(&Route::Settings));
    assert!(Route::ALL.contains(&Route::WalletConnect));
    assert_eq!(Route::ALL.first(), Some(&Route::Reviews));
    assert_eq!(Route::Reviews.label(), "Inbox");
    assert_eq!(Route::Overview.label(), "Portfolio");
    assert!(NAVIGATION_RAIL_WIDTH >= px(80.0));
    assert!(NAVIGATION_BUTTON_SIZE >= px(52.0));
    assert_eq!(Route::ALL.last(), Some(&Route::Settings));
}

#[test]
fn transaction_review_launch_is_single_flight_before_and_after_the_prompt_arrives() {
    let mut flow = ReviewFlowState::Ready;

    assert!(flow.begin_transaction());
    assert!(flow.is_in_progress());
    assert!(!flow.begin_transaction());
    assert!(flow.activate_transaction_prompt());
    assert!(!flow.begin_transaction());

    flow = ReviewFlowState::Ready;
    assert!(flow.begin_transaction());
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
        ("⌘9 / ⌘,", "cmd-9"),
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
        ("Ctrl+9 / Ctrl+,", "ctrl-9"),
    ];

    let actual = Route::ALL.map(|route| (route.shortcut(), route.key_binding()));
    assert_eq!(actual, expected);
    #[cfg(target_os = "macos")]
    assert_eq!(SETTINGS_ALTERNATE_KEY_BINDING, "cmd-,");
    #[cfg(not(target_os = "macos"))]
    assert_eq!(SETTINGS_ALTERNATE_KEY_BINDING, "ctrl-,");
}

#[test]
fn token_network_labels_prefer_human_readable_configured_names() {
    let networks = ekubo_wallet_core::networks::default_networks();
    let labels = token_network_names(&networks);
    let ethereum = networks
        .iter()
        .find(|network| network.chain_id == 1)
        .unwrap();

    assert_eq!(
        labels.get(&1).map(AsRef::<str>::as_ref),
        Some(ethereum.display_name.as_deref().unwrap_or(&ethereum.name))
    );
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
fn token_search_ranks_exact_symbols_before_longer_prefix_matches() {
    let token = |symbol: &str, address: &str| StoredToken {
        chain_id: "1".into(),
        address: address.into(),
        symbol: Some(symbol.into()),
        name: None,
        decimals: Some(18),
        source: "test".into(),
        added_at: chrono::Utc::now(),
    };
    let exact = token("USDe", "0x1111111111111111111111111111111111111111");
    let prefix = token("USDEBT", "0x2222222222222222222222222222222222222222");

    assert!(token_search_rank(&exact, "usde") < token_search_rank(&prefix, "usde"));
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
fn embedded_suisse_fonts_are_true_type_and_name_both_application_families() {
    assert_eq!(EMBEDDED_FONTS.len(), 6);
    assert!(
        EMBEDDED_FONTS
            .iter()
            .all(|font| font.starts_with(&[0, 1, 0, 0]))
    );

    for family in [UI_FONT_FAMILY, MONO_FONT_FAMILY] {
        let utf16_name = family
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        assert!(EMBEDDED_FONTS.iter().any(|font| {
            font.windows(utf16_name.len())
                .any(|name| name == utf16_name)
        }));
    }
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
fn token_editor_parses_a_complete_owner_authored_row() {
    let (token, errors) = parse_token_editor_fields(
        " 8453 ",
        "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        " USDC ",
        " USD Coin ",
        "6",
    );
    let token = token.unwrap();

    assert_eq!(errors, TokenEditorErrors::default());
    assert_eq!(token.chain_id, 8453);
    assert_eq!(
        token.address,
        "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse::<alloy::primitives::Address>()
            .unwrap()
    );
    assert_eq!(token.symbol, "USDC");
    assert_eq!(token.name.as_deref(), Some("USD Coin"));
    assert_eq!(token.decimals, 6);
}

#[test]
fn token_editor_reports_each_invalid_field_next_to_that_field() {
    let (token, errors) = parse_token_editor_fields(
        "0",
        "not-an-address",
        "\u{202e}",
        "unsafe\u{200b}name",
        "256",
    );

    assert!(token.is_none());
    assert!(errors.chain_id.is_some());
    assert!(errors.address.is_some());
    assert!(errors.symbol.is_some());
    assert!(errors.name.is_some());
    assert!(errors.decimals.is_some());
    assert!(errors.form.is_none());
}

#[test]
fn token_editor_allows_an_omitted_full_name() {
    let (token, errors) = parse_token_editor_fields(
        "1",
        "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "USDC",
        "  ",
        "6",
    );

    assert_eq!(errors, TokenEditorErrors::default());
    assert_eq!(token.unwrap().name, None);
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
