use super::*;

#[test]
fn update_handoff_releases_the_instance_before_relaunch() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let (sender, _receiver) = std::sync::mpsc::channel();
    let InstanceOutcome::Primary(instance) =
        SingleInstance::acquire(directory.path(), sender.clone()).unwrap()
    else {
        panic!("the first wallet must own the instance lock");
    };
    let slot = Arc::new(Mutex::new(Some(instance)));

    assert!(matches!(
        SingleInstance::acquire(directory.path(), sender.clone()).unwrap(),
        InstanceOutcome::ActivatedExisting
    ));
    release_single_instance(&slot).expect("the updater releases the old process lock");
    assert!(matches!(
        SingleInstance::acquire(directory.path(), sender).unwrap(),
        InstanceOutcome::Primary(_)
    ));
}
use ekubo_wallet_core::approval::{ApprovalKind, ApprovalRequest};
use ekubo_wallet_core::core::policy::Effect;

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
fn review_sections_put_simulated_effects_before_actions_and_fees() {
    let request = ApprovalRequest::new(ApprovalKind::Transaction, "Review", "Summary")
        .section_kind(ApprovalSectionKind::Fees, "Fees")
        .section_kind(ApprovalSectionKind::Details, "Details")
        .section_kind(ApprovalSectionKind::Action, "Action")
        .section_kind(ApprovalSectionKind::Effects, "Effects");
    let document = ReviewDocument::from_request(request, Vec::new());

    assert_eq!(
        review_sections_for_display(&document)
            .into_iter()
            .map(|section| section.heading.as_str())
            .collect::<Vec<_>>(),
        ["Effects", "Action", "Fees", "Details"]
    );
}

#[test]
fn recognized_balance_effects_separate_the_symbol_from_the_exact_address() {
    let address = "0x1111111111111111111111111111111111111111";
    assert_eq!(
        balance_effect_asset(&format!("USDC ({address})")),
        ("USDC".into(), Some(address.into()))
    );
    assert_eq!(
        balance_effect_asset(&format!("{address} (unlisted token)")),
        ("Unlisted token".into(), Some(address.into()))
    );
    assert_eq!(
        balance_effect_asset("ETH (native)"),
        ("ETH".into(), Some("Native asset".into()))
    );
}

#[test]
fn the_install_button_reflects_what_is_left_to_install() {
    let agent = |installed| DetectedAgent {
        kind: AgentKind::Codex,
        display_name: "Agent",
        config_path: "agent.json".into(),
        installed,
    };

    let mixed = AgentDetectionState::Ready(vec![agent(Ok(true)), agent(Ok(false))]);
    assert!(agents_need_install(&mixed));
    assert!(!agents_all_installed(&mixed));
    assert!(agents_any_installed(&mixed));

    let done = AgentDetectionState::Ready(vec![agent(Ok(true))]);
    assert!(!agents_need_install(&done));
    assert!(agents_all_installed(&done));
    assert!(agents_any_installed(&done));

    // An unreadable configuration is not an installed one, so the button
    // stays live and the reassurance stays off.
    let broken = AgentDetectionState::Ready(vec![agent(Err("unreadable".into()))]);
    assert!(agents_need_install(&broken));
    assert!(!agents_all_installed(&broken));
    assert!(!agents_any_installed(&broken));

    // Nothing detected: nothing to install, and nothing to claim either.
    let none = AgentDetectionState::Ready(Vec::new());
    assert!(!agents_need_install(&none));
    assert!(!agents_all_installed(&none));
    assert!(!agents_any_installed(&none));

    // Still looking, or unable to look: offer the button, promise nothing.
    for unknown in [
        AgentDetectionState::Loading,
        AgentDetectionState::Failed("detection failed".into()),
    ] {
        assert!(agents_need_install(&unknown));
        assert!(!agents_all_installed(&unknown));
    }
}

#[test]
fn structured_network_editor_builds_the_complete_network_configuration() {
    let draft = NetworkEditorDraft {
        name: "owner-chain".into(),
        display_name: "Owner Chain".into(),
        aliases: "owner, owner_test".into(),
        chain_id: "9999991".into(),
        rpc_urls: "https://rpc-one.example,\nhttps://rpc-two.example".into(),
        max_gas_limit: "30000000".into(),
        max_fee_per_gas: "100000000000".into(),
        native_currency_name: "Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        documentation_url: "https://docs.example/network".into(),
    };

    let (network, errors) = parse_network_editor_draft(&draft, true, true, RpcStrategy::Random, 12);
    assert_eq!(errors, NetworkEditorErrors::default());
    let network = network.unwrap();
    assert_eq!(network.name, "owner-chain");
    assert_eq!(network.display_name.as_deref(), Some("Owner Chain"));
    assert_eq!(network.aliases, ["owner", "owner_test"]);
    assert_eq!(network.chain_id, 9_999_991);
    assert_eq!(network.rpc_urls.len(), 2);
    assert_eq!(network.rpc_strategy, RpcStrategy::Random);
    assert!(network.disabled);
    assert!(network.testnet);
    assert_eq!(network.native_currency.unwrap().symbol, "ETH");
}

#[test]
fn network_rpc_editor_displays_explicit_commas_and_round_trips_them() {
    let urls = vec![
        "https://rpc-one.example".parse().unwrap(),
        "https://rpc-two.example".parse().unwrap(),
    ];
    let displayed = rpc_urls_for_editor(&urls);
    assert_eq!(
        displayed,
        "https://rpc-one.example/,\nhttps://rpc-two.example/"
    );

    let draft = NetworkEditorDraft {
        name: "comma-chain".into(),
        chain_id: "9001".into(),
        rpc_urls: displayed,
        native_currency_name: "Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        documentation_url: "https://docs.example".into(),
        ..NetworkEditorDraft::default()
    };
    let (parsed, errors) =
        parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered, 12);
    assert_eq!(errors, NetworkEditorErrors::default());
    assert_eq!(parsed.unwrap().rpc_urls, urls);
}

#[test]
fn structured_network_editor_requires_network_metadata() {
    let draft = NetworkEditorDraft {
        name: "example".into(),
        chain_id: "123456".into(),
        rpc_urls: "https://rpc.example".into(),
        native_currency_name: "Example Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        ..NetworkEditorDraft::default()
    };

    let (network, errors) =
        parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered, 12);

    assert!(network.is_none());
    assert_eq!(
        errors.documentation_url.as_deref(),
        Some("Enter the network's documentation URL.")
    );
}

#[test]
fn structured_network_editor_reports_errors_beside_the_relevant_fields() {
    let draft = NetworkEditorDraft {
        name: "not valid".into(),
        chain_id: "zero".into(),
        rpc_urls: "https://user:secret@rpc.example\nhttps://user:secret@rpc.example".into(),
        max_gas_limit: "12".into(),
        native_currency_name: "Ether".into(),
        ..NetworkEditorDraft::default()
    };

    let (network, errors) =
        parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered, 12);
    assert!(network.is_none());
    assert!(errors.name.is_some());
    assert!(errors.chain_id.is_some());
    assert!(errors.rpc_urls.is_some());
    assert!(errors.max_gas_limit.is_some());
    assert!(errors.native_currency.is_some());
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
fn blocked_notification_navigation_retains_the_exact_clicked_destination() {
    let request_id = uuid::Uuid::new_v4();
    let mut navigation = NotificationNavigation::default();

    navigation.receive(NotificationRoute::Review(request_id));

    assert_eq!(navigation.take(true), None);
    assert_eq!(
        navigation.take(false),
        Some(NotificationRoute::Review(request_id))
    );
    assert_eq!(navigation.take(false), None);
}

#[test]
fn the_latest_notification_click_supersedes_an_unopened_destination() {
    let earlier = uuid::Uuid::new_v4();
    let latest = uuid::Uuid::new_v4();
    let mut navigation = NotificationNavigation::default();

    navigation.receive(NotificationRoute::Review(earlier));
    navigation.receive(NotificationRoute::Activity(latest));

    assert_eq!(
        navigation.take(false),
        Some(NotificationRoute::Activity(latest))
    );
}

#[test]
fn portfolio_amounts_preserve_every_significant_digit() {
    assert_eq!(
        format_asset_amount("123450000", Some(6), "base units"),
        "123.45"
    );
    assert_eq!(
        format_asset_amount(
            "340282366920938463463374607431768211455",
            Some(18),
            "base units"
        ),
        "340282366920938463463.374607431768211455"
    );
    assert_eq!(format_asset_amount("7", None, "base units"), "7 base units");
}

#[test]
fn portfolio_rows_are_commingled_by_chain_then_token_address() {
    let mut rows = vec![
        PortfolioBalanceRow {
            chain_id: 10,
            network_name: "Optimism".into(),
            asset_address: "0xbb".into(),
            token_symbol: Some("B".into()),
            token_name: Some("Token B".into()),
            native: false,
            balance: "2".into(),
            explorer_url: None,
        },
        PortfolioBalanceRow {
            chain_id: 1,
            network_name: "Ethereum".into(),
            asset_address: "0xcc".into(),
            token_symbol: Some("C".into()),
            token_name: Some("Token C".into()),
            native: false,
            balance: "3".into(),
            explorer_url: None,
        },
        PortfolioBalanceRow {
            chain_id: 1,
            network_name: "Ethereum".into(),
            asset_address: "0xAA".into(),
            token_symbol: Some("A".into()),
            token_name: Some("Token A".into()),
            native: false,
            balance: "1".into(),
            explorer_url: None,
        },
    ];

    sort_portfolio_balance_rows(&mut rows);

    assert_eq!(
        rows.iter()
            .map(|row| (row.chain_id, row.asset_address.as_str()))
            .collect::<Vec<_>>(),
        [(1, "0xAA"), (1, "0xcc"), (10, "0xbb")]
    );
}

#[test]
fn allow_anything_preset_is_canonical_and_unambiguously_unrestricted() {
    let document = allow_anything_policy_document().unwrap();
    let policy = WalletPolicy::parse(serde_json::from_str(&document).unwrap()).unwrap();

    assert_eq!(policy, WalletPolicy::allow_anything());
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.rules[0].effect, Effect::Allow);
    assert!(policy.rules[0].chain_id.is_none());
    assert!(policy.rules[0].to.is_none());
    assert!(policy.rules[0].native_value.is_none());
    assert!(policy.rules[0].calldata.is_none());
}

#[test]
fn disable_signing_preset_is_one_unconditional_deny() {
    let document = disable_signing_policy_document().unwrap();
    let policy = WalletPolicy::parse(serde_json::from_str(&document).unwrap()).unwrap();

    assert_eq!(policy, WalletPolicy::deny_all());
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.rules[0].effect, Effect::Deny);
    assert!(policy.rules[0].chain_id.is_none());
    assert!(policy.rules[0].to.is_none());
    assert!(policy.rules[0].native_value.is_none());
    assert!(policy.rules[0].calldata.is_none());
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
    assert_eq!(Route::ALL.len(), 8);
    assert!(Route::ALL.contains(&Route::Settings));
    assert!(Route::ALL.contains(&Route::WalletConnect));
    assert_eq!(Route::Activity.label(), "Inbox");
    assert_eq!(Route::Overview.label(), "Portfolio");
    assert!(NAVIGATION_RAIL_WIDTH >= px(80.0));
    assert!(NAVIGATION_BUTTON_SIZE >= px(52.0));
    assert_eq!(Route::ALL.last(), Some(&Route::Settings));
}

#[test]
fn the_rail_opens_on_accounts_because_nothing_works_without_one() {
    assert_eq!(Route::ALL.first(), Some(&Route::Accounts));
    // The window's landing screen and the first rail entry are the same
    // thing on purpose: a new install has no account, and every other
    // screen is empty until it does.
    assert_eq!(Route::DEFAULT, Route::Accounts);
    // The requests an agent is waiting on sit directly below setup, ahead
    // of the read-only and configuration screens.
    assert_eq!(Route::ALL.get(1), Some(&Route::Activity));
}

#[test]
fn every_route_explains_itself_in_one_sentence() {
    for route in Route::ALL {
        let description = route.description();
        assert!(
            description.len() > 30,
            "{} has no usable description",
            route.label()
        );
        assert!(
            description.ends_with('.'),
            "{} description is not a sentence",
            route.label()
        );
        assert!(
            !description
                .trim_end_matches('.')
                .eq_ignore_ascii_case(route.label()),
            "{} description only repeats its own title",
            route.label()
        );
    }
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
        ("⌘8 / ⌘,", "cmd-8"),
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
        ("Ctrl+8 / Ctrl+,", "ctrl-8"),
    ];

    let actual = Route::ALL.map(|route| (route.shortcut().to_string(), route.key_binding()));
    for (index, (shortcut, binding)) in expected.into_iter().enumerate() {
        assert_eq!(actual[index], (shortcut.to_owned(), binding));
    }
    #[cfg(target_os = "macos")]
    assert_eq!(SETTINGS_ALTERNATE_KEY_BINDING, "cmd-,");
    #[cfg(not(target_os = "macos"))]
    assert_eq!(SETTINGS_ALTERNATE_KEY_BINDING, "ctrl-,");
}

#[test]
fn shortcuts_follow_rail_position_so_reordering_tabs_cannot_desynchronize_them() {
    // Both the displayed hint and the registered binding are derived from
    // the route's index in `ALL`. Nothing is spelled out per variant, so a
    // future reorder can never leave the first tab answering to ⌘3.
    for (index, route) in Route::ALL.into_iter().enumerate() {
        let digit = (index + 1).to_string();
        assert!(
            route.shortcut().contains(&digit),
            "{} shows a shortcut that does not match its rail position",
            route.label()
        );
        assert!(
            route.key_binding().ends_with(&digit),
            "{} is bound to a key that does not match its rail position",
            route.label()
        );
    }
    // The platform preferences shortcut belongs to Settings itself, not to
    // whichever slot Settings happens to occupy.
    assert!(
        Route::Settings
            .shortcut()
            .contains(SETTINGS_ALTERNATE_SHORTCUT)
    );
    for route in Route::ALL
        .into_iter()
        .filter(|route| *route != Route::Settings)
    {
        assert!(
            !route.shortcut().contains(SETTINGS_ALTERNATE_SHORTCUT),
            "{} claims the preferences shortcut",
            route.label()
        );
    }
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
fn legal_markdown_rows_are_fixed_width_semantic_and_contained() {
    let long_paragraph = "x".repeat(LEGAL_WRAP_COLUMNS * 3);
    let source = format!(
        "# Terms\n\nIntro split\nacross lines.\n\n- A bullet\n\n```text\n# not a heading\n{long_paragraph}\n```\n\nTail\n"
    );
    let rows = legal_markdown_rows(&source);

    assert!(
        rows.iter()
            .all(|row| row.text.chars().count() <= LEGAL_WRAP_COLUMNS)
    );
    assert_eq!(rows[0].kind, LegalRowKind::Heading);
    assert!(
        rows.iter()
            .any(|row| row.text == "Intro split across lines.")
    );
    assert!(rows.iter().any(|row| row.text == "• A bullet"));
    assert!(
        rows.iter()
            .any(|row| row.kind == LegalRowKind::Code && row.text == "# not a heading")
    );
    assert!(!rows.iter().any(|row| row.text.contains("```")));
}

#[test]
fn legal_rows_keep_punctuation_literal_and_linkify_web_urls() {
    let html = legal_row_html(
        "crate-name 1.2.3 — https://github.com/example/crate. Contact <dev@example.com>",
    );
    assert!(html.contains("crate-name 1.2.3"));
    assert!(!html.contains("\\-"));
    assert!(!html.contains("\\."));
    assert!(html.contains(
        "<a href=\"https://github.com/example/crate\">https://github.com/example/crate</a>."
    ));
    assert!(html.contains("&lt;dev@example.com&gt;"));
}

#[test]
fn long_legal_urls_remain_clickable_across_wrapped_rows() {
    let url =
        "https://example.com/a/path/that/is/deliberately/longer/than/the/legal/view/line/width";
    let rows = legal_markdown_rows(url);
    assert!(rows.len() > 1);
    assert!(rows.iter().all(|row| row.link_url.as_deref() == Some(url)));
}

#[test]
fn explorer_transaction_links_use_the_configured_chain_url() {
    let mut network = crate::config::default_networks().remove(0);
    network.chain_id = 7;
    network.block_explorer_url = Some("https://explorer.example/base".parse().unwrap());
    assert_eq!(
        block_explorer_transaction_url(&[network], 7, "0xabc").as_deref(),
        Some("https://explorer.example/base/tx/0xabc")
    );
}

#[test]
fn explorer_token_links_use_the_configured_chain_url() {
    let mut network = crate::config::default_networks().remove(0);
    network.block_explorer_url = Some("https://explorer.example/base/".parse().unwrap());
    assert_eq!(
        block_explorer_token_url(&network, "0xabc").as_deref(),
        Some("https://explorer.example/base/token/0xabc")
    );
}

#[test]
fn portfolio_account_selection_is_clamped_after_accounts_change() {
    assert_eq!(clamped_portfolio_account_index(3, 1), 1);
    assert_eq!(clamped_portfolio_account_index(1, 2), 0);
    assert_eq!(clamped_portfolio_account_index(0, 7), 0);
}

#[test]
fn policy_account_tab_follows_the_open_editor() {
    let labels = vec!["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()];
    assert_eq!(policy_selected_account_index(&labels, Some("beta")), 1);
    assert_eq!(policy_selected_account_index(&labels, Some("gamma")), 2);
    // No editor open yet, and an editor left on a deleted account, both fall
    // back to the first tab rather than to a tab that is not there.
    assert_eq!(policy_selected_account_index(&labels, None), 0);
    assert_eq!(policy_selected_account_index(&labels, Some("deleted")), 0);
    assert_eq!(policy_selected_account_index(&[], Some("alpha")), 0);
}

#[test]
fn policy_proposals_stay_with_their_account_tab() {
    let proposal = |wallet_id: &str| PolicyProposal {
        wallet_instance_id: uuid::Uuid::new_v4(),
        wallet_id: wallet_id.to_owned(),
        wallet_address: alloy::primitives::Address::ZERO,
        source_revision: 1,
        policy: WalletPolicy::require_approval_for_everything(),
        rationale: format!("rationale for {wallet_id}"),
        created_at: chrono::Utc::now(),
    };
    let proposals = vec![proposal("alpha"), proposal("beta")];

    assert_eq!(
        policy_proposal_for_account(&proposals, "beta").map(|proposal| proposal.wallet_id.as_str()),
        Some("beta")
    );
    assert!(policy_proposal_for_account(&proposals, "gamma").is_none());
}

fn relative_luminance(rgb: u32) -> f64 {
    let channel = |shift: u32| {
        let value = f64::from(u8::try_from((rgb >> shift) & 0xff_u32).unwrap()) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(16) + 0.7152 * channel(8) + 0.0722 * channel(0)
}

fn contrast_ratio(first: u32, second: u32) -> f64 {
    let (lighter, darker) = {
        let first = relative_luminance(first);
        let second = relative_luminance(second);
        if first > second {
            (first, second)
        } else {
            (second, first)
        }
    };
    (lighter + 0.05) / (darker + 0.05)
}

#[test]
fn every_button_interaction_state_has_aa_text_contrast_in_both_themes() {
    for dark in [false, true] {
        let palette = interface_interaction_palette(dark);
        for (background, foreground) in [
            (palette.button, palette.button_foreground),
            (palette.button_hover, palette.button_foreground),
            (palette.button_active, palette.button_foreground),
            (palette.primary, palette.primary_foreground),
            (palette.primary_hover, palette.primary_foreground),
            (palette.primary_active, palette.primary_foreground),
            (palette.danger, palette.danger_foreground),
            (palette.danger_hover, palette.danger_foreground),
            (palette.danger_active, palette.danger_foreground),
            (palette.success, palette.success_foreground),
            (palette.success_hover, palette.success_foreground),
            (palette.success_active, palette.success_foreground),
            (palette.warning, palette.warning_foreground),
            (palette.warning_hover, palette.warning_foreground),
            (palette.warning_active, palette.warning_foreground),
        ] {
            assert!(
                contrast_ratio(background, foreground) >= 4.5,
                "button state #{background:06x} on #{foreground:06x} failed AA contrast"
            );
        }
    }
}

#[test]
#[allow(clippy::unreadable_literal)]
fn interaction_palette_uses_the_figma_brand_colors() {
    let dark = interface_interaction_palette(true);
    assert_eq!(dark.primary, 0x7a36d2);
    assert_eq!(dark.primary_hover, 0x8b4ade);
    assert_eq!(dark.primary_foreground, 0xffffff);
    assert_eq!(dark.danger, 0xb5124f);
    assert_eq!(dark.danger_foreground, 0xffffff);
    assert_eq!(dark.success, 0x26e7ad);
    assert_eq!(dark.warning, 0xdf7b32);

    let light = interface_interaction_palette(false);
    assert_eq!(light.primary, 0x7a36d2);
    assert_eq!(light.primary_foreground, 0xffffff);
    assert_eq!(light.danger, 0xb5124f);
    assert_eq!(light.danger_foreground, 0xffffff);
}

#[test]
fn shared_controls_use_contextual_desktop_dimensions() {
    assert_eq!(BUTTON_HEIGHT, px(44.0));
    assert_eq!(COPY_BUTTON_HEIGHT, px(32.0));
    assert_eq!(CONTROL_RADIUS, px(14.0));
    assert_eq!(SURFACE_RADIUS, px(16.0));
}

#[test]
fn selectable_plain_text_escapes_markup_without_changing_visible_content() {
    // Only the five characters that mean something to a markup parser are
    // touched. Everything else — the dots and slashes in a URL, the dashes in
    // a name, the parentheses around a token symbol — reaches the screen as
    // the caller wrote it.
    assert_eq!(
        html_escaped_plain_text("https://example.com/path").as_ref(),
        "https://example.com/path"
    );
    assert_eq!(
        html_escaped_plain_text("Account_#1 [0xabc]. 1.25 USDC (native) — a-b").as_ref(),
        "Account_#1 [0xabc]. 1.25 USDC (native) — a-b"
    );
    assert_eq!(
        html_escaped_plain_text("<script>alert('x' & \"y\")</script>").as_ref(),
        "&lt;script&gt;alert(&#39;x&#39; &amp; &quot;y&quot;)&lt;/script&gt;"
    );
    // A newline is a line break rather than a paragraph join.
    assert_eq!(
        html_escaped_plain_text("first\nsecond").as_ref(),
        "first<br>second"
    );
}

#[test]
fn selectable_code_uses_a_fence_longer_than_embedded_backticks() {
    let value = "before ``` after";
    let markdown = markdown_fenced_code(value);
    assert!(markdown.starts_with("````text\n"));
    assert!(markdown.contains(value));
    assert!(markdown.ends_with("\n````"));
}

#[test]
fn only_plain_enter_submits_a_single_line_form() {
    assert!(primary_enter(&InputEvent::PressEnter {
        secondary: false,
        shift: false,
    }));
    assert!(!primary_enter(&InputEvent::PressEnter {
        secondary: true,
        shift: false,
    }));
    assert!(!primary_enter(&InputEvent::PressEnter {
        secondary: false,
        shift: true,
    }));
}

#[test]
#[allow(clippy::unreadable_literal)]
fn light_selected_button_uses_secondary_purple_instead_of_dark_mode_surface() {
    let light = interface_interaction_palette(false);
    let dark = interface_interaction_palette(true);
    assert_eq!(light.button_active, 0xf3e7fe);
    assert_ne!(light.button_active, dark.button_active);
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
fn networks_stay_sorted_by_numeric_chain_id_when_enabled_state_changes() {
    let mut networks = ekubo_wallet_core::networks::default_networks();
    for network in &mut networks {
        network.disabled = network.chain_id != 42_161;
    }
    networks.reverse();

    let sorted = networks_for_display(&networks, false);
    assert!(
        sorted
            .windows(2)
            .all(|pair| pair[0].chain_id <= pair[1].chain_id)
    );
}

#[test]
fn testnet_mode_controls_visibility_without_hiding_unknown_chain_context() {
    let networks = ekubo_wallet_core::networks::default_networks();
    let testnet_chain = networks
        .iter()
        .find(|network| network.testnet)
        .map(|network| network.chain_id)
        .unwrap();
    let configured = networks
        .iter()
        .map(|network| network.chain_id)
        .collect::<BTreeSet<_>>();
    let hidden = visible_network_chain_ids(&networks, false);

    assert!(!hidden.contains(&testnet_chain));
    assert!(!chain_is_visible(Some(testnet_chain), &hidden, &configured));
    assert!(chain_is_visible(Some(u64::MAX), &hidden, &configured));
    assert!(visible_network_chain_ids(&networks, true).contains(&testnet_chain));
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
fn bundled_licenses_are_informational_not_acceptance_gated() {
    assert!(legal_requires_acceptance(LegalDocument::TermsOfService));
    assert!(legal_requires_acceptance(LegalDocument::PrivacyPolicy));
    assert!(!legal_requires_acceptance(
        LegalDocument::ApplicationLicense
    ));
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
        Some(&status)
    ));
    assert!(!legal_review_requires_acceptance(
        LegalDocument::PrivacyPolicy,
        Some(&status)
    ));
}

#[test]
fn owner_legal_documents_fail_closed_when_status_is_unavailable() {
    assert!(legal_review_requires_acceptance(
        LegalDocument::TermsOfService,
        None
    ));
    assert!(legal_review_requires_acceptance(
        LegalDocument::PrivacyPolicy,
        None
    ));
    assert!(!legal_review_requires_acceptance(
        LegalDocument::ApplicationLicense,
        None
    ));
    assert!(!legal_review_requires_acceptance(
        LegalDocument::ThirdPartyLicenses,
        None
    ));
}

#[test]
fn legal_acceptance_waits_until_the_final_virtual_row_has_rendered() {
    let handle = UniformListScrollHandle::new();
    let end_rendered = AtomicBool::new(false);
    assert!(!legal_list_reached_end(&handle, &end_rendered));
    end_rendered.store(true, Ordering::Release);
    assert!(legal_list_reached_end(&handle, &end_rendered));
}

#[test]
fn application_license_is_compiled_for_the_legal_viewer() {
    let text = LegalDocument::ApplicationLicense.text();
    assert!(text.contains("Functional Source License, Version 1.1"));
    assert!(text.contains("Copyright 2026 Ekubo, Inc."));
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
            send: true,
            cancel: false,
            discard: true,
        }
    );
    assert_eq!(
        transaction_actions(PendingStatus::Broadcast),
        TransactionActions {
            send: true,
            cancel: true,
            discard: false,
        }
    );
    assert_eq!(
        transaction_actions(PendingStatus::Cancelling),
        TransactionActions {
            send: false,
            cancel: true,
            discard: false,
        }
    );
    assert_eq!(
        transaction_actions(PendingStatus::Confirmed),
        TransactionActions {
            send: false,
            cancel: false,
            discard: false,
        }
    );
}

#[test]
fn automatic_status_refresh_only_polls_transactions_the_network_can_advance() {
    for status in [
        PendingStatus::Submitting,
        PendingStatus::Broadcast,
        PendingStatus::Cancelling,
    ] {
        assert!(transaction_status_needs_automatic_refresh(status));
    }
    for status in [
        PendingStatus::AwaitingApproval,
        PendingStatus::Rejected,
        PendingStatus::Signed,
        PendingStatus::Confirmed,
        PendingStatus::Reverted,
        PendingStatus::Cancelled,
        PendingStatus::Replaced,
    ] {
        assert!(!transaction_status_needs_automatic_refresh(status));
    }
}

#[test]
fn policy_draft_validation_canonicalizes_and_previews_permission_changes() {
    let current = WalletPolicy::require_approval_for_everything();
    let proposed = WalletPolicy::allow_anything();
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
        r#"{"version":1,"rules":[],"unexpected":true}"#,
    )
    .unwrap_err();

    assert!(format!("{error:#}").contains("unknown field"));
}

#[test]
fn changing_routes_resets_scroll_without_disturbing_the_current_route() {
    let scroll = ScrollHandle::new();
    scroll.set_offset(gpui::point(px(-14.0), px(-220.0)));

    reset_route_scroll_if_changed(Route::Networks, Route::Networks, &scroll);
    assert_eq!(scroll.offset().y, px(-220.0));

    reset_route_scroll_if_changed(Route::Networks, Route::Tokens, &scroll);
    assert_eq!(scroll.offset(), gpui::point(px(0.0), px(0.0)));
}

#[test]
fn every_lifecycle_state_reads_as_english_rather_than_its_variant_name() {
    for status in [
        PendingStatus::AwaitingApproval,
        PendingStatus::Rejected,
        PendingStatus::Signed,
        PendingStatus::Submitting,
        PendingStatus::Broadcast,
        PendingStatus::Confirmed,
        PendingStatus::Reverted,
        PendingStatus::Cancelled,
        PendingStatus::Replaced,
        PendingStatus::Cancelling,
    ] {
        let label = status.label();
        let debug = format!("{status:?}");
        // A few variants are already ordinary words ("Rejected"), so the
        // test that matters is that none of them still reads as an
        // identifier — no run-together capitals, and nothing left of
        // `AwaitingApproval` shape.
        assert!(
            !label.chars().skip(1).any(char::is_uppercase),
            "{label} is CamelCase rather than a phrase"
        );
        assert!(
            debug
                .chars()
                .filter(|character| character.is_uppercase())
                .count()
                < 2
                || label != debug,
            "{debug} is still shown as its variant name"
        );
        assert!(
            status.explanation().ends_with('.'),
            "{debug} has no explanatory sentence"
        );
    }

    // The four outcomes a reader cares most about are the ones the wallet
    // used to spell in lifecycle vocabulary.
    assert_eq!(PendingStatus::Confirmed.label(), "Succeeded");
    assert_eq!(PendingStatus::Reverted.label(), "Failed on chain");
    assert_eq!(PendingStatus::Broadcast.label(), "Waiting to be mined");
    assert_eq!(PendingStatus::AwaitingApproval.label(), "Waiting for you");
}

#[test]
fn status_colour_separates_success_from_waiting_from_failure() {
    assert_eq!(
        transaction_status_tone(PendingStatus::Confirmed),
        StatusTone::Done
    );
    assert_eq!(
        transaction_status_tone(PendingStatus::AwaitingApproval),
        StatusTone::NeedsYou
    );
    // A signed-but-unsent transaction is stalled on the owner, not on the
    // network, so it is coloured like a decision rather than like progress.
    assert_eq!(
        transaction_status_tone(PendingStatus::Signed),
        StatusTone::NeedsYou
    );
    assert_eq!(
        transaction_status_tone(PendingStatus::Broadcast),
        StatusTone::Working
    );
    for status in [
        PendingStatus::Rejected,
        PendingStatus::Reverted,
        PendingStatus::Cancelled,
        PendingStatus::Replaced,
    ] {
        assert_eq!(transaction_status_tone(status), StatusTone::Failed);
    }
    assert_eq!(message_status_tone(MessageStatus::Signed), StatusTone::Done);
    assert_eq!(
        typed_data_status_tone(TypedDataStatus::AwaitingApproval),
        StatusTone::NeedsYou
    );
}

#[test]
fn a_gateway_that_could_not_start_reads_as_a_failure_and_carries_its_reason() {
    assert_eq!(McpGatewayStatus::Starting.tone(), StatusTone::Working);
    assert_eq!(McpGatewayStatus::Starting.label(), "Starting");
    assert_eq!(McpGatewayStatus::Starting.detail(), None);

    assert_eq!(McpGatewayStatus::Online.tone(), StatusTone::Done);
    assert_eq!(McpGatewayStatus::Online.label(), "Reachable");
    // Nothing to explain: the endpoint beside the pill is the whole story.
    assert_eq!(McpGatewayStatus::Online.detail(), None);

    let offline = McpGatewayStatus::Offline("address already in use".into());
    assert_eq!(offline.tone(), StatusTone::Failed);
    assert_eq!(offline.label(), "Unreachable");
    // The one fact a reader cannot guess from a status word: the port is
    // fixed, so why it could not be served is the whole of the diagnosis.
    assert_eq!(offline.detail().as_deref(), Some("address already in use"));
}

#[test]
fn ages_read_as_elapsed_time_until_they_are_old_enough_to_need_a_date() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-08-12T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let ago = |seconds: i64| now - chrono::Duration::seconds(seconds);

    assert_eq!(relative_time_label(now, now), "just now");
    assert_eq!(relative_time_label(ago(30), now), "just now");
    // Clock skew between the writing process and this render must not
    // produce "-1 minutes ago".
    assert_eq!(
        relative_time_label(now + chrono::Duration::seconds(90), now),
        "just now"
    );
    assert_eq!(relative_time_label(ago(60), now), "1 minute ago");
    assert_eq!(relative_time_label(ago(3 * 60), now), "3 minutes ago");
    assert_eq!(relative_time_label(ago(3_600), now), "1 hour ago");
    assert_eq!(relative_time_label(ago(5 * 3_600), now), "5 hours ago");
    assert_eq!(relative_time_label(ago(86_400), now), "1 day ago");
    assert_eq!(relative_time_label(ago(3 * 86_400), now), "3 days ago");
    // Past a week, "63 days ago" is not something a person can place.
    let old = relative_time_label(ago(60 * 86_400), now);
    assert!(!old.contains("ago"), "{old} should be a calendar date");
    assert!(old.contains("2026"), "{old} should name its year");
}

#[test]
fn walletconnect_expiry_reads_as_time_remaining() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-08-12T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let after = |seconds: i64| now.timestamp() + seconds;

    assert_eq!(
        walletconnect_expiry_label(after(-1), now),
        "Expired; reconnect to renew"
    );
    assert_eq!(
        walletconnect_expiry_label(after(30), now),
        "Expires in less than a minute; reconnect to renew"
    );
    assert_eq!(
        walletconnect_expiry_label(after(90), now),
        "Expires in 2 minutes; reconnect to renew"
    );
    assert_eq!(
        walletconnect_expiry_label(after(3_600), now),
        "Expires in 1 hour; reconnect to renew"
    );
    assert_eq!(
        walletconnect_expiry_label(after(2 * 86_400), now),
        "Expires in 2 days; reconnect to renew"
    );
}

#[test]
fn overflow_indicator_final_click_clamps_to_the_true_bottom() {
    assert_eq!(
        next_overflow_indicator_offset(px(-900.0), px(1_000.0), px(400.0)),
        px(-1_000.0)
    );
    assert_eq!(
        next_overflow_indicator_offset(px(-200.0), px(1_000.0), px(400.0)),
        px(-488.0)
    );
}

#[test]
fn overflow_indicator_breathes_and_reaches_full_opacity_on_hover() {
    assert!((overflow_indicator_opacity(false, Duration::from_millis(350)) - 0.90).abs() < 0.001);
    assert!((overflow_indicator_opacity(false, Duration::from_millis(1_050)) - 0.70).abs() < 0.001);
    assert!((overflow_indicator_opacity(true, Duration::ZERO) - 1.0).abs() < f32::EPSILON);
}

#[test]
fn overflow_indicator_animation_is_isolated_in_a_child_view() {
    let source = include_str!("desktop.rs");
    assert!(source.contains("struct ScrollOverflowIndicatorView"));
    assert!(source.contains("impl Render for ScrollOverflowIndicatorView"));
    assert!(!source.contains("fn scroll_overflow_indicator<"));
    assert!(!source.contains("window.request_animation_frame()"));
}

#[test]
fn activity_detail_scroll_uses_the_overflow_indicator() {
    let source = include_str!("desktop.rs");
    let detail_overlay = source
        .split_once("fn render_activity_detail_overlay")
        .expect("activity detail overlay exists")
        .1
        .split_once("/// A labelled key/value block")
        .expect("activity detail overlay has an end marker")
        .0;

    assert!(detail_overlay.contains("track_scroll(&self.activity_detail_scroll_handle)"));
    assert!(detail_overlay.contains("self.activity_detail_overflow_indicator.element()"));
}

#[test]
fn sidebar_tooltips_are_immediate_right_side_theme_elements() {
    let source = include_str!("desktop.rs");
    let sidebar = source
        .split_once("fn render_sidebar")
        .expect("sidebar renderer exists")
        .1
        .split_once("/// One waiting request")
        .expect("sidebar renderer has an end marker")
        .0;

    assert!(sidebar.contains(".on_hover("));
    assert!(sidebar.contains(".anchor(Anchor::LeftCenter)"));
    assert!(sidebar.contains("NAVIGATION_BUTTON_SIZE + px(10.0)"));
    assert!(sidebar.contains("NAVIGATION_BUTTON_SIZE / 2.0"));
    assert!(sidebar.contains(".bg(cx.theme().primary)"));
    assert!(!sidebar.contains(".tooltip("));
}

#[test]
fn counts_are_written_the_way_a_person_would_say_them() {
    assert_eq!(pluralize(0, "request"), "0 requests");
    assert_eq!(pluralize(1, "request"), "1 request");
    assert_eq!(pluralize(2, "request"), "2 requests");
    assert_eq!(pluralize(1, "token name"), "1 token name");
    assert_eq!(pluralize(4, "token name"), "4 token names");
}

#[test]
fn chains_are_named_when_configured_and_numbered_only_as_a_last_resort() {
    let mut networks = BTreeMap::new();
    networks.insert(1_u64, SharedString::from("Ethereum"));

    assert_eq!(chain_label(Some(1), &networks), "Ethereum");
    assert_eq!(chain_label(Some(8_453), &networks), "chain 8453");
    assert_eq!(chain_label(None, &networks), "no network");
}

#[test]
fn the_rpc_endpoint_field_holds_text_only_a_multi_line_input_can_shape() {
    // gpui shapes a single-line input with `shape_line`, which panics on a
    // newline instead of wrapping or truncating — opening the network editor
    // aborted the process. Both the placeholder and the value seeded from an
    // existing network span lines, so the field must be built with
    // `.multi_line(true)`; `.rows(n)` alone does not change the mode.
    assert!(RPC_URLS_PLACEHOLDER.contains('\n'));

    let seeded = rpc_urls_for_editor(&[
        "https://rpc-one.example/".parse().unwrap(),
        "https://rpc-two.example/".parse().unwrap(),
    ]);
    assert!(seeded.contains('\n'));

    // The editor has to read back what it wrote, newlines and all.
    let draft = NetworkEditorDraft {
        name: "owner-chain".into(),
        display_name: "Owner Chain".into(),
        aliases: String::new(),
        chain_id: "9999991".into(),
        rpc_urls: seeded,
        max_gas_limit: "30000000".into(),
        max_fee_per_gas: "100000000000".into(),
        native_currency_name: "Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        documentation_url: "https://docs.example/network".into(),
    };
    let (network, errors) =
        parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered, 12);
    assert_eq!(errors, NetworkEditorErrors::default());
    assert_eq!(
        network
            .unwrap()
            .rpc_urls
            .iter()
            .map(url::Url::as_str)
            .collect::<Vec<_>>(),
        ["https://rpc-one.example/", "https://rpc-two.example/"]
    );
}

#[test]
fn a_row_names_whoever_asked_for_it() {
    let agent = SharedString::from("Claude Code");

    // The authenticated agent is the most specific answer there is, so it
    // outranks the provenance of the plan it handed over.
    assert_eq!(
        activity_source_label(Some("mcp.ekubo.org"), Some(&agent)),
        "via Claude Code"
    );
    assert_eq!(
        activity_source_label(Some("WalletConnect: Ekubo Protocol"), None),
        "via Ekubo Protocol over WalletConnect"
    );
    assert_eq!(
        activity_source_label(Some("app.ekubo.org"), None),
        "from a plan served by app.ekubo.org"
    );
    assert_eq!(
        activity_source_label(Some("inline data URI"), None),
        "from a plan given inline"
    );
    assert_eq!(
        activity_source_label(Some("a file on this machine"), None),
        "from a plan file on this machine"
    );

    // Nothing carried a source, which is what a transfer the owner typed into
    // this wallet looks like.
    assert_eq!(activity_source_label(None, None), "built by this wallet");
}

#[test]
fn a_signature_row_prefers_the_claim_its_review_showed() {
    let agent = SharedString::from("Codex");
    assert_eq!(
        signature_source_label(Some("app.uniswap.org"), Some(&agent)),
        "via app.uniswap.org"
    );
    // An MCP client names no requester, so the agent it authenticated as
    // answers instead of the row reading "unnamed".
    assert_eq!(signature_source_label(None, Some(&agent)), "via Codex");
    assert_eq!(
        signature_source_label(Some("   "), Some(&agent)),
        "via Codex"
    );
    assert_eq!(
        signature_source_label(None, None),
        "from an unnamed requester"
    );
}

#[test]
fn a_source_cannot_draw_outside_its_line() {
    // Both names are somebody else's text. The stores refuse control and
    // bidirectional characters on the way in; the row refuses them again, and
    // caps how much of itself a name can occupy.
    let long = "x".repeat(200);
    let label = activity_source_label(Some(&format!("WalletConnect: {long}")), None);
    assert_eq!(label, format!("via {} over WalletConnect", "x".repeat(64)));
    assert_eq!(
        signature_source_label(Some("Ekubo\u{202e}Protocol\n"), None),
        "via EkuboProtocol"
    );
}

#[test]
fn a_digest_is_only_described_as_signed_when_something_signed_it() {
    assert_eq!(digest_label(true), "Digest that was signed");
    // A rejected request sits under an explanation reading "no signature was
    // ever produced". The row beneath it used to say the digest was signed.
    assert_eq!(digest_label(false), "Digest this would have signed");
}

#[test]
fn removing_an_account_puts_the_danger_on_the_button_that_destroys_the_key() {
    // Approving is normally the permissive choice, so reject carries the red.
    // Account removal inverts that: approving destroys a key that cannot be
    // recovered, and the red used to sit on the button that keeps it.
    let removal = review_decision_labels(Some(&ActiveReviewCompletion::AccountRemoval {
        wallet: WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        },
    }));
    assert!(removal.approve_is_destructive);
    assert_eq!(removal.approve, "Authenticate & remove");
    assert_eq!(removal.reject, "Keep this account");

    let transaction = review_decision_labels(None);
    assert!(!transaction.approve_is_destructive);
    assert_eq!(transaction.approve, "Authenticate & approve");
    assert_eq!(transaction.reject, "Reject request");
}
