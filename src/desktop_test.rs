use super::*;

#[test]
fn window_title_uses_the_exact_compiled_build_version() {
    assert_eq!(
        wallet_window_title(),
        format!("Ekubo Wallet {}", env!("EKUBO_WALLET_BUILD_VERSION"))
    );
}

#[test]
fn shutdown_timeout_is_created_inside_the_tokio_runtime() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a Tokio runtime");
    let handle = runtime.handle().clone();

    let value = std::thread::spawn(move || {
        block_on_with_timeout(&handle, Duration::from_millis(10), async { 42 })
    })
    .join()
    .expect("the desktop shutdown thread must not panic")
    .expect("the ready shutdown future must finish before its timeout");

    assert_eq!(value, 42);
}

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

#[test]
fn close_window_binding_matches_the_platform_convention() {
    let binding = close_window_key_binding();
    #[cfg(target_os = "macos")]
    let shortcut = "cmd-w";
    #[cfg(target_os = "linux")]
    let shortcut = "ctrl-w";
    #[cfg(target_os = "windows")]
    let shortcut = "alt-f4";
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let shortcut = "ctrl-w";
    let keystroke = gpui::Keystroke::parse(shortcut).expect("a valid platform shortcut");

    assert_eq!(binding.match_keystrokes(&[keystroke]), Some(false));
    assert!(binding.action().as_any().is::<CloseWindow>());
}

struct EmptyWindow;

impl Render for EmptyWindow {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
    }
}

#[gpui::test]
fn close_window_action_removes_the_active_window(cx: &mut gpui::TestAppContext) {
    let window = cx.update(|cx| {
        cx.on_action(close_active_window);
        let window = cx
            .open_window(WindowOptions::default(), |_, cx| cx.new(|_| EmptyWindow))
            .expect("a test window");
        window
            .update(cx, |_, window, _| window.activate_window())
            .expect("the test window activates");
        cx.dispatch_action(&CloseWindow);
        window
    });
    cx.run_until_parked();

    assert!(
        window.update(cx, |_, _, _| ()).is_err(),
        "the close action must remove the active window"
    );
}
use ekubo_wallet_core::approval::{ApprovalKind, ApprovalRequest};
use ekubo_wallet_core::core::policy::Effect;

#[test]
fn json_editor_build_includes_a_real_syntax_grammar() {
    let json = gpui_component::highlighter::LanguageRegistry::singleton()
        .language("json")
        .expect("the packaged wallet must register JSON highlighting");
    assert!(
        json.has_grammar(),
        "JSON editor mode must not silently fall back to plain text"
    );
}

#[test]
fn previous_policy_revision_stops_at_the_oldest_revision() {
    assert_eq!(latest_policy_revision(0), None);
    assert_eq!(latest_policy_revision(1), Some(0));
    assert_eq!(latest_policy_revision(6), Some(5));
    assert_eq!(previous_policy_revision(Some(0), 1), None);
    assert_eq!(previous_policy_revision(Some(1), 3), Some(0));
    assert_eq!(previous_policy_revision(Some(2), 3), Some(1));
    assert_eq!(previous_policy_revision(None, 3), Some(2));
}

#[test]
fn reopening_policies_keeps_the_selected_account_when_it_still_exists() {
    let account = |id: &str| WalletMetadata {
        instance_id: uuid::Uuid::new_v4(),
        id: id.to_owned(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    };
    let accounts = vec![account("primary"), account("company")];

    assert_eq!(
        policy_account_to_open(&accounts, Some("company")),
        Some("company")
    );
    assert_eq!(
        policy_account_to_open(&accounts, Some("removed")),
        Some("primary")
    );
    assert_eq!(policy_account_to_open(&[], Some("company")), None);
}

#[test]
fn policy_editor_header_explains_purpose_without_repeating_picker_context() {
    assert_eq!(
        POLICY_EDITOR_DESCRIPTION,
        "Requests are automatically signed, refused or require review according to the account policy"
    );
    assert!(!POLICY_EDITOR_DESCRIPTION.contains("Account"));
    assert!(!POLICY_EDITOR_DESCRIPTION.contains("revision"));
}

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
fn structured_network_editor_builds_the_complete_network_configuration() {
    let draft = NetworkEditorDraft {
        name: "owner-chain".into(),
        display_name: "Owner Chain".into(),
        aliases: "owner, owner_test".into(),
        chain_id: "9999991".into(),
        finality_confirmations: "6".into(),
        rpc_urls: "https://rpc-one.example,\nhttps://rpc-two.example".into(),
        native_currency_name: "Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        documentation_url: "https://docs.example/network".into(),
    };

    let (network, errors) = parse_network_editor_draft(&draft, true, true, RpcStrategy::Random);
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
        finality_confirmations: "3".into(),
        rpc_urls: displayed,
        native_currency_name: "Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        documentation_url: "https://docs.example".into(),
        ..NetworkEditorDraft::default()
    };
    let (parsed, errors) = parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered);
    assert_eq!(errors, NetworkEditorErrors::default());
    assert_eq!(parsed.unwrap().rpc_urls, urls);
}

/// The value was carried through the editor untouched and shown nowhere, so
/// every network ran on whatever the build's constant happened to be.
#[test]
fn structured_network_editor_takes_finality_confirmations_from_the_owner() {
    let draft = NetworkEditorDraft {
        name: "owner-chain".into(),
        chain_id: "9001".into(),
        finality_confirmations: "1".into(),
        rpc_urls: "https://rpc.example".into(),
        native_currency_name: "Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        documentation_url: "https://docs.example".into(),
        ..NetworkEditorDraft::default()
    };
    let (network, errors) = parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered);
    assert_eq!(errors, NetworkEditorErrors::default());
    assert_eq!(network.unwrap().finality_confirmations, 1);

    // The editor must refuse exactly what the config loader refuses, so a
    // saved network is never one core would reject on the next launch.
    for rejected in ["0", "1001", "", "3.5", "-1", "twelve"] {
        let draft = NetworkEditorDraft {
            finality_confirmations: rejected.into(),
            ..draft.clone()
        };
        let (network, errors) =
            parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered);
        assert!(network.is_none(), "{rejected} was accepted");
        assert!(
            errors.finality_confirmations.is_some(),
            "{rejected} produced no error"
        );
    }
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

    let (network, errors) = parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered);

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
        native_currency_name: "Ether".into(),
        ..NetworkEditorDraft::default()
    };

    let (network, errors) = parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered);
    assert!(network.is_none());
    assert!(errors.name.is_some());
    assert!(errors.chain_id.is_some());
    assert!(errors.rpc_urls.is_some());
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

    navigation.receive(NotificationRoute::Review {
        subject: NotificationSubject::Transaction,
        request_id,
    });

    assert_eq!(navigation.take(true), None);
    assert_eq!(
        navigation.take(false),
        Some(NotificationRoute::Review {
            subject: NotificationSubject::Transaction,
            request_id,
        })
    );
    assert_eq!(navigation.take(false), None);
}

#[test]
fn the_latest_notification_click_supersedes_an_unopened_destination() {
    let earlier = uuid::Uuid::new_v4();
    let latest = uuid::Uuid::new_v4();
    let mut navigation = NotificationNavigation::default();

    navigation.receive(NotificationRoute::Review {
        subject: NotificationSubject::Transaction,
        request_id: earlier,
    });
    navigation.receive(NotificationRoute::Activity {
        subject: NotificationSubject::Message,
        request_id: latest,
    });

    assert_eq!(
        navigation.take(false),
        Some(NotificationRoute::Activity {
            subject: NotificationSubject::Message,
            request_id: latest,
        })
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
    assert_eq!(Route::ALL.len(), 9);
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
fn the_network_editor_stops_an_inset_short_of_both_edges() {
    for height in [420.0, 600.0, 900.0, 1440.0, 2160.0] {
        let viewport = gpui::size(px(1400.0), px(height));
        let metrics = network_editor_metrics(viewport);

        assert!(
            metrics.top > px(0.0),
            "the dialog must not start at the top edge in a {height}px window"
        );
        assert!(
            metrics.top + metrics.max_height < viewport.height,
            "the dialog must end above the bottom edge in a {height}px window: \
             {:?} + {:?}",
            metrics.top,
            metrics.max_height
        );
        assert_eq!(
            viewport.height - (metrics.top + metrics.max_height),
            metrics.top,
            "what is left under the dialog must match the inset above it in a \
             {height}px window"
        );
    }
}

#[test]
fn a_taller_window_lets_the_network_editor_grow() {
    // The ceiling is the window, not a number: whatever height the form comes
    // to, a display with the room for it must be allowed to show it.
    let short = network_editor_metrics(gpui::size(px(1400.0), px(900.0)));
    let tall = network_editor_metrics(gpui::size(px(1400.0), px(2160.0)));

    assert!(
        tall.max_height > short.max_height + px(1000.0),
        "a window 1260px taller must raise the ceiling by about as much: \
         {:?} against {:?}",
        tall.max_height,
        short.max_height
    );
}

#[test]
fn networks_list_enabled_first_then_alphabetically_ignoring_case() {
    let mut networks = ekubo_wallet_core::networks::default_networks();
    for network in &mut networks {
        network.disabled = network.chain_id != 42_161;
    }
    // A byte comparison puts every capital ahead of every lowercase letter, so
    // these two labels are ordered one way by case and the other way by
    // alphabet. Only the alphabet may decide it.
    let mut visible_disabled = networks
        .iter_mut()
        .filter(|network| network.disabled && !network.testnet);
    visible_disabled.next().unwrap().display_name = Some("Zebra network".to_owned());
    visible_disabled.next().unwrap().display_name = Some("alpha network".to_owned());
    networks.reverse();

    let sorted = networks_for_display(&networks, false);
    let labels = sorted
        .iter()
        .map(|network| network_display_label(network).to_owned())
        .collect::<Vec<_>>();

    assert!(
        sorted
            .windows(2)
            .all(|pair| pair[0].disabled <= pair[1].disabled),
        "enabled networks come before disabled ones: {labels:?}"
    );
    assert!(
        sorted.windows(2).all(|pair| {
            pair[0].disabled != pair[1].disabled
                || network_display_label(pair[0]).to_lowercase()
                    <= network_display_label(pair[1]).to_lowercase()
        }),
        "each group is alphabetical ignoring case: {labels:?}"
    );
    assert!(
        labels.iter().position(|label| label == "alpha network")
            < labels.iter().position(|label| label == "Zebra network"),
        "case does not decide the order: {labels:?}"
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
fn gateway_status_only_exposes_an_actionable_failure_reason() {
    assert_eq!(McpGatewayStatus::Starting.detail(), None);
    assert_eq!(McpGatewayStatus::Online.detail(), None);

    let offline = McpGatewayStatus::Offline("address already in use".into());
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
        next_overflow_indicator_offset(px(-900.0), px(1_000.0), px(400.0), 1),
        px(-1_000.0)
    );
    assert_eq!(
        next_overflow_indicator_offset(px(-200.0), px(1_000.0), px(400.0), 1),
        px(-488.0)
    );
    assert_eq!(
        next_overflow_indicator_offset(px(-200.0), px(2_000.0), px(400.0), 4),
        px(-1_352.0)
    );
}

#[test]
fn overflow_indicator_rapid_presses_double_until_the_burst_expires() {
    let start = std::time::Instant::now();
    let mut paging = OverflowPagingState::default();
    let maximum = px(5_000.0);
    let viewport = px(400.0);
    assert_eq!(
        paging.begin_press(start, px(-200.0), maximum, viewport).0,
        px(-488.0)
    );
    assert_eq!(paging.multiplier, 1);
    assert_eq!(
        paging
            .begin_press(
                start + Duration::from_millis(300),
                px(-240.0),
                maximum,
                viewport,
            )
            .0,
        px(-1_064.0),
        "a rapid second press must accumulate from the first destination"
    );
    assert_eq!(paging.multiplier, 2);
    assert_eq!(
        paging
            .begin_press(
                start + Duration::from_millis(650),
                px(-500.0),
                maximum,
                viewport,
            )
            .0,
        px(-2_216.0)
    );
    assert_eq!(paging.multiplier, 4);
    assert_eq!(
        paging
            .begin_press(
                start + Duration::from_millis(1_051),
                px(-800.0),
                maximum,
                viewport,
            )
            .0,
        px(-1_088.0),
        "the next press after more than 400 ms starts a fresh 1x burst from the live offset"
    );
    assert_eq!(paging.multiplier, 1);
}

#[test]
fn overflow_indicator_is_static_and_reaches_full_opacity_on_hover() {
    assert!((overflow_indicator_opacity(false) - 0.82).abs() < f32::EPSILON);
    assert!((overflow_indicator_opacity(true) - 1.0).abs() < f32::EPSILON);
}

#[test]
fn overflow_indicator_does_not_schedule_a_continuous_redraw_loop() {
    let source = include_str!("desktop.rs");
    let indicator = source
        .split_once("impl Render for ScrollOverflowIndicatorView")
        .expect("overflow indicator view exists")
        .1
        .split_once("struct ScrollOverflowIndicator")
        .expect("overflow indicator view has an end marker")
        .0;
    // The one remaining task is the finite, user-triggered click animation.
    // Merely showing the affordance must not start a self-scheduling task.
    assert_eq!(indicator.matches(".spawn(").count(), 1);
    assert!(!indicator.contains("animation_frame_pending"));
    assert!(!indicator.contains("animation_started_at"));
    assert!(!indicator.contains("request_animation_frame"));
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
    assert!(detail_overlay.contains("variable_detail_list"));
    assert!(detail_overlay.contains("activity-detail-list"));
    assert!(detail_overlay.contains("self.activity_detail_overflow_indicator.element()"));
}

#[test]
fn large_transaction_details_keep_every_call_as_a_virtual_row() {
    const CALLS: usize = 4_096;
    let mut request = ekubo_wallet_core::approval::ApprovalRequest::new(
        ekubo_wallet_core::approval::ApprovalKind::Transaction,
        "Large transaction",
        "Every call remains inspectable.",
    )
    .fact("Wallet", "main")
    .warning("Review every action before relying on this record.");
    for index in 0..CALLS {
        request = request
            .section_kind(ApprovalSectionKind::Action, format!("Call {index}"))
            .fact("What it does", format!("Action {index}"));
    }
    // Effects sort before actions even when the authored document placed them
    // last; virtualization must preserve that display ordering as well as all
    // 4,096 individual action cards.
    request = request
        .section_kind(ApprovalSectionKind::Effects, "Effects")
        .fact("Result", "No balance changes");
    let document = ReviewDocument::from_request(request, vec!["{}".to_owned()]);

    let rows = transaction_activity_detail_rows(&document, false);
    assert_eq!(rows.first(), Some(&TransactionActivityDetailRow::Prelude));
    assert_eq!(
        rows.get(1),
        Some(&TransactionActivityDetailRow::Section(CALLS))
    );
    assert_eq!(
        rows.iter()
            .filter(
                |row| matches!(row, TransactionActivityDetailRow::Section(index) if *index < CALLS)
            )
            .count(),
        CALLS
    );
    assert!(rows.contains(&TransactionActivityDetailRow::WarningsHeading));
    assert!(rows.contains(&TransactionActivityDetailRow::Warning(0)));
    assert!(rows.contains(&TransactionActivityDetailRow::RecordKeeping));
    assert_eq!(
        rows.last(),
        Some(&TransactionActivityDetailRow::ExactPayloadDisclosure)
    );

    let list = virtual_review_detail_list(rows.len());
    assert_eq!(list.item_count(), CALLS + 6);

    let review_rows = security_review_detail_rows(&document, false);
    assert_eq!(review_rows.first(), Some(&SecurityReviewDetailRow::Prelude));
    assert_eq!(
        review_rows.get(1),
        Some(&SecurityReviewDetailRow::Section(CALLS))
    );
    assert_eq!(
        review_rows
            .iter()
            .filter(|row| matches!(row, SecurityReviewDetailRow::Section(index) if *index < CALLS))
            .count(),
        CALLS
    );
    assert!(review_rows.contains(&SecurityReviewDetailRow::WarningsHeading));
    assert!(review_rows.contains(&SecurityReviewDetailRow::Warning(0)));
    assert!(review_rows.contains(&SecurityReviewDetailRow::RequestDetails));
    assert!(review_rows.contains(&SecurityReviewDetailRow::ExactDataHeading));
    assert!(review_rows.contains(&SecurityReviewDetailRow::ExactPayloadHeading(0)));
    assert!(matches!(
        review_rows.last(),
        Some(SecurityReviewDetailRow::ExactPayloadChunk {
            payload_index: 0,
            start: 0,
            end: 2,
        })
    ));
    let review_list = virtual_review_detail_list(review_rows.len());
    assert_eq!(review_list.item_count(), CALLS + 8);
}

#[test]
fn exact_payload_chunks_are_utf8_safe_complete_and_virtual_rows_when_expanded() {
    let payload = format!(
        "{}\n{}\n{}",
        "x".repeat(EXACT_PAYLOAD_CHUNK_BYTES - 3),
        "🦀".repeat(EXACT_PAYLOAD_CHUNK_BYTES),
        "tail"
    );
    let ranges = exact_payload_chunk_ranges(&payload);
    assert!(ranges.len() > 3);
    assert_eq!(ranges.first().map(|range| range.0), Some(0));
    assert_eq!(ranges.last().map(|range| range.1), Some(payload.len()));
    assert!(ranges.windows(2).all(|pair| pair[0].1 == pair[1].0));
    assert!(ranges.iter().all(|(start, end)| {
        payload.is_char_boundary(*start)
            && payload.is_char_boundary(*end)
            && end - start <= EXACT_PAYLOAD_CHUNK_BYTES
    }));
    assert_eq!(
        ranges
            .iter()
            .map(|(start, end)| &payload[*start..*end])
            .collect::<String>(),
        payload
    );

    let document = ReviewDocument::from_request(
        ekubo_wallet_core::approval::ApprovalRequest::new(
            ekubo_wallet_core::approval::ApprovalKind::Transaction,
            "Large exact payload",
            "The exact payload is chunked only for rendering.",
        ),
        vec![payload],
    );
    let rows = transaction_activity_detail_rows(&document, true);
    assert_eq!(
        rows.iter()
            .filter(|row| matches!(row, TransactionActivityDetailRow::ExactPayloadChunk { .. }))
            .count(),
        ranges.len()
    );
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
    assert!(sidebar.contains(".position(tooltip_position)"));
    assert!(sidebar.contains(".bg(cx.theme().primary)"));
    assert!(!sidebar.contains(".tooltip("));
}

#[test]
fn sidebar_tooltip_uses_the_measured_button_right_center() {
    let bounds = gpui::Bounds::new(point(px(12.0), px(100.0)), size(px(48.0), px(48.0)));

    assert_eq!(sidebar_tooltip_position(bounds), point(px(70.0), px(124.0)));
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
        finality_confirmations: "3".into(),
        rpc_urls: seeded,
        native_currency_name: "Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        documentation_url: "https://docs.example/network".into(),
    };
    let (network, errors) = parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered);
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
fn a_permission_diff_is_read_by_the_direction_its_kernel_marked() {
    let rows = policy_diff_rows(&[
        "+ rule 1: starts allowing: to any address".to_owned(),
        "- rule 2: stops allowing: to 0xaaaa".to_owned(),
        "~ rule 3 changed: allow: to 0xaaaa → allow: to 0xbbbb".to_owned(),
        "No permission changes: the proposed policy is identical.".to_owned(),
    ]);

    // The marker is the kernel's own judgement about which way authority
    // moved — a `deny` that disappears is a widening — so the screen reads it
    // rather than inferring a second, possibly opposite, answer.
    assert_eq!(rows[0].direction, PolicyDiffDirection::Widens);
    assert_eq!(rows[0].summary, "rule 1: starts allowing: to any address");
    assert_eq!(rows[0].before, None);
    assert_eq!(rows[1].direction, PolicyDiffDirection::Narrows);

    // A rewritten rule arrives as two long, nearly identical sentences joined
    // by an arrow. Stacked and labelled they can be compared; on one line
    // they cannot.
    assert_eq!(rows[2].direction, PolicyDiffDirection::Rewrites);
    assert_eq!(rows[2].summary, "rule 3 changed");
    assert_eq!(rows[2].before.as_deref(), Some("allow: to 0xaaaa"));
    assert_eq!(rows[2].after.as_deref(), Some("allow: to 0xbbbb"));

    assert_eq!(rows[3].direction, PolicyDiffDirection::Unchanged);
    assert_eq!(
        rows[3].summary,
        "No permission changes: the proposed policy is identical."
    );
}

#[test]
fn the_change_summary_counts_each_direction_separately() {
    let rows = policy_diff_rows(&[
        "+ rule 1: starts allowing: to any address".to_owned(),
        "+ rule 2: stops denying: to 0xaaaa".to_owned(),
        "- rule 3: stops allowing: to 0xbbbb".to_owned(),
    ]);
    let summary = policy_change_summary(&rows);

    assert_eq!(
        summary,
        vec![
            (
                PolicyDiffDirection::Widens,
                "2 rules grant more authority".to_owned()
            ),
            (
                PolicyDiffDirection::Narrows,
                "1 rule grants less authority".to_owned()
            ),
        ],
        "widening is the direction that can cost the owner something, so it is \
         counted first"
    );

    assert_eq!(
        policy_change_summary(&policy_diff_rows(&[
            "No permission changes: the proposed policy is identical.".to_owned()
        ])),
        vec![(
            PolicyDiffDirection::Unchanged,
            "No permission changes".to_owned()
        )]
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

    // Approving a transaction is what sends it, and the button is the only
    // place the owner is told that before they press it.
    let (response, _receiver) = oneshot::channel();
    let transaction = review_decision_labels(Some(&ActiveReviewCompletion::Transaction(response)));
    assert!(!transaction.approve_is_destructive);
    assert_eq!(transaction.approve, "Authenticate & send");
    assert_eq!(transaction.reject, "Reject request");

    let other = review_decision_labels(None);
    assert!(!other.approve_is_destructive);
    assert_eq!(other.approve, "Authenticate & approve");
    assert_eq!(other.reject, "Reject request");
}

/// A session summary in whichever state a test needs, with the fields it does
/// not care about left at what `begin_uri` produces.
fn walletconnect_summary(id: uuid::Uuid, settled: bool) -> SessionSummary {
    SessionSummary {
        id,
        status: if settled {
            crate::walletconnect::SessionStatus::Connected
        } else {
            crate::walletconnect::SessionStatus::AwaitingProposal
        },
        active_requests: 0,
        dapp_name: None,
        last_error: None,
        expires_at: None,
        settled,
    }
}

#[test]
fn the_connect_button_spins_only_while_its_own_pairing_is_still_unsettled() {
    let pairing = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();

    // Still waiting on the dapp: the URI has been spent and a second press
    // would spend it again, so the button stays busy.
    assert!(walletconnect_pairing_is_in_flight(
        &[walletconnect_summary(pairing, false)],
        pairing
    ));
    // Settled — it is a connection now, and the list below draws it.
    assert!(!walletconnect_pairing_is_in_flight(
        &[walletconnect_summary(pairing, true)],
        pairing
    ));
    // Failed before settling, so the manager dropped it entirely. A spinner
    // that outlived this would never stop.
    assert!(!walletconnect_pairing_is_in_flight(&[], pairing));
    // Somebody else's unsettled pairing is not this button's business.
    assert!(!walletconnect_pairing_is_in_flight(
        &[walletconnect_summary(other, false)],
        pairing
    ));
}

#[test]
fn a_dapp_connection_cannot_be_approved_before_an_account_is_chosen() {
    // A connection can go on to propose transactions that policy signs
    // without a second review, so "which account" is not a question with a
    // sensible default.
    let (response, _receiver) = oneshot::channel();
    assert!(!review_selection_is_complete(Some(
        &ActiveReviewCompletion::WalletConnect {
            choices: Vec::new(),
            selected_account: None,
            response,
        }
    )));

    let (response, _receiver) = oneshot::channel();
    assert!(review_selection_is_complete(Some(
        &ActiveReviewCompletion::WalletConnect {
            choices: Vec::new(),
            selected_account: Some(0),
            response,
        }
    )));

    // Every other review answers its own question by existing.
    assert!(review_selection_is_complete(None));
}

fn setup_account(id: &str) -> WalletMetadata {
    WalletMetadata {
        instance_id: uuid::Uuid::new_v4(),
        id: id.to_owned(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    }
}

fn setup_policies(
    account: &WalletMetadata,
    policy: WalletPolicy,
) -> BTreeMap<String, std::result::Result<Option<StoredPolicy>, SharedString>> {
    let mut policies = BTreeMap::new();
    policies.insert(
        account.id.clone(),
        Ok(Some(StoredPolicy {
            wallet_instance_id: account.instance_id,
            wallet_id: account.id.clone(),
            wallet_address: account.address,
            policy,
            revision: 1,
            updated_at: chrono::Utc::now(),
        })),
    );
    policies
}

fn setup_message(status: MessageStatus) -> OwnerActivityRecord {
    OwnerActivityRecord::Message(ekubo_wallet_core::message::PendingMessage {
        request_id: uuid::Uuid::new_v4(),
        wallet_instance_id: uuid::Uuid::new_v4(),
        wallet_id: "trading".into(),
        wallet_address: alloy::primitives::Address::ZERO,
        chain_id: None,
        message_hex: "0x68690a".into(),
        encoding: ekubo_wallet_core::message::MessageEncoding::Text,
        digest: "0xabc".into(),
        status,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        approved_at: None,
        rejected_at: None,
        signature: None,
        requester: None,
    })
}

fn setup_agents(installed: bool) -> AgentDetectionState {
    AgentDetectionState::Ready(vec![DetectedAgent {
        kind: AgentKind::ClaudeCode,
        display_name: "Claude Code",
        config_path: "/tmp/config.json".into(),
        installed: Ok(installed),
    }])
}

#[test]
fn a_fresh_install_has_finished_none_of_the_setup() {
    let observation = observe_setup(
        None,
        &BTreeMap::new(),
        None,
        &AgentDetectionState::Loading,
        &[],
    );

    assert_eq!(observation, SetupObservation::default());
    for task in SetupTask::ALL {
        assert!(!observation.holds(task), "{task:?} cannot already be done");
    }
}

#[test]
fn the_default_deny_everything_policy_does_not_count_as_relaxing_one() {
    // Every account is installed with `require_approval_for_everything`. If
    // that satisfied the task, the checklist would tick a box for something
    // the owner never did — and would be saying an agent may transact on its
    // own at the exact moment nothing may.
    let account = setup_account("trading");
    let observation = observe_setup(
        Some(std::slice::from_ref(&account)),
        &setup_policies(&account, WalletPolicy::require_approval_for_everything()),
        None,
        &AgentDetectionState::Loading,
        &[],
    );

    assert!(observation.account);
    assert!(!observation.policy);
}

#[test]
fn any_policy_other_than_the_installed_default_finishes_the_policy_task() {
    let account = setup_account("trading");
    let observation = observe_setup(
        Some(std::slice::from_ref(&account)),
        &setup_policies(&account, WalletPolicy::allow_anything()),
        None,
        &AgentDetectionState::Loading,
        &[],
    );

    assert!(observation.policy);
}

#[test]
fn a_signature_request_only_counts_once_it_has_been_decided() {
    // The step being taught is the review, not the arrival. A request sitting
    // in the inbox is the moment before the thing worth seeing.
    let waiting = observe_setup(
        None,
        &BTreeMap::new(),
        Some(&[setup_message(MessageStatus::AwaitingApproval)]),
        &AgentDetectionState::Loading,
        &[],
    );
    assert!(!waiting.signature);

    for decided in [MessageStatus::Signed, MessageStatus::Rejected] {
        let observation = observe_setup(
            None,
            &BTreeMap::new(),
            Some(&[setup_message(decided)]),
            &AgentDetectionState::Loading,
            &[],
        );
        // Refusing one teaches exactly what approving one does: that the
        // decision is yours and nothing happens without it.
        assert!(observation.signature, "{decided:?} should finish the task");
    }
}

#[test]
fn an_unsettled_pairing_is_not_a_connected_dapp() {
    // Everything before settlement is a pairing with a stranger.
    let pairing = observe_setup(
        None,
        &BTreeMap::new(),
        None,
        &AgentDetectionState::Loading,
        &[walletconnect_summary(uuid::Uuid::new_v4(), false)],
    );
    assert!(!pairing.dapp);

    let connected = observe_setup(
        None,
        &BTreeMap::new(),
        None,
        &AgentDetectionState::Loading,
        &[walletconnect_summary(uuid::Uuid::new_v4(), true)],
    );
    assert!(connected.dapp);
}

#[test]
fn an_agent_counts_only_once_this_wallet_is_in_its_configuration() {
    let detected_but_empty = observe_setup(None, &BTreeMap::new(), None, &setup_agents(false), &[]);
    assert!(!detected_but_empty.agent);

    let installed = observe_setup(None, &BTreeMap::new(), None, &setup_agents(true), &[]);
    assert!(installed.agent);
}

#[test]
fn a_finished_task_stays_finished_when_the_state_behind_it_goes_away() {
    // A dapp closing its tab ends the session, and history can be cleared.
    // Neither undoes having done the thing once, and a box that unticks
    // itself reads as a bug rather than as news.
    let mut setup = GuidedSetup::loaded(GuidedSetupState::default());
    assert!(setup.latch(SetupObservation {
        dapp: true,
        ..SetupObservation::default()
    }));
    assert!(setup.is_complete(SetupTask::ConnectDapp));

    assert!(!setup.latch(SetupObservation::default()));
    assert!(setup.is_complete(SetupTask::ConnectDapp));
    assert_eq!(setup.completed_count(), 1);
}

#[test]
fn the_card_stays_up_until_every_task_is_done_or_it_is_sent_away() {
    let mut setup = GuidedSetup::loaded(GuidedSetupState::default());
    assert!(setup.visible());

    setup.latch(SetupObservation {
        account: true,
        agent: true,
        signature: true,
        dapp: true,
        policy: false,
    });
    assert!(
        setup.visible(),
        "four of five is not finished, however far along it looks"
    );

    setup.latch(SetupObservation {
        account: true,
        agent: true,
        signature: true,
        dapp: true,
        policy: true,
    });
    assert!(!setup.visible());
    assert_eq!(setup.completed_count(), SetupTask::ALL.len());
}

#[test]
fn dismissal_lasts_the_run_and_still_records_what_the_run_saw() {
    let mut setup = GuidedSetup::loaded(GuidedSetupState::default());
    setup.dismiss();
    assert!(!setup.visible());

    // The evidence for a task can be gone by the next launch — a session
    // ends, a history is cleared — so a dismissed card has to keep watching.
    assert!(setup.latch(SetupObservation {
        dapp: true,
        ..SetupObservation::default()
    }));
    assert!(!setup.visible(), "dismissal holds for the rest of the run");
    assert!(setup.is_complete(SetupTask::ConnectDapp));
}

#[test]
fn the_checklist_starts_over_at_the_next_launch_while_anything_is_left() {
    let mut run = GuidedSetup::loaded(GuidedSetupState::default());
    run.latch(SetupObservation {
        account: true,
        ..SetupObservation::default()
    });
    run.dismiss();
    let stored = run.state.clone().expect("the run had its progress loaded");

    // Whatever a run does to the card, the next one reads only the finished
    // tasks back — which is what makes dismissal "not now" rather than
    // "never again".
    let relaunched = GuidedSetup::loaded(stored);
    assert!(relaunched.visible());
    assert_eq!(relaunched.completed_count(), 1);
}

#[test]
fn a_finished_checklist_does_not_come_back() {
    let mut run = GuidedSetup::loaded(GuidedSetupState::default());
    run.latch(SetupObservation {
        account: true,
        agent: true,
        signature: true,
        dapp: true,
        policy: true,
    });
    let stored = run.state.clone().expect("the run had its progress loaded");

    assert!(!GuidedSetup::loaded(stored).visible());
}

#[test]
fn nothing_is_drawn_or_recorded_until_the_stored_progress_is_read() {
    // Defaulting an unreadable store would show an empty checklist to
    // somebody who has finished it, at every launch rather than once, and
    // storing the result would overwrite the progress it failed to read.
    let mut unread = GuidedSetup::unloaded();
    assert!(!unread.visible(), "an unread checklist draws nothing");
    assert!(!unread.latch(SetupObservation {
        account: true,
        ..SetupObservation::default()
    }));
    assert_eq!(unread.completed_count(), 0);
    assert!(!unread.is_complete(SetupTask::CreateAccount));

    unread.load(GuidedSetupState::default());
    assert!(unread.visible());
}

#[test]
fn the_guided_setup_card_fits_across_every_window_the_wallet_can_be_dragged_to() {
    // 660x500 is the window minimum, so it is the smallest the card ever has
    // to survive, and the card is pinned 20px off two edges.
    for (width, height) in [(660.0, 500.0), (960.0, 650.0), (1400.0, 900.0)] {
        let viewport = gpui::size(px(width), px(height));

        assert!(
            guided_setup_width(viewport) + px(40.0) <= viewport.width,
            "the card is wider than a {width}x{height} window: {:?}",
            guided_setup_width(viewport)
        );
    }
}

#[test]
fn a_roomy_window_does_not_make_the_guided_setup_card_enormous() {
    // The card is an aside, not the page: past the point where a task reads
    // comfortably, more window is not more checklist.
    let huge = guided_setup_width(gpui::size(px(3840.0), px(2160.0)));

    assert_eq!(huge, px(400.0));
    assert!(guided_setup_width(gpui::size(px(960.0), px(650.0))) <= huge);
}

#[test]
fn nothing_on_the_guided_setup_card_scrolls() {
    // A card in the corner that has to be scrolled to be read is a card
    // arguing with the page behind it over the wheel. It is kept short enough
    // not to need one instead, so a scroll box reappearing here is the
    // regression, not the fix.
    let source = include_str!("desktop.rs");
    let card = source
        .split_once("fn render_guided_setup")
        .expect("guided setup card exists")
        .1
        .split_once("impl Render for WalletWindow")
        .expect("guided setup card has an end marker")
        .0;

    assert_eq!(card.matches("overflow_y_scroll()").count(), 0);
    assert_eq!(card.matches("overflow_x_scroll()").count(), 0);
    assert_eq!(card.matches("track_scroll(").count(), 0);
    // A height cap with nothing scrolling behind it is silent clipping: the
    // card takes the height its content comes to, and the content is what is
    // kept short.
    assert_eq!(card.matches("max_h(").count(), 0);
}

#[test]
fn only_the_task_up_next_is_explained() {
    // Every explanation at once does not fit the smallest window, and the
    // card has nowhere to put the overflow now that it does not scroll.
    let mut setup = GuidedSetup::loaded(GuidedSetupState::default());
    assert_eq!(setup.next_task(), Some(SetupTask::CreateAccount));

    setup.latch(SetupObservation {
        account: true,
        ..SetupObservation::default()
    });
    assert_eq!(setup.next_task(), Some(SetupTask::InstallAgent));

    setup.latch(SetupObservation {
        account: true,
        agent: true,
        signature: true,
        dapp: true,
        policy: true,
    });
    assert_eq!(
        setup.next_task(),
        None,
        "a finished checklist has nothing up next"
    );
}

#[test]
fn folding_the_card_keeps_it_while_dismissal_sends_it_away() {
    // The two ways past the card are not the same one: folding gives the
    // corner back and keeps the checklist, so it must not take the card off
    // the screen the way dismissal does.
    let mut setup = GuidedSetup::loaded(GuidedSetupState::default());
    assert!(!setup.is_collapsed());

    setup.toggle_collapsed();
    assert!(setup.is_collapsed());
    assert!(
        setup.visible(),
        "a folded card is still on the screen, and still counting"
    );

    setup.toggle_collapsed();
    assert!(!setup.is_collapsed(), "the title opens it again");
    assert!(setup.visible());
}

#[test]
fn every_setup_task_has_a_distinct_stored_name_and_a_screen_to_go_to() {
    // The stored name is what survives a rename of the variant, so two tasks
    // sharing one would silently tick each other's box.
    let keys: std::collections::BTreeSet<&str> =
        SetupTask::ALL.iter().map(|task| task.key()).collect();
    assert_eq!(keys.len(), SetupTask::ALL.len());

    for task in SetupTask::ALL {
        assert!(!task.title().is_empty());
        assert!(!task.detail().is_empty());
        // Every row is a shortcut, so every task needs somewhere to send you.
        assert!(Route::ALL.contains(&task.route()));
    }
}
