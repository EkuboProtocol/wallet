use super::*;
use ekubo_wallet_core::approval::{ApprovalKind, ApprovalRequest};

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
fn agent_session_expiry_labels_active_expired_and_missing_sessions() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-08-11T14:30:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let future = now + chrono::Duration::days(1);
    let past = now - chrono::Duration::minutes(1);

    assert_eq!(
        agent_session_expiry_label(Some(future), now),
        ("Expires Aug 12, 2026 at 14:30 UTC".into(), false)
    );
    assert_eq!(
        agent_session_expiry_label(Some(past), now),
        ("Expired Aug 11, 2026 at 14:29 UTC".into(), true)
    );
    assert_eq!(
        agent_session_expiry_label(None, now),
        ("No active session (expired or not completed)".into(), true)
    );
}

#[test]
fn revoked_and_optimistically_hidden_agent_sessions_are_not_rendered() {
    let active_id = uuid::Uuid::new_v4();
    let hidden_id = uuid::Uuid::new_v4();
    let revoked_id = uuid::Uuid::new_v4();
    let client = |id, revoked_at| McpClient {
        id,
        display_name: "Agent".into(),
        agent_kind: AgentKind::Codex,
        registration: None,
        created_at: chrono::Utc::now(),
        authorized_at: Some(chrono::Utc::now()),
        last_used_at: None,
        session_expires_at: None,
        revoked_at,
    };
    let clients = vec![
        client(active_id, None),
        client(hidden_id, None),
        client(revoked_id, Some(chrono::Utc::now())),
    ];
    let hidden = BTreeSet::from([hidden_id]);

    let visible = visible_agent_sessions(&clients, &hidden);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].id, active_id);
}

#[test]
fn every_supported_agent_has_a_copy_ready_oauth_login_instruction() {
    let expected = [
        (AgentKind::Codex, "codex mcp login ekubo-wallet"),
        (AgentKind::ClaudeCode, "claude mcp login ekubo-wallet"),
        (AgentKind::GeminiCli, "/mcp auth ekubo-wallet"),
        (AgentKind::Cursor, "cursor-agent mcp login ekubo-wallet"),
        (AgentKind::Opencode, "opencode mcp auth ekubo-wallet"),
    ];
    for (kind, command) in expected {
        assert_eq!(agent_login_instruction(kind).unwrap().command, command);
    }
    assert_eq!(agent_login_instruction(AgentKind::Other), None);
}

#[test]
fn login_instructions_only_include_installed_detected_agents() {
    let detected = AgentDetectionState::Ready(vec![
        DetectedAgent {
            kind: AgentKind::Codex,
            display_name: "Codex",
            config_path: "codex.toml".into(),
            installed: Ok(true),
        },
        DetectedAgent {
            kind: AgentKind::ClaudeCode,
            display_name: "Claude Code",
            config_path: "claude.json".into(),
            installed: Ok(false),
        },
        DetectedAgent {
            kind: AgentKind::Cursor,
            display_name: "Cursor",
            config_path: "cursor.json".into(),
            installed: Err("cannot inspect".into()),
        },
    ]);
    assert_eq!(
        installed_agent_login_instructions(&detected),
        vec![agent_login_instruction(AgentKind::Codex).unwrap()]
    );
}

#[test]
fn network_preset_search_prefers_exact_names_and_chain_ids() {
    let presets = ekubo_wallet_core::networks::known_networks();
    let configured = ekubo_wallet_core::config::default_networks();

    let by_chain = network_presets_for_display(presets, &configured, "8453", 10, false);
    assert_eq!(by_chain[0].config.chain_id, 8453);

    let by_name = network_presets_for_display(presets, &configured, "base", 10, false);
    assert_eq!(by_name[0].config.name, "base");
    assert!(
        by_name
            .iter()
            .all(|profile| { network_preset_match_rank(profile, "base").is_some() })
    );
}

#[test]
fn network_reset_preview_names_every_custom_or_modified_row() {
    let defaults = ekubo_wallet_core::config::default_networks();
    let mut configured = defaults.clone();
    configured[0].rpc_urls = vec!["https://owner-rpc.example".parse().unwrap()];
    configured.push(NetworkConfig {
        name: "owner-chain".into(),
        disabled: true,
        testnet: false,
        display_name: Some("Owner Chain".into()),
        aliases: Vec::new(),
        chain_id: 9_999_991,
        rpc_urls: vec!["https://owner-chain.example".parse().unwrap()],
        rpc_strategy: RpcStrategy::default(),
        max_gas_limit: None,
        max_fee_per_gas: None,
        native_currency: None,
        block_explorer_url: None,
        documentation_url: None,
    });

    let discarded = networks_discarded_by_default_reset(&configured, &defaults);
    assert!(discarded.contains(&configured[0].name));
    assert!(discarded.contains(&"owner-chain".to_owned()));
    assert_eq!(discarded.len(), 2);
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
        rpc_urls: displayed,
        native_currency_name: "Ether".into(),
        native_currency_symbol: "ETH".into(),
        native_currency_decimals: "18".into(),
        block_explorer_url: "https://explorer.example".into(),
        ..NetworkEditorDraft::default()
    };
    let (parsed, errors) = parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered);
    assert_eq!(errors, NetworkEditorErrors::default());
    assert_eq!(parsed.unwrap().rpc_urls, urls);
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

    let (network, errors) = parse_network_editor_draft(&draft, false, false, RpcStrategy::Ordered);
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
        chain_mode: GuidedLiteralMode::Exact,
        chain_ids: "1".into(),
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
    let (document, policy) = update_guided_policy_rule(&document, None, &draft).unwrap();

    assert_eq!(policy.rules.len(), 1);
    assert_eq!(
        policy.rules[0].label.as_deref(),
        Some("Send a bounded amount to named recipients")
    );
    assert!(policy.rules[0].describe().contains("transfer"));

    let mut replacement = draft;
    replacement.effect = GuidedRuleEffect::Deny;
    replacement.label = "Never make this transfer".into();
    replacement.calldata_mode = GuidedCalldataMode::Empty;
    let (document, policy) = update_guided_policy_rule(&document, Some(0), &replacement).unwrap();
    assert_eq!(policy.rules.len(), 1);
    assert!(
        policy.rules[0]
            .describe()
            .starts_with("deny [Never make this transfer]")
    );

    let (document, policy) = remove_guided_policy_rule(&document, 0).unwrap();
    assert!(policy.rules.is_empty());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&document).unwrap()["rules"],
        serde_json::json!([])
    );
}

#[test]
fn guided_policy_rule_preserves_recursive_predicates_when_reopened() {
    let document = serde_json::to_string(&WalletPolicy::require_approval_for_everything()).unwrap();
    let draft = GuidedPolicyRuleDraft {
        effect: GuidedRuleEffect::Allow,
        label: "Bounded mainnet transfer".into(),
        target_mode: GuidedLiteralMode::Predicate,
        targets: r#"{ "not": { "eq": "0x0000000000000000000000000000000000000000" } }"#.into(),
        chain_mode: GuidedLiteralMode::Predicate,
        chain_ids: r#"{ "any": [{ "eq": "1" }, { "eq": "8453" }] }"#.into(),
        value_mode: GuidedLiteralMode::Predicate,
        values: r#"{ "all": [{ "gte": "1" }, { "lte": "1000000000000000000" }] }"#.into(),
        calldata_mode: GuidedCalldataMode::Any,
        abi: String::new(),
        args: "{}".into(),
    };
    let (_, policy) = update_guided_policy_rule(&document, None, &draft).unwrap();
    let reopened = guided_rule_draft(&policy.rules[0]).unwrap();

    assert_eq!(reopened.target_mode, GuidedLiteralMode::Predicate);
    assert_eq!(reopened.chain_mode, GuidedLiteralMode::Predicate);
    assert_eq!(reopened.value_mode, GuidedLiteralMode::Predicate);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&reopened.values).unwrap(),
        serde_json::json!({ "all": [{ "gte": "1" }, { "lte": "1000000000000000000" }] })
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
        chain_mode: GuidedLiteralMode::Exact,
        chain_ids: "0x1234".into(),
        value_mode: GuidedLiteralMode::Exact,
        values: "one ether".into(),
        calldata_mode: GuidedCalldataMode::Selector,
        abi: String::new(),
        args: "[]".into(),
    };

    let errors = update_guided_policy_rule(&document, None, &draft).unwrap_err();
    assert!(errors.label.is_some());
    assert!(errors.targets.is_some());
    assert!(errors.chain_ids.is_some());
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
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.rules[0].effect, Effect::Allow);
    assert!(policy.rules[0].chain_id.is_none());
    assert!(policy.rules[0].to.is_none());
    assert!(policy.rules[0].native_value.is_none());
    assert!(policy.rules[0].calldata.is_none());
}

#[test]
fn disable_signing_preset_is_one_unconditional_deny() {
    let (document, policy) = disable_signing_policy_document().unwrap();
    let reparsed = WalletPolicy::parse(serde_json::from_str(&document).unwrap()).unwrap();

    assert_eq!(policy, reparsed);
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
    assert_eq!(Route::ALL.first(), Some(&Route::Activity));
    assert_eq!(Route::Activity.label(), "Inbox");
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
fn selectable_plain_text_escapes_markdown_without_changing_visible_content() {
    assert_eq!(
        markdown_escape_plain_text("Account_#1 [0xabc].").as_ref(),
        r"Account\_\#1 \[0xabc\]\."
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
