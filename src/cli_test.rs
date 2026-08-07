//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn a_readable_message_still_shows_the_bytes_that_get_signed() {
    // Two messages that render identically after escaping: one holds a
    // real right-to-left override, the other the seven ASCII characters
    // that the escape of an override looks like. Only the hex tells the
    // reviewer which one they are signing.
    let real = "pay \u{202e}1".as_bytes();
    let literal = "pay \\u{202e}1".as_bytes();

    let rows = |bytes: &[u8]| {
        let hex = format!("0x{}", hex::encode(bytes));
        let display = crate::message::describe_message(bytes);
        let lines = message_payload_lines(&hex, &display);
        crate::fullscreen::lines_to_text(&lines, |text, _| text.to_owned())
    };

    let real_text = rows(real);
    let literal_text = rows(literal);
    assert!(real_text.contains("Exact bytes signed"), "{real_text}");
    assert_ne!(
        real_text, literal_text,
        "an override and its own escape rendered identically"
    );
    assert!(real_text.contains(&hex::encode(real)), "{real_text}");
}

#[test]
fn a_review_transcript_carries_nothing_that_can_redraw_a_terminal() {
    // serde_json escapes quotes, backslashes, and C0 controls. Everything
    // below is valid JSON string content and would reach the approver's
    // terminal intact: the override reverses what they read, the isolate
    // and the zero-width space hide inside it.
    let rendered = review_transcript_text(&serde_json::json!({
        "message": {
            "text": "pay \u{202e}0001\u{202c} to \u{2066}them\u{2069}",
            "symbol": "US\u{200b}DC",
        },
    }))
    .unwrap();
    for hostile in ['\u{202e}', '\u{202c}', '\u{2066}', '\u{2069}', '\u{200b}'] {
        assert!(
            !rendered.contains(hostile),
            "{hostile:?} survived into the transcript: {rendered}"
        );
    }
    // The transcript is still JSON, and still readable.
    assert!(rendered.contains("\"symbol\""));
}

#[test]
fn a_new_wallet_never_starts_permissive_by_accident() {
    // The tests run without a terminal, which is exactly the case that
    // must not quietly enable automatic signing: with nobody to ask, the
    // locked-down policy is taken rather than the convenient one.
    assert_eq!(
        resolve_starting_policy(None).unwrap(),
        Some(StartingPolicy::RequireApproval)
    );
    // An explicit flag is obeyed either way, including the permissive one.
    for chosen in [StartingPolicy::RequireApproval, StartingPolicy::AllowAll] {
        assert_eq!(resolve_starting_policy(Some(chosen)).unwrap(), Some(chosen));
    }
}

#[test]
fn the_two_starting_policies_are_the_profiles_they_name() {
    // A wallet that asked to require approval must not be able to sign
    // anything automatically, whatever the profile is called.
    let locked = StartingPolicy::RequireApproval.policy();
    assert_eq!(locked, WalletPolicy::require_approval_for_everything());
    assert_eq!(
        StartingPolicy::AllowAll.policy(),
        WalletPolicy::allow_all_with_approval()
    );
    assert_ne!(locked, StartingPolicy::AllowAll.policy());
}

#[test]
fn transaction_lines_render_offline() {
    let plan = crate::core::execution_plan::ExecutionPlan::parse(serde_json::json!({
        "schema_version": "1",
        "chain_id": "1",
        "caip2_chain_id": "eip155:1",
        "sender": "0x1111111111111111111111111111111111111111",
        "ordered_steps": [{
            "step": 1,
            "kind": "execution",
            "transaction": {
                "chain_id": "1",
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0xa9059cbb",
                "value": "5"
            }
        }]
    }))
    .unwrap();
    let now = chrono::Utc::now();
    let record = PendingTransaction {
        plan_source: None,
        request_id: Uuid::nil(),
        wallet_id: "primary".into(),
        network_name: "ethereum".into(),
        chain_id: "1".into(),
        digest: format!("{:#x}", plan.digest()),
        execution_plan: plan,
        review_digest: None,
        policy_revision: 3,
        approval_required: true,
        status: PendingStatus::AwaitingApproval,
        created_at: now - chrono::TimeDelta::minutes(7),
        updated_at: now - chrono::TimeDelta::minutes(7),
        approved_at: None,
        rejected_at: None,
        serialized_transaction: None,
        signed_transaction_hash: None,
        broadcast_transaction_hash: None,
        block_number: None,
        mined_fee: None,
        cancel_serialized_transaction: None,
        cancel_transaction_hashes: Vec::new(),
    };

    let line = transaction_line(&record);
    assert!(line.contains("7 minutes ago"));
    assert!(line.contains("awaiting approval"));
    assert!(line.contains("primary"));
    assert!(line.contains("1 call(s), 5 wei native"));
    // The piped listing keeps the whole request ID, because that is what
    // `transaction show` takes as an identifier.
    assert!(line.contains(&Uuid::nil().to_string()));

    // The approvals browser flattens every queue into rows whose Enter
    // action carries the right identifier, and its network column names
    // the chain rather than numbering it.
    let now = chrono::Utc::now();
    let typed = PendingTypedData {
        request_id: Uuid::from_u128(2),
        wallet_id: "primary".into(),
        chain_id: "1".into(),
        typed_data: serde_json::json!({}),
        digest: format!("0x{}", "cd".repeat(32)),
        status: TypedDataStatus::AwaitingApproval,
        created_at: now,
        updated_at: now,
        approved_at: None,
        rejected_at: None,
        signature: None,
    };
    let message = PendingMessage {
        request_id: Uuid::from_u128(3),
        wallet_id: "primary".into(),
        chain_id: None,
        message_hex: "0x68690a".into(),
        encoding: crate::message::MessageEncoding::Text,
        digest: format!("0x{}", "ef".repeat(32)),
        status: MessageStatus::AwaitingApproval,
        created_at: now,
        updated_at: now,
        approved_at: None,
        rejected_at: None,
        signature: None,
    };
    let proposal = crate::policy_store::PolicyProposal {
        wallet_id: "primary".into(),
        source_revision: 4,
        policy: WalletPolicy::require_approval_for_everything(),
        rationale: "allow the weekly compounding plan".into(),
        created_at: now,
    };
    let network_proposal = crate::config::NetworkConfig {
        name: "arbitrum".into(),
        display_name: None,
        aliases: Vec::new(),
        chain_id: 42_161,
        rpc_url: "https://example.invalid/rpc".parse().unwrap(),
        max_gas_limit: None,
        native_currency: None,
        block_explorer_url: None,
        documentation_url: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigStore::new(directory.path());
    let (rows, choices) = pending_approval_rows(
        &config,
        std::slice::from_ref(&record),
        std::slice::from_ref(&typed),
        std::slice::from_ref(&message),
        std::slice::from_ref(&proposal),
        std::slice::from_ref(&network_proposal),
    );
    assert_eq!(rows.len(), 5);
    assert_eq!(choices.len(), 5);
    // The default configuration names chain 1, so the row says
    // "ethereum" — the chain ID lives in the haystack instead.
    assert!(rows[0].haystack.contains("ethereum"));
    assert!(rows[0].haystack.contains(&Uuid::nil().to_string()));
    assert!(matches!(choices[0], PendingChoice::Request(id) if id == Uuid::nil()));
    assert!(matches!(choices[1], PendingChoice::Request(id) if id == Uuid::from_u128(2)));
    // A typed-data row is searchable by its EIP-712 digest.
    assert!(rows[1].haystack.contains(&format!("0x{}", "cd".repeat(32))));
    assert!(matches!(choices[2], PendingChoice::Request(id) if id == Uuid::from_u128(3)));
    // A proposal reviews per wallet, and its rationale is searchable.
    assert!(matches!(&choices[3], PendingChoice::Proposal(wallet) if wallet == "primary"));
    assert!(rows[3].haystack.contains("weekly compounding"));
    // A suggested network reviews per chain, and is searchable by the endpoint
    // being proposed — the URL is the whole decision for an edit.
    assert!(matches!(choices[4], PendingChoice::Network(chain) if chain == 42_161));
    assert!(rows[4].haystack.contains("example.invalid"));
    assert!(rows[4].haystack.contains("42161"));
}

#[test]
fn parses_transaction_network_and_completion_parity_commands() {
    let cli = Cli::try_parse_from([
        "ekubo-wallet",
        "transaction",
        "list",
        "primary",
        "--limit",
        "50",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Transaction(TransactionArgs {
            command: TransactionCommand::List {
                wallet_id: Some(ref wallet_id),
                limit: 50,
            },
        }) if wallet_id == "primary"
    ));
    let cli = Cli::try_parse_from(["ekubo-wallet", "completion", "zsh"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Completion { shell: Shell::Zsh }
    ));
    let cli = Cli::try_parse_from(["ekubo-wallet", "network", "presets"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Network(args) if matches!(args.command, NetworkCommand::Presets)
    ));
}

fn add_args(name: &str, chain_id: Option<u64>) -> NetworkAddArgs {
    NetworkAddArgs {
        name: Some(name.into()),
        chain_id,
        rpc_url: None,
        display_name: None,
        aliases: Vec::new(),
        native_currency_name: None,
        native_currency_symbol: None,
        native_currency_decimals: None,
        max_gas_limit: None,
        block_explorer_url: None,
        documentation_url: None,
    }
}

/// Resolves the candidate exactly as the `network add` arm does: the
/// name is taken out of the parsed arguments first.
fn candidate_of(mut args: NetworkAddArgs, configured: &[NetworkConfig]) -> Result<NetworkConfig> {
    let name = args
        .name
        .take()
        .expect("test arguments always carry a name");
    network_candidate(name, args, configured)
}

#[test]
fn editing_a_configured_network_only_needs_the_field_that_changes() {
    let mut configured = default_networks();
    let base = configured
        .iter_mut()
        .find(|network| network.name == "base")
        .unwrap();
    base.display_name = Some("My Base".into());
    base.max_gas_limit = Some("1234567".into());
    let configured = configured;

    let mut args = add_args("base", None);
    args.rpc_url = Some("https://rpc.example.invalid/base".parse().unwrap());
    let candidate = candidate_of(args, &configured).unwrap();

    assert_eq!(
        candidate.rpc_url.as_str(),
        "https://rpc.example.invalid/base"
    );
    // Everything the user did not name survives, including their own
    // earlier customizations rather than the preset's values.
    assert_eq!(candidate.display_name.as_deref(), Some("My Base"));
    assert_eq!(candidate.max_gas_limit.as_deref(), Some("1234567"));
    assert_eq!(candidate.chain_id, 8453);
    assert!(!candidate.aliases.is_empty());
}

#[test]
fn a_chain_id_names_its_own_network_so_add_never_asks_for_one() {
    // What `network add` asks first is the chain ID, and the answer is
    // only turned back into a name when nothing already holds that chain.
    let mut configured = default_networks();
    let base = configured
        .iter_mut()
        .find(|network| network.name == "base")
        .unwrap();
    base.rpc_url = "https://rpc.example.invalid/base".parse().unwrap();
    let configured = configured;

    let (known, origin) = network_for_chain(8453, &configured).unwrap();
    assert_eq!(known.name, "base");
    assert_eq!(origin, "configured as");
    // The configured endpoint is what the RPC prompt offers back, not the
    // shipped default it was changed away from.
    assert_eq!(known.rpc_url.as_str(), "https://rpc.example.invalid/base");

    let (preset, origin) = network_for_chain(8453, &[]).unwrap();
    assert_eq!(preset.name, "base");
    assert_eq!(origin, "the built-in preset");

    assert!(network_for_chain(987_654, &configured).is_none());
}

#[test]
fn an_alias_and_a_matching_chain_id_both_resolve_the_same_base() {
    let configured = default_networks();
    for (name, chain_id) in [("base-mainnet", None), ("base", Some(8453))] {
        let candidate = candidate_of(add_args(name, chain_id), &configured).unwrap();
        assert_eq!(candidate.name, "base");
        assert_eq!(candidate.chain_id, 8453);
    }
}

#[test]
fn preset_network_add_uses_complete_catalog_metadata() {
    let candidate = candidate_of(add_args("eth", None), &[]).unwrap();
    assert_eq!(candidate.name, "ethereum");
    assert_eq!(candidate.chain_id, 1);
    assert!(candidate.native_currency.is_some());
    assert!(candidate.max_gas_limit.is_some());
}

#[test]
fn an_unknown_network_without_a_chain_id_says_where_to_look() {
    let error = candidate_of(add_args("nowhere", None), &default_networks())
        .expect_err("an unknown name is not a network");
    let message = error.to_string();
    assert!(message.contains("network presets"), "{message}");
    assert!(message.contains("network list"), "{message}");
    assert!(message.contains("chain ID"), "{message}");
}

#[test]
fn a_new_custom_network_reports_every_missing_value_at_once() {
    // Non-interactive, so this is the scripted path: one error has to
    // name the complete set, or fixing it takes one run per flag.
    let error = candidate_of(add_args("custom", Some(987_654)), &default_networks())
        .expect_err("an incomplete custom network is rejected");
    let message = error.to_string();
    for flag in CUSTOM_NETWORK_FIELDS.iter().map(|field| field.flag) {
        assert!(message.contains(flag), "{flag} missing from:\n{message}");
    }
    assert!(message.contains("987654"), "{message}");
    // Every flag carries its own explanation and a usable example.
    assert!(message.contains("eth_simulateV1"), "{message}");
    assert!(message.contains("16777216"), "{message}");
}

#[test]
fn a_complete_custom_network_needs_no_terminal_at_all() {
    let mut args = add_args("custom", Some(987_654));
    args.rpc_url = Some("https://rpc.example.invalid".parse().unwrap());
    args.display_name = Some("Custom Chain".into());
    args.aliases = vec!["custom-chain".into()];
    args.native_currency_name = Some("Ether".into());
    args.native_currency_symbol = Some("ETH".into());
    args.native_currency_decimals = Some(18);
    args.max_gas_limit = Some("16777216".into());
    args.block_explorer_url = Some("https://explorer.example.invalid".parse().unwrap());
    args.documentation_url = Some("https://docs.example.invalid".parse().unwrap());
    let candidate = candidate_of(args, &default_networks()).unwrap();
    assert_eq!(candidate.chain_id, 987_654);
    assert_eq!(candidate.aliases, vec!["custom-chain".to_owned()]);
    assert_eq!(candidate.native_currency.unwrap().decimals, 18);
}

#[test]
fn every_editable_field_round_trips_through_its_own_validator() {
    // The edit menu re-prompts with the current value pre-filled; that
    // value must satisfy the field's validator and write back unchanged,
    // or editing an untouched field would corrupt the profile.
    let preset = || {
        default_networks()
            .into_iter()
            .find(|network| network.name == "base")
            .expect("base preset exists")
    };
    let mut network = preset();
    for field in CUSTOM_NETWORK_FIELDS {
        let current = network_field_value(&network, field.flag);
        assert!(
            validate_network_field(field.flag, &current).is_ok(),
            "{} rejects its own current value {current:?}",
            field.flag
        );
        set_network_field(&mut network, field.flag, &current).unwrap();
    }
    let untouched = preset();
    assert_eq!(network.chain_id, untouched.chain_id);
    assert_eq!(network.rpc_url, untouched.rpc_url);
    assert_eq!(network.aliases, untouched.aliases);
    assert_eq!(network.native_currency, untouched.native_currency);
}

#[test]
fn setting_network_fields_applies_each_typed_value() {
    let mut network = default_networks().remove(0);
    set_network_field(&mut network, "--rpc-url", "https://rpc.example.invalid").unwrap();
    assert_eq!(network.rpc_url.as_str(), "https://rpc.example.invalid/");
    set_network_field(&mut network, "--native-currency-decimals", "6").unwrap();
    assert_eq!(network.native_currency.clone().unwrap().decimals, 6);
    set_network_field(&mut network, "--alias", "one, two").unwrap();
    assert_eq!(network.aliases, vec!["one".to_owned(), "two".to_owned()]);
    set_network_field(&mut network, "--display-name", " Renamed ").unwrap();
    assert_eq!(network.display_name.as_deref(), Some("Renamed"));
    // A blank alias list cannot silently strand the network.
    assert!(set_network_field(&mut network, "--alias", "  ").is_err());
}

#[test]
fn prompt_validation_rejects_malformed_answers_before_the_next_question() {
    let field = |flag: &str| {
        CUSTOM_NETWORK_FIELDS
            .iter()
            .find(|field| field.flag == flag)
            .expect("declared field")
    };
    let rpc = field("--rpc-url").flag;
    assert!(validate_network_field(rpc, "https://rpc.example.invalid").is_ok());
    assert!(validate_network_field(rpc, "rpc.example.invalid").is_err());
    assert!(validate_network_field(rpc, "ftp://rpc.example.invalid").is_err());
    assert!(validate_network_field(rpc, "").is_err());

    let decimals = field("--native-currency-decimals").flag;
    assert!(validate_network_field(decimals, "18").is_ok());
    assert!(validate_network_field(decimals, "18.5").is_err());

    let gas = field("--max-gas-limit").flag;
    assert!(validate_network_field(gas, "16777216").is_ok());
    assert!(validate_network_field(gas, "1000").is_err());

    // Every declared default has to survive its own validator.
    for entry in CUSTOM_NETWORK_FIELDS {
        if let Some(default) = entry.default {
            assert!(
                validate_network_field(entry.flag, default).is_ok(),
                "{} offers a default its validator rejects",
                entry.flag
            );
        }
    }
}

#[test]
fn cursor_configuration_is_private_atomic_and_preserves_other_servers() {
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join(".cursor");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("mcp.json"),
        br#"{"mcpServers":{"other":{"command":"other"}},"setting":true}"#,
    )
    .unwrap();
    let file = configure_cursor_mcp_at(
        home.path(),
        "/usr/local/bin/ekubo-wallet",
        &["server".into()],
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(value["setting"], true);
    assert_eq!(value["mcpServers"]["other"]["command"], "other");
    assert_eq!(
        value["mcpServers"]["ekubo-wallet"]["args"],
        serde_json::json!(["server"])
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
