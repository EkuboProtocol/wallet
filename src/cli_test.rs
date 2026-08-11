//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::{message::MessageStatus, typed_data::TypedDataStatus};

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
        generation: 0,
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
        requester: None,
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
        requester: None,
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
        rpc_urls: vec!["https://example.invalid/rpc".parse().unwrap()],
        rpc_strategy: ekubo_wallet_core::config::RpcStrategy::Ordered,
        max_gas_limit: None,
        max_fee_per_gas: None,
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
        "--account",
        "primary",
        "--limit",
        "50",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Transaction(TransactionArgs {
            command: TransactionCommand::List {
                account: Some(ref account),
                limit: 50,
            },
        }) if account == "primary"
    ));
    let cli = Cli::try_parse_from(["ekubo-wallet", "shell-completion", "zsh"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Completion { shell: Shell::Zsh }
    ));
    let cli = Cli::try_parse_from(["ekubo-wallet", "network", "presets"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Network(args) if matches!(args.command, NetworkCommand::Presets { .. })
    ));
}

fn add_args(name: &str, chain_id: Option<u64>) -> NetworkAddArgs {
    NetworkAddArgs {
        name: Some(name.into()),
        chain_id,
        rpc_urls: Vec::new(),
        rpc_strategy: None,
        display_name: None,
        aliases: Vec::new(),
        max_fee_per_gas: None,
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
    args.rpc_urls = vec!["https://rpc.example.invalid/base".parse().unwrap()];
    let candidate = candidate_of(args, &configured).unwrap();

    assert_eq!(
        candidate.primary_rpc_url().as_str(),
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
    base.rpc_urls = vec!["https://rpc.example.invalid/base".parse().unwrap()];
    let configured = configured;

    let (known, origin) = network_for_chain(8453, &configured).unwrap();
    assert_eq!(known.name, "base");
    assert_eq!(origin, "configured as");
    // The configured endpoint is what the RPC prompt offers back, not the
    // shipped default it was changed away from.
    assert_eq!(
        known.primary_rpc_url().as_str(),
        "https://rpc.example.invalid/base"
    );

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
    for field in CUSTOM_NETWORK_FIELDS.iter().filter(|field| !field.optional) {
        assert!(
            message.contains(field.flag),
            "{} missing from:\n{message}",
            field.flag
        );
    }
    // A setting that is a choice between safe alternatives is not demanded:
    // requiring it would break every scripted install that was already
    // correct, to ask a question whose answer was already fine.
    for field in CUSTOM_NETWORK_FIELDS.iter().filter(|field| field.optional) {
        assert!(
            !message.contains(field.flag),
            "{} must not be demanded:\n{message}",
            field.flag
        );
    }
    assert!(message.contains("987654"), "{message}");
    // Every flag carries its own explanation and a usable example.
    assert!(message.contains("eth_simulateV1"), "{message}");
    assert!(message.contains("16777216"), "{message}");
}

#[test]
fn a_complete_custom_network_needs_no_terminal_at_all() {
    let mut args = add_args("custom", Some(987_654));
    args.rpc_urls = vec!["https://rpc.example.invalid".parse().unwrap()];
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
    // The omitted optional setting took its default rather than blocking.
    assert_eq!(
        candidate.rpc_strategy,
        ekubo_wallet_core::config::RpcStrategy::Ordered
    );
}

/// The strategy is settable from the same command as every other network
/// field, and validated against the endpoints it is given.
#[test]
fn the_rpc_strategy_is_set_and_checked_alongside_the_other_fields() {
    let mut args = add_args("base", None);
    args.rpc_urls = vec![
        "https://one.example.invalid".parse().unwrap(),
        "https://two.example.invalid".parse().unwrap(),
    ];
    args.rpc_strategy = Some(ekubo_wallet_core::config::RpcStrategy::MOfN { agree: 2 });
    let candidate = candidate_of(args, &default_networks()).unwrap();
    assert_eq!(
        candidate.rpc_strategy,
        ekubo_wallet_core::config::RpcStrategy::MOfN { agree: 2 }
    );

    // Asking for more agreement than there are endpoints is refused where the
    // number is typed, not at signing time.
    let mut args = add_args("base", None);
    args.rpc_urls = vec!["https://only.example.invalid".parse().unwrap()];
    args.rpc_strategy = Some(ekubo_wallet_core::config::RpcStrategy::MOfN { agree: 2 });
    let error = candidate_of(args, &default_networks())
        .expect_err("two of one is not reachable")
        .to_string();
    assert!(error.contains("needs 2 endpoints but"), "{error}");
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
    assert_eq!(network.rpc_urls, untouched.rpc_urls);
    assert_eq!(network.aliases, untouched.aliases);
    assert_eq!(network.native_currency, untouched.native_currency);
}

#[test]
fn setting_network_fields_applies_each_typed_value() {
    let mut network = default_networks().remove(0);
    set_network_field(&mut network, "--rpc-url", "https://rpc.example.invalid").unwrap();
    assert_eq!(
        network.primary_rpc_url().as_str(),
        "https://rpc.example.invalid/"
    );
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
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
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

fn ready_status() -> StatusFacts<'static> {
    StatusFacts {
        data_dir: "/tmp/ekubo",
        signing_allowed: true,
        terms_accepted: true,
        privacy_accepted: true,
        accounts: &[],
        networks: 10,
        token_count: 17_120,
        token_proposals: 0,
        waiting: 0,
        policy_proposals: 0,
        network_proposals: 0,
    }
}

#[test]
fn status_names_the_command_that_fixes_each_missing_prerequisite() {
    // A wallet nobody has set up yet: every line that reports something
    // missing has to say what supplies it, or the command only moves the
    // search rather than ending it.
    let fresh = StatusFacts {
        signing_allowed: false,
        terms_accepted: false,
        privacy_accepted: false,
        ..ready_status()
    };
    let rendered = status_lines(&fresh);
    assert!(rendered.contains("neither document accepted"));
    assert!(rendered.contains("ekubo-wallet legal accept"));
    assert!(rendered.contains("ekubo-wallet account create"));
    assert!(rendered.contains("Waiting for you  nothing"));
}

#[test]
fn status_distinguishes_a_changed_document_from_an_unread_one() {
    // Both accepted yet signing still refused means a document changed since,
    // which is a different action from never having read one.
    let stale = StatusFacts {
        signing_allowed: false,
        ..ready_status()
    };
    assert!(status_lines(&stale).contains("a document changed and needs re-accepting"));

    let partial = StatusFacts {
        signing_allowed: false,
        privacy_accepted: false,
        ..ready_status()
    };
    assert!(status_lines(&partial).contains("privacy policy not accepted"));
}

#[test]
fn status_summarizes_every_queue_that_is_waiting() {
    let busy = StatusFacts {
        waiting: 2,
        policy_proposals: 1,
        network_proposals: 3,
        token_proposals: 40,
        ..ready_status()
    };
    let rendered = status_lines(&busy);
    assert!(rendered.contains("2 signing request(s)"));
    assert!(rendered.contains("1 policy proposal(s)"));
    assert!(rendered.contains("3 network suggestion(s)"));
    assert!(rendered.contains("ekubo-wallet review"));
    // Token suggestions are not part of the review inbox, so they are reported
    // on their own line pointing at their own screen.
    assert!(rendered.contains("40 suggested"));
    assert!(rendered.contains("ekubo-wallet meta-tokens review"));
}

#[test]
fn unregistering_cursor_leaves_every_other_entry_alone() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
    let file = home.path().join(".cursor").join("mcp.json");
    std::fs::write(
        &file,
        serde_json::json!({
            "mcpServers": {
                "ekubo-wallet": {"command": "/old/path", "args": ["server"]},
                "something-else": {"command": "/bin/other", "args": []},
            },
            // A key this wallet knows nothing about. Rewriting the file must
            // not be an opportunity to drop it.
            "unrelated": {"keep": true},
        })
        .to_string(),
    )
    .unwrap();

    remove_cursor_mcp_at(home.path(), LOCAL_SERVER_NAME).unwrap();

    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert!(document["mcpServers"].get("ekubo-wallet").is_none());
    assert_eq!(
        document["mcpServers"]["something-else"]["command"],
        "/bin/other"
    );
    assert_eq!(document["unrelated"]["keep"], true);
}

#[test]
fn unregistering_cursor_without_a_configuration_is_not_an_error() {
    // `meta-agent remove` with no agent named walks everything detected, so a
    // machine where Cursor was never configured must not fail the sweep.
    let home = tempfile::tempdir().unwrap();
    remove_cursor_mcp_at(home.path(), LOCAL_SERVER_NAME).unwrap();
    remove_cursor_mcp_at(home.path(), COMPANION_SERVER_NAME).unwrap();
}

#[test]
fn cursor_gets_the_companion_as_a_url_entry_beside_the_wallet() {
    // Cursor has no transport field: `command` means a subprocess and `url`
    // means a remote endpoint, so writing the wrong key is how the companion
    // would silently become an unlaunchable stdio server.
    let home = tempfile::tempdir().unwrap();
    configure_cursor_mcp_at(
        home.path(),
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
    )
    .unwrap();
    let file = configure_cursor_mcp_at(
        home.path(),
        COMPANION_SERVER_NAME,
        &ServerTransport::Http(COMPANION_SERVER_URL),
    )
    .unwrap();

    let document: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    let companion = &document["mcpServers"]["ekubo"];
    assert_eq!(companion["url"], COMPANION_SERVER_URL);
    assert!(companion.get("command").is_none());
    // Registering the second one must not have displaced the first.
    assert_eq!(
        document["mcpServers"]["ekubo-wallet"]["command"],
        "/usr/local/bin/ekubo-wallet"
    );
}

#[test]
fn removing_the_wallet_from_cursor_leaves_the_companion_in_place() {
    // The two are removed by separate calls, and `ekubo` is a prefix of
    // `ekubo-wallet`: a removal keyed on anything looser than an exact name
    // would take both.
    let home = tempfile::tempdir().unwrap();
    configure_cursor_mcp_at(
        home.path(),
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
    )
    .unwrap();
    let file = configure_cursor_mcp_at(
        home.path(),
        COMPANION_SERVER_NAME,
        &ServerTransport::Http(COMPANION_SERVER_URL),
    )
    .unwrap();

    remove_cursor_mcp_at(home.path(), LOCAL_SERVER_NAME).unwrap();

    let document: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert!(document["mcpServers"].get("ekubo-wallet").is_none());
    assert_eq!(document["mcpServers"]["ekubo"]["url"], COMPANION_SERVER_URL);
}

#[test]
fn opencode_configuration_is_private_and_preserves_everything_else() {
    let config = tempfile::tempdir().unwrap();
    fs::write(
        config.path().join("opencode.json"),
        br#"{"$schema":"https://opencode.ai/config.json","mcp":{"other":{"type":"local","command":["other"]}},"model":"anthropic/claude-opus-4"}"#,
    )
    .unwrap();

    let file = configure_opencode_mcp_at(
        config.path(),
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
    )
    .unwrap();

    let document: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    // Nothing this wallet does not understand may be lost on the way through.
    assert_eq!(document["$schema"], "https://opencode.ai/config.json");
    assert_eq!(document["model"], "anthropic/claude-opus-4");
    assert_eq!(
        document["mcp"]["other"]["command"],
        serde_json::json!(["other"])
    );
    // opencode's local form is a tagged union with an argv array, not Cursor's
    // command string beside an `args` list.
    let wallet = &document["mcp"][LOCAL_SERVER_NAME];
    assert_eq!(wallet["type"], "local");
    assert_eq!(
        wallet["command"],
        serde_json::json!(["/usr/local/bin/ekubo-wallet", "server"])
    );
    assert_eq!(wallet["enabled"], true);
    assert!(wallet.get("args").is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn opencode_gets_the_companion_as_a_remote_entry_beside_the_wallet() {
    // Writing the local shape for a remote endpoint would have opencode try to
    // execute the URL as a command, so the discriminant is the thing to pin.
    let config = tempfile::tempdir().unwrap();
    configure_opencode_mcp_at(
        config.path(),
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
    )
    .unwrap();
    let file = configure_opencode_mcp_at(
        config.path(),
        COMPANION_SERVER_NAME,
        &ServerTransport::Http(COMPANION_SERVER_URL),
    )
    .unwrap();

    let document: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    let companion = &document["mcp"][COMPANION_SERVER_NAME];
    assert_eq!(companion["type"], "remote");
    assert_eq!(companion["url"], COMPANION_SERVER_URL);
    assert!(companion.get("command").is_none());
    // Registering the second must not have displaced the first.
    assert_eq!(document["mcp"][LOCAL_SERVER_NAME]["type"], "local");
    // `opencode.json` is the file written even on a machine that has none,
    // because it is the one a plain-JSON serializer can own outright.
    assert_eq!(file, config.path().join("opencode.json"));
}

#[test]
fn removing_the_wallet_from_opencode_leaves_the_companion_in_place() {
    // `ekubo` is a prefix of `ekubo-wallet`, so a removal keyed on anything
    // looser than an exact name would take both.
    let config = tempfile::tempdir().unwrap();
    configure_opencode_mcp_at(
        config.path(),
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
    )
    .unwrap();
    let file = configure_opencode_mcp_at(
        config.path(),
        COMPANION_SERVER_NAME,
        &ServerTransport::Http(COMPANION_SERVER_URL),
    )
    .unwrap();

    remove_opencode_mcp_at(config.path(), LOCAL_SERVER_NAME).unwrap();

    let document: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert!(document["mcp"].get(LOCAL_SERVER_NAME).is_none());
    assert_eq!(
        document["mcp"][COMPANION_SERVER_NAME]["url"],
        COMPANION_SERVER_URL
    );
}

#[test]
fn unregistering_opencode_without_a_configuration_is_not_an_error() {
    // `meta-agent remove` with no agent named walks everything detected, so a
    // machine where opencode was never configured must not fail the sweep.
    let config = tempfile::tempdir().unwrap();
    remove_opencode_mcp_at(config.path(), LOCAL_SERVER_NAME).unwrap();
    remove_opencode_mcp_at(config.path(), COMPANION_SERVER_NAME).unwrap();
}

#[test]
fn removing_from_opencode_sweeps_every_file_it_merges() {
    // opencode merges all three of its global files, later ones winning, so an
    // entry left behind in the legacy `config.json` would go on being the
    // registration this command just said it had taken away.
    let config = tempfile::tempdir().unwrap();
    fs::write(
        config.path().join("config.json"),
        serde_json::json!({"mcp": {LOCAL_SERVER_NAME: {"type": "local", "command": ["/old/path", "server"]}}})
            .to_string(),
    )
    .unwrap();
    configure_opencode_mcp_at(
        config.path(),
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
    )
    .unwrap();

    remove_opencode_mcp_at(config.path(), LOCAL_SERVER_NAME).unwrap();

    for candidate in OPENCODE_CONFIG_FILES {
        let file = config.path().join(candidate);
        if !file.exists() {
            continue;
        }
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert!(
            document["mcp"].get(LOCAL_SERVER_NAME).is_none(),
            "{candidate} still registers the wallet"
        );
    }
}

#[test]
fn a_commented_opencode_file_is_passed_over_unless_it_names_the_server() {
    // `.jsonc` is a format this wallet can read only by accident, and
    // rewriting one through a plain-JSON serializer would delete the comments
    // that are the only reason to keep a file in it. So one that says nothing
    // about these servers is left alone, and one that does is reported rather
    // than quietly skipped.
    let config = tempfile::tempdir().unwrap();
    let jsonc = config.path().join("opencode.jsonc");
    let untouched = "{\n  // my own notes\n  \"model\": \"anthropic/claude-opus-4\",\n}\n";
    fs::write(&jsonc, untouched).unwrap();
    remove_opencode_mcp_at(config.path(), LOCAL_SERVER_NAME).unwrap();
    assert_eq!(fs::read_to_string(&jsonc).unwrap(), untouched);

    fs::write(
        &jsonc,
        "{\n  // mine, by hand\n  \"mcp\": { \"ekubo-wallet\": { \"type\": \"local\", \"command\": [\"x\"] } },\n}\n",
    )
    .unwrap();
    let error = remove_opencode_mcp_at(config.path(), LOCAL_SERVER_NAME).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("opencode.jsonc"), "{message}");
    assert!(message.contains("by hand"), "{message}");
}

#[test]
fn a_commented_opencode_json_is_refused_rather_than_replaced() {
    // opencode parses every one of its files as JSONC, the `.json` included,
    // so someone's settings may be commented under either name. Starting from
    // an empty document there would silently reduce a whole configuration to
    // one MCP entry, which is why this fails and says what to do instead.
    let config = tempfile::tempdir().unwrap();
    let file = config.path().join("opencode.json");
    let original =
        "{\n  // the model I actually want\n  \"model\": \"anthropic/claude-opus-4\"\n}\n";
    fs::write(&file, original).unwrap();

    let error = configure_opencode_mcp_at(
        config.path(),
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
    )
    .unwrap_err();

    let message = format!("{error:#}");
    assert!(message.contains("by hand"), "{message}");
    assert!(message.contains("opencode.json"), "{message}");
    assert_eq!(fs::read_to_string(&file).unwrap(), original);
}

#[test]
fn opencode_detection_reads_every_file_and_tells_the_two_servers_apart() {
    let config = tempfile::tempdir().unwrap();
    // Nothing configured at all is a definite no, not an unanswerable
    // question: `meta-agent list` has to be able to say "not registered".
    let empty = opencode_registration_at(config.path()).unwrap();
    assert!(!empty.wallet);
    assert!(!empty.companion);

    // The wallet alone must not read as the companion too — `ekubo` is a
    // prefix of `ekubo-wallet`, which is the bug this shape is chosen against.
    configure_opencode_mcp_at(
        config.path(),
        LOCAL_SERVER_NAME,
        &ServerTransport::Stdio("/usr/local/bin/ekubo-wallet".into()),
    )
    .unwrap();
    let wallet_only = opencode_registration_at(config.path()).unwrap();
    assert!(wallet_only.wallet);
    assert!(!wallet_only.companion);

    // A registration in any file opencode merges counts, including one this
    // wallet would never have written itself.
    fs::write(
        config.path().join("config.json"),
        serde_json::json!({"mcp": {COMPANION_SERVER_NAME: {"type": "remote", "url": COMPANION_SERVER_URL}}})
            .to_string(),
    )
    .unwrap();
    let both = opencode_registration_at(config.path()).unwrap();
    assert!(both.wallet);
    assert!(both.companion);

    // A file that will not parse and might be holding the answer makes the
    // question unanswerable rather than answered wrongly.
    fs::write(
        config.path().join("opencode.jsonc"),
        "{ // note\n  \"mcp\": { \"ekubo-wallet\": { \"type\": \"local\", \"command\": [\"x\"] } },\n}\n",
    )
    .unwrap();
    assert!(opencode_registration_at(config.path()).is_none());
}

#[test]
fn opencode_config_lives_under_xdg_rather_than_the_platform_convention() {
    // opencode resolves this with `xdg-basedir`, so it is `~/.config/opencode`
    // on macOS and Windows too. Reaching for the native config directory would
    // write to `~/Library/Application Support` on macOS, where opencode would
    // never look.
    let directory = opencode_config_dir().unwrap();
    assert!(directory.ends_with("opencode"));
    if std::env::var_os("XDG_CONFIG_HOME").is_none() {
        assert!(
            directory.ends_with(Path::new(".config").join("opencode")),
            "{}",
            directory.display()
        );
    }
}

#[test]
fn a_registered_wallet_alone_does_not_read_as_a_registered_companion() {
    // The bug this exists for: `ekubo` is a prefix of `ekubo-wallet`, so the
    // obvious substring test reports both servers present when only the
    // wallet is, and `meta-agent list` then never tells anyone the companion is
    // missing.
    let wallet_only =
        read_registration("ekubo-wallet: /Users/x/.local/bin/ekubo-wallet server - ✓ Connected\n");
    assert!(wallet_only.wallet);
    assert!(!wallet_only.companion);

    let both = read_registration(
        "ekubo-wallet: /Users/x/.local/bin/ekubo-wallet server - ✓ Connected\n\
         ekubo: https://mcp.ekubo.org/mcp (HTTP) - ✓ Connected\n",
    );
    assert!(both.wallet);
    assert!(both.companion);

    let companion_only = read_registration("ekubo: https://mcp.ekubo.org/mcp (HTTP)\n");
    assert!(!companion_only.wallet);
    assert!(companion_only.companion);

    let neither = read_registration("No MCP servers configured.\n");
    assert!(!neither.wallet);
    assert!(!neither.companion);
}

#[test]
fn the_companion_is_a_first_party_https_endpoint() {
    // A plaintext or redirected companion URL would be a downgrade the wallet
    // ships to every install at once, so the constant is pinned rather than
    // merely reviewed.
    assert_eq!(COMPANION_SERVER_URL, "https://mcp.ekubo.org/mcp");
    assert!(COMPANION_SERVER_URL.starts_with("https://"));
    // The names are distinct but one is a prefix of the other, which is the
    // whole reason detection blanks the longer one out first.
    assert_ne!(COMPANION_SERVER_NAME, LOCAL_SERVER_NAME);
    assert!(LOCAL_SERVER_NAME.starts_with(COMPANION_SERVER_NAME));
}

#[test]
fn every_agent_has_a_distinct_key_and_label() {
    let mut keys = std::collections::HashSet::new();
    for agent in AgentName::ALL {
        assert!(keys.insert(agent.key()), "{agent:?} duplicates a key");
        assert!(!agent.label().is_empty());
    }
    // Cursor and opencode are the two this wallet configures by writing the
    // file itself, because neither has a CLI that owns both halves of its MCP
    // configuration — opencode can add a server and cannot remove one.
    assert!(AgentName::Cursor.binary().is_none());
    assert!(AgentName::Opencode.binary().is_none());
    assert!(AgentName::Codex.binary().is_some());
}

/// Every spelling a user can type at one level of the command tree, labelled
/// by the command it reaches.
///
/// `get_all_aliases` rather than `get_visible_aliases`: an alias declared with
/// `alias =` is hidden from `--help` and still typed, still offered by the
/// hand-written completion scripts, and so still a candidate at the prompt.
/// Hiding it from the help text is what let these accumulate unnoticed.
fn spellings(command: &clap::Command) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        out.push((sub.get_name().to_owned(), sub.get_name().to_owned()));
        for alias in sub.get_all_aliases() {
            out.push((alias.to_owned(), sub.get_name().to_owned()));
        }
    }
    out
}

fn value_spellings(command: &clap::Command) -> Vec<Vec<(String, String)>> {
    let mut out = Vec::new();
    for argument in command.get_arguments() {
        let values = argument.get_possible_values();
        if values.len() < 2 {
            continue;
        }
        out.push(
            values
                .iter()
                .filter(|value| !value.is_hide_set())
                .flat_map(|value| {
                    let canonical = value.get_name().to_owned();
                    value
                        .get_name_and_aliases()
                        .map(|spelling| (spelling.to_owned(), canonical.clone()))
                        .collect::<Vec<_>>()
                })
                .collect(),
        );
    }
    out
}

/// Every command in the tree, the root included: one level of completion
/// candidates each.
fn every_command(command: &clap::Command, into: &mut Vec<clap::Command>) {
    into.push(command.clone());
    for sub in command.get_subcommands() {
        every_command(sub, into);
    }
}

#[test]
fn no_spelling_is_a_prefix_of_a_sibling() {
    // Tab completion stalls exactly when one whole word is the beginning of
    // another: typing all of `net` still left `network` as a second
    // candidate, so the shell completed nothing and the short spelling had
    // bought a keystroke and cost a decision. Short aliases were where this
    // crept in — `acct` beside `account`, `bal` beside `balance`, `claude`
    // beside `claude-code` — and the rule is checked over the whole tree so
    // the next one does not.
    let mut commands = Vec::new();
    every_command(&Cli::command(), &mut commands);
    let mut levels = Vec::new();
    for command in &commands {
        levels.push(spellings(command));
        levels.extend(value_spellings(command));
    }

    // An alias competes with the name it stands for, so the comparison is
    // between spellings and never between the commands behind them: `net`
    // and `network` are one command and still two candidates at the prompt.
    for level in levels {
        for (spelling, owner) in &level {
            for (other, other_owner) in &level {
                assert!(
                    spelling == other || !other.starts_with(spelling.as_str()),
                    "`{spelling}` ({owner}) is a prefix of `{other}` ({other_owner}), \
                     so completing it can never decide between them"
                );
            }
        }
    }
}

#[test]
fn one_character_reaches_each_of_the_commands_people_actually_type() {
    // `review`, `account`, and `transaction` are the three a person reaches
    // for daily, so each is worth a whole letter of the top-level namespace.
    // Everything that used to share one has moved rather than been abbreviated:
    // `agent` and `address-book` to `meta-agent` and `meta-address-book`,
    // `reference` to `meta-reference`, `token` to `meta-tokens`. The `meta-`
    // prefix is not decoration — it is what keeps those letters clear.
    //
    // A rival is another *command*, not another spelling: `tx` shares `t`
    // with `transaction` and reaches the same place, so the letter is still
    // unambiguous. Only a second destination makes the shell stop and ask.
    let root = Cli::command();
    let level = spellings(&root);
    for wanted in ["review", "account", "transaction"] {
        let letter = &wanted[..1];
        let rivals: Vec<&str> = level
            .iter()
            .filter(|(spelling, owner)| owner != wanted && spelling.starts_with(letter))
            .map(|(spelling, _)| spelling.as_str())
            .collect();
        assert!(
            rivals.is_empty(),
            "`{letter}` does not reach `{wanted}` on its own: {rivals:?} share it"
        );
    }
}

#[test]
fn the_command_tree_has_no_shell_completion_ambiguity_for_connect() {
    // `completion` sat on `c` beside `connect`, so the one command a person
    // types while holding a pasted WalletConnect link could not be completed
    // in a keystroke. Spelling it `shell-completion` is the fix, and the cost
    // is that `s` now carries three commands — none of them typed often.
    let level = spellings(&Cli::command());
    let names: Vec<&str> = level
        .iter()
        .map(|(spelling, _)| spelling.as_str())
        .filter(|spelling| spelling.starts_with('c'))
        .collect();
    assert_eq!(names, ["connect"]);
}

#[test]
fn two_characters_pick_out_any_alias() {
    // An alias earns its place by being faster to reach than the name it
    // stands for, which means its first one or two characters have to decide
    // it against every other spelling at that level — the sibling commands,
    // and the long name it abbreviates. `acct` failed on the last of those:
    // it saved three characters over `account` and cost two, because `ac` and
    // `acc` now completed to nothing.
    let mut commands = Vec::new();
    every_command(&Cli::command(), &mut commands);
    let mut aliases = Vec::new();
    for command in &commands {
        let level = spellings(command);
        for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
            for alias in sub.get_all_aliases() {
                aliases.push((alias.to_owned(), sub.get_name().to_owned(), level.clone()));
            }
        }
    }

    for (alias, owner, level) in aliases {
        let prefix: String = alias.chars().take(2).collect();
        let rivals: Vec<&str> = level
            .iter()
            .map(|(spelling, _)| spelling.as_str())
            .filter(|spelling| *spelling != alias && spelling.starts_with(&prefix))
            .collect();
        assert!(
            rivals.is_empty(),
            "`{prefix}` does not reach the `{alias}` alias of `{owner}`: {rivals:?} share it"
        );
    }
}

mod reviewed_wallet_tests {
    //! A policy change lands on the wallet that was reviewed, or on none.

    use super::super::ensure_reviewed_wallet;
    use crate::config::{ConfigStore, WalletMetadata, WalletSource};
    use alloy::primitives::Address;

    fn metadata(id: &str, byte: u8) -> WalletMetadata {
        WalletMetadata {
            id: id.into(),
            address: Address::repeat_byte(byte),
            created_at: chrono::Utc::now(),
            source: WalletSource::Created,
            exported_at: None,
        }
    }

    fn store_holding(wallet: &WalletMetadata) -> (tempfile::TempDir, ConfigStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(directory.path());
        store
            .update(|config| {
                config.wallets.push(wallet.clone());
                Ok(())
            })
            .unwrap();
        (directory, store)
    }

    /// The ABA this closes. `account remove` purges the policy database by
    /// name and `account create` under that name starts a wallet whose policy
    /// numbering begins again at revision 1 -- so a review authorized against
    /// the predecessor can land on the successor with every number matching,
    /// precisely because the sequence restarted. The owner authorized a policy
    /// for one key and it would govern another.
    #[test]
    fn a_wallet_replaced_during_authorization_is_refused() {
        let replacement = metadata("primary", 0x22);
        let (_directory, config) = store_holding(&replacement);

        let reviewed = metadata("primary", 0x11);
        let error = format!(
            "{:#}",
            ensure_reviewed_wallet(&config, &reviewed)
                .expect_err("the reviewed wallet is gone; nothing may be applied")
        );
        assert!(error.contains("was replaced"), "{error}");
        assert!(
            error.contains("nothing was applied"),
            "the refusal has to say the change did not happen: {error}"
        );
    }

    /// A wallet gone entirely is refused too, and says why rather than
    /// reporting a missing wallet as if the caller had asked for one.
    #[test]
    fn a_wallet_removed_during_authorization_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigStore::new(directory.path());
        let error = format!(
            "{:#}",
            ensure_reviewed_wallet(&config, &metadata("primary", 0x11))
                .expect_err("a wallet that is gone cannot have its policy replaced")
        );
        assert!(error.contains("nothing was applied"), "{error}");
    }

    /// And the ordinary case still applies, which is what a guard that refused
    /// everything would fail.
    #[test]
    fn an_unchanged_wallet_still_applies_its_policy() {
        let reviewed = metadata("primary", 0x11);
        let (_directory, config) = store_holding(&reviewed);
        ensure_reviewed_wallet(&config, &reviewed).expect("nothing changed");
    }

    /// Both policy-application paths consult it, and after owner
    /// authentication rather than before: the window this is about is the one
    /// that authentication opens.
    #[test]
    fn both_policy_paths_recheck_after_owner_authentication() {
        let source = include_str!("cli.rs");
        assert_eq!(
            source
                .matches("ensure_reviewed_wallet(config, &wallet)?;")
                .count(),
            2,
            "the proposal review and the direct `policy set` both check"
        );
        // No newline in either needle. The checkout is CRLF on Windows, so a
        // `\n` in the pattern matches nothing there and `split_once` returns
        // `None` -- the test passed locally and failed only in CI, which is
        // the failure mode a source-scanning test is most prone to.
        for applying in [
            "policies.consume_proposal(&proposal)?",
            "let stored = policies.put(",
        ] {
            let before = source
                .split_once(applying)
                .expect("the application site exists")
                .0;
            let checked = before
                .rfind("ensure_reviewed_wallet(config, &wallet)?;")
                .expect("it is checked first");
            let authenticated = before
                .rfind("PresenceRequest::ReplacePolicy")
                .expect("owner authentication precedes it");
            assert!(
                checked > authenticated,
                "the recheck must follow the authentication it is protecting against"
            );
        }
    }
}

mod removal_fencing_tests {
    //! A wallet is not removed out from under a transaction that can still mine.

    /// The ordering is the property, and what it protects changed shape.
    ///
    /// `purge` deletes every pending row under the name, including the exact
    /// signed envelope and the cancellation state that are the only means of
    /// stopping something already authorized and possibly already sent. Those
    /// bytes do not stop being valid because the wallet was removed.
    ///
    /// It used to `bail!` on that. The maintainer's review called it what it
    /// was: a wall in front of an approval screen the code already builds. An
    /// owner whose node is gone and whose transaction will never mine is
    /// entitled to remove the wallet, and refusing left them editing the
    /// database -- the outcome the rest of this file works to avoid. So the
    /// list is on the screen now, and the read still has to happen before the
    /// screen is drawn, because afterwards there is no decision left to inform.
    #[test]
    fn removal_shows_live_transactions_on_the_approval_it_precedes() {
        let source = include_str!("cli.rs");
        let body = source
            .split_once("AccountCommand::Remove { wallet_id } =>")
            .expect("the removal arm exists")
            .1;
        let read = body
            .find("in_flight_transactions")
            .expect("removal asks what may still reach the chain");
        let warned = body
            .find("request = request.warning(")
            .expect("and puts each one on the approval as a warning");
        let approved = body
            .find("require_approval(request)")
            .expect("which is then shown to the owner");
        let removed = body
            .find("custody.remove(")
            .expect("before the credential is destroyed");
        assert!(
            read < warned && warned < approved && approved < removed,
            "read, warn, ask, then destroy -- in that order"
        );
        assert!(
            !body[..removed].contains("anyhow::bail!"),
            "nothing may refuse the removal outright before the owner is asked"
        );
    }
}

mod fee_ceiling_surface_tests {
    //! The one bound on what a dishonest endpoint can charge is settable.

    use super::*;

    /// `docs/networks.md` calls `max_fee_per_gas` the protection for automatic
    /// transactions -- their fee comes from an endpoint, no policy rule speaks
    /// about it, and nobody reviews it -- and the CLI had no way to set it.
    /// Every other field of a custom network was reachable; this one was
    /// hard-coded to `None`.
    #[test]
    fn a_custom_network_can_be_given_a_fee_ceiling() {
        let mut network = crate::config::NetworkConfig {
            name: "custom".into(),
            display_name: None,
            aliases: Vec::new(),
            chain_id: 999,
            rpc_urls: vec!["https://example.invalid/rpc".parse().unwrap()],
            rpc_strategy: ekubo_wallet_core::config::RpcStrategy::Ordered,
            max_gas_limit: None,
            max_fee_per_gas: None,
            native_currency: None,
            block_explorer_url: None,
            documentation_url: None,
        };
        set_network_field(&mut network, "--max-fee-per-gas", " 50000000000 ").unwrap();
        assert_eq!(network.max_fee_per_gas.as_deref(), Some("50000000000"));
    }

    /// Parsed when it is set rather than when a transaction is due. A ceiling
    /// that does not fit refuses every transaction on that chain, and finding
    /// that out at signing time is finding out too late.
    #[test]
    fn a_ceiling_that_is_not_a_number_is_refused_at_the_prompt() {
        let mut network = crate::config::NetworkConfig {
            name: "custom".into(),
            display_name: None,
            aliases: Vec::new(),
            chain_id: 999,
            rpc_urls: vec!["https://example.invalid/rpc".parse().unwrap()],
            rpc_strategy: ekubo_wallet_core::config::RpcStrategy::Ordered,
            max_gas_limit: None,
            max_fee_per_gas: None,
            native_currency: None,
            block_explorer_url: None,
            documentation_url: None,
        };
        for bad in ["50 gwei", "-1", "1e9"] {
            assert!(
                set_network_field(&mut network, "--max-fee-per-gas", bad).is_err(),
                "`{bad}` is not a whole number of wei"
            );
        }
        assert!(network.max_fee_per_gas.is_none(), "and nothing was written");

        // Blank is not a bad value, it is the way to remove a ceiling: unset
        // is unbounded, and an owner who set one has to be able to take it off
        // without editing JSON by hand.
        set_network_field(&mut network, "--max-fee-per-gas", "1").unwrap();
        set_network_field(&mut network, "--max-fee-per-gas", "  ").unwrap();
        assert!(
            network.max_fee_per_gas.is_none(),
            "blank clears the ceiling"
        );
    }

    /// The interactive form offers it, and offers it as optional: unset is
    /// unbounded and a number invented here would be wrong on most chains, so
    /// it must not become a required answer.
    #[test]
    fn the_custom_network_form_offers_the_ceiling_without_demanding_one() {
        let field = CUSTOM_NETWORK_FIELDS
            .iter()
            .find(|field| field.flag == "--max-fee-per-gas")
            .expect("the form asks about the fee ceiling");
        assert!(field.optional, "an unset ceiling is a valid answer");
        assert!(field.default.is_none(), "and no number is invented for it");
    }
}

/// A plaintext-to-a-remote-host RPC is allowed only after the network review
/// names that endpoint and its risk. These tests keep the warning and the
/// screen wired together.
mod plaintext_remote_endpoint_warning_tests {
    use super::*;

    fn network(rpc_urls: &[&str]) -> crate::config::NetworkConfig {
        crate::config::NetworkConfig {
            name: "custom".into(),
            display_name: None,
            aliases: Vec::new(),
            chain_id: 999,
            rpc_urls: rpc_urls.iter().map(|url| url.parse().unwrap()).collect(),
            rpc_strategy: ekubo_wallet_core::config::RpcStrategy::Ordered,
            max_gas_limit: None,
            max_fee_per_gas: None,
            native_currency: None,
            block_explorer_url: None,
            documentation_url: None,
        }
    }

    #[test]
    fn an_https_or_loopback_endpoint_earns_no_extra_warning() {
        assert!(plaintext_remote_warning(&network(&["https://rpc.example.invalid"])).is_none());
        assert!(plaintext_remote_warning(&network(&["http://127.0.0.1:8545"])).is_none());
        assert!(plaintext_remote_warning(&network(&["http://localhost:8545"])).is_none());
    }

    #[test]
    fn a_remote_plaintext_endpoint_is_named_in_the_warning() {
        let warning = plaintext_remote_warning(&network(&["http://192.0.2.10:8545"]))
            .expect("a remote http endpoint earns a warning");
        assert!(
            warning.contains("http://192.0.2.10:8545/"),
            "names the offending URL: {warning}"
        );
        assert!(
            warning.contains("plaintext http to a remote host"),
            "states what is wrong: {warning}"
        );
    }

    #[test]
    fn several_remote_plaintext_endpoints_are_all_named() {
        let warning = plaintext_remote_warning(&network(&[
            "https://safe.example.invalid",
            "http://192.0.2.10:8545",
            "http://198.51.100.20:8545",
        ]))
        .expect("two remote http endpoints earn a warning");
        assert!(warning.contains("http://192.0.2.10:8545/"), "{warning}");
        assert!(warning.contains("http://198.51.100.20:8545/"), "{warning}");
        assert!(
            !warning.contains("safe.example.invalid"),
            "the https endpoint is not implicated: {warning}"
        );
    }

    /// The confirmation screen an owner actually sees, not just the predicate
    /// behind it -- `network_review`/`confirm_network_change` are what could
    /// silently drop the warning even with `plaintext_remote_warning` correct.
    #[test]
    fn the_review_document_carries_the_named_warning() {
        let candidate = network(&["http://192.0.2.10:8545"]);
        let review = network_review(
            "Add or update network",
            "The wallet will read chain state and run eth_simulateV1 through this endpoint.",
            vec![("RPC URLs", endpoint_list(&candidate))],
            plaintext_remote_warning(&candidate),
        );
        let text = crate::fullscreen::lines_to_text(&review.document(), |text, _| text.to_owned());
        assert!(text.contains("plaintext http to a remote host"), "{text}");
        assert!(text.contains("http://192.0.2.10:8545/"), "{text}");
    }

    #[test]
    fn the_review_document_says_nothing_extra_for_a_safe_endpoint() {
        let candidate = network(&["https://rpc.example.invalid"]);
        let review = network_review(
            "Add or update network",
            "The wallet will read chain state and run eth_simulateV1 through this endpoint.",
            vec![("RPC URLs", endpoint_list(&candidate))],
            plaintext_remote_warning(&candidate),
        );
        let text = crate::fullscreen::lines_to_text(&review.document(), |text, _| text.to_owned());
        assert!(!text.contains("plaintext"), "{text}");
    }
}
