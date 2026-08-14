//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::{
    config::{WalletMetadata, WalletSource},
    policy_store::DatabaseKey,
};
use alloy::primitives::Address;
use std::str::FromStr;
use uuid::Uuid;

#[test]
fn tool_errors_are_capped_and_stripped() {
    // An RPC or plan producer chooses this text and alloy embeds whole
    // response bodies in it, so neither its length nor its bytes are the
    // wallet's to trust.
    let error = tool_error(&format!("upstream said \u{1b}[31m{}", "y".repeat(50_000)));
    assert!(
        error.message.chars().count() <= MAX_TOOL_ERROR_CHARS,
        "{} characters survived",
        error.message.chars().count()
    );
    assert!(!error.message.contains('\u{1b}'), "{}", error.message);
    // The head of the message is what carries the diagnosis, so it must
    // survive intact rather than being truncated from the front.
    assert!(error.message.starts_with("upstream said"));
}

#[test]
fn tool_errors_keep_the_anyhow_cause_chain() {
    // anyhow::Error's plain `Display` prints only the outermost context,
    // silently dropping the cause it was built to explain. An agent that
    // only sees "failed to open the config file" cannot tell a permission
    // problem from a missing directory from a stale symlink.
    let error = anyhow::anyhow!("permission denied").context("failed to open the config file");
    let message = tool_error(&error).message;
    assert!(
        message.contains("failed to open the config file"),
        "{message}"
    );
    assert!(message.contains("permission denied"), "{message}");
}

#[test]
fn tool_input_errors_use_invalid_params_instead_of_internal_error() {
    let error = tool_input_error(&"top-level from conflicts with referenced bundle");
    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
}

fn server() -> (tempfile::TempDir, WalletMcpServer) {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigStore::new(directory.path());
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "primary".into(),
        address: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    };
    config
        .update_for_test(|state| {
            state.wallets.push(wallet.clone());
            Ok(())
        })
        .unwrap();
    let mut policies = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([4; 32]),
    )
    .unwrap();
    policies
        .put_for_instance(&wallet, &WalletPolicy::allow_anything(), None)
        .unwrap();
    let pending_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([4; 32]),
    )
    .unwrap();
    let typed_data_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([4; 32]),
    )
    .unwrap();
    let message_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([4; 32]),
    )
    .unwrap();
    let legal_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([4; 32]),
    )
    .unwrap();
    let token_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([4; 32]),
    )
    .unwrap();
    let server = WalletMcpServer::new(
        config,
        policies,
        PendingStore::new(pending_database),
        TypedDataStore::new(typed_data_database),
        MessageStore::new(message_database),
        LegalStore::new(legal_database),
        TokenStore::new(token_database),
        Arc::new(crate::custody::MemoryKeyStore::default()),
    )
    .unwrap();
    (directory, server)
}

fn accept_legal(server: &WalletMcpServer) {
    let store = server.legal.lock().unwrap();
    store
        .record_acceptance(
            LegalDocument::TermsOfService,
            &LegalDocument::TermsOfService.digest(),
        )
        .unwrap();
    store
        .record_acceptance(
            LegalDocument::PrivacyPolicy,
            &LegalDocument::PrivacyPolicy.digest(),
        )
        .unwrap();
}

#[test]
fn wallet_and_network_inventories_are_separate_and_hide_disabled_networks() {
    let (_directory, server) = server();
    let Json(wallets) = server.wallet_list().unwrap();
    assert_eq!(wallets.wallets[0].id, "primary");
    let wallet_json = serde_json::to_value(&wallets).unwrap();
    assert!(wallet_json.get("networks").is_none());

    let disabled = server
        .config
        .load()
        .unwrap()
        .networks
        .into_iter()
        .filter(|network| network.disabled)
        .map(|network| network.chain_id.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    server
        .config
        .update_for_test(|state| {
            let network = state
                .networks
                .iter_mut()
                .find(|network| !network.disabled)
                .expect("an enabled network");
            network.rpc_urls = vec![
                "https://rpc.example.invalid:8443/v2/PATH_CANARY?key=QUERY_CANARY"
                    .parse()
                    .unwrap(),
            ];
            Ok(())
        })
        .unwrap();
    let Json(inventory) = server.list_networks().unwrap();
    assert!(
        inventory
            .networks
            .iter()
            .all(|network| network.rpc_urls.iter().all(|url| url.starts_with("http")))
    );
    let inventory_json = serde_json::to_string(&inventory).unwrap();
    assert!(inventory_json.contains("https://rpc.example.invalid:8443/"));
    assert!(!inventory_json.contains("PATH_CANARY"), "{inventory_json}");
    assert!(!inventory_json.contains("QUERY_CANARY"), "{inventory_json}");
    assert!(
        inventory
            .networks
            .iter()
            .all(|network| !disabled.contains(&network.chain_id))
    );
}

#[test]
fn token_inventory_never_discloses_disabled_network_rows() {
    let (_directory, server) = server();
    let disabled_chain = server
        .config
        .load()
        .unwrap()
        .networks
        .into_iter()
        .find(|network| network.disabled)
        .unwrap()
        .chain_id;
    server
        .tokens
        .lock()
        .unwrap()
        .insert_if_absent_for_test(
            &crate::token_store::ListedToken {
                chain_id: disabled_chain,
                address: Address::repeat_byte(0x44),
                symbol: "HIDDEN".into(),
                name: Some("Disabled Network Token".into()),
                decimals: 18,
            },
            "test",
        )
        .unwrap();

    let Json(listed) = server
        .wallet_list_tokens(Parameters(ListTokensInput {
            chain_id: None,
            limit: 1_000,
            offset: 0,
        }))
        .unwrap();
    assert!(
        listed
            .tokens
            .iter()
            .all(|token| token.symbol.as_deref() != Some("HIDDEN"))
    );
    assert!(
        server
            .wallet_list_tokens(Parameters(ListTokensInput {
                chain_id: Some(crate::token_store::ChainIdInput::Number(disabled_chain)),
                limit: 10,
                offset: 0,
            }))
            .is_err()
    );
    let Json(found) = server
        .wallet_search_tokens(Parameters(SearchTokensInput {
            query: "HIDDEN".into(),
            chain_id: None,
            limit: 10,
        }))
        .unwrap();
    assert!(found.tokens.is_empty());
}

#[test]
fn policy_tool_reads_encrypted_policy_revision() {
    let (_directory, server) = server();
    let Json(output) = server
        .wallet_get_policy(Parameters(WalletInput {
            wallet_id: "primary".into(),
        }))
        .unwrap();
    assert_eq!(output.revision, 1);
    assert_eq!(output.wallet_id, "primary");
}

#[test]
fn advertised_version_matches_crate() {
    assert_eq!(crate::VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn tool_schemas_contain_no_boolean_schemas() {
    // Schemars renders serde_json::Value as the boolean schema `true`,
    // which Claude Code's MCP client rejects when it validates tools/list
    // ("Invalid input at tools.N.outputSchema..."). Every position that
    // holds a subschema must hold an object.
    fn assert_no_boolean_schemas(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    let child_path = format!("{path}.{key}");
                    // additionalProperties is exempt: boolean forms are
                    // universal there and clients accept them.
                    let schema_position = matches!(key.as_str(), "items" | "contains" | "not")
                        || path.ends_with(".properties")
                        || path.ends_with(".$defs")
                        || path.ends_with(".definitions");
                    if schema_position {
                        assert!(
                            child.is_object(),
                            "boolean or non-object schema at {child_path}: {child}"
                        );
                    }
                    assert_no_boolean_schemas(child, &child_path);
                }
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_no_boolean_schemas(item, &format!("{path}[{index}]"));
                }
            }
            _ => {}
        }
    }

    fn assert_no_nonstandard_formats(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(format) = map.get("format").and_then(serde_json::Value::as_str) {
                    assert!(
                        !(format.starts_with("uint")
                            || format.starts_with("int")
                            || format == "float"
                            || format == "double"),
                        "nonstandard format {format:?} at {path}"
                    );
                }
                for (key, child) in map {
                    assert_no_nonstandard_formats(child, &format!("{path}.{key}"));
                }
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    assert_no_nonstandard_formats(item, &format!("{path}[{index}]"));
                }
            }
            _ => {}
        }
    }

    for tool in WalletMcpServer::sanitized_tool_router().list_all() {
        let name = tool.name.clone();
        let input = serde_json::to_value(tool.input_schema.as_ref()).unwrap();
        assert_no_boolean_schemas(&input, &format!("{name}.inputSchema"));
        assert_no_nonstandard_formats(&input, &format!("{name}.inputSchema"));
        if let Some(output) = &tool.output_schema {
            let output = serde_json::to_value(output.as_ref()).unwrap();
            assert_no_boolean_schemas(&output, &format!("{name}.outputSchema"));
            assert_no_nonstandard_formats(&output, &format!("{name}.outputSchema"));
        }
    }
}

#[test]
fn artifact_reference_inputs_are_explicit_json_objects() {
    let router = WalletMcpServer::sanitized_tool_router();
    for tool_name in [
        "wallet_batch_eth_call",
        "wallet_get_balances",
        "wallet_propose_tokens",
        "wallet_send_execution_plan",
        "wallet_simulate_execution_plan",
    ] {
        let tool = router.get(tool_name).expect("reference tool is published");
        let reference = tool
            .input_schema
            .get("properties")
            .and_then(|properties| properties.get("reference"))
            .unwrap_or_else(|| panic!("{tool_name} has no reference property"));
        assert_eq!(
            reference.get("type").and_then(serde_json::Value::as_str),
            Some("object"),
            "{tool_name}.reference must advertise an object directly: {reference}"
        );
        let properties = reference
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("{tool_name}.reference has no object properties"));
        for required in ["kind", "artifact_type", "url"] {
            assert!(
                properties.contains_key(required),
                "{tool_name}.reference does not describe {required}"
            );
        }
    }
}

#[test]
fn artifact_reference_inputs_reject_json_encoded_strings() {
    let encoded = serde_json::json!({
        "kind": "artifact_reference",
        "artifact_type": "execution_plan",
        "url": "data:application/json,%7B%7D"
    })
    .to_string();
    assert!(
        serde_json::from_value::<SimulateInput>(serde_json::json!({
            "wallet_id": "primary",
            "chain_id": "1",
            "reference": encoded,
        }))
        .is_err(),
        "JSON-encoded strings must not be accepted as artifact references"
    );
}

#[test]
fn policy_proposal_schema_is_the_exact_policy_object_shape() {
    let router = WalletMcpServer::sanitized_tool_router();
    let tool = router
        .get("wallet_propose_policy")
        .expect("policy proposal tool is published");
    let policy = tool
        .input_schema
        .get("properties")
        .and_then(|properties| properties.get("policy"))
        .expect("policy property is published");
    assert_eq!(policy.get("type"), Some(&serde_json::json!("object")));
    let properties = policy
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .expect("policy object describes its fields");
    assert!(properties.contains_key("version"));
    assert!(properties.contains_key("rules"));
    assert!(policy.to_string().contains("tuple"));
}

#[test]
fn policy_proposals_reject_json_encoded_strings() {
    assert!(
        serde_json::from_value::<ProposePolicyInput>(serde_json::json!({
            "wallet_id": "primary",
            "source_revision": 1,
            "policy": "{\"version\":1,\"rules\":[]}",
            "rationale": "encoded incorrectly"
        }))
        .is_err(),
        "the tool must require a policy object instead of accepting stringified JSON"
    );
}

/// Put a fork into the server's registry without touching an RPC.
fn insert_fork(server: &WalletMcpServer, wallet_id: &str, chain_id: u64) -> uuid::Uuid {
    use crate::fork::ForkParent;

    let wallet = server.config.wallet(wallet_id).unwrap();

    server
        .forks
        .lock()
        .unwrap()
        .create(
            wallet_id,
            wallet.instance_id,
            wallet.address,
            chain_id,
            ForkParent {
                number: 1_000,
                hash: alloy::primitives::B256::repeat_byte(0xcd),
                gas_limit: 30_000_000,
            },
            Utc::now(),
        )
        .unwrap()
        .fork_id
}

#[test]
fn a_fork_only_answers_for_the_wallet_and_chain_it_was_opened_for() {
    let (_directory, server) = server();
    let fork_id = insert_fork(&server, "primary", 1);

    assert!(
        server
            .fork_session(Some(fork_id), "1", Some("primary"))
            .unwrap()
            .is_some()
    );
    let wrong_chain = server
        .fork_session(Some(fork_id), "8453", Some("primary"))
        .expect_err("a fork must not answer for another chain");
    assert!(format!("{wrong_chain:?}").contains("different chain"));
    let wrong_wallet = server
        .fork_session(Some(fork_id), "1", Some("other"))
        .expect_err("a fork must not answer for another wallet");
    assert!(format!("{wrong_wallet:?}").contains("unknown wallet"));
}

#[test]
fn a_fork_does_not_follow_a_deleted_and_reimported_wallet() {
    let (_directory, server) = server();
    let fork_id = insert_fork(&server, "primary", 1);
    let replacement_instance = Uuid::new_v4();

    server
        .config
        .update_for_test(|state| {
            state.wallets[0].instance_id = replacement_instance;
            Ok(())
        })
        .unwrap();

    let error = server
        .fork_session(Some(fork_id), "1", Some("primary"))
        .expect_err("an old fork must not attach to a replacement wallet instance");
    assert!(format!("{error:?}").contains("different wallet"));
}

#[test]
fn an_unknown_or_discarded_fork_is_rejected_rather_than_ignored() {
    let (_directory, server) = server();
    let fork_id = insert_fork(&server, "primary", 1);

    // Omitting fork_id keeps the real-state path; it never silently
    // resolves to some other fork.
    assert!(
        server
            .fork_session(None, "1", Some("primary"))
            .unwrap()
            .is_none()
    );

    let discarded = server
        .wallet_discard_fork(Parameters(DiscardForkInput { fork_id }))
        .unwrap();
    assert!(discarded.0.discarded);
    let again = server
        .wallet_discard_fork(Parameters(DiscardForkInput { fork_id }))
        .unwrap();
    assert!(!again.0.discarded);

    let error = server
        .fork_session(Some(fork_id), "1", Some("primary"))
        .expect_err("a discarded fork must not resolve");
    assert!(format!("{error:?}").contains("unknown or expired"));
}

#[tokio::test]
async fn a_fork_cannot_be_opened_for_an_unknown_wallet_or_chain() {
    let (_directory, server) = server();
    let unknown_wallet = server
        .wallet_create_fork(Parameters(CreateForkInput {
            wallet_id: "missing".into(),
            chain_id: "1".into(),
        }))
        .await
        .err()
        .expect("an unknown wallet must not open a fork");
    assert!(format!("{unknown_wallet:?}").contains("unknown wallet"));

    let unknown_chain = server
        .wallet_create_fork(Parameters(CreateForkInput {
            wallet_id: "primary".into(),
            chain_id: "999999".into(),
        }))
        .await
        .err()
        .expect("an unconfigured chain must not open a fork");
    assert!(format!("{unknown_chain:?}").contains("no configured network"));
    assert!(server.forks.lock().unwrap().is_empty());
}

#[test]
fn forks_never_reach_the_signing_or_approval_surface() {
    // Fork state lives only in this process, and only the read and
    // simulate tools accept a fork_id. Everything that can sign,
    // approve, or submit takes no fork input at all.
    let schemas = WalletMcpServer::tool_router()
        .list_all()
        .into_iter()
        .map(|tool| {
            (
                tool.name.clone().into_owned(),
                serde_json::to_string(tool.input_schema.as_ref()).unwrap(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let accepts_fork = schemas
        .iter()
        .filter(|(_, schema)| schema.contains("fork_id"))
        .map(|(name, _)| name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        accepts_fork,
        [
            "wallet_batch_eth_call",
            "wallet_discard_fork",
            "wallet_get_balances",
            "wallet_get_portfolio",
            "wallet_get_status",
            "wallet_simulate_execution_plan",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>(),
    );
    for signing_tool in [
        "wallet_send_execution_plan",
        "wallet_sign_message",
        "wallet_sign_typed_data",
        "wallet_wait_for_approval",
        "wallet_wait_for_execution",
        "wallet_propose_policy",
    ] {
        assert!(
            !schemas[signing_tool].contains("fork"),
            "{signing_tool} must not accept fork input"
        );
    }
}

#[test]
fn tool_inventory_exposes_implemented_parity_surface() {
    let names = WalletMcpServer::tool_router()
        .list_all()
        .into_iter()
        .map(|tool| tool.name.into_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        [
            "list_networks",
            "wallet_check_for_updates",
            "wallet_propose_network",
            "wallet_attempt_cancel",
            "wallet_batch_eth_call",
            "wallet_create_fork",
            "wallet_decode_abi_result",
            "wallet_discard_fork",
            "wallet_get_balances",
            "wallet_get_legal",
            "wallet_get_policy",
            "wallet_get_portfolio",
            "wallet_get_status",
            "wallet_get_execution_status",
            "wallet_import_token_list",
            "wallet_list",
            "wallet_list_tokens",
            "wallet_propose_policy",
            "wallet_propose_tokens",
            "wallet_search_tokens",
            "wallet_send_execution_plan",
            "wallet_sign_message",
            "wallet_sign_typed_data",
            "wallet_simulate_execution_plan",
            "wallet_wait_for_approval",
            "wallet_wait_for_execution",
            "wallet_wait_for_message",
            "wallet_wait_for_typed_data",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn approval_wait_schema_uses_only_the_pending_request_id() {
    let router = WalletMcpServer::tool_router();
    let tool = router.get("wallet_wait_for_approval").unwrap();
    let properties = tool
        .input_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert!(properties.contains_key("request_id"));
    assert!(properties.contains_key("timeout_seconds"));
    assert!(!properties.contains_key("wallet_id"));
    assert!(!properties.contains_key("chain_id"));
    assert_eq!(
        tool.annotations.as_ref().unwrap().read_only_hint,
        Some(true)
    );
}

#[test]
fn proposing_a_network_is_not_destructive_and_is_idempotent() {
    // The annotations are how a client decides whether to ask its user
    // before calling. Proposing destroys nothing and changes nothing an
    // existing request depends on: a repeat replaces the suggestion for
    // that chain, and the configuration is untouched either way. The
    // destructive act is accepting it, which has no tool at all.
    let router = WalletMcpServer::tool_router();
    let tool = router.get("wallet_propose_network").unwrap();
    let annotations = tool.annotations.as_ref().unwrap();
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.read_only_hint, Some(false));
}

#[test]
fn simulating_a_plan_is_not_annotated_read_only() {
    // It signs nothing and broadcasts nothing, but it is not read-only: a
    // simulation against real chain state is recorded under a simulation_id
    // that a later send accepts in place of simulating again, and one on a
    // fork appends the plan to that fork, changing what every later call on
    // it sees. read_only_hint is the strongest "safe to call without asking"
    // signal a client has, so claiming it here would be an overclaim — and
    // wallet_create_fork is already annotated for creating the same state.
    let router = WalletMcpServer::tool_router();
    let tool = router.get("wallet_simulate_execution_plan").unwrap();
    let annotations = tool.annotations.as_ref().unwrap();
    assert_eq!(annotations.read_only_hint, Some(false));
    // The writes are additions to in-process registries that expire, so
    // nothing here is destructive, and a repeat records a second simulation
    // rather than nothing.
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(true));
}

#[test]
fn every_tool_that_resolves_a_reference_is_annotated_open_world() {
    // A reference is a URL the caller named, and resolving one leaves this
    // machine under the same admission policy a plan reference gets. That is
    // an open world whether or not the tool also reaches a chain, which is
    // what wallet_propose_tokens — the one tool here that touches no RPC at
    // all — got wrong.
    //
    // `url` is the same fact spelled differently: wallet_import_token_list
    // takes a bare published URL rather than an envelope, and fetches it
    // through that identical admission policy. Whether the caller names the
    // URL directly or inside a reference changes nothing about whether the
    // call leaves this machine, so both spellings are collected here.
    let router = WalletMcpServer::tool_router();
    let names_a_url = router
        .list_all()
        .into_iter()
        .filter(|tool| {
            tool.input_schema
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|properties| {
                    properties.contains_key("reference") || properties.contains_key("url")
                })
        })
        .map(|tool| tool.name.into_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names_a_url,
        [
            "wallet_batch_eth_call",
            "wallet_get_balances",
            "wallet_import_token_list",
            "wallet_propose_tokens",
            "wallet_send_execution_plan",
            "wallet_simulate_execution_plan",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>(),
    );
    for name in names_a_url {
        let tool = router.get(&name).unwrap();
        assert_eq!(
            tool.annotations.as_ref().unwrap().open_world_hint,
            Some(true),
            "{name} fetches a caller-named URL and must be open-world"
        );
    }
}

#[test]
fn importing_a_list_by_url_takes_no_caller_chosen_label() {
    // The review screen groups suggestions by their source string, so that
    // string is the whole of what the owner reads when deciding whether a
    // publisher is worth trusting. On this path the wallet builds it from the
    // TLS-proved host, and a caller that could pass a name could write
    // "Uniswap Labs Default" over a list served by anyone — which is the one
    // claim the token database exists to keep an agent from making. The
    // schema is where that is enforced: `deny_unknown_fields` rejects the
    // field rather than ignoring it, so there is no spelling that slips one
    // through.
    let router = WalletMcpServer::tool_router();
    let tool = router.get("wallet_import_token_list").unwrap();
    let properties = tool
        .input_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .unwrap();
    assert!(properties.contains_key("url"));
    assert!(!properties.contains_key("list_name"));
    assert!(!properties.contains_key("source"));
    assert!(!properties.contains_key("name"));
    // Nothing is named by importing; the owner still accepts the list.
    let annotations = tool.annotations.as_ref().unwrap();
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
}

#[test]
fn wait_schemas_publish_the_timeout_bounds_the_validator_enforces() {
    // A u8 admits 0 and 255; the validator admits neither. The schema is the
    // only thing a caller reads before choosing a number, so it states the
    // range rather than leaving it to be discovered by a rejected call.
    let router = WalletMcpServer::tool_router();
    for name in [
        "wallet_wait_for_approval",
        "wallet_wait_for_execution",
        "wallet_wait_for_message",
        "wallet_wait_for_typed_data",
    ] {
        let tool = router.get(name).unwrap();
        let timeout = tool
            .input_schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .and_then(|properties| properties.get("timeout_seconds"))
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| panic!("{name} has no timeout_seconds"));
        assert_eq!(
            timeout.get("minimum"),
            Some(&serde_json::json!(1)),
            "{name}"
        );
        assert_eq!(
            timeout.get("maximum"),
            Some(&serde_json::json!(55)),
            "{name}"
        );
    }
    assert!(validate_timeout_seconds(0).is_err());
    assert!(validate_timeout_seconds(55).is_ok());
    assert!(validate_timeout_seconds(56).is_err());
}

/// Endpoint admission resolves a hostname the caller chose, so a name
/// collision has to be settled before it: a profile that could never be
/// stored must not become outbound work on its way to being rejected.
///
/// A name already belonging to a *different* chain is the one conflict no
/// confirmation can resolve, so it fails at proposal time rather than
/// becoming a decision the owner cannot act on.
#[tokio::test]
async fn proposing_a_network_settles_name_conflicts_before_contacting_anything() {
    let (_directory, server) = server();
    let existing = server.config.load().unwrap().networks[0].clone();
    let result = server
        .wallet_propose_network(Parameters(AddNetworkInput {
            name: existing.name.clone(),
            display_name: "Untrusted Test".into(),
            aliases: vec!["untrusted-testnet".into()],
            chain_id: "999999".into(),
            testnet: true,
            // Nothing listens here, so reaching it at all fails slowly and
            // with a connection error rather than the conflict below.
            rpc_urls: vec!["http://127.0.0.1:9".parse().unwrap()],
            rpc_strategy: None,
            finality_confirmations: 12,
            max_gas_limit: "30000000".into(),
            native_currency: NativeCurrency {
                name: "Test Ether".into(),
                symbol: "TETH".into(),
                decimals: 18,
            },
            block_explorer_url: "https://explorer.example.invalid".parse().unwrap(),
            documentation_url: "https://docs.example.invalid".parse().unwrap(),
        }))
        .await;
    let Err(error) = result else {
        panic!("a conflicting network was added");
    };
    assert!(
        error.message.contains("already names chain"),
        "rejected for the wrong reason: {}",
        error.message
    );
}

/// Every other optional list on this tool's inputs (`tokens`, `chain_ids`)
/// tolerates a caller who omits it; `aliases` used to be the one exception,
/// failing deserialization outright instead of reaching this tool's own
/// `tool_error` path.
#[test]
fn proposing_a_network_tolerates_a_call_that_omits_aliases() {
    let input = serde_json::json!({
        "name": "untrusted",
        "display_name": "Untrusted Test",
        "chain_id": "999999",
        "testnet": true,
        "rpc_urls": ["http://127.0.0.1:9"],
        "max_gas_limit": "30000000",
        "native_currency": {
            "name": "Test Ether",
            "symbol": "TETH",
            "decimals": 18,
        },
        "block_explorer_url": "https://explorer.example.invalid",
        "documentation_url": "https://docs.example.invalid",
    });
    let parsed: AddNetworkInput =
        serde_json::from_value(input).expect("aliases should be optional");
    assert!(parsed.aliases.is_empty());
}

fn add_network_input(rpc_url: &str) -> AddNetworkInput {
    AddNetworkInput {
        name: "untrusted".into(),
        display_name: "Untrusted Test".into(),
        aliases: vec![],
        chain_id: "999999".into(),
        testnet: true,
        rpc_urls: vec![rpc_url.parse().unwrap()],
        rpc_strategy: None,
        finality_confirmations: 12,
        max_gas_limit: "30000000".into(),
        native_currency: NativeCurrency {
            name: "Test Ether".into(),
            symbol: "TETH".into(),
            decimals: 18,
        },
        block_explorer_url: "https://explorer.example.invalid".parse().unwrap(),
        documentation_url: "https://docs.example.invalid".parse().unwrap(),
    }
}

/// Both halves of the admission on the one tool that contacts an address
/// its caller chose. They share a test because the probe permit is
/// process-global: as separate tests they would race each other for it.
#[tokio::test]
async fn network_add_admits_an_endpoint_before_contacting_it() {
    let (_directory, server) = server();

    // One probe at a time. Held here, so the tool must refuse rather than
    // queue behind it — and must refuse before resolving anything.
    let held = NETWORK_PROBE_SLOTS
        .try_acquire()
        .expect("the only permit is free");
    let result = server
        .wallet_propose_network(Parameters(add_network_input(
            "https://rpc.example.invalid/",
        )))
        .await;
    let Err(error) = result else {
        panic!("a second probe ran while one was in flight");
    };
    assert!(
        error.message.contains("already being checked"),
        "refused for the wrong reason: {}",
        error.message
    );
    drop(held);

    // The address is admitted before the request, not judged by whether
    // the request happens to succeed.
    for (rpc_url, reason) in [
        ("http://mainnet.example.invalid/rpc", "https"),
        ("https://127.0.0.1/rpc", "private or reserved"),
        (
            "https://169.254.169.254/latest/meta-data/",
            "private or reserved",
        ),
        ("https://[::1]/rpc", "private or reserved"),
        ("https://localhost/rpc", "public host"),
        ("https://vault.internal/rpc", "public host"),
        ("https://key@mainnet.example.invalid/rpc", "credentials"),
    ] {
        let result = server
            .wallet_propose_network(Parameters(add_network_input(rpc_url)))
            .await;
        let Err(error) = result else {
            panic!("{rpc_url} was accepted");
        };
        assert!(
            error.message.contains(reason),
            "{rpc_url} rejected for the wrong reason: {}",
            error.message
        );
    }
}

#[test]
fn startup_fails_closed_when_a_configured_wallet_has_no_policy() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigStore::new(directory.path());
    let wallet = WalletMetadata {
        instance_id: Uuid::new_v4(),
        id: "orphan".into(),
        address: Address::repeat_byte(0x22),
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    };
    config
        .update_for_test(|state| {
            state.wallets.push(wallet.clone());
            Ok(())
        })
        .unwrap();
    let mut policies = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([5; 32]),
    )
    .unwrap();
    policies.register_wallet_without_policy(&wallet).unwrap();
    let pending_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([5; 32]),
    )
    .unwrap();
    let typed_data_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([5; 32]),
    )
    .unwrap();
    let message_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([5; 32]),
    )
    .unwrap();
    let legal_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([5; 32]),
    )
    .unwrap();
    let token_database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &DatabaseKey::new([5; 32]),
    )
    .unwrap();
    let result = WalletMcpServer::new(
        config,
        policies,
        PendingStore::new(pending_database),
        TypedDataStore::new(typed_data_database),
        MessageStore::new(message_database),
        LegalStore::new(legal_database),
        TokenStore::new(token_database),
        std::sync::Arc::new(crate::custody::MemoryKeyStore::default()),
    );
    assert!(result.is_err());
    assert!(result.err().unwrap().to_string().contains("has no policy"));
}

fn permit_payload() -> serde_json::Value {
    serde_json::json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"}
            ]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Test Token",
            "chainId": 1,
            "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        },
        "message": {
            "owner": "0x1111111111111111111111111111111111111111",
            "spender": "0x2222222222222222222222222222222222222222",
            "value": "1000000",
            "nonce": "0",
            "deadline": "1900000000"
        }
    })
}

/// The exemptions, by name. `wallet_get_legal` is how the documents are read
/// in order to be accepted; `wallet_check_for_updates` reads a release listing
/// and touches no wallet, key, or policy. Enumerated over the whole router, so
/// a new tool is gated unless someone adds it here on purpose.
const UNGATED_TOOLS: [&str; 2] = ["wallet_get_legal", "wallet_check_for_updates"];

#[test]
fn every_tool_except_legal_and_the_release_check_is_gated_on_acceptance() {
    let (_directory, server) = server();
    for tool in WalletMcpServer::sanitized_tool_router().list_all() {
        let gated = server.tool_gate(&tool.name).is_err();
        assert_eq!(
            gated,
            !UNGATED_TOOLS.contains(&tool.name.as_ref()),
            "unexpected gate state for {}",
            tool.name
        );
    }
    accept_legal(&server);
    for tool in WalletMcpServer::sanitized_tool_router().list_all() {
        assert!(server.tool_gate(&tool.name).is_ok());
    }
}

#[test]
fn simulation_failure_handling_defaults_to_the_approval_queue() {
    // Callers that never heard of the field keep the behavior they had:
    // a failed simulation becomes a request the user can override.
    let input: SendExecutionPlanInput = serde_json::from_value(serde_json::json!({
        "wallet_id": "primary",
        "chain_id": "1",
        "request_id": "00000000-0000-0000-0000-000000000000",
    }))
    .expect("the field is optional");
    assert_eq!(
        input.on_simulation_failure,
        OnSimulationFailure::RequestApproval
    );

    let asked: SendExecutionPlanInput = serde_json::from_value(serde_json::json!({
        "wallet_id": "primary",
        "chain_id": "1",
        "request_id": "00000000-0000-0000-0000-000000000000",
        "on_simulation_failure": "fail",
    }))
    .expect("snake_case values parse");
    assert_eq!(asked.on_simulation_failure, OnSimulationFailure::Fail);

    assert!(
        serde_json::from_value::<SendExecutionPlanInput>(serde_json::json!({
            "wallet_id": "primary",
            "chain_id": "1",
            "request_id": "00000000-0000-0000-0000-000000000000",
            "on_simulation_failure": "sign_anyway",
        }))
        .is_err(),
        "only the two defined actions are accepted"
    );
}

#[test]
fn a_policy_denial_is_documented_as_a_step_forward_not_a_stop() {
    // An agent that reads allowed=false as a blocker reports findings back
    // and asks the user to widen their policy, which is the one thing the
    // user is not being asked to do: the send is what queues the review.
    assert!(
        SERVER_INSTRUCTIONS
            .contains("matching no policy rule is the ordinary route to a human approval")
    );
    assert!(SERVER_INSTRUCTIONS.contains("never a prerequisite for the one in hand"));

    // The opposite half of the same fact: a deny rule is not a route to
    // approval at all, so the instructions must not read as though every
    // allowed=false eventually queues.
    assert!(SERVER_INSTRUCTIONS.contains("nothing signs it and nothing queues it"));

    // wallet_wait_for_execution returns immediately while a request is
    // still AwaitingApproval, so the instructions must not let an agent
    // reach for it and conclude that nothing is happening.
    assert!(SERVER_INSTRUCTIONS.contains("wallet_wait_for_execution does not cover this phase"));
    assert!(SERVER_INSTRUCTIONS.contains("never hand back a request-id and stop"));

    // The same fact belongs on the tool an agent is holding when it first
    // sees policy findings.
    let router = WalletMcpServer::sanitized_tool_router();
    let simulate = router
        .list_all()
        .into_iter()
        .find(|tool| tool.name == "wallet_simulate_execution_plan")
        .expect("the simulation tool is published");
    let description = simulate.description.clone().unwrap_or_default();
    assert!(description.contains("not a reason to stop"));

    // And on the result itself, in band, at the moment the agent decides
    // what to do next: instructions and descriptions are read once, but
    // the denial arrives mid-task.
    // A call no rule covers is the ordinary route to approval.
    let next_step = policy_denial_next_step(
        crate::core::policy::PolicyOutcome::RequiresApproval,
        uuid::Uuid::nil(),
    );
    assert!(next_step.contains("not a dead end"));
    assert!(next_step.contains("wallet_send_execution_plan"));
    assert!(next_step.contains(&uuid::Uuid::nil().to_string()));
    assert!(next_step.contains("do not ask the user to change their policy"));

    // An explicit deny gets the opposite advice: do not queue, and the policy
    // is exactly what has to change.
    let refused = policy_denial_next_step(
        crate::core::policy::PolicyOutcome::Rejected,
        uuid::Uuid::nil(),
    );
    assert!(refused.contains("refuses this plan outright"));
    assert!(refused.contains("do not queue it"));
    assert!(!refused.contains("not a dead end"));
}

#[test]
fn ekubo_wallet_skill_is_advertised_for_onchain_and_ambiguous_wallet_requests() {
    let info = ServerHandler::get_info(&server().1);
    let instructions = info.instructions.unwrap();
    assert!(instructions.contains("any onchain request"));
    assert!(instructions.contains("wallet_list"));
    assert!(instructions.contains("list_networks"));
    assert!(instructions.contains("does not clearly rule out a crypto wallet"));
    assert!(instructions.contains(SKILL_RESOURCE_URI));

    let resources = serde_json::to_string(&wallet_resources()).unwrap();
    assert!(resources.contains(SKILL_RESOURCE_URI));
    assert!(resources.contains("onchain work on enabled EVM networks"));

    assert!(EKUBO_WALLET_SKILL.starts_with("---\nname: use-ekubo-wallet\n"));
    assert!(EKUBO_WALLET_SKILL.contains("whenever \"wallet\" is ambiguous"));
    assert!(EKUBO_WALLET_SKILL.contains("does not prepare transaction actions"));
    assert!(EKUBO_WALLET_SKILL.contains("native-token and ERC-20 transfers"));
    assert!(EKUBO_WALLET_SKILL.contains("A simulation is not approval"));
}

#[test]
fn the_authoring_surfaces_explain_order_and_the_two_negative_outcomes() {
    let schema = serde_json::to_string(&crate::core::policy::json_schema()).unwrap();
    for surface in [POLICY_AUTHORING_GUIDE, &schema] {
        assert!(
            surface.contains("rejects without queuing")
                || surface.contains("rejects the complete transaction"),
            "a deny rule forecloses rather than gating"
        );
        assert!(
            surface.contains("explicit owner approval") || surface.contains("needs owner"),
            "matching no rule is a question, not a refusal"
        );
        assert!(
            surface.contains("first matching rule"),
            "order is authority"
        );
    }
    for fact in [
        "Present matchers are ANDed",
        "omitted matcher means any value",
        "integer comparisons",
        "There is no `from` matcher",
        "The only policy variable is `$self`",
    ] {
        assert!(
            POLICY_AUTHORING_GUIDE.contains(fact),
            "the authoring guide no longer states: {fact}"
        );
    }
}

fn sendable_plan() -> ExecutionPlan {
    ExecutionPlan::parse(serde_json::json!({
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
                "data": "0x",
                "value": "1"
            }
        }]
    }))
    .unwrap()
}

/// A result that failed for a reason no live simulation in these tests
/// could produce, so an error quoting it proves the send reused this
/// record rather than simulating again.
fn recorded_failure(plan: &ExecutionPlan, policy_revision: u64) -> SimulationResult {
    use crate::{
        core::execution_plan::SimulationFailureAction,
        simulation::{
            ExecutionMode, SimulationExecution, SimulationFailure, SimulationFailureCategory,
        },
    };
    SimulationResult {
        simulation_id: None,
        digest: format!("{:#x}", plan.digest()),
        allowed: false,
        policy_outcome: crate::core::policy::PolicyOutcome::RequiresApproval,
        policy_findings: Vec::new(),
        policy_revision,
        execution_mode: ExecutionMode::Direct,
        implementation: None,
        will_authorize_delegation: false,
        replaces_delegated_implementation: None,
        simulation: SimulationExecution {
            success: false,
            gas_used: None,
            block_gas_limit: None,
            output: None,
            error: Some("recorded revert".into()),
            failure: Some(SimulationFailure {
                category: SimulationFailureCategory::ExecutionReverted,
                message: "recorded revert".into(),
                retryable_same_plan: false,
                recommended_action: SimulationFailureAction::RepreparePlan,
                instruction: "GUIDANCE FROM THE RECORDED SIMULATION".into(),
                source: "wallet_default".into(),
                revert_data: None,
                revert_selector: None,
                unwrapped_revert_data: None,
                unwrapped_revert_selector: None,
                wrapped_errors: None,
                decoded_error: None,
            }),
        },
        token_spends: std::collections::BTreeMap::new(),
        balance_changes: None,
        block_number: "100".into(),
        fork: None,
    }
}

#[tokio::test]
async fn a_recorded_simulation_is_sent_without_simulating_again_and_only_once() {
    let (_directory, server) = server();
    accept_legal(&server);
    let plan = sendable_plan();
    let wallet = server.config.wallet("primary").unwrap();
    let recorded = server.simulations.lock().unwrap().record_for_instance(
        &wallet.id,
        wallet.instance_id,
        "1",
        plan.clone(),
        Some("mcp.ekubo.org".into()),
        recorded_failure(&plan, 1),
        Utc::now(),
    );

    let error = Box::pin(server.send_recorded_simulation(
        server.config.wallet("primary").unwrap(),
        server.config.network_by_chain_id("1").unwrap(),
        recorded.simulation_id,
        OnSimulationFailure::Fail,
    ))
    .await
    .expect_err("the recorded failure is reported, not re-simulated");
    // The recorded result's own guidance comes back, so nothing asked the
    // RPC to execute this plan a second time.
    assert!(
        error.to_string().contains("GUIDANCE FROM THE RECORDED"),
        "{error}"
    );

    // And the record is spent, so one simulation can authorize at most one
    // send however many times the identifier is replayed.
    assert!(server.simulations.lock().unwrap().is_empty());
    let replayed = Box::pin(server.send_recorded_simulation(
        server.config.wallet("primary").unwrap(),
        server.config.network_by_chain_id("1").unwrap(),
        recorded.simulation_id,
        OnSimulationFailure::Fail,
    ))
    .await
    .expect_err("a spent simulation must not send again");
    assert!(replayed.to_string().contains("already sent"), "{replayed}");
}

#[tokio::test]
async fn a_simulation_evaluated_under_a_superseded_policy_is_refused() {
    let (_directory, server) = server();
    accept_legal(&server);
    let plan = sendable_plan();
    let wallet = server.config.wallet("primary").unwrap();
    let recorded = server.simulations.lock().unwrap().record_for_instance(
        &wallet.id,
        wallet.instance_id,
        "1",
        plan.clone(),
        Some("mcp.ekubo.org".into()),
        recorded_failure(&plan, 1),
        Utc::now(),
    );
    {
        let mut policies = server.policies.lock().unwrap();
        let current = policies.get("primary").unwrap().unwrap();
        policies
            .put_for_instance(
                &wallet,
                &WalletPolicy::require_approval_for_everything(),
                Some(current.revision),
            )
            .unwrap();
    }
    let error = Box::pin(server.send_recorded_simulation(
        server.config.wallet("primary").unwrap(),
        server.config.network_by_chain_id("1").unwrap(),
        recorded.simulation_id,
        OnSimulationFailure::Fail,
    ))
    .await
    .expect_err("findings from a policy that is no longer active must not be sent");
    assert!(error.to_string().contains("moved to revision 2"), "{error}");
}

#[tokio::test]
async fn a_fork_result_can_never_be_sent_even_if_one_reaches_the_registry() {
    let (_directory, server) = server();
    accept_legal(&server);
    let plan = sendable_plan();
    let mut hypothetical = recorded_failure(&plan, 1);
    hypothetical.fork = Some(crate::fork::ForkContext {
        fork_id: uuid::Uuid::new_v4(),
        hypothetical: true,
        chain_id: "1".into(),
        parent_block_number: "100".into(),
        simulated_block_number: "101".into(),
        applied_plans: 1,
        max_plans: 8,
        expires_at: Utc::now(),
        note: crate::fork::FORK_NOTE.into(),
    });
    let wallet = server.config.wallet("primary").unwrap();
    let recorded = server.simulations.lock().unwrap().record_for_instance(
        &wallet.id,
        wallet.instance_id,
        "1",
        plan,
        None,
        hypothetical,
        Utc::now(),
    );
    let error = Box::pin(server.send_recorded_simulation(
        server.config.wallet("primary").unwrap(),
        server.config.network_by_chain_id("1").unwrap(),
        recorded.simulation_id,
        OnSimulationFailure::Fail,
    ))
    .await
    .expect_err("a hypothetical result must not authorize a send");
    assert!(error.to_string().contains("hypothetical"), "{error}");
}

#[test]
fn a_send_names_exactly_one_of_plan_simulation_and_request() {
    let base = serde_json::json!({"wallet_id": "primary", "chain_id": "1"});
    let with = |extra: serde_json::Value| {
        let mut value = base.clone();
        for (key, entry) in extra.as_object().unwrap() {
            value[key] = entry.clone();
        }
        serde_json::from_value::<SendExecutionPlanInput>(value)
    };
    let id = serde_json::json!("00000000-0000-0000-0000-000000000000");
    assert!(
        with(serde_json::json!({"simulation_id": id}))
            .unwrap()
            .simulation_id
            .is_some()
    );
    // The tool rejects zero or several of them; the schema itself accepts
    // each field independently, which is what the count check is for.
    let none = with(serde_json::json!({})).unwrap();
    assert!(none.reference.is_none() && none.simulation_id.is_none() && none.request_id.is_none());
    let with_reference = with(serde_json::json!({
        "reference": {
            "kind": "artifact_reference",
            "artifact_type": "execution_plan",
            "url": "https://mcp.ekubo.org/artifact/x",
            "integrity": {
                "algorithm": "keccak256",
                "value": format!("0x{}", "11".repeat(32)),
            },
            "bytes": 2,
            // Additive producer fields must not break older wallets.
            "some_future_field": true,
        },
    }))
    .unwrap();
    assert!(with_reference.reference.is_some());
}

#[tokio::test]
async fn simulate_refuses_a_mismatched_plan_digest_before_simulating() {
    use base64::Engine as _;
    let (_directory, server) = server();
    let body = "{\"schema_version\":\"1\"}";
    let url = format!(
        "data:application/json;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(body)
    );
    let result = server
        .wallet_simulate_execution_plan(Parameters(SimulateInput {
            wallet_id: "primary".into(),
            chain_id: "1".into(),
            reference: ekubo_wallet_core::plan_fetch::ArtifactReference {
                kind: "artifact_reference".into(),
                artifact_type: ekubo_wallet_core::plan_fetch::ArtifactType::ExecutionPlan,
                url,
                integrity: Some(ekubo_wallet_core::plan_fetch::ArtifactIntegrity {
                    algorithm: "keccak256".into(),
                    value: format!("0x{}", "11".repeat(32)),
                }),
                bytes: Some(body.len() as u64),
                instruction: None,
            },
            fork_id: None,
        }))
        .await;
    let Err(error) = result else {
        panic!("a digest mismatch must refuse the plan");
    };
    assert!(
        error.message.contains("must not be simulated or signed"),
        "{}",
        error.message
    );
}

#[tokio::test]
async fn signing_tools_fail_closed_until_legal_acceptance() {
    let (_directory, server) = server();
    let result = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: "1".into(),
            reference: None,
            simulation_id: Some(uuid::Uuid::nil()),
            request_id: None,
            on_simulation_failure: OnSimulationFailure::default(),
        }))
        .await;
    let Err(error) = result else {
        panic!("send unexpectedly bypassed the legal acceptance gate");
    };
    assert!(error.message.contains("Legal"));

    let result = server.wallet_sign_typed_data(Parameters(SignTypedDataInput {
        wallet_id: "primary".into(),
        typed_data: permit_payload(),
    }));
    let Err(error) = result else {
        panic!("typed-data signing unexpectedly bypassed the legal acceptance gate");
    };
    assert!(error.message.contains("Legal"));

    let result = server.wallet_sign_message(Parameters(SignMessageInput {
        wallet_id: "primary".into(),
        message_text: Some("gm".into()),
        message_hex: None,
        chain_id: None,
    }));
    let Err(error) = result else {
        panic!("message signing unexpectedly bypassed the legal acceptance gate");
    };
    assert!(error.message.contains("Legal"));
}

fn sign_message(server: &WalletMcpServer, text: &str) -> Result<Json<MessageOutput>, ErrorData> {
    server.wallet_sign_message(Parameters(SignMessageInput {
        wallet_id: "primary".into(),
        message_text: Some(text.into()),
        message_hex: None,
        chain_id: None,
    }))
}

fn siwe_payload(address: &str) -> String {
    [
        "example.com wants you to sign in with your Ethereum account:",
        address,
        "",
        "Sign in to Example.",
        "",
        "URI: https://example.com/login",
        "Version: 1",
        "Chain ID: 1",
        "Nonce: 32891756",
        "Issued At: 2026-08-04T16:25:24Z",
    ]
    .join("\n")
}

#[test]
fn message_signing_always_queues_and_never_signs_inline() {
    let (_directory, server) = server();
    accept_legal(&server);
    // The wallet policy is allow-all: a message still queues, because no
    // policy can score what a message signature authorizes.
    let Json(output) = sign_message(&server, "gm").unwrap();
    assert_eq!(output.status, MessageStatus::AwaitingApproval);
    assert!(output.signature.is_none());
    assert!(output.chain_id.is_none());
    assert_eq!(output.message_hex, "0x676d");
    assert_eq!(output.display.text.as_deref(), Some("gm"));
    assert_eq!(
        output.digest,
        format!("{:#x}", crate::message::message_digest(b"gm"))
    );
    assert!(output.siwe.is_none());
    assert!(
        output
            .display
            .warnings
            .iter()
            .any(|warning| warning.contains("not a recognized sign-in message"))
    );
    assert!(
        output
            .instruction
            .as_deref()
            .unwrap()
            .contains("open review")
    );

    // A duplicate message reuses the pending request.
    let Json(duplicate) = sign_message(&server, "gm").unwrap();
    assert_eq!(duplicate.request_id, output.request_id);

    // Waiting on it returns the same pending state with a re-poll nudge.
    let Json(waited) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(server.wallet_wait_for_message(Parameters(MessageWaitInput {
            request_id: output.request_id,
            timeout_seconds: 1,
        })))
        .unwrap();
    assert_eq!(waited.status, MessageStatus::AwaitingApproval);
    assert!(waited.signature.is_none());
    assert!(
        waited
            .instruction
            .as_deref()
            .unwrap()
            .contains("wallet_wait_for_message")
    );
}

#[test]
fn sign_in_messages_are_parsed_and_bound_to_the_signing_wallet() {
    let (_directory, server) = server();
    accept_legal(&server);
    let Json(output) = sign_message(
        &server,
        &siwe_payload("0x1111111111111111111111111111111111111111"),
    )
    .unwrap();
    let siwe = output.siwe.unwrap();
    assert_eq!(siwe.domain, "example.com");
    assert_eq!(siwe.nonce, "32891756");
    assert!(
        !output
            .display
            .warnings
            .iter()
            .any(|warning| warning.contains("not a recognized sign-in message"))
    );

    // A login naming another account is refused before a request exists.
    let Err(error) = sign_message(
        &server,
        &siwe_payload("0x2222222222222222222222222222222222222222"),
    ) else {
        panic!("a sign-in for another account was queued");
    };
    assert!(error.message.contains("names account"));
}

#[test]
fn message_input_is_validated_before_anything_queues() {
    let (_directory, server) = server();
    accept_legal(&server);
    let Err(error) = server.wallet_sign_message(Parameters(SignMessageInput {
        wallet_id: "primary".into(),
        message_text: None,
        message_hex: Some(format!("0x{}", "ab".repeat(32))),
        chain_id: None,
    })) else {
        panic!("a bare 32-byte digest was queued for signing");
    };
    assert!(error.message.contains("eth_sign is not supported"));

    let both = server.wallet_sign_message(Parameters(SignMessageInput {
        wallet_id: "primary".into(),
        message_text: Some("gm".into()),
        message_hex: Some("0x676d".into()),
        chain_id: None,
    }));
    assert!(both.is_err());

    let neither = server.wallet_sign_message(Parameters(SignMessageInput {
        wallet_id: "primary".into(),
        message_text: None,
        message_hex: None,
        chain_id: None,
    }));
    assert!(neither.is_err());

    // A chain the server does not know is rejected outright, even though
    // the signature would not be bound to it.
    let foreign = server.wallet_sign_message(Parameters(SignMessageInput {
        wallet_id: "primary".into(),
        message_text: Some("gm".into()),
        message_hex: None,
        chain_id: Some("999999".into()),
    }));
    assert!(foreign.is_err());
}

fn order_payload() -> serde_json::Value {
    serde_json::json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Order": [
                {"name": "maker", "type": "address"},
                {"name": "amount", "type": "uint256"}
            ]
        },
        "primaryType": "Order",
        "domain": {
            "name": "Test Exchange",
            "chainId": 1,
            "verifyingContract": "0x4444444444444444444444444444444444444444"
        },
        "message": {
            "maker": "0x1111111111111111111111111111111111111111",
            "amount": "5"
        }
    })
}

#[test]
fn unrecognized_typed_data_queues_for_human_approval_and_never_signs_inline() {
    let (_directory, server) = server();
    accept_legal(&server);
    // The wallet policy is allow-all, but a payload that is not a
    // recognized permit cannot be policy-evaluated and must queue.
    let Json(output) = server
        .wallet_sign_typed_data(Parameters(SignTypedDataInput {
            wallet_id: "primary".into(),
            typed_data: order_payload(),
        }))
        .unwrap();
    assert_eq!(output.status, TypedDataStatus::AwaitingApproval);
    assert_eq!(output.chain_id, "1");
    assert!(output.signature.is_none());
    assert!(output.permit_approvals.is_none());
    assert!(
        output
            .instruction
            .as_deref()
            .unwrap()
            .contains("open review")
    );

    // A duplicate payload reuses the pending request.
    let Json(duplicate) = server
        .wallet_sign_typed_data(Parameters(SignTypedDataInput {
            wallet_id: "primary".into(),
            typed_data: order_payload(),
        }))
        .unwrap();
    assert_eq!(duplicate.request_id, output.request_id);

    // A chain the server does not know is rejected outright.
    let mut foreign = order_payload();
    foreign["domain"]["chainId"] = serde_json::json!(999_999);
    assert!(
        server
            .wallet_sign_typed_data(Parameters(SignTypedDataInput {
                wallet_id: "primary".into(),
                typed_data: foreign,
            }))
            .is_err()
    );
}

#[test]
fn a_recognized_permit_queues_even_under_the_most_permissive_policy() {
    let (_directory, server) = server();
    accept_legal(&server);
    // The wallet is on the allow-all policy, which authorizes approvals to
    // any spender for any token in unlimited amounts. No policy authorizes
    // a signature: a spender holding one permit under a limit can collect
    // an unbounded number of them, so every payload goes to a human.
    let Json(output) = server
        .wallet_sign_typed_data(Parameters(SignTypedDataInput {
            wallet_id: "primary".into(),
            typed_data: permit_payload(),
        }))
        .unwrap();
    assert_eq!(output.status, TypedDataStatus::AwaitingApproval);
    assert!(output.signature.is_none());
    assert!(output.approved_at.is_none());
    // The approvals it grants are still decoded, as review information.
    let approvals = output.permit_approvals.as_deref().unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].kind, "erc2612_permit");
    assert!(
        output
            .instruction
            .as_deref()
            .unwrap()
            .contains("open review")
    );
}

#[test]
fn policy_proposals_bind_revision_and_return_a_permission_diff() {
    let (_directory, server) = server();
    accept_legal(&server);
    let mut events = server.events.subscribe();
    let proposed = serde_json::to_value(WalletPolicy::require_approval_for_everything()).unwrap();

    // The wrong source revision is rejected with re-read guidance.
    let stale = server.wallet_propose_policy(Parameters(ProposePolicyInput {
        wallet_id: "primary".into(),
        source_revision: 7,
        policy: proposed.clone(),
        rationale: "tighten to approvals-only".into(),
    }));
    let Err(error) = stale else {
        panic!("stale source revision unexpectedly accepted");
    };
    assert!(error.message.contains("active revision"));

    let Json(output) = server
        .wallet_propose_policy(Parameters(ProposePolicyInput {
            wallet_id: "primary".into(),
            source_revision: 1,
            policy: proposed.clone(),
            rationale: "tighten to approvals-only".into(),
        }))
        .unwrap();
    assert_eq!(output.source_revision, 1);
    assert!(!output.replaced_previous_proposal);
    assert!(!output.diff.is_empty());
    assert!(output.diff.iter().any(|line| line.starts_with('-')));
    assert!(output.instruction.contains("open policy proposal primary"));
    assert!(matches!(
        events.try_recv().unwrap().kind,
        DomainEventKind::PolicyProposalChanged { wallet_id }
            if wallet_id == "primary"
    ));

    // A newer proposal replaces the pending one; the tool never touches
    // the active policy.
    let Json(second) = server
        .wallet_propose_policy(Parameters(ProposePolicyInput {
            wallet_id: "primary".into(),
            source_revision: 1,
            policy: proposed,
            rationale: "same change, updated rationale".into(),
        }))
        .unwrap();
    assert!(second.replaced_previous_proposal);
    assert!(matches!(
        events.try_recv().unwrap().kind,
        DomainEventKind::PolicyProposalChanged { wallet_id }
            if wallet_id == "primary"
    ));
    let policies = server.policies.lock().unwrap();
    assert_eq!(policies.get("primary").unwrap().unwrap().revision, 1);
    assert_eq!(
        policies.proposal("primary").unwrap().unwrap().rationale,
        "same change, updated rationale"
    );

    // An invalid document is rejected with authoring guidance.
    drop(policies);
    let invalid = server.wallet_propose_policy(Parameters(ProposePolicyInput {
        wallet_id: "primary".into(),
        source_revision: 1,
        policy: serde_json::json!({"version": 1, "rules": [], "unexpected": true}),
        rationale: "broken".into(),
    }));
    let Err(error) = invalid else {
        panic!("invalid policy unexpectedly accepted");
    };
    assert!(error.message.contains("policy-authoring"));
}

#[test]
fn legal_tool_reports_status_and_document_text() {
    let (_directory, server) = server();
    let Json(output) = server
        .wallet_get_legal(Parameters(LegalInput {
            document: Some(LegalDocument::PrivacyPolicy),
        }))
        .unwrap();
    assert!(!output.status.signing_allowed);
    assert!(output.instruction.contains("Legal"));
    let document = output.document.unwrap();
    assert!(document.text.contains("RPC"));
    assert_eq!(document.digest, LegalDocument::PrivacyPolicy.digest());

    accept_legal(&server);
    let Json(output) = server
        .wallet_get_legal(Parameters(LegalInput { document: None }))
        .unwrap();
    assert!(output.status.signing_allowed);
    assert!(output.document.is_none());
}

#[test]
fn server_advertises_the_security_resource_and_rpc_simulation_boundary() {
    let (_directory, server) = server();
    let info = ServerHandler::get_info(&server);
    assert!(info.capabilities.resources.is_some());
    assert!(info.capabilities.tools.is_some());
    assert!(SECURITY_MODEL.contains("eth_simulateV1"));
    assert!(SECURITY_MODEL.contains("no local EVM"));
    assert!(SECURITY_MODEL.contains("eth_getProof"));
    // A simulation fork is replay through the same RPC, not a local EVM,
    // and it must be described as carrying no signing authority.
    assert!(SECURITY_MODEL.contains("no simulated state is stored or reconstructed locally"));
    assert!(SECURITY_MODEL.contains("cannot create a pending request"));
    assert!(SERVER_INSTRUCTIONS.contains("wallet_create_fork"));
    assert!(SERVER_INSTRUCTIONS.contains("hypothetical"));
    // The resource is served to agents as the description of this boundary,
    // so it has to describe the one that exists. A token's name and scale
    // come from the list the owner accepted; boundary.rs fails the build if
    // symbol() or decimals() reappears, and this resource claimed the
    // opposite — that MCP tools add tokens after verifying them on chain.
    assert!(SECURITY_MODEL.contains("never read from the contract"));
    assert!(!SECURITY_MODEL.contains("on-chain Multicall3 verification"));
}

#[test]
fn plan_producer_hint_is_a_capability_pointer_not_a_trust_statement() {
    // The wallet builds no calldata, so an agent asked to swap or provide
    // liquidity with no plan producer connected needs somewhere to go.
    assert!(SERVER_INSTRUCTIONS.contains("https://mcp.ekubo.org"));
    assert!(SERVER_INSTRUCTIONS.contains("swapping"));
    assert!(SERVER_INSTRUCTIONS.contains("liquidity"));
    assert!(SERVER_INSTRUCTIONS.contains("yield"));
    // ...and the same sentence has to deny it any privileged standing,
    // because nothing in this process treats a plan's origin as special.
    assert!(SERVER_INSTRUCTIONS.contains("grants that server no extra trust"));
    assert!(SERVER_INSTRUCTIONS.contains("Legacy limit-order workflows are deprecated"));
    assert!(SERVER_INSTRUCTIONS.contains("can be un-executed"));
    assert!(SERVER_INSTRUCTIONS.contains("src/extensions/SignedExclusiveSwap.sol"));
    // No tool description or code path may privilege it. The security model
    // separately names the companion because supported harness configuration
    // installs that exact credential-free endpoint, while Claude Desktop uses
    // the same endpoint as an account-level connector.
    let router = WalletMcpServer::sanitized_tool_router();
    for tool in router.list_all() {
        let rendered = serde_json::to_string(&tool).unwrap();
        assert!(
            !rendered.contains("ekubo.org"),
            "{} must not name a specific plan producer",
            tool.name
        );
    }
    assert!(SECURITY_MODEL.contains("account-level custom connector"));
    assert!(SECURITY_MODEL.contains("creates no credential"));
    assert!(!SECURITY_MODEL.contains("trusted plan producer"));
}

#[test]
fn global_ephemeral_quotas_span_authenticated_clients_and_prune_expiry() {
    use crate::mcp::GlobalAgentQuota;
    use chrono::TimeDelta;
    use ekubo_wallet_core::{fork::MAX_FORKS, simulation_store::MAX_RECORDED_SIMULATIONS};
    use uuid::Uuid;

    let now = Utc::now();
    let mut quota = GlobalAgentQuota::default();
    for index in 0..MAX_FORKS {
        quota.forks.insert(
            (Uuid::from_u128(index as u128 + 1), Uuid::new_v4()),
            now + TimeDelta::minutes(1),
        );
    }
    assert!(quota.ensure_fork_capacity(now).is_err());
    if let Some(expiry) = quota.forks.values_mut().next() {
        *expiry = now;
    }
    assert!(quota.ensure_fork_capacity(now).is_ok());

    for index in 0..MAX_RECORDED_SIMULATIONS {
        quota.simulations.insert(
            (Uuid::from_u128(index as u128 + 1), Uuid::new_v4()),
            now + TimeDelta::minutes(1),
        );
    }
    quota.prune(now);
    assert_eq!(quota.simulations.len(), MAX_RECORDED_SIMULATIONS);
}
