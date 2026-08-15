use super::*;
use serde_json::json;

const HELPER: &str = "/private/ekubo-wallet-mcp-bridge-1.1.1";

#[test]
fn bridge_helper_is_versioned_outside_the_application_bundle() {
    let data_dir = ekubo_wallet_core::config::default_data_dir().unwrap();
    let helper = installed_bridge_path().unwrap();
    assert_eq!(helper.parent(), Some(data_dir.join("helpers").as_path()));
    let filename = helper.file_name().unwrap().to_string_lossy();
    assert!(filename.starts_with("ekubo-wallet-mcp-bridge-"));
    assert!(filename.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn codex_uses_exact_stdio_shape_and_removes_http_oauth_credentials() {
    let before = r#"
[unrelated]
keep = true
[mcp_servers.ekubo_wallet]
url = "http://127.0.0.1:61744/mcp"
auth = "oauth"
bearer_token_env_var = "SECRET"
http_headers = { Authorization = "Bearer secret" }
"#;
    let output = merge_codex(before, HELPER, "codex").unwrap();
    let parsed = output.parse::<DocumentMut>().unwrap();
    assert_eq!(parsed["unrelated"]["keep"].as_bool(), Some(true));
    let local = parsed["mcp_servers"][LOCAL_SERVER_NAME].as_table().unwrap();
    assert_eq!(local.len(), 2);
    assert_eq!(local["command"].as_str(), Some(HELPER));
    let args = local["args"].as_array().unwrap();
    assert_eq!(
        args.iter()
            .filter_map(toml_edit::Value::as_str)
            .collect::<Vec<_>>(),
        ["--client", "codex"]
    );
    assert_eq!(
        parsed["mcp_servers"][COMPANION_SERVER_NAME]["url"].as_str(),
        Some(COMPANION_SERVER_URL)
    );
}

#[test]
fn grok_build_uses_its_native_toml_shape_and_exact_bridge_identity() {
    let before = r#"
[models]
default = "grok-4.5"
[mcp_servers.ekubo_wallet]
url = "http://127.0.0.1:61744/mcp"
headers = { Authorization = "secret" }
"#;
    let output = merge_codex(before, HELPER, "grok-build").unwrap();
    let parsed = output.parse::<DocumentMut>().unwrap();
    assert_eq!(parsed["models"]["default"].as_str(), Some("grok-4.5"));
    let local = parsed["mcp_servers"][LOCAL_SERVER_NAME].as_table().unwrap();
    assert_eq!(local.len(), 2);
    assert_eq!(local["command"].as_str(), Some(HELPER));
    assert_eq!(
        local["args"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(toml_edit::Value::as_str)
            .collect::<Vec<_>>(),
        ["--client", "grok-build"]
    );
    assert_eq!(
        parsed["mcp_servers"][COMPANION_SERVER_NAME]["url"].as_str(),
        Some(COMPANION_SERVER_URL)
    );
}

#[test]
fn every_json_harness_gets_exact_credential_free_stdio_shape() {
    let cases = [
        (
            AgentKind::ClaudeCode,
            "mcpServers",
            JsonShape::Stdio,
            "claude-code",
            true,
        ),
        (
            AgentKind::GeminiCli,
            "mcpServers",
            JsonShape::Gemini,
            "gemini-cli",
            true,
        ),
        (
            AgentKind::Cursor,
            "mcpServers",
            JsonShape::Stdio,
            "cursor",
            true,
        ),
        (
            AgentKind::Opencode,
            "mcp",
            JsonShape::Local,
            "opencode",
            true,
        ),
    ];
    for (_kind, root, shape, client, include_companion) in cases {
        let before = format!(
            r#"{{"keep":7,"{root}":{{"ekubo_wallet":{{"type":"http","url":"http://127.0.0.1:61744/mcp","auth":"oauth","headers":{{"Authorization":"secret"}},"env":{{"TOKEN":"secret"}}}}}}}}"#
        );
        let output = merge_json(&before, root, shape, HELPER, client, include_companion).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["keep"], 7);
        assert_eq!(
            parsed[root][LOCAL_SERVER_NAME],
            json_server(shape, HELPER, client)
        );
        assert_eq!(
            parsed[root][COMPANION_SERVER_NAME],
            remote_json_server(shape, COMPANION_SERVER_URL)
        );
        let rendered = parsed[root][LOCAL_SERVER_NAME].to_string();
        for forbidden in [
            "61744",
            "oauth",
            "Authorization",
            "TOKEN",
            "secret",
            "url",
            "httpUrl",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{client} retained {forbidden}: {rendered}"
            );
        }
    }
}

#[test]
fn claude_desktop_keeps_only_local_stdio_in_its_config() {
    let before = r#"{"mcpServers":{"keep":{"command":"keep"},"ekubo":{"type":"http","url":"https://mcp.ekubo.org/mcp"}}}"#;
    let output = merge_json(
        before,
        "mcpServers",
        JsonShape::Stdio,
        HELPER,
        "claude-desktop",
        false,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["mcpServers"]["keep"]["command"], "keep");
    assert_eq!(
        parsed["mcpServers"][LOCAL_SERVER_NAME],
        json_server(JsonShape::Stdio, HELPER, "claude-desktop")
    );
    assert!(parsed["mcpServers"].get(COMPANION_SERVER_NAME).is_none());
}

#[test]
fn malformed_or_wrong_root_documents_are_rejected() {
    assert!(merge_codex("not = [toml", HELPER, "codex").is_err());
    assert!(merge_json("[]", "mcpServers", JsonShape::Stdio, HELPER, "cursor", true).is_err());
    assert!(
        merge_json(
            r#"{"mcpServers":[]}"#,
            "mcpServers",
            JsonShape::Stdio,
            HELPER,
            "cursor",
            true,
        )
        .is_err()
    );
}

#[test]
fn managed_diff_never_discloses_unrelated_credentials() {
    let before = r#"{"secret":"do-not-print","mcpServers":{}}"#;
    let after = merge_json(
        before,
        "mcpServers",
        JsonShape::Stdio,
        HELPER,
        "cursor",
        true,
    )
    .unwrap();
    let diff = managed_config_diff(AgentKind::Cursor, before, &after).unwrap();
    assert!(!diff.contains("do-not-print"));
    assert!(diff.contains("mcpServers.ekubo_wallet"));
}

#[test]
fn local_and_companion_names_are_stable() {
    assert_eq!(LOCAL_SERVER_NAME, "ekubo_wallet");
    assert_eq!(COMPANION_SERVER_NAME, "ekubo");
    assert_eq!(COMPANION_SERVER_URL, "https://mcp.ekubo.org/mcp");
    assert_eq!(
        json_server(JsonShape::Stdio, HELPER, "claude-desktop"),
        json!({
            "command": HELPER,
            "args": ["--client", "claude-desktop"]
        })
    );
}

#[test]
fn removal_deletes_only_wallet_managed_entries_for_every_shape() {
    let codex = r#"
[mcp_servers.keep]
command = "keep"
[mcp_servers.ekubo_wallet]
command = "bridge"
[mcp_servers.ekubo]
url = "https://mcp.ekubo.org/mcp"
"#;
    let removed = remove_codex(codex).unwrap();
    let parsed = parse_codex_document(&removed).unwrap();
    let servers = parsed["mcp_servers"].as_table().unwrap();
    assert!(servers.contains_key("keep"));
    assert!(!servers.contains_key(LOCAL_SERVER_NAME));
    assert!(!servers.contains_key(COMPANION_SERVER_NAME));

    for root in ["mcpServers", "mcp"] {
        let before = format!(
            r#"{{"keep":7,"{root}":{{"keep":{{"command":"keep"}},"ekubo_wallet":{{"command":"bridge"}},"ekubo":{{"url":"https://mcp.ekubo.org/mcp"}}}}}}"#
        );
        let removed = remove_json(&before, root).unwrap();
        let parsed: Value = serde_json::from_str(&removed).unwrap();
        assert_eq!(parsed["keep"], 7);
        assert_eq!(parsed[root]["keep"]["command"], "keep");
        assert!(parsed[root].get(LOCAL_SERVER_NAME).is_none());
        assert!(parsed[root].get(COMPANION_SERVER_NAME).is_none());
    }
}

#[test]
fn install_rejects_a_config_changed_after_its_preview() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mcp.json");
    std::fs::write(
        &path,
        r#"{"mcpServers":{"ekubo_wallet":{"command":"old"}}}"#,
    )
    .unwrap();
    let adapter = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: path.clone(),
    };
    let preview = adapter.preview_remove().unwrap();
    std::fs::write(&path, r#"{"mcpServers":{"keep":{"command":"new"}}}"#).unwrap();

    assert!(ConfigBatchInstall::install(vec![preview]).is_err());
    assert!(std::fs::read_to_string(path).unwrap().contains("new"));
}

#[test]
fn batch_rollback_does_not_overwrite_a_later_external_edit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mcp.json");
    std::fs::write(
        &path,
        r#"{"mcpServers":{"ekubo_wallet":{"command":"old"}}}"#,
    )
    .unwrap();
    let adapter = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: path.clone(),
    };
    let batch = ConfigBatchInstall::install(vec![adapter.preview_remove().unwrap()]).unwrap();
    std::fs::write(&path, r#"{"mcpServers":{"keep":{"command":"external"}}}"#).unwrap();

    drop(batch);
    assert!(std::fs::read_to_string(path).unwrap().contains("external"));
}
