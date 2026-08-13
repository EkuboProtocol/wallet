use super::*;

#[test]
fn codex_uses_documented_oauth_mode_without_credentials_and_preserves_unknowns() {
    let output = merge_codex(
        "model = \"gpt\"\n[other]\nvalue = 7\n",
        "http://127.0.0.1:50000/mcp",
        true,
    )
    .unwrap();
    let parsed = output.parse::<DocumentMut>().unwrap();
    assert_eq!(parsed["model"].as_str(), Some("gpt"));
    assert_eq!(parsed["other"]["value"].as_integer(), Some(7));
    assert_eq!(
        parsed["mcp_oauth_credentials_store"].as_str(),
        Some("keyring")
    );
    assert_eq!(
        parsed["mcp_servers"][LOCAL_SERVER_NAME]["url"].as_str(),
        Some("http://127.0.0.1:50000/mcp")
    );
    assert_eq!(
        parsed["mcp_servers"][LOCAL_SERVER_NAME]["auth"].as_str(),
        Some("oauth")
    );
    assert!(
        parsed["mcp_servers"][LOCAL_SERVER_NAME]
            .get("http_headers")
            .is_none()
    );
}

/// Whatever else the entry held, the upsert leaves only the loopback URL and
/// OAuth mode: a stdio field would contradict the transport, and a header or
/// token field is a static credential this wallet never accepts.
#[test]
fn codex_upsert_clears_stdio_and_credential_fields() {
    let output = merge_codex(
        "[mcp_servers.ekubo_wallet]\ncommand = \"wallet\"\nargs = [\"serve\"]\nbearer_token_env_var = \"TOKEN\"\nhttp_headers = { Authorization = \"Bearer stale\" }\n\n",
        "http://127.0.0.1:50000/mcp",
        false,
    )
    .unwrap();
    let parsed = output.parse::<DocumentMut>().unwrap();
    let local = &parsed["mcp_servers"][LOCAL_SERVER_NAME];
    assert!(local.get("command").is_none());
    assert!(local.get("args").is_none());
    assert!(local.get("bearer_token_env_var").is_none());
    assert_eq!(local["url"].as_str(), Some("http://127.0.0.1:50000/mcp"));
    assert_eq!(local["auth"].as_str(), Some("oauth"));
    assert!(local.get("http_headers").is_none());
    assert_eq!(
        parsed["mcp_oauth_credentials_store"].as_str(),
        Some("keyring")
    );
}

#[test]
fn codex_upsert_replaces_file_oauth_storage_with_the_os_keyring() {
    let output = merge_codex(
        "mcp_oauth_credentials_store = \"file\"\n",
        "http://127.0.0.1:61744/mcp",
        false,
    )
    .unwrap();
    let parsed = output.parse::<DocumentMut>().unwrap();
    assert_eq!(
        parsed["mcp_oauth_credentials_store"].as_str(),
        Some("keyring")
    );
}

#[test]
fn every_json_shape_preserves_unrelated_servers() {
    for (root, shape) in [
        ("mcpServers", JsonShape::Url),
        ("mcpServers", JsonShape::HttpUrl),
        ("mcp", JsonShape::Remote),
    ] {
        let before =
            format!(r#"{{"keep":true,"{root}":{{"unrelated":{{"url":"https://example.com"}}}}}}"#);
        let output = merge_json(&before, root, shape, "http://127.0.0.1:50000/mcp", false).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["keep"], true);
        assert_eq!(parsed[root]["unrelated"]["url"], "https://example.com");
        assert!(parsed[root][LOCAL_SERVER_NAME].get("headers").is_none());
    }
}

#[test]
fn managed_json_diff_shows_only_changed_server_fields() {
    let before =
        r#"{"keep":{"large":"unrelated"},"mcpServers":{"other":{"url":"https://example.com"}}}"#;
    let after = merge_json(
        before,
        "mcpServers",
        JsonShape::Url,
        "http://127.0.0.1:61744/mcp",
        false,
    )
    .unwrap();
    let diff = managed_config_diff(AgentKind::Cursor, before, &after).unwrap();

    assert!(diff.contains("mcpServers.ekubo_wallet"));
    assert!(diff.contains("http://127.0.0.1:61744/mcp"));
    assert!(!diff.contains("large"));
    assert!(!diff.contains("other"));
}

#[test]
fn managed_codex_diff_does_not_echo_static_credentials_or_unrelated_settings() {
    let before = "model = \"gpt\"\n[mcp_servers.ekubo_wallet]\nurl = \"http://127.0.0.1:1/mcp\"\nhttp_headers = { Authorization = \"Bearer do-not-display\" }\n";
    let after = merge_codex(before, "http://127.0.0.1:61744/mcp", false).unwrap();
    let diff = managed_config_diff(AgentKind::Codex, before, &after).unwrap();

    assert!(diff.contains("mcp_servers.ekubo_wallet"));
    assert!(diff.contains("<credential field redacted>"));
    assert!(!diff.contains("do-not-display"));
    assert!(!diff.contains("model ="));
}

#[test]
fn a_failed_install_restores_without_persisting_a_credential_backup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mcp.json");
    fs::write(&path, "{\"keep\":true}\n").unwrap();
    let preview = ConfigPreview {
        path: path.clone(),
        before: "{\"keep\":true}\n".into(),
        after: "{".into(),
        diff: "redacted test diff".into(),
        validation: ConfigValidation::Installed {
            kind: AgentKind::Cursor,
            companion: false,
        },
    };
    assert!(preview.install().is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"keep\":true}\n");
    let backups = fs::read_dir(directory.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".backup-"))
        .count();
    assert_eq!(backups, 0);
}

#[test]
fn successful_install_keeps_secret_prior_bytes_only_in_memory() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mcp.json");
    let secret = "Bearer must-not-be-copied";
    fs::write(
        &path,
        format!(r#"{{"mcpServers":{{"other":{{"headers":{{"Authorization":"{secret}"}}}}}}}}"#),
    )
    .unwrap();
    let preview = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: path,
    }
    .preview_install(false)
    .unwrap();

    ConfigBatchInstall::install(vec![preview]).unwrap().commit();

    let files = fs::read_dir(directory.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 1);
    assert!(files[0].file_name().to_string_lossy().eq("mcp.json"));
}

#[test]
fn startup_shape_does_not_add_or_restore_the_remote_companion() {
    for (root, shape) in [
        ("mcpServers", JsonShape::Url),
        ("mcpServers", JsonShape::HttpUrl),
        ("mcp", JsonShape::Remote),
    ] {
        let output = merge_json("{}", root, shape, "http://127.0.0.1:61744/mcp", false).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert!(parsed[root].get(COMPANION_SERVER_NAME).is_none());
        assert_eq!(
            parsed[root][LOCAL_SERVER_NAME]
                .get("url")
                .or_else(|| parsed[root][LOCAL_SERVER_NAME].get("httpUrl"))
                .and_then(Value::as_str),
            Some("http://127.0.0.1:61744/mcp")
        );
    }
}

#[test]
fn managed_preview_contains_no_credential() {
    let preview = ConfigPreview {
        path: PathBuf::from("mcp.json"),
        before: String::new(),
        after: "http://127.0.0.1:61744/mcp".into(),
        diff: "+http://127.0.0.1:61744/mcp".into(),
        validation: ConfigValidation::Installed {
            kind: AgentKind::Cursor,
            companion: false,
        },
    };
    assert!(!preview.diff.contains("Authorization"));
    assert!(!preview.after.contains("Bearer"));
}

#[test]
fn automatic_upserts_skip_files_that_are_already_exact() {
    let preview = ConfigPreview {
        path: PathBuf::from("mcp.json"),
        before: "same".into(),
        after: "same".into(),
        diff: String::new(),
        validation: ConfigValidation::Installed {
            kind: AgentKind::Cursor,
            companion: false,
        },
    };
    assert!(!preview.has_changes());
}

#[test]
fn managed_previews_always_use_the_fixed_oauth_resource() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: directory.path().join("mcp.json"),
    };
    let preview = adapter.preview_install(false).unwrap();
    assert!(preview.after.contains("http://127.0.0.1:61744/mcp"));
    assert!(!preview.after.contains("Authorization"));
}

#[test]
fn install_rejects_a_parseable_config_with_static_credentials_and_rolls_back() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mcp.json");
    let before = "{\"keep\":true}\n";
    fs::write(&path, before).unwrap();
    let preview = ConfigPreview {
        path: path.clone(),
        before: before.into(),
        after: format!(
            "{{\"mcpServers\":{{\"{LOCAL_SERVER_NAME}\":{{\"type\":\"http\",\"url\":\"http://127.0.0.1:50000/mcp\",\"headers\":{{\"Authorization\":\"Bearer secret\"}}}}}}}}\n"
        ),
        diff: "redacted test diff".into(),
        validation: ConfigValidation::Installed {
            kind: AgentKind::Cursor,
            companion: false,
        },
    };
    let error = preview.install().unwrap_err();
    assert!(error.to_string().contains("validation failed"), "{error:#}");
    assert_eq!(fs::read_to_string(path).unwrap(), before);
}

#[test]
fn a_multi_agent_install_restores_every_earlier_file_when_one_fails() {
    let directory = tempfile::tempdir().unwrap();
    let first_path = directory.path().join("first.json");
    let second_path = directory.path().join("second.json");
    let first_before = "{\"keep\":1}\n";
    let second_before = "{\"keep\":2}\n";
    fs::write(&first_path, first_before).unwrap();
    fs::write(&second_path, second_before).unwrap();
    let first = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: first_path.clone(),
    }
    .preview_install(false)
    .unwrap();
    let invalid_second = ConfigPreview {
        path: second_path.clone(),
        before: second_before.into(),
        after: "{".into(),
        diff: "redacted test diff".into(),
        validation: ConfigValidation::Installed {
            kind: AgentKind::Cursor,
            companion: false,
        },
    };

    assert!(ConfigBatchInstall::install(vec![first, invalid_second]).is_err());
    assert_eq!(fs::read_to_string(first_path).unwrap(), first_before);
    assert_eq!(fs::read_to_string(second_path).unwrap(), second_before);
}
