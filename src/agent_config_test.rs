use super::*;
use serde_json::json;

const HELPER: &str = "/private/ekubo-wallet-mcp-bridge";

#[test]
fn bridge_helper_path_is_fixed_outside_the_application_bundle() {
    let data_dir = ekubo_wallet_core::config::default_data_dir().unwrap();
    let helper = installed_bridge_path().unwrap();
    assert_eq!(helper.parent(), Some(data_dir.join("helpers").as_path()));
    let filename = helper.file_name().unwrap().to_string_lossy();
    assert_eq!(filename, BRIDGE_FILE_NAME);
    // A version in the name is what forced every managed agent config to be
    // rewritten on update, so the path must never carry one again.
    assert!(!filename.contains(env!("CARGO_PKG_VERSION")));
}

/// An update leaves every managed config untouched by design, so the config
/// can no longer answer whether an agent reaches this build. These bytes can.
#[test]
fn a_helper_from_another_build_is_not_reported_as_the_current_one() {
    let directory = tempfile::tempdir().unwrap();
    let installed = directory.path().join(BRIDGE_FILE_NAME);
    let packaged = b"bridge 1.3.0".as_slice();

    assert!(!installed_image_matches(&installed, packaged).unwrap());
    fs::write(&installed, b"bridge 1.2.0-longer").unwrap();
    assert!(!installed_image_matches(&installed, packaged).unwrap());
    // Same length, different build: the cheap length check must not be the
    // only one that runs.
    fs::write(&installed, b"bridge 1.2.9").unwrap();
    assert!(!installed_image_matches(&installed, packaged).unwrap());
    fs::write(&installed, packaged).unwrap();
    assert!(installed_image_matches(&installed, packaged).unwrap());
}

/// The desktop render tests build a wallet window, and its constructor starts
/// agent detection, which repairs the helper. Nothing in a test process won
/// the single-instance lock, so nothing in a test process may write the path
/// every agent on the machine executes — a plain `cargo test` used to replace
/// the installed release helper with the build tree's debug bridge and break
/// every agent session until a wallet reinstalled it.
///
/// The test process never grants authority, so this asserts the real default.
#[test]
fn a_process_that_lost_the_instance_lock_cannot_write_the_shared_helper() {
    assert!(
        !holds_helper_write_authority(),
        "a test process must never hold helper write authority"
    );
    let error = install_bridge_helper().unwrap_err();
    assert!(
        format!("{error:#}").contains("single-instance lock"),
        "unexpected error: {error:#}"
    );
}

/// The wallet claims the shared helper path once, at launch. When another
/// build's bytes land there afterwards, every harness keeps spawning a bridge
/// that version-mismatches against the running wallet, and the bridge's advice
/// to start a new agent session cannot help because the new session executes
/// the same stale bytes. The socket owner must be able to put its own image
/// back while it is still running.
#[test]
fn a_helper_clobbered_by_another_build_is_restored_in_place() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("helpers");
    let installed = parent.join(BRIDGE_FILE_NAME);
    let packaged = b"bridge 1.5.0".as_slice();

    install_bridge_image(&parent, &installed, packaged).unwrap();
    assert!(installed_image_matches(&installed, packaged).unwrap());

    // Another wallet build takes the path over while this one keeps running.
    fs::write(&installed, b"bridge 1.5.0+7af8600.dirty").unwrap();
    assert!(!installed_image_matches(&installed, packaged).unwrap());

    install_bridge_image(&parent, &installed, packaged).unwrap();
    assert_eq!(fs::read(&installed).unwrap(), packaged);
}

/// Re-asserting is triggered by a bridge connection, and a mismatched bridge
/// exits immediately — so a harness that respawns it must not make the wallet
/// re-read two helper images per attempt. The first check after launch is
/// never suppressed.
#[test]
fn reasserting_is_due_once_per_interval_but_never_skips_the_first() {
    let start = Instant::now();
    let just_inside = REASSERT_INTERVAL
        .checked_sub(Duration::from_millis(1))
        .expect("the interval is longer than a millisecond");
    let mut last = None;
    assert!(reassert_is_due(&mut last, start));
    assert!(!reassert_is_due(&mut last, start + REASSERT_INTERVAL / 2));
    assert!(!reassert_is_due(&mut last, start + just_inside));
    assert!(reassert_is_due(&mut last, start + REASSERT_INTERVAL));
    // The window restarts from the check that ran, not from launch.
    assert!(!reassert_is_due(
        &mut last,
        start + REASSERT_INTERVAL + Duration::from_millis(1)
    ));
}

#[test]
fn superseded_helper_path_skips_names_already_taken() {
    let directory = tempfile::tempdir().unwrap();
    let installed = directory.path().join(BRIDGE_FILE_NAME);
    let first = superseded_helper_path(&installed).unwrap();
    assert_eq!(
        first.file_name().unwrap().to_string_lossy(),
        format!("{BRIDGE_FILE_NAME}.old-0")
    );
    fs::write(&first, b"still running").unwrap();
    let second = superseded_helper_path(&installed).unwrap();
    assert_eq!(
        second.file_name().unwrap().to_string_lossy(),
        format!("{BRIDGE_FILE_NAME}.old-1")
    );
}

#[test]
fn superseded_helpers_are_collected_and_the_installed_one_is_kept() {
    let directory = tempfile::tempdir().unwrap();
    let installed = directory.path().join(BRIDGE_FILE_NAME);
    let unrelated = directory.path().join("notes.txt");
    for stale in [
        format!("{BRIDGE_NAME_PREFIX}-1.1.1"),
        format!("{BRIDGE_NAME_PREFIX}-1.2.0.exe"),
        format!("{BRIDGE_FILE_NAME}.old-0"),
    ] {
        fs::write(directory.path().join(stale), b"stale").unwrap();
    }
    fs::write(&installed, b"current").unwrap();
    fs::write(&unrelated, b"keep").unwrap();

    remove_superseded_helpers(directory.path());

    let remaining: std::collections::BTreeSet<String> = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        remaining,
        [BRIDGE_FILE_NAME.to_owned(), "notes.txt".to_owned()]
            .into_iter()
            .collect()
    );
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
    let output = merge_codex(before, HELPER, "codex", &CompanionSelection::all()).unwrap();
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
    assert_companion_tables(&parsed, &CompanionSelection::all());
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
    let output = merge_codex(before, HELPER, "grok-build", &CompanionSelection::all()).unwrap();
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
    assert_companion_tables(&parsed, &CompanionSelection::all());
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
        let companions = include_companion.then(CompanionSelection::all);
        let before = format!(
            r#"{{"keep":7,"{root}":{{"ekubo_wallet":{{"type":"http","url":"http://127.0.0.1:61744/mcp","auth":"oauth","headers":{{"Authorization":"secret"}},"env":{{"TOKEN":"secret"}}}}}}}}"#
        );
        let output = merge_json(&before, root, shape, HELPER, client, companions.as_ref()).unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["keep"], 7);
        assert_eq!(
            parsed[root][LOCAL_SERVER_NAME],
            json_server(shape, HELPER, client)
        );
        for server in COMPANION_SERVERS {
            assert_eq!(
                parsed[root][server.config_key],
                remote_json_server(shape, server.url),
                "{client} did not write {}",
                server.title
            );
        }
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
        None,
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["mcpServers"]["keep"]["command"], "keep");
    assert_eq!(
        parsed["mcpServers"][LOCAL_SERVER_NAME],
        json_server(JsonShape::Stdio, HELPER, "claude-desktop")
    );
    for server in COMPANION_SERVERS {
        assert!(parsed["mcpServers"].get(server.config_key).is_none());
    }
}

/// Whether an agent is installed is a question about the two managed entries,
/// not about the bytes of the file around them. Claude Code rewrites
/// `~/.claude.json` on every launch — it counts them — and writes it without
/// the trailing newline this wallet's JSON serializer appends. Comparing whole
/// files therefore reported a correctly configured harness as uninstalled from
/// the first launch after installing it, while Codex, whose TOML round-trips
/// byte for byte, went on reporting the truth.
#[test]
fn a_harness_that_rewrote_its_own_config_still_reads_as_installed() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("claude.json");
    let helper = installed_bridge_path().unwrap();
    let adapter = AgentAdapter {
        kind: AgentKind::ClaudeCode,
        display_name: "Claude Code",
        config_path: config.clone(),
    };

    // Nothing there at all, a file with nothing in it, and a file holding no
    // entries of ours. None of the three is an error to report.
    assert!(!adapter.in_sync(&CompanionSelection::all()).unwrap());
    fs::write(&config, "  \n\t\n").unwrap();
    assert!(!adapter.in_sync(&CompanionSelection::all()).unwrap());
    fs::write(&config, r#"{"numStartups":507}"#).unwrap();
    assert!(!adapter.in_sync(&CompanionSelection::all()).unwrap());

    let installed = merge_json(
        r#"{"numStartups":507}"#,
        "mcpServers",
        JsonShape::Stdio,
        &helper.to_string_lossy(),
        "claude-code",
        Some(&CompanionSelection::all()),
    )
    .unwrap();
    fs::write(&config, &installed).unwrap();
    assert!(adapter.in_sync(&CompanionSelection::all()).unwrap());

    // What the harness leaves behind the next time it saves: our exact
    // entries, its own bytes. The trailing newline alone was the whole of the
    // difference on the machine this was found on.
    let without_newline = installed.trim_end().to_owned();
    assert_ne!(without_newline, installed);
    fs::write(&config, &without_newline).unwrap();
    assert!(adapter.in_sync(&CompanionSelection::all()).unwrap());

    let reformatted =
        serde_json::to_string(&serde_json::from_str::<Value>(&installed).unwrap()).unwrap();
    assert_ne!(reformatted, installed);
    fs::write(&config, &reformatted).unwrap();
    assert!(adapter.in_sync(&CompanionSelection::all()).unwrap());

    // A harness that dropped the entries is genuinely not installed.
    let removed = remove_json(&installed, "mcpServers").unwrap();
    fs::write(&config, &removed).unwrap();
    assert!(!adapter.in_sync(&CompanionSelection::all()).unwrap());

    // A configuration that does not parse is something the owner can act on,
    // so it must not read as a quiet "not installed".
    fs::write(&config, "{not json").unwrap();
    assert!(adapter.in_sync(&CompanionSelection::all()).is_err());
}

#[test]
fn malformed_or_wrong_root_documents_are_rejected() {
    let all = CompanionSelection::all();
    assert!(merge_codex("not = [toml", HELPER, "codex", &all).is_err());
    assert!(
        merge_json(
            "[]",
            "mcpServers",
            JsonShape::Stdio,
            HELPER,
            "cursor",
            Some(&all)
        )
        .is_err()
    );
    assert!(
        merge_json(
            r#"{"mcpServers":[]}"#,
            "mcpServers",
            JsonShape::Stdio,
            HELPER,
            "cursor",
            Some(&all),
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
        Some(&CompanionSelection::all()),
    )
    .unwrap();
    let diff = managed_config_diff(AgentKind::Cursor, before, &after).unwrap();
    assert!(!diff.contains("do-not-print"));
    assert!(diff.contains("mcpServers.ekubo_wallet"));
}

#[test]
fn local_and_companion_names_are_stable() {
    assert_eq!(LOCAL_SERVER_NAME, "ekubo_wallet");
    // Ekubo's own server keeps the pre-split key, which is what retargets an
    // existing entry at the per-protocol endpoint instead of leaving it
    // beside a differently named one.
    assert_eq!(
        COMPANION_SERVERS[0].config_key,
        ekubo_wallet_core::mcp_companions::LEGACY_COMPANION_KEY
    );
    assert_eq!(COMPANION_SERVERS[0].url, "https://mcp.ekubo.org/mcp/ekubo");
    assert_eq!(
        managed_keys().collect::<Vec<_>>(),
        [
            "ekubo_wallet",
            "ekubo",
            "ekubo_aave",
            "ekubo_aerodrome",
            "ekubo_lido",
            "ekubo_merkl",
            "ekubo_morpho",
            "ekubo_sky",
        ]
    );
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
    for key in managed_keys() {
        assert!(!servers.contains_key(key));
    }

    for root in ["mcpServers", "mcp"] {
        let before = format!(
            r#"{{"keep":7,"{root}":{{"keep":{{"command":"keep"}},"ekubo_wallet":{{"command":"bridge"}},"ekubo":{{"url":"https://mcp.ekubo.org/mcp"}}}}}}"#
        );
        let removed = remove_json(&before, root).unwrap();
        let parsed: Value = serde_json::from_str(&removed).unwrap();
        assert_eq!(parsed["keep"], 7);
        assert_eq!(parsed[root]["keep"]["command"], "keep");
        for key in managed_keys() {
            assert!(parsed[root].get(key).is_none());
        }
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

/// The bridge path validation compares against.
///
/// The older tests write a fixture path and never re-validate, but every test
/// below asserts that the wallet's own write satisfies the wallet's own
/// validation — and validation requires the exact installed helper path,
/// because that is the whole point of it.
fn installed_helper() -> String {
    installed_bridge_path()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// The helper the TOML tests share: every selected server present with only
/// its URL, and nothing unselected left behind.
fn assert_companion_tables(parsed: &DocumentMut, selection: &CompanionSelection) {
    let servers = parsed["mcp_servers"].as_table().unwrap();
    for server in selection.enabled() {
        let table = servers[server.config_key].as_table().unwrap();
        assert_eq!(table.len(), 1, "{} carries unmanaged fields", server.title);
        assert_eq!(table["url"].as_str(), Some(server.url));
    }
    for server in selection.disabled() {
        assert!(
            !servers.contains_key(server.config_key),
            "{} was not removed",
            server.title
        );
    }
}

/// The default is every Ekubo-provided server, so a fresh install writes all
/// seven — not the single pre-split entry, and not none of them.
#[test]
fn a_default_selection_writes_every_hosted_server() {
    let selection = CompanionSelection::all();
    let output = merge_json(
        "{}",
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&selection),
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    let servers = parsed["mcpServers"].as_object().unwrap();
    assert_eq!(servers.len(), COMPANION_SERVERS.len() + 1);
    for server in COMPANION_SERVERS {
        assert_eq!(
            servers[server.config_key],
            json!({"type": "http", "url": server.url})
        );
    }
    assert!(
        validate_json_shape(&output, AgentKind::Cursor, &selection).is_ok(),
        "the wallet's own write must satisfy its own validation"
    );
}

/// Switching a server off has to take its entry out of an agent that already
/// holds it. Insert-only would leave the harness carrying a URL the owner just
/// declined, and would report the write as successful.
#[test]
fn deselecting_a_server_removes_it_from_an_existing_config() {
    let mut selection = CompanionSelection::all();
    let installed = merge_json(
        "{}",
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&selection),
    )
    .unwrap();
    selection.set_enabled("aave", false);
    selection.set_enabled("sky", false);
    let after = merge_json(
        &installed,
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&selection),
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&after).unwrap();
    assert!(parsed["mcpServers"].get("ekubo_aave").is_none());
    assert!(parsed["mcpServers"].get("ekubo_sky").is_none());
    assert_eq!(
        parsed["mcpServers"]["ekubo_morpho"],
        json!({"type": "http", "url": "https://mcp.ekubo.org/mcp/morpho"})
    );
    assert!(validate_json_shape(&after, AgentKind::Cursor, &selection).is_ok());
}

/// The same for Codex's TOML, where the entries are tables rather than
/// objects and the removal path is a different one.
#[test]
fn deselecting_a_server_removes_it_from_an_existing_codex_config() {
    let mut selection = CompanionSelection::all();
    let installed = merge_codex("", &installed_helper(), "codex", &selection).unwrap();
    selection.set_enabled("lido", false);
    let after = merge_codex(&installed, &installed_helper(), "codex", &selection).unwrap();
    assert_companion_tables(&after.parse::<DocumentMut>().unwrap(), &selection);
}

/// Validation has to fail in both directions, or "the write succeeded" would
/// stop meaning "the file says what the owner chose".
#[test]
fn validation_rejects_a_config_that_disagrees_with_the_selection() {
    let all = CompanionSelection::all();
    let mut without_aave = all.clone();
    without_aave.set_enabled("aave", false);

    let full = merge_json(
        "{}",
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&all),
    )
    .unwrap();
    // Every server present, but the owner asked for one fewer.
    let error = validate_json_shape(&full, AgentKind::Cursor, &without_aave).unwrap_err();
    assert!(format!("{error:#}").contains("was not removed"));

    let trimmed = merge_json(
        "{}",
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&without_aave),
    )
    .unwrap();
    // One server missing, and the owner asked for it.
    let error = validate_json_shape(&trimmed, AgentKind::Cursor, &all).unwrap_err();
    assert!(format!("{error:#}").contains("is missing"));

    // A credential riding alongside the URL is still refused.
    let smuggled = trimmed.replace(
        r#""url": "https://mcp.ekubo.org/mcp/ekubo""#,
        r#""url": "https://mcp.ekubo.org/mcp/ekubo", "headers": {"Authorization": "secret"}"#,
    );
    assert_ne!(smuggled, trimmed);
    assert!(validate_json_shape(&smuggled, AgentKind::Cursor, &without_aave).is_err());
}

/// The upgrade case. Every configuration written before the split names the
/// single `ekubo` server at `/mcp`; installing over it must retarget that same
/// key at `/mcp/ekubo` and add the rest, leaving the harness's own entries
/// alone.
#[test]
fn a_pre_split_config_is_retargeted_rather_than_duplicated() {
    let before = r#"{"mcpServers":{"keep":{"command":"keep"},"ekubo_wallet":{"command":"bridge"},"ekubo":{"type":"http","url":"https://mcp.ekubo.org/mcp"}}}"#;
    let selection = CompanionSelection::all();
    let after = merge_json(
        before,
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&selection),
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&after).unwrap();
    assert_eq!(parsed["mcpServers"]["keep"]["command"], "keep");
    assert_eq!(
        parsed["mcpServers"]["ekubo"]["url"],
        "https://mcp.ekubo.org/mcp/ekubo"
    );
    // The all-protocol endpoint is nowhere in the result: an agent given it
    // alongside the per-protocol servers would carry every tool twice.
    assert!(!after.contains(r#""https://mcp.ekubo.org/mcp""#));
    assert!(validate_json_shape(&after, AgentKind::Cursor, &selection).is_ok());
}

/// A pre-split config is a wallet the owner installed, so it reads as
/// present-but-stale rather than as absent. That distinction is what lets the
/// wallet bring it up to date on its own instead of showing the owner a button
/// they should never have needed.
#[test]
fn a_pre_split_config_reads_as_present_but_out_of_sync() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("mcp.json");
    let helper = installed_bridge_path().unwrap();
    let adapter = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: config.clone(),
    };
    let selection = CompanionSelection::all();
    assert!(!adapter.has_wallet_entry().unwrap());

    // Serialized rather than interpolated. A Windows helper path is
    // `C:\Users\…`, and splicing it into a JSON string literal emits invalid
    // escapes — `\U` is not one — so the fixture was unparseable there and the
    // entry it is supposed to establish read as absent.
    let legacy = serde_json::json!({
        "mcpServers": {
            "ekubo_wallet": {
                "command": helper.to_string_lossy(),
                "args": ["--client", "cursor"],
            },
            "ekubo": {"type": "http", "url": "https://mcp.ekubo.org/mcp"},
        }
    })
    .to_string();
    fs::write(&config, &legacy).unwrap();
    assert!(adapter.has_wallet_entry().unwrap());
    assert!(!adapter.in_sync(&selection).unwrap());

    let preview = adapter.preview_install(&selection).unwrap();
    assert!(preview.has_changes());
    ConfigBatchInstall::install(vec![preview]).unwrap().commit();
    assert!(adapter.has_wallet_entry().unwrap());
    assert!(adapter.in_sync(&selection).unwrap());
}

/// An agent the owner never connected is left alone. Propagating a selection
/// must reach every harness that already has this wallet and no others.
#[test]
fn an_unconnected_config_has_no_wallet_entry() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("mcp.json");
    let adapter = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: config.clone(),
    };
    for contents in [
        "",
        "  \n\t\n",
        r#"{"mcpServers":{"somebody-else":{"command":"other"}}}"#,
        // Even a config holding one of our hosted servers, but not our bridge,
        // is not a wallet the owner installed.
        r#"{"mcpServers":{"ekubo":{"type":"http","url":"https://mcp.ekubo.org/mcp/ekubo"}}}"#,
        "{not json",
    ] {
        fs::write(&config, contents).unwrap();
        assert!(
            !adapter.has_wallet_entry().unwrap(),
            "{contents} reported a wallet entry"
        );
    }
}

/// Selecting nothing is a coherent choice: the wallet's own bridge entry is
/// still written, because an owner who prepares plans some other way still
/// wants their agent able to reach the wallet.
#[test]
fn selecting_no_servers_still_writes_the_local_bridge() {
    let mut selection = CompanionSelection::all();
    for server in COMPANION_SERVERS {
        selection.set_enabled(server.slug, false);
    }
    let output = merge_json(
        "{}",
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&selection),
    )
    .unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    let servers = parsed["mcpServers"].as_object().unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(
        servers[LOCAL_SERVER_NAME],
        json_server(JsonShape::Stdio, &installed_helper(), "cursor")
    );
    assert!(validate_json_shape(&output, AgentKind::Cursor, &selection).is_ok());
}

/// The diff an owner reviews names every managed key that changed, including
/// the ones being taken away.
#[test]
fn the_managed_diff_names_a_server_being_removed() {
    let all = CompanionSelection::all();
    let before = merge_json(
        "{}",
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&all),
    )
    .unwrap();
    let mut without_merkl = all.clone();
    without_merkl.set_enabled("merkl", false);
    let after = merge_json(
        &before,
        "mcpServers",
        JsonShape::Stdio,
        &installed_helper(),
        "cursor",
        Some(&without_merkl),
    )
    .unwrap();
    let diff = managed_config_diff(AgentKind::Cursor, &before, &after).unwrap();
    assert!(diff.contains("mcpServers.ekubo_merkl"));
    assert!(diff.contains("<not configured>"));
    // Nothing else moved.
    assert!(!diff.contains("mcpServers.ekubo_morpho"));
}
