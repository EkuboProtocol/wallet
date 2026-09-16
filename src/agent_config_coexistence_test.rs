use super::*;
use std::fmt::Write as _;

// Pin released 1.x keys independently of the v2 catalog under test.
const V1_KEYS: [&str; 8] = [
    "ekubo_wallet",
    "ekubo",
    "ekubo_aave",
    "ekubo_aerodrome",
    "ekubo_lido",
    "ekubo_merkl",
    "ekubo_morpho",
    "ekubo_sky",
];

fn v1_document(kind: AgentKind) -> String {
    let client = harness_argument(kind).unwrap();
    let helper = "/private/ekubo-wallet/helpers/ekubo-wallet-mcp-bridge";
    if matches!(kind, AgentKind::Codex | AgentKind::GrokBuild) {
        let mut document = String::from("# Owner's config\nmodel = 'keep'\n");
        let _ = writeln!(
            document,
            "\n[mcp_servers.ekubo_wallet]\ncommand = '{helper}'\nargs = ['--client', '{client}']"
        );
        for key in &V1_KEYS[1..] {
            let slug = key.strip_prefix("ekubo_").unwrap_or(key);
            let _ = writeln!(
                document,
                "\n[mcp_servers.{key}]\nurl = 'https://mcp.ekubo.org/mcp/{slug}'"
            );
        }
        document
    } else {
        let shape = match kind {
            AgentKind::Opencode => JsonShape::Local,
            AgentKind::GeminiCli => JsonShape::Gemini,
            _ => JsonShape::Stdio,
        };
        let mut servers: Map<String, Value> = V1_KEYS[1..]
            .iter()
            .map(|key| {
                let slug = key.strip_prefix("ekubo_").unwrap_or(key);
                (
                    key.to_string(),
                    remote_json_server(shape, &format!("https://mcp.ekubo.org/mcp/{slug}")),
                )
            })
            .collect();
        servers.insert("ekubo_wallet".into(), json_server(shape, helper, client));
        json!({json_root(kind): servers, "ownerSetting": "keep"}).to_string()
    }
}

fn assert_v1_preserved(kind: AgentKind, before: &str, after: &str) {
    if matches!(kind, AgentKind::Codex | AgentKind::GrokBuild) {
        let before = parse_codex_document(before).unwrap();
        let after = parse_codex_document(after).unwrap();
        assert_eq!(before["model"].as_str(), after["model"].as_str());
        // Compare values, not renderings: rewriting a table through toml_edit
        // normalizes its quotes while leaving every value identical.
        for key in V1_KEYS {
            let (before, after) = (&before["mcp_servers"][key], &after["mcp_servers"][key]);
            for field in ["url", "command"] {
                assert_eq!(
                    before.get(field).and_then(Item::as_str),
                    after.get(field).and_then(Item::as_str),
                    "{key}.{field} changed"
                );
            }
            assert_eq!(
                before.get("args").map(Item::to_string),
                after.get("args").map(Item::to_string),
                "{key}.args changed"
            );
        }
    } else {
        let before = parse_json_document(before).unwrap();
        let after = parse_json_document(after).unwrap();
        assert_eq!(before["ownerSetting"], after["ownerSetting"]);
        for key in V1_KEYS {
            assert_eq!(before[json_root(kind)][key], after[json_root(kind)][key]);
        }
    }
}

/// After v2 deselect or removal, the shared hosted keys are gone — v2 and 1.x
/// write the same keys, so taking an entry out takes it out for both — while
/// 1.x's own local entry and everything outside the managed keys survives.
fn assert_v1_companions_removed(kind: AgentKind, before: &str, after: &str) {
    if matches!(kind, AgentKind::Codex | AgentKind::GrokBuild) {
        let before = parse_codex_document(before).unwrap();
        let after = parse_codex_document(after).unwrap();
        assert_eq!(before["model"].as_str(), after["model"].as_str());
        let servers = after["mcp_servers"].as_table().unwrap();
        assert_eq!(
            before["mcp_servers"]["ekubo_wallet"].to_string(),
            servers["ekubo_wallet"].to_string()
        );
        for key in &V1_KEYS[1..] {
            assert!(
                !servers.contains_key(key),
                "{key} survived v2 deselect/removal"
            );
        }
    } else {
        let before = parse_json_document(before).unwrap();
        let after = parse_json_document(after).unwrap();
        assert_eq!(before["ownerSetting"], after["ownerSetting"]);
        let servers = after[json_root(kind)].as_object().unwrap();
        assert_eq!(
            before[json_root(kind)]["ekubo_wallet"],
            servers["ekubo_wallet"]
        );
        for key in &V1_KEYS[1..] {
            assert!(
                !servers.contains_key(*key),
                "{key} survived v2 deselect/removal"
            );
        }
    }
}

#[test]
fn every_harness_shares_hosted_keys_with_v1_across_install_repair_and_removal() {
    for kind in [
        AgentKind::Codex,
        AgentKind::GrokBuild,
        AgentKind::ClaudeCode,
        AgentKind::ClaudeDesktop,
        AgentKind::GeminiCli,
        AgentKind::Cursor,
        AgentKind::Opencode,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let filename = if matches!(kind, AgentKind::Codex | AgentKind::GrokBuild) {
            "config.toml"
        } else {
            "config.json"
        };
        let adapter = AgentAdapter {
            kind,
            display_name: "test harness",
            config_path: directory.path().join(filename),
        };
        let before = v1_document(kind);
        fs::write(&adapter.config_path, &before).unwrap();
        let mut selection = CompanionSelection::all();
        assert!(!adapter.has_wallet_entry().unwrap());
        assert!(!adapter.in_sync(&selection).unwrap());
        // Removal takes the shared hosted keys out with v2's own entries;
        // only 1.x's local entry and the owner's content survive it.
        let removal = adapter.preview_remove().unwrap();
        assert_v1_companions_removed(kind, &before, &removal.after);

        // Explicit installation is needed; launch repair must not see v1 as v2.
        ConfigBatchInstall::install(vec![adapter.preview_install(&selection).unwrap()])
            .unwrap()
            .commit();
        assert!(adapter.has_wallet_entry().unwrap());
        assert!(adapter.in_sync(&selection).unwrap());
        let installed = fs::read_to_string(&adapter.config_path).unwrap();
        // Claude Desktop's file never carries hosted servers, so even a full
        // install takes the shared keys out; every other harness rewrites
        // them byte-identically.
        if kind == AgentKind::ClaudeDesktop {
            assert_v1_companions_removed(kind, &before, &installed);
        } else {
            assert_v1_preserved(kind, &before, &installed);
        }
        assert!(!adapter.preview_install(&selection).unwrap().has_changes());

        // A stale v2 bridge is repaired without taking over any 1.x entry.
        let stale = installed.replace(BRIDGE_FILE_NAME, "stale-v2-helper");
        assert_ne!(stale, installed);
        fs::write(&adapter.config_path, stale).unwrap();
        assert!(adapter.has_wallet_entry().unwrap());
        assert!(!adapter.in_sync(&selection).unwrap());
        ConfigBatchInstall::install(vec![adapter.preview_install(&selection).unwrap()])
            .unwrap()
            .commit();
        assert!(adapter.in_sync(&selection).unwrap());
        if kind == AgentKind::ClaudeDesktop {
            assert_v1_companions_removed(
                kind,
                &before,
                &fs::read_to_string(&adapter.config_path).unwrap(),
            );
        } else {
            assert_v1_preserved(
                kind,
                &before,
                &fs::read_to_string(&adapter.config_path).unwrap(),
            );
        }

        for server in COMPANION_SERVERS {
            selection.set_enabled(server.slug, false);
        }
        ConfigBatchInstall::install(vec![adapter.preview_install(&selection).unwrap()])
            .unwrap()
            .commit();
        assert!(adapter.in_sync(&selection).unwrap());
        assert_v1_companions_removed(
            kind,
            &before,
            &fs::read_to_string(&adapter.config_path).unwrap(),
        );
        ConfigBatchInstall::install(vec![adapter.preview_remove().unwrap()])
            .unwrap()
            .commit();
        assert!(!adapter.has_wallet_entry().unwrap());
        assert_v1_companions_removed(
            kind,
            &before,
            &fs::read_to_string(&adapter.config_path).unwrap(),
        );
    }
}

#[test]
fn v2_batch_holds_the_released_v1_document_lock() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: directory.path().join("mcp.json"),
    };
    fs::write(&adapter.config_path, v1_document(adapter.kind)).unwrap();
    let batch = ConfigBatchInstall::install(vec![
        adapter.preview_install(&CompanionSelection::all()).unwrap(),
    ])
    .unwrap();
    // Open the literal released sidecar, not a name derived from v2 code.
    let legacy_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join(".mcp.json.ekubo-wallet.lock"))
        .unwrap();
    assert!(legacy_lock.try_lock_exclusive().is_err());
    batch.commit();
    legacy_lock.try_lock_exclusive().unwrap();
}

#[test]
fn a_v1_edit_invalidates_a_pending_v2_preview() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = AgentAdapter {
        kind: AgentKind::Cursor,
        display_name: "Cursor",
        config_path: directory.path().join("mcp.json"),
    };
    let before = v1_document(adapter.kind);
    fs::write(&adapter.config_path, &before).unwrap();
    let preview = adapter.preview_install(&CompanionSelection::all()).unwrap();
    let changed = before.replace("ekubo-wallet-mcp-bridge", "updated-v1-helper");
    fs::write(&adapter.config_path, &changed).unwrap();
    assert!(ConfigBatchInstall::install(vec![preview]).is_err());
    assert_eq!(fs::read_to_string(&adapter.config_path).unwrap(), changed);
}

#[test]
fn helper_replacement_and_cleanup_preserve_the_other_product() {
    let directory = tempfile::tempdir().unwrap();
    let v1_parent = directory.path().join("ekubo-wallet/helpers");
    let v2_parent = directory.path().join("ekubo-wallet-v2/helpers");
    fs::create_dir_all(&v1_parent).unwrap();
    let v1_name = if cfg!(windows) {
        "ekubo-wallet-mcp-bridge.exe"
    } else {
        "ekubo-wallet-mcp-bridge"
    };
    let v1 = v1_parent.join(v1_name);
    fs::write(&v1, b"v1 installed image").unwrap();
    let v2 = v2_parent.join(BRIDGE_FILE_NAME);
    install_bridge_image(&v2_parent, &v2, b"v2 initial image").unwrap();
    fs::write(
        v2_parent.join(format!("{BRIDGE_FILE_NAME}.old-0")),
        b"old v2",
    )
    .unwrap();
    // Even a misplaced 1.x helper is outside v2's cleanup prefix.
    let misplaced_v1 = v2_parent.join(v1_name);
    fs::write(&misplaced_v1, b"keep misplaced v1").unwrap();
    install_bridge_image(&v2_parent, &v2, b"v2 repaired image").unwrap();
    assert_eq!(fs::read(&v1).unwrap(), b"v1 installed image");
    assert_eq!(fs::read(&misplaced_v1).unwrap(), b"keep misplaced v1");
    assert!(!v2_parent.join(format!("{BRIDGE_FILE_NAME}.old-0")).exists());
    // Model released 1.x's prefix cleanup in its own helpers directory.
    for entry in fs::read_dir(&v1_parent).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_str().unwrap();
        if name != v1_name && name.starts_with("ekubo-wallet-mcp-bridge") {
            fs::remove_file(entry.path()).unwrap();
        }
    }
    assert_eq!(fs::read(&v2).unwrap(), b"v2 repaired image");
    assert_eq!(fs::read(&v1).unwrap(), b"v1 installed image");
}
