use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn release_has_no_terminal_or_stdio_dependency_surface() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    for forbidden in ["clap =", "clap_complete", "crossterm", "ratatui"] {
        assert!(
            !manifest.contains(forbidden),
            "Cargo.toml still contains {forbidden}"
        );
    }
    let main = fs::read_to_string(root().join("src/main.rs")).unwrap();
    assert!(main.contains("run_desktop"));
    assert!(!main.contains("run_cli"));
}

#[test]
fn mcp_has_no_owner_capability_or_local_file_transport() {
    let source = fs::read_to_string(root().join("src/mcp.rs")).unwrap();
    for forbidden in [
        "OwnerApi",
        "KeyStore",
        "OsKeyStore",
        "export_account",
        "approve_request",
        "set_network_disabled(",
        "install_policy_for_instance(",
        "apply_proposal(",
        "remove_reviewed(",
        "add_authorized(",
        "consume_proposals_authorized(",
        "record_acceptance(",
        "set_detailed_notification_previews(",
        "transport::stdio",
    ] {
        assert!(
            !source.contains(forbidden),
            "MCP module contains owner surface {forbidden}"
        );
    }
    let resolver =
        fs::read_to_string(root().join("crates/ekubo-wallet-core/src/plan_fetch.rs")).unwrap();
    assert!(!resolver.contains("read_local_file"));
    assert!(!resolver.contains("ArtifactSource::LocalFile"));
}

#[test]
fn local_ipc_transport_has_only_the_restricted_agent_capability() {
    let source = fs::read_to_string(root().join("src/ipc_server.rs")).unwrap();
    for forbidden in [
        "OwnerApi",
        "OwnerAuthorization",
        "KeyStore",
        "CustodyService",
    ] {
        assert!(
            !source.contains(forbidden),
            "IPC transport contains privileged capability {forbidden}"
        );
    }
    assert!(source.contains("AgentApi"));
    assert!(source.contains("peer_cred"));
    assert!(source.contains("0o600"));
    assert!(source.contains("ConvertStringSecurityDescriptorToSecurityDescriptorW"));
    assert!(source.contains("GetNamedPipeClientProcessId"));
    assert!(source.contains("token_sid_string"));
}

#[test]
fn walletconnect_adapter_has_only_the_restricted_dapp_capability() {
    let source = fs::read_to_string(root().join("src/walletconnect_handler.rs")).unwrap();
    for forbidden in [
        "OwnerApi",
        "KeyStore",
        "OsKeyStore",
        "execute_automatic",
        "PolicyStore",
        "PendingStore",
        "MessageStore",
        "TypedDataStore",
        "config_store",
    ] {
        assert!(
            !source.contains(forbidden),
            "WalletConnect adapter contains privileged surface {forbidden}"
        );
    }
    assert!(source.contains("DappApi"));
    assert!(source.contains("execute_transaction"));
}

#[test]
fn restricted_dapp_capability_has_no_owner_or_custody_operations() {
    let source = fs::read_to_string(root().join("src/authority.rs")).unwrap();
    let dapp = source
        .split_once("impl DappApi {")
        .and_then(|(_, rest)| rest.split_once("/// Owner-only operations."))
        .map(|(dapp, _)| dapp)
        .expect("DappApi implementation remains a distinct capability block");
    for forbidden in [
        "authorize_owner",
        "OwnerAuthorization",
        "CustodyService",
        "OsKeyStore",
        "PrivateKeyMaterial",
        "export_account",
        "set_network_disabled(",
        "install_policy_for_instance(",
        "apply_proposal(",
        "remove_reviewed(",
        "add_authorized(",
        "consume_proposals_authorized(",
        "record_acceptance(",
        "set_detailed_notification_previews(",
    ] {
        assert!(
            !dapp.contains(forbidden),
            "DappApi contains privileged surface {forbidden}"
        );
    }
}

#[test]
fn release_source_has_no_local_http_oauth_or_node_adapter() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("serde_urlencoded"));
    assert!(!manifest.contains("transport-streamable-http-server"));
    assert!(!root().join("src/http_server.rs").exists());
    assert!(!root().join("integrations/claude-desktop").exists());
    assert!(
        !root()
            .join("contrib/sync-claude-desktop-version.py")
            .exists()
    );

    for path in ["src", "crates/ekubo-wallet-core/src"] {
        for entry in walkdir::WalkDir::new(root().join(path)) {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy();
            if !entry.file_type().is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("rs")
                || name.ends_with("_test.rs")
            {
                continue;
            }
            let source = fs::read_to_string(entry.path()).unwrap();
            assert!(
                !source.contains("61744"),
                "{} binds the retired port",
                entry.path().display()
            );
            assert!(
                !source.to_ascii_lowercase().contains("oauth"),
                "{} retains local OAuth code",
                entry.path().display()
            );
        }
    }
}

#[test]
fn repository_links_a_current_system_wide_threat_model() {
    let readme = fs::read_to_string(root().join("README.md")).unwrap();
    assert!(readme.contains("docs/threat-model.md"));
    let security = fs::read_to_string(root().join("docs/security-boundary.md")).unwrap();
    assert!(security.contains("threat-model.md"));
    let threat_model = fs::read_to_string(root().join("docs/threat-model.md")).unwrap();
    for boundary in [
        "Owner authorization",
        "Local MCP IPC",
        "WalletConnect and dapps",
        "RPC, transactions, and policy",
        "Updates and release supply chain",
        "Residual risks and response",
    ] {
        assert!(threat_model.contains(boundary), "missing {boundary}");
    }
}

#[test]
fn gpui_revisions_and_desktop_database_identity_are_pinned() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(manifest.contains("cc053a4a6fa2fd0e8793201ed9099466af1be0b1"));
    assert!(manifest.contains("26cc9366abb27ccedce386ac99a615a8fa7018da"));
    let store =
        fs::read_to_string(root().join("crates/ekubo-wallet-core/src/policy_store.rs")).unwrap();
    assert!(store.contains("org.ekubo.wallet.db"));
    assert!(store.contains("wallet.db"));
}

#[test]
fn windows_resource_version_macro_is_rc_compatible() {
    let build_script = fs::read_to_string(root().join("build.rs")).unwrap();
    assert!(build_script.contains("format!(r#\"VERSION_STRING=\"{}\"\"#"));
    assert!(
        !build_script.contains("VERSION_STRING=\\\""),
        "RC.EXE receives macro arguments directly; escaped quotes become literal backslashes"
    );
}
