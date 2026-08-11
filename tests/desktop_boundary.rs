use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn release_has_no_terminal_or_stdio_dependency_surface() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    for forbidden in [
        "clap =",
        "clap_complete",
        "crossterm",
        "ratatui",
        "transport-io",
    ] {
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
        "export_account",
        "approve_request",
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
fn gpui_revisions_and_desktop_database_identity_are_pinned() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(manifest.contains("cc053a4a6fa2fd0e8793201ed9099466af1be0b1"));
    assert!(manifest.contains("26cc9366abb27ccedce386ac99a615a8fa7018da"));
    let store =
        fs::read_to_string(root().join("crates/ekubo-wallet-core/src/policy_store.rs")).unwrap();
    assert!(store.contains("org.ekubo.wallet.db"));
    assert!(store.contains("wallet.db"));
}
