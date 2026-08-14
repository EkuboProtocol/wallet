use super::*;
use crate::policy_store::DatabaseKey;

fn store() -> (tempfile::TempDir, DesktopStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = DesktopStore::open(
        &directory.path().join("wallet.db"),
        &DatabaseKey::new([0x42; 32]),
    )
    .unwrap();
    (directory, store)
}

#[test]
fn encrypted_application_settings_round_trip() {
    let (_directory, mut store) = store();
    assert_eq!(
        store.appearance_preference().unwrap(),
        AppearancePreference::System
    );
    assert!(!store.testnet_mode().unwrap());
    store
        .set_appearance_preference(AppearancePreference::Dark)
        .unwrap();
    store.set_testnet_mode(true).unwrap();
    assert_eq!(
        store.appearance_preference().unwrap(),
        AppearancePreference::Dark
    );
    assert!(store.testnet_mode().unwrap());
}

#[test]
fn every_supported_harness_has_a_stable_database_value_and_label() {
    let cases = [
        (AgentKind::Codex, "codex", "Codex"),
        (AgentKind::ClaudeCode, "claude_code", "Claude Code"),
        (AgentKind::ClaudeDesktop, "claude_desktop", "Claude Desktop"),
        (AgentKind::GeminiCli, "gemini_cli", "Gemini CLI"),
        (AgentKind::Cursor, "cursor", "Cursor"),
        (AgentKind::Opencode, "opencode", "opencode"),
    ];
    for (kind, value, label) in cases {
        assert_eq!(kind.as_str(), value);
        assert_eq!(AgentKind::parse(value).unwrap(), kind);
        assert_eq!(kind.label(), label);
    }
    assert!(AgentKind::parse("oauth-client").is_err());
}
