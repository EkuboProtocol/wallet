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
        (AgentKind::GrokBuild, "grok_build", "Grok Build"),
    ];
    for (kind, value, label) in cases {
        assert_eq!(kind.as_str(), value);
        assert_eq!(AgentKind::parse(value).unwrap(), kind);
        assert_eq!(kind.label(), label);
    }
    assert!(AgentKind::parse("oauth-client").is_err());
}

/// Every column that stores a harness kind has to accept every kind the code
/// can hand it.
///
/// This is checked against the column rather than through one write, because
/// the failure it catches is silent until the exact combination happens: the
/// value is written by an `UPDATE` that runs after a request is already
/// stored — and, for an automatic send, after the key has been used — so a
/// kind the constraint rejects turns a completed signature into an error the
/// agent sees. `Grok Build` was accepted by the bridge handshake for six
/// releases while every one of these columns refused to store it.
#[test]
fn every_harness_column_accepts_every_harness_the_bridge_admits() {
    let (_directory, store) = store();
    let mut statement = store
        .connection
        .prepare(
            "SELECT name, sql FROM sqlite_master
             WHERE type = 'table' AND sql LIKE '%requesting_harness_kind%'",
        )
        .unwrap();
    let tables: Vec<(String, String)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        tables.len() >= 6,
        "expected every attribution table, found {tables:?}"
    );
    for (table, sql) in tables {
        for kind in AgentKind::ALL {
            assert!(
                sql.contains(&format!("'{}'", kind.as_str())),
                "{table} cannot store {}",
                kind.as_str()
            );
        }
    }
}

/// A database created before the vocabulary was fixed still refuses the kinds
/// it was created without, and that has to stay survivable rather than
/// become an error the caller sees.
///
/// The constraint cannot be widened in place — every mechanism `SQLite` offers
/// for it rewrites the table — so an existing wallet keeps the narrow column.
/// What changed is the consequence: `WalletMcpServer::with_attribution`
/// returns nothing, so a refused label leaves the request it was describing
/// exactly as it was. This pins the refusal itself, which is the input that
/// path has to tolerate.
#[test]
fn a_narrow_column_refuses_a_newer_harness_rather_than_storing_something_else() {
    let (_directory, store) = store();
    store
        .connection
        .execute_batch(
            "CREATE TABLE narrow_attribution (
                 request_id BLOB PRIMARY KEY NOT NULL,
                 requesting_harness_kind TEXT CHECK (
                     requesting_harness_kind IS NULL OR requesting_harness_kind IN
                     ('codex','claude_code','claude_desktop','gemini_cli','cursor','opencode')
                 )
             ) STRICT;
             INSERT INTO narrow_attribution(request_id) VALUES (x'00');",
        )
        .unwrap();

    let write = |kind: AgentKind| {
        store.connection.execute(
            "UPDATE narrow_attribution SET requesting_harness_kind = ?1 WHERE request_id = x'00'",
            [kind.as_str()],
        )
    };
    assert!(write(AgentKind::Codex).is_ok(), "a kind it was built with");
    assert!(
        write(AgentKind::GrokBuild).is_err(),
        "the constraint refuses rather than silently storing something else"
    );
    // Refused, so the row keeps the last label it accepted rather than being
    // left half-written.
    let stored: Option<String> = store
        .connection
        .query_row(
            "SELECT requesting_harness_kind FROM narrow_attribution WHERE request_id = x'00'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored.as_deref(), Some("codex"));
}
