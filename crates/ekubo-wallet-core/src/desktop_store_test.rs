use super::*;

const REDIRECT: &str = "http://127.0.0.1:43119/callback";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc";

fn agent_authorization() -> OwnerAuthorization {
    OwnerAuthorization::for_test(OwnerAuthorizationScope::AgentAccess)
}

fn store(key: u8) -> DesktopStore {
    let directory = tempfile::tempdir().unwrap();
    DesktopStore::open(
        &directory.keep().join("wallet.db"),
        &DatabaseKey::new([key; 32]),
    )
    .unwrap()
}

fn register(store: &mut DesktopStore) -> McpClient {
    store
        .register_oauth_client("Codex", AgentKind::Codex, &[REDIRECT.to_owned()], None)
        .unwrap()
}

fn authorize_and_exchange(store: &mut DesktopStore, client: &McpClient) -> OAuthTokenPair {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let code = store
        .issue_authorization_code(
            client.id,
            REDIRECT,
            &challenge,
            MCP_SCOPE,
            MCP_RESOURCE,
            &agent_authorization(),
        )
        .unwrap();
    store
        .exchange_authorization_code(
            &code.code.expose_base64url(),
            client.id,
            REDIRECT,
            VERIFIER,
            MCP_RESOURCE,
        )
        .unwrap()
}

#[test]
fn registration_creates_no_credential_until_owner_authorizes_login() {
    let mut store = store(31);
    let client = register(&mut store);
    assert!(store.clients().unwrap().is_empty());

    let pair = authorize_and_exchange(&mut store, &client);
    assert_eq!(pair.expires_in, 24 * 60 * 60);
    assert_eq!(store.clients().unwrap()[0].id, client.id);
    assert_eq!(
        store
            .authenticate_access_token(&pair.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .unwrap()
            .id,
        client.id
    );
}

#[test]
fn oauth_refresh_families_have_a_hard_non_sliding_session_expiry() {
    let mut store = store(36);
    let client = register(&mut store);
    let pair = authorize_and_exchange(&mut store, &client);
    let refresh = pair.refresh_token.expose_base64url();
    let original_expiration = store
        .connection
        .query_row(
            "SELECT expires_at FROM oauth_refresh_tokens WHERE consumed_at IS NULL",
            [],
            |row| Ok(row.get::<_, crate::sql::Millis>(0)?.0),
        )
        .unwrap();

    store
        .refresh_access_token(&refresh, client.id, MCP_RESOURCE)
        .unwrap();
    let rotated_expiration = store
        .connection
        .query_row(
            "SELECT expires_at FROM oauth_refresh_tokens WHERE consumed_at IS NULL",
            [],
            |row| Ok(row.get::<_, crate::sql::Millis>(0)?.0),
        )
        .unwrap();
    assert_eq!(rotated_expiration, original_expiration);
}

#[test]
fn owner_selected_oauth_access_and_refresh_lifetimes_are_bound_to_the_code() {
    let mut store = store(37);
    let client = register(&mut store);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let before = chrono::Utc::now();
    let code = store
        .issue_authorization_code_with_session(
            client.id,
            REDIRECT,
            &challenge,
            MCP_SCOPE,
            MCP_RESOURCE,
            OAuthSessionPreset::OneWeekOneMonth,
            &agent_authorization(),
        )
        .unwrap();
    let pair = store
        .exchange_authorization_code(
            &code.code.expose_base64url(),
            client.id,
            REDIRECT,
            VERIFIER,
            MCP_RESOURCE,
        )
        .unwrap();
    let expiration = store
        .connection
        .query_row(
            "SELECT expires_at FROM oauth_refresh_tokens WHERE consumed_at IS NULL",
            [],
            |row| Ok(row.get::<_, crate::sql::Millis>(0)?.0),
        )
        .unwrap();

    assert!(expiration >= before + chrono::Duration::days(30) - chrono::Duration::seconds(1));
    assert!(expiration <= chrono::Utc::now() + chrono::Duration::days(30));
    assert_eq!(
        store.clients().unwrap()[0].session_expires_at,
        Some(expiration)
    );
    assert_eq!(pair.expires_in, 7 * 24 * 60 * 60);
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT access_token_ttl_seconds FROM oauth_refresh_tokens",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        7 * 24 * 60 * 60
    );
    assert_eq!(
        OAuthSessionPreset::OneHourOneDay.as_query_value(),
        "hour-day"
    );
    assert_eq!(
        OAuthSessionPreset::OneWeekOneMonth.label(),
        "1 week / 1 month"
    );
    assert!(OAuthSessionPreset::parse_query_value("forever").is_err());
}

#[test]
fn agent_session_listing_retains_an_expired_absolute_deadline() {
    let mut store = store(40);
    let client = register(&mut store);
    let _pair = authorize_and_exchange(&mut store, &client);
    let expired_at = chrono::DateTime::from_timestamp_millis(
        (chrono::Utc::now() - chrono::Duration::minutes(1)).timestamp_millis(),
    )
    .unwrap();
    store
        .connection
        .execute(
            "UPDATE oauth_refresh_tokens SET expires_at = ?1 WHERE client_id = ?2",
            rusqlite::params![
                crate::sql::Millis(expired_at),
                crate::sql::Blob(*client.id.as_bytes())
            ],
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE oauth_authorization_codes SET session_expires_at = ?1 WHERE client_id = ?2",
            rusqlite::params![
                crate::sql::Millis(expired_at),
                crate::sql::Blob(*client.id.as_bytes())
            ],
        )
        .unwrap();

    assert_eq!(
        store.clients().unwrap()[0].session_expires_at,
        Some(expired_at)
    );
}

#[test]
fn authorization_codes_are_one_time_and_pkce_bound() {
    let mut store = store(32);
    let client = register(&mut store);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let code = store
        .issue_authorization_code(
            client.id,
            REDIRECT,
            &challenge,
            MCP_SCOPE,
            MCP_RESOURCE,
            &agent_authorization(),
        )
        .unwrap();
    let encoded = code.code.expose_base64url();
    assert!(
        store
            .exchange_authorization_code(
                &encoded,
                client.id,
                REDIRECT,
                &"Z".repeat(43),
                MCP_RESOURCE,
            )
            .is_err()
    );
    assert!(
        store
            .exchange_authorization_code(&encoded, client.id, REDIRECT, VERIFIER, MCP_RESOURCE,)
            .is_ok()
    );
    assert!(
        store
            .exchange_authorization_code(&encoded, client.id, REDIRECT, VERIFIER, MCP_RESOURCE,)
            .is_err()
    );
}

#[test]
fn refresh_token_is_stable_and_reusable_across_client_restarts() {
    let mut store = store(33);
    let client = register(&mut store);
    let first = authorize_and_exchange(&mut store, &client);
    let first_refresh = first.refresh_token.expose_base64url();
    let second = store
        .refresh_access_token(&first_refresh, client.id, MCP_RESOURCE)
        .unwrap();
    assert_eq!(second.refresh_token.expose_base64url(), first_refresh);
    let third = store
        .refresh_access_token(&first_refresh, client.id, MCP_RESOURCE)
        .unwrap();
    assert_eq!(third.refresh_token.expose_base64url(), first_refresh);
    assert!(
        store
            .authenticate_access_token(&second.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .authenticate_access_token(&third.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_some()
    );
}

#[test]
fn revocation_invalidates_access_without_removing_harness_registration() {
    let mut store = store(34);
    let client = register(&mut store);
    let pair = authorize_and_exchange(&mut store, &client);
    store.revoke_client(client.id).unwrap();
    assert!(
        store
            .authenticate_access_token(&pair.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .refresh_access_token(
                &pair.refresh_token.expose_base64url(),
                client.id,
                MCP_RESOURCE,
            )
            .is_err()
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT COUNT(*) FROM oauth_access_tokens", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT COUNT(*) FROM oauth_refresh_tokens", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
    assert!(
        store
            .oauth_client_for_authorization(client.id, REDIRECT)
            .is_ok()
    );
}

#[test]
fn removal_requires_agent_authorization_and_deletes_every_oauth_credential() {
    let mut store = store(39);
    let client = register(&mut store);
    let pair = authorize_and_exchange(&mut store, &client);
    let wrong_scope = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);

    assert!(store.remove_client(client.id, &wrong_scope).is_err());
    assert!(
        store
            .authenticate_access_token(&pair.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_some()
    );

    store
        .remove_client(client.id, &agent_authorization())
        .unwrap();
    assert!(store.clients().unwrap().is_empty());
    assert!(
        store
            .authenticate_access_token(&pair.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .refresh_access_token(
                &pair.refresh_token.expose_base64url(),
                client.id,
                MCP_RESOURCE,
            )
            .is_err()
    );
    assert!(
        store
            .oauth_client_for_authorization(client.id, REDIRECT)
            .is_err()
    );
}

#[test]
fn protected_desktop_settings_reject_the_wrong_authorization_scope() {
    let mut store = store(35);
    let client = register(&mut store);
    let wrong_scope = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    assert!(
        store
            .set_detailed_notification_previews(true, &wrong_scope)
            .is_err()
    );
    assert!(
        store
            .issue_authorization_code(
                client.id,
                REDIRECT,
                &challenge,
                MCP_SCOPE,
                MCP_RESOURCE,
                &wrong_scope,
            )
            .is_err()
    );
    assert!(store.clients().unwrap().is_empty());
}

#[test]
fn appearance_defaults_to_system_and_persists_in_the_encrypted_store() {
    let mut store = store(36);
    assert_eq!(
        store.appearance_preference().unwrap(),
        AppearancePreference::System
    );

    store
        .set_appearance_preference(AppearancePreference::Dark)
        .unwrap();
    assert_eq!(
        store.appearance_preference().unwrap(),
        AppearancePreference::Dark
    );

    store
        .set_appearance_preference(AppearancePreference::Light)
        .unwrap();
    assert_eq!(
        store.appearance_preference().unwrap(),
        AppearancePreference::Light
    );
}
