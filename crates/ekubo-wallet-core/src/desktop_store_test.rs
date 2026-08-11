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
fn refresh_tokens_rotate_and_reuse_revokes_the_family() {
    let mut store = store(33);
    let client = register(&mut store);
    let first = authorize_and_exchange(&mut store, &client);
    let first_refresh = first.refresh_token.expose_base64url();
    let second = store
        .refresh_access_token(&first_refresh, client.id, MCP_RESOURCE)
        .unwrap();
    assert!(
        store
            .refresh_access_token(&first_refresh, client.id, MCP_RESOURCE)
            .is_err()
    );
    assert!(
        store
            .authenticate_access_token(&second.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_none()
    );
}

#[test]
fn revocation_invalidates_access_without_removing_harness_registration() {
    let mut store = store(34);
    let client = register(&mut store);
    let pair = authorize_and_exchange(&mut store, &client);
    store
        .revoke_client(client.id, &agent_authorization())
        .unwrap();
    assert!(
        store
            .authenticate_access_token(&pair.access_token.expose_base64url(), MCP_RESOURCE)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .oauth_client_for_authorization(client.id, REDIRECT)
            .is_ok()
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
