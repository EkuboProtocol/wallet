use super::*;
use axum::http::HeaderValue;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ekubo_wallet_core::{
    desktop_store::{MCP_RESOURCE, MCP_SCOPE},
    human_presence::{OwnerAuthorization, OwnerAuthorizationScope},
    policy_store::DatabaseKey,
};
use sha2::{Digest as _, Sha256};

const REDIRECT: &str = "http://127.0.0.1:43821/callback";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abc";

fn clients() -> (Arc<Mutex<DesktopStore>>, String) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.keep().join("wallet.db");
    let mut store = DesktopStore::open(&path, &DatabaseKey::new([44; 32])).unwrap();
    let client = store
        .register_oauth_client("Codex", AgentKind::Codex, &[REDIRECT.to_owned()], None)
        .unwrap();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));
    let code = store
        .issue_authorization_code(
            client.id,
            REDIRECT,
            &challenge,
            MCP_SCOPE,
            MCP_RESOURCE,
            &OwnerAuthorization::for_test(OwnerAuthorizationScope::AgentAccess),
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
    (
        Arc::new(Mutex::new(store)),
        pair.access_token.expose_base64url(),
    )
}

#[test]
fn host_and_browser_cors_headers_are_rejected_before_dispatch() {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("127.0.0.1:61744"));
    assert!(validate_request_envelope(&Method::POST, &headers, "127.0.0.1:61744").is_ok());
    for forbidden in [
        "origin",
        "access-control-request-method",
        "access-control-request-headers",
        "access-control-request-private-network",
        "access-control-allow-origin",
    ] {
        headers.insert(forbidden, HeaderValue::from_static("attacker"));
        assert_eq!(
            validate_request_envelope(&Method::POST, &headers, "127.0.0.1:61744")
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.remove(forbidden);
    }
    assert_eq!(
        validate_request_envelope(&Method::OPTIONS, &headers, "127.0.0.1:61744")
            .unwrap_err()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    headers.insert("host", HeaderValue::from_static("localhost:61744"));
    assert_eq!(
        validate_request_envelope(&Method::GET, &headers, "127.0.0.1:61744")
            .unwrap_err()
            .status(),
        StatusCode::MISDIRECTED_REQUEST
    );
}

#[test]
fn mcp_requires_an_oauth_access_token_for_the_exact_resource() {
    let (clients, token) = clients();
    let mut headers = HeaderMap::new();
    assert_eq!(
        authenticate_headers(&headers, &clients)
            .unwrap_err()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    assert!(authenticate_headers(&headers, &clients).is_ok());
}

#[test]
fn unauthorized_challenge_points_to_protected_resource_metadata() {
    let response = unauthorized_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(challenge.contains("/.well-known/oauth-protected-resource"));
    assert!(challenge.contains(MCP_SCOPE));
}
