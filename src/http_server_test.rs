use super::*;
use axum::http::HeaderValue;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ekubo_wallet_core::{
    desktop_store::{DesktopStore, MCP_RESOURCE, MCP_SCOPE},
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
        .issue_authorization_code_with_session(
            client.id,
            REDIRECT,
            &challenge,
            MCP_SCOPE,
            MCP_RESOURCE,
            OAuthSessionPreset::OneDayOneWeek,
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
    assert!(validate_request_envelope(&Method::POST, "/mcp", &headers, "127.0.0.1:61744").is_ok());
    for forbidden in [
        "origin",
        "access-control-request-method",
        "access-control-request-headers",
        "access-control-request-private-network",
        "access-control-allow-origin",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-fetch-user",
    ] {
        headers.insert(forbidden, HeaderValue::from_static("attacker"));
        assert_eq!(
            validate_request_envelope(&Method::POST, "/mcp", &headers, "127.0.0.1:61744")
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        headers.remove(forbidden);
    }
    assert_eq!(
        validate_request_envelope(&Method::OPTIONS, "/mcp", &headers, "127.0.0.1:61744")
            .unwrap_err()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    headers.insert("host", HeaderValue::from_static("localhost:61744"));
    assert_eq!(
        validate_request_envelope(&Method::GET, "/mcp", &headers, "127.0.0.1:61744")
            .unwrap_err()
            .status(),
        StatusCode::MISDIRECTED_REQUEST
    );
}

#[test]
fn top_level_authorization_navigation_is_the_only_browser_shaped_request_allowed() {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("127.0.0.1:61744"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));

    assert!(
        validate_request_envelope(&Method::GET, "/authorize", &headers, "127.0.0.1:61744").is_ok()
    );
    for (method, path) in [
        (Method::GET, "/mcp"),
        (Method::POST, "/token"),
        (Method::POST, "/register"),
    ] {
        assert_eq!(
            validate_request_envelope(&method, path, &headers, "127.0.0.1:61744")
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
    assert_eq!(
        validate_request_envelope(&Method::GET, "/authorize", &headers, "127.0.0.1:61744")
            .unwrap_err()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn mcp_requires_an_oauth_access_token_for_the_exact_resource() {
    let (clients, token) = clients();
    let authenticate = |encoded: &str| {
        clients
            .lock()
            .ok()
            .and_then(|mut store| store.authenticate_access_token(encoded, MCP_RESOURCE).ok())
            .flatten()
    };
    let mut headers = HeaderMap::new();
    assert_eq!(
        authenticate_headers(&headers, authenticate)
            .unwrap_err()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    assert!(
        authenticate_headers(&headers, |encoded| {
            clients
                .lock()
                .ok()
                .and_then(|mut store| store.authenticate_access_token(encoded, MCP_RESOURCE).ok())
                .flatten()
        })
        .is_ok()
    );
}

#[test]
fn http_transport_has_no_owner_or_raw_store_capability() {
    let source = include_str!("http_server.rs");
    assert!(!source.contains("OwnerApi"));
    assert!(!source.contains("DesktopStore"));
    assert!(!source.contains("state.owner"));
    assert!(!source.contains("state.clients"));
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

/// The owner reads `/authorize` in a browser and the agent only ever sees its
/// own callback, so a rejection here has to name the cause and the recovery.
/// An opaque `{"error":"invalid_request"}` left a stale registration
/// indistinguishable from a malformed request.
#[tokio::test]
async fn authorization_failures_explain_themselves_and_escape_the_reason() {
    let response = authorization_error_page(
        "This wallet cannot authorize that request",
        "unknown OAuth client <script>alert(1)</script>",
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
        "DENY"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let body = to_bytes(response.into_body(), OAUTH_REQUEST_LIMIT_BYTES)
        .await
        .unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("unknown OAuth client"));
    assert!(body.contains("/mcp"));
    assert!(body.contains("clear authentication"));
    assert!(!body.contains("<script"));
}

#[tokio::test]
async fn machine_facing_oauth_errors_carry_a_description() {
    let response = oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "unknown or expired authorization code",
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), OAUTH_REQUEST_LIMIT_BYTES)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"],
        "unknown or expired authorization code"
    );
}

#[tokio::test]
async fn oauth_consent_page_has_exact_duration_choices_and_cannot_be_framed() {
    let response = consent_page("Codex <local>", MCP_SCOPE, "opaque-consent");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
        "DENY"
    );
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("default-src 'none'"));
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY).unwrap(),
        "no-referrer"
    );

    let body = to_bytes(response.into_body(), OAUTH_REQUEST_LIMIT_BYTES)
        .await
        .unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("1 hour / 1 day"));
    assert!(body.contains("1 day / 1 week"));
    assert!(body.contains("1 week / 1 month"));
    assert!(body.contains("Codex &lt;local&gt;"));
    assert!(body.contains("display:flex;align-items:center;justify-content:center"));
    assert!(!body.contains("<script"));
    assert!(!body.contains("forever"));
}
