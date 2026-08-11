use super::*;
use axum::http::HeaderValue;
use ekubo_wallet_core::{desktop_store::AgentKind, policy_store::DatabaseKey};

fn clients() -> (Arc<Mutex<DesktopStore>>, String) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.keep().join("wallet.db");
    let mut store = DesktopStore::open(&path, &DatabaseKey::new([44; 32])).unwrap();
    let registered = store
        .register_client(
            "Codex",
            AgentKind::Codex,
            None,
            &ekubo_wallet_core::human_presence::OwnerAuthorization::for_test(
                ekubo_wallet_core::human_presence::OwnerAuthorizationScope::AgentAccess,
            ),
        )
        .unwrap();
    (
        Arc::new(Mutex::new(store)),
        registered.token.expose_base64url(),
    )
}

#[test]
fn all_security_headers_are_checked_before_dispatch() {
    let (clients, token) = clients();
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("127.0.0.1:54321"));
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    assert!(authenticate_headers(&Method::POST, &headers, "127.0.0.1:54321", &clients).is_ok());
    headers.insert("origin", HeaderValue::from_static("http://127.0.0.1"));
    assert_eq!(
        authenticate_headers(&Method::POST, &headers, "127.0.0.1:54321", &clients)
            .unwrap_err()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        authenticate_headers(&Method::OPTIONS, &headers, "127.0.0.1:54321", &clients)
            .unwrap_err()
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}
