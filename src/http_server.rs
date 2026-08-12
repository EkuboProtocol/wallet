//! OAuth-protected, loopback-only Streamable HTTP transport.

use crate::{
    authority::{AgentApi, OwnerApi},
    events::{DomainEventKind, EventBus},
    mcp::WalletMcpServer,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::any,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ekubo_wallet_core::desktop_store::{
    AgentKind, AuthenticatedClient, DesktopStore, MCP_PORT, MCP_RESOURCE, MCP_SCOPE,
    OAuthSessionPreset, OAuthTokenPair,
};
use rand::TryRng as _;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, hash_map::Entry},
    fmt::Write as _,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;
use uuid::Uuid;

pub const MCP_REQUEST_LIMIT_BYTES: usize = 24 * 1024 * 1024;
const OAUTH_REQUEST_LIMIT_BYTES: usize = 64 * 1024;
const PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";
const AUTHORIZATION_SERVER_PATH: &str = "/.well-known/oauth-authorization-server";
const CONSENT_TTL: Duration = Duration::from_mins(5);
const MAX_PENDING_CONSENTS: usize = 128;

type ClientService = StreamableHttpService<WalletMcpServer, LocalSessionManager>;

struct HttpState {
    expected_host: String,
    issuer: String,
    owner: OwnerApi,
    clients: Arc<Mutex<DesktopStore>>,
    agent: AgentApi,
    services: Mutex<HashMap<Uuid, ClientService>>,
    pending_consents: Mutex<HashMap<String, PendingConsent>>,
    cancellation: CancellationToken,
}

struct PendingConsent {
    request: AuthorizationRequest,
    created_at: Instant,
}

pub struct McpHttpServer {
    pub address: SocketAddr,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
    events: EventBus,
}

impl McpHttpServer {
    pub async fn start(
        owner: OwnerApi,
        agent: AgentApi,
        clients: Arc<Mutex<DesktopStore>>,
        events: EventBus,
    ) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", MCP_PORT))
            .await
            .with_context(|| {
                format!(
                    "the fixed MCP port {MCP_PORT} is occupied; close the conflicting local service and restart Ekubo Wallet"
                )
            })?;
        let address = listener.local_addr()?;
        ensure!(
            address.ip().is_loopback() && address.port() == MCP_PORT,
            "MCP listener is not the fixed loopback endpoint"
        );

        let cancellation = CancellationToken::new();
        let expected_host = format!("127.0.0.1:{MCP_PORT}");
        let state = Arc::new(HttpState {
            issuer: format!("http://{expected_host}"),
            expected_host,
            owner,
            clients,
            agent,
            services: Mutex::new(HashMap::new()),
            pending_consents: Mutex::new(HashMap::new()),
            cancellation: cancellation.clone(),
        });
        let router = Router::new().fallback(any(dispatch)).with_state(state);
        let shutdown = cancellation.clone();
        let task = tokio::spawn(async move {
            let result = axum::serve(listener, router)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await;
            if let Err(error) = result {
                tracing::error!(%error, "MCP HTTP listener stopped");
            }
        });
        events.publish(DomainEventKind::McpStatusChanged { online: true });
        Ok(Self {
            address,
            cancellation,
            task,
            events,
        })
    }

    pub async fn stop(self) {
        self.cancellation.cancel();
        let _ = self.task.await;
        self.events
            .publish(DomainEventKind::McpStatusChanged { online: false });
    }
}

async fn dispatch(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    if let Err(response) = validate_request_envelope(
        request.method(),
        request.uri().path(),
        request.headers(),
        &state.expected_host,
    ) {
        return response;
    }
    match (request.method().clone(), request.uri().path()) {
        (Method::GET, PROTECTED_RESOURCE_PATH) => protected_resource_metadata(&state),
        (Method::GET, AUTHORIZATION_SERVER_PATH) => authorization_server_metadata(&state),
        (Method::POST, "/register") => register_client(state, request).await,
        (Method::GET, "/authorize") => {
            authorize(state, request.uri().query().unwrap_or_default().to_owned()).await
        }
        (Method::POST, "/token") => token(state, request).await,
        (Method::GET | Method::POST | Method::DELETE, "/mcp") => dispatch_mcp(state, request).await,
        (_, "/mcp" | "/register" | "/authorize" | "/token") => {
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn protected_resource_metadata(state: &HttpState) -> Response {
    axum::Json(json!({
        "resource": MCP_RESOURCE,
        "authorization_servers": [state.issuer],
        "scopes_supported": [MCP_SCOPE],
        "bearer_methods_supported": ["header"]
    }))
    .into_response()
}

fn authorization_server_metadata(state: &HttpState) -> Response {
    axum::Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "registration_endpoint": format!("{}/register", state.issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [MCP_SCOPE]
    }))
    .into_response()
}

#[derive(Deserialize, Serialize)]
struct RegistrationRequest {
    client_name: String,
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    #[serde(default)]
    response_types: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

async fn register_client(state: Arc<HttpState>, request: Request) -> Response {
    if !has_media_type(request.headers(), "application/json") {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    let Ok(body) = to_bytes(request.into_body(), OAUTH_REQUEST_LIMIT_BYTES).await else {
        return oauth_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_client_metadata");
    };
    let registration: RegistrationRequest = match serde_json::from_slice(&body) {
        Ok(registration) => registration,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata"),
    };
    if registration
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("none")
        != "none"
        || (!registration.grant_types.is_empty()
            && !registration
                .grant_types
                .iter()
                .any(|value| value == "authorization_code"))
        || (!registration.response_types.is_empty()
            && !registration
                .response_types
                .iter()
                .any(|value| value == "code"))
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    let raw_registration = serde_json::from_slice::<Value>(&body).ok();
    let kind = infer_agent_kind(&registration.client_name);
    let Ok(client) = state.owner.register_oauth_client(
        &registration.client_name,
        kind,
        &registration.redirect_uris,
        raw_registration.as_ref(),
    ) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    };
    let mut response = axum::Json(json!({
        "client_id": client.id.to_string(),
        "client_id_issued_at": client.created_at.timestamp(),
        "client_name": client.display_name,
        "redirect_uris": registration.redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    }))
    .into_response();
    *response.status_mut() = StatusCode::CREATED;
    response
}

#[derive(Clone, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: Uuid,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: Option<String>,
    scope: Option<String>,
    resource: String,
}

#[derive(Deserialize)]
struct ConsentSelection {
    consent: Option<String>,
    duration: Option<String>,
}

async fn authorize(state: Arc<HttpState>, encoded_query: String) -> Response {
    if encoded_query.len() > OAUTH_REQUEST_LIMIT_BYTES {
        return oauth_error(StatusCode::URI_TOO_LONG, "invalid_request");
    }
    let Ok(selection) = serde_urlencoded::from_str::<ConsentSelection>(&encoded_query) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if selection.consent.is_some() || selection.duration.is_some() {
        let (Some(consent), Some(duration)) = (selection.consent, selection.duration) else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let Ok(session_preset) = OAuthSessionPreset::parse_query_value(&duration) else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let pending = {
            let Ok(mut pending) = state.pending_consents.lock() else {
                return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
            };
            pending.retain(|_, consent| consent.created_at.elapsed() < CONSENT_TTL);
            pending.remove(&consent)
        };
        let Some(pending) = pending else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        return finish_authorization(state, pending.request, session_preset).await;
    }
    let query: AuthorizationRequest = match serde_urlencoded::from_str(&encoded_query) {
        Ok(query) => query,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if query.response_type != "code" || query.code_challenge_method != "S256" {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let scope = query.scope.clone().unwrap_or_else(|| MCP_SCOPE.to_owned());
    let Ok(client) = state.owner.validate_oauth_authorization_request(
        query.client_id,
        &query.redirect_uri,
        &query.code_challenge,
        &scope,
        &query.resource,
    ) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(consent) = create_pending_consent(&state, query) else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    consent_page(&client.display_name, &scope, &consent)
}

async fn finish_authorization(
    state: Arc<HttpState>,
    query: AuthorizationRequest,
    session_preset: OAuthSessionPreset,
) -> Response {
    let Ok(mut redirect) = url::Url::parse(&query.redirect_uri) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let scope = query.scope.as_deref().unwrap_or(MCP_SCOPE);
    let result = state
        .owner
        .authorize_oauth_client(
            query.client_id,
            &query.redirect_uri,
            &query.code_challenge,
            scope,
            &query.resource,
            session_preset,
        )
        .await;
    match result {
        Ok(code) => {
            redirect
                .query_pairs_mut()
                .append_pair("code", &code.code.expose_base64url());
        }
        Err(_) => {
            redirect
                .query_pairs_mut()
                .append_pair("error", "access_denied");
        }
    }
    if let Some(state) = query.state {
        redirect.query_pairs_mut().append_pair("state", &state);
    }
    Redirect::to(redirect.as_str()).into_response()
}

fn create_pending_consent(state: &HttpState, request: AuthorizationRequest) -> Result<String> {
    let mut bytes = [0_u8; 32];
    rand::rng()
        .try_fill_bytes(&mut bytes)
        .context("operating-system randomness is unavailable")?;
    let consent = URL_SAFE_NO_PAD.encode(bytes);
    let mut pending = state
        .pending_consents
        .lock()
        .map_err(|_| anyhow::anyhow!("OAuth consent store is unavailable"))?;
    pending.retain(|_, consent| consent.created_at.elapsed() < CONSENT_TTL);
    ensure!(
        pending.len() < MAX_PENDING_CONSENTS,
        "too many pending OAuth consent requests"
    );
    ensure!(
        !pending.contains_key(&consent),
        "OAuth consent nonce collision"
    );
    pending.insert(
        consent.clone(),
        PendingConsent {
            request,
            created_at: Instant::now(),
        },
    );
    Ok(consent)
}

fn consent_page(client_name: &str, scope: &str, consent: &str) -> Response {
    let choices = [
        OAuthSessionPreset::OneHourOneDay,
        OAuthSessionPreset::OneDayOneWeek,
        OAuthSessionPreset::OneWeekOneMonth,
    ];
    let mut buttons = String::new();
    for duration in choices {
        let query = serde_urlencoded::to_string([
            ("consent", consent),
            ("duration", duration.as_query_value()),
        ])
        .expect("fixed OAuth consent query is serializable");
        write!(
            buttons,
            "<a class=\"choice\" href=\"/authorize?{}\">{}</a>",
            escape_html(&query),
            duration.label()
        )
        .expect("writing OAuth consent HTML to a string cannot fail");
    }
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Authorize Ekubo Wallet</title><style>:root{{color-scheme:light dark;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:Canvas;color:CanvasText}}main{{width:min(32rem,calc(100% - 2rem));padding:2rem;border:1px solid GrayText;border-radius:1rem;box-sizing:border-box}}h1{{font-size:1.35rem;margin:0 0 1rem}}p{{line-height:1.5}}code{{font-family:ui-monospace,monospace}}.choices{{display:grid;grid-template-columns:repeat(3,1fr);gap:.75rem;margin-top:1.5rem}}.choice{{padding:.8rem .5rem;text-align:center;text-decoration:none;border:1px solid LinkText;border-radius:.6rem;color:LinkText;font-weight:600}}.choice:focus,.choice:hover{{outline:2px solid LinkText;outline-offset:2px}}small{{display:block;margin-top:1.25rem;color:GrayText;line-height:1.4}}@media(max-width:28rem){{.choices{{grid-template-columns:1fr}}}}</style></head><body><main><h1>Authorize {}</h1><p><strong>{}</strong> is requesting <code>{}</code> access to this wallet.</p><p>Choose an access-token lifetime and the absolute refresh-session deadline. Shorter access tokens reduce the value of a leaked bearer token; the client can reuse its refresh credential until the paired deadline.</p><div class=\"choices\">{buttons}</div><small>Each choice is shown as access / refresh. Your agent harness is responsible for protecting both credentials; either can authorize wallet operations while valid. The wallet will ask for operating-system authentication after you choose, and revocation in Settings immediately invalidates both.</small></main></body></html>",
        escape_html(client_name),
        escape_html(client_name),
        escape_html(scope),
    );
    let mut response = Html(body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: Uuid,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: String,
}

async fn token(state: Arc<HttpState>, request: Request) -> Response {
    if !has_media_type(request.headers(), "application/x-www-form-urlencoded") {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(body) = to_bytes(request.into_body(), OAUTH_REQUEST_LIMIT_BYTES).await else {
        return oauth_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request");
    };
    let request: TokenRequest = match serde_urlencoded::from_bytes(&body) {
        Ok(request) => request,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let result = match request.grant_type.as_str() {
        "authorization_code" => match (
            request.code.as_deref(),
            request.redirect_uri.as_deref(),
            request.code_verifier.as_deref(),
        ) {
            (Some(code), Some(redirect_uri), Some(code_verifier)) => {
                state.owner.exchange_oauth_code(
                    code,
                    request.client_id,
                    redirect_uri,
                    code_verifier,
                    &request.resource,
                )
            }
            _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        "refresh_token" => match request.refresh_token.as_deref() {
            Some(refresh_token) => {
                state
                    .owner
                    .refresh_oauth_token(refresh_token, request.client_id, &request.resource)
            }
            None => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        _ => return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    };
    match result {
        Ok(pair) => token_response(&pair),
        Err(_) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}

fn token_response(pair: &OAuthTokenPair) -> Response {
    let mut response = axum::Json(json!({
        "access_token": pair.access_token.expose_base64url(),
        "token_type": "Bearer",
        "expires_in": pair.expires_in,
        "refresh_token": pair.refresh_token.expose_base64url(),
        "scope": pair.scope
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn dispatch_mcp(state: Arc<HttpState>, request: Request) -> Response {
    let client = match authenticate_headers(request.headers(), &state.clients) {
        Ok(client) => client,
        Err(response) => return response,
    };
    let service = {
        let Ok(mut services) = state.services.lock() else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        if let Entry::Vacant(entry) = services.entry(client.id) {
            let Ok(server) = state.agent.server(client.id) else {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            let mut config = StreamableHttpServerConfig::default();
            config.allowed_hosts = vec![state.expected_host.clone()];
            config.allowed_origins = Vec::new();
            config.max_request_body_bytes = MCP_REQUEST_LIMIT_BYTES;
            config.cancellation_token = state.cancellation.child_token();
            entry.insert(StreamableHttpService::new(
                move || Ok(server.clone()),
                Arc::default(),
                config,
            ));
        }
        services.get(&client.id).expect("inserted above").clone()
    };
    service
        .oneshot(request)
        .await
        .expect("StreamableHttpService is infallible")
        .into_response()
}

#[allow(clippy::result_large_err)]
fn validate_request_envelope(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    expected_host: &str,
) -> std::result::Result<(), Response> {
    if *method == Method::OPTIONS {
        return Err(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    for name in headers.keys() {
        if name == header::ORIGIN || name.as_str().starts_with("access-control-") {
            return Err(StatusCode::FORBIDDEN.into_response());
        }
    }
    let has_fetch_metadata = headers
        .keys()
        .any(|name| name.as_str().starts_with("sec-fetch-"));
    if has_fetch_metadata && !is_owner_authorization_navigation(method, path, headers) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    if headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        != Some(expected_host)
    {
        return Err(StatusCode::MISDIRECTED_REQUEST.into_response());
    }
    Ok(())
}

fn is_owner_authorization_navigation(method: &Method, path: &str, headers: &HeaderMap) -> bool {
    *method == Method::GET
        && path == "/authorize"
        && matches!(
            headers
                .get("sec-fetch-site")
                .and_then(|value| value.to_str().ok()),
            Some("none" | "same-origin")
        )
        && headers
            .get("sec-fetch-mode")
            .and_then(|value| value.to_str().ok())
            == Some("navigate")
        && headers
            .get("sec-fetch-dest")
            .and_then(|value| value.to_str().ok())
            == Some("document")
}

#[allow(clippy::result_large_err)]
fn authenticate_headers(
    headers: &HeaderMap,
    clients: &Arc<Mutex<DesktopStore>>,
) -> std::result::Result<AuthenticatedClient, Response> {
    let Some(encoded) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && !value.contains(char::is_whitespace))
    else {
        return Err(unauthorized_response());
    };
    let authenticated = clients
        .lock()
        .ok()
        .and_then(|mut clients| {
            clients
                .authenticate_access_token(encoded, MCP_RESOURCE)
                .ok()
        })
        .flatten();
    authenticated.ok_or_else(unauthorized_response)
}

fn unauthorized_response() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    let challenge = format!(
        "Bearer resource_metadata=\"http://127.0.0.1:{MCP_PORT}{PROTECTED_RESOURCE_PATH}\", scope=\"{MCP_SCOPE}\""
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn oauth_error(status: StatusCode, code: &str) -> Response {
    let mut response = axum::Json(json!({"error": code})).into_response();
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn infer_agent_kind(name: &str) -> AgentKind {
    let name = name.to_ascii_lowercase();
    if name.contains("codex") || name.contains("chatgpt") {
        AgentKind::Codex
    } else if name.contains("claude") {
        AgentKind::ClaudeCode
    } else if name.contains("gemini") {
        AgentKind::GeminiCli
    } else if name.contains("cursor") {
        AgentKind::Cursor
    } else if name.contains("opencode") {
        AgentKind::Opencode
    } else {
        AgentKind::Other
    }
}

fn has_media_type(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

#[cfg(test)]
#[path = "http_server_test.rs"]
mod tests;
