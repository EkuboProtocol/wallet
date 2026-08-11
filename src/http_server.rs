//! Authenticated loopback-only Streamable HTTP transport.

use crate::{
    authority::{AgentApi, OwnerApi},
    events::{DomainEventKind, EventBus},
    mcp::WalletMcpServer,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use ekubo_wallet_core::desktop_store::{
    AuthenticatedClient, DEFAULT_MCP_PORT_MAX, DEFAULT_MCP_PORT_MIN, DesktopStore,
};
use rand::RngExt as _;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::{
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;
use uuid::Uuid;

pub const MCP_REQUEST_LIMIT_BYTES: usize = 24 * 1024 * 1024;

type ClientService = StreamableHttpService<WalletMcpServer, LocalSessionManager>;

struct HttpState {
    expected_host: String,
    clients: Arc<Mutex<DesktopStore>>,
    agent: AgentApi,
    services: Mutex<HashMap<Uuid, ClientService>>,
    cancellation: CancellationToken,
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
        let persisted = owner.mcp_port()?;
        let listener = match persisted {
            Some(port) => TcpListener::bind(("127.0.0.1", port))
                .await
                .with_context(|| {
                    format!(
                        "the persisted MCP port {port} is occupied; the server remains offline. \
                         Choose ‘Choose new port and repair agents’ in Settings"
                    )
                })?,
            None => bind_new_high_port().await?,
        };
        let address = listener.local_addr()?;
        ensure!(
            address.ip().is_loopback(),
            "MCP listener is not loopback-only"
        );
        if persisted.is_none() {
            owner.set_mcp_port(address.port())?;
        }

        let cancellation = CancellationToken::new();
        let state = Arc::new(HttpState {
            expected_host: format!("127.0.0.1:{}", address.port()),
            clients,
            agent,
            services: Mutex::new(HashMap::new()),
            cancellation: cancellation.clone(),
        });
        let router = Router::new().route("/mcp", any(dispatch)).with_state(state);
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

async fn bind_new_high_port() -> Result<TcpListener> {
    for _ in 0..256 {
        let port = rand::rng().random_range(DEFAULT_MCP_PORT_MIN..=DEFAULT_MCP_PORT_MAX);
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error).context("failed to bind the loopback MCP listener"),
        }
    }
    anyhow::bail!("could not select an unused high loopback port")
}

async fn dispatch(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let client = match authenticate_headers(
        request.method(),
        request.headers(),
        &state.expected_host,
        &state.clients,
    ) {
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
fn authenticate_headers(
    method: &Method,
    headers: &HeaderMap,
    expected_host: &str,
    clients: &Arc<Mutex<DesktopStore>>,
) -> std::result::Result<AuthenticatedClient, Response> {
    if !matches!(*method, Method::GET | Method::POST | Method::DELETE) {
        return Err(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    if headers.get("origin").is_some() {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    if headers.get("host").and_then(|value| value.to_str().ok()) != Some(expected_host) {
        return Err(StatusCode::MISDIRECTED_REQUEST.into_response());
    }
    let Some(encoded) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && !value.contains(char::is_whitespace))
    else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    let authenticated = clients
        .lock()
        .ok()
        .and_then(|mut clients| clients.authenticate(encoded).ok())
        .flatten();
    authenticated.ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())
}

#[cfg(test)]
#[path = "http_server_test.rs"]
mod tests;
