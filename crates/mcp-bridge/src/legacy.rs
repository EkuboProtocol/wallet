//! Stateful MCP forwarding with a cancellable background reconnect. A slow
//! wallet must not freeze stdin or turn an unknown catalog into an empty one.
use super::*;

const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const UNAVAILABLE: &str = "Ekubo Wallet is unavailable; the bridge will reconnect automatically. Start or unlock the wallet and retry. If tools do not refresh, refresh the client's MCP connection.";

/// Retried only before forwarding application requests. The future is kept
/// across stdin reads and the startup deadline, so a slow but healthy wallet
/// gets its full attempt budget instead of being restarted every two seconds.
async fn reconnect(
    client: ClientKind,
    initialize: Vec<u8>,
    initialized: Option<Vec<u8>>,
) -> Result<WalletSession<Stream>> {
    let mut backoff = Duration::from_millis(250);
    let mut last_failure = None;
    loop {
        let attempt = tokio::time::timeout(ATTEMPT_TIMEOUT, async {
            let stream = connect(client)
                .await
                .context("could not connect to wallet")?;
            handshake(stream, &initialize, initialized.as_deref()).await
        })
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "wallet handshake timed out after 10 seconds"
            ))
        });
        match attempt {
            Ok(session) => {
                if last_failure.is_some() {
                    eprintln!("ekubo-wallet-mcp-bridge: wallet connection recovered");
                }
                return Ok(session);
            }
            Err(failure) if failure.downcast_ref::<VersionMismatch>().is_some() => {
                return Err(failure);
            }
            Err(failure) => {
                let diagnostic = format!("{failure:#}");
                if last_failure.as_ref() != Some(&diagnostic) {
                    eprintln!("ekubo-wallet-mcp-bridge: {diagnostic}; retrying automatically");
                    last_failure = Some(diagnostic);
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

struct Bridge {
    upstream: Option<WalletSession<Stream>>,
    initialized: Option<Vec<u8>>,
    tools: Option<Value>,
    resources: Option<Value>,
    in_flight: BTreeSet<String>,
    tools_refresh_pending: bool,
    resources_refresh_pending: bool,
    upstream_partial: Vec<u8>,
}

impl Bridge {
    async fn disconnect(&mut self, stdout: &mut tokio::io::Stdout) -> Result<()> {
        self.upstream = None;
        self.upstream_partial.clear();
        self.tools_refresh_pending = false;
        self.resources_refresh_pending = false;
        eprintln!("ekubo-wallet-mcp-bridge: wallet transport disconnected; reconnecting");
        for id in std::mem::take(&mut self.in_flight) {
            let id: Value = serde_json::from_str(&id)?;
            emit(stdout, &error(&id,
                "Ekubo Wallet stopped responding while the request was in flight. It may have executed; inspect its existing handle/status before retrying. The bridge will reconnect automatically.")).await?;
        }
        Ok(())
    }

    async fn connected(
        &mut self,
        mut session: WalletSession<Stream>,
        initialized_replayed: bool,
        stdout: &mut tokio::io::Stdout,
    ) -> Result<()> {
        // The harness may finish initializing while the first wallet
        // handshake is still pending. Deliver its notification exactly once.
        if !initialized_replayed
            && let Some(frame) = &self.initialized
            && session.write.write_all(frame).await.is_err()
        {
            return self.disconnect(stdout).await;
        }
        for (cached, catalog, method) in [
            (
                &mut self.tools,
                &session.tools,
                "notifications/tools/list_changed",
            ),
            (
                &mut self.resources,
                &session.resources,
                "notifications/resources/list_changed",
            ),
        ] {
            if cached.as_ref() != Some(catalog) {
                *cached = Some(catalog.clone());
                emit(
                    stdout,
                    &serde_json::to_vec(&json!({"jsonrpc":"2.0","method":method}))?,
                )
                .await?;
            }
        }
        self.upstream = Some(session);
        Ok(())
    }

    async fn client_frame(&mut self, frame: Vec<u8>, stdout: &mut tokio::io::Stdout) -> Result<()> {
        let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
            return emit(stdout, &parse_error()).await;
        };
        if message["method"] == "notifications/initialized" && self.initialized.is_none() {
            self.initialized = Some(frame.clone());
        }
        if let Some(session) = self.upstream.as_mut() {
            if let Some(id) = request_id(&message) {
                self.in_flight.insert(id.to_string());
            }
            if session.write.write_all(&frame).await.is_err() {
                self.disconnect(stdout).await?;
            }
            return Ok(());
        }
        let Some(id) = request_id(&message) else {
            return Ok(());
        };
        let reply = match message["method"].as_str() {
            Some("ping") => response(&id, &json!({})),
            Some("tools/list") => self
                .tools
                .as_ref()
                .map_or_else(|| error(&id, UNAVAILABLE), |catalog| response(&id, catalog)),
            Some("resources/list") => self
                .resources
                .as_ref()
                .map_or_else(|| error(&id, UNAVAILABLE), |catalog| response(&id, catalog)),
            Some("resources/templates/list") => response(&id, &json!({"resourceTemplates":[]})),
            _ => error(&id, UNAVAILABLE),
        };
        emit(stdout, &reply).await
    }

    async fn wallet_frame(
        &mut self,
        frame: Result<Option<Vec<u8>>>,
        stdout: &mut tokio::io::Stdout,
    ) -> Result<()> {
        let Ok(Some(frame)) = frame else {
            return self.disconnect(stdout).await;
        };
        let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
            return self.disconnect(stdout).await;
        };
        let sentinel = message.get("id").and_then(Value::as_str);
        for (pending, id, key, cached) in [
            (
                &mut self.tools_refresh_pending,
                TOOLS_SENTINEL,
                "tools",
                &mut self.tools,
            ),
            (
                &mut self.resources_refresh_pending,
                RESOURCES_SENTINEL,
                "resources",
                &mut self.resources,
            ),
        ] {
            let internal = *pending && sentinel == Some(id);
            if message["result"][key].is_array() {
                *cached = Some(message["result"].clone());
            }
            if internal {
                *pending = false;
                return Ok(());
            }
        }
        if let Some(id) = message.get("id") {
            self.in_flight.remove(&id.to_string());
        }
        emit(stdout, frame.strip_suffix(b"\n").unwrap_or(&frame)).await?;
        let refresh = match message["method"].as_str() {
            Some("notifications/tools/list_changed") if !self.tools_refresh_pending => {
                self.tools_refresh_pending = true;
                Some(catalog_request(TOOLS_SENTINEL, "tools/list"))
            }
            Some("notifications/resources/list_changed") if !self.resources_refresh_pending => {
                self.resources_refresh_pending = true;
                Some(catalog_request(RESOURCES_SENTINEL, "resources/list"))
            }
            _ => None,
        };
        if let Some(refresh) = refresh
            && let Some(session) = self.upstream.as_mut()
            && session.write.write_all(&refresh).await.is_err()
        {
            self.disconnect(stdout).await?;
        }
        Ok(())
    }
}

enum Frame {
    Client(Option<Vec<u8>>),
    Wallet(Result<Option<Vec<u8>>>),
    Connected(Result<WalletSession<Stream>>),
}

pub(super) async fn run(
    client: ClientKind,
    mut stdin: BufReader<tokio::io::Stdin>,
    mut stdout: tokio::io::Stdout,
    initialize_frame: Vec<u8>,
    initialize: Value,
) -> Result<()> {
    let id = initialize
        .get("id")
        .context("initialize request has no id")?;
    let protocol = initialize
        .pointer("/params/protocolVersion")
        .cloned()
        .unwrap_or_else(|| json!("2025-11-25"));
    let mut bridge = Bridge {
        upstream: None,
        initialized: None,
        tools: None,
        resources: None,
        in_flight: BTreeSet::new(),
        tools_refresh_pending: false,
        resources_refresh_pending: false,
        upstream_partial: Vec::new(),
    };
    let mut first_attempt = Box::pin(reconnect(client, initialize_frame.clone(), None));
    // Do not cancel the attempt when the harness's short startup budget
    // expires: keep polling that same future alongside stdin below.
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, &mut first_attempt).await;
    let mut connecting = if let Ok(session) = first {
        let session = session?;
        emit(&mut stdout, &response(id, &session.initialize_result)).await?;
        bridge.tools = Some(session.tools.clone());
        bridge.resources = Some(session.resources.clone());
        bridge.upstream = Some(session);
        None
    } else {
        eprintln!(
            "ekubo-wallet-mcp-bridge: wallet is not ready; continuing connection in background"
        );
        emit(
            &mut stdout,
            &response(id, &offline_initialize_result(&protocol)),
        )
        .await?;
        Some(first_attempt)
    };
    let mut initialized_replayed = false;
    let mut stdin_partial = Vec::new();
    loop {
        let frame = if let Some(session) = bridge.upstream.as_mut() {
            tokio::select! {
                frame = read_frame_into(&mut stdin, &mut stdin_partial) => Frame::Client(frame?),
                frame = read_frame_into(&mut session.read, &mut bridge.upstream_partial) => Frame::Wallet(frame),
            }
        } else {
            let attempt = connecting.get_or_insert_with(|| {
                initialized_replayed = bridge.initialized.is_some();
                Box::pin(reconnect(
                    client,
                    initialize_frame.clone(),
                    bridge.initialized.clone(),
                ))
            });
            tokio::select! {
                frame = read_frame_into(&mut stdin, &mut stdin_partial) => Frame::Client(frame?),
                session = attempt, if bridge.initialized.is_some() => Frame::Connected(session),
            }
        };
        match frame {
            Frame::Client(Some(frame)) => bridge.client_frame(frame, &mut stdout).await?,
            Frame::Client(None) => return Ok(()),
            Frame::Wallet(frame) => bridge.wallet_frame(frame, &mut stdout).await?,
            Frame::Connected(session) => {
                connecting = None;
                bridge
                    .connected(session?, initialized_replayed, &mut stdout)
                    .await?;
            }
        }
    }
}
