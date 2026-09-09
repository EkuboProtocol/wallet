//! Stateless MCP forwarding. No initialize frames, cached catalogs or replay of
//! interrupted calls: each request retains its own version and capabilities.
use super::*;

const PROTOCOL: &str = "2026-07-28";
const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const SERVER_INFO_KEY: &str = "io.modelcontextprotocol/serverInfo";
const DISCOVER_ID: &str = "__ekubo_bridge_discover";

#[cfg(unix)]
type Stream = tokio::net::UnixStream;
#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

struct Upstream {
    read: BufReader<tokio::io::ReadHalf<Stream>>,
    write: tokio::io::WriteHalf<Stream>,
}

fn discovery_request() -> Value {
    json!({"jsonrpc":"2.0","id":DISCOVER_ID,"method":"server/discover","params":{
        "_meta":{VERSION_KEY:PROTOCOL,CAPABILITIES_KEY:{}}
    }})
}

async fn connect_modern(client: ClientKind) -> Result<Upstream> {
    let stream = connect(client).await?;
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    write
        .write_all(&serde_json::to_vec(&discovery_request())?)
        .await?;
    write.write_all(b"\n").await?;
    let frame = read_frame(&mut read)
        .await?
        .context("wallet closed during discovery")?;
    let message: Value = serde_json::from_slice(&frame)?;
    ensure!(
        message["id"] == DISCOVER_ID,
        "unexpected wallet discovery response"
    );
    let result = &message["result"];
    ensure!(
        result["supportedVersions"]
            .as_array()
            .is_some_and(|versions| versions.iter().any(|v| v == PROTOCOL)),
        "wallet does not support modern MCP"
    );
    let wallet_version = safe_reported_version(result["_meta"][SERVER_INFO_KEY].get("version"));
    let wallet_protocol = reported_wallet_protocol(&message);
    if !wallet_is_compatible(&wallet_version, wallet_protocol) {
        return Err(VersionMismatch {
            wallet_version,
            wallet_protocol,
        }
        .into());
    }
    Ok(Upstream { read, write })
}

fn rpc_error(id: &Value, code: i64, message: &str, data: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"error":{
        "code":code,"message":message,"data":data
    }}))
    .expect("JSON error")
}

/// Validate the metadata even while the wallet is offline. A client must be
/// able to distinguish an unsupported version from a temporary outage.
pub(super) fn invalid_request(message: &Value) -> Option<Vec<u8>> {
    let id = &message["id"];
    if message["jsonrpc"] != "2.0" || !message["method"].is_string() {
        return Some(rpc_error(id, -32600, "Invalid MCP request", &Value::Null));
    }
    if id.is_null() {
        return None; // Notifications have no per-request metadata requirement.
    }
    if !id.is_string() && !id.is_number() {
        return Some(rpc_error(
            &Value::Null,
            -32600,
            "Invalid request id",
            &Value::Null,
        ));
    }
    let meta = &message["params"]["_meta"];
    let Some(version) = meta[VERSION_KEY].as_str() else {
        return Some(rpc_error(
            id,
            -32602,
            "Missing protocol version metadata",
            &Value::Null,
        ));
    };
    if version != PROTOCOL {
        return Some(rpc_error(
            id,
            -32022,
            "Unsupported protocol version",
            &json!({"requested":version,"supported":[PROTOCOL]}),
        ));
    }
    if !meta[CAPABILITIES_KEY].is_object() {
        return Some(rpc_error(
            id,
            -32602,
            "Missing client capabilities metadata",
            &Value::Null,
        ));
    }
    None
}

fn offline_discovery() -> Value {
    json!({
        "supportedVersions":[PROTOCOL],
        // Unlike the legacy path, modern clients may rediscover after startup.
        // Do not promise subscriptions the offline bridge cannot deliver.
        "capabilities":{"tools":{},"resources":{}},
        "instructions":"Ekubo Wallet is not running. Retry discovery or a catalog request after starting the wallet application.",
        "resultType":"complete","ttlMs":0,"cacheScope":"private",
        "_meta":{
            SERVER_INFO_KEY:{"name":"ekubo-wallet-mcp-bridge","version":BUILD_VERSION},
            BRIDGE_PROTOCOL_META_KEY:BRIDGE_PROTOCOL_VERSION
        }
    })
}

struct Bridge {
    client: ClientKind,
    upstream: Option<Upstream>,
    in_flight: BTreeSet<String>,
    upstream_partial: Vec<u8>,
}

impl Bridge {
    async fn disconnect(&mut self, stdout: &mut tokio::io::Stdout) -> Result<()> {
        self.upstream = None;
        self.upstream_partial.clear();
        for id in std::mem::take(&mut self.in_flight) {
            let id: Value = serde_json::from_str(&id)?;
            emit(stdout, &error(&id,
                "Ekubo Wallet disconnected. The request may have executed; inspect its existing handle/status before retrying. The bridge will reconnect on the next request.")).await?;
        }
        Ok(())
    }

    async fn client_frame(&mut self, frame: &[u8], stdout: &mut tokio::io::Stdout) -> Result<()> {
        let Ok(message) = serde_json::from_slice::<Value>(frame) else {
            return emit(stdout, &parse_error()).await;
        };
        if let Some(error) = invalid_request(&message) {
            return emit(stdout, &error).await;
        }
        if message["id"].is_null() {
            return self.notification(frame, &message, stdout).await;
        }
        self.request(frame, &message, stdout).await
    }

    async fn notification(
        &mut self,
        frame: &[u8],
        message: &Value,
        stdout: &mut tokio::io::Stdout,
    ) -> Result<()> {
        // Modern clients only send cancellation notifications. Never forward
        // a legacy initialized notification or a client JSON-RPC response.
        if message["method"] != "notifications/cancelled" {
            return Ok(());
        }
        self.in_flight
            .remove(&message["params"]["requestId"].to_string());
        if let Some(upstream) = self.upstream.as_mut()
            && upstream.write.write_all(frame).await.is_err()
        {
            self.disconnect(stdout).await?;
        }
        Ok(())
    }

    async fn request(
        &mut self,
        frame: &[u8],
        message: &Value,
        stdout: &mut tokio::io::Stdout,
    ) -> Result<()> {
        let id = &message["id"];
        if self.in_flight.contains(&id.to_string()) {
            return emit(
                stdout,
                &rpc_error(id, -32600, "Request id is already in flight", &Value::Null),
            )
            .await;
        }
        if self.upstream.is_none() {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, connect_modern(self.client)).await {
                Ok(Ok(upstream)) => self.upstream = Some(upstream),
                Ok(Err(failure)) if failure.downcast_ref::<VersionMismatch>().is_some() => {
                    return emit(stdout, &error(id, &failure.to_string())).await;
                }
                _ => {}
            }
        }
        let Some(upstream) = self.upstream.as_mut() else {
            let reply = if message["method"] == "server/discover" {
                response(id, &offline_discovery())
            } else {
                error(
                    id,
                    "Ekubo Wallet is unavailable. The bridge will reconnect on the next request.",
                )
            };
            return emit(stdout, &reply).await;
        };
        self.in_flight.insert(id.to_string());
        if upstream.write.write_all(frame).await.is_err() {
            self.disconnect(stdout).await?;
        }
        Ok(())
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
        // Never emit a late result for a cancelled request or an internal
        // discovery response. Modern servers cannot initiate RPC requests.
        if let Some(id) = message.get("id")
            && (message.get("method").is_some() || !self.in_flight.remove(&id.to_string()))
        {
            return Ok(());
        }
        emit(stdout, frame.strip_suffix(b"\n").unwrap_or(&frame)).await
    }
}

enum Frame {
    Client(Option<Vec<u8>>),
    Wallet(Result<Option<Vec<u8>>>),
}

pub(super) async fn run(
    client: ClientKind,
    mut stdin: BufReader<tokio::io::Stdin>,
    mut stdout: tokio::io::Stdout,
    first: Vec<u8>,
) -> Result<()> {
    let mut bridge = Bridge {
        client,
        upstream: None,
        in_flight: BTreeSet::new(),
        upstream_partial: Vec::new(),
    };
    bridge.client_frame(&first, &mut stdout).await?;
    let mut stdin_partial = Vec::new();
    loop {
        let frame = match bridge.upstream.as_mut() {
            Some(upstream) => tokio::select! {
                frame = read_frame_into(&mut stdin, &mut stdin_partial) => Frame::Client(frame?),
                frame = read_frame_into(&mut upstream.read, &mut bridge.upstream_partial) => Frame::Wallet(frame),
            },
            None => Frame::Client(read_frame_into(&mut stdin, &mut stdin_partial).await?),
        };
        match frame {
            Frame::Client(Some(frame)) => bridge.client_frame(&frame, &mut stdout).await?,
            Frame::Client(None) => return Ok(()),
            Frame::Wallet(frame) => bridge.wallet_frame(frame, &mut stdout).await?,
        }
    }
}
