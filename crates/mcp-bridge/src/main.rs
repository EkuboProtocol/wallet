#![cfg_attr(windows, allow(unsafe_code))]

use anyhow::{Context, Result, ensure};
#[cfg(unix)]
use directories::BaseDirs;
use serde_json::{Value, json};
#[cfg(unix)]
use std::path::PathBuf;
use std::{collections::BTreeSet, env, fmt, time::Duration};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;
const OFFLINE_CODE: i64 = -32_001;
const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");

#[derive(Debug)]
struct VersionMismatch {
    wallet_version: String,
}

impl VersionMismatch {
    fn message(&self) -> String {
        format!(
            "Ekubo Wallet {} is running, but this agent session is using MCP bridge {BUILD_VERSION}. Start a new agent session so the harness launches the matching bridge.",
            self.wallet_version
        )
    }
}

impl fmt::Display for VersionMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for VersionMismatch {}

fn safe_reported_version(version: Option<&Value>) -> String {
    version
        .and_then(Value::as_str)
        .filter(|version| {
            !version.is_empty()
                && version.len() <= 64
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        })
        .unwrap_or("unknown")
        .to_string()
}

fn reported_wallet_version(initialize_response: &Value) -> String {
    safe_reported_version(initialize_response.pointer("/result/serverInfo/version"))
}

#[derive(Clone, Copy)]
enum ClientKind {
    Codex,
    ClaudeCode,
    ClaudeDesktop,
    GeminiCli,
    Cursor,
    Opencode,
    GrokBuild,
}

impl ClientKind {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "codex" => Ok(Self::Codex),
            "claude-code" => Ok(Self::ClaudeCode),
            "claude-desktop" => Ok(Self::ClaudeDesktop),
            "gemini-cli" => Ok(Self::GeminiCli),
            "cursor" => Ok(Self::Cursor),
            "opencode" => Ok(Self::Opencode),
            "grok-build" => Ok(Self::GrokBuild),
            _ => anyhow::bail!("unsupported --client value"),
        }
    }

    const fn wire_name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude_code",
            Self::ClaudeDesktop => "claude_desktop",
            Self::GeminiCli => "gemini_cli",
            Self::Cursor => "cursor",
            Self::Opencode => "opencode",
            Self::GrokBuild => "grok_build",
        }
    }
}

fn arguments() -> Result<ClientKind> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        args.len() == 2 && args[0] == "--client",
        "usage: ekubo-wallet-mcp-bridge --client <harness>"
    );
    ClientKind::parse(&args[1])
}

#[cfg(unix)]
fn data_dir() -> Result<PathBuf> {
    if let Some(path) = env::var_os("EKUBO_WALLET_HOME") {
        ensure!(!path.is_empty(), "EKUBO_WALLET_HOME cannot be empty");
        return Ok(path.into());
    }
    let base = BaseDirs::new().context("could not determine the user home directory")?;
    #[cfg(target_os = "macos")]
    return Ok(base
        .home_dir()
        .join("Library/Application Support/org.ekubo.wallet"));
    #[cfg(target_os = "windows")]
    return Ok(base.data_local_dir().join("Ekubo/wallet"));
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    Ok(env::var_os("XDG_STATE_HOME")
        .map_or_else(|| base.home_dir().join(".local/state"), PathBuf::from)
        .join("ekubo-wallet"))
}

async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                anyhow::bail!("MCP frame ended before its newline")
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        ensure!(
            frame.len() + take <= MAX_FRAME_BYTES,
            "MCP frame exceeds 24 MiB"
        );
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        if frame.last() == Some(&b'\n') {
            return Ok(Some(frame));
        }
    }
}

fn request_id(message: &Value) -> Option<Value> {
    message
        .get("id")
        .cloned()
        .filter(|_| message.get("method").is_some())
}

fn response(id: &Value, result: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).expect("JSON response")
}

fn error(id: &Value, message: &str) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":id,"error":{"code":OFFLINE_CODE,"message":message}}),
    )
    .expect("JSON error")
}

fn parse_error() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid MCP JSON frame"}}),
    )
    .expect("JSON parse error")
}

async fn emit(stdout: &mut tokio::io::Stdout, bytes: &[u8]) -> Result<()> {
    stdout.write_all(bytes).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}

#[cfg(unix)]
async fn connect(client: ClientKind) -> Result<tokio::net::UnixStream> {
    let mut stream = tokio::net::UnixStream::connect(data_dir()?.join("mcp.sock")).await?;
    let hello = serde_json::to_vec(&json!({"client":client.wire_name()}))?;
    stream.write_all(&hello).await?;
    stream.write_all(b"\n").await?;
    Ok(stream)
}

#[cfg(windows)]
async fn connect(client: ClientKind) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut stream = ClientOptions::new().open(windows_pipe_name()?)?;
    let hello = serde_json::to_vec(&json!({"client":client.wire_name()}))?;
    stream.write_all(&hello).await?;
    stream.write_all(b"\n").await?;
    Ok(stream)
}

#[cfg(windows)]
fn windows_pipe_name() -> Result<String> {
    Ok(format!(
        r"\\.\pipe\ekubo-wallet-mcp-{}",
        current_user_sid_string()?.replace('-', "_")
    ))
}

#[cfg(windows)]
fn current_user_sid_string() -> Result<String> {
    use std::ptr;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        ensure!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0,
            "could not open current-user token"
        );
        let mut size = 0;
        let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
        ensure!(size > 0, "could not size current-user token");
        let mut buffer = vec![0u8; size as usize];
        ensure!(
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size
            ) != 0,
            "could not read current-user token"
        );
        let sid = (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let mut text = ptr::null_mut();
        ensure!(
            ConvertSidToStringSidW(sid, &mut text) != 0,
            "could not format current-user SID"
        );
        let length = (0..).take_while(|offset| *text.add(*offset) != 0).count();
        let result = String::from_utf16(std::slice::from_raw_parts(text, length))?;
        LocalFree(text.cast());
        CloseHandle(token);
        Ok(result)
    }
}

/// The wallet's own answers to the two catalog requests the bridge makes on
/// its own behalf. Ids the harness never sees, so its own request ids can
/// never collide with them.
const TOOLS_SENTINEL: &str = "__ekubo_bridge_tools";
const RESOURCES_SENTINEL: &str = "__ekubo_bridge_resources";

/// How long the harness waits for the wallet to describe itself before the
/// bridge answers `initialize` on its own. Long enough for a local socket
/// round trip on a loaded machine, short enough that a hung wallet costs a
/// pause rather than a session that never starts.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// What the bridge claims when it has to answer `initialize` alone.
///
/// It must name every capability the wallet has, not every capability the
/// bridge can service while the wallet is down: a harness asks once, at
/// startup, and holds the answer for the session. Claiming less here makes
/// the wallet's resources unreachable for that whole session even after it
/// starts. The wallet's own advertisement is checked against this file by
/// `capabilities_cover_every_wallet_capability` in the wallet's MCP tests,
/// so a capability added there cannot silently go unannounced here.
const OFFLINE_CAPABILITIES: &str = include_str!("offline_capabilities.json");

/// One live wallet connection, and everything the harness learns from it.
struct WalletSession<S> {
    read: BufReader<tokio::io::ReadHalf<S>>,
    write: tokio::io::WriteHalf<S>,
    initialize_result: Value,
    tools: Value,
    resources: Value,
}

fn catalog_request(id: &str, method: &str) -> Vec<u8> {
    let mut frame =
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":{}}))
            .expect("JSON catalog request");
    frame.push(b'\n');
    frame
}

/// Initialize a wallet connection and read both catalogs from it.
///
/// The returned `initialize_result` is the wallet's, not a restatement of it,
/// so the instructions and capabilities the harness records are the ones the
/// wallet actually publishes. Only `listChanged` is the bridge's to add: the
/// wallet cannot promise a notification it has no connection to send, while
/// the bridge does emit one whenever a reconnect turns up a different
/// catalog.
async fn handshake<S>(
    stream: S,
    initialize_frame: &[u8],
    initialized: Option<&[u8]>,
) -> Result<WalletSession<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    write.write_all(initialize_frame).await?;
    let initialize_response = read_frame(&mut read)
        .await?
        .context("wallet closed during MCP initialization")?;
    let initialize_response: Value = serde_json::from_slice(&initialize_response)
        .context("invalid wallet initialize response")?;
    ensure!(
        initialize_response.get("result").is_some(),
        "wallet rejected MCP initialization"
    );
    let wallet_version = reported_wallet_version(&initialize_response);
    if wallet_version != BUILD_VERSION {
        return Err(VersionMismatch { wallet_version }.into());
    }
    let mut initialize_result = initialize_response["result"].clone();
    for capability in ["tools", "resources"] {
        if let Some(entry) = initialize_result.pointer_mut(&format!("/capabilities/{capability}"))
            && entry.is_object()
        {
            entry["listChanged"] = json!(true);
        }
    }
    if let Some(frame) = initialized {
        write.write_all(frame).await?;
    }
    write
        .write_all(&catalog_request(TOOLS_SENTINEL, "tools/list"))
        .await?;
    write
        .write_all(&catalog_request(RESOURCES_SENTINEL, "resources/list"))
        .await?;
    let mut tools = None;
    let mut resources = None;
    // Responses to concurrent requests may arrive in either order, and a
    // notification may land between them, so match on the id rather than on
    // arrival. The bound is a guard against a wallet that answers neither.
    for _ in 0..64 {
        if tools.is_some() && resources.is_some() {
            break;
        }
        let frame = read_frame(&mut read)
            .await?
            .context("wallet closed while listing its catalogs")?;
        let message: Value =
            serde_json::from_slice(&frame).context("invalid wallet catalog frame")?;
        match message.get("id").and_then(Value::as_str) {
            Some(TOOLS_SENTINEL) => {
                let listed = message
                    .get("result")
                    .cloned()
                    .context("wallet rejected tools/list")?;
                ensure!(
                    listed.get("tools").and_then(Value::as_array).is_some(),
                    "wallet returned an invalid tool catalog"
                );
                tools = Some(listed);
            }
            // A wallet build with nothing to publish is a wallet with an
            // empty shelf, not a broken connection: keep the session and let
            // every tool work.
            Some(RESOURCES_SENTINEL) => {
                resources = Some(
                    message
                        .get("result")
                        .filter(|listed| {
                            listed.get("resources").and_then(Value::as_array).is_some()
                        })
                        .cloned()
                        .unwrap_or_else(|| json!({"resources":[]})),
                );
            }
            _ => {}
        }
    }
    Ok(WalletSession {
        read,
        write,
        initialize_result,
        tools: tools.context("wallet did not answer tools/list")?,
        resources: resources.unwrap_or_else(|| json!({"resources":[]})),
    })
}

/// The handshake for a harness that started before the wallet did.
fn offline_initialize_result(protocol: &Value) -> Value {
    json!({
        "protocolVersion": protocol,
        "capabilities": serde_json::from_str::<Value>(OFFLINE_CAPABILITIES)
            .expect("offline capabilities are valid JSON"),
        "serverInfo":{"name":"ekubo-wallet-mcp-bridge","version":BUILD_VERSION},
        "instructions":"Ekubo Wallet tools appear automatically whenever the wallet application is running."
    })
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ekubo-wallet-mcp-bridge: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let client = arguments()?;
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let initialize_frame = read_frame(&mut stdin)
        .await?
        .context("stdin closed before MCP initialize")?;
    let initialize: Value =
        serde_json::from_slice(&initialize_frame).context("invalid MCP initialize frame")?;
    ensure!(
        initialize.get("method").and_then(Value::as_str) == Some("initialize"),
        "first MCP request must be initialize"
    );
    let initialize_id = initialize
        .get("id")
        .cloned()
        .context("initialize request has no id")?;
    let protocol = initialize
        .pointer("/params/protocolVersion")
        .cloned()
        .unwrap_or_else(|| json!("2025-11-25"));

    let mut initialized: Option<Vec<u8>> = None;
    let mut upstream = None;
    let mut last_tools = json!({"tools":[]});
    let mut last_resources = json!({"resources":[]});
    let mut in_flight = BTreeSet::<String>::new();
    let mut tools_refresh_pending = false;
    let mut resources_refresh_pending = false;
    let mut backoff = Duration::from_millis(250);

    // Ask the wallet for the handshake before answering the harness, because
    // a harness records what it is told here for the whole session and never
    // asks again. Anything the bridge invents instead — capabilities, the
    // server instructions — is what the model is stuck with even after the
    // wallet comes up, so the invented answer is the fallback and not the
    // rule. A wallet that is down, hung, or version-mismatched simply misses
    // its turn; the reconnect below applies the ordinary policy to it.
    let wallet_handshake = match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let stream = connect(client).await?;
        handshake(stream, &initialize_frame, None).await
    })
    .await
    {
        Ok(Ok(session)) => Some(session),
        // A bridge that does not match the wallet may not serve this session
        // at all, and saying so before the harness has recorded a handshake
        // is the earliest the user can be told to restart the agent.
        Ok(Err(error)) if error.downcast_ref::<VersionMismatch>().is_some() => {
            return Err(error);
        }
        Ok(Err(_)) | Err(_) => None,
    };
    let initialize_result = match wallet_handshake {
        Some(session) => {
            last_tools = session.tools;
            last_resources = session.resources;
            upstream = Some((session.read, session.write));
            session.initialize_result
        }
        None => offline_initialize_result(&protocol),
    };
    emit(&mut stdout, &response(&initialize_id, &initialize_result)).await?;

    loop {
        if upstream.is_none()
            && initialized.is_some()
            && let Ok(stream) = connect(client).await
        {
            match handshake(stream, &initialize_frame, initialized.as_deref()).await {
                Ok(session) => {
                    if session.tools != last_tools {
                        last_tools = session.tools;
                        emit(
                            &mut stdout,
                            br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                        )
                        .await?;
                    }
                    if session.resources != last_resources {
                        last_resources = session.resources;
                        emit(
                            &mut stdout,
                            br#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#,
                        )
                        .await?;
                    }
                    upstream = Some((session.read, session.write));
                    tools_refresh_pending = false;
                    resources_refresh_pending = false;
                    backoff = Duration::from_millis(250);
                }
                Err(error) => {
                    if error.downcast_ref::<VersionMismatch>().is_some() {
                        return Err(error);
                    }
                }
            }
            // The offline branch below waits for either harness input or
            // the backoff when this connection attempt fails, so requests
            // stay responsive while a quiet harness reconnects.
        }

        if let Some((up_read, up_write)) = upstream.as_mut() {
            tokio::select! {
                frame = read_frame(&mut stdin) => {
                    let Some(frame) = frame? else { return Ok(()); };
                    let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
                        emit(&mut stdout, &parse_error()).await?;
                        continue;
                    };
                    if initialized.is_none() && message.get("method").and_then(Value::as_str) == Some("notifications/initialized") { initialized = Some(frame.clone()); }
                    if let Some(id) = request_id(&message) { in_flight.insert(id.to_string()); }
                    up_write.write_all(&frame).await?;
                }
                frame = read_frame(up_read) => {
                    let Ok(Some(frame)) = frame else {
                        for id in std::mem::take(&mut in_flight) {
                            if let Ok(id) = serde_json::from_str(&id) { emit(&mut stdout, &error(&id, "Ekubo Wallet stopped while the request was in flight; the bridge will reconnect automatically" )).await?; }
                        }
                        upstream = None;
                        tools_refresh_pending = false;
                        resources_refresh_pending = false;
                        continue;
                    };
                            let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
                                for id in std::mem::take(&mut in_flight) {
                                    if let Ok(id) = serde_json::from_str(&id) {
                                        emit(&mut stdout, &error(&id, "Ekubo Wallet sent an invalid frame; the bridge will reconnect automatically")).await?;
                                    }
                                }
                                upstream = None;
                                tools_refresh_pending = false;
                                resources_refresh_pending = false;
                                continue;
                            };
                            let sentinel = message.get("id").and_then(Value::as_str);
                            if tools_refresh_pending && sentinel == Some(TOOLS_SENTINEL) {
                                tools_refresh_pending = false;
                                if message.get("result").and_then(|result| result.get("tools")).is_some() {
                                    last_tools = message["result"].clone();
                                }
                                continue;
                            }
                            if resources_refresh_pending && sentinel == Some(RESOURCES_SENTINEL) {
                                resources_refresh_pending = false;
                                if message.get("result").and_then(|result| result.get("resources")).is_some() {
                                    last_resources = message["result"].clone();
                                }
                                continue;
                            }
                            if let Some(id) = message.get("id") { in_flight.remove(&id.to_string()); }
                            if message.get("result").and_then(|r| r.get("tools")).is_some() { last_tools = message["result"].clone(); }
                            if message.get("result").and_then(|r| r.get("resources")).is_some() { last_resources = message["result"].clone(); }
                            emit(&mut stdout, frame.strip_suffix(b"\n").unwrap_or(&frame)).await?;
                            match message.get("method").and_then(Value::as_str) {
                                Some("notifications/tools/list_changed") if !tools_refresh_pending => {
                                    up_write.write_all(&catalog_request(TOOLS_SENTINEL, "tools/list")).await?;
                                    tools_refresh_pending = true;
                                }
                                Some("notifications/resources/list_changed") if !resources_refresh_pending => {
                                    up_write.write_all(&catalog_request(RESOURCES_SENTINEL, "resources/list")).await?;
                                    resources_refresh_pending = true;
                                }
                                _ => {}
                            }
                }
            }
        } else {
            let frame = if initialized.is_some() {
                let Ok(frame) = tokio::time::timeout(backoff, read_frame(&mut stdin)).await else {
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                    continue;
                };
                frame?
            } else {
                read_frame(&mut stdin).await?
            };
            let Some(frame) = frame else {
                return Ok(());
            };
            let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
                emit(&mut stdout, &parse_error()).await?;
                continue;
            };
            match message.get("method").and_then(Value::as_str) {
                Some("notifications/initialized") => initialized = Some(frame),
                // A harness that pings a stopped wallet is checking on the
                // bridge, which is answering — so this is not an outage.
                Some("ping") => {
                    if let Some(id) = request_id(&message) {
                        emit(&mut stdout, &response(&id, &json!({}))).await?;
                    }
                }
                Some("tools/list") => {
                    if let Some(id) = request_id(&message) {
                        emit(&mut stdout, &response(&id, &last_tools)).await?;
                    }
                }
                Some("resources/list") => {
                    if let Some(id) = request_id(&message) {
                        emit(&mut stdout, &response(&id, &last_resources)).await?;
                    }
                }
                // The wallet publishes fixed URIs rather than templates, so
                // the empty answer is the true one and not a stand-in.
                Some("resources/templates/list") => {
                    if let Some(id) = request_id(&message) {
                        emit(
                            &mut stdout,
                            &response(&id, &json!({"resourceTemplates":[]})),
                        )
                        .await?;
                    }
                }
                Some("tools/call" | "resources/read") => {
                    if let Some(id) = request_id(&message) {
                        emit(&mut stdout, &error(&id, "Ekubo Wallet is not running; the bridge is still active and will reconnect automatically")).await?;
                    }
                }
                _ => {
                    if let Some(id) = request_id(&message) {
                        emit(&mut stdout, &error(&id, "Ekubo Wallet is not running")).await?;
                    }
                }
            }
        }
    }
}
