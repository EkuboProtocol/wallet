#![cfg_attr(windows, allow(unsafe_code))]

use anyhow::{Context, Result, ensure};
#[cfg(unix)]
use directories::BaseDirs;
use serde_json::{Value, json};
#[cfg(unix)]
use std::path::PathBuf;
use std::{collections::BTreeSet, env, fmt, time::Duration};

/// Shared verbatim with the wallet, which includes the same file.
#[path = "../../../bridge_protocol.rs"]
mod bridge_protocol;
use bridge_protocol::{BRIDGE_PROTOCOL_META_KEY, BRIDGE_PROTOCOL_VERSION};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
mod legacy;
mod modern;

#[cfg(unix)]
type Stream = tokio::net::UnixStream;
#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;
const OFFLINE_CODE: i64 = -32_001;
const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");

#[derive(Debug)]
struct VersionMismatch {
    wallet_version: String,
    wallet_protocol: Option<u32>,
}

impl VersionMismatch {
    fn message(&self) -> String {
        let contract = match self.wallet_protocol {
            Some(protocol) => format!(
                "it speaks bridge protocol {protocol} and this bridge speaks {BRIDGE_PROTOCOL_VERSION}"
            ),
            None => "it predates bridge protocol versioning, so the builds must match exactly"
                .to_owned(),
        };
        format!(
            "Ekubo Wallet {} is running, but this agent session is using MCP bridge {BUILD_VERSION}: {contract}. Start a new agent session so the harness launches the matching bridge.",
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

/// The bridge protocol the wallet publishes, or `None` for a wallet built
/// before the constant existed.
fn reported_wallet_protocol(initialize_response: &Value) -> Option<u32> {
    initialize_response
        .pointer("/result/_meta")?
        .get(BRIDGE_PROTOCOL_META_KEY)?
        .as_u64()?
        .try_into()
        .ok()
}

/// Whether this bridge may serve the wallet that just described itself.
///
/// A wallet that publishes a protocol is compared on that alone, so every
/// wallet change that leaves the shared contract untouched — a new tool, a
/// fixed quote path, a repaired helper — keeps working with a bridge the
/// harness started earlier. A wallet that publishes nothing predates the
/// constant and still expects exact build agreement, which is what it gets.
fn wallet_is_compatible(wallet_version: &str, wallet_protocol: Option<u32>) -> bool {
    wallet_protocol.map_or_else(
        || wallet_version == BUILD_VERSION,
        |protocol| protocol == BRIDGE_PROTOCOL_VERSION,
    )
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

/// Read one newline-terminated frame, accumulating into caller-owned `partial`.
///
/// The accumulator belongs to the caller because this future gets dropped
/// between polls: it is a `tokio::select!` branch against the other direction
/// of the bridge, and in the offline loop it also runs under a `timeout`. A
/// frame is only rarely one read — the peer's JSON writer emits it in several
/// small writes — so a cancelled call has usually already `consume`d some
/// bytes out of `reader`. Held in a future-local buffer those bytes are
/// dropped with the future, and the *next* call resumes mid-JSON: the peer
/// then looks like it sent a corrupt frame, and the bridge tears down a
/// perfectly good connection over bytes it deleted itself.
///
/// Only `fill_buf` awaits here, and it consumes nothing, so whatever this
/// leaves in `partial` is exactly what a resumed call needs.
async fn read_frame_into<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    partial: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if partial.is_empty() {
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
            partial.len() + take <= MAX_FRAME_BYTES,
            "MCP frame exceeds 24 MiB"
        );
        partial.extend_from_slice(&available[..take]);
        reader.consume(take);
        if partial.last() == Some(&b'\n') {
            return Ok(Some(std::mem::take(partial)));
        }
    }
}

/// [`read_frame_into`] for the sequential call sites, which are never raced
/// against another branch and so cannot lose a partial frame.
async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    read_frame_into(reader, &mut Vec::new()).await
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

    let mut stream = match ekubo_wallet_client::try_connect_agent_stream().await? {
        Some(stream) => stream,
        None => ClientOptions::new().open(windows_pipe_name()?)?,
    };
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
    let wallet_protocol = reported_wallet_protocol(&initialize_response);
    if !wallet_is_compatible(&wallet_version, wallet_protocol) {
        return Err(VersionMismatch {
            wallet_version,
            wallet_protocol,
        }
        .into());
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
        "instructions":"Ekubo Wallet is temporarily unavailable. The bridge reconnects automatically and announces catalog changes. Retry discovery after starting or unlocking the wallet; if your client does not refresh tools, refresh its MCP connection."
    })
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("ekubo-wallet-mcp-bridge: {error:#}");
        std::process::exit(1);
    }
}

/// A legacy client may probe before initializing. Reject malformed probes
/// without latching the connection into the modern era or closing its stdin.
async fn opening_request(
    stdin: &mut BufReader<tokio::io::Stdin>,
    stdout: &mut tokio::io::Stdout,
) -> Result<Option<(Vec<u8>, Value)>> {
    while let Some(frame) = read_frame(stdin).await? {
        let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
            emit(stdout, &parse_error()).await?;
            continue;
        };
        if message["method"] == "initialize"
            || message
                .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
                .is_some()
        {
            return Ok(Some((frame, message)));
        }
        if message["method"] == "ping" {
            if let Some(id) = request_id(&message) {
                emit(stdout, &response(&id, &json!({}))).await?;
            }
        } else if let Some(error) = modern::invalid_request(&message) {
            emit(stdout, &error).await?;
        }
    }
    Ok(None)
}

async fn run() -> Result<()> {
    let client = arguments()?;
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let Some((first, message)) = opening_request(&mut stdin, &mut stdout).await? else {
        return Ok(());
    };
    if message["method"] == "initialize" {
        legacy::run(client, stdin, stdout, first, message).await
    } else {
        modern::run(client, stdin, stdout, first).await
    }
}
