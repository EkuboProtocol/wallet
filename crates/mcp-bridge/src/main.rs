#![cfg_attr(windows, allow(unsafe_code))]

use anyhow::{Context, Result, ensure};
#[cfg(unix)]
use directories::BaseDirs;
use serde_json::{Value, json};
#[cfg(unix)]
use std::path::PathBuf;
use std::{collections::BTreeSet, env, time::Duration};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;
const OFFLINE_CODE: i64 = -32_001;

#[derive(Clone, Copy)]
enum ClientKind {
    Codex,
    ClaudeCode,
    ClaudeDesktop,
    GeminiCli,
    Cursor,
    Opencode,
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

fn response(id: Value, result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).expect("JSON response")
}

fn error(id: Value, message: &str) -> Vec<u8> {
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
    emit(&mut stdout, &response(initialize_id, json!({
        "protocolVersion": protocol,
        "capabilities": {"tools":{"listChanged":true}},
        "serverInfo":{"name":"ekubo-wallet-mcp-bridge","version":env!("CARGO_PKG_VERSION")},
        "instructions":"Ekubo Wallet tools appear automatically whenever the wallet application is running."
    }))).await?;

    let mut initialized: Option<Vec<u8>> = None;
    let mut upstream = None;
    let mut last_tools = json!({"tools":[]});
    let mut in_flight = BTreeSet::<String>::new();
    let mut catalog_refresh_pending = false;
    let mut backoff = Duration::from_millis(250);

    loop {
        if upstream.is_none() && initialized.is_some() {
            match connect(client).await {
                Ok(stream) => {
                    let connected: Result<_> = async {
                        let (read, mut write) = tokio::io::split(stream);
                        let mut read = BufReader::new(read);
                        write.write_all(&initialize_frame).await?;
                        let initialize_response = read_frame(&mut read)
                            .await?
                            .context("wallet closed during initialization")?;
                        let initialize_response: Value = serde_json::from_slice(&initialize_response)
                            .context("invalid wallet initialize response")?;
                        ensure!(initialize_response.get("result").is_some(), "wallet rejected MCP initialization");
                        if let Some(frame) = &initialized {
                            write.write_all(frame).await?;
                        }
                        write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"__ekubo_bridge_tools\",\"method\":\"tools/list\",\"params\":{}}\n").await?;
                        let catalog_frame = read_frame(&mut read)
                            .await?
                            .context("wallet closed while listing tools")?;
                        let catalog: Value = serde_json::from_slice(&catalog_frame)
                            .context("invalid wallet tool catalog")?;
                        let refreshed = catalog.get("result").cloned().context("wallet rejected tools/list")?;
                        ensure!(refreshed.get("tools").and_then(Value::as_array).is_some(), "wallet returned an invalid tool catalog");
                        Ok((read, write, refreshed))
                    }
                    .await;
                    if let Ok((read, write, refreshed)) = connected {
                        if refreshed != last_tools {
                            last_tools = refreshed;
                            emit(
                                &mut stdout,
                                br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                            )
                            .await?;
                        }
                        upstream = Some((read, write));
                        catalog_refresh_pending = false;
                        backoff = Duration::from_millis(250);
                    }
                }
                Err(_) => {
                    // The offline branch below waits for either harness input
                    // or this backoff, so requests stay responsive while a
                    // quiet harness still reconnects autonomously.
                }
            }
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
                    match frame {
                        Ok(Some(frame)) => {
                            let Ok(message) = serde_json::from_slice::<Value>(&frame) else {
                                for id in std::mem::take(&mut in_flight) {
                                    if let Ok(id) = serde_json::from_str(&id) {
                                        emit(&mut stdout, &error(id, "Ekubo Wallet sent an invalid frame; the bridge will reconnect automatically")).await?;
                                    }
                                }
                                upstream = None;
                                catalog_refresh_pending = false;
                                continue;
                            };
                            if catalog_refresh_pending
                                && message.get("id").and_then(Value::as_str) == Some("__ekubo_bridge_tools")
                            {
                                catalog_refresh_pending = false;
                                if message.get("result").and_then(|result| result.get("tools")).is_some() {
                                    last_tools = message["result"].clone();
                                }
                                continue;
                            }
                            if let Some(id) = message.get("id") { in_flight.remove(&id.to_string()); }
                            if message.get("result").and_then(|r| r.get("tools")).is_some() { last_tools = message["result"].clone(); }
                            emit(&mut stdout, frame.strip_suffix(b"\n").unwrap_or(&frame)).await?;
                            if message.get("method").and_then(Value::as_str) == Some("notifications/tools/list_changed")
                                && !catalog_refresh_pending
                            {
                                up_write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"__ekubo_bridge_tools\",\"method\":\"tools/list\",\"params\":{}}\n").await?;
                                catalog_refresh_pending = true;
                            }
                        }
                        Ok(None) | Err(_) => {
                            for id in std::mem::take(&mut in_flight) {
                                if let Ok(id) = serde_json::from_str(&id) { emit(&mut stdout, &error(id, "Ekubo Wallet stopped while the request was in flight; the bridge will reconnect automatically" )).await?; }
                            }
                            upstream = None;
                            catalog_refresh_pending = false;
                        }
                    }
                }
            }
        } else {
            let frame = if initialized.is_some() {
                match tokio::time::timeout(backoff, read_frame(&mut stdin)).await {
                    Ok(frame) => frame?,
                    Err(_) => {
                        backoff = (backoff * 2).min(Duration::from_secs(5));
                        continue;
                    }
                }
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
                Some("tools/list") => {
                    if let Some(id) = request_id(&message) {
                        emit(&mut stdout, &response(id, last_tools.clone())).await?;
                    }
                }
                Some("tools/call") => {
                    if let Some(id) = request_id(&message) {
                        emit(&mut stdout, &error(id, "Ekubo Wallet is not running; the bridge is still active and will reconnect automatically")).await?;
                    }
                }
                _ => {
                    if let Some(id) = request_id(&message) {
                        emit(&mut stdout, &error(id, "Ekubo Wallet is not running")).await?;
                    }
                }
            }
        }
    }
}
