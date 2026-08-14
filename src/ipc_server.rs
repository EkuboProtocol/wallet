//! Same-user local IPC listener for resilient stdio MCP bridges.

use crate::{
    authority::AgentApi,
    events::{DomainEventKind, EventBus},
};
use anyhow::{Context, Result, ensure};
use ekubo_wallet_core::desktop_store::AgentKind;
use rmcp::ServiceExt as _;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;

#[derive(Deserialize)]
struct BridgeHello {
    client: String,
}

pub struct McpIpcServer {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    #[cfg(unix)]
    socket_path: PathBuf,
    active: Arc<AtomicUsize>,
}

impl McpIpcServer {
    pub async fn start(data_dir: &Path, agent: AgentApi, events: EventBus) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            use tokio::net::UnixListener;

            let socket_path = data_dir.join("mcp.sock");
            if socket_path.exists() {
                std::fs::remove_file(&socket_path).context("failed to remove stale MCP socket")?;
            }
            let listener =
                UnixListener::bind(&socket_path).context("failed to bind local MCP socket")?;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
            let cancel = CancellationToken::new();
            let stopped = cancel.clone();
            let active = Arc::new(AtomicUsize::new(0));
            let connection_count = active.clone();
            let expected_uid = unix_owner(data_dir)?;
            events.publish(DomainEventKind::McpStatusChanged { online: true });
            let task = tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! { _ = stopped.cancelled() => break, accepted = listener.accept() => accepted };
                    let Ok((stream, _)) = accepted else {
                        break;
                    };
                    if stream.peer_cred().ok().map(|credential| credential.uid())
                        != Some(expected_uid)
                    {
                        tracing::warn!("rejected local MCP peer owned by another user");
                        continue;
                    }
                    let agent = agent.clone();
                    let events = events.clone();
                    let active = connection_count.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_connection(stream, agent, active, events).await {
                            tracing::warn!(%error, "local MCP bridge disconnected");
                        }
                    });
                }
            });
            Ok(Self {
                cancel,
                task,
                socket_path,
                active,
            })
        }
        #[cfg(windows)]
        anyhow::bail!("Windows current-user MCP named pipe is not implemented")
    }

    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub async fn stop(self) -> Result<()> {
        self.cancel.cancel();
        let _ = self.task.await;
        #[cfg(unix)]
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn unix_owner(path: &Path) -> Result<u32> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(std::fs::metadata(path)?.uid())
}

#[cfg(unix)]
async fn serve_connection(
    stream: tokio::net::UnixStream,
    agent: AgentApi,
    active: Arc<AtomicUsize>,
    events: EventBus,
) -> Result<()> {
    let (read, write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut hello = Vec::new();
    read.read_until(b'\n', &mut hello).await?;
    ensure!(
        !hello.is_empty() && hello.len() <= MAX_FRAME_BYTES,
        "invalid bridge handshake"
    );
    let hello: BridgeHello = serde_json::from_slice(&hello).context("invalid bridge handshake")?;
    ensure!(
        matches!(
            hello.client.as_str(),
            "codex" | "claude_code" | "claude_desktop" | "gemini_cli" | "cursor" | "opencode"
        ),
        "unsupported bridge harness"
    );
    let harness = match hello.client.as_str() {
        "codex" => AgentKind::Codex,
        "claude_code" => AgentKind::ClaudeCode,
        "claude_desktop" => AgentKind::ClaudeDesktop,
        "gemini_cli" => AgentKind::GeminiCli,
        "cursor" => AgentKind::Cursor,
        "opencode" => AgentKind::Opencode,
        _ => unreachable!("validated harness"),
    };
    let session_id = uuid::Uuid::new_v4();
    let server = agent.server(session_id, harness)?;
    active.fetch_add(1, Ordering::AcqRel);
    events.publish(DomainEventKind::AgentConnectionChanged {
        client_id: session_id,
    });
    let result = server
        .serve((read, write))
        .await
        .context("MCP initialization failed")?
        .waiting()
        .await
        .context("MCP task failed")?;
    active.fetch_sub(1, Ordering::AcqRel);
    events.publish(DomainEventKind::AgentConnectionChanged {
        client_id: session_id,
    });
    tracing::debug!(
        ?result,
        harness = hello.client,
        "local MCP bridge session ended"
    );
    Ok(())
}
