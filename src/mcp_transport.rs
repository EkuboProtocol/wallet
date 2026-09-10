//! MCP session protocol shared by the desktop adapter and protected service.

use crate::{
    authority::AgentApi,
    events::{DomainEventKind, EventBus},
};
use anyhow::{Context, Result, ensure};
use ekubo_wallet_core::desktop_store::AgentKind;
use rmcp::ServiceExt as _;
use serde::Deserialize;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, BufReader};

const MAX_FRAME_BYTES: usize = 24 * 1024 * 1024;

#[derive(Deserialize)]
struct BridgeHello {
    client: String,
}

struct ActiveConnection {
    active: Arc<AtomicUsize>,
    events: EventBus,
}

impl ActiveConnection {
    fn begin(active: Arc<AtomicUsize>, events: EventBus) -> Self {
        let active_connections = active.fetch_add(1, Ordering::AcqRel) + 1;
        events.publish(DomainEventKind::AgentConnectionChanged { active_connections });
        Self { active, events }
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        let active_connections = self.active.fetch_sub(1, Ordering::AcqRel) - 1;
        self.events
            .publish(DomainEventKind::AgentConnectionChanged { active_connections });
    }
}

pub(crate) async fn serve_connection<S>(
    stream: S,
    agent: AgentApi,
    active: Arc<AtomicUsize>,
    events: EventBus,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (read, write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    let hello = read_bounded_line(&mut read)
        .await?
        .context("bridge closed before its handshake")?;
    let hello: BridgeHello = serde_json::from_slice(&hello).context("invalid bridge handshake")?;
    ensure!(
        matches!(
            hello.client.as_str(),
            "codex"
                | "claude_code"
                | "claude_desktop"
                | "gemini_cli"
                | "cursor"
                | "opencode"
                | "grok_build"
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
        "grok_build" => AgentKind::GrokBuild,
        _ => unreachable!("validated harness"),
    };
    let session_id = uuid::Uuid::new_v4();
    let server = agent.server(session_id, harness)?;
    let _active = ActiveConnection::begin(active, events);
    let result = server
        .serve((read, write))
        .await
        .context("MCP initialization failed")?
        .waiting()
        .await
        .context("MCP task failed")?;
    tracing::debug!(
        ?result,
        harness = hello.client,
        "local MCP bridge session ended"
    );
    Ok(())
}

async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                anyhow::bail!("bridge handshake ended before its newline")
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        ensure!(
            frame.len() + take <= MAX_FRAME_BYTES,
            "bridge handshake exceeds 24 MiB"
        );
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        if frame.last() == Some(&b'\n') {
            return Ok(Some(frame));
        }
    }
}
