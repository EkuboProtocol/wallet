//! The websocket client for a `WalletConnect` relay.
//!
//! The relay is a dumb pipe with an authenticated door: it routes opaque
//! ciphertext between topics and can neither read a payload nor forge one that
//! opens. It is still a third party that sees which topics talk to which and
//! when, and it can drop messages, so the honest summary is "untrusted for
//! confidentiality and integrity, trusted for liveness only".
//!
//! Everything here is transport. The one security-relevant rule this module
//! enforces is that the relay is reached over TLS and nothing else, because the
//! authentication token in the URL is a bearer credential for the connection.

use super::{
    crypto::ClientIdentity,
    protocol::{IncomingMessage, JSONRPC_VERSION},
};
use anyhow::{Context, Result, bail, ensure};
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

/// The public relay, used when nothing else is configured.
pub const DEFAULT_RELAY_URL: &str = "wss://relay.walletconnect.org";

/// How long a relay authentication token stays valid. One day, as the
/// reference client uses; the connection is re-authenticated on reconnect.
const JWT_TTL_SECONDS: i64 = 86_400;

/// How long to wait for the relay to answer one of our own JSON-RPC calls.
const RELAY_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// A message the relay delivered on a topic this client subscribed to.
pub struct RelayMessage {
    pub topic: String,
    /// The still-encrypted envelope. Nothing in this module can open it.
    pub message: String,
}

/// What the relay connection needs to know to open a socket.
pub struct RelayConfig {
    pub url: Url,
    /// The relay refuses an anonymous connection, so this is required rather
    /// than optional. It identifies the *application*, not the user.
    pub project_id: String,
}

/// One live relay connection.
///
/// Reads happen on a background task so that a caller can be awaiting the next
/// delivered message while another part of the program publishes — which is the
/// normal state of affairs, since answering a request means publishing while
/// still listening.
pub struct RelayConnection {
    outgoing: mpsc::UnboundedSender<Message>,
    incoming: mpsc::UnboundedReceiver<RelayMessage>,
    pending: PendingCalls,
    next_id: AtomicU64,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

type PendingCalls = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

impl RelayConnection {
    /// Open and authenticate a connection.
    pub async fn connect(config: &RelayConfig, identity: &ClientIdentity) -> Result<Self> {
        let url = authenticated_url(config, identity)?;
        // The websocket URL carries a bearer token in its query string. Over
        // `ws:` that token — and every topic this wallet subscribes to — is
        // readable by anything on the path, so plaintext is refused rather than
        // downgraded to.
        ensure!(
            url.scheme() == "wss",
            "the relay URL must use `wss:`; `{}` would send the connection's authentication token \
             in the clear",
            url.scheme()
        );
        let (stream, _) = tokio_tungstenite::connect_async(url.as_str())
            .await
            .with_context(|| {
                format!(
                    "could not reach the WalletConnect relay at {}",
                    config.url.as_str()
                )
            })?;
        let (mut sink, mut source) = stream.split();

        let (outgoing_sender, mut outgoing_receiver) = mpsc::unbounded_channel::<Message>();
        let (incoming_sender, incoming_receiver) = mpsc::unbounded_channel::<RelayMessage>();
        let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));

        let writer = tokio::spawn(async move {
            while let Some(message) = outgoing_receiver.recv().await {
                if sink.send(message).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let reader_pending = Arc::clone(&pending);
        let reader_outgoing = outgoing_sender.clone();
        let reader = tokio::spawn(async move {
            while let Some(frame) = source.next().await {
                let Ok(frame) = frame else { break };
                match frame {
                    Message::Text(text) => {
                        dispatch(&text, &reader_pending, &incoming_sender, &reader_outgoing);
                    }
                    // tungstenite queues its own pong, but only flushes it on
                    // the next write, and a wallet waiting quietly for a
                    // request may have nothing to write for minutes. Answering
                    // explicitly is what keeps the relay from timing the
                    // connection out mid-session.
                    Message::Ping(payload) => {
                        let _ = reader_outgoing.send(Message::Pong(payload));
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            // Nothing else will ever answer these, so wake every caller now
            // rather than leaving them on a 30-second timeout each.
            let waiting: Vec<_> = reader_pending
                .lock()
                .map(|mut pending| pending.drain().map(|(_, sender)| sender).collect())
                .unwrap_or_default();
            for sender in waiting {
                let _ = sender.send(Err("the relay connection closed".to_owned()));
            }
        });

        Ok(Self {
            outgoing: outgoing_sender,
            incoming: incoming_receiver,
            pending,
            // Relay call ids are per-connection and need only be unique; unlike
            // protocol-level ids no peer inspects their shape.
            next_id: AtomicU64::new(1),
            reader,
            writer,
        })
    }

    /// Subscribe to a topic and return the relay's subscription id.
    pub async fn subscribe(&self, topic: &str) -> Result<String> {
        let result = self
            .call("irn_subscribe", json!({ "topic": topic }))
            .await?;
        result
            .as_str()
            .map(ToOwned::to_owned)
            .context("the relay did not return a subscription id")
    }

    /// Publish one sealed envelope.
    ///
    /// `tag` and `ttl` are protocol constants for the method being sent, not
    /// choices: the relay routes and retains on the tag, and refuses one it
    /// does not know.
    pub async fn publish(&self, topic: &str, message: &str, tag: u32, ttl: u64) -> Result<()> {
        self.call(
            "irn_publish",
            json!({
                "topic": topic,
                "message": message,
                "ttl": ttl,
                "tag": tag,
                "prompt": false,
            }),
        )
        .await?;
        Ok(())
    }

    /// The next message delivered on any subscribed topic, or `None` once the
    /// connection has closed.
    pub async fn next_message(&mut self) -> Option<RelayMessage> {
        self.incoming.recv().await
    }

    /// Whether the reader task has finished, which is the only durable signal
    /// that the socket is gone.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.reader.is_finished()
    }

    /// Close the socket and stop both tasks.
    pub fn close(self) {
        drop(self.outgoing);
        self.reader.abort();
        self.writer.abort();
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .map_err(|_| anyhow::anyhow!("relay call registry lock was poisoned"))?
            .insert(id, sender);
        let request = json!({
            "id": id,
            "jsonrpc": JSONRPC_VERSION,
            "method": method,
            "params": params,
        });
        if self
            .outgoing
            .send(Message::text(request.to_string()))
            .is_err()
        {
            self.forget(id);
            bail!("the relay connection is closed");
        }
        match tokio::time::timeout(RELAY_CALL_TIMEOUT, receiver).await {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(message))) => bail!("the relay refused `{method}`: {message}"),
            Ok(Err(_)) => bail!("the relay connection closed before answering `{method}`"),
            Err(_) => {
                self.forget(id);
                bail!("the relay did not answer `{method}` within {RELAY_CALL_TIMEOUT:?}")
            }
        }
    }

    fn forget(&self, id: u64) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&id);
        }
    }
}

/// Route one frame from the relay: either the answer to a call this client
/// made, or a message delivered on a subscribed topic.
fn dispatch(
    text: &str,
    pending: &PendingCalls,
    incoming: &mpsc::UnboundedSender<RelayMessage>,
    outgoing: &mpsc::UnboundedSender<Message>,
) {
    let Ok(message) = serde_json::from_str::<IncomingMessage>(text) else {
        return;
    };
    if let Some(("irn_subscription", params)) = message.as_request() {
        // Acknowledged before the payload is even looked at: the relay
        // redelivers anything it was not told arrived, and a malformed payload
        // would then be redelivered forever.
        let _ = outgoing.send(Message::text(
            json!({ "id": message.id, "jsonrpc": JSONRPC_VERSION, "result": true }).to_string(),
        ));
        let topic = params.pointer("/data/topic").and_then(Value::as_str);
        let payload = params.pointer("/data/message").and_then(Value::as_str);
        if let (Some(topic), Some(payload)) = (topic, payload) {
            let _ = incoming.send(RelayMessage {
                topic: topic.to_owned(),
                message: payload.to_owned(),
            });
        }
        return;
    }
    let Ok(mut pending) = pending.lock() else {
        return;
    };
    if let Some(sender) = pending.remove(&message.id) {
        let answer = match (message.result, message.error) {
            (_, Some(error)) => Err(error.message),
            (Some(result), None) => Ok(result),
            (None, None) => Err("the relay sent a response with neither result nor error".into()),
        };
        let _ = sender.send(answer);
    }
}

/// The websocket URL with a freshly signed authentication token.
fn authenticated_url(config: &RelayConfig, identity: &ClientIdentity) -> Result<Url> {
    // The token's audience is the relay's own URL without the query string:
    // signing the full URL would mean signing the token into itself.
    let mut audience = config.url.clone();
    audience.set_query(None);
    let audience = audience.as_str().trim_end_matches('/').to_owned();
    let jwt = identity.relay_jwt(&audience, chrono::Utc::now().timestamp(), JWT_TTL_SECONDS)?;

    let mut url = config.url.clone();
    url.query_pairs_mut()
        .append_pair("auth", &jwt)
        .append_pair("projectId", &config.project_id)
        .append_pair("ua", &user_agent());
    Ok(url)
}

/// The relay's user-agent triple: protocol, SDK, environment.
fn user_agent() -> String {
    format!("wc-2/rust-ekubo-wallet-{}/cli", crate::VERSION)
}

#[cfg(test)]
#[path = "relay_test.rs"]
mod tests;
