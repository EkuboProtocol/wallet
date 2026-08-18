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
    protocol::{IncomingMessage, JSONRPC_VERSION, request_id},
};
use anyhow::{Context, Result, bail, ensure};
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

/// The public relay, used when nothing else is configured.
pub const DEFAULT_RELAY_URL: &str = "wss://relay.walletconnect.org";

/// Application-specific settings for a relay connection.
///
/// The project id is not a secret: it travels in the connection URL. The user
/// agent should use `WalletConnect`'s `protocol/sdk/environment` shape, for
/// example `wc-2/rust-my-wallet-1.0/cli`.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub url: Url,
    pub project_id: String,
    pub user_agent: String,
}

impl RelayConfig {
    #[must_use]
    pub fn new(url: Url, project_id: impl Into<String>, user_agent: impl Into<String>) -> Self {
        Self {
            url,
            project_id: project_id.into(),
            user_agent: user_agent.into(),
        }
    }
}

/// How long a relay authentication token stays valid. One day, as the
/// reference client uses; the connection is re-authenticated on reconnect.
const JWT_TTL_SECONDS: i64 = 86_400;

/// How long to wait for the relay to answer one of our own JSON-RPC calls.
const RELAY_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the relay has to finish opening the connection.
///
/// The call timeout above bounds a request sent over a connection that is
/// already up. Nothing bounded getting it up: a host that completes the TCP
/// handshake and then never sends a TLS record, or never answers the websocket
/// upgrade, left `connect` awaiting one future forever. The relay is trusted
/// for liveness, which is a statement about dropped messages rather than a
/// licence to hold the owner's connection UI open indefinitely — and the host on
/// the other end is whatever the URL resolved to, not necessarily a relay at
/// all.
///
/// Same thirty seconds as a call, for the same reason: long enough that a slow
/// link is not mistaken for a dead one, short enough to be a wait rather than
/// a hang.
const RELAY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Delivered messages held for the session loop before the relay is left to
/// hold the rest.
///
/// The loop consumes one at a time and stops entirely while the owner is
/// reading an approval — which is minutes, and is exactly when a hostile peer
/// would choose to flood. An unbounded queue turned that pause into unbounded
/// memory: every payload was acknowledged and enqueued the moment it arrived,
/// so nothing anywhere pushed back.
///
/// A relay redelivers what it was not acknowledged for, so a full queue is not
/// a lost message. It is the backpressure this had none of: the acknowledgement
/// is withheld, the peer's message stays the relay's problem, and the session
/// picks it up when the owner is done.
const MAX_QUEUED_MESSAGES: usize = 64;

/// Frames waiting to reach the socket.
///
/// Mostly acknowledgements and pongs, one per inbound frame, so a flood
/// generates one of these per message too. Bounded for the same reason and
/// dropped rather than queued when full: an unacknowledged message is
/// redelivered, and an unanswered ping is followed by another.
const MAX_QUEUED_FRAMES: usize = 256;

/// The largest websocket frame this client will read at all.
///
/// Twice [`super::crypto::MAX_ENVELOPE_BYTES`], so the JSON-RPC wrapper around
/// a maximum-size envelope fits and nothing much larger does. Enforced by the
/// socket rather than by this module, because a frame is assembled in full
/// before any of this code is reached.
const MAX_FRAME_BYTES: usize = 2 * super::crypto::MAX_ENVELOPE_BYTES;

/// A message the relay delivered on a topic this client subscribed to.
pub struct RelayMessage {
    pub topic: String,
    /// The still-encrypted envelope. Nothing in this module can open it.
    pub message: String,
}

/// One live relay connection.
///
/// Reads happen on a background task so that a caller can be awaiting the next
/// delivered message while another part of the program publishes — which is the
/// normal state of affairs, since answering a request means publishing while
/// still listening.
pub struct RelayConnection {
    outgoing: mpsc::Sender<Message>,
    incoming: mpsc::Receiver<RelayMessage>,
    /// Every topic this connection has subscribed to.
    ///
    /// The relay is trusted for liveness and nothing else, so what it delivers
    /// is checked against what was asked for rather than assumed to match. A
    /// topic nobody subscribed to has no key that opens it and no session that
    /// wants it; enqueueing one only spends memory on a string the session
    /// will discard.
    subscribed: Subscriptions,
    pending: PendingCalls,
    /// Distinguishes calls made within the same millisecond; see
    /// [`next_call_id`].
    salt: AtomicU16,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

type PendingCalls = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;
type Subscriptions = Arc<Mutex<std::collections::HashSet<String>>>;

impl RelayConnection {
    /// Open and authenticate a connection.
    pub async fn connect(config: &RelayConfig, identity: &ClientIdentity) -> Result<Self> {
        Self::connect_within(config, identity, RELAY_HANDSHAKE_TIMEOUT).await
    }

    /// [`Self::connect`], with the handshake deadline named rather than
    /// compiled in, so a test can stand a stalled host up in milliseconds
    /// instead of waiting out the real one.
    async fn connect_within(
        relay: &RelayConfig,
        identity: &ClientIdentity,
        handshake: Duration,
    ) -> Result<Self> {
        install_rustls_provider()?;
        let url = authenticated_url(relay, identity)?;
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
        // The socket's own bounds, below tungstenite's 64 MiB message and 16
        // MiB frame defaults. A frame is buffered whole before this code sees
        // it, so a limit applied any later is a limit on what is kept rather
        // than on what is read. Two megabytes is twice the largest envelope
        // this wallet will accept, which leaves room for the JSON-RPC wrapper
        // around one and refuses anything that is not a message at all.
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME_BYTES))
            .max_frame_size(Some(MAX_FRAME_BYTES));
        // The deadline covers name resolution, the TCP connection, TLS, and the
        // upgrade together, because they are one await and a host that stalls
        // can stall in any of them. The error names the configured URL rather
        // than the one built above, which carries this connection's bearer
        // token in its query string.
        let opening =
            tokio_tungstenite::connect_async_with_config(url.as_str(), Some(config), false);
        let (stream, _) = match tokio::time::timeout(handshake, opening).await {
            Ok(opened) => opened.with_context(|| {
                format!(
                    "could not reach the WalletConnect relay at {}",
                    relay.url.as_str()
                )
            })?,
            Err(_) => bail!(
                "the WalletConnect relay at {} did not finish opening a connection within \
                 {handshake:?}",
                relay.url.as_str()
            ),
        };
        let (mut sink, mut source) = stream.split();

        let (outgoing_sender, mut outgoing_receiver) = mpsc::channel::<Message>(MAX_QUEUED_FRAMES);
        let (incoming_sender, incoming_receiver) =
            mpsc::channel::<RelayMessage>(MAX_QUEUED_MESSAGES);
        let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
        let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));

        let writer = tokio::spawn(async move {
            while let Some(message) = outgoing_receiver.recv().await {
                if sink.send(message).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let reader_pending = Arc::clone(&pending);
        let reader_subscribed = Arc::clone(&subscribed);
        let reader_outgoing = outgoing_sender.clone();
        let reader = tokio::spawn(async move {
            while let Some(frame) = source.next().await {
                let Ok(frame) = frame else { break };
                match frame {
                    Message::Text(text) => {
                        dispatch(
                            &text,
                            &reader_pending,
                            &reader_subscribed,
                            &incoming_sender,
                            &reader_outgoing,
                        );
                    }
                    // tungstenite queues its own pong, but only flushes it on
                    // the next write, and a wallet waiting quietly for a
                    // request may have nothing to write for minutes. Answering
                    // explicitly is what keeps the relay from timing the
                    // connection out mid-session.
                    Message::Ping(payload) => {
                        let _ = reader_outgoing.try_send(Message::Pong(payload));
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
            subscribed,
            salt: AtomicU16::new(0),
            reader,
            writer,
        })
    }

    /// Subscribe to a topic and return the relay's subscription id.
    pub async fn subscribe(&self, topic: &str) -> Result<String> {
        // Recorded before the call, so a message that races the answer is not
        // discarded as unsolicited. Recording it for a subscription that then
        // fails costs nothing: nothing will be delivered on it.
        if let Ok(mut subscribed) = self.subscribed.lock() {
            subscribed.insert(topic.to_owned());
        }
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

    /// Close the socket and stop both tasks.
    pub fn close(self) {}

    /// Whether the socket behind this connection has gone away.
    ///
    /// A relay drops connections for reasons that have nothing to do with the
    /// session running over them — a laptop sleeping, a network changing, the
    /// relay retiring a socket it has held for hours. The caller uses this to
    /// tell "this connection is gone, dial another" apart from "the relay
    /// answered and said no", which are the same `Err` at the call site and
    /// want opposite responses.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.reader.is_finished() || self.outgoing.is_closed()
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = next_call_id(&self.salt);
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
        if let Err(error) = self.outgoing.try_send(Message::text(request.to_string())) {
            self.forget(id);
            match error {
                mpsc::error::TrySendError::Closed(_) => {
                    bail!("the relay connection is closed")
                }
                mpsc::error::TrySendError::Full(_) => bail!(
                    "the relay connection has {MAX_QUEUED_FRAMES} frames waiting to be sent, so \
                     `{method}` was not queued behind them"
                ),
            }
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

impl Drop for RelayConnection {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

fn install_rustls_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Feature unification in the desktop application can enable both Ring
        // and AWS-LC through unrelated HTTPS clients. Rustls deliberately
        // refuses to guess in that case, so WalletConnect selects the provider
        // this crate enables explicitly.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    ensure!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "no process-level TLS crypto provider is available"
    );
    Ok(())
}

/// The id for the next call this client makes.
///
/// The relay checks the *shape* of a JSON-RPC id and answers `Invalid request
/// ID` to anything that is not a microsecond-scale timestamp. A per-connection
/// counter starting at 1 is therefore refused on the very first
/// `irn_subscribe`, leaving a paired session that can never be delivered
/// anything — so relay calls are numbered exactly as protocol calls are.
///
/// The salt separates calls made within the same millisecond; it wraps, and
/// two ids collide only if this client makes 1000 relay calls in one
/// millisecond.
fn next_call_id(salt: &AtomicU16) -> u64 {
    request_id(
        chrono::Utc::now().timestamp_millis(),
        salt.fetch_add(1, Ordering::Relaxed),
    )
}

/// Route one frame from the relay: either the answer to a call this client
/// made, or a message delivered on a subscribed topic.
fn dispatch(
    text: &str,
    pending: &PendingCalls,
    subscribed: &Subscriptions,
    incoming: &mpsc::Sender<RelayMessage>,
    outgoing: &mpsc::Sender<Message>,
) {
    let Ok(message) = serde_json::from_str::<IncomingMessage>(text) else {
        return;
    };
    if let Some(("irn_subscription", params)) = message.as_request() {
        let topic = params.pointer("/data/topic").and_then(Value::as_str);
        let payload = params.pointer("/data/message").and_then(Value::as_str);
        // Everything that can be decided here is decided before the queue is
        // touched, and each outcome is acknowledged — the relay redelivers
        // what it was not told arrived, and none of these get better on a
        // second attempt.
        //
        // The size bound is the envelope's own, applied here rather than after
        // dequeue: a megabyte that will be refused is still a megabyte held
        // while the owner reads an approval. The topic check is against what
        // this connection actually subscribed to, since a relay that decides
        // to deliver on a topic nobody asked for is spending this process's
        // memory on a string no key opens.
        let deliverable = match (topic, payload) {
            (Some(topic), Some(payload))
                if payload.len() <= super::crypto::MAX_ENVELOPE_BYTES
                    && subscribed
                        .lock()
                        .is_ok_and(|subscribed| subscribed.contains(topic)) =>
            {
                Some(RelayMessage {
                    topic: topic.to_owned(),
                    message: payload.to_owned(),
                })
            }
            _ => None,
        };
        let Some(delivery) = deliverable else {
            let _ = outgoing.try_send(Message::text(
                json!({ "id": message.id, "jsonrpc": JSONRPC_VERSION, "result": true }).to_string(),
            ));
            return;
        };
        // Acknowledged only once it is held. A full queue means the session is
        // busy — reading an approval, most likely — and withholding the
        // acknowledgement leaves the message with the relay to redeliver
        // rather than accumulating it here. That is the backpressure the
        // unbounded channel had none of.
        if incoming.try_send(delivery).is_ok() {
            let _ = outgoing.try_send(Message::text(
                json!({ "id": message.id, "jsonrpc": JSONRPC_VERSION, "result": true }).to_string(),
            ));
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
fn authenticated_url(relay: &RelayConfig, identity: &ClientIdentity) -> Result<Url> {
    ensure!(
        !relay.project_id.is_empty(),
        "the relay project id is empty"
    );
    ensure!(
        !relay.user_agent.is_empty(),
        "the relay user agent is empty"
    );
    // The token's audience is the relay's own URL without the query string:
    // signing the full URL would mean signing the token into itself.
    let mut audience = relay.url.clone();
    audience.set_query(None);
    let audience = audience.as_str().trim_end_matches('/').to_owned();
    let jwt = identity.relay_jwt(&audience, chrono::Utc::now().timestamp(), JWT_TTL_SECONDS)?;

    let mut url = relay.url.clone();
    url.query_pairs_mut()
        .append_pair("auth", &jwt)
        .append_pair("projectId", &relay.project_id)
        .append_pair("ua", &relay.user_agent);
    Ok(url)
}

#[cfg(test)]
#[path = "relay_test.rs"]
mod tests;
