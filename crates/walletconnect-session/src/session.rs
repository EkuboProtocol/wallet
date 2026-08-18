//! The Sign protocol session: pair, propose, settle, then serve requests.
//!
//! This module owns the conversation and nothing else. It never reads wallet
//! configuration, never touches a key, and never decides whether a transaction
//! is acceptable — every one of those questions goes out through
//! [`SessionHandler`], which is implemented against the wallet's own kernel in
//! `connect.rs`. Keeping the split sharp is what lets the whole state machine
//! be tested against a scripted handler with no GUI, no relay, and no
//! chain.
//!
//! What this module *does* enforce is the session's own boundary: a request
//! naming a chain the session never approved, or a method it never approved, is
//! refused here and never reaches the handler at all. That check belongs at
//! this layer because the approved scope is this layer's state — the handler
//! would have to be told about it to repeat the check, and a check the handler
//! could forget is a check that eventually gets forgotten.

use super::{
    crypto::{ClientIdentity, Envelope, KeyAgreement, SymKey, seal},
    protocol::{
        AppMetadata, IncomingMessage, OutgoingRequest, OutgoingResponse, ProposalNamespace, Relay,
        SESSION_TTL_SECONDS, SessionDeleteParams, SessionProposeParams, SessionRequestParams,
        SettledNamespace, error_code, method, request_id, tag, ttl,
    },
    relay::{RelayConfig, RelayConnection},
    request as dapp_request,
    uri::PairingUri,
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Request ids remembered for replay protection at once.
///
/// Generous against any real dapp — a busy session answers a handful of
/// requests a minute — and a hard ceiling against one that is not trying to be
/// real.
const MAX_ANSWERED_IDS: usize = 4_096;

/// How much of a proposal may reach the screen that approves it, in the
/// characters the review would draw.
///
/// The envelope that delivers a proposal is capped at a megabyte, which bounds
/// the memory but not the *screen*: everything a proposal names — namespace
/// keys, chains, methods, events, and the proposer's icons — is joined into the
/// review a person reads before deciding which account to expose. Burying the
/// account and the chains under a wall of text is the same outcome as lying
/// about them, reached differently, and this is the last point before that
/// review where the whole proposal is still one value.
///
/// **Characters rather than entries, because the dapp chooses both.** A count
/// of entries bounds a thousand short method names and admits a hundred
/// eight-kilobyte ones, which is the same wall of text with a different shape.
/// Each string is charged its own length plus the two characters the separator
/// costs beside it, so neither axis has a cheap side.
///
/// Sixteen kilobytes is generous by a wide margin against anything real. An
/// ordinary proposal draws a few hundred characters; the wordiest legitimate
/// shape — a multichain dapp that names each chain as its own namespace key and
/// repeats its method list under every one — reaches a few thousand at sixty-odd
/// chains. It is also sixty times below the megabyte the envelope permits.
///
/// A refusal rather than a truncation, on purpose. A trimmed proposal either
/// hides part of what the dapp asked for from the person approving it, or
/// quietly narrows the scope that gets settled; telling the dapp to ask for less
/// is honest about both.
const MAX_PROPOSAL_CHARACTERS: usize = 16_384;

/// What one string costs on the review: itself, and the separator drawn beside
/// it.
const SEPARATOR_CHARACTERS: usize = 2;

/// The CAIP-2 namespace this wallet implements. Anything else is somebody
/// else's chain family.
pub const EIP155: &str = "eip155";

/// The events a dapp may subscribe to. Both are emitted by this wallet when the
/// session's chain or account changes, which for now only happens through
/// `wallet_switchEthereumChain`.
pub const SUPPORTED_EVENTS: &[&str] = &["chainChanged", "accountsChanged"];

/// What a dapp asked for, reduced to the decision a person has to make.
pub struct ProposalSummary {
    /// The dapp's own account of itself. Unverified, attacker-controlled, and
    /// displayed only through the sanitizer.
    pub metadata: AppMetadata,
    /// CAIP-2 chains the dapp cannot work without.
    pub required_chains: Vec<String>,
    /// CAIP-2 chains the dapp would like but can do without.
    pub optional_chains: Vec<String>,
    /// Methods the dapp cannot work without.
    pub required_methods: Vec<String>,
    /// Methods the dapp would like but can do without.
    pub optional_methods: Vec<String>,
    /// Events the dapp wants to be told about.
    pub events: Vec<String>,
    /// Each namespace's chain-to-method relationship. The flattened fields
    /// above are review text; these grants are the authorization boundary.
    pub requested_grants: Vec<ScopeGrant>,
    /// The pairing topic, shown so a person can tell two concurrent proposals
    /// apart.
    pub pairing_topic: String,
}

/// Methods one proposal namespace requested for its own chains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeGrant {
    pub chains: Vec<String>,
    pub methods: Vec<String>,
}

/// What the wallet decided about a proposal.
pub enum ProposalDecision {
    /// Settle a session exposing exactly this scope.
    Approve(ApprovedScope),
    /// Refuse, with a code and a sentence the dapp will show its user.
    Reject { code: i64, message: String },
}

/// Exactly what a settled session exposes.
///
/// This is the security boundary of the whole feature: a request outside it is
/// refused before any wallet code runs. It is built by the handler from what
/// the person approved, never from what the dapp asked for.
#[derive(Clone)]
pub struct ApprovedScope {
    /// The address exposed, as a checksummed `0x` string.
    pub address: String,
    /// CAIP-2 chains the session may act on.
    pub chains: Vec<String>,
    /// Methods the session may call.
    pub methods: Vec<String>,
    /// Relational grants preserved from the proposal namespaces.
    pub grants: Vec<ScopeGrant>,
    /// Events the session will be sent.
    pub events: Vec<String>,
}

impl ApprovedScope {
    fn accounts(&self) -> Vec<String> {
        self.chains
            .iter()
            .map(|chain| format!("{chain}:{}", self.address))
            .collect()
    }

    fn allows(&self, chain: &str, method: &str) -> bool {
        self.grants.iter().any(|grant| {
            grant.chains.iter().any(|granted| granted == chain)
                && grant.methods.iter().any(|granted| granted == method)
        })
    }
}

/// One request from the dapp, after the session boundary has accepted it.
pub struct DappRequest<'a> {
    pub method: String,
    pub params: Value,
    /// The CAIP-2 chain the dapp named, already known to be in scope.
    pub caip2_chain_id: String,
    /// The same chain as the decimal id the rest of the wallet speaks.
    pub chain_id: u64,
    /// The dapp's own description of itself, so a review can name what is
    /// asking. Unverified and attacker-controlled: display it only through the
    /// sanitizer.
    pub dapp: &'a AppMetadata,
    /// What the session approved, so a handler can answer a question *about*
    /// the scope rather than only be constrained by it.
    ///
    /// `wallet_switchEthereumChain` is the reason this is here: it asks about
    /// a chain other than the one it arrived on, and answering it from the
    /// arriving chain alone would refuse every switch between two chains the
    /// person did approve.
    pub scope: &'a ApprovedScope,
}

/// A handler's answer to one request.
pub enum RequestOutcome {
    /// The JSON-RPC result to hand back, already in the shape the method's
    /// callers expect — a transaction hash, a signature.
    Result(Value),
    /// A protocol error the dapp will surface to its user.
    Error { code: i64, message: String },
}

impl RequestOutcome {
    #[must_use]
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::Error {
            code: error_code::USER_REJECTED,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self::Error {
            code: error_code::INVALID_METHOD,
            message: message.into(),
        }
    }
}

/// Things worth presenting to the wallet owner.
pub enum SessionEvent<'a> {
    Pairing,
    ProposalReceived,
    Settled {
        scope: &'a ApprovedScope,
        metadata: &'a AppMetadata,
        expiry: i64,
    },
    RequestReceived {
        method: &'a str,
        caip2_chain_id: &'a str,
    },
    RequestAnswered {
        method: &'a str,
        outcome: &'a RequestOutcome,
    },
    /// A request the session boundary refused without consulting the handler.
    RequestRefused {
        method: &'a str,
        reason: &'a str,
    },
    Ping,
    DappDisconnected {
        code: i64,
        message: &'a str,
    },
    /// The relay connection dropped and the session is dialing again. The
    /// session is still the owner's; only the socket under it went away.
    RelayDisconnected,
    RelayReconnected,
}

/// Everything the session needs from the wallet, and nothing more.
///
/// `?Send`, because an implementation may reach the wallet's `SQLite` stores and
/// a `rusqlite::Connection` is not `Sync`. The embedding application keeps the
/// handler on its owning task and publishes results back to the UI.
#[async_trait::async_trait(?Send)]
pub trait SessionHandler {
    /// Review a proposal and decide the scope. Runs through the owner UI and may
    /// take as long as the person takes.
    async fn review_proposal(&self, proposal: &ProposalSummary) -> Result<ProposalDecision>;

    /// Carry out one in-scope request.
    ///
    /// Returning `Err` is for a failure of this wallet — a database that would
    /// not open — and ends the session. A request that is merely refused or
    /// impossible is `Ok(RequestOutcome::Error)`, which answers the dapp and
    /// keeps the session alive.
    async fn handle_request(&self, request: &DappRequest<'_>) -> Result<RequestOutcome>;

    /// Progress for the connection UI. Never fails and never blocks the protocol.
    fn notify(&self, event: &SessionEvent<'_>);

    /// Called before the session waits, so a handler that draws something
    /// while idle can put it back up.
    ///
    /// Idempotent: the session calls it before every wait, including the ones
    /// that follow a request the handler served without touching the UI.
    /// A handler that needs owner input takes it during `review_proposal` or
    /// `handle_request` and simply does not put the idle surface back until
    /// this is called again — which is what keeps exactly one thing reading
    /// keystrokes at any moment.
    async fn enter_idle(&self) {}

    /// Resolves when the person asks, from whatever the handler draws while
    /// idle, to end the session.
    ///
    /// Must be cancellation-safe: the session drops this future whenever a
    /// relay message or a shutdown arrives first. The default never resolves,
    /// for a handler with no such surface.
    async fn quit_requested(&self) {
        std::future::pending::<()>().await;
    }
}

/// Why one turn of the session loop stopped waiting.
enum Woke {
    /// The owner asking to disconnect from the idle surface.
    Stop,
    /// The relay delivered something, or closed.
    Delivered(Option<super::relay::RelayMessage>),
}

/// What both refusals say, because they are the same refusal: whatever the
/// dapp asked for, the answer is that this session is over.
const EXPIRED_REFUSAL: &str = "This session has expired. Reconnect to continue.";

/// What to tell the owner when a relay outage outlives the session.
///
/// The old wording said the dapp would show the session as disconnected, which
/// is the opposite of what happens. A dapp's own client reconnects to the relay
/// and never hears that the wallet stopped, so it goes on showing a live
/// session — which is precisely why someone reading this needs to be sent to
/// the dapp to clear it.
const STALE_AFTER_OUTAGE: &str = "The dapp will most likely still show the session as connected: disconnect it there, then \
     open Connections → WalletConnect and use a fresh link.";

/// How long to wait after the first reconnect attempt fails.
///
/// The first attempt itself is immediate — see [`Session::restore_connection`]
/// — so this is the pause between a dial that failed and the next one. Long
/// enough that a network still settling is not dialed into the same failure at
/// once, short enough that a blip costs the owner nothing they would notice.
const RECONNECT_MIN_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// The longest the backoff climbs to.
///
/// A relay that has been down for minutes is not helped by being dialed every
/// second, and the owner is not helped by a wallet that waits ten minutes
/// after it comes back. Half a minute is the compromise, and matches the order
/// of the relay's own call timeout.
const RECONNECT_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(30);

/// How long the farewell to a dapp may take when the owner is disconnecting.
///
/// Publishing reconnects if the connection is gone, and a relay that is
/// unreachable takes the full handshake deadline to say so. That wait is worth
/// it for an answer the dapp is waiting on; it is not worth it for a goodbye
/// on the way out, where the owner has already closed the connection and the
/// wallet is holding the window open to talk to a relay that is not there.
const DISCONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const EXTEND_REFUSAL: &str =
    "This wallet controls the session lifetime. Disconnect and reconnect to approve a new session.";

/// Why a relay outage should end the session rather than be waited out, if it
/// should.
///
/// Both deadlines are the reason. A settled session past its expiry can no
/// longer answer anything, and an unsettled pairing past the dapp's own
/// deadline is a proposal nobody is coming to make; dialing again for either
/// would spend the owner's connection on a conversation that is over. A
/// session still inside its deadline is worth waiting for, however long the
/// relay takes — the topics and their keys outlive any one socket.
///
/// Both messages say the dapp will most likely still show the session as
/// connected, because it will. A dapp's own client reconnects to the relay and
/// has been told nothing, and the wallet cannot tell it: saying so would take
/// the relay that just went away. The wording this replaced promised the
/// opposite, and sent people looking for a disconnected dapp that was sitting
/// there looking connected.
fn outage_refusal(
    settled_expiry: Option<i64>,
    pairing_expiry: Option<chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
) -> Option<String> {
    match settled_expiry {
        Some(expiry) if lapsed(expiry, now.timestamp()) => Some(format!(
            "the relay connection dropped and this session reached its deadline before the relay \
             came back. {STALE_AFTER_OUTAGE}"
        )),
        Some(_) => None,
        None => pairing_refusal(pairing_expiry, now).map(|_| {
            format!(
                "the relay connection dropped and this pairing expired before the relay came \
                 back. {STALE_AFTER_OUTAGE}"
            )
        }),
    }
}

/// How long to wait before the next reconnect attempt, given the last wait.
///
/// Doubling with a ceiling: a relay that is down for a moment is dialed again
/// almost at once, and one that is down for an hour is not dialed three
/// thousand times while it is.
fn backoff(previous: std::time::Duration) -> std::time::Duration {
    (previous * 2).min(RECONNECT_MAX_DELAY)
}

/// The refusal to send for a pairing whose deadline is `expiry`, at `now`, or
/// `None` when it has not passed or the dapp never named one.
///
/// Checked when a proposal arrives *and* again after the review it triggers,
/// because a review takes as long as a person takes and settling grants a
/// fresh seven days. A deadline tested only on the way in bounds nothing: it
/// would let a pairing that lapsed an hour earlier become a week-long session.
fn pairing_refusal(
    expiry: Option<chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
) -> Option<String> {
    let expiry = expiry?;
    (now >= expiry).then(|| {
        format!(
            "This pairing expired at {expiry}. Pairing URIs are short-lived: ask the dapp to \
             connect again and paste the new link."
        )
    })
}

/// Whether a session whose deadline is `expiry` has reached it at `now`.
///
/// One rule, used by the per-request scope check and by the gate that keeps
/// every other session method out. Extension is separately refused even
/// before expiry because this wallet owns the deadline.
const fn lapsed(expiry: i64, now: i64) -> bool {
    now >= expiry
}

fn controller_refusal(rpc_method: &str, _settled: &Settled) -> Option<(i64, &'static str)> {
    (rpc_method == method::SESSION_EXTEND)
        .then_some((error_code::UNAUTHORIZED_EXTEND, EXTEND_REFUSAL))
}

/// Which of the two topics an envelope authenticated on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Origin {
    Pairing,
    Session,
}

/// Every method this wallet acts on when it arrives on the settled session
/// topic. The `_ => Ok(false)` arm below covers everything else, and this is
/// what keeps such a method from being recorded as answered on the way to
/// being ignored.
const SESSION_METHODS: [&str; 6] = [
    method::SESSION_REQUEST,
    method::SESSION_PING,
    method::SESSION_DELETE,
    method::SESSION_EXTEND,
    method::SESSION_UPDATE,
    method::SESSION_EVENT,
];

/// The ids this session has already answered.
#[derive(Debug, Default)]
struct AnsweredIds {
    seen: HashSet<u64>,
}

impl AnsweredIds {
    fn remember(&mut self, id: u64) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        if self.seen.len() > MAX_ANSWERED_IDS {
            // Forgetting an authenticated request makes its captured envelope
            // executable again. A real dapp never needs thousands of distinct
            // answerable requests in one session, so stop admission at the
            // bound instead of weakening replay protection.
            self.seen.remove(&id);
            return false;
        }
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.len()
    }
}

/// Record `id` as answered, reporting whether it is new.
///
/// Once the set is full, no new id is admitted. Eviction would make an earlier
/// authenticated request executable again; bounded denial of service is safer
/// than replaying a transfer at a fresh nonce.
fn remember(answered: &mut AnsweredIds, id: u64) -> bool {
    answered.remember(id)
}

/// Whether a method may be answered when it arrived on `origin`.
///
/// The pairing key and the session key are separate credentials with separate
/// lifetimes. The pairing key is in a URI the person pasted and a dapp stored;
/// the session key is derived at settlement and never travels. Without this
/// split, the topic chose only which key had to verify, and every method was
/// then dispatched identically — so anyone who kept the URI still held a
/// working credential after settlement, could send `wc_sessionRequest` under
/// the settled dapp's approved scope and metadata, and could delete or extend
/// the session. A policy-allowed transfer would have been signed and broadcast
/// automatically.
///
/// The pairing carries exactly one method, the proposal it exists to deliver.
/// Everything else belongs to the session that was settled and is answered
/// only there.
fn answerable_from(rpc_method: &str, origin: Origin) -> bool {
    match origin {
        Origin::Pairing => rpc_method == method::SESSION_PROPOSE,
        Origin::Session => SESSION_METHODS.contains(&rpc_method),
    }
}

/// A settled session's live state.
struct Settled {
    topic: String,
    key: SymKey,
    scope: ApprovedScope,
    metadata: AppMetadata,
    expiry: i64,
}

/// Drive one pairing all the way from a pasted URI to a closed session.
pub struct Session<'a> {
    relay: RelayConnection,
    /// How to dial the relay again.
    ///
    /// A relay connection is not the session. The session is a pair of topics
    /// and the keys that open them, and it outlives any one socket: the relay
    /// holds what it could not deliver and redelivers it to whoever subscribes
    /// next. Keeping the configuration is what lets a dropped socket be a
    /// pause rather than the end of the conversation.
    relay_config: RelayConfig,
    handler: &'a dyn SessionHandler,
    wallet_metadata: AppMetadata,
    pairing_topic: String,
    pairing_key: SymKey,
    /// When the dapp said this pairing stops being valid, if it said.
    ///
    /// Carried rather than discarded after parsing. A pairing URI is a secret
    /// that travels through a clipboard and may appear in other UI history, and its
    /// deadline is the dapp's statement about how long a copy is worth
    /// anything. Checking it once when the string is pasted and then waiting
    /// on the topic indefinitely made that statement decorative.
    pairing_expiry: Option<chrono::DateTime<Utc>>,
    relay_protocol: String,
    relay_data: Option<String>,
    settled: Option<Settled>,
    /// Ids answered already, so a relay redelivery cannot run a transaction
    /// twice. The relay redelivers anything it was not acknowledged for, and
    /// acknowledgement happens before the request is carried out.
    ///
    /// Bounded, and populated only for methods this wallet actually dispatches.
    /// It used to take an id from every authenticated request, including ones
    /// the match below ignores, and never gave one back — so a dapp sending
    /// tiny envelopes with a method nobody handles grew this set for as long
    /// as `connect` ran, without ever opening a review or doing anything the
    /// wallet would notice.
    answered: AnsweredIds,
    salt: u16,
}

impl<'a> Session<'a> {
    /// Parse-independent session setup: create an ephemeral relay identity,
    /// authenticate the connection, and bind it to one pairing.
    ///
    /// The embedding wallet supplies its public metadata and handles every
    /// security-sensitive decision through [`SessionHandler`].
    pub async fn connect(
        relay_config: &RelayConfig,
        pairing: PairingUri,
        wallet_metadata: AppMetadata,
        handler: &'a dyn SessionHandler,
    ) -> Result<Self> {
        let identity = ClientIdentity::generate()?;
        let relay = RelayConnection::connect(relay_config, &identity).await?;
        Ok(Self {
            relay,
            relay_config: relay_config.clone(),
            handler,
            wallet_metadata,
            pairing_topic: pairing.topic,
            pairing_key: pairing.sym_key,
            pairing_expiry: pairing.expiry,
            relay_protocol: pairing.relay_protocol,
            relay_data: pairing.relay_data,
            settled: None,
            answered: AnsweredIds::default(),
            salt: 0,
        })
    }

    /// Run until the dapp disconnects, the relay closes, or `shutdown` fires.
    ///
    /// `shutdown` is the application's disconnect signal. It is awaited alongside the relay
    /// rather than checked between messages so that it interrupts a wait that
    /// would otherwise last as long as the dapp stays quiet.
    pub async fn run(
        mut self,
        shutdown: impl std::future::Future<Output = ()> + Send,
    ) -> Result<()> {
        let pairing_topic = self.pairing_topic.clone();
        self.subscribe(&pairing_topic)
            .await
            .context("could not subscribe to the pairing topic")?;
        self.handler.notify(&SessionEvent::Pairing);

        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            // Before every wait, not only the first: a request the handler
            // just served may have opened the UI to review something, and
            // this is where it gets to put its own surface back.
            self.handler.enter_idle().await;
            // Bound separately so the shared borrow of the handler and the
            // exclusive one of the relay do not overlap on `self`.
            let handler = self.handler;
            let woke = tokio::select! {
                () = &mut shutdown => Woke::Stop,
                () = handler.quit_requested() => Woke::Stop,
                message = self.relay.next_message() => Woke::Delivered(message),
            };
            match woke {
                Woke::Stop => {
                    self.disconnect("The wallet closed the session.").await;
                    return Ok(());
                }
                Woke::Delivered(None) => {
                    if !self.restore_connection(&mut shutdown).await? {
                        return Ok(());
                    }
                }
                Woke::Delivered(Some(message)) => {
                    if self.receive(&message.topic, &message.message).await? {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Dial the relay again after a drop, and keep trying until it answers,
    /// the owner asks to stop, or the session has nothing left to reconnect
    /// for.
    ///
    /// Returns whether the session should keep running: `false` is the owner
    /// stopping, and `Err` is the session ending for a reason worth showing.
    ///
    /// The first attempt is made at once, without waiting. Two of the three
    /// close codes the relay documents are routine — a server terminating and
    /// a load rebalance — and both mean "come back now" rather than "stay
    /// away"; a delay in front of the first dial would spend a second of every
    /// rebalance doing nothing. Only a failed attempt earns a wait.
    ///
    /// Both the dial and the wait are inside the same `select!` the idle loop
    /// uses. A relay that is down stays down for as long as it likes, and
    /// opening a connection to a host that has stopped answering takes the
    /// whole handshake deadline to fail — so the person has to be able to
    /// close the connection during either, rather than after both.
    async fn restore_connection<F>(&mut self, shutdown: &mut std::pin::Pin<&mut F>) -> Result<bool>
    where
        F: std::future::Future<Output = ()>,
    {
        self.handler.notify(&SessionEvent::RelayDisconnected);
        let mut delay = RECONNECT_MIN_DELAY;
        loop {
            // Checked before each attempt rather than once: the deadline can
            // pass during the retries, and a session whose authority has
            // lapsed has nothing to come back to.
            if let Some(reason) = self.outage_is_terminal() {
                bail!("{reason}");
            }
            let handler = self.handler;
            let dialed = tokio::select! {
                () = &mut *shutdown => None,
                () = handler.quit_requested() => None,
                opened = self.reopen() => Some(opened),
            };
            match dialed {
                Some(Ok(())) => {
                    self.handler.notify(&SessionEvent::RelayReconnected);
                    return Ok(true);
                }
                // Nothing here distinguishes a relay that is down from one
                // that refused the connection, and neither is worth ending a
                // live session over while its deadline still stands. The
                // backoff is what keeps a long outage from becoming a dial
                // loop.
                Some(Err(_)) => {
                    let waited = tokio::select! {
                        () = &mut *shutdown => false,
                        () = handler.quit_requested() => false,
                        () = tokio::time::sleep(delay) => true,
                    };
                    if !waited {
                        self.disconnect("The wallet closed the session.").await;
                        return Ok(false);
                    }
                    delay = backoff(delay);
                }
                None => {
                    self.disconnect("The wallet closed the session.").await;
                    return Ok(false);
                }
            }
        }
    }

    /// One reconnect attempt: a fresh connection, then the topics this session
    /// is listening on.
    ///
    /// The relay identity is ephemeral and is generated again here. It
    /// authenticates the socket, not the session — the topics and their keys
    /// are what the dapp is talking to, and neither changes.
    ///
    /// Resubscribing is not optional bookkeeping. A subscription belongs to
    /// the connection that made it, so a session that reconnected without
    /// resubscribing would sit on a healthy socket hearing nothing, which
    /// looks exactly like a quiet dapp.
    async fn reopen(&mut self) -> Result<()> {
        let identity = ClientIdentity::generate()?;
        self.relay = RelayConnection::connect(&self.relay_config, &identity).await?;
        self.relay
            .subscribe(&self.pairing_topic)
            .await
            .context("could not resubscribe to the pairing topic")?;
        if let Some(topic) = self.settled.as_ref().map(|settled| settled.topic.clone()) {
            self.relay
                .subscribe(&topic)
                .await
                .context("could not resubscribe to the session topic")?;
        }
        Ok(())
    }

    /// Why an outage should end the session rather than be waited out, if it
    /// should. See [`outage_refusal`].
    fn outage_is_terminal(&self) -> Option<String> {
        outage_refusal(
            self.settled.as_ref().map(|settled| settled.expiry),
            self.pairing_expiry,
            Utc::now(),
        )
    }

    /// Handle one delivered envelope. Returns whether the session is over.
    ///
    /// Two credentials reach this wallet, and they are not the same authority.
    /// The pairing key travels in a URI — pasted, screenshotted, kept in a
    /// dapp's storage — and its one job is carrying a proposal. The session
    /// key is derived at settlement from a fresh key agreement and never
    /// leaves either side. See [`answerable_from`] for why the difference has
    /// to survive past settlement.
    async fn receive(&mut self, topic: &str, envelope: &str) -> Result<bool> {
        // Which key opens this is decided by which topic it arrived on, so a
        // message cannot be replayed from the pairing onto the session or the
        // other way round: the wrong key simply fails to authenticate.
        let (origin, key) = if topic == self.pairing_topic {
            (Origin::Pairing, &self.pairing_key)
        } else if self
            .settled
            .as_ref()
            .is_some_and(|settled| settled.topic == topic)
        {
            (
                Origin::Session,
                &self.settled.as_ref().expect("checked just above").key,
            )
        } else {
            // A topic nothing is subscribed to under this session. Not an
            // error worth ending on; just not ours.
            return Ok(false);
        };

        let Ok(envelope) = Envelope::decode(envelope) else {
            return Ok(false);
        };
        let Ok(plaintext) = envelope.open(key) else {
            return Ok(false);
        };
        let Ok(message) = serde_json::from_str::<IncomingMessage>(&plaintext) else {
            return Ok(false);
        };
        let Some((rpc_method, params)) = message.as_request() else {
            // A response to something this wallet sent. Nothing here waits on
            // one: settle is fire-and-forget by design, because a dapp that
            // never answers it is a dapp that has gone away, which the session
            // finds out about the next time it tries to publish.
            return Ok(false);
        };
        if !answerable_from(rpc_method, origin) {
            // Decided before the id is consumed, so a message on the wrong
            // topic cannot burn an id the other topic will legitimately use.
            return Ok(false);
        }
        // Expiry ends the session's authority over everything, not only over
        // the requests `check_in_scope` measures. It used to be checked there
        // alone, which once left `wc_sessionExtend` reachable after the
        // deadline. The controller now refuses extension at every point, but
        // this common gate still ensures no method answers after expiry.
        if origin == Origin::Session && self.expired() {
            let refusal = EXPIRED_REFUSAL;
            self.handler.notify(&SessionEvent::RequestRefused {
                method: rpc_method,
                reason: refusal,
            });
            let id = message.id;
            self.respond_on_session(
                OutgoingResponse::error(id, error_code::USER_DISCONNECTED, refusal),
                tag::SESSION_REQUEST_RESPONSE,
            )
            .await?;
            return Ok(false);
        }
        if !remember(&mut self.answered, message.id) {
            // Already handled; this is a relay redelivery.
            return Ok(false);
        }

        let rpc_method = rpc_method.to_owned();
        let params = params.clone();
        match rpc_method.as_str() {
            method::SESSION_PROPOSE => self.on_propose(message.id, &params).await,
            method::SESSION_REQUEST => {
                self.on_request(message.id, &params).await?;
                Ok(false)
            }
            method::SESSION_PING => {
                self.handler.notify(&SessionEvent::Ping);
                self.respond_on_session(
                    OutgoingResponse::result(message.id, json!(true)),
                    tag::SESSION_PING_RESPONSE,
                )
                .await?;
                Ok(false)
            }
            method::SESSION_DELETE => {
                let params: SessionDeleteParams =
                    serde_json::from_value(params).unwrap_or(SessionDeleteParams {
                        code: error_code::USER_DISCONNECTED,
                        message: String::new(),
                    });
                self.respond_on_session(
                    OutgoingResponse::result(message.id, json!(true)),
                    tag::SESSION_DELETE_RESPONSE,
                )
                .await?;
                self.handler.notify(&SessionEvent::DappDisconnected {
                    code: params.code,
                    message: &params.message,
                });
                Ok(true)
            }
            // A dapp may ask to extend or update; both are answered honestly
            // rather than silently. `wc_sessionUpdate` would change what the
            // session exposes, which is a decision only the person makes, and
            // there is no way to ask them mid-flight without a second review
            // surface, so it is refused rather than accepted quietly.
            method::SESSION_EXTEND => {
                let settled = self
                    .settled
                    .as_ref()
                    .expect("a session-topic request has settled state");
                let (code, refusal) = controller_refusal(&rpc_method, settled)
                    .expect("session extension is always controller-refused");
                self.respond_on_session(
                    OutgoingResponse::error(message.id, code, refusal),
                    tag::SESSION_EXTEND_RESPONSE,
                )
                .await?;
                Ok(false)
            }
            method::SESSION_UPDATE => {
                self.respond_on_session(
                    OutgoingResponse::error(
                        message.id,
                        error_code::USER_REJECTED,
                        "This wallet does not accept session scope changes. Disconnect and \
                         reconnect to approve a different scope.",
                    ),
                    tag::SESSION_UPDATE_RESPONSE,
                )
                .await?;
                Ok(false)
            }
            method::SESSION_EVENT => {
                self.respond_on_session(
                    OutgoingResponse::result(message.id, json!(true)),
                    tag::SESSION_EVENT_RESPONSE,
                )
                .await?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Answer a proposal. Returns whether the pairing is finished with it.
    ///
    /// A refused proposal ends the pairing. The URI that carried it is a
    /// one-shot credential and the refusal is about the dapp behind it, not
    /// about a moment — so leaving the pairing subscribed would keep a
    /// stranger on the relay with standing to propose again, and would keep
    /// the wallet holding a session slot for a connection the owner already
    /// said no to. Ask again from a fresh link.
    async fn on_propose(&mut self, id: u64, params: &Value) -> Result<bool> {
        if self.settled.is_some() {
            // One `connect` run serves one session. A second proposal on the
            // same pairing would need a second review while the first session
            // is live, and there is one owner review surface. This refusal is
            // the exception that does not end anything: the session it
            // collides with is still the owner's and still running.
            self.reject_proposal(
                id,
                error_code::USER_REJECTED,
                "This wallet already has a session on this pairing.",
            )
            .await?;
            return Ok(false);
        }
        self.handler.notify(&SessionEvent::ProposalReceived);

        let proposal: SessionProposeParams = match serde_json::from_value(params.clone()) {
            Ok(proposal) => proposal,
            Err(error) => {
                return self
                    .refuse_pairing(
                        id,
                        error_code::INVALID_METHOD,
                        format!("The session proposal could not be read: {error}"),
                    )
                    .await;
            }
        };
        // Before anything reads the proposal for content, and before the review
        // it leads to: everything below this line either summarizes the
        // proposal or draws it, and a person has to be able to read the result.
        if let Some(refusal) = oversized_refusal(&proposal) {
            return self
                .refuse_pairing(id, error_code::INVALID_METHOD, refusal)
                .await;
        }
        if let Some(refusal) = self.stale_pairing() {
            return self
                .refuse_pairing(id, error_code::INVALID_METHOD, refusal)
                .await;
        }
        if let Some(expiry) = proposal.expiry_timestamp
            && expiry <= Utc::now().timestamp()
        {
            return self
                .refuse_pairing(
                    id,
                    error_code::INVALID_METHOD,
                    "The session proposal had already expired when it arrived.",
                )
                .await;
        }

        let summary = summarize(&proposal, &self.pairing_topic);
        let decision = self.handler.review_proposal(&summary).await?;
        let scope = match decision {
            ProposalDecision::Reject { code, message } => {
                return self.refuse_pairing(id, code, message).await;
            }
            ProposalDecision::Approve(scope) => scope,
        };

        // Both deadlines again, because the review took as long as a person
        // takes and either may have passed while it was on screen. Settling
        // grants a fresh seven days, so a deadline checked only on the way in
        // bounds nothing: it would let a pairing that expired an hour ago, or
        // a proposal that did, become a week-long session.
        if let Some(refusal) = self.stale_pairing() {
            return self
                .refuse_pairing(id, error_code::INVALID_METHOD, refusal)
                .await;
        }
        if let Some(expiry) = proposal.expiry_timestamp
            && expiry <= Utc::now().timestamp()
        {
            return self
                .refuse_pairing(
                    id,
                    error_code::INVALID_METHOD,
                    "The session proposal expired while it was being reviewed. Ask the dapp to \
                     connect again.",
                )
                .await;
        }

        // Key agreement, then settle, then answer the proposal — in that order.
        // The dapp starts listening on the session topic the moment it reads
        // `responderPublicKey`, so answering first would race the settle it is
        // waiting for.
        let agreement = KeyAgreement::generate()?;
        let session_key = agreement.derive(&proposal.proposer.public_key)?;
        let session_topic = session_key.topic();
        let expiry = Utc::now().timestamp() + SESSION_TTL_SECONDS;
        let namespaces = settled_namespaces(&proposal, &scope);
        // Recorded before the topic is subscribed to, rather than after the
        // dapp has been answered. Everything below this line can lose the
        // connection and dial another, and a reconnect resubscribes the topics
        // this session holds — which it can only do for a session topic it has
        // been told about. Settling and then reconnecting from the window in
        // between left the wallet on a healthy socket, subscribed to the
        // pairing alone, deaf to the session it had just granted.
        self.settled = Some(Settled {
            topic: session_topic.clone(),
            key: session_key.clone(),
            scope,
            metadata: proposal.proposer.metadata,
            expiry,
        });
        self.subscribe(&session_topic)
            .await
            .context("could not subscribe to the session topic")?;

        let settle = OutgoingRequest::new(
            self.next_id(),
            method::SESSION_SETTLE,
            json!({
                "relay": self.relay_object(),
                "controller": {
                    "publicKey": agreement.public_key_hex(),
                    "metadata": &self.wallet_metadata,
                },
                "namespaces": namespaces,
                "expiry": expiry,
            }),
        );
        self.publish(
            &session_topic,
            &session_key,
            &serde_json::to_string(&settle)?,
            tag::SESSION_SETTLE_REQUEST,
            ttl::SESSION_SETTLE,
        )
        .await?;

        let response = OutgoingResponse::result(
            id,
            json!({
                "relay": self.relay_object(),
                "responderPublicKey": agreement.public_key_hex(),
            }),
        );
        let pairing_key = self.pairing_key.clone();
        self.publish(
            &self.pairing_topic.clone(),
            &pairing_key,
            &serde_json::to_string(&response)?,
            tag::SESSION_PROPOSE_RESPONSE_APPROVE,
            ttl::SESSION_PROPOSE_RESPONSE,
        )
        .await?;

        let settled = self.settled.as_ref().expect("recorded before settling");
        self.handler.notify(&SessionEvent::Settled {
            scope: &settled.scope,
            metadata: &settled.metadata,
            expiry,
        });
        Ok(false)
    }

    async fn on_request(&mut self, id: u64, params: &Value) -> Result<()> {
        let Some(settled) = self.settled.as_ref() else {
            return Ok(());
        };
        let request: SessionRequestParams = match serde_json::from_value(params.clone()) {
            Ok(request) => request,
            Err(error) => {
                let message = format!("The request could not be read: {error}");
                self.handler.notify(&SessionEvent::RequestRefused {
                    method: "<unreadable>",
                    reason: &message,
                });
                return self
                    .respond_on_session(
                        OutgoingResponse::error(id, error_code::INVALID_METHOD, message),
                        tag::SESSION_REQUEST_RESPONSE,
                    )
                    .await;
            }
        };

        self.handler.notify(&SessionEvent::RequestReceived {
            method: &request.request.method,
            caip2_chain_id: &request.chain_id,
        });

        // The session boundary, checked here and nowhere else.
        if let Err(refusal) = check_in_scope(&settled.scope, &request, settled.expiry) {
            self.handler.notify(&SessionEvent::RequestRefused {
                method: &request.request.method,
                reason: &refusal.1,
            });
            return self
                .respond_on_session(
                    OutgoingResponse::error(id, refusal.0, refusal.1),
                    tag::SESSION_REQUEST_RESPONSE,
                )
                .await;
        }

        let chain_id = numeric_chain_id(&request.chain_id)
            .expect("chain was accepted by the scope check, which parses it");
        let dapp_request = DappRequest {
            method: request.request.method.clone(),
            params: request.request.params,
            caip2_chain_id: request.chain_id,
            chain_id,
            dapp: &settled.metadata,
            scope: &settled.scope,
        };
        let outcome = self.handler.handle_request(&dapp_request).await?;
        self.handler.notify(&SessionEvent::RequestAnswered {
            method: &dapp_request.method,
            outcome: &outcome,
        });
        let response = match outcome {
            RequestOutcome::Result(result) => OutgoingResponse::result(id, result),
            RequestOutcome::Error { code, message } => OutgoingResponse::error(id, code, message),
        };
        self.respond_on_session(response, tag::SESSION_REQUEST_RESPONSE)
            .await
    }

    /// Tell the dapp the session is over, best effort.
    ///
    /// Failure is ignored on purpose: this runs while the person is shutting
    /// the application down, and a relay that has already gone away must not
    /// turn an explicit disconnect into an error.
    async fn disconnect(&mut self, reason: &str) {
        let Some((topic, key)) = self
            .settled
            .as_ref()
            .map(|settled| (settled.topic.clone(), settled.key.clone()))
        else {
            return;
        };
        let request = OutgoingRequest::new(
            request_id(Utc::now().timestamp_millis(), self.salt),
            method::SESSION_DELETE,
            json!({ "code": error_code::USER_DISCONNECTED, "message": reason }),
        );
        if let Ok(body) = serde_json::to_string(&request) {
            // Bounded, because publishing now dials a new connection when the
            // old one is gone, and this call sits between the owner asking to
            // disconnect and the wallet acting on it.
            let _ = tokio::time::timeout(
                DISCONNECT_TIMEOUT,
                self.publish(
                    &topic,
                    &key,
                    &body,
                    tag::SESSION_DELETE_REQUEST,
                    ttl::SESSION_DELETE,
                ),
            )
            .await;
        }
    }

    /// Refuse a proposal and be done with the pairing that carried it.
    ///
    /// The refusal is published first, so the dapp is told why before the
    /// wallet stops listening.
    async fn refuse_pairing(
        &mut self,
        id: u64,
        code: i64,
        message: impl Into<String>,
    ) -> Result<bool> {
        self.reject_proposal(id, code, message).await?;
        Ok(true)
    }

    async fn reject_proposal(
        &mut self,
        id: u64,
        code: i64,
        message: impl Into<String>,
    ) -> Result<()> {
        let response = OutgoingResponse::error(id, code, message);
        let key = self.pairing_key.clone();
        let topic = self.pairing_topic.clone();
        self.publish(
            &topic,
            &key,
            &serde_json::to_string(&response)?,
            tag::SESSION_PROPOSE_RESPONSE_REJECT,
            ttl::SESSION_PROPOSE_RESPONSE,
        )
        .await
    }

    async fn respond_on_session(
        &mut self,
        response: OutgoingResponse,
        publish_tag: u32,
    ) -> Result<()> {
        let Some(settled) = self.settled.as_ref() else {
            return Ok(());
        };
        let topic = settled.topic.clone();
        let key = settled.key.clone();
        self.publish(
            &topic,
            &key,
            &serde_json::to_string(&response)?,
            publish_tag,
            ttl::SESSION_REQUEST_RESPONSE,
        )
        .await
    }

    /// Listen on a topic, dialing again first if the connection went away
    /// while the wallet was busy.
    ///
    /// The same retry [`Self::publish`] does, and needed for the same reason:
    /// the first thing settlement does after a review is subscribe to the
    /// session topic, and a review is a person reading a screen. Reopening
    /// resubscribes everything this session holds, so a successful reopen has
    /// already done what the caller asked.
    async fn subscribe(&mut self, topic: &str) -> Result<()> {
        let first = self.relay.subscribe(topic).await;
        if first.is_ok() || !self.relay.is_closed() {
            return first.map(|_| ());
        }
        self.handler.notify(&SessionEvent::RelayDisconnected);
        self.reopen()
            .await
            .context("the relay connection closed and could not be reopened")?;
        self.handler.notify(&SessionEvent::RelayReconnected);
        Ok(())
    }

    /// Seal one body and hand it to the relay, dialing again first if the
    /// connection went away while the wallet was busy.
    ///
    /// This is the other half of the reconnect, and the half a session notices
    /// most. The wallet publishes when it has an answer, and an answer is what
    /// it has after a review that took the owner minutes — which is exactly
    /// how long a socket needs to be left alone to die. Without the retry, a
    /// dropped connection turned every approval that outlasted it into a
    /// failed session and an answer the dapp never received.
    ///
    /// One retry, and only when the connection is actually gone. A relay that
    /// answered and refused is answering; redialing would not change its mind
    /// and the caller's error should say what it said.
    async fn publish(
        &mut self,
        topic: &str,
        key: &SymKey,
        body: &str,
        publish_tag: u32,
        publish_ttl: u64,
    ) -> Result<()> {
        let envelope = seal(key, body)?;
        let first = self
            .relay
            .publish(topic, &envelope, publish_tag, publish_ttl)
            .await;
        if first.is_ok() || !self.relay.is_closed() {
            return first;
        }
        self.handler.notify(&SessionEvent::RelayDisconnected);
        self.reopen()
            .await
            .context("the relay connection closed and could not be reopened")?;
        self.handler.notify(&SessionEvent::RelayReconnected);
        self.relay
            .publish(topic, &envelope, publish_tag, publish_ttl)
            .await
    }

    /// The refusal to send when the pairing's own deadline has passed.
    fn stale_pairing(&self) -> Option<String> {
        pairing_refusal(self.pairing_expiry, Utc::now())
    }

    /// Whether the settled session's deadline has passed. An unsettled session
    /// has no deadline to have passed, and nothing on the session topic can
    /// reach it anyway.
    fn expired(&self) -> bool {
        self.settled
            .as_ref()
            .is_some_and(|settled| lapsed(settled.expiry, Utc::now().timestamp()))
    }

    fn relay_object(&self) -> Relay {
        Relay {
            protocol: self.relay_protocol.clone(),
            data: self.relay_data.clone(),
        }
    }

    fn next_id(&mut self) -> u64 {
        self.salt = self.salt.wrapping_add(1);
        request_id(Utc::now().timestamp_millis(), self.salt)
    }
}

/// Whether a request is inside what the session approved.
///
/// Returns the protocol error to send when it is not. Each refusal names the
/// specific thing that was out of scope, because a dapp shows this string to
/// its user and "rejected" alone sends them to support.
fn check_in_scope(
    scope: &ApprovedScope,
    request: &SessionRequestParams,
    expiry: i64,
) -> std::result::Result<(), (i64, String)> {
    let now = Utc::now().timestamp();
    if lapsed(expiry, now) {
        return Err((error_code::USER_DISCONNECTED, EXPIRED_REFUSAL.to_owned()));
    }
    if let Some(request_expiry) = request.request.expiry_timestamp
        && request_expiry <= now
    {
        return Err((
            error_code::INVALID_METHOD,
            "This request had already expired when it arrived.".to_owned(),
        ));
    }
    if !scope.chains.iter().any(|chain| chain == &request.chain_id) {
        return Err((
            error_code::UNAUTHORIZED_CHAIN,
            format!(
                "This session was approved for {} and does not cover {}.",
                scope.chains.join(", "),
                request.chain_id
            ),
        ));
    }
    if numeric_chain_id(&request.chain_id).is_none() {
        return Err((
            error_code::UNAUTHORIZED_CHAIN,
            format!("`{}` is not an eip155 chain identifier.", request.chain_id),
        ));
    }
    if !scope.allows(&request.chain_id, &request.request.method) {
        return Err((
            error_code::UNSUPPORTED_METHODS,
            format!(
                "This session was not approved for `{}`.",
                request.request.method
            ),
        ));
    }
    // EIP-5792 carries a second, effective chain selector inside
    // `wallet_sendCalls`. Authorizing only the outer WalletConnect selector
    // turns relational chain-method grants into two independent sets: a dapp
    // can arrive on a chain where this method is granted, then execute the
    // batch on another approved chain where it is not. Keep the two selectors
    // identical at the session boundary so no handler or signing path ever
    // sees that confused-deputy request.
    if request.request.method == "wallet_sendCalls" {
        let batch = dapp_request::parse_send_calls(&request.request.params).map_err(|error| {
            (
                error_code::INVALID_METHOD,
                format!("The wallet_sendCalls request could not be read: {error:#}"),
            )
        })?;
        let effective_chain = format!("{EIP155}:{}", batch.chain_id);
        if effective_chain != request.chain_id {
            return Err((
                error_code::UNAUTHORIZED_CHAIN,
                format!(
                    "wallet_sendCalls names {effective_chain} inside a request authorized for {}.",
                    request.chain_id
                ),
            ));
        }
    }
    Ok(())
}

/// The decimal chain id inside a CAIP-2 identifier, when it names eip155.
#[must_use]
pub fn numeric_chain_id(caip2: &str) -> Option<u64> {
    let (namespace, reference) = caip2.split_once(':')?;
    if namespace != EIP155 {
        return None;
    }
    reference.parse().ok()
}

/// The chains one proposal namespace asks for, in either of the two spellings
/// the protocol allows: the chain inside the key (`eip155:1`), or a `chains`
/// list under a bare namespace key (`eip155`).
fn namespace_chains(key: &str, namespace: &ProposalNamespace) -> Vec<String> {
    if key.contains(':') {
        return vec![key.to_owned()];
    }
    namespace.chains.clone().unwrap_or_default()
}

/// Everything a proposal names, as the number of characters a review drawing
/// all of it would hold.
///
/// One number rather than a limit per field, because the reviewer's screen does
/// not care which list a string came from, and a rule with one number has one
/// thing to get wrong.
fn proposal_characters(proposal: &SessionProposeParams) -> usize {
    let drawn = |value: &String| value.chars().count() + SEPARATOR_CHARACTERS;
    let namespaces = proposal
        .required_namespaces
        .iter()
        .chain(proposal.optional_namespaces.iter());
    let asked: usize = namespaces
        .map(|(key, namespace)| {
            drawn(key)
                + namespace
                    .chains
                    .iter()
                    .flatten()
                    .chain(&namespace.methods)
                    .chain(&namespace.events)
                    .map(drawn)
                    .sum::<usize>()
        })
        .sum();
    asked
        + proposal
            .proposer
            .metadata
            .icons
            .iter()
            .map(drawn)
            .sum::<usize>()
}

/// The refusal for a proposal too long to review, or `None` for one a person
/// could read.
fn oversized_refusal(proposal: &SessionProposeParams) -> Option<String> {
    let asked = proposal_characters(proposal);
    (asked > MAX_PROPOSAL_CHARACTERS).then(|| {
        format!(
            "This proposal names {asked} characters of chains, methods, and events. This wallet \
             reviews a proposal on a screen a person reads and refuses anything above \
             {MAX_PROPOSAL_CHARACTERS}; ask for the scope the dapp actually needs."
        )
    })
}

/// Reduce a proposal to the facts a person decides on, with required and
/// optional kept apart — a chain the dapp merely *prefers* is not a reason to
/// expose an account on it.
fn summarize(proposal: &SessionProposeParams, pairing_topic: &str) -> ProposalSummary {
    let mut required_chains = BTreeSet::new();
    let mut required_methods = BTreeSet::new();
    let mut optional_chains = BTreeSet::new();
    let mut optional_methods = BTreeSet::new();
    let mut events = BTreeSet::new();
    let mut requested_grants = Vec::new();

    for (key, namespace) in &proposal.required_namespaces {
        let chains = namespace_chains(key, namespace);
        required_chains.extend(chains.iter().cloned());
        required_methods.extend(namespace.methods.iter().cloned());
        events.extend(namespace.events.iter().cloned());
        requested_grants.push(ScopeGrant {
            chains,
            methods: namespace.methods.clone(),
        });
    }
    for (key, namespace) in &proposal.optional_namespaces {
        let chains = namespace_chains(key, namespace);
        optional_chains.extend(chains.iter().cloned());
        optional_methods.extend(namespace.methods.iter().cloned());
        events.extend(namespace.events.iter().cloned());
        requested_grants.push(ScopeGrant {
            chains,
            methods: namespace.methods.clone(),
        });
    }
    // A chain or method that is required is not also optional; showing it twice
    // would overstate what the dapp is asking for.
    for chain in &required_chains {
        optional_chains.remove(chain);
    }
    for method in &required_methods {
        optional_methods.remove(method);
    }

    ProposalSummary {
        metadata: proposal.proposer.metadata.clone(),
        required_chains: required_chains.into_iter().collect(),
        optional_chains: optional_chains.into_iter().collect(),
        required_methods: required_methods.into_iter().collect(),
        optional_methods: optional_methods.into_iter().collect(),
        events: events.into_iter().collect(),
        requested_grants,
        pairing_topic: pairing_topic.to_owned(),
    }
}

/// Build the settled namespaces, mirroring the proposal's own key structure.
///
/// Mirroring matters for compatibility: a dapp that asked under `eip155:1`
/// validates the answer under `eip155:1`, and one that asked under a bare
/// `eip155` validates it there. Emitting one shape for both is how a session
/// settles and is then immediately dropped by the dapp as non-conforming.
///
/// Whatever the shape, the content is the approved scope and nothing else —
/// this function narrows, and can never widen.
fn settled_namespaces(
    proposal: &SessionProposeParams,
    scope: &ApprovedScope,
) -> BTreeMap<String, SettledNamespace> {
    let approved_chains: BTreeSet<&String> = scope.chains.iter().collect();
    let mut settled: BTreeMap<String, SettledNamespace> = BTreeMap::new();

    let proposed = proposal
        .required_namespaces
        .iter()
        .chain(proposal.optional_namespaces.iter());
    for (key, namespace) in proposed {
        if !key.starts_with(EIP155) {
            continue;
        }
        let chains: Vec<String> = namespace_chains(key, namespace)
            .into_iter()
            .filter(|chain| approved_chains.contains(chain))
            .collect();
        if chains.is_empty() {
            continue;
        }
        let methods: Vec<String> = namespace
            .methods
            .iter()
            .filter(|method| chains.iter().any(|chain| scope.allows(chain, method)))
            .cloned()
            .collect();
        let events: Vec<String> = namespace
            .events
            .iter()
            .filter(|event| scope.events.contains(event))
            .cloned()
            .collect();
        let accounts: Vec<String> = chains
            .iter()
            .map(|chain| format!("{chain}:{}", scope.address))
            .collect();
        let entry = settled.entry(key.clone()).or_default();
        merge(&mut entry.accounts, accounts);
        merge(&mut entry.methods, methods);
        merge(&mut entry.events, events);
        if key.contains(':') {
            // A CAIP-2 key names its own chain; repeating it in `chains` is not
            // what the reference client emits.
            entry.chains = None;
        } else {
            let mut listed = entry.chains.take().unwrap_or_default();
            merge(&mut listed, chains);
            entry.chains = Some(listed);
        }
    }

    // A dapp that proposed nothing this wallet recognizes still gets a usable
    // session when the person approved one: without this, `namespaces` would be
    // empty and the dapp would have no account to talk to.
    if settled.is_empty() && !scope.chains.is_empty() {
        settled.insert(
            EIP155.to_owned(),
            SettledNamespace {
                chains: Some(scope.chains.clone()),
                accounts: scope.accounts(),
                methods: scope.methods.clone(),
                events: scope.events.clone(),
            },
        );
    }
    settled
}

fn merge(destination: &mut Vec<String>, addition: Vec<String>) {
    for value in addition {
        if !destination.contains(&value) {
            destination.push(value);
        }
    }
}

#[cfg(test)]
#[path = "session_test.rs"]
mod tests;
