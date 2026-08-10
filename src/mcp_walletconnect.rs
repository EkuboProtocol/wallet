//! `WalletConnect` sessions an agent opens for itself.
//!
//! `ekubo-wallet connect` exists for a person sitting at a terminal with a
//! pairing link in their clipboard. This module exists for the case that
//! motivates the whole MCP server: an agent driving a dapp's own web interface
//! because the dapp has no MCP server, which means the agent — not a person —
//! is the one who has the pairing link, and there is no terminal to show a
//! connection review on.
//!
//! **A session opened here is not reviewed by anybody.** That is the point of
//! it, and it is a real reduction in what this wallet checks. What the
//! connection review does is four things, and only the fourth is given up:
//!
//! 1. It narrows the scope to chains this wallet has configured and methods it
//!    implements. Kept — [`crate::dapp::DappSession::negotiate`] is the same
//!    code the terminal calls, and `chain_ids` on the tool narrows it further.
//! 2. It binds the session to exactly one account. Kept — `wallet_id` names it,
//!    and every request naming another address is still refused.
//! 3. It shows what is checkable about the dapp apart from what it claims.
//!    Kept, but *moved*: the host, the claims, and every caution
//!    [`DappIdentity`] derives are returned to the agent instead of drawn, so
//!    they can be repeated to the user and weighed.
//! 4. It asks a person whether to connect at all. **Given up.** An agent that
//!    can call [`open`] can point this wallet's account at any dapp it likes.
//!
//! ## The agent looks before the policy does
//!
//! Giving up (4) would not be survivable on its own, and the reason is an
//! asymmetry that has nothing to do with how strong the policy is. An agent
//! that produces a plan itself simulates it, reads what it does, and *chooses*
//! to send. A dapp's plan used to go from its calldata straight to the policy
//! with nobody's judgement in between — so an obvious drainer got exactly one
//! check, whether some rule happened to match it, and a policy is a set of
//! shapes rather than a reader.
//!
//! So [`HeadlessSurface::approve_plan`] stops every dapp-proposed plan after
//! its simulation and before `execute_automatic`, publishes it as a
//! [`ProposedTransaction`], and waits. What is published is deliberately the
//! same material the agent already reads before sending its own plans: the
//! exact plan and the same `SimulationResult`. `token_spends`,
//! `balance_changes`, `will_authorize_delegation`, and `policy_outcome` are
//! where a drainer and the swap the user asked for stop resembling each other.
//!
//! That gate is a gate and never a grant. Approving releases the plan into the
//! policy, which decides exactly as it always did; nothing an agent can say
//! makes something sign that the policy would have queued. And every way out
//! of it other than an explicit approval — silence, a closed session, an
//! expired budget — refuses.
//!
//! What survives, then, is both halves of what an agent-proposed transaction
//! gets: a reader, and the policy. The blast radius of an unreviewed
//! *connection* is no longer "whatever the policy signs without asking" but
//! "whatever the policy signs without asking, that the agent also looked at
//! and approved" — which is exactly the position a plan the agent fetched from
//! a producer is already in.
//!
//! ## Waiting without a terminal
//!
//! The terminal surface answers a queued transaction by drawing a review and
//! waiting for a keystroke. There is no keystroke here, so this surface leaves
//! the record where `ekubo-wallet review` will find it and watches the row.
//!
//! That wait is bounded, and the bound is not a detail. A dapp's
//! `wc_sessionRequest` response is worth nothing to it after
//! `ttl::SESSION_REQUEST_RESPONSE`, so a wait that outran it would tell the
//! dapp nothing while leaving a row an owner could approve minutes later — and
//! an approved row is one `wallet_send_execution_plan` away from broadcasting a
//! transaction the dapp was already told had failed, quite possibly after the
//! agent retried and produced a second one. So the wait ends at
//! [`REQUEST_BUDGET`] and **rejects the record on its way out**, atomically:
//! [`crate::pending::PendingStore::reject`] only moves a row that is still
//! awaiting approval, so an owner who approved in the same instant wins the
//! race and their signature is used. Either the dapp is told the truth and the
//! row is dead, or the row is alive and the dapp is told about it. Never both.
//!
//! Closing a session ends every wait the same way, for the same reason, and so
//! does a store read that fails mid-wait. The one residual is a store that
//! will not answer at all: the rejection is attempted and cannot be written
//! either, so the row survives in `awaiting_approval` with nothing left
//! watching it. Approving it then produces signed bytes nobody broadcasts —
//! this session is gone — and it takes a deliberate
//! `wallet_send_execution_plan` with that id to send them, which is why both
//! tool descriptions say not to submit an id a session is waiting on.

use crate::{
    config::{ConfigStore, WalletMetadata},
    core::execution_plan::ExecutionPlan,
    dapp::{DappSession, DappSurface, PlanVerdict},
    legal,
    message::{MessageStatus, MessageStore, PendingMessage},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    sanitize::terminal_safe_line,
    simulation::SimulationResult,
    typed_data::{PendingTypedData, TypedDataStatus, TypedDataStore},
    walletconnect::{
        crypto::ClientIdentity,
        identity::DappIdentity,
        relay::{DEFAULT_RELAY_URL, RelayConnection},
        session::{
            DappRequest, ProposalDecision, ProposalSummary, RequestOutcome, Session, SessionEvent,
            SessionHandler,
        },
        uri::PairingUri,
    },
};
use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

/// Sessions this process will hold open at once.
///
/// Each is an OS thread and a websocket to the relay, held for as long as the
/// dapp keeps it. An agent working through one dapp's interface needs one; a
/// handful covers comparing two. A number this small is also the bound on how
/// many unreviewed connections can exist at all, which is the reason it is a
/// hard refusal rather than a queue.
pub const MAX_SESSIONS: usize = 4;

/// The whole time one dapp request may take, across every wait it needs.
///
/// A request can wait twice — once for the agent to look at the simulation,
/// then, if the policy does not already cover it, for `ekubo-wallet review`.
/// One budget covers both rather than a bound each, because two bounds add: a
/// generous agent window plus a generous human window is a total past the
/// protocol's own 300-second response TTL, and an answer published after that
/// reaches nobody. It is stamped when the request arrives and spent from
/// there, so whatever the first wait leaves is what the second gets.
pub const REQUEST_BUDGET: Duration = Duration::from_mins(4);

/// How often a wait re-reads the row it is waiting on. The same interval the
/// MCP approval waits poll at.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Activity lines kept per session. A busy dapp produces a line per request;
/// this is enough to explain what just happened without letting a session's
/// memory grow with its age.
const MAX_ACTIVITY: usize = 64;

/// Where a session is in its life.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum SessionLifecycle {
    /// Paired with the link, waiting for the dapp's connection proposal.
    Pairing,
    /// Settled. The dapp can propose.
    Connected,
    /// Over, for the reason given.
    Closed(String),
    /// Never got going, or died, for the reason given.
    Failed(String),
}

impl SessionLifecycle {
    /// Whether nothing further will happen on this session.
    #[must_use]
    pub const fn is_over(&self) -> bool {
        matches!(self, Self::Closed(_) | Self::Failed(_))
    }
}

/// What this wallet can say about the dapp on the other end.
///
/// Every field is the dapp's own claim except `host`, which is parsed out of
/// the URL it claimed, and `cautions`, which are this wallet's observations
/// about those claims. The connection review would have drawn all of it; with
/// no review to draw it, it is returned to the agent instead. Repeat it to the
/// user rather than acting on it: a site impersonating another one puts the
/// other one's name in `name`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct DappSummary {
    /// The host parsed out of the dapp's claimed URL. The one field with a
    /// shape that can be wrong, and the one to compare against the page the
    /// session was opened from.
    pub host: Option<String>,
    /// The dapp's claimed name, attested by nobody.
    pub name: Option<String>,
    /// Its claimed description, attested by nobody.
    pub description: Option<String>,
    /// Its claimed URL in full.
    pub url: Option<String>,
    /// Hosts its icons are served from. Never fetched.
    pub icon_hosts: Vec<String>,
    /// Things worth weighing about the claims above: a name that spells a
    /// domain the dapp does not serve from, a URL that is not https, icons
    /// from somewhere else. None is a verdict — a legitimate dapp can trip any
    /// of them.
    pub cautions: Vec<String>,
}

impl DappSummary {
    fn of(metadata: &crate::walletconnect::protocol::AppMetadata) -> Self {
        let identity = DappIdentity::of(metadata);
        Self {
            host: identity.site.as_ref().map(|site| site.host.clone()),
            name: identity.name,
            description: identity.description,
            url: identity.url,
            icon_hosts: identity.icon_hosts,
            cautions: identity.cautions,
        }
    }
}

/// One request from this session that is waiting for the owner.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct AwaitingRequest {
    /// The id `ekubo-wallet review` takes, and the id to watch with
    /// `wallet_wait_for_approval`.
    pub request_id: Uuid,
    /// `transaction`, `message`, or `typed_data`.
    pub kind: &'static str,
    /// What the dapp called for, for a line the user can be told.
    pub method: String,
    pub waiting_since: DateTime<Utc>,
    /// When this wait gives up and the dapp is told the request was not
    /// approved. The record is rejected at that moment, so approving after it
    /// is not possible.
    pub expires_at: DateTime<Utc>,
}

/// A dapp's plan, simulated and waiting for the agent to look at it.
///
/// This is the whole of what the agent gate is. The difference between an
/// agent's own transaction and a dapp's used to be that the agent produced the
/// first one, saw its simulation, and chose to send it, while the second went
/// from the dapp's calldata to the policy with nobody's judgement in between —
/// so an obvious drainer got exactly one check, whether some rule happened to
/// match it. What is carried here is deliberately the same material the agent
/// already reads before sending a plan of its own: the exact plan, and the
/// same [`SimulationResult`] `wallet_simulate_execution_plan` returns.
///
/// The tells are in that struct rather than in anything invented for this:
/// `token_spends` says how much of which token leaves, `balance_changes` says
/// what the account looks like afterwards, `will_authorize_delegation` and
/// `replaces_delegated_implementation` say whether the account's own code is
/// being pointed somewhere new, and `policy_outcome` says what would happen
/// next. A swap the user asked for and a drainer do not resemble each other in
/// any of them.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct ProposedTransaction {
    pub session_id: Uuid,
    /// The id to pass to `wallet_walletconnect_decide`. It names this proposal
    /// and nothing else, and it is not a pending-request id: no record exists
    /// yet, because the policy has not seen this plan.
    pub proposal_id: Uuid,
    /// `eth_sendTransaction` or `wallet_sendCalls`.
    pub method: String,
    pub chain_id: String,
    /// Who this is from, restated at request time rather than only at
    /// connection: the session was opened without a review, so the claims and
    /// cautions belong beside every decision made under it.
    pub dapp: DappSummary,
    /// Exactly what would be executed, step by step.
    pub execution_plan: ExecutionPlan,
    /// The same simulation the agent reads before sending its own plans.
    pub simulation: SimulationResult,
    pub proposed_at: DateTime<Utc>,
    /// When this proposal is refused on the agent's behalf and the dapp is
    /// told. Deciding is fail-closed: silence is a refusal.
    pub expires_at: DateTime<Utc>,
    pub instruction: String,
}

/// What the agent said about one proposal.
#[derive(Clone, Debug)]
struct AgentDecision {
    proposal_id: Uuid,
    approve: bool,
    reason: Option<String>,
}

/// Something that happened on a session, for the agent to read back.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct Activity {
    pub at: DateTime<Utc>,
    pub message: String,
}

/// Everything a session publishes about itself, read from another thread.
#[derive(Debug, Default)]
struct SessionShared {
    lifecycle: Option<SessionLifecycle>,
    dapp: Option<DappSummary>,
    address: Option<String>,
    chains: Vec<String>,
    methods: Vec<String>,
    awaiting: BTreeMap<Uuid, AwaitingRequest>,
    /// The one proposal waiting on the agent, if any.
    ///
    /// One slot rather than a map, because the session loop serves one request
    /// at a time: it awaits `handle_request` to completion before reading the
    /// relay again, so a second proposal cannot exist while this one is
    /// undecided.
    proposed: Option<ProposedTransaction>,
    /// The answer to whatever is in `proposed`, written by the decide tool.
    decision: Option<AgentDecision>,
    activity: VecDeque<Activity>,
}

impl SessionShared {
    fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone().unwrap_or(SessionLifecycle::Pairing)
    }

    fn note(&mut self, message: &str) {
        self.activity.push_back(Activity {
            at: Utc::now(),
            // Everything reaching here may carry a dapp-authored string, and
            // an agent's transcript is rendered on somebody's terminal often
            // enough that the same sanitizer applies.
            message: terminal_safe_line(message),
        });
        while self.activity.len() > MAX_ACTIVITY {
            self.activity.pop_front();
        }
    }
}

/// A live session as the registry holds it.
struct LiveSession {
    wallet_id: String,
    opened_at: DateTime<Utc>,
    shared: Arc<Mutex<SessionShared>>,
    /// Set to end the session. Read by the session loop between messages and
    /// by every wait, so closing cuts a wait short rather than outlasting it.
    quit: Arc<AtomicBool>,
}

/// What the tools report about one session.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SessionReport {
    /// The handle to disconnect with.
    pub session_id: Uuid,
    pub wallet_id: String,
    /// The address the dapp was told about, once the session settled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub lifecycle: SessionLifecycle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dapp: Option<DappSummary>,
    /// CAIP-2 chains this session may act on. Nothing outside this list
    /// reaches the wallet at all.
    pub chains: Vec<String>,
    /// The methods the session settled on.
    pub methods: Vec<String>,
    pub opened_at: DateTime<Utc>,
    /// Requests this dapp has made that need `ekubo-wallet review`. Tell the
    /// user to run it; do not submit these ids yourself — the session
    /// broadcasts what it is waiting on, and a second submission is a second
    /// transaction.
    pub awaiting_review: Vec<AwaitingRequest>,
    /// A dapp proposal waiting for you to call `wallet_walletconnect_decide`.
    /// Also returned by `wallet_walletconnect_next_request`, which blocks for
    /// it; this field is how an agent that stopped waiting finds it again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub awaiting_decision: Option<ProposedTransaction>,
    /// The most recent things that happened, oldest first.
    pub activity: Vec<Activity>,
}

/// Every session this process is holding open.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: BTreeMap<Uuid, LiveSession>,
}

impl SessionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget sessions that have finished, so a dead one does not spend a slot.
    fn prune(&mut self) {
        self.sessions
            .retain(|_, session| !session.lifecycle().is_over());
    }

    fn report(id: Uuid, session: &LiveSession) -> SessionReport {
        // A poisoned lock is read through rather than propagated: this state
        // is a report, every write to it is a whole assignment, and refusing
        // to say what a session is doing because one write panicked is the
        // less useful failure.
        let shared = session
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        SessionReport {
            session_id: id,
            wallet_id: session.wallet_id.clone(),
            address: shared.address.clone(),
            lifecycle: shared.lifecycle(),
            dapp: shared.dapp.clone(),
            chains: shared.chains.clone(),
            methods: shared.methods.clone(),
            opened_at: session.opened_at,
            awaiting_review: shared.awaiting.values().cloned().collect(),
            awaiting_decision: shared.proposed.clone(),
            activity: shared.activity.iter().cloned().collect(),
        }
    }

    /// Every session, live or just finished, oldest first.
    pub fn list(&mut self) -> Vec<SessionReport> {
        self.prune();
        self.sessions
            .iter()
            .map(|(id, session)| Self::report(*id, session))
            .collect()
    }

    /// One session's report.
    pub fn get(&mut self, id: Uuid) -> Result<SessionReport> {
        self.prune();
        let session = self
            .sessions
            .get(&id)
            .with_context(|| format!("no WalletConnect session {id}"))?;
        Ok(Self::report(id, session))
    }
}

impl LiveSession {
    fn lifecycle(&self) -> SessionLifecycle {
        lifecycle_of(&self.shared)
    }
}

/// Read a session's lifecycle and let go of the lock.
///
/// Returned by value rather than read through a guard because every caller
/// tests it and then awaits, and a `std` guard held across an await would make
/// the surrounding future `!Send` — which the MCP tool router requires.
fn lifecycle_of(shared: &Mutex<SessionShared>) -> SessionLifecycle {
    shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .lifecycle()
}

/// Ask a session to end, wait briefly for it to say it has, and forget it.
///
/// The flag is what ends it: the session loop honours it between messages, and
/// every wait for an owner decision honours it too, so a close does not have
/// to outlast a review that is not going to happen. What is waited for here is
/// only the courtesy `wc_sessionDelete` reaching the dapp, and a relay that has
/// gone away must not turn a close into an error.
pub async fn close(registry: &Mutex<SessionRegistry>, id: Uuid) -> Result<SessionReport> {
    let shared = {
        let mut sessions = lock(registry)?;
        sessions.prune();
        let session = sessions
            .sessions
            .get(&id)
            .with_context(|| format!("no WalletConnect session {id}"))?;
        session.quit.store(true, Ordering::Relaxed);
        Arc::clone(&session.shared)
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !lifecycle_of(&shared).is_over() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let mut sessions = lock(registry)?;
    let report = sessions
        .sessions
        .get(&id)
        .map(|session| SessionRegistry::report(id, session))
        .with_context(|| format!("no WalletConnect session {id}"))?;
    // Removed whether or not the goodbye landed. The flag is set, the thread
    // is on its way out, and a session the agent has closed must not keep
    // occupying a slot.
    sessions.sessions.remove(&id);
    Ok(report)
}

/// Wait for a dapp on this session to propose a transaction.
///
/// Blocks like `wallet_wait_for_approval` does, and for the same reason: the
/// thing being waited on happens outside this process on nobody's schedule,
/// and polling in the model's loop costs a turn per poll. The wait is free in
/// wall-clock terms — the agent has just told the dapp's page to do something
/// and has to wait for the result regardless. This *is* that wait.
///
/// `None` means nothing arrived before the timeout, which decides nothing:
/// call again.
pub async fn next_proposal(
    registry: &Mutex<SessionRegistry>,
    session_id: Uuid,
    timeout: Duration,
) -> Result<Option<ProposedTransaction>> {
    let shared = {
        let mut sessions = lock(registry)?;
        sessions.prune();
        Arc::clone(
            &sessions
                .sessions
                .get(&session_id)
                .with_context(|| format!("no WalletConnect session {session_id}"))?
                .shared,
        )
    };
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let (proposal, over) = {
            let shared = shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (shared.proposed.clone(), shared.lifecycle().is_over())
        };
        if proposal.is_some() {
            return Ok(proposal);
        }
        // A session that ended will never propose anything, so waiting out the
        // timeout on one would just be a slower way of saying so.
        if over || tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Answer the proposal a session is holding.
///
/// Approving is not an authorization: it releases the plan into the policy,
/// which decides as it always did, so a plan no rule covers still queues for
/// `ekubo-wallet review`. Refusing ends it here and the dapp is told.
///
/// The id must be the one actually waiting. An answer to a proposal that has
/// already been decided, expired, or been superseded is refused rather than
/// applied to whatever is waiting now — the agent's judgement was about a
/// specific plan and a specific simulation, and applying it to a different one
/// is exactly the substitution this gate exists to prevent.
pub fn decide_proposal(
    registry: &Mutex<SessionRegistry>,
    session_id: Uuid,
    proposal_id: Uuid,
    approve: bool,
    reason: Option<String>,
) -> Result<()> {
    let sessions = lock(registry)?;
    let session = sessions
        .sessions
        .get(&session_id)
        .with_context(|| format!("no WalletConnect session {session_id}"))?;
    let mut shared = session
        .shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let waiting = shared
        .proposed
        .as_ref()
        .map(|proposal| proposal.proposal_id);
    ensure!(
        waiting == Some(proposal_id),
        "session {session_id} is not waiting on proposal {proposal_id}; {}",
        waiting.map_or_else(
            || "it has nothing waiting for a decision, so that proposal has already been \
                 decided, expired, or been withdrawn by the dapp"
                .to_owned(),
            |current| format!(
                "it is waiting on {current}. Read that proposal before deciding it rather than \
                 answering it with a decision made about a different plan"
            )
        )
    );
    shared.decision = Some(AgentDecision {
        proposal_id,
        approve,
        reason,
    });
    Ok(())
}

fn lock(registry: &Mutex<SessionRegistry>) -> Result<std::sync::MutexGuard<'_, SessionRegistry>> {
    registry
        .lock()
        .map_err(|_| anyhow!("the WalletConnect session registry lock was poisoned"))
}

/// Open a session against a pairing link, with nobody asked whether to.
///
/// Returns once the dapp has settled the session, or once it is clear it will
/// not: a proposal this wallet refuses, a relay that will not connect, or
/// `timeout` elapsing with no proposal at all.
pub async fn open(
    registry: &Mutex<SessionRegistry>,
    config: &ConfigStore,
    wallet_id: &str,
    uri: &str,
    chain_ids: Option<Vec<String>>,
    timeout: Duration,
) -> Result<SessionReport> {
    // The same gate every signing path takes, checked before a dapp is told
    // anything. The session re-checks per request as well, because acceptance
    // can lapse while a session is up.
    legal::require_current_acceptance(config.data_dir())?;
    let account = config.wallet(wallet_id)?;
    // Parsed here rather than on the session thread so a malformed link fails
    // the tool call instead of a thread the caller has to go and read about.
    let pairing = PairingUri::parse(uri, Utc::now())?;
    let limit_to = chain_ids
        .map(|chains| -> Result<Vec<String>> {
            ensure!(
                !chains.is_empty(),
                "chain_ids must name at least one chain, or be omitted to allow every configured \
                 chain the dapp asks for"
            );
            chains
                .into_iter()
                .map(|chain| {
                    let numeric = crate::input_validation::parse_chain_id(&chain).map_or_else(
                        |_| {
                            crate::walletconnect::session::numeric_chain_id(&chain).with_context(
                                || format!("`{chain}` is neither a chain id nor an eip155 CAIP-2 identifier"),
                            )
                        },
                        Ok,
                    )?;
                    // Refused now rather than at settlement: a caller naming a
                    // chain this wallet cannot act on has made a mistake, and
                    // hearing about it as "the dapp asked for nothing we have"
                    // names the wrong party.
                    config.network_by_chain_id(&numeric.to_string())?;
                    Ok(format!("eip155:{numeric}"))
                })
                .collect()
        })
        .transpose()?;

    let shared = Arc::new(Mutex::new(SessionShared::default()));
    let quit = Arc::new(AtomicBool::new(false));
    let session_id = Uuid::new_v4();
    {
        let mut registry = lock(registry)?;
        registry.prune();
        ensure!(
            registry.sessions.len() < MAX_SESSIONS,
            "this wallet already holds {MAX_SESSIONS} WalletConnect sessions. Disconnect one with \
             wallet_walletconnect_disconnect before opening another."
        );
        registry.sessions.insert(
            session_id,
            LiveSession {
                wallet_id: account.id.clone(),
                opened_at: Utc::now(),
                shared: Arc::clone(&shared),
                quit: Arc::clone(&quit),
            },
        );
    }

    spawn_session(
        session_id,
        config.clone(),
        account,
        pairing,
        limit_to,
        Arc::clone(&shared),
        Arc::clone(&quit),
    );

    // Wait for the dapp to propose and the session to settle. A dapp that has
    // just been handed a link proposes within a second or two; one that never
    // does leaves the caller a `pairing` report rather than a hang.
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let lifecycle = lifecycle_of(&shared);
        if lifecycle != SessionLifecycle::Pairing || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    lock(registry)?.get(session_id)
}

/// Run one session on a thread of its own until it ends.
///
/// A thread rather than a task because the session's futures are `?Send` — the
/// handler holds `Cell`s and opens `SQLite` connections — and the MCP server
/// runs on a multi-threaded runtime that can only hold `Send` ones. The thread
/// carries a current-thread runtime and a `LocalSet`, which is what makes
/// `?Send` legal, and it owns everything it touches: a cloned `ConfigStore`,
/// its own store handles, and its own relay connection.
///
/// Nothing is joined. The thread ends when the dapp disconnects, when the
/// relay drops, or when the quit flag is set; the last thing it does is record
/// why in the shared state, which is what the tools read.
fn spawn_session(
    session_id: Uuid,
    config: ConfigStore,
    account: WalletMetadata,
    pairing: PairingUri,
    limit_to: Option<Vec<String>>,
    shared: Arc<Mutex<SessionShared>>,
    quit: Arc<AtomicBool>,
) {
    let unstarted = Arc::clone(&shared);
    let started = std::thread::Builder::new()
        .name("walletconnect-session".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    finish(&shared, SessionLifecycle::Failed(format!("{error:#}")));
                    return;
                }
            };
            let local = tokio::task::LocalSet::new();
            let outcome = local.block_on(
                &runtime,
                run_session(
                    session_id, &config, account, pairing, limit_to, &shared, &quit,
                ),
            );
            match outcome {
                Ok(()) => finish(
                    &shared,
                    SessionLifecycle::Closed("The session ended.".to_owned()),
                ),
                Err(error) => finish(&shared, SessionLifecycle::Failed(format!("{error:#}"))),
            }
        });
    if let Err(error) = started {
        // The registry already holds this session, so the failure has to be
        // recorded where the tools read rather than dropped on the floor.
        finish(&unstarted, SessionLifecycle::Failed(format!("{error:#}")));
    }
}

/// Record a session's last word, unless it already had one.
///
/// A dapp that sent `wc_sessionDelete` said why, and the generic "the session
/// ended" written when the loop returns must not overwrite it.
fn finish(shared: &Mutex<SessionShared>, lifecycle: SessionLifecycle) {
    if let Ok(mut shared) = shared.lock()
        && !shared.lifecycle().is_over()
    {
        shared.note(&match &lifecycle {
            SessionLifecycle::Closed(reason) | SessionLifecycle::Failed(reason) => reason.clone(),
            other => format!("{other:?}"),
        });
        shared.lifecycle = Some(lifecycle);
    }
}

async fn run_session(
    session_id: Uuid,
    config: &ConfigStore,
    account: WalletMetadata,
    pairing: PairingUri,
    limit_to: Option<Vec<String>>,
    shared: &Arc<Mutex<SessionShared>>,
    quit: &Arc<AtomicBool>,
) -> Result<()> {
    // Fixed, never a parameter. The relay sees which topics talk to which and
    // when; letting an untrusted caller name one would let it choose who
    // observes that, and the connection's authentication token travels in the
    // relay URL. The owner's `--relay-url` remains a CLI flag.
    let relay_url = url::Url::parse(DEFAULT_RELAY_URL).expect("the default relay URL is valid");
    let identity = ClientIdentity::generate()?;
    let relay = RelayConnection::connect(&relay_url, &identity).await?;

    let surface = HeadlessSurface {
        session_id,
        data_dir: config.data_dir().to_path_buf(),
        shared: Arc::clone(shared),
        quit: Arc::clone(quit),
        deadline: RefCell::new(None),
    };
    let handler = HeadlessDapp {
        session: DappSession::new(config, vec![account], 0, surface),
        limit_to,
    };
    Session::new(relay, pairing, &handler)
        .run(std::future::pending())
        .await
}

/// The MCP server's answer to everything a dapp session has to ask a person:
/// leave it where `ekubo-wallet review` will find it, and watch the row.
struct HeadlessSurface {
    session_id: Uuid,
    data_dir: PathBuf,
    shared: Arc<Mutex<SessionShared>>,
    quit: Arc<AtomicBool>,
    /// When the request being served now runs out of budget.
    ///
    /// A `RefCell` because only the session thread touches it; the tools read
    /// the published `expires_at` instead. Stamped by `notify` when a request
    /// arrives, which is before `handle_request` is called for it.
    deadline: RefCell<Option<tokio::time::Instant>>,
}

impl HeadlessSurface {
    fn with_shared(&self, act: impl FnOnce(&mut SessionShared)) {
        if let Ok(mut shared) = self.shared.lock() {
            act(&mut shared);
        }
    }

    /// Start the clock for a newly arrived request.
    fn start_request(&self) {
        *self.deadline.borrow_mut() = Some(tokio::time::Instant::now() + REQUEST_BUDGET);
    }

    /// When whatever is being served now runs out of budget. A full budget if
    /// nothing stamped one, which cannot happen for a request the session
    /// dispatched but is the safe reading if it ever did.
    fn deadline(&self) -> tokio::time::Instant {
        self.deadline
            .borrow()
            .unwrap_or_else(|| tokio::time::Instant::now() + REQUEST_BUDGET)
    }

    /// The same instant as a wall-clock time, for a caller to read.
    fn expires_at(&self) -> DateTime<Utc> {
        let left = self
            .deadline()
            .saturating_duration_since(tokio::time::Instant::now());
        Utc::now() + chrono::Duration::from_std(left).unwrap_or_else(|_| chrono::Duration::zero())
    }

    /// Publish that a request is waiting, and return when it stops being so.
    ///
    /// `read` re-reads the record; `settled` says whether a read record has
    /// been decided; `give_up` makes the decision terminal when this wait ends
    /// without one. The three-way split is what lets transactions, messages,
    /// and typed data share one loop against three stores that have nothing
    /// else in common.
    ///
    /// The deadline is real, and so is `give_up`: see the module comment for
    /// what leaving an approvable row behind would allow.
    async fn await_decision<R>(
        &self,
        awaiting: AwaitingRequest,
        read: impl Fn() -> Result<R>,
        settled: impl Fn(&R) -> bool,
        give_up: impl FnOnce() -> Result<R>,
    ) -> Result<R> {
        let request_id = awaiting.request_id;
        let deadline = self.deadline();
        self.with_shared(|shared| {
            shared.note(&format!(
                "{} {request_id} needs approval: tell the user to run `ekubo-wallet review \
                 {request_id}`.",
                awaiting.kind
            ));
            shared.awaiting.insert(request_id, awaiting);
        });

        let outcome = loop {
            let record = match read() {
                Ok(record) => record,
                // A read that fails ends this wait as surely as the deadline
                // does, and it must end it the same way. Answering the dapp
                // "could not be settled" while the row stays awaiting approval
                // is the exact state the deadline exists to prevent, reached
                // by a different route -- so `give_up` runs here too, and only
                // if it fails as well does the read's own error stand.
                Err(error) => break give_up().map_err(|_| error),
            };
            if settled(&record) {
                break Ok(record);
            }
            // A close ends the wait rather than outlasting it. Anything else
            // would make disconnecting take as long as an approval nobody is
            // going to give.
            if self.quit.load(Ordering::Relaxed) || tokio::time::Instant::now() >= deadline {
                break give_up();
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        };

        self.with_shared(|shared| {
            shared.awaiting.remove(&request_id);
            if outcome.is_err() {
                shared.note(&format!(
                    "{request_id} could not be settled and the dapp was told so."
                ));
            }
        });
        outcome
    }
}

#[async_trait::async_trait(?Send)]
impl DappSurface for HeadlessSurface {
    /// Hand the plan and its simulation to the agent and wait for a verdict.
    ///
    /// The point of this is parity, not a second policy. An agent that
    /// produces a plan itself calls `wallet_simulate_execution_plan`, reads
    /// `token_spends`, `balance_changes`, `will_authorize_delegation`, and
    /// `policy_outcome`, and then decides whether to send. A dapp's plan used
    /// to skip all of that: its calldata went to the policy, and if some rule
    /// matched, it signed. So the same struct is published here and the plan
    /// stops until somebody has read it.
    ///
    /// Fail-closed in every direction. Silence for the rest of the budget is a
    /// refusal, a session being closed is a refusal, and a verdict cannot
    /// widen anything — `Proceed` only means the plan now faces the policy it
    /// always faced.
    async fn approve_plan(
        &self,
        method: &str,
        plan: &ExecutionPlan,
        simulation: &SimulationResult,
        dapp: &crate::walletconnect::protocol::AppMetadata,
    ) -> Result<PlanVerdict> {
        let proposal_id = Uuid::new_v4();
        let mut simulation = simulation.clone();
        // A dapp's plan is never sendable by identifier: this simulation was
        // performed by the session for the session, and was never recorded in
        // the store `wallet_send_execution_plan` consumes. Cleared rather than
        // relied upon to be absent, so the agent is never handed something
        // that looks like a second, independent route to broadcasting this.
        simulation.simulation_id = None;
        let proposal = ProposedTransaction {
            session_id: self.session_id,
            proposal_id,
            method: terminal_safe_line(method),
            chain_id: plan.chain_id.as_str().to_owned(),
            dapp: DappSummary::of(dapp),
            execution_plan: plan.clone(),
            simulation,
            proposed_at: Utc::now(),
            expires_at: self.expires_at(),
            instruction: format!(
                "This dapp proposed a transaction. Read the simulation as you would your own: \
                 `token_spends` says what leaves this account, `balance_changes` what it looks \
                 like afterwards, and `will_authorize_delegation` whether the account's own code \
                 is being pointed somewhere new. Check it against what you asked the site to do, \
                 tell the user what it moves, then call wallet_walletconnect_decide with \
                 proposal_id {proposal_id}. Doing nothing refuses it."
            ),
        };
        self.with_shared(|shared| {
            shared.note(&format!(
                "{method} proposed; waiting for the agent to decide {proposal_id}."
            ));
            shared.proposed = Some(proposal);
            shared.decision = None;
        });

        let deadline = self.deadline();
        let verdict = loop {
            let decided = self
                .shared
                .lock()
                .ok()
                .and_then(|shared| shared.decision.clone())
                .filter(|decision| decision.proposal_id == proposal_id);
            if let Some(decision) = decided {
                break if decision.approve {
                    PlanVerdict::Proceed
                } else {
                    PlanVerdict::Refuse(decision.reason.map_or_else(
                        || "The agent declined this transaction.".to_owned(),
                        |reason| format!("The agent declined this transaction: {reason}"),
                    ))
                };
            }
            if self.quit.load(Ordering::Relaxed) {
                break PlanVerdict::Refuse(
                    "This session was disconnected before the transaction was reviewed.".to_owned(),
                );
            }
            if tokio::time::Instant::now() >= deadline {
                break PlanVerdict::Refuse(
                    "This transaction was not reviewed in time and was not sent.".to_owned(),
                );
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        };

        self.with_shared(|shared| {
            shared.proposed = None;
            shared.decision = None;
            shared.note(match &verdict {
                PlanVerdict::Proceed => "The agent approved it; putting it to the policy.",
                PlanVerdict::Refuse(reason) => reason,
            });
        });
        Ok(verdict)
    }

    fn closing(&self) -> bool {
        self.quit.load(Ordering::Relaxed)
    }

    fn log(&self, text: &str) {
        self.with_shared(|shared| shared.note(text));
    }

    async fn resolve_queued(
        &self,
        queued: PendingTransaction,
    ) -> Result<Option<PendingTransaction>> {
        let request_id = queued.request_id;
        let data_dir = self.data_dir.clone();
        let read = move || PendingStore::production(&data_dir)?.get(request_id);
        let data_dir = self.data_dir.clone();
        // `reject` moves the row only while it is still awaiting approval, so
        // an owner who approved in the same instant wins and their signature
        // is what this returns. There is no window in which both the dapp is
        // told no and the row stays approvable.
        let give_up = move || {
            let mut store = PendingStore::production(&data_dir)?;
            match store.reject(request_id) {
                Ok(rejected) => Ok(rejected),
                Err(_) => store.get(request_id),
            }
        };
        let record = self
            .await_decision(
                AwaitingRequest {
                    request_id,
                    kind: "transaction",
                    method: "eth_sendTransaction / wallet_sendCalls".to_owned(),
                    waiting_since: Utc::now(),
                    expires_at: self.expires_at(),
                },
                read,
                |record| record.status != PendingStatus::AwaitingApproval,
                give_up,
            )
            .await?;
        Ok(match record.status {
            PendingStatus::Signed => Some(record),
            // Anything else is a decision this session does not get to use:
            // rejected by the owner, rejected by the deadline, or already
            // carried somewhere else.
            _ => None,
        })
    }

    async fn resolve_message(
        &self,
        record: PendingMessage,
        _account: &WalletMetadata,
    ) -> Result<Option<PendingMessage>> {
        let request_id = record.request_id;
        let data_dir = self.data_dir.clone();
        let read = move || MessageStore::production(&data_dir)?.get(request_id);
        let data_dir = self.data_dir.clone();
        let give_up = move || {
            let mut store = MessageStore::production(&data_dir)?;
            match store.reject(request_id) {
                Ok(rejected) => Ok(rejected),
                Err(_) => store.get(request_id),
            }
        };
        let record = self
            .await_decision(
                AwaitingRequest {
                    request_id,
                    kind: "message",
                    method: "personal_sign".to_owned(),
                    waiting_since: Utc::now(),
                    expires_at: self.expires_at(),
                },
                read,
                |record| record.status != MessageStatus::AwaitingApproval,
                give_up,
            )
            .await?;
        Ok((record.status == MessageStatus::Signed).then_some(record))
    }

    async fn resolve_typed_data(
        &self,
        record: PendingTypedData,
        _account: &WalletMetadata,
    ) -> Result<Option<PendingTypedData>> {
        let request_id = record.request_id;
        let data_dir = self.data_dir.clone();
        let read = move || TypedDataStore::production(&data_dir)?.get(request_id);
        let data_dir = self.data_dir.clone();
        let give_up = move || {
            let mut store = TypedDataStore::production(&data_dir)?;
            match store.reject(request_id) {
                Ok(rejected) => Ok(rejected),
                Err(_) => store.get(request_id),
            }
        };
        let record = self
            .await_decision(
                AwaitingRequest {
                    request_id,
                    kind: "typed_data",
                    method: "eth_signTypedData_v4".to_owned(),
                    waiting_since: Utc::now(),
                    expires_at: self.expires_at(),
                },
                read,
                |record| record.status != TypedDataStatus::AwaitingApproval,
                give_up,
            )
            .await?;
        Ok((record.status == TypedDataStatus::Signed).then_some(record))
    }
}

/// One dapp session with nobody at a terminal.
struct HeadlessDapp<'a> {
    session: DappSession<'a, HeadlessSurface>,
    /// CAIP-2 chains the caller confined this session to, if it named any.
    limit_to: Option<Vec<String>>,
}

#[async_trait::async_trait(?Send)]
impl SessionHandler for HeadlessDapp<'_> {
    /// Approve the proposal without asking anybody.
    ///
    /// This is the whole of what the tool trades away, and it is deliberately
    /// the *only* thing traded away: the scope is still built by
    /// [`DappSession::negotiate`] from what this wallet can serve, still bound
    /// to the one account named when the session was opened, and still
    /// narrowed by `chain_ids` if the caller gave one. A refusal
    /// `negotiate` returns is still a refusal.
    async fn review_proposal(&self, proposal: &ProposalSummary) -> Result<ProposalDecision> {
        let summary = DappSummary::of(&proposal.metadata);
        let (chains, methods) = match self.session.negotiate(proposal, self.limit_to.as_deref()) {
            Ok(negotiated) => negotiated,
            Err(refusal) => {
                if let ProposalDecision::Reject { message, .. } = &refusal {
                    let message = message.clone();
                    self.session
                        .surface()
                        .with_shared(|shared| shared.note(&format!("Proposal refused: {message}")));
                }
                return Ok(refusal);
            }
        };
        // Published before the session settles, so a `wallet_walletconnect_*`
        // report can never show a connected session whose dapp is unknown.
        self.session.surface().with_shared(|shared| {
            shared.dapp = Some(summary);
        });
        Ok(ProposalDecision::Approve(
            DappSession::<HeadlessSurface>::scope_for(self.session.wallet(), chains, methods),
        ))
    }

    async fn handle_request(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        Ok(self.session.answer(request).await)
    }

    async fn quit_requested(&self) {
        // Polled for the same reason the terminal surface polls: this future
        // is dropped and rebuilt on every turn of the session loop, so a
        // receiver would have to survive being dropped mid-wait.
        loop {
            if self.session.surface().closing() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn notify(&self, event: &SessionEvent<'_>) {
        let surface = self.session.surface();
        match event {
            SessionEvent::Pairing => surface.with_shared(|shared| {
                shared.note("Paired. Waiting for the dapp's connection proposal.");
            }),
            SessionEvent::ProposalReceived => surface.with_shared(|shared| {
                shared.note("A connection proposal arrived.");
            }),
            SessionEvent::Settled { scope, metadata } => {
                let summary = DappSummary::of(metadata);
                surface.with_shared(|shared| {
                    shared.note(&format!(
                        "Connected to {}.",
                        summary.host.as_deref().unwrap_or("an unnamed site")
                    ));
                    shared.dapp = Some(summary);
                    shared.address = Some(scope.address.clone());
                    shared.chains.clone_from(&scope.chains);
                    shared.methods.clone_from(&scope.methods);
                    shared.lifecycle = Some(SessionLifecycle::Connected);
                });
            }
            SessionEvent::RequestReceived {
                method,
                caip2_chain_id,
            } => {
                // Before `handle_request` runs for it, so both of the waits it
                // may need are spending one budget rather than a fresh one
                // each. See `REQUEST_BUDGET`.
                surface.start_request();
                surface.with_shared(|shared| {
                    shared.note(&format!("{method} on {caip2_chain_id}"));
                });
            }
            SessionEvent::RequestAnswered { method, outcome } => surface.with_shared(|shared| {
                shared.note(&match outcome {
                    RequestOutcome::Result(_) => format!("{method} — answered."),
                    RequestOutcome::Error { message, .. } => {
                        format!("{method} — refused: {message}")
                    }
                });
            }),
            SessionEvent::RequestRefused { method, reason } => surface.with_shared(|shared| {
                shared.note(&format!(
                    "{method} — outside this session's scope: {reason}"
                ));
            }),
            SessionEvent::Ping => {}
            SessionEvent::DappDisconnected { code, message } => surface.with_shared(|shared| {
                let reason = format!("The dapp closed the session ({code}): {message}");
                shared.note(&reason);
                shared.lifecycle = Some(SessionLifecycle::Closed(terminal_safe_line(&reason)));
            }),
            SessionEvent::RelayReconnected => surface.with_shared(|shared| {
                shared.note("Reconnected to the relay.");
            }),
        }
    }
}

#[cfg(test)]
#[path = "mcp_walletconnect_test.rs"]
mod tests;
