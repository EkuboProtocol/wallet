//! In-memory multi-session `WalletConnect` coordination.

use crate::{authority::DappApi, events::EventBus};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use ekubo_wallet_core::{
    approval::ReviewDocument, config::WalletMetadata, human_presence::DappAuthorization,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use walletconnect_session::{ApprovedScope, PairingUri};

pub const MAX_WALLETCONNECT_SESSIONS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Pairing,
    AwaitingProposal,
    Connected,
    /// The relay connection dropped and the session is dialing again.
    ///
    /// A distinct state rather than a silent one, because the session is still
    /// the owner's and the dapp still believes in it — what has gone away is
    /// the socket in between, and a row that went on saying "Connected"
    /// through an outage would be the wallet asserting something it cannot
    /// currently do.
    Reconnecting,
    Disconnecting,
}

impl SessionStatus {
    /// Owner-facing wording for the state of one dapp connection.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pairing => "Connecting",
            Self::AwaitingProposal => "Waiting for the dapp",
            Self::Connected => "Connected",
            Self::Reconnecting => "Reconnecting",
            Self::Disconnecting => "Disconnecting",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: Uuid,
    pub status: SessionStatus,
    pub active_requests: usize,
    pub dapp_name: Option<String>,
    pub last_error: Option<String>,
    /// The controller-selected settlement deadline. Peers cannot extend it.
    pub expires_at: Option<i64>,
    /// Whether the owner has approved this dapp and the session settled.
    ///
    /// Everything before that point is a pairing with a stranger: the relay
    /// carries nothing but a proposal, and the only thing the wallet knows
    /// about the peer is whatever the proposal will claim. A connection list
    /// that draws those rows invites the reader to treat "it is in the list"
    /// as "I let it in". The review window is where a dapp is met; the list is
    /// what came out of that decision.
    pub settled: bool,
}

#[derive(Default)]
pub struct WalletConnectManager {
    sessions: BTreeMap<Uuid, ManagedSession>,
}

struct ManagedSession {
    summary: SessionSummary,
    shutdown: CancellationToken,
    farewell: CancellationToken,
}

pub struct SessionStart {
    pub id: Uuid,
    pub pairing: PairingUri,
    pub shutdown: CancellationToken,
    /// Cancelled by the session task on its way out, whatever ended it.
    ///
    /// The wallet tells a dapp the session is over by publishing
    /// `wc_sessionDelete`, and a dapp that never receives one goes on showing
    /// a live session — its client reconnects to the relay by itself and is
    /// told nothing. On the way out of the application that publish is a race
    /// against the process exiting, which it lost: the token was cancelled and
    /// the runtime was gone a moment later. This is what the shutdown waits
    /// on, so the goodbye reaches the relay before the wallet stops existing.
    ///
    /// It only has to reach the *relay*. A `wc_sessionDelete` is retained and
    /// delivered to a dapp that is not currently connected, so the dapp being
    /// closed at the time costs nothing.
    pub farewell: CancellationToken,
}

impl WalletConnectManager {
    pub fn begin_uri(&mut self, uri: &str) -> Result<(SessionStart, SessionSummary)> {
        ensure!(
            self.sessions.len() < MAX_WALLETCONNECT_SESSIONS,
            "too many concurrent WalletConnect sessions"
        );
        let pairing = PairingUri::parse(uri, Utc::now())?;
        let id = Uuid::new_v4();
        let shutdown = CancellationToken::new();
        let farewell = CancellationToken::new();
        let summary = SessionSummary {
            id,
            status: SessionStatus::Pairing,
            active_requests: 0,
            dapp_name: None,
            last_error: None,
            expires_at: None,
            settled: false,
        };
        self.sessions.insert(
            id,
            ManagedSession {
                summary: summary.clone(),
                shutdown: shutdown.clone(),
                farewell: farewell.clone(),
            },
        );
        Ok((
            SessionStart {
                id,
                pairing,
                shutdown,
                farewell,
            },
            summary,
        ))
    }

    /// Every session, settled or not.
    ///
    /// A caller drawing the connection list keeps only the settled ones. The
    /// unsettled rows are still returned because something has to know a
    /// pairing is in flight: the concurrency cap, and the connect button
    /// waiting to learn what became of the pairing it started.
    #[must_use]
    pub fn sessions(&self) -> Vec<SessionSummary> {
        self.sessions
            .values()
            .map(|session| session.summary.clone())
            .collect()
    }

    pub fn disconnect(&mut self, id: Uuid) -> Result<SessionSummary> {
        let session = self
            .sessions
            .remove(&id)
            .context("unknown WalletConnect session")?;
        session.shutdown.cancel();
        Ok(session.summary)
    }

    /// Ask every session to end, and hand back what to wait on.
    ///
    /// Each returned token is cancelled once that session's task has finished
    /// saying goodbye to its dapp. The caller is the application shutdown,
    /// which waits on them briefly: cancelling the sessions and exiting
    /// immediately is what left dapps showing a connection to a wallet that
    /// was no longer running.
    #[must_use]
    pub fn disconnect_all(&mut self) -> Vec<CancellationToken> {
        let mut farewells = Vec::with_capacity(self.sessions.len());
        for session in self.sessions.values() {
            session.shutdown.cancel();
            // An unsettled pairing has no dapp to tell and no session to
            // delete, so waiting on one would only spend the shutdown's
            // budget on a task with nothing to publish.
            if session.summary.settled {
                farewells.push(session.farewell.clone());
            }
        }
        self.sessions.clear();
        farewells
    }

    pub fn update(
        &mut self,
        id: Uuid,
        status: SessionStatus,
        dapp_name: Option<String>,
        active_requests: usize,
        expires_at: Option<i64>,
    ) {
        if let Some(session) = self.sessions.get_mut(&id) {
            // `Connected` is only ever reported for a session the owner
            // approved and the protocol then settled, so it is what promotes a
            // pairing into the connection list. Nothing demotes it: a settled
            // dapp that later fails or disconnects stays visible, because by
            // then the owner has something to act on.
            session.summary.settled |= status == SessionStatus::Connected;
            session.summary.status = status;
            if dapp_name.is_some() {
                session.summary.dapp_name = dapp_name;
            }
            session.summary.active_requests = active_requests;
            if expires_at.is_some() {
                session.summary.expires_at = expires_at;
            }
        }
    }

    /// Record that a session ended badly.
    ///
    /// A settled session keeps its row so the owner can read the error beside
    /// the dapp it belongs to. One that failed before it ever settled has no
    /// row to keep — it was never in the list — so it is dropped rather than
    /// left holding a slot against [`MAX_WALLETCONNECT_SESSIONS`] that nothing
    /// on screen could ever free. The caller reports that failure beside the
    /// connect button, which is where the owner was waiting for it.
    pub fn fail(&mut self, id: Uuid, error: String) {
        let Some(session) = self.sessions.get_mut(&id) else {
            return;
        };
        if !session.summary.settled {
            self.sessions.remove(&id);
            return;
        }
        session.summary.last_error = Some(error);
        session.summary.status = SessionStatus::Disconnecting;
    }

    pub fn finish(&mut self, id: Uuid) {
        self.sessions.remove(&id);
    }
}

pub struct ProposalChoice {
    pub account: WalletMetadata,
    pub scope: ApprovedScope,
    pub document: ReviewDocument,
}

pub struct ProposalPrompt {
    pub session_id: Uuid,
    /// The same review with the account left blank, for the state the window
    /// opens in. Drawing one of the `choices` instead would name an account the
    /// owner has not chosen, on the screen whose entire question is which
    /// account to expose.
    pub unselected_document: ReviewDocument,
    pub choices: Vec<ProposalChoice>,
    pub response: oneshot::Sender<ProposalCommand>,
}

pub enum ProposalCommand {
    Approve {
        index: usize,
        authorization: DappAuthorization,
    },
    Reject,
    Close,
}

#[derive(Clone)]
pub struct ProposalPresenter {
    sender: mpsc::UnboundedSender<ProposalPrompt>,
}

impl ProposalPresenter {
    #[must_use]
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<ProposalPrompt>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }

    pub async fn review(
        &self,
        session_id: Uuid,
        unselected_document: ReviewDocument,
        choices: Vec<ProposalChoice>,
    ) -> Result<ProposalCommand> {
        ensure!(
            !choices.is_empty(),
            "connection review has no account choices"
        );
        let (response, decision) = oneshot::channel();
        self.sender
            .send(ProposalPrompt {
                session_id,
                unselected_document,
                choices,
                response,
            })
            .map_err(|_| anyhow::anyhow!("the WalletConnect review UI is unavailable"))?;
        decision
            .await
            .context("the WalletConnect review window closed")
    }
}

pub(crate) async fn run_session(
    start: SessionStart,
    dapp: DappApi,
    presenter: ProposalPresenter,
    manager: Arc<Mutex<WalletConnectManager>>,
    events: EventBus,
) -> Result<()> {
    crate::walletconnect_handler::run(start, dapp, presenter, manager, events).await
}

#[cfg(test)]
#[path = "walletconnect_test.rs"]
mod tests;
