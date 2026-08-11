//! In-memory multi-session `WalletConnect` coordination and ephemeral QR input.

use crate::{authority::OwnerApi, events::EventBus};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use ekubo_wallet_core::{approval::ReviewDocument, config::WalletMetadata};
use image::{GrayImage, Luma};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use walletconnect_session::{ApprovedScope, PairingUri};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_WALLETCONNECT_SESSIONS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Pairing,
    AwaitingProposal,
    Connected,
    Disconnecting,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: Uuid,
    pub pairing_topic: String,
    pub status: SessionStatus,
    pub active_requests: usize,
    pub dapp_name: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Default)]
pub struct WalletConnectManager {
    sessions: BTreeMap<Uuid, ManagedSession>,
}

struct ManagedSession {
    summary: SessionSummary,
    shutdown: CancellationToken,
}

pub struct SessionStart {
    pub id: Uuid,
    pub pairing: PairingUri,
    pub shutdown: CancellationToken,
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
        let summary = SessionSummary {
            id,
            pairing_topic: pairing.topic.clone(),
            status: SessionStatus::Pairing,
            active_requests: 0,
            dapp_name: None,
            last_error: None,
        };
        self.sessions.insert(
            id,
            ManagedSession {
                summary: summary.clone(),
                shutdown: shutdown.clone(),
            },
        );
        Ok((
            SessionStart {
                id,
                pairing,
                shutdown,
            },
            summary,
        ))
    }

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

    pub fn disconnect_all(&mut self) {
        for session in self.sessions.values() {
            session.shutdown.cancel();
        }
        self.sessions.clear();
    }

    pub fn update(
        &mut self,
        id: Uuid,
        status: SessionStatus,
        dapp_name: Option<String>,
        active_requests: usize,
    ) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.summary.status = status;
            if dapp_name.is_some() {
                session.summary.dapp_name = dapp_name;
            }
            session.summary.active_requests = active_requests;
        }
    }

    pub fn fail(&mut self, id: Uuid, error: String) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.summary.last_error = Some(error);
            session.summary.status = SessionStatus::Disconnecting;
        }
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
    pub choices: Vec<ProposalChoice>,
    pub response: oneshot::Sender<ProposalCommand>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalCommand {
    Approve(usize),
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
                choices,
                response,
            })
            .map_err(|_| anyhow::anyhow!("the WalletConnect review UI is unavailable"))?;
        decision
            .await
            .context("the WalletConnect review window closed")
    }
}

pub async fn run_session(
    start: SessionStart,
    owner: OwnerApi,
    presenter: ProposalPresenter,
    manager: Arc<Mutex<WalletConnectManager>>,
    events: EventBus,
) -> Result<()> {
    crate::walletconnect_handler::run(start, owner, presenter, manager, events).await
}

pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

impl Drop for CapturedFrame {
    fn drop(&mut self) {
        self.rgba.zeroize();
    }
}

pub trait ScreenPicker {
    /// Return one ephemeral frame from the owner-selected screen or window.
    fn capture_once(&self) -> Result<Option<CapturedFrame>>;
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct QrChoices(Vec<String>);

impl QrChoices {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn take(mut self, index: usize) -> Result<String> {
        ensure!(index < self.0.len(), "QR choice is out of range");
        let selected = self.0.swap_remove(index);
        Ok(selected)
    }
}

pub fn scan_screen(picker: &dyn ScreenPicker) -> Result<Option<QrChoices>> {
    let Some(frame) = picker.capture_once()? else {
        return Ok(None);
    };
    let expected = usize::try_from(frame.width)?
        .checked_mul(usize::try_from(frame.height)?)
        .and_then(|pixels| pixels.checked_mul(4))
        .context("captured frame dimensions overflow")?;
    ensure!(
        frame.rgba.len() == expected,
        "captured frame has invalid dimensions"
    );
    let mut gray = GrayImage::new(frame.width, frame.height);
    for (pixel, rgba) in gray.pixels_mut().zip(frame.rgba.chunks_exact(4)) {
        let luminance =
            ((u16::from(rgba[0]) * 77 + u16::from(rgba[1]) * 150 + u16::from(rgba[2]) * 29) >> 8)
                as u8;
        *pixel = Luma([luminance]);
    }
    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let mut choices = Vec::new();
    for grid in prepared.detect_grids() {
        if let Ok((_metadata, content)) = grid.decode()
            && PairingUri::parse(&content, Utc::now()).is_ok()
        {
            choices.push(content);
        }
    }
    Ok(Some(QrChoices(choices)))
}

#[cfg(test)]
#[path = "walletconnect_test.rs"]
mod tests;
