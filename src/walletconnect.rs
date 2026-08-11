//! In-memory multi-session `WalletConnect` coordination and ephemeral QR input.

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use image::{GrayImage, Luma};
use std::collections::BTreeMap;
use uuid::Uuid;
use walletconnect_session::PairingUri;
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
}

#[derive(Default)]
pub struct WalletConnectManager {
    sessions: BTreeMap<Uuid, SessionSummary>,
}

impl WalletConnectManager {
    pub fn add_uri(&mut self, uri: &str) -> Result<SessionSummary> {
        ensure!(
            self.sessions.len() < MAX_WALLETCONNECT_SESSIONS,
            "too many concurrent WalletConnect sessions"
        );
        let pairing = PairingUri::parse(uri, Utc::now())?;
        let summary = SessionSummary {
            id: Uuid::new_v4(),
            pairing_topic: pairing.topic,
            status: SessionStatus::Pairing,
            active_requests: 0,
        };
        self.sessions.insert(summary.id, summary.clone());
        Ok(summary)
    }

    #[must_use]
    pub fn sessions(&self) -> Vec<SessionSummary> {
        self.sessions.values().cloned().collect()
    }

    pub fn disconnect(&mut self, id: Uuid) -> Result<SessionSummary> {
        self.sessions
            .remove(&id)
            .context("unknown WalletConnect session")
    }

    pub fn disconnect_all(&mut self) {
        self.sessions.clear();
    }
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
