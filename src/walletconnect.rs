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
#[cfg(target_os = "macos")]
use std::{
    fs,
    io::{Cursor, Read, Seek},
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Stdio},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use walletconnect_session::{ApprovedScope, PairingUri};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_WALLETCONNECT_SESSIONS: usize = 16;
const MAX_QR_CHOICES: usize = 8;
#[cfg(target_os = "macos")]
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

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

/// The native owner-mediated screen/window picker.
pub struct SystemScreenPicker;

impl SystemScreenPicker {
    #[must_use]
    pub const fn supported() -> bool {
        cfg!(target_os = "macos")
    }
}

impl ScreenPicker for SystemScreenPicker {
    #[cfg(target_os = "macos")]
    fn capture_once(&self) -> Result<Option<CapturedFrame>> {
        capture_macos_screen_with(run_macos_screen_picker)
    }

    #[cfg(not(target_os = "macos"))]
    fn capture_once(&self) -> Result<Option<CapturedFrame>> {
        anyhow::bail!("screen scanning is not available on this platform")
    }
}

#[cfg(target_os = "macos")]
fn run_macos_screen_picker(target: &Path) -> Result<bool> {
    let output = Command::new("/usr/sbin/screencapture")
        // `-U` presents the familiar interactive toolbar instead of leaving
        // users to discover an invisible crosshair mode. `-d` lets macOS show
        // capture-permission failures as well as returning them below.
        .args(["-i", "-U", "-d", "-x", "-t", "png"])
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("could not open the macOS screen picker")?;
    if output.status.success() {
        return Ok(true);
    }

    let message = String::from_utf8_lossy(&output.stderr);
    let message = message.trim();
    if message.is_empty() {
        // Escape/cancel exits without an image or diagnostic.
        return Ok(false);
    }
    anyhow::bail!(
        "macOS screen picker failed: {}",
        ekubo_wallet_core::sanitize::stripped_capped(message, 512)
    )
}

#[cfg(target_os = "macos")]
fn capture_macos_screen_with(
    launch: impl FnOnce(&Path) -> Result<bool>,
) -> Result<Option<CapturedFrame>> {
    // `screencapture` delegates through macOS services, so a `/dev/fd` path
    // names the wrong process's descriptor and can yield no image. Give it a
    // real randomized path inside a mode-0700 directory instead. The image is
    // mode 0600, read immediately, and removed with the directory on return.
    let directory = tempfile::Builder::new()
        .prefix("ekubo-wallet-qr-")
        .tempdir()
        .context("could not allocate private screen-capture directory")?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .context("could not protect the screen-capture directory")?;
    let capture_guard = tempfile::Builder::new()
        .prefix("capture-")
        .suffix(".png")
        .tempfile_in(directory.path())
        .context("could not allocate ephemeral screen capture")?;
    capture_guard
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("could not protect the screen-capture file")?;
    let capture_path = capture_guard.path().to_owned();
    if !launch(&capture_path)? {
        return Ok(None);
    }

    // Reopen by name because ScreenCaptureKit may replace the directory entry
    // instead of writing through the inode we created. NOFOLLOW makes the
    // regular-file check atomic with opening, even against another same-user
    // process that discovers the private temporary directory.
    let capture_fd = rustix::fs::open(
        &capture_path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .context("could not securely open the selected screen capture")?;
    rustix::fs::fchmod(&capture_fd, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
        .context("could not protect the completed screen capture")?;
    let mut captured_file = fs::File::from(capture_fd);
    let capture_metadata = captured_file
        .metadata()
        .context("could not inspect selected screen capture")?;
    ensure!(
        capture_metadata.file_type().is_file(),
        "the screen picker returned an invalid file"
    );
    let capture_size = capture_metadata.len();
    ensure!(capture_size > 0, "the screen picker returned no image");
    ensure!(
        capture_size <= u64::try_from(MAX_CAPTURE_BYTES)?,
        "selected screen capture is too large"
    );
    captured_file
        .rewind()
        .context("could not rewind screen capture")?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(usize::try_from(capture_size)?));
    captured_file
        .take(u64::try_from(MAX_CAPTURE_BYTES + 1)?)
        .read_to_end(&mut encoded)
        .context("could not read selected screen capture")?;
    ensure!(
        encoded.len() <= MAX_CAPTURE_BYTES,
        "selected screen capture is too large"
    );
    decode_png_capture(&encoded).map(Some)
}

#[cfg(target_os = "macos")]
fn decode_png_capture(encoded: &[u8]) -> Result<CapturedFrame> {
    let mut reader = image::ImageReader::with_format(Cursor::new(encoded), image::ImageFormat::Png);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .context("could not decode the selected screen capture")?
        .into_rgba8();
    Ok(CapturedFrame {
        width: image.width(),
        height: image.height(),
        rgba: image.into_raw(),
    })
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct QrPreview {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct QrChoice {
    uri: String,
    preview: QrPreview,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct QrChoices(Vec<QrChoice>);

impl QrChoices {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn take_previews(&mut self) -> Vec<QrPreview> {
        self.0
            .iter_mut()
            .map(|choice| {
                std::mem::replace(
                    &mut choice.preview,
                    QrPreview {
                        width: 0,
                        height: 0,
                        rgba: Vec::new(),
                    },
                )
            })
            .collect()
    }

    pub fn take(mut self, index: usize) -> Result<Zeroizing<String>> {
        ensure!(index < self.0.len(), "QR choice is out of range");
        let mut selected = self.0.swap_remove(index);
        Ok(Zeroizing::new(std::mem::take(&mut selected.uri)))
    }
}

fn qr_preview(frame: &CapturedFrame, bounds: &[rqrr::Point; 4]) -> Result<QrPreview> {
    let min_x = bounds.iter().map(|point| point.x).min().unwrap_or(0);
    let max_x = bounds.iter().map(|point| point.x).max().unwrap_or(0);
    let min_y = bounds.iter().map(|point| point.y).min().unwrap_or(0);
    let max_y = bounds.iter().map(|point| point.y).max().unwrap_or(0);
    ensure!(max_x >= min_x && max_y >= min_y, "QR bounds are invalid");
    let code_width = u32::try_from(max_x - min_x + 1)?;
    let code_height = u32::try_from(max_y - min_y + 1)?;
    let margin = (code_width.max(code_height) / 12).max(4);
    let left = u32::try_from(min_x.max(0))?.saturating_sub(margin);
    let top = u32::try_from(min_y.max(0))?.saturating_sub(margin);
    let right = u32::try_from(max_x.max(0))?
        .saturating_add(1)
        .saturating_add(margin)
        .min(frame.width);
    let bottom = u32::try_from(max_y.max(0))?
        .saturating_add(1)
        .saturating_add(margin)
        .min(frame.height);
    ensure!(
        right > left && bottom > top,
        "QR bounds are outside the capture"
    );
    let width = right - left;
    let height = bottom - top;
    let capacity = usize::try_from(width)?
        .checked_mul(usize::try_from(height)?)
        .and_then(|pixels| pixels.checked_mul(4))
        .context("QR preview dimensions overflow")?;
    let mut rgba = Vec::with_capacity(capacity);
    let stride = usize::try_from(frame.width)?
        .checked_mul(4)
        .context("captured frame stride overflow")?;
    let left_byte = usize::try_from(left)?
        .checked_mul(4)
        .context("QR preview offset overflow")?;
    let row_bytes = usize::try_from(width)?
        .checked_mul(4)
        .context("QR preview row width overflow")?;
    for y in top..bottom {
        let start = usize::try_from(y)?
            .checked_mul(stride)
            .and_then(|offset| offset.checked_add(left_byte))
            .context("QR preview offset overflow")?;
        let end = start
            .checked_add(row_bytes)
            .context("QR preview offset overflow")?;
        rgba.extend_from_slice(&frame.rgba[start..end]);
    }
    Ok(QrPreview {
        width,
        height,
        rgba,
    })
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
    let mut seen = std::collections::BTreeSet::new();
    for grid in prepared.detect_grids() {
        if let Ok((_metadata, content)) = grid.decode()
            && PairingUri::parse(&content, Utc::now()).is_ok()
            && seen.insert(content.clone())
            && choices.len() < MAX_QR_CHOICES
        {
            choices.push(QrChoice {
                uri: content,
                preview: qr_preview(&frame, &grid.bounds)?,
            });
        }
    }
    Ok(Some(QrChoices(choices)))
}

#[cfg(test)]
#[path = "walletconnect_test.rs"]
mod tests;
