use crate::desktop::Route;
use anyhow::{Context, Result};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

const OPEN_ID: &str = "ekubo.open";
const REVIEWS_ID: &str = "ekubo.reviews";
const CONNECT_ID: &str = "ekubo.connect";
const AGENTS_ID: &str = "ekubo.agents";
const SETTINGS_ID: &str = "ekubo.settings";
const QUIT_ID: &str = "ekubo.quit";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrayCommand {
    OpenWallet,
    OpenRoute(Route),
    Quit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraySnapshot {
    pub pending_reviews: usize,
    pub mcp_online: bool,
    pub connected_agents: usize,
    pub walletconnect_sessions: usize,
}

pub trait TrayService {
    fn available(&self) -> bool;
    fn update(&mut self, snapshot: &TraySnapshot);
    fn drain_commands(&mut self) -> Vec<TrayCommand>;
}

/// Native status-item adapter. `tray-icon` confines the platform FFI to its
/// Apache-2.0/MIT implementation: `NSStatusItem` on macOS, `Shell_NotifyIcon` on
/// Windows, and AppIndicator/StatusNotifierItem on Linux.
pub struct PlatformTray {
    tray: TrayIcon,
    reviews: MenuItem,
    agents: MenuItem,
    snapshot: TraySnapshot,
    #[cfg(not(target_os = "macos"))]
    dark_mode: bool,
}

impl PlatformTray {
    /// Two commands that did the same thing used to sit in this menu: the
    /// agent-status line and `Settings…` both opened Settings, so one of them
    /// was a label pretending to be a command. The status line is now inert
    /// and says what it knows; `Settings` is the only way in.
    ///
    /// Nothing here ends in an ellipsis either. The convention reserves one for
    /// a command that stops to ask for more input, and every one of these just
    /// brings a window forward.
    ///
    /// `Check for updates` is gone for the same reason the status line stopped
    /// being a command: it opened Settings, which is where `Settings` goes, and
    /// arriving there already runs the check. Two items landing on one screen
    /// read as though they differ.
    pub fn new(dark_mode: bool) -> Result<Self> {
        let menu = Menu::new();
        let open = MenuItem::with_id(OPEN_ID, "Open Ekubo Wallet", true, None);
        let reviews = MenuItem::with_id(REVIEWS_ID, review_menu_text(0), false, None);
        let agents = MenuItem::with_id(AGENTS_ID, "Starting the agent gateway", false, None);
        let connect = MenuItem::with_id(CONNECT_ID, "Connect a dapp", true, None);
        let settings = MenuItem::with_id(SETTINGS_ID, "Settings", true, None);
        let quit = MenuItem::with_id(QUIT_ID, "Quit Ekubo Wallet", true, None);
        let separator_one = PredefinedMenuItem::separator();
        let separator_two = PredefinedMenuItem::separator();
        menu.append_items(&[
            &open,
            &reviews,
            &separator_one,
            &agents,
            &connect,
            &settings,
            &separator_two,
            &quit,
        ])
        .context("failed to construct the tray menu")?;

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(true)
            .with_tooltip("Ekubo Wallet")
            .with_icon(wallet_icon(dark_mode)?)
            // AppKit owns the status-item foreground color. The icon remains
            // one stable template for its entire lifetime so AppKit can react
            // to the actual menu-bar backdrop (which is independent of the
            // application's light/dark preference).
            .with_icon_as_template(cfg!(target_os = "macos"))
            .build()
            .context("the desktop has no usable tray host")?;

        Ok(Self {
            tray,
            reviews,
            agents,
            snapshot: TraySnapshot {
                pending_reviews: 0,
                mcp_online: false,
                connected_agents: 0,
                walletconnect_sessions: 0,
            },
            #[cfg(not(target_os = "macos"))]
            dark_mode,
        })
    }

    pub fn set_dark_mode(&mut self, dark_mode: bool) {
        #[cfg(target_os = "macos")]
        {
            // Replacing a tray-icon image can drop AppKit's template-image
            // state and leave the raw dark pixels visible on a dark menu bar.
            // The template already adapts itself, so theme updates are a no-op.
            let _ = dark_mode;
        }
        #[cfg(not(target_os = "macos"))]
        {
            if self.dark_mode == dark_mode {
                return;
            }
            if let Ok(icon) = wallet_icon(dark_mode)
                && self.tray.set_icon(Some(icon)).is_ok()
            {
                self.dark_mode = dark_mode;
            }
        }
    }

    /// Update only MCP connectivity without discarding newer review, agent,
    /// or dapp counts held by the shared tray snapshot.
    pub fn set_mcp_online(&mut self, online: bool) {
        let mut snapshot = self.snapshot.clone();
        snapshot.mcp_online = online;
        self.update(&snapshot);
    }

    /// Block until the native tray backend emits a command. Desktop startup
    /// calls this from one dedicated thread so GPUI never needs a polling
    /// timer on its foreground executor.
    #[must_use]
    pub fn recv_command() -> Option<TrayCommand> {
        MenuEvent::receiver()
            .recv()
            .ok()
            .and_then(|event| command_for_id(event.id.as_ref()))
    }
}

impl TrayService for PlatformTray {
    fn available(&self) -> bool {
        true
    }

    fn update(&mut self, snapshot: &TraySnapshot) {
        self.snapshot = snapshot.clone();
        set_application_badge_count(snapshot.pending_reviews);
        self.reviews.set_enabled(snapshot.pending_reviews > 0);
        self.reviews
            .set_text(review_menu_text(snapshot.pending_reviews));
        self.agents.set_text(agent_menu_text(snapshot));
        let _ = self.tray.set_tooltip(Some(tray_tooltip(snapshot)));
    }

    fn drain_commands(&mut self) -> Vec<TrayCommand> {
        MenuEvent::receiver()
            .try_iter()
            .filter_map(|event| command_for_id(event.id.as_ref()))
            .collect()
    }
}

#[cfg(any(test, target_os = "macos"))]
fn application_badge_label(count: usize) -> Option<String> {
    (count > 0).then(|| count.to_string())
}

#[cfg(target_os = "macos")]
fn set_application_badge_count(count: usize) {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSApplication;
    use objc2_foundation::NSString;

    let Some(main_thread) = MainThreadMarker::new() else {
        tracing::warn!("ignored a macOS Dock badge update away from the main thread");
        return;
    };
    let label = application_badge_label(count).map(|label| NSString::from_str(&label));
    NSApplication::sharedApplication(main_thread)
        .dockTile()
        .setBadgeLabel(label.as_deref());
}

#[cfg(not(target_os = "macos"))]
fn set_application_badge_count(_count: usize) {}

/// "3 requests waiting for you", and the flat truth when there are none. The
/// item is disabled at zero, so it reads as a status line rather than an
/// action that would do nothing.
fn review_menu_text(pending_reviews: usize) -> String {
    match pending_reviews {
        0 => "Nothing waiting for you".to_owned(),
        1 => "1 request waiting for you".to_owned(),
        count => format!("{count} requests waiting for you"),
    }
}

fn count_phrase(count: usize, singular: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {singular}s")
    }
}

/// What can reach the wallet right now, in one line. The old wording —
/// `MCP online · 2 agent(s) · 1 dapp(s)` — named the protocol rather than the
/// capability and used a suffix nobody says out loud.
fn agent_menu_text(snapshot: &TraySnapshot) -> String {
    if !snapshot.mcp_online {
        return "Agents cannot connect right now".to_owned();
    }
    match (snapshot.connected_agents, snapshot.walletconnect_sessions) {
        (0, 0) => "Ready for agents · nothing connected".to_owned(),
        (agents, 0) => format!(
            "Ready for agents · {} connected",
            count_phrase(agents, "agent")
        ),
        (0, dapps) => format!(
            "Ready for agents · {} connected",
            count_phrase(dapps, "dapp")
        ),
        (agents, dapps) => format!(
            "Ready for agents · {} and {} connected",
            count_phrase(agents, "agent"),
            count_phrase(dapps, "dapp")
        ),
    }
}

/// The hover text has room for one fact, so it carries the only one that is
/// ever urgent.
fn tray_tooltip(snapshot: &TraySnapshot) -> String {
    if snapshot.pending_reviews == 0 {
        "Ekubo Wallet".to_owned()
    } else {
        format!(
            "Ekubo Wallet — {}",
            review_menu_text(snapshot.pending_reviews)
        )
    }
}

fn command_for_id(id: &str) -> Option<TrayCommand> {
    match id {
        OPEN_ID => Some(TrayCommand::OpenWallet),
        REVIEWS_ID => Some(TrayCommand::OpenRoute(Route::Activity)),
        CONNECT_ID => Some(TrayCommand::OpenRoute(Route::WalletConnect)),
        SETTINGS_ID => Some(TrayCommand::OpenRoute(Route::Settings)),
        QUIT_ID => Some(TrayCommand::Quit),
        // `AGENTS_ID` lands here with everything unrecognized: the
        // agent-status line reports, it does not act.
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn wallet_icon(_dark_mode: bool) -> Result<Icon> {
    let encoded = macos_tray_artwork();
    let image = image::load_from_memory_with_format(encoded, image::ImageFormat::Png)
        .context("failed to decode the macOS tray artwork")?
        .into_rgba8();
    let image = scaled_tray_artwork(&image);
    let (width, height) = image.dimensions();
    Icon::from_rgba(image.into_raw(), width, height)
        .context("failed to construct the macOS tray icon pixels")
}

/// `AppKit` uses the alpha channel of this single monochrome source as its
/// status-item template and supplies the contrasting foreground color.
#[cfg(target_os = "macos")]
fn macos_tray_artwork() -> &'static [u8] {
    include_bytes!("../assets/tray/dark_mode_tray_icon.png").as_slice()
}

/// Keep the status item's pixel canvas stable while making the visible mark
/// 20% smaller. `AppKit` uses the canvas when reserving menu-bar space, so
/// shrinking the canvas itself would let it scale the artwork straight back
/// up and would also make the item's width jump between releases.
#[cfg(target_os = "macos")]
fn scaled_tray_artwork(image: &image::RgbaImage) -> image::RgbaImage {
    let (width, height) = image.dimensions();
    let scaled_width = width.saturating_mul(4) / 5;
    let scaled_height = height.saturating_mul(4) / 5;
    let scaled = image::imageops::resize(
        image,
        scaled_width,
        scaled_height,
        image::imageops::FilterType::Lanczos3,
    );
    let mut canvas = image::RgbaImage::new(width, height);
    image::imageops::overlay(
        &mut canvas,
        &scaled,
        i64::from((width - scaled_width) / 2),
        i64::from((height - scaled_height) / 2),
    );
    canvas
}

#[cfg(not(target_os = "macos"))]
fn wallet_icon(_dark_mode: bool) -> Result<Icon> {
    const SIDE: u32 = 32;
    let image = image::load_from_memory_with_format(
        include_bytes!("../assets/app-icon-512.png"),
        image::ImageFormat::Png,
    )
    .context("failed to decode the application icon")?
    .into_rgba8();
    let image = image::imageops::resize(&image, SIDE, SIDE, image::imageops::FilterType::Lanczos3);
    Icon::from_rgba(image.into_raw(), SIDE, SIDE).context("failed to construct tray icon pixels")
}

#[cfg(test)]
#[path = "tray_test.rs"]
mod tests;
