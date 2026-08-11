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
const UPDATES_ID: &str = "ekubo.updates";
const SETTINGS_ID: &str = "ekubo.settings";
const QUIT_ID: &str = "ekubo.quit";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrayCommand {
    OpenWallet,
    OpenRoute(Route),
    ConnectDapp,
    CheckForUpdates,
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
}

impl PlatformTray {
    pub fn new() -> Result<Self> {
        let menu = Menu::new();
        let open = MenuItem::with_id(OPEN_ID, "Open Wallet", true, None);
        let reviews = MenuItem::with_id(REVIEWS_ID, "No pending reviews", true, None);
        let connect = MenuItem::with_id(CONNECT_ID, "Connect dapp…", true, None);
        let agents = MenuItem::with_id(AGENTS_ID, "MCP starting…", true, None);
        let updates = MenuItem::with_id(UPDATES_ID, "Check for Updates…", true, None);
        let settings = MenuItem::with_id(SETTINGS_ID, "Settings…", true, None);
        let quit = MenuItem::with_id(QUIT_ID, "Quit Ekubo Wallet", true, None);
        let separator_one = PredefinedMenuItem::separator();
        let separator_two = PredefinedMenuItem::separator();
        menu.append_items(&[
            &open,
            &reviews,
            &separator_one,
            &connect,
            &agents,
            &separator_two,
            &updates,
            &settings,
            &quit,
        ])
        .context("failed to construct the tray menu")?;

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(true)
            .with_tooltip("Ekubo Wallet")
            .with_icon(wallet_icon()?)
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
        })
    }
}

impl TrayService for PlatformTray {
    fn available(&self) -> bool {
        true
    }

    fn update(&mut self, snapshot: &TraySnapshot) {
        self.snapshot = snapshot.clone();
        self.reviews.set_text(match snapshot.pending_reviews {
            0 => "No pending reviews".to_owned(),
            1 => "1 pending review".to_owned(),
            count => format!("{count} pending reviews"),
        });
        let status = if snapshot.mcp_online {
            "online"
        } else {
            "offline"
        };
        self.agents.set_text(format!(
            "MCP {status} · {} agent(s) · {} dapp(s)",
            snapshot.connected_agents, snapshot.walletconnect_sessions
        ));
        let _ = self.tray.set_tooltip(Some(format!(
            "Ekubo Wallet · MCP {status} · {} review(s)",
            snapshot.pending_reviews
        )));
    }

    fn drain_commands(&mut self) -> Vec<TrayCommand> {
        MenuEvent::receiver()
            .try_iter()
            .filter_map(|event| match event.id.as_ref() {
                OPEN_ID => Some(TrayCommand::OpenWallet),
                REVIEWS_ID => Some(TrayCommand::OpenRoute(Route::Reviews)),
                CONNECT_ID => Some(TrayCommand::ConnectDapp),
                AGENTS_ID => Some(TrayCommand::OpenRoute(Route::Agents)),
                UPDATES_ID => Some(TrayCommand::CheckForUpdates),
                SETTINGS_ID => Some(TrayCommand::OpenRoute(Route::Settings)),
                QUIT_ID => Some(TrayCommand::Quit),
                _ => None,
            })
            .collect()
    }
}

fn wallet_icon() -> Result<Icon> {
    const SIDE: u32 = 20;
    let mut rgba = vec![0_u8; (SIDE * SIDE * 4) as usize];
    for y in 3..17 {
        for x in 3..17 {
            let stroke = x <= 6
                || (x >= 6 && (4..=7).contains(&y))
                || (x >= 6 && (9..=11).contains(&y))
                || (x >= 6 && (14..=16).contains(&y));
            if stroke {
                let offset = ((y * SIDE + x) * 4) as usize;
                rgba[offset..offset + 4].copy_from_slice(&[0, 0, 0, 255]);
            }
        }
    }
    Icon::from_rgba(rgba, SIDE, SIDE).context("failed to construct tray icon pixels")
}

#[cfg(test)]
#[path = "tray_test.rs"]
mod tests;
