//! Linux tray integration over the `StatusNotifierItem` and `DBusMenu` protocols.
//! No GTK, `AppIndicator`, or X11 automation library participates in this path.

// These methods implement externally fixed D-Bus interfaces. zbus requires
// receiver methods and owned wire arguments even when a particular property or
// event does not consult them.
#![allow(
    clippy::needless_pass_by_value,
    clippy::unnecessary_literal_bound,
    clippy::unused_self,
    clippy::used_underscore_binding
)]

use super::{
    TrayCommand, TrayService, TraySnapshot, agent_menu_text, review_menu_text, tray_tooltip,
};
use crate::desktop::Route;
use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Condvar, LazyLock, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc,
    },
    time::Duration,
};
use zbus::{
    object_server::SignalEmitter,
    zvariant::{ObjectPath, OwnedValue, Str, Type, Value},
};

const SNI_PATH: &str = "/StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
const MENU_OPEN: i32 = 1;
const MENU_REVIEWS: i32 = 2;
const MENU_SEPARATOR_ONE: i32 = 3;
const MENU_AGENTS: i32 = 4;
const MENU_CONNECT: i32 = 5;
const MENU_SETTINGS: i32 = 6;
const MENU_SEPARATOR_TWO: i32 = 7;
const MENU_QUIT: i32 = 8;

type Pixmap = (i32, i32, Vec<u8>);
type ToolTip = (String, Vec<Pixmap>, String, String);
type Properties = HashMap<Cow<'static, str>, OwnedValue>;

static COMMANDS: LazyLock<(Mutex<VecDeque<TrayCommand>>, Condvar)> =
    LazyLock::new(|| (Mutex::new(VecDeque::new()), Condvar::new()));

fn queue_command(command: TrayCommand) {
    if let Ok(mut commands) = COMMANDS.0.lock() {
        commands.push_back(command);
        COMMANDS.1.notify_one();
    }
}

fn string_value(value: impl Into<String>) -> OwnedValue {
    OwnedValue::from(Str::from(value.into()))
}

fn bool_value(value: bool) -> OwnedValue {
    OwnedValue::from(value)
}

fn menu_properties(id: i32, snapshot: &TraySnapshot) -> Option<Properties> {
    let mut properties = Properties::new();
    let (label, enabled, separator) = match id {
        0 => (String::new(), true, false),
        MENU_OPEN => ("Open Ekubo Wallet".to_owned(), true, false),
        MENU_REVIEWS => (
            review_menu_text(snapshot.pending_reviews),
            snapshot.pending_reviews > 0,
            false,
        ),
        MENU_SEPARATOR_ONE | MENU_SEPARATOR_TWO => (String::new(), false, true),
        MENU_AGENTS => (agent_menu_text(snapshot), false, false),
        MENU_CONNECT => ("Connect a dapp".to_owned(), true, false),
        MENU_SETTINGS => ("Settings".to_owned(), true, false),
        MENU_QUIT => ("Quit Ekubo Wallet".to_owned(), true, false),
        _ => return None,
    };
    if id == 0 {
        properties.insert("children-display".into(), string_value("submenu"));
    } else if separator {
        properties.insert("type".into(), string_value("separator"));
    } else {
        properties.insert("label".into(), string_value(label));
        properties.insert("enabled".into(), bool_value(enabled));
        properties.insert("visible".into(), bool_value(true));
    }
    Some(properties)
}

fn filtered_properties(
    id: i32,
    snapshot: &TraySnapshot,
    requested: &[String],
) -> Option<Properties> {
    let mut properties = menu_properties(id, snapshot)?;
    if !requested.is_empty() {
        properties.retain(|name, _| requested.iter().any(|requested| requested == name.as_ref()));
    }
    Some(properties)
}

#[derive(Debug, Default, Type, Serialize)]
struct Layout {
    id: i32,
    properties: Properties,
    children: Vec<Value<'static>>,
}

impl From<Layout> for Value<'_> {
    fn from(layout: Layout) -> Self {
        Value::from(
            zbus::zvariant::StructureBuilder::new()
                .add_field(layout.id)
                .add_field(layout.properties)
                .add_field(layout.children)
                .build()
                .expect("static DBusMenu layout has a valid signature"),
        )
    }
}

fn layout(id: i32, snapshot: &TraySnapshot, requested: &[String]) -> Option<Layout> {
    let children = if id == 0 {
        [
            MENU_OPEN,
            MENU_REVIEWS,
            MENU_SEPARATOR_ONE,
            MENU_AGENTS,
            MENU_CONNECT,
            MENU_SETTINGS,
            MENU_SEPARATOR_TWO,
            MENU_QUIT,
        ]
        .into_iter()
        .filter_map(|child| layout(child, snapshot, requested).map(Value::from))
        .collect()
    } else {
        Vec::new()
    };
    Some(Layout {
        id,
        properties: filtered_properties(id, snapshot, requested)?,
        children,
    })
}

#[derive(Clone)]
struct SharedState {
    snapshot: Arc<RwLock<TraySnapshot>>,
    pixmap: Arc<Vec<Pixmap>>,
    revision: Arc<AtomicU32>,
}

impl SharedState {
    fn snapshot(&self) -> TraySnapshot {
        self.snapshot
            .read()
            .map_or_else(|_| initial_snapshot(), |snapshot| snapshot.clone())
    }
}

struct StatusNotifierItem(SharedState);

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl StatusNotifierItem {
    fn context_menu(&self, _x: i32, _y: i32) -> zbus::fdo::Result<()> {
        Err(zbus::fdo::Error::UnknownMethod(
            "use the exported DBusMenu".into(),
        ))
    }

    fn activate(&self, _x: i32, _y: i32) {
        queue_command(TrayCommand::OpenWallet);
    }

    fn secondary_activate(&self, _x: i32, _y: i32) {
        queue_command(TrayCommand::OpenWallet);
    }

    fn scroll(&self, _delta: i32, _orientation: String) {}

    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }

    #[zbus(property)]
    fn id(&self) -> &str {
        "ekubo-wallet"
    }

    #[zbus(property)]
    fn title(&self) -> &str {
        "Ekubo Wallet"
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        "Active"
    }

    #[zbus(property)]
    fn window_id(&self) -> i32 {
        0
    }

    #[zbus(property)]
    fn icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<Pixmap> {
        self.0.pixmap.as_ref().clone()
    }

    #[zbus(property)]
    fn overlay_icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn overlay_icon_pixmap(&self) -> Vec<Pixmap> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn attention_icon_pixmap(&self) -> Vec<Pixmap> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_movie_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn menu(&self) -> ObjectPath<'_> {
        ObjectPath::from_static_str_unchecked(MENU_PATH)
    }

    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        true
    }

    #[zbus(property)]
    fn tool_tip(&self) -> ToolTip {
        (
            String::new(),
            self.0.pixmap.as_ref().clone(),
            "Ekubo Wallet".to_owned(),
            tray_tooltip(&self.0.snapshot()),
        )
    }

    #[zbus(signal)]
    async fn new_tool_tip(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

struct DbusMenu(SharedState);

#[zbus::interface(name = "com.canonical.dbusmenu")]
impl DbusMenu {
    fn get_layout(
        &self,
        parent_id: i32,
        _recursion_depth: i32,
        property_names: Vec<String>,
    ) -> zbus::fdo::Result<(u32, Layout)> {
        let snapshot = self.0.snapshot();
        let layout = layout(parent_id, &snapshot, &property_names)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("parent ID not found".into()))?;
        Ok((self.0.revision.load(Ordering::Acquire), layout))
    }

    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        property_names: Vec<String>,
    ) -> Vec<(i32, Properties)> {
        let snapshot = self.0.snapshot();
        let ids = if ids.is_empty() {
            (0..=MENU_QUIT).collect::<Vec<_>>()
        } else {
            ids
        };
        ids.into_iter()
            .filter_map(|id| {
                filtered_properties(id, &snapshot, &property_names)
                    .map(|properties| (id, properties))
            })
            .collect()
    }

    fn get_property(&self, id: i32, name: String) -> zbus::fdo::Result<OwnedValue> {
        filtered_properties(id, &self.0.snapshot(), std::slice::from_ref(&name))
            .and_then(|mut properties| properties.remove(name.as_str()))
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("property not found".into()))
    }

    fn event(
        &self,
        id: i32,
        event_id: String,
        _data: OwnedValue,
        _timestamp: u32,
    ) -> zbus::fdo::Result<()> {
        if event_id != "clicked" {
            return Ok(());
        }
        let snapshot = self.0.snapshot();
        let command = match id {
            MENU_OPEN => Some(TrayCommand::OpenWallet),
            MENU_REVIEWS if snapshot.pending_reviews > 0 => {
                Some(TrayCommand::OpenRoute(Route::Activity))
            }
            MENU_CONNECT => Some(TrayCommand::OpenRoute(Route::WalletConnect)),
            MENU_SETTINGS => Some(TrayCommand::OpenRoute(Route::Settings)),
            MENU_QUIT => Some(TrayCommand::Quit),
            MENU_AGENTS | MENU_SEPARATOR_ONE | MENU_SEPARATOR_TWO => None,
            _ => {
                return Err(zbus::fdo::Error::InvalidArgs("menu item not found".into()));
            }
        };
        if let Some(command) = command {
            queue_command(command);
        }
        Ok(())
    }

    fn event_group(&self, events: Vec<(i32, String, OwnedValue, u32)>) -> Vec<i32> {
        events
            .into_iter()
            .filter_map(|(id, event, data, timestamp)| {
                self.event(id, event, data, timestamp).err().map(|_| id)
            })
            .collect()
    }

    fn about_to_show(&self, id: i32) -> zbus::fdo::Result<bool> {
        menu_properties(id, &self.0.snapshot())
            .map(|_| false)
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("menu item not found".into()))
    }

    fn about_to_show_group(&self, ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        let snapshot = self.0.snapshot();
        let missing = ids
            .into_iter()
            .filter(|id| menu_properties(*id, &snapshot).is_none())
            .collect();
        (Vec::new(), missing)
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }

    #[zbus(property)]
    fn text_direction(&self) -> &str {
        "ltr"
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        "normal"
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(signal)]
    async fn layout_updated(
        emitter: &SignalEmitter<'_>,
        revision: u32,
        parent: i32,
    ) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.kde.StatusNotifierWatcher",
    default_service = "org.kde.StatusNotifierWatcher",
    default_path = "/StatusNotifierWatcher"
)]
trait StatusNotifierWatcher {
    async fn register_status_notifier_item(&self, service: &str) -> zbus::Result<()>;
}

fn initial_snapshot() -> TraySnapshot {
    TraySnapshot {
        pending_reviews: 0,
        mcp_online: false,
        walletconnect_sessions: 0,
    }
}

fn icon_pixmap() -> Result<Vec<Pixmap>> {
    const SIDE: u32 = 32;
    let image = image::load_from_memory_with_format(
        include_bytes!("../assets/app-icon-512.png"),
        image::ImageFormat::Png,
    )
    .context("failed to decode the Linux tray artwork")?
    .into_rgba8();
    let image = image::imageops::resize(&image, SIDE, SIDE, image::imageops::FilterType::Lanczos3);
    let mut argb = Vec::with_capacity((SIDE * SIDE * 4) as usize);
    for pixel in image.pixels() {
        let [red, green, blue, alpha] = pixel.0;
        argb.extend_from_slice(&[alpha, red, green, blue]);
    }
    let side = i32::try_from(SIDE).expect("tray icon side fits i32");
    Ok(vec![(side, side, argb)])
}

async fn serve(
    state: SharedState,
    mut updates: tokio::sync::mpsc::UnboundedReceiver<TraySnapshot>,
    ready: mpsc::SyncSender<std::result::Result<(), String>>,
    online: Arc<AtomicBool>,
) -> Result<()> {
    let connection = zbus::connection::Builder::session()
        .context("failed to connect to the desktop D-Bus session")?
        .serve_at(SNI_PATH, StatusNotifierItem(state.clone()))
        .context("failed to export StatusNotifierItem")?
        .serve_at(MENU_PATH, DbusMenu(state.clone()))
        .context("failed to export DBusMenu")?
        .build()
        .await
        .context("failed to start the Linux tray D-Bus service")?;
    let service_name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
    connection
        .request_name(service_name.as_str())
        .await
        .context("failed to reserve the Linux tray D-Bus name")?;
    let watcher = StatusNotifierWatcherProxy::new(&connection)
        .await
        .context("failed to find a StatusNotifierWatcher")?;
    watcher
        .register_status_notifier_item(&service_name)
        .await
        .context("the desktop rejected the StatusNotifierItem")?;
    online.store(true, Ordering::Release);
    let _ = ready.send(Ok(()));

    while let Some(snapshot) = updates.recv().await {
        if let Ok(mut current) = state.snapshot.write() {
            *current = snapshot;
        }
        let revision = state.revision.fetch_add(1, Ordering::AcqRel) + 1;
        let item = connection
            .object_server()
            .interface::<_, StatusNotifierItem>(SNI_PATH)
            .await?;
        StatusNotifierItem::new_tool_tip(item.signal_emitter()).await?;
        let menu = connection
            .object_server()
            .interface::<_, DbusMenu>(MENU_PATH)
            .await?;
        DbusMenu::layout_updated(menu.signal_emitter(), revision, 0).await?;
    }
    online.store(false, Ordering::Release);
    Ok(())
}

pub struct PlatformTray {
    updates: tokio::sync::mpsc::UnboundedSender<TraySnapshot>,
    snapshot: TraySnapshot,
    online: Arc<AtomicBool>,
}

impl PlatformTray {
    pub fn new(_dark_mode: bool) -> Result<Self> {
        let snapshot = initial_snapshot();
        let state = SharedState {
            snapshot: Arc::new(RwLock::new(snapshot.clone())),
            pixmap: Arc::new(icon_pixmap()?),
            revision: Arc::new(AtomicU32::new(1)),
        };
        let (updates, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let online = Arc::new(AtomicBool::new(false));
        let service_online = online.clone();
        std::thread::Builder::new()
            .name("ekubo-linux-tray".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                match runtime {
                    Ok(runtime) => {
                        if let Err(error) = runtime.block_on(serve(
                            state,
                            receiver,
                            ready_tx.clone(),
                            service_online.clone(),
                        )) {
                            service_online.store(false, Ordering::Release);
                            let _ = ready_tx.send(Err(format!("{error:#}")));
                            tracing::warn!("Linux tray stopped: {error:#}");
                        }
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(format!(
                            "failed to start the Linux tray runtime: {error}"
                        )));
                    }
                }
            })
            .context("failed to start the Linux tray thread")?;
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                updates,
                snapshot,
                online,
            }),
            Ok(Err(error)) => Err(anyhow!(error)),
            Err(error) => Err(anyhow!("Linux tray startup did not complete: {error}")),
        }
    }

    pub fn set_dark_mode(&mut self, _dark_mode: bool) {}

    pub fn set_mcp_online(&mut self, online: bool) {
        let mut snapshot = self.snapshot.clone();
        snapshot.mcp_online = online;
        self.update(&snapshot);
    }

    #[must_use]
    pub fn recv_command() -> Option<TrayCommand> {
        let mut commands = COMMANDS.0.lock().ok()?;
        loop {
            if let Some(command) = commands.pop_front() {
                return Some(command);
            }
            commands = COMMANDS.1.wait(commands).ok()?;
        }
    }
}

impl TrayService for PlatformTray {
    fn available(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    fn update(&mut self, snapshot: &TraySnapshot) {
        self.snapshot = snapshot.clone();
        let _ = self.updates.send(snapshot.clone());
    }

    fn drain_commands(&mut self) -> Vec<TrayCommand> {
        COMMANDS
            .0
            .lock()
            .map_or_else(|_| Vec::new(), |mut commands| commands.drain(..).collect())
    }
}

#[cfg(test)]
#[path = "tray_linux_test.rs"]
mod tests;
