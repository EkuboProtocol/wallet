use crate::{
    BUILD_VERSION,
    authority::{ApplicationAuthority, OwnerApi},
    http_server::{MCP_REQUEST_LIMIT_BYTES, McpHttpServer},
    migration::prepare_desktop_data_dir,
    notifications::{
        NotificationPreferences, NotificationRoute, NotificationService as _,
        PlatformNotificationService, notification_for,
    },
    single_instance::{InstanceOutcome, SingleInstance},
    tray::{PlatformTray, TrayCommand, TrayService, TraySnapshot},
};
use anyhow::Result;
use gpui::{
    App, Context, KeyBinding, QuitMode, Render, SharedString, Window, WindowBounds, WindowOptions,
    actions, div, prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme, Root, StyledExt,
    button::{Button, ButtonVariants},
};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Mutex},
    time::Duration,
};

actions!(ekubo_wallet, [OpenCommandPalette, Quit]);

struct DesktopRuntime {
    _instance: SingleInstance,
    _server: Arc<Mutex<Option<McpHttpServer>>>,
    _walletconnect: Arc<Mutex<crate::walletconnect::WalletConnectManager>>,
    _tray: Rc<RefCell<Option<PlatformTray>>>,
}

impl gpui::Global for DesktopRuntime {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Overview,
    Reviews,
    Activity,
    Accounts,
    Policies,
    Networks,
    Tokens,
    AddressBook,
    Agents,
    WalletConnect,
    Settings,
    Legal,
    Updates,
}

impl Route {
    const ALL: [Self; 13] = [
        Self::Overview,
        Self::Reviews,
        Self::Activity,
        Self::Accounts,
        Self::Policies,
        Self::Networks,
        Self::Tokens,
        Self::AddressBook,
        Self::Agents,
        Self::WalletConnect,
        Self::Settings,
        Self::Legal,
        Self::Updates,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Reviews => "Reviews",
            Self::Activity => "Activity",
            Self::Accounts => "Accounts",
            Self::Policies => "Policies",
            Self::Networks => "Networks",
            Self::Tokens => "Tokens",
            Self::AddressBook => "Address Book",
            Self::Agents => "Agents",
            Self::WalletConnect => "WalletConnect",
            Self::Settings => "Settings",
            Self::Legal => "Legal & Version",
            Self::Updates => "Updates",
        }
    }
}

pub struct WalletWindow {
    owner: OwnerApi,
    route: Route,
    command_palette: bool,
    mcp_status: SharedString,
    selected_record: Option<uuid::Uuid>,
}

impl WalletWindow {
    fn new(owner: OwnerApi) -> Self {
        Self {
            owner,
            route: Route::Overview,
            command_palette: false,
            mcp_status: "MCP starting…".into(),
            selected_record: None,
        }
    }

    fn toggle_palette(&mut self, _: &OpenCommandPalette, _: &mut Window, cx: &mut Context<Self>) {
        self.command_palette = !self.command_palette;
        cx.notify();
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut sidebar = div()
            .w(px(184.0))
            .h_full()
            .flex()
            .flex_col()
            .gap_1()
            .p_3()
            .border_r_1()
            .border_color(cx.theme().border)
            .child(div().text_lg().font_semibold().mb_3().child("Ekubo Wallet"));
        for route in Route::ALL {
            let selected = route == self.route;
            sidebar = sidebar.child(
                Button::new(SharedString::from(format!("route-{route:?}")))
                    .label(route.label())
                    .when(selected, ButtonVariants::primary)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.route = route;
                        this.command_palette = false;
                        cx.notify();
                    })),
            );
        }
        sidebar
    }

    fn render_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let accounts = self.owner.accounts().map_or(0, |accounts| accounts.len());
        let agents = self.owner.clients().map_or(0, |agents| agents.len());
        div()
            .flex_1()
            .h_full()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(div().text_2xl().font_semibold().child(self.route.label()))
                    .child(
                        Button::new("command-palette")
                            .label("Search  ⌘K")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.command_palette = true;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .p_4()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(format!("{accounts} account(s)"))
                    .child(format!("{agents} registered agent(s)"))
                    .child(self.mcp_status.clone())
                    .child(format!(
                        "Loopback requests are limited to {} MiB",
                        MCP_REQUEST_LIMIT_BYTES / 1024 / 1024
                    )),
            )
            .child(div().text_sm().text_color(cx.theme().muted_foreground).child(
                "Agent tokens protect this endpoint from accidental or unauthorized local clients. Plaintext loopback HTTP cannot protect against malicious code already running as your OS user.",
            ))
    }

    fn render_palette(cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .absolute()
            .top(px(54.0))
            .left(px(220.0))
            .w(px(360.0))
            .p_3()
            .rounded_lg()
            .shadow_lg()
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().popover)
            .child(div().font_semibold().mb_2().child("Go to…"))
            .children(Route::ALL.into_iter().map(|route| {
                Button::new(SharedString::from(format!("palette-{route:?}")))
                    .label(route.label())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.route = route;
                        this.command_palette = false;
                        cx.notify();
                    }))
            }))
    }
}

impl Render for WalletWindow {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .key_context("Wallet")
            .on_action(cx.listener(Self::toggle_palette))
            .relative()
            .size_full()
            .flex()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(self.render_sidebar(cx))
            .child(self.render_content(cx))
            .when(self.command_palette, |view| {
                view.child(Self::render_palette(cx))
            })
    }
}

pub fn run_desktop() -> Result<()> {
    let config = crate::config::ConfigStore::production()?;
    let _legacy_archive = prepare_desktop_data_dir(config.data_dir())?;
    let (activation_tx, activation_rx) = std::sync::mpsc::channel();
    let instance = match SingleInstance::acquire(config.data_dir(), activation_tx)? {
        InstanceOutcome::Primary(instance) => instance,
        InstanceOutcome::ActivatedExisting => return Ok(()),
    };
    let authority = ApplicationAuthority::open(config)?;
    let owner = authority.owner_api();
    let agent = authority.agent_api();
    let clients = authority.desktop_store();
    let events = authority.events();
    let server_slot = Arc::new(Mutex::new(None::<McpHttpServer>));
    let walletconnect = Arc::new(Mutex::new(
        crate::walletconnect::WalletConnectManager::default(),
    ));

    gpui_platform::application().run(move |cx: &mut App| {
        gpui_component::init(cx);
        gpui_tokio::init(cx);
        cx.set_quit_mode(QuitMode::Explicit);
        let tray = Rc::new(RefCell::new(PlatformTray::new().ok()));
        let initial_agents = owner.clients().map_or(0, |clients| clients.len());
        if let Some(tray) = tray.borrow_mut().as_mut() {
            tray.update(&TraySnapshot {
                pending_reviews: 0,
                mcp_online: false,
                connected_agents: initial_agents,
                walletconnect_sessions: 0,
            });
        }
        cx.set_global(DesktopRuntime {
            _instance: instance,
            _server: server_slot.clone(),
            _walletconnect: walletconnect.clone(),
            _tray: tray.clone(),
        });
        cx.bind_keys([
            KeyBinding::new("cmd-k", OpenCommandPalette, Some("Wallet")),
            KeyBinding::new("ctrl-k", OpenCommandPalette, Some("Wallet")),
            #[cfg(target_os = "macos")]
            KeyBinding::new("cmd-q", Quit, None),
            #[cfg(not(target_os = "macos"))]
            KeyBinding::new("ctrl-q", Quit, None),
        ]);
        cx.on_action(|_: &Quit, cx| cx.quit());
        let shutdown_server = server_slot.clone();
        let shutdown_walletconnect = walletconnect.clone();
        let tokio = gpui_tokio::Tokio::handle(cx);
        cx.on_app_quit(move |_| {
            if let Ok(mut sessions) = shutdown_walletconnect.lock() {
                sessions.disconnect_all();
            }
            let server = shutdown_server
                .lock()
                .ok()
                .and_then(|mut server| server.take());
            let tokio = tokio.clone();
            async move {
                if let Some(server) = server {
                    let _ = tokio.spawn(server.stop()).await;
                }
            }
        })
        .detach();

        let wallet_view = cx.new(|_| WalletWindow::new(owner.clone()));
        let root_view = wallet_view.clone();
        let window = cx
            .open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::centered(size(px(960.0), px(650.0)), cx)),
                    ..Default::default()
                },
                |window, cx| {
                    window.set_window_title(&format!("Ekubo Wallet {BUILD_VERSION}"));
                    window.on_window_should_close(cx, |window, _| {
                        window.minimize_window();
                        false
                    });
                    cx.new(|cx| Root::new(root_view, window, cx))
                },
            )
            .expect("failed to open the wallet window");
        window
            .update(cx, |_, window, _| window.activate_window())
            .ok();

        let tray_events = tray.clone();
        let tray_window = window;
        let tray_view = wallet_view.clone();
        cx.spawn(async move |cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                let commands = tray_events
                    .borrow_mut()
                    .as_mut()
                    .map_or_else(Vec::new, TrayService::drain_commands);
                for command in commands {
                    match command {
                        TrayCommand::OpenWallet => {
                            let _ = tray_window.update(cx, |_, window, _| window.activate_window());
                        }
                        TrayCommand::OpenRoute(route) => {
                            tray_view.update(cx, |view, cx| {
                                view.route = route;
                                cx.notify();
                            });
                            let _ = tray_window.update(cx, |_, window, _| window.activate_window());
                        }
                        TrayCommand::ConnectDapp => {
                            tray_view.update(cx, |view, cx| {
                                view.route = Route::WalletConnect;
                                cx.notify();
                            });
                            let _ = tray_window.update(cx, |_, window, _| window.activate_window());
                        }
                        TrayCommand::CheckForUpdates => {
                            tray_view.update(cx, |view, cx| {
                                view.route = Route::Updates;
                                cx.notify();
                            });
                            let _ = tray_window.update(cx, |_, window, _| window.activate_window());
                        }
                        TrayCommand::Quit => {
                            cx.update(|cx| cx.quit());
                            return;
                        }
                    }
                }
            }
        })
        .detach();

        let detailed_previews = clients
            .lock()
            .ok()
            .and_then(|store| store.setting::<bool>("notification_detailed_previews").ok())
            .flatten()
            .unwrap_or(false);
        let preferences = NotificationPreferences { detailed_previews };
        let (notification_clicks, mut clicked_notifications) =
            tokio::sync::mpsc::unbounded_channel();
        let notification_service = PlatformNotificationService::new(notification_clicks);
        let mut domain_events = events.subscribe();
        gpui_tokio::Tokio::spawn(cx, async move {
            loop {
                match domain_events.recv().await {
                    Ok(event) => {
                        if let Some(notification) = notification_for(&event, preferences) {
                            notification_service.show(notification);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
        .detach();

        let notification_window = window;
        let notification_view = wallet_view.clone();
        cx.spawn(async move |cx| {
            while let Some(route) = clicked_notifications.recv().await {
                notification_view.update(cx, |view, cx| {
                    match route {
                        NotificationRoute::Review(request_id) => {
                            view.route = Route::Reviews;
                            view.selected_record = Some(request_id);
                        }
                        NotificationRoute::Activity(request_id) => {
                            view.route = Route::Activity;
                            view.selected_record = Some(request_id);
                        }
                    }
                    cx.notify();
                });
                let _ = notification_window.update(cx, |_, window, _| window.activate_window());
            }
        })
        .detach();

        let activation_window = window;
        cx.spawn(async move |cx| {
            let mut receiver = activation_rx;
            loop {
                let receive_task = gpui_tokio::Tokio::spawn(cx, async move {
                    tokio::task::spawn_blocking(move || {
                        let result = receiver.recv();
                        (receiver, result)
                    })
                    .await
                })
                .await;
                let Ok(Ok((next, Ok(())))) = receive_task else {
                    break;
                };
                receiver = next;
                let _ = activation_window.update(cx, |_, window, _| window.activate_window());
            }
        })
        .detach();

        let slot = server_slot.clone();
        let status_tray = tray.clone();
        let server_events = events.clone();
        let server_task = gpui_tokio::Tokio::spawn_result(cx, async move {
            McpHttpServer::start(owner, agent, clients, server_events).await
        });
        cx.spawn(async move |cx| match server_task.await {
            Ok(server) => {
                let address = server.address;
                if let Ok(mut guard) = slot.lock() {
                    *guard = Some(server);
                }
                if let Some(tray) = status_tray.borrow_mut().as_mut() {
                    tray.update(&TraySnapshot {
                        pending_reviews: 0,
                        mcp_online: true,
                        connected_agents: initial_agents,
                        walletconnect_sessions: 0,
                    });
                }
                wallet_view.update(cx, |view, cx| {
                    view.mcp_status = format!("MCP online at {address}/mcp").into();
                    cx.notify();
                });
            }
            Err(error) => wallet_view.update(cx, |view, cx| {
                view.mcp_status = format!("MCP offline: {error:#}").into();
                cx.notify();
            }),
        })
        .detach();
    });
    Ok(())
}
