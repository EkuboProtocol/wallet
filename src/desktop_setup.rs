//! Pre-custody setup. Only the installed coordinator performs enrollment.
use super::*;
use ekubo_wallet_core::legacy_move::MoveStatus;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupAction {
    Install,
    Resume,
    DiscardUnused,
}

impl SetupAction {
    const fn argument(self) -> &'static str {
        match self {
            Self::Install => "--owner",
            Self::Resume => "--resume-owner",
            Self::DiscardUnused => "--discard-unused",
        }
    }
}

// Windows resolves the installation relative to its fallible executable lookup.
#[cfg_attr(target_os = "linux", allow(clippy::unnecessary_wraps))]
fn coordinator_path() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from(
            "/usr/lib/ekubo-wallet-v2/ekubo-wallet-v2-enroll",
        ))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(std::env::current_exe()?
            .parent()
            .context("wallet installation directory unavailable")?
            .join("ekubo-wallet-v2-enroll.exe"))
    }
}

fn enroll(action: SetupAction) -> Result<String> {
    let helper = coordinator_path()?;
    anyhow::ensure!(
        helper.is_file(),
        "The enrollment coordinator is missing. Install the signed Ekubo Wallet 2 package, then reopen this window."
    );
    let mut command = std::process::Command::new(helper);
    command.arg(action.argument());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW; UAC remains native.
    }
    let output = command
        .output()
        .context("could not start the installed enrollment coordinator")?;
    anyhow::ensure!(
        output.status.success(),
        "Setup did not complete ({}). {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(if action == SetupAction::DiscardUnused {
        "The coordinator discarded only the unused unpublished setup attempt. You can now choose Set up wallet."
    } else {
        "The coordinator completed setup and connected to the protected service. Restart the wallet to continue."
    }.into())
}

struct SetupWindow {
    message: Option<String>,
    busy: bool,
    can_enroll: bool,
    restart: Rc<Cell<bool>>,
    owner: Option<crate::desktop_owner::DesktopOwner>,
    move_view: Option<Entity<super::legacy_move::MoveWindow>>,
    completed: bool,
    move_status: MoveStatus,
}

impl SetupWindow {
    fn start(&mut self, action: SetupAction, cx: &mut Context<Self>) {
        if self.busy
            || self.completed
            || self.owner.is_some()
            || (action != SetupAction::Resume && !self.can_enroll)
        {
            return;
        }
        self.busy = true;
        self.message = Some(
            "Waiting for the installed coordinator and the operating-system approval prompt."
                .into(),
        );
        let task = gpui_tokio::Tokio::handle(cx).spawn_blocking(move || enroll(action));
        cx.spawn(async move |view, cx| {
            let result = task.await.unwrap_or_else(|error| Err(error.into()));
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                view.message = Some(match result {
                    Ok(message) => { if action != SetupAction::DiscardUnused { view.can_enroll = false; view.completed = true; } message }
                    Err(error) => format!("{error:#}\nAn interrupted attempt may have been retained. Use Resume setup; do not attempt to reset an installed wallet."),
                });
                cx.notify();
            });
        }).detach();
        cx.notify();
    }
}

impl Render for SetupWindow {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if let Some(view) = &self.move_view {
            return div().size_full().child(view.clone());
        }
        if self.owner.is_some() {
            return div().size_full().p_6().flex().flex_col().gap_4()
                .bg(cx.theme().background).text_color(cx.theme().foreground)
                .child(div().text_lg().font_semibold().child(if self.move_status.pending() { "Resume move cleanup" } else { "Start with Ekubo Wallet 2" }))
                .when(!self.move_status.pending(), |panel| panel.child(selectable_label("Your protected v2 wallet has no accounts. Continue to create or import an account, or choose an explicit move from 1.x. A move requires v2 to remain unchanged from fresh setup; core refuses to overwrite a configured profile. Nothing from 1.x has been read.")))
                .when(self.move_status.pending(), |panel| panel.child(selectable_label("The destination import is committed, but old-credential cleanup is not confirmed complete. Execution remains paused. Review the same source and preserved profiles to resume; no deletion is retried automatically.")))
                .child(app_button("first-run-continue").self_start().label("Continue without moving").disabled(self.move_status.pending())
                    .on_click(cx.listener(|view, _, _, cx| { if !view.move_status.pending() { view.restart.set(true); cx.quit(); } })))
                .child(app_button("first-run-move").self_start().label(if self.move_status.pending() { "Review pending cleanup…" } else { "Move from 1.x…" }).disabled(cfg!(target_os = "windows"))
                    .on_click(cx.listener(|view, _, window, cx| {
                        let Some(owner) = view.owner.clone() else { return; };
                        let pending = match &view.move_status { MoveStatus::PendingCleanup { binding, .. } => Some(binding.clone()), _ => None };
                        match super::legacy_move::create(owner, window, cx, view.restart.clone(), pending) {
                            Ok(child) => view.move_view = Some(child),
                            Err(error) => view.message = Some(format!("Could not open the move review: {error:#}")),
                        }
                        cx.notify();
                    })))
                .when(cfg!(target_os = "windows"), |panel| panel.child(selectable_label("Protected owner authorization is unavailable in this Windows build. Moving from 1.x and other protected owner operations remain blocked.")))
                .when_some(self.message.clone(), |panel, message| panel.child(selectable_label(message)));
        }
        div().size_full().p_6().flex().flex_col().gap_4()
            .bg(cx.theme().background).text_color(cx.theme().foreground)
            .child(div().text_lg().font_semibold().child("Set up Ekubo Wallet 2"))
            .child(selectable_label("The protected service must be ready before the wallet can open. Set up wallet runs the installed coordinator and asks the operating system for approval. Existing 1.x data is not read or moved during setup."))
            .when(cfg!(target_os = "windows"), |panel| panel.child(selectable_label(
                "Protected owner authorization is unavailable in this Windows build. Setup does not enable approvals, key export, legal acceptance, or moving from 1.x; those operations remain blocked."
            )))
            .when_some(self.message.clone(), |panel, message| panel.child(div().id("setup-status").overflow_y_scroll().flex_1().min_h_0().child(selectable_label(message))))
            .when(self.can_enroll, |panel| panel
                .child(app_button("enroll-wallet").label("Set up wallet").self_start().primary().disabled(self.busy)
                    .on_click(cx.listener(|view, _, _, cx| view.start(SetupAction::Install, cx))))
                .child(app_button("discard-unused-enrollment").label("Discard unused setup…").self_start().disabled(self.busy)
                    .on_click(cx.listener(|_, _, window, cx| {
                        let view = cx.entity().downgrade();
                        window.open_alert_dialog(cx, move |alert, _, _| {
                            let view = view.clone();
                            alert.title("Discard unused setup?")
                                .description("The coordinator will remove only an unpublished, unused v2 setup attempt. It refuses installed wallets. Continue only if you intend to abandon that attempt.")
                                .button_props(DialogButtonProps::default().ok_text("Discard unused setup").cancel_text("Cancel").show_cancel(true))
                                .on_ok(move |_, _, cx| { let _ = view.update(cx, |view, cx| view.start(SetupAction::DiscardUnused, cx)); true })
                        });
                    }))))
            .when(!self.completed, |panel| panel.child(app_button("resume-enrollment").label("Resume setup").self_start().disabled(self.busy)
                .on_click(cx.listener(|view, _, _, cx| view.start(SetupAction::Resume, cx)))))
            .child(app_button("restart-after-setup").label("Restart wallet").self_start().disabled(self.busy)
                .on_click(cx.listener(|view, _, _, cx| { view.restart.set(true); cx.quit(); })))
            .child(gpui_component::link::Link::new("setup-installers").href(LATEST_RELEASE_URL).child("Get the signed installer"))
    }
}

pub(super) fn run(error: Option<String>, can_enroll: bool) -> Result<bool> {
    run_window(error, can_enroll, None, MoveStatus::Unavailable)
}

pub(super) fn first_run(
    owner: crate::desktop_owner::DesktopOwner,
    status: MoveStatus,
) -> Result<bool> {
    run_window(None, false, Some(owner), status)
}

pub(super) const fn show_move(
    status: &MoveStatus,
    accounts_empty: bool,
    continue_empty: bool,
) -> bool {
    match status {
        MoveStatus::PendingCleanup { .. } => true,
        MoveStatus::Baseline => accounts_empty && !continue_empty,
        MoveStatus::Unavailable | MoveStatus::Complete { .. } => false,
    }
}

fn run_window(
    error: Option<String>,
    can_enroll: bool,
    owner: Option<crate::desktop_owner::DesktopOwner>,
    move_status: MoveStatus,
) -> Result<bool> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let handle = runtime.handle().clone();
    let restart = Rc::new(Cell::new(false));
    let result = restart.clone();
    let failure = Rc::new(RefCell::new(None));
    let opened = failure.clone();
    gpui_platform::application()
        .with_assets(WalletAssets::default())
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            apply_appearance_preference(AppearancePreference::default(), None, cx);
            if let Err(error) = load_application_fonts(cx) {
                tracing::warn!(%error, "setup is using the platform font fallback");
            }
            gpui_tokio::init_from_handle(cx, handle);
            let window = cx.open_window(
                WindowOptions {
                    app_id: Some("ekubo-wallet-v2".into()),
                    titlebar: Some(gpui::TitlebarOptions {
                        title: Some("Ekubo Wallet 2 setup".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                |window, cx| {
                    let view = cx.new(|_| SetupWindow {
                        message: error,
                        busy: false,
                        can_enroll,
                        restart,
                        owner,
                        move_view: None,
                        completed: false,
                        move_status,
                    });
                    let closing = view.downgrade();
                    window.on_window_should_close(cx, move |_, cx| {
                        closing
                            .read_with(cx, |view, cx| {
                                !view.busy
                                    && view
                                        .move_view
                                        .as_ref()
                                        .is_none_or(|child| !child.read(cx).busy())
                            })
                            .unwrap_or(true)
                    });
                    let host = cx.new(|_| ComponentLayerHost::new(view));
                    cx.new(|cx| Root::new(host, window, cx))
                },
            );
            if let Err(error) = window {
                *opened.borrow_mut() = Some(error);
                cx.quit();
            }
            cx.activate(true);
        });
    if let Some(error) = failure.borrow_mut().take() {
        return Err(error);
    }
    Ok(result.get())
}

pub(super) fn relaunch() -> Result<()> {
    std::process::Command::new(std::env::current_exe()?)
        .spawn()
        .context("setup finished, but automatic restart failed; open Ekubo Wallet 2 again")?;
    Ok(())
}

pub(super) fn recover_connection(
    error: &anyhow::Error,
    owner: Option<&crate::desktop_owner::DesktopOwner>,
    runtime: &tokio::runtime::Runtime,
    instance: &Arc<Mutex<Option<SingleInstance>>>,
) -> Result<()> {
    if let Some(owner) = owner
        && let Err(error) = runtime.block_on(owner.disconnect_service())
    {
        tracing::warn!(%error, "startup connection shutdown failed");
    }
    let restart = run(Some(format!("{error:#}")), false)?;
    release_single_instance(instance)?;
    if restart {
        relaunch()?;
    }
    Ok(())
}

// UI continuation only: this skips an optional chooser, never authorization,
// enrollment, empty-destination validation, or a source review. It is passed
// only to the child process and writes no persistent wallet setting.
pub(super) const CONTINUE_EMPTY: &str = "EKUBO_WALLET_V2_CONTINUE_EMPTY";

pub(super) fn continue_to_wallet() -> Result<()> {
    std::process::Command::new(std::env::current_exe()?)
        .env(CONTINUE_EMPTY, "1")
        .spawn()
        .context("could not reopen the wallet; open Ekubo Wallet 2 again")?;
    Ok(())
}

#[cfg(test)]
#[path = "desktop_setup_test.rs"]
mod tests;
