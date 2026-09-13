//! Explicit first-run inventory review. Custody transfer and cleanup stay in core.
use super::*;
use ekubo_wallet_core::legacy_move::{LegacySource, MoveSummary, ProfileInventory};
use gpui_component::checkbox::Checkbox;
use std::fmt::Write as _;

pub(super) struct MoveWindow {
    owner: crate::desktop_owner::DesktopOwner,
    source_input: Entity<InputState>,
    preserved_input: Entity<InputState>,
    inventory_complete: bool,
    deletion_confirmed: bool,
    reviewed: Option<LegacySource>,
    summary: Option<MoveSummary>,
    busy: bool,
    message: Option<String>,
    restart: Rc<Cell<bool>>,
}

fn selected_profiles(
    source: &str,
    preserved: &str,
    complete: bool,
) -> Result<(PathBuf, ProfileInventory)> {
    anyhow::ensure!(
        complete,
        "Identify every other 1.x profile before reviewing the move. If the inventory is unknown, keep using 1.x until it can be established."
    );
    let source = PathBuf::from(source.trim());
    let profiles = preserved
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        source.is_absolute() && profiles.iter().all(|path| path.is_absolute()),
        "Use absolute paths for the source and every preserved profile."
    );
    anyhow::ensure!(
        profiles.len() <= 32,
        "At most 32 preserved profiles are supported; do not omit a profile to bypass this limit."
    );
    anyhow::ensure!(
        !profiles.contains(&source),
        "The source cannot also be a preserved profile."
    );
    Ok((
        source,
        ProfileInventory::ReviewedComplete {
            preserve_profiles: profiles,
        },
    ))
}

fn inventory_text(summary: &MoveSummary) -> String {
    let mut text = format!(
        "Source: {}\n\nAccounts (exact instance and address):\n",
        summary.source.display()
    );
    for wallet in &summary.accounts {
        let disposition = if summary
            .retained_shared_accounts
            .contains(&wallet.instance_id)
        {
            "Retain old credential: shared with a preserved profile"
        } else {
            "Delete old account credential only after destination verification"
        };
        let _ = writeln!(
            text,
            "\n{}\n{}\n{}\n{}",
            wallet.id, wallet.address, wallet.instance_id, disposition
        );
    }
    text.push_str("\nPreserved 1.x profiles:\n");
    for path in &summary.preserved_profiles {
        let _ = writeln!(text, "{}", path.display());
    }
    if summary.preserved_profiles.is_empty() {
        text.push_str("None declared\n");
    }
    text.push_str("\nStored data included:\n");
    for (table, rows) in &summary.tables {
        let _ = writeln!(text, "{table}: {rows} rows");
    }
    text
}

impl MoveWindow {
    fn finished(&self) -> bool {
        // The reviewed source is consumed exactly once by move_and_cleanup.
        self.summary.is_some() && self.reviewed.is_none() && !self.busy
    }
    pub(super) const fn busy(&self) -> bool {
        self.busy
    }
    fn review(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.finished() {
            return;
        }
        let selection = selected_profiles(
            self.source_input.read(cx).value().as_ref(),
            self.preserved_input.read(cx).value().as_ref(),
            self.inventory_complete,
        );
        let (source, inventory) = match selection {
            Ok(selection) => selection,
            Err(error) => {
                self.message = Some(error.to_string());
                cx.notify();
                return;
            }
        };
        self.busy = true;
        self.reviewed = None;
        self.summary = None;
        self.deletion_confirmed = false;
        self.message = Some(
            "Waiting for owner authorization to read and lock the selected 1.x profiles.".into(),
        );
        let owner = self.owner.clone();
        let runtime = gpui_tokio::Tokio::handle(cx);
        let worker = runtime.clone();
        let task = runtime.spawn_blocking(move || {
            worker.block_on(async move {
                let status = owner.legacy_move_status().await?;
                anyhow::ensure!(
                    owner.uses_service() && !matches!(&status, ekubo_wallet_core::legacy_move::MoveStatus::Complete { .. })
                        && (status.pending() || owner.accounts().await?.is_empty()),
                    "Moving from 1.x requires an empty destination or its pending cleanup receipt."
                );
                let reviewed = LegacySource::review(source, inventory).await?;
                if let ekubo_wallet_core::legacy_move::MoveStatus::PendingCleanup { binding, .. } = status {
                    let summary = reviewed.summary();
                    anyhow::ensure!(summary.source == binding.source
                        && summary.preserved_profiles == binding.preserved_profiles
                        && summary.retained_shared_accounts == binding.retained_shared_accounts,
                        "Resume must review the exact source and preserved-profile inventory bound to the destination receipt.");
                }
                Ok(reviewed)
            })
        });
        cx.spawn(async move |view, cx| {
            let result = task.await.unwrap_or_else(|error| Err(error.into()));
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                match result {
                    Ok(source) => {
                        view.summary = Some(source.summary().clone());
                        view.reviewed = Some(source);
                        view.message = None;
                    }
                    Err(error) => {
                        view.message = Some(format!("Could not review this source: {error:#}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn move_reviewed(&mut self, cx: &mut Context<Self>) {
        if self.busy || !self.deletion_confirmed || self.finished() {
            return;
        }
        let Some(source) = self.reviewed.take() else {
            return;
        };
        self.busy = true;
        self.message = Some("Moving the reviewed state, verifying the protected destination, then requesting owner authorization for old account-credential cleanup. Keep this window open.".into());
        let runtime = gpui_tokio::Tokio::handle(cx);
        let worker = runtime.clone();
        let task = runtime.spawn_blocking(move || worker.block_on(source.move_and_cleanup()));
        cx.spawn(async move |view, cx| {
            let result = task.await.unwrap_or_else(|error| Err(error.into()));
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                view.message = Some(match result {
                    Ok(report) => format!(
                        "Destination verified. Deleted {} old account credential(s); {} already absent; {} shared account credential(s) retained.\nThe shared 1.x database credential is retained: {}. The old database and preserved profiles remain. Close and reopen v2 to reload the moved state.",
                        report.deleted_account_credentials.len(), report.already_absent.len(), report.retained_shared_accounts.len(), report.shared_database_credential_retained
                    ),
                    Err(error) => format!("Move or cleanup did not complete: {error:#}\nThe destination may already contain the moved state and cleanup may be partial. Keep both profiles. Close and reopen v2 to inspect the result before taking another action; this window will not replay the move."),
                });
                cx.notify();
            });
        }).detach();
        cx.notify();
    }
}

impl Render for MoveWindow {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div().size_full().flex().flex_col().p_6().gap_4().bg(cx.theme().background).text_color(cx.theme().foreground)
            .child(div().text_lg().font_semibold().child("Move from Ekubo Wallet 1.x"))
            .child(div().id("legacy-move-content").overflow_y_scroll().flex_1().min_h_0().flex().flex_col().gap_3()
                .child(selectable_label("Close 1.x first. A new move requires an empty v2 wallet; pending cleanup resumes against its exact committed destination receipt. Eligible old credentials are deleted only after core verifies the destination. Already-absent old keys can be verified against v2 during resume. The old database, its shared credential, and credentials shared with preserved profiles are retained. Retained copies and prior key exposure are not repaired by this move."))
                .when(self.summary.is_none() && !self.finished(), |panel| panel
                    .child(selectable_label("1.x source profile (absolute path)"))
                    .child(Input::new(&self.source_input).disabled(self.busy))
                    .child(selectable_label("Every other 1.x profile to preserve (one absolute path per line; leave blank only if none exist)"))
                    .child(Input::new(&self.preserved_input).disabled(self.busy))
                    .child(Checkbox::new("complete-legacy-inventory").checked(self.inventory_complete).disabled(self.busy)
                        .label("This is the complete list of my other 1.x profiles, including custom profiles. If blank, I confirm there are none.")
                        .on_click(cx.listener(|view, checked, _, cx| { view.inventory_complete = *checked; cx.notify(); }))))
                .when_some(self.summary.as_ref(), |panel, summary| panel
                    .child(selectable_label(inventory_text(summary)))
                    .when(!self.finished(), |panel| panel.child(Checkbox::new("confirm-legacy-deletion")
                        .checked(self.deletion_confirmed).disabled(self.busy)
                        .label("I reviewed this exact source and account inventory. I authorize moving it and deleting the eligible old account credentials only after the destination is verified, with the shared credentials shown above retained.")
                        .on_click(cx.listener(|view, checked, _, cx| { view.deletion_confirmed = *checked; cx.notify(); })))))
                .when_some(self.message.clone(), |panel, message| panel.child(div().id("legacy-move-status").role(Role::Status).child(selectable_label(message)))))
            .when(self.summary.is_none() && !self.finished(), |panel| panel.child(app_button("review-legacy-source").self_start().label("Review selected source…")
                .disabled(self.busy || !self.inventory_complete).on_click(cx.listener(|view, _, _, cx| view.review(cx)))))
            .when(self.reviewed.is_some(), |panel| panel
                .child(app_button("move-reviewed-legacy").self_start().label("Move and delete eligible old credentials").danger()
                    .disabled(self.busy || !self.deletion_confirmed).on_click(cx.listener(|view, _, _, cx| view.move_reviewed(cx))))
                .child(app_button("change-legacy-source").self_start().label("Change source").disabled(self.busy)
                    .on_click(cx.listener(|view, _, _, cx| { view.reviewed = None; view.summary = None; view.deletion_confirmed = false; cx.notify(); }))))
            .child(app_button("close-legacy-move").self_start().label(if self.finished() { "Open wallet" } else { "Close" }).disabled(self.busy)
                .on_click(cx.listener(|view, _, _, cx| {
                    view.restart.set(view.finished());
                    cx.quit();
                })))
    }
}

pub(super) fn create(
    owner: crate::desktop_owner::DesktopOwner,
    window: &mut Window,
    cx: &mut App,
    restart: Rc<Cell<bool>>,
    pending: Option<ekubo_wallet_core::legacy_move::MoveBinding>,
) -> Result<Entity<MoveWindow>> {
    anyhow::ensure!(
        !cfg!(target_os = "windows"),
        "Protected owner authorization is unavailable in this Windows build."
    );
    let suggested = match &pending {
        Some(binding) => binding.source.clone(),
        None => ekubo_wallet_core::legacy_move::suggested_legacy_root()?,
    };
    let preserved = pending.map_or_else(String::new, |binding| {
        binding
            .preserved_profiles
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    });
    Ok(create_with_path(
        owner, window, cx, restart, &suggested, &preserved,
    ))
}

fn create_with_path(
    owner: crate::desktop_owner::DesktopOwner,
    window: &mut Window,
    cx: &mut App,
    restart: Rc<Cell<bool>>,
    suggested: &std::path::Path,
    preserved: &str,
) -> Entity<MoveWindow> {
    cx.new(|cx| MoveWindow {
        owner,
        source_input: cx.new(|cx| {
            InputState::new(window, cx).default_value(suggested.to_string_lossy().to_string())
        }),
        preserved_input: cx.new(|cx| {
            InputState::new(window, cx)
                .multi_line(true)
                .default_value(preserved.to_owned())
        }),
        inventory_complete: false,
        deletion_confirmed: false,
        reviewed: None,
        summary: None,
        busy: false,
        message: None,
        restart,
    })
}

#[cfg(test)]
#[path = "desktop_legacy_move_test.rs"]
mod tests;
