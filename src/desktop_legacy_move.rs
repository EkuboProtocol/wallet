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
    /// Recovery from a pending cleanup whose 1.x source is unreadable or
    /// deleted. Grouped so the window stays under the boolean-count lint.
    /// `source_missing` is set only after a review/resume attempt fails with
    /// an absent source; a pending receipt alone never offers recovery.
    recovery: Recovery,
}

/// Pending-cleanup recovery state. A bound receipt alone never offers
/// recovery; only a review/resume failure proving the source is absent moves
/// past `AwaitingSource`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Recovery {
    /// No pending receipt, or recovery already resolved out of band.
    Unavailable,
    /// A receipt is pending but the source has not yet proven absent.
    AwaitingSource,
    /// A review/resume attempt failed with an absent source.
    Offered,
    /// The owner confirmed recovery of the absent source.
    Confirmed,
    /// Recovery completed.
    Done,
}

impl Recovery {
    fn offerable(self) -> bool {
        matches!(self, Self::Offered | Self::Confirmed)
    }
}

fn selected_profiles(
    source: &str,
    preserved: &str,
    complete: bool,
) -> Result<(PathBuf, ProfileInventory)> {
    anyhow::ensure!(
        complete,
        "Confirm whether you use any custom 1.x profiles. Add their paths above before continuing."
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

/// Offer source-less recovery only when a cleanup receipt is pending and the
/// failed review/resume ended because the 1.x source is absent. Generic
/// review errors (wrong paths, locked profiles, unreadable inventories) must
/// resume the exact source, never bypass it.
fn should_offer_recovery(has_pending_receipt: bool, error: &anyhow::Error) -> bool {
    has_pending_receipt && ekubo_wallet_core::legacy_move::is_source_missing(error)
}

fn recovery_message(report: &ekubo_wallet_core::legacy_move::CleanupReport) -> String {
    format!(
        "Pending cleanup finished after destination re-verification. Deleted {} old account credential(s); {} already absent; {} shared account credential(s) retained.\nThe shared 1.x database credential is retained: {}. Encrypted history is preserved in wallet.db.retired-v2-backup. Any retained shared signing key still remains accessible to 1.x. Close and reopen v2 to reload the moved state.",
        report.deleted_account_credentials.len(),
        report.already_absent.len(),
        report.retained_shared_accounts.len(),
        report.shared_database_credential_retained
    )
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
        text.push_str("None declared. The old global database credential will be deleted after verification.\n");
    } else {
        text.push_str("The old global database credential stays available to these profiles.\n");
    }
    if !summary.retained_shared_accounts.is_empty() {
        text.push_str("\nShared signing keys remain accessible to 1.x. These accounts do not have full key isolation.\n");
    }
    text.push_str("\nThe moved profile will be retired. Its encrypted database is kept as wallet.db.retired-v2-backup; its original database path will block 1.x startup. Do not remove or reset that retirement file.\n");
    text.push_str("\nStored data included:\n");
    for (table, rows) in &summary.tables {
        let _ = writeln!(text, "{table}: {rows} rows");
    }
    text
}

impl MoveWindow {
    fn finished(&self) -> bool {
        // The reviewed source is consumed exactly once by move_and_cleanup.
        // Recovery completes the pending receipt without a source review.
        !self.busy
            && (self.recovery == Recovery::Done
                || (self.summary.is_some() && self.reviewed.is_none()))
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
                        if should_offer_recovery(view.recovery == Recovery::AwaitingSource, &error)
                        {
                            view.recovery = Recovery::Offered;
                        }
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
                        "Destination verified and source profile retired. Deleted {} old account credential(s); {} already absent; {} shared account credential(s) retained.\nThe shared 1.x database credential is retained: {}. Encrypted history is preserved in wallet.db.retired-v2-backup. Any retained shared signing key still remains accessible to 1.x. Close and reopen v2 to reload the moved state.",
                        report.deleted_account_credentials.len(), report.already_absent.len(), report.retained_shared_accounts.len(), report.shared_database_credential_retained
                    ),
                    Err(error) => format!("Move or cleanup did not complete: {error:#}\nThe destination may already contain the moved state and cleanup may be partial. Keep both profiles. Close and reopen v2 to inspect the result before taking another action; this window will not replay the move."),
                });
                cx.notify();
            });
        }).detach();
        cx.notify();
    }

    /// Owner-authorized recovery when the 1.x source is gone but a cleanup
    /// receipt is pending. The window only carries intent. Sequencing, and
    /// who proves what where:
    /// 1. The service natively authenticates the owner and binds the pending
    ///    receipt (destination custody re-verified) — before anything else.
    /// 2. The desktop, running un-sandboxed as the login owner, proves the
    ///    bound source database is absent and mints the receipt-bound
    ///    absence attestation. The sandboxed service never re-stats.
    /// 3. The desktop retires the bound unshared 1.x credentials, which
    ///    requires the authorized receipt from step 1 — never a boolean.
    /// 4. The service re-verifies destination custody, re-validates the
    ///    attestation against the pending receipt, and finishes it.
    ///
    /// Steps 2–3 run synchronously on this blocking worker thread, outside
    /// async execution: the Secret Service adapter owns its own Tokio
    /// runtime, so retiring inside `block_on` would nest runtimes and panic.
    /// A refusal leaves the receipt pending so recovery retries cleanly;
    /// retirement itself is idempotent.
    fn complete_without_source(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.recovery != Recovery::Confirmed || self.finished() {
            return;
        }
        self.busy = true;
        self.message = Some("Requesting owner authorization, proving the 1.x source is absent, retiring the moved profile's unshared 1.x credentials, and finishing the pending cleanup. Keep this window open.".into());
        let owner = self.owner.clone();
        let runtime = gpui_tokio::Tokio::handle(cx);
        let worker = runtime.clone();
        let task = runtime.spawn_blocking(
            move || -> anyhow::Result<ekubo_wallet_core::legacy_move::CleanupReport> {
                let crate::desktop_owner::DesktopOwner::Service(client) = owner else {
                    anyhow::bail!("source-less recovery requires the v2 service");
                };
                // Step 1: owner-authorized service step before any mutation.
                // No 1.x credential is touched before this returns.
                let recovery =
                    worker.block_on(client.authorize_legacy_move_recovery(uuid::Uuid::new_v4()))?;
                // Steps 2–3 are synchronous on this blocking thread, outside
                // async execution, so the credential-store runtime may start.
                let Some(binding) = recovery.binding().cloned() else {
                    anyhow::bail!("no pending legacy move cleanup for this destination");
                };
                ekubo_wallet_core::legacy_move::require_source_absent(&binding.source)?;
                let absence = ekubo_wallet_core::legacy_move::RecoveryAbsence {
                    digest: recovery.digest(),
                    source: binding.source.clone(),
                };
                let report =
                    ekubo_wallet_core::legacy_move::retire_recovered_credentials(&recovery)?;
                // Step 4: finish with the receipt-bound attestation. A
                // refusal leaves the receipt pending; retirement is
                // idempotent so recovery retries cleanly.
                worker.block_on(
                    client.complete_legacy_move_recovery(uuid::Uuid::new_v4(), absence),
                )?;
                Ok(report)
            },
        );
        cx.spawn(async move |view, cx| {
            let result = task.await.unwrap_or_else(|error| Err(error.into()));
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                match result {
                    Ok(report) => {
                        view.recovery = Recovery::Done;
                        view.message = Some(recovery_message(&report));
                    }
                    Err(error) => {
                        view.message = Some(format!("Recovery did not complete: {error:#}\nThe pending cleanup was not marked complete. Unshared 1.x credentials may already be retired; keep both profiles and retry only after inspecting the result."));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
}

impl Render for MoveWindow {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div().size_full().flex().flex_col().p_6().gap_4().bg(cx.theme().background).text_color(cx.theme().foreground)
            .child(div().text_lg().font_semibold().child("Move from Ekubo Wallet 1.x"))
            .child(div().id("legacy-move-content").overflow_y_scroll().flex_1().min_h_0().flex().flex_col().gap_3()
                .child(selectable_label("Close 1.x, then review the suggested default profile or enter a custom path. After verifying v2, this move retires the selected profile and deletes its unshared credentials. Other profiles keep their required keys. Interrupted cleanup resumes from the protected destination, even after the old database key is gone. Encrypted history is preserved; previous key exposure cannot be undone."))
                .when(self.summary.is_none() && !self.finished(), |panel| panel
                    .child(selectable_label("1.x source profile (absolute path)"))
                    .child(Input::new(&self.source_input).disabled(self.busy))
                    .child(selectable_label("Other custom 1.x profiles you use (optional; one absolute path per line)"))
                    .child(Input::new(&self.preserved_input).disabled(self.busy))
                    .child(Checkbox::new("complete-legacy-inventory").checked(self.inventory_complete).disabled(self.busy)
                        .label("This is the complete list of my other 1.x profiles, including custom profiles. If blank, I confirm there are none.")
                        .on_click(cx.listener(|view, checked, _, cx| { view.inventory_complete = *checked; cx.notify(); }))))
                .when_some(self.summary.as_ref(), |panel, summary| panel
                    .child(selectable_label(inventory_text(summary)))
                    .when(!self.finished(), |panel| panel.child(Checkbox::new("confirm-legacy-deletion")
                        .checked(self.deletion_confirmed).disabled(self.busy)
                        .label("Retire this profile after verifying v2. Delete its unshared account credentials and, if no other profiles need it, the old database key. Keep the shared keys shown above.")
                        .on_click(cx.listener(|view, checked, _, cx| { view.deletion_confirmed = *checked; cx.notify(); })))))
                .when_some(self.message.clone(), |panel, message| panel.child(div().id("legacy-move-status").role(Role::Status).child(selectable_label(message)))))
                .when(self.recovery.offerable() && !self.finished(), |panel| panel
                    .child(selectable_label("A previous move left cleanup unfinished and the 1.x source cannot be read. If the 1.x profile or directory was deleted, the moved keys may still be sealed in v2. Recovery re-verifies the protected destination, retires the moved profile's unshared 1.x credentials after owner authorization, and finishes the pending cleanup. Shared keys stay with the preserved profiles bound to the receipt."))
                    .child(Checkbox::new("confirm-legacy-recovery")
                        .checked(self.recovery == Recovery::Confirmed).disabled(self.busy)
                        .label("The 1.x source is gone and I cannot restore it. Re-verify the destination, retire its unshared credentials, and finish the pending cleanup.")
                        .on_click(cx.listener(|view, checked, _, cx| {
                            if view.recovery == Recovery::Offered
                                || view.recovery == Recovery::Confirmed
                            {
                                view.recovery = if *checked {
                                    Recovery::Confirmed
                                } else {
                                    Recovery::Offered
                                };
                            }
                            cx.notify();
                        }))))
            .when(self.summary.is_none() && !self.finished(), |panel| panel.child(app_button("review-legacy-source").self_start().label("Review selected source…")
                .disabled(self.busy || !self.inventory_complete).on_click(cx.listener(|view, _, _, cx| view.review(cx)))))
            .when(self.reviewed.is_some(), |panel| panel
                .child(app_button("move-reviewed-legacy").self_start().label("Move and delete eligible old credentials").danger()
                    .disabled(self.busy || !self.deletion_confirmed).on_click(cx.listener(|view, _, _, cx| view.move_reviewed(cx))))
                .child(app_button("change-legacy-source").self_start().label("Change source").disabled(self.busy)
                    .on_click(cx.listener(|view, _, _, cx| { view.reviewed = None; view.summary = None; view.deletion_confirmed = false; cx.notify(); }))))
            .when(self.recovery == Recovery::Confirmed && !self.finished(), |panel| panel.child(app_button("complete-legacy-without-source").self_start().label("Re-verify and finish pending cleanup").danger()
                .disabled(self.busy).on_click(cx.listener(|view, _, _, cx| view.complete_without_source(cx)))))
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
    let suggested = match &pending {
        Some(binding) => binding.source.clone(),
        None => ekubo_wallet_core::legacy_move::suggested_legacy_root()?,
    };
    // A pending receipt alone never offers recovery: the checkbox appears
    // only after a review/resume attempt fails with the source absent.
    let pending_receipt = pending.is_some();
    let preserved = pending.map_or_else(String::new, |binding| {
        binding
            .preserved_profiles
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    });
    Ok(create_with_path(
        owner,
        window,
        cx,
        restart,
        &suggested,
        &preserved,
        pending_receipt,
    ))
}

fn create_with_path(
    owner: crate::desktop_owner::DesktopOwner,
    window: &mut Window,
    cx: &mut App,
    restart: Rc<Cell<bool>>,
    suggested: &std::path::Path,
    preserved: &str,
    pending_receipt: bool,
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
        recovery: if pending_receipt {
            Recovery::AwaitingSource
        } else {
            Recovery::Unavailable
        },
    })
}

#[cfg(test)]
#[path = "desktop_legacy_move_test.rs"]
mod tests;
