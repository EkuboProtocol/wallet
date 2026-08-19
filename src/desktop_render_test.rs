//! Every route and every overlay, laid out and painted.
//!
//! The wallet had no test that drew anything. Its interface is a single
//! 12,000-line render tree, and the two worst bugs in its history were layout
//! faults that no type checked and no unit test could reach: a single-line
//! input handed a newline aborted the process through `shape_line` when the
//! network editor opened, and a dialog capped at the viewport height put its
//! own footer below the bottom of the window. Both reached a person before
//! anything else noticed.
//!
//! These tests run on GPUI's fake platform, so they need no display — which is
//! the only reason they can run in CI, and the reason they could be written at
//! all on a machine with its lid shut. They assert layout, not appearance: a
//! surface that panics or lays out to nothing fails here, while whether a
//! colour is right is still a question for eyes.

use super::*;
use crate::authority::OwnerApi;
use ekubo_wallet_core::approval::{ApprovalKind, ApprovalRequest};

/// Serializes the render tests against each other.
///
/// Each one stands up a real GPUI application, a window, and the tokio bridge,
/// and then tears all three down. Two of those overlapping in one process
/// crashed it on exit — reliably when this file's tests were the only ones
/// running, and intermittently in a full suite run, where more surrounding work
/// changed the timing. One alone never crashed, and `--test-threads=1` never
/// crashed, which is what named the cause.
///
/// So the fixture hands out a lock rather than the tests each remembering to
/// take one: a render test that forgets is a flake nobody can reproduce on
/// demand, and the whole point of these tests is to be the thing that catches
/// layout regressions rather than the thing people learn to re-run.
static RENDER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Held for the life of one render test.
///
/// Poisoning is ignored on purpose. The mutex guards a process, not data: an
/// earlier test panicking says nothing about whether this one may run, and
/// failing every subsequent test with "poisoned" would hide the first real
/// failure behind twenty-five spurious ones.
fn render_test_lock() -> std::sync::MutexGuard<'static, ()> {
    RENDER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A wallet window over a throwaway database, with the component library, the
/// tokio bridge, and the embedded fonts initialised the way `run_desktop` does.
///
/// The first element of the returned tuple is the test's scope guard: the
/// temporary directory that outlives the window, and the serialization lock
/// above. Tests bind it as `_directory` and never touch it; dropping it at the
/// end of the test is the whole contract.
fn wallet(
    cx: &mut gpui::TestAppContext,
) -> (
    (tempfile::TempDir, std::sync::MutexGuard<'static, ()>),
    Entity<WalletWindow>,
    gpui::AnyWindowHandle,
) {
    let lock = render_test_lock();
    // The wallet reads its database and detects agents through `gpui_tokio`,
    // so completions arrive from a real tokio thread. The deterministic test
    // scheduler calls that non-determinism and fails the test at the end
    // unless it is told to expect it — the same hatch Zed's own tests use when
    // they bridge to a runtime they do not drive.
    cx.executor().allow_parking();
    let directory = tempfile::tempdir().expect("temp dir");
    let owner = cx.update(|cx| {
        gpui_component::init(cx);
        gpui_tokio::init(cx);
        load_application_fonts(cx).expect("embedded fonts must load");
        apply_interface_palette(cx);
        OwnerApi::for_test(directory.path()).expect("throwaway owner")
    });
    let (review_presenter, _reviews) = GuiReviewPresenter::channel();
    let (walletconnect_presenter, _proposals) = ProposalPresenter::channel();
    let walletconnect = Arc::new(Mutex::new(WalletConnectManager::default()));
    let window = cx.add_window(|_, cx| {
        WalletWindow::new(
            owner,
            review_presenter,
            walletconnect,
            walletconnect_presenter,
            Rc::new(RefCell::new(None)),
            Arc::new(Mutex::new(None)),
            directory.path(),
            cx,
        )
    });
    let view = window.root(cx).expect("root view");
    // The constructor starts two lookups on the tokio thread whose answers
    // depend on the machine and land whenever that thread gets to them:
    // agent detection, and on Linux the polkit probe. Either one changes the
    // height of the Settings page, and on a machine with agents installed
    // detection landed between two measurements of one test. Settle both
    // here for every test; a test about either section sets its own state.
    cx.update_entity(&view, |wallet, _| {
        // A result only lands for the generation that asked for it.
        wallet.detected_agents_generation = wallet.detected_agents_generation.wrapping_add(1);
        wallet.detected_agents = AgentDetectionState::Ready(Vec::new());
        // A probe result only ever replaces a state that is still `Probing`.
        #[cfg(target_os = "linux")]
        {
            wallet.owner_auth = OwnerAuthState::Ready;
        }
    });
    ((directory, lock), view, window.into())
}

/// Make a test's detected-agent list the one the page actually draws.
///
/// Assigning the field alone is not enough. Startup detection is a real read
/// of this machine's filesystem on a background task, and whenever it lands it
/// overwrites whatever a test put there — so on a machine that genuinely has
/// one of these agents installed, rows appear that the test never asked for
/// and every control below them moves. Which side of a `measure` the read
/// finished on decided whether the test passed, which is what made these
/// flake.
///
/// `refresh_detected_agents` already stamps each run with a generation and
/// drops a result whose generation has been superseded. Bumping it here uses
/// that existing guard rather than adding a test-only escape hatch: the
/// in-flight read still completes, and is still discarded.
fn supersede_agent_detection(wallet: &mut WalletWindow) {
    wallet.detected_agents_generation = wallet.detected_agents_generation.wrapping_add(1);
}

/// Wait for the background snapshot to arrive.
///
/// Without it every page renders its loading spinner and `route_panel` is
/// never called, so a test that only asserted "no panic" would pass while
/// drawing nothing it claimed to draw. The read happens on a real tokio
/// runtime this scheduler does not drive, so waiting means actually waiting.
fn settle(cx: &mut gpui::TestAppContext, view: &Entity<WalletWindow>) {
    cx.run_until_parked();
    cx.update_entity(view, |wallet, _| {
        // Whatever the background read made of this machine, the pages draw
        // from here.
        wallet.desktop_snapshot = Some(Arc::new(quiet_snapshot()));
        wallet.desktop_snapshot_error = None;
        wallet.legal_gate = false;
        wallet.legal_review = None;
    });
    cx.run_until_parked();
}

/// A snapshot with nothing waiting and the shipped networks configured.
///
/// Built by hand rather than read, and that is the point: every read on
/// `OwnerApi` opens a keychain-backed store, so a snapshot captured for real
/// needs an unlocked keychain, which needs a display. Rendering reads only
/// this cached value, so handing it over directly is what lets these tests
/// draw the actual pages on any machine — including a CI runner and a laptop
/// with its lid shut.
fn quiet_snapshot() -> DesktopSnapshot {
    let accepted = |digest: &str| ekubo_wallet_core::legal::DocumentStatus {
        accepted: true,
        current_digest: digest.to_owned(),
        accepted_at: Some(chrono::Utc::now()),
        superseded_digest: None,
    };
    DesktopSnapshot {
        reviews: Ok(crate::authority::OwnerReviewQueues {
            transactions: Vec::new(),
            typed_data: Vec::new(),
            messages: Vec::new(),
            policy_proposals: Vec::new(),
            network_proposals: Vec::new(),
            token_proposals: Vec::new(),
        }),
        activity: Ok(Arc::from(Vec::new())),
        activity_sources: BTreeMap::new(),
        accounts: Ok(Vec::new()),
        automations: Ok(Vec::new()),
        automation_runs: BTreeMap::new(),
        policies: BTreeMap::new(),
        legal_status: Ok(LegalStatus {
            signing_allowed: true,
            terms_of_service: accepted("terms"),
            privacy_policy: accepted("privacy"),
        }),
        networks: Ok(ekubo_wallet_core::config::default_networks()),
        message_documents: BTreeMap::new(),
        typed_data_documents: BTreeMap::new(),
        native_token_prices: BTreeMap::new(),
    }
}

/// The viewport these tests lay out in.
///
/// Deliberately wider than the 960 the wallet opens at: the width-dependent
/// choices this round — the settings measure, the anchored buttons — only
/// misbehave on a wide window, which is where they were reported from.
const VIEWPORT: gpui::Size<gpui::Pixels> = gpui::Size {
    width: px(1400.0),
    height: px(900.0),
};

/// Release everything the window owns and let its in-flight work finish.
///
/// GPUI fails a test that ends with a live entity handle, and a first render
/// builds two searchable lists and twenty-odd inputs, plus a detached task
/// holding one of the lists while it reads the token inventory. Dropping the
/// fields is not enough on its own — the task has to be allowed to finish, or
/// its clone of the handle outlives the app.
fn release(cx: &mut gpui::TestAppContext, view: &Entity<WalletWindow>) {
    cx.update_entity(view, WalletWindow::release_window_state);
    for _ in 0..200 {
        cx.run_until_parked();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    cx.run_until_parked();
}

/// Wait for whatever snapshot read is in flight to land.
///
/// `DesktopSnapshot::capture` runs on a blocking thread this scheduler does not
/// drive, so a test that acts while one is in flight is racing it.
fn settle_snapshot(cx: &mut gpui::TestAppContext, view: &Entity<WalletWindow>) {
    for _ in 0..200 {
        cx.run_until_parked();
        if cx.update_entity(view, |wallet, _| !wallet.desktop_snapshot_loading) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    cx.run_until_parked();
}

/// Lay out and paint the whole view tree, then let what it spawned settle.
///
/// Marking the window dirty is not enough — nothing in a test drives the
/// platform's redraw — so the view is drawn explicitly. That distinction
/// matters: a test that only refreshed passed while rendering nothing, which
/// is the failure mode these tests exist to rule out.
fn draw(cx: &mut gpui::TestAppContext, window: gpui::AnyWindowHandle, view: &Entity<WalletWindow>) {
    let _ = measure(cx, window, view, &[]);
}

/// Draw, and read back where the named elements actually ended up.
///
/// The two things reported from using this build were both geometry — a
/// control sitting a hand's width from its label, and a button as wide as the
/// page — so those are measured here rather than argued in a commit message.
/// `debug_selector` is a no-op in release builds, so the anchors cost nothing.
fn measure(
    cx: &mut gpui::TestAppContext,
    window: gpui::AnyWindowHandle,
    view: &Entity<WalletWindow>,
    selectors: &[&'static str],
) -> Vec<Option<gpui::Bounds<gpui::Pixels>>> {
    measure_at(cx, window, view, VIEWPORT, selectors)
}

/// A `rem`-denominated interface constant, in the pixels this window resolves
/// it to.
///
/// The chrome's widths and heights are relative now, and a laid-out bound is
/// still absolute, so an assertion comparing the two has to convert one of
/// them. It asks the window rather than assuming 16: these tests open a bare
/// `WalletWindow` rather than the `Root` the application wraps it in, and
/// `Root` is what copies `theme.font_size` onto the window's rem — so if
/// either of those ever changes, this follows instead of quietly passing.
fn resolved(
    cx: &mut gpui::TestAppContext,
    window: gpui::AnyWindowHandle,
    length: gpui::Rems,
) -> gpui::Pixels {
    let rem = cx
        .update_window(window, |_, window, _| window.rem_size())
        .expect("the window must still be open");
    length.to_pixels(rem)
}

fn measure_at(
    cx: &mut gpui::TestAppContext,
    window: gpui::AnyWindowHandle,
    view: &Entity<WalletWindow>,
    viewport: gpui::Size<gpui::Pixels>,
    selectors: &[&'static str],
) -> Vec<Option<gpui::Bounds<gpui::Pixels>>> {
    let mut visual = gpui::VisualTestContext::from_window(window, cx);
    let view = view.clone();
    visual.draw(gpui::point(px(0.0), px(0.0)), viewport, |_, _| {
        gpui::AnyView::from(view).into_any_element()
    });
    let bounds = selectors
        .iter()
        .map(|selector| visual.debug_bounds(selector))
        .collect();
    visual.run_until_parked();
    bounds
}

/// Draw, then press the named element in the middle of wherever it landed.
///
/// Whether something is clickable at all is only answerable from outside: a
/// row that navigates and a row that is inert look identical in the tree, and
/// the difference between them is the whole point of a finished task.
fn click(
    cx: &mut gpui::TestAppContext,
    window: gpui::AnyWindowHandle,
    view: &Entity<WalletWindow>,
    selector: &'static str,
) {
    let mut visual = gpui::VisualTestContext::from_window(window, cx);
    let drawn = view.clone();
    visual.draw(gpui::point(px(0.0), px(0.0)), VIEWPORT, |_, _| {
        gpui::AnyView::from(drawn).into_any_element()
    });
    let bounds = visual
        .debug_bounds(selector)
        .unwrap_or_else(|| panic!("{selector} did not draw, so it cannot be pressed"));
    visual.simulate_click(bounds.center(), gpui::Modifiers::none());
    visual.run_until_parked();
}

/// Hosts the network form in a real view so entity-backed inputs have the
/// rendered-view context GPUI requires during prepaint.
struct NetworkEditorFormTestView {
    wallet: Entity<WalletWindow>,
}

impl Render for NetworkEditorFormTestView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.wallet
            .read(cx)
            .render_network_editor_form(&self.wallet.downgrade(), cx)
    }
}

#[gpui::test]
fn every_route_lays_out(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    for route in Route::ALL {
        cx.update_entity(&view, |wallet, _| wallet.set_route(route));
        draw(cx, window, &view);
    }
    release(cx, &view);
}

#[gpui::test]
fn scrollbar_tracks_stay_hidden_in_favor_of_the_overflow_chevron(cx: &mut gpui::TestAppContext) {
    let (_directory, view, _window) = wallet(cx);
    cx.read(|cx| {
        let theme = Theme::global(cx);
        assert!(theme.colors.scrollbar_thumb.a.abs() < f32::EPSILON);
        assert!(theme.colors.scrollbar_thumb_hover.a.abs() < f32::EPSILON);
    });
    release(cx, &view);
}

/// The gutter is drawn over the text, so an unfilled one lets a horizontally
/// scrolled policy pass under its own line numbers.
#[gpui::test]
fn the_code_gutter_is_filled_so_scrolled_text_cannot_run_under_it(cx: &mut gpui::TestAppContext) {
    let (_directory, view, _window) = wallet(cx);
    cx.read(|cx| {
        let theme = Theme::global(cx);
        assert_eq!(
            theme.highlight_theme.style.editor_gutter_background,
            Some(theme.colors.secondary),
            "the gutter must match the field the editor is drawn on"
        );
    });
    release(cx, &view);
}

#[gpui::test]
fn an_accounts_page_that_fits_has_no_phantom_scroll_range(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::Accounts));
    draw(cx, window, &view);

    let max = cx.read_entity(&view, |wallet, _| wallet.route_scroll_handle.max_offset());
    assert_eq!(max.x, px(0.0), "Accounts must not scroll horizontally");
    assert_eq!(
        max.y,
        px(0.0),
        "page padding must not manufacture vertical scroll space when Accounts fits"
    );
    release(cx, &view);
}

#[gpui::test]
fn settings_remain_scrollable_in_a_short_window(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Settings);
        supersede_agent_detection(wallet);
        wallet.detected_agents = AgentDetectionState::Ready(Vec::new());
    });
    let short = gpui::size(px(900.0), px(420.0));
    let initial = measure_at(cx, window, &view, short, &["route-content-scroll"])[0]
        .expect("the settings scroll viewport must be laid out");
    assert!(
        initial.size.height >= px(180.0),
        "a short window must preserve a usable settings viewport: {initial:?}"
    );
    let max = cx.read_entity(&view, |wallet, _| wallet.route_scroll_handle.max_offset());
    assert!(max.y > px(0.0), "short settings must expose real overflow");

    cx.read_entity(&view, |wallet, _| {
        wallet.route_scroll_handle.scroll_to_bottom();
    });
    let bottom = measure_at(cx, window, &view, short, &["route-content-scroll"])[0]
        .expect("the settings viewport must remain laid out");
    assert!(bottom.size.height >= px(180.0));
    let (offset, max) = cx.read_entity(&view, |wallet, _| {
        (
            wallet.route_scroll_handle.offset(),
            wallet.route_scroll_handle.max_offset(),
        )
    });
    assert_eq!(
        offset.y, -max.y,
        "short settings must be able to reach their true bottom"
    );
    release(cx, &view);
}

#[gpui::test]
fn the_command_palette_lays_out_over_a_page(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    // The scrim is a full-window occluding parent added this round, and the
    // palette is absolutely positioned inside it.
    cx.update_entity(&view, |wallet, _| wallet.command_palette = true);
    draw(cx, window, &view);
    release(cx, &view);
}

#[gpui::test]
fn a_record_detail_lays_out_with_its_fixed_footer(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    // A selection naming no record is dropped during render — the notification
    // case fixed this round — so this also exercises that reconciliation.
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Activity);
        wallet.selected_record = Some(uuid::Uuid::new_v4());
    });
    draw(cx, window, &view);
    cx.update_entity(&view, |wallet, _| {
        assert!(
            wallet.desktop_snapshot.is_some(),
            "the snapshot must have loaded before this claim means anything"
        );
        assert!(
            wallet.cached_activity_records().is_ok(),
            "the activity read must succeed or the reconciliation cannot run: {:?}",
            wallet
                .cached_activity_records()
                .err()
                .map(|e| e.to_string())
        );
        assert!(
            wallet.selected_record.is_none(),
            "a selection the snapshot cannot account for must not survive a frame"
        );
    });
    release(cx, &view);
}

/// Clearing history hides finished records rather than deleting them, exactly
/// so an automation run's link to the transaction it produced keeps resolving.
/// The window only ever looked for the record in the visible list, so following
/// one after a tidy-up dropped the selection on the next frame and left the
/// reader on an empty inbox with nothing open.
#[gpui::test]
fn a_transaction_cleared_from_history_still_opens_from_the_run_that_made_it(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let request_id = uuid::Uuid::new_v4();
    let record =
        OwnerActivityRecord::Transaction(Box::new(cleared_transaction_fixture(request_id)));
    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        // The list after a clear: the row is hidden, so nothing here has it.
        snapshot.activity = Ok(Arc::from(Vec::new()));
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Activity);
        wallet.detached_activity_records.insert(request_id, record);
        wallet.selected_record = Some(request_id);
    });

    let laid_out = measure(cx, window, &view, &["activity-detail-overlay"]);
    assert!(
        laid_out[0].is_some(),
        "a record the list has forgotten must still draw its detail"
    );
    cx.update_entity(&view, |wallet, _| {
        assert_eq!(
            wallet.selected_record,
            Some(request_id),
            "the selection must survive the frame that reconciles it against the list"
        );
    });
    release(cx, &view);
}

fn cleared_transaction_fixture(request_id: uuid::Uuid) -> PendingTransaction {
    let now = chrono::Utc::now();
    serde_json::from_value(serde_json::json!({
        "request_id": request_id,
        "wallet_instance_id": uuid::Uuid::new_v4(),
        "wallet_id": "primary",
        "wallet_address": "0x1111111111111111111111111111111111111111",
        "network_name": "ethereum",
        "chain_id": "1",
        "execution_plan": {
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0x",
                    "value": "1"
                }
            }]
        },
        "plan_source": "an automation",
        "digest": "0x00",
        "policy_revision": 1,
        "approval_required": false,
        "status": "confirmed",
        "created_at": now,
        "updated_at": now
    }))
    .expect("test transaction")
}

#[gpui::test]
fn an_expanded_multi_megabyte_transaction_payload_stays_virtual_and_scrollable(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let request_id = uuid::Uuid::new_v4();
    let wallet_instance_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let transaction: PendingTransaction = serde_json::from_value(serde_json::json!({
        "request_id": request_id,
        "wallet_instance_id": wallet_instance_id,
        "wallet_id": "primary",
        "wallet_address": "0x1111111111111111111111111111111111111111",
        "network_name": "ethereum",
        "chain_id": "1",
        "execution_plan": {
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0x",
                    "value": "1"
                }
            }]
        },
        "plan_source": "inline data URI",
        "digest": "0x00",
        "policy_revision": 1,
        "approval_required": true,
        "status": "rejected",
        "created_at": now,
        "updated_at": now
    }))
    .expect("test transaction");
    let payload = format!(
        "{{\n{}\n}}",
        (0..32_768)
            .map(|index| format!("  \"field_{index}\": \"{}\"", "a".repeat(48)))
            .collect::<Vec<_>>()
            .join(",\n")
    );
    assert!(payload.len() > 2 * 1024 * 1024);
    let chunk_count = exact_payload_chunk_ranges(&payload).len();
    let document = ReviewDocument::from_request(
        ApprovalRequest::new(
            ApprovalKind::Transaction,
            "Large transaction",
            "The exact execution plan remains available without one enormous text layout.",
        ),
        vec![payload],
    );
    let ready = Rc::new(ReadyActivityInspection::new(OwnerTransactionInspection {
        document,
        receipt_loaded: false,
        receipt_error: None,
    }));
    ready.set_exact_payload_expanded(true);

    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.activity = Ok(Arc::from(vec![OwnerActivityRecord::Transaction(Box::new(
            transaction,
        ))]));
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Activity);
        wallet.selected_record = Some(request_id);
        wallet
            .activity_inspections
            .insert(request_id, ActivityInspectionState::Ready(ready.clone()));
        wallet
            .activity_payloads_expanded
            .insert((request_id, "execution-plan".to_owned()));
    });

    draw(cx, window, &view);
    assert_eq!(
        ready.detail_list.item_count(),
        2 + chunk_count,
        "the prelude, disclosure, and each bounded payload chunk stay separate virtual rows"
    );
    assert!(
        ready.detail_list.max_offset_for_scrollbar().y > px(0.0),
        "the expanded transaction detail must expose a real outer-list scroll range"
    );
    release(cx, &view);
}

#[gpui::test]
fn the_settings_pane_is_capped_to_a_readable_measure(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    // The cap is the whole of the fix for a control sitting a hand's width
    // from its label, so it is worth asserting rather than eyeballing.
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::Settings));
    let measured = measure(cx, window, &view, &["settings-pane", "settings-prose"]);
    let pane = measured[0].expect("the settings pane must have been laid out");
    // A row wants the full measure so its control can sit at the right edge.
    // The sentence under the row does not: measured, this prose ran 634px,
    // which at 14px is about ninety characters a line against a comfortable
    // band nearer sixty-five to seventy-five.
    let prose = measured[1].expect("the settings prose must have been laid out");
    let prose_measure = resolved(cx, window, PROSE_MEASURE);
    let page_measure = resolved(cx, window, PAGE_CONTENT_MAX_WIDTH);
    assert!(
        prose.size.width <= prose_measure,
        "explanatory text must stay inside a readable measure: it was {:?}",
        prose.size.width
    );
    assert!(
        pane.size.width <= page_measure,
        "the settings pane must stay within its measure, not stretch to the \
         {VIEWPORT:?} window: it was {:?}",
        pane.size.width
    );
    release(cx, &view);
}

#[gpui::test]
fn every_route_uses_the_same_centered_content_measure(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let page_measure = resolved(cx, window, PAGE_CONTENT_MAX_WIDTH);
    for route in Route::ALL {
        cx.update_entity(&view, |wallet, _| wallet.set_route(route));
        let measured = measure(
            cx,
            window,
            &view,
            &["route-header-inner", "route-content-inner"],
        );
        let header = measured[0].expect("the fixed route header must be laid out");
        let content = measured[1].expect("the scrolling route content must be laid out");
        assert!(
            header.size.width <= page_measure,
            "{} header exceeded the shared measure: {:?}",
            route.label(),
            header.size.width
        );
        assert!(
            content.size.width <= page_measure,
            "{} content exceeded the shared measure: {:?}",
            route.label(),
            content.size.width
        );
        assert_eq!(
            header.origin.x,
            content.origin.x,
            "{} header and body must share a left edge",
            route.label()
        );
    }
    release(cx, &view);
}

#[gpui::test]
fn inbox_tabs_render_one_queue_at_a_time(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::Activity));

    let waiting = measure(
        cx,
        window,
        &view,
        &["activity-waiting-panel", "activity-decided-panel"],
    );
    assert!(waiting[0].is_some());
    assert!(waiting[1].is_none());

    cx.update_entity(&view, |wallet, cx| {
        wallet.set_inbox_tab(InboxTab::Decided, cx);
    });
    let decided = measure(
        cx,
        window,
        &view,
        &["activity-waiting-panel", "activity-decided-panel"],
    );
    assert!(decided[0].is_none());
    assert!(decided[1].is_some());
    release(cx, &view);
}

/// Opening the inbox asks what needs you now, and pressing its rail button
/// while it is already open asks again. Both used to land on whichever tab was
/// read last, so a person who had once looked at history kept arriving in it.
#[gpui::test]
fn re_entering_the_inbox_returns_to_the_waiting_queue(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    cx.update_entity(&view, |wallet, cx| {
        wallet.navigate_route(Route::Activity, cx);
        wallet.set_inbox_tab(InboxTab::Decided, cx);
        wallet.navigate_route(Route::Overview, cx);
        assert_eq!(
            wallet.inbox_tab,
            InboxTab::Decided,
            "leaving the tab is not what resets it"
        );
        wallet.navigate_route(Route::Activity, cx);
        assert_eq!(
            wallet.inbox_tab,
            InboxTab::Waiting,
            "returning to the inbox must land on the waiting queue"
        );

        wallet.set_inbox_tab(InboxTab::Decided, cx);
        wallet.navigate_route(Route::Activity, cx);
        assert_eq!(
            wallet.inbox_tab,
            InboxTab::Waiting,
            "pressing the inbox while already in it must return to the waiting queue"
        );
    });
    draw(cx, window, &view);
    release(cx, &view);
}

/// History only grows, and it used to grow the page: two hundred records laid
/// out two hundred cards and pushed the tab bar off the top of the window.
/// The list holds the window's height and scrolls inside it instead.
#[gpui::test]
fn a_long_history_scrolls_inside_the_inbox_rather_than_the_page(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let records = (0..200)
        .map(|_| {
            OwnerActivityRecord::Transaction(Box::new(cleared_transaction_fixture(
                uuid::Uuid::new_v4(),
            )))
        })
        .collect::<Vec<_>>();
    cx.update_entity(&view, |wallet, cx| {
        let mut snapshot = quiet_snapshot();
        snapshot.activity = Ok(Arc::from(records));
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Activity);
        wallet.set_inbox_tab(InboxTab::Decided, cx);
    });

    let bounds = measure(
        cx,
        window,
        &view,
        &[
            "activity-decided-panel",
            "activity-records",
            "route-content-scroll",
        ],
    );
    let panel = bounds[0].expect("the history panel must draw");
    let records = bounds[1].expect("the history list must draw");
    let scroll = bounds[2].expect("the route's scroll region must draw");
    assert!(
        panel.bottom() <= scroll.bottom() + px(1.0),
        "the inbox must keep the window's height rather than growing with its history: \
         it ended at {} against a window bottom of {}",
        panel.bottom(),
        scroll.bottom()
    );
    assert!(
        records.bottom() <= scroll.bottom() + px(1.0),
        "the history list must end inside the window: it ended at {} against a window bottom of {}",
        records.bottom(),
        scroll.bottom()
    );
    release(cx, &view);
}

/// The two facts under the balances — which balances are listed, and how old
/// they are — belong on one line at the bottom of the tab, and have to stay on
/// screen however many balances the account holds.
#[gpui::test]
fn the_portfolio_footer_stays_on_screen_under_a_long_list(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let account = WalletMetadata {
        instance_id: uuid::Uuid::nil(),
        id: "primary".into(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    };
    let network = ekubo_wallet_core::config::default_networks()
        .first()
        .expect("a shipped network")
        .clone();
    let tokens = (0..250u32)
        .map(|index| ekubo_wallet_core::token_store::PortfolioToken {
            address: format!("0x{index:040x}"),
            symbol: Some(format!("TKN{index}")),
            name: Some(format!("Token {index}")),
            decimals: Some(18),
            balance: "1000000000000000000".to_owned(),
            // Priced, so the long list this test lays out is the list the tab
            // shows by default rather than the one the dust filter hid.
            approximate_usd_price: Some(12.5),
        })
        .collect::<Vec<_>>();
    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account.clone()]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.portfolio = PortfolioState::Ready(crate::authority::OwnerPortfolioSnapshot {
            accounts: vec![OwnerPortfolioAccount {
                wallet: account,
                networks: vec![crate::authority::OwnerPortfolioNetwork {
                    network: network.clone(),
                    result: Ok(ekubo_wallet_core::token_store::Portfolio {
                        address: "0x0000000000000000000000000000000000000000".to_owned(),
                        chain_id: network.chain_id.to_string(),
                        network: network.name.clone(),
                        native_balance: "1000000000000000000".to_owned(),
                        block_number: "1".to_owned(),
                        tokens,
                        tokens_checked: 250,
                        tokens_skipped: None,
                        fork: None,
                    }),
                    ekubo_positions: Ok(crate::authority::OwnerEkuboPositions {
                        positions: Vec::new(),
                        total_items: 0,
                    }),
                }],
            }],
        });
        wallet
            .portfolio_refreshed_at
            .insert("primary".to_owned(), chrono::Utc::now());
        wallet.set_route(Route::Overview);
    });

    let bounds = measure(
        cx,
        window,
        &view,
        &[
            "portfolio-balances",
            "portfolio-footer",
            "portfolio-refreshed-at",
            "route-content-scroll",
        ],
    );
    let balances = bounds[0].expect("the balance list must draw");
    let footer = bounds[1].expect("the footer must draw");
    let refreshed = bounds[2].expect("the refreshed line must draw");
    let scroll = bounds[3].expect("the route's scroll region must draw");
    assert!(
        footer.bottom() <= scroll.bottom() + px(1.0),
        "the footer must stay in the window: it ended at {} against a window bottom of {}",
        footer.bottom(),
        scroll.bottom()
    );
    assert!(
        balances.bottom() <= footer.origin.y + px(1.0),
        "the balances must end above the footer rather than running under it"
    );
    assert!(
        refreshed.origin.x > footer.center().x,
        "the refreshed line belongs on the right of the footer, opposite the note about \
         which balances are listed"
    );
    release(cx, &view);
}

#[gpui::test]
fn claude_connector_instructions_require_detected_claude_desktop(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Settings);
        supersede_agent_detection(wallet);
        wallet.detected_agents = AgentDetectionState::Ready(Vec::new());
    });
    assert!(
        measure(cx, window, &view, &["claude-desktop-hosted-connector"],)[0].is_none(),
        "hosted connector instructions must stay hidden without Claude Desktop"
    );

    cx.update_entity(&view, |wallet, _| {
        supersede_agent_detection(wallet);
        wallet.detected_agents = AgentDetectionState::Ready(vec![DetectedAgent {
            kind: AgentKind::ClaudeDesktop,
            display_name: "Claude Desktop",
            config_path: "/tmp/Claude/claude_desktop_config.json".into(),
            installed: Ok(false),
        }]);
    });
    assert!(
        measure(cx, window, &view, &["claude-desktop-hosted-connector"],)[0].is_some(),
        "detected Claude Desktop must expose its account-connector instructions"
    );
    release(cx, &view);
}

#[gpui::test]
fn every_detected_agent_has_its_own_configuration_action(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Settings);
        supersede_agent_detection(wallet);
        wallet.detected_agents = AgentDetectionState::Ready(vec![
            DetectedAgent {
                kind: AgentKind::Codex,
                display_name: "Codex",
                config_path: "/tmp/codex.toml".into(),
                installed: Ok(true),
            },
            DetectedAgent {
                kind: AgentKind::Cursor,
                display_name: "Cursor",
                config_path: "/tmp/cursor.json".into(),
                installed: Ok(false),
            },
        ]);
    });

    let actions = measure_at(
        cx,
        window,
        &view,
        gpui::size(px(1400.0), px(1400.0)),
        &["configure-detected-agent-0", "configure-detected-agent-1"],
    );
    assert!(
        actions.iter().all(Option::is_some),
        "installed and uninstalled agents must each expose their own action: {actions:?}"
    );
    release(cx, &view);
}

#[gpui::test]
fn checking_for_updates_keeps_the_action_in_place(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Settings);
        supersede_agent_detection(wallet);
        wallet.detected_agents = AgentDetectionState::Ready(Vec::new());
        wallet.release_state = ReleaseDisplayState::Idle;
    });
    let idle = measure(cx, window, &view, &["check-latest-release"])[0]
        .expect("the idle update action must be laid out");

    cx.update_entity(&view, |wallet, _| {
        wallet.release_state = ReleaseDisplayState::Checking;
    });
    let checking = measure(cx, window, &view, &["check-latest-release"])[0]
        .expect("the checking update action must remain laid out");
    assert_eq!(
        checking, idle,
        "checking must disable the existing action without moving or resizing it"
    );
    assert!(
        measure(cx, window, &view, &["release-check-progress"])[0].is_some(),
        "the version-status line must show checking progress and its spinner"
    );
    release(cx, &view);
}

#[cfg(target_os = "linux")]
#[gpui::test]
fn a_missing_polkit_policy_offers_one_click_install_and_the_manual_command(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Settings);
        wallet.detected_agents = AgentDetectionState::Ready(Vec::new());
        wallet.release_state = ReleaseDisplayState::Idle;
        wallet.owner_auth = OwnerAuthState::PolicyMissing {
            source: Ok("/home/owner/.local/share/ekubo-wallet/com.ekubo.wallet.policy".into()),
            pkexec: true,
            actions_dir: ekubo_wallet_core::polkit::ActionsDir::Writable,
            installing: false,
            error: None,
        };
    });
    let missing = measure(
        cx,
        window,
        &view,
        &[
            "install-polkit-policy",
            "polkit-manual-install",
            "recheck-polkit",
        ],
    );
    assert!(
        missing.iter().all(Option::is_some),
        "a missing policy must offer the pkexec install, the shell fallback, and a re-check: {missing:?}"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet.owner_auth = OwnerAuthState::PolicyMissing {
            source: Ok("/home/owner/.local/share/ekubo-wallet/com.ekubo.wallet.policy".into()),
            pkexec: true,
            actions_dir: ekubo_wallet_core::polkit::ActionsDir::Writable,
            installing: true,
            error: None,
        };
    });
    let installing = measure(cx, window, &view, &["install-polkit-policy"])[0]
        .expect("the install action stays in place while pkexec prompts");
    assert_eq!(
        installing,
        missing[0].unwrap(),
        "installing must disable the action without moving it"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet.owner_auth = OwnerAuthState::PolicyMissing {
            source: Ok("/home/owner/.local/share/ekubo-wallet/com.ekubo.wallet.policy".into()),
            pkexec: false,
            actions_dir: ekubo_wallet_core::polkit::ActionsDir::Writable,
            installing: false,
            error: None,
        };
    });
    let no_pkexec = measure(
        cx,
        window,
        &view,
        &["install-polkit-policy", "polkit-manual-install"],
    );
    assert!(
        no_pkexec[0].is_none() && no_pkexec[1].is_some(),
        "without pkexec there is nothing to click, only the command to run: {no_pkexec:?}"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet.owner_auth = OwnerAuthState::PolicyMissing {
            source: Ok("/home/owner/.local/share/ekubo-wallet/com.ekubo.wallet.policy".into()),
            pkexec: true,
            actions_dir: ekubo_wallet_core::polkit::ActionsDir::ReadOnly,
            installing: false,
            error: None,
        };
    });
    let immutable = measure(
        cx,
        window,
        &view,
        &[
            "install-polkit-policy",
            "polkit-manual-install",
            "polkit-policy-file",
            "recheck-polkit",
        ],
    );
    assert!(
        immutable[0].is_none() && immutable[1].is_none(),
        "a read-only /usr offers neither pkexec nor sudo, which would both fail: {immutable:?}"
    );
    assert!(
        immutable[2].is_some() && immutable[3].is_some(),
        "it names the file to layer and can be re-checked: {immutable:?}"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet.owner_auth = OwnerAuthState::Ready;
    });
    let ready = measure(
        cx,
        window,
        &view,
        &[
            "polkit-ready",
            "install-polkit-policy",
            "polkit-manual-install",
        ],
    );
    assert!(ready[0].is_some(), "a ready backend says so");
    assert!(
        ready[1].is_none() && ready[2].is_none(),
        "a ready backend offers nothing to install: {ready:?}"
    );
    release(cx, &view);
}

#[gpui::test]
fn add_network_is_part_of_the_fixed_header(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::Networks));

    let measured = measure(
        cx,
        window,
        &view,
        &["route-header-inner", "network-header-action"],
    );
    let header = measured[0].expect("the fixed header must be laid out");
    let action = measured[1].expect("the add-network action must be laid out");
    assert!(action.origin.y >= header.origin.y);
    assert!(
        action.origin.y + action.size.height <= header.origin.y + header.size.height,
        "the add-network action must remain inside the fixed header"
    );
    release(cx, &view);
}

/// Reloading the background snapshot is what enabling, disabling, or adding a
/// network does, and it used to put an unlabelled spinner in the corner of the
/// title band on every page but the one that had already worked out the better
/// answer. A spinner there reports only that something, somewhere, is
/// happening: the list keeps showing the networks it last read, and the row
/// the owner pressed carries its own progress.
#[gpui::test]
fn reloading_the_snapshot_puts_no_spinner_in_the_title_band(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.desktop_snapshot = Some(Arc::new(quiet_snapshot()));
        wallet.desktop_snapshot_loading = true;
        wallet.set_route(Route::Networks);
    });

    let measured = measure(
        cx,
        window,
        &view,
        &["route-header-inner", "route-header-loading"],
    );
    measured[0].expect("the fixed header must be laid out");
    assert!(
        measured[1].is_none(),
        "a reloading snapshot must not add a spinner to the title band"
    );
    release(cx, &view);
}

#[gpui::test]
fn portfolio_refresh_sits_with_the_refreshed_line_and_not_in_the_header(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        }]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.desktop_snapshot_loading = true;
        wallet.portfolio = PortfolioState::Loading;
        wallet.set_route(Route::Overview);
    });

    let overview = measure(
        cx,
        window,
        &view,
        &[
            "refresh-portfolio",
            "route-header-loading",
            "portfolio-footer",
            "portfolio-refreshed-at",
        ],
    );
    // No balances have been read yet, so there is no age to print -- and this
    // is exactly when asking again is worth doing, so the control is here
    // whether or not the line beside it has anything to say.
    let refresh = overview[0].expect("the refresh control must draw");
    assert!(
        overview[1].is_none(),
        "the portfolio header must not add a redundant loading spinner"
    );
    let footer = overview[2].expect("the footer must draw");
    let refreshed = overview[3].expect("the refreshed line must draw");
    assert!(
        refresh.origin.y >= footer.origin.y - px(1.0)
            && refresh.bottom() <= footer.bottom() + px(1.0),
        "refresh belongs on the footer line, next to the age it would replace: it drew at \
         {refresh:?} against a footer of {footer:?}"
    );
    assert!(
        refresh.origin.x >= refreshed.origin.x - px(1.0)
            && refresh.right() <= refreshed.right() + px(1.0),
        "refresh belongs inside the refreshed line rather than beside it"
    );

    release(cx, &view);
}

/// What the open add/edit network dialog measured to in a window this size.
struct NetworkEditorLayout {
    /// The form's place in the dialog, between the title bar and the footer.
    form: gpui::Bounds<gpui::Pixels>,
    /// The pane the form scrolls in, which has to be the size of the space the
    /// form was given and not the size of the form.
    pane: gpui::Bounds<gpui::Pixels>,
    /// Save, which is the lowest thing in the dialog.
    save: gpui::Bounds<gpui::Pixels>,
    /// How tall the form's contents are, whether or not they fit.
    content: gpui::Pixels,
}

/// Draws the add/edit network dialog the way `Root` would.
///
/// `overlay(false)` is the one departure, and it is not about layout: the
/// overlay's mouse handling reads the window's `Root`, which a test window has
/// none of. The backdrop it drops is behind the dialog and the size of the
/// window either way.
struct NetworkEditorDialogTestView {
    wallet: Entity<WalletWindow>,
}

impl Render for NetworkEditorDialogTestView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        WalletWindow::build_network_editor_dialog(
            Dialog::new(cx),
            &self.wallet.downgrade(),
            window,
            cx,
        )
        .overlay(false)
    }
}

/// Draw the add/edit network dialog in a window of the given size.
fn draw_network_editor(
    cx: &mut gpui::TestAppContext,
    window: gpui::AnyWindowHandle,
    view: &Entity<WalletWindow>,
    viewport: gpui::Size<gpui::Pixels>,
) -> NetworkEditorLayout {
    // The wallet has to draw once before the dialog can: the form's twenty-odd
    // inputs are built on the wallet's first render, and the dialog renders
    // nothing without them.
    draw(cx, window, view);
    let dialog_view = cx.new(|_| NetworkEditorDialogTestView {
        wallet: view.clone(),
    });
    let mut visual = gpui::VisualTestContext::from_window(window, cx);
    // The dialog sizes itself against `window.viewport_size()`, so the window
    // has to actually be this size — drawing into a space of the size is a
    // different claim, and not the one the dialog reads.
    visual.simulate_resize(viewport);
    visual.draw(gpui::point(px(0.0), px(0.0)), viewport, |_, _| {
        gpui::AnyView::from(dialog_view.clone()).into_any_element()
    });

    // Read the frame that was just drawn, before parking — the same order
    // `measure_at` uses, and for the same reason. Parking first lets anything
    // still pending repaint the window from its own root, which has no dialog
    // in it; the bounds recorded for the dialog are replaced by that frame's,
    // and the form reads as never laid out. Whether a repaint happened to be
    // pending is what decided this test, and under a loaded machine it usually
    // was.
    let form = visual
        .debug_bounds("network-editor-body")
        .expect("the network editor form must be laid out");
    let save = visual
        .debug_bounds("network-editor-save")
        .expect("the network editor's Save button must be laid out");
    let pane = visual
        .debug_bounds("network-editor-scroll")
        .expect("the network editor's scroll pane must be laid out");
    let content = visual.update(|_, cx| {
        view.read(cx)
            .network_editor_scroll_handle
            .content_size()
            .height
    });
    visual.run_until_parked();
    drop(dialog_view);
    NetworkEditorLayout {
        form,
        pane,
        save,
        content,
    }
}

#[gpui::test]
fn the_network_editor_scrolls_and_keeps_its_footer_in_a_short_window(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    let viewport = gpui::size(px(1400.0), px(650.0));
    let layout = draw_network_editor(cx, window, &view, viewport);

    assert!(
        layout.form.size.height > px(300.0),
        "the form must take the height the dialog has for it, not collapse to \
         nothing: {:?}",
        layout.form.size.height
    );
    assert!(
        layout.content > layout.form.size.height,
        "this window is too short for the whole form, so the form must scroll \
         inside it: {:?} of content in {:?}",
        layout.content,
        layout.form.size.height
    );
    // A pane still as tall as everything in it is not a viewport, and nothing
    // scrolls: the form is simply cut off at the bottom of the dialog. This is
    // the assertion that says the scroll is real.
    assert_eq!(
        layout.pane.size.height, layout.form.size.height,
        "the scroll pane must be the size of the space the form was given, \
         not the size of the form"
    );
    assert!(
        layout.pane.size.height < layout.content,
        "the scroll pane must be shorter than what it scrolls: {:?} of {:?}",
        layout.pane.size.height,
        layout.content
    );
    assert!(
        layout.save.bottom() <= viewport.height,
        "Save must stay above the bottom of the window: {:?} of {:?}",
        layout.save.bottom(),
        viewport.height
    );
    assert!(
        layout.save.top() >= layout.form.bottom(),
        "Save must sit under the form rather than over it: {:?} against {:?}",
        layout.save.top(),
        layout.form.bottom()
    );

    release(cx, &view);
}

#[gpui::test]
fn the_network_editor_takes_the_height_a_tall_window_offers(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    // Taller than the 640px the dialog was once pinned to, and taller than the
    // form: nothing here should be scrolling, and nothing should be padded out
    // to a size the content did not ask for.
    let viewport = gpui::size(px(1400.0), px(2160.0));
    let layout = draw_network_editor(cx, window, &view, viewport);

    assert!(
        layout.form.size.height >= layout.content,
        "a window with the room for the whole form must show the whole form: \
         {:?} of content in {:?}",
        layout.content,
        layout.form.size.height
    );
    assert!(
        layout.form.size.height > px(640.0),
        "the form must not be held to the height a small window would give it: \
         {:?}",
        layout.form.size.height
    );
    assert!(
        layout.save.top() >= layout.form.bottom(),
        "Save must sit under the form rather than over it: {:?} against {:?}",
        layout.save.top(),
        layout.form.bottom()
    );
    assert!(
        layout.save.bottom() <= viewport.height,
        "Save must stay above the bottom of the window: {:?} of {:?}",
        layout.save.bottom(),
        viewport.height
    );

    release(cx, &view);
}

#[gpui::test]
fn disabling_a_network_moves_the_card_out_of_enabled(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    draw(cx, window, &view);

    // The window asks for a snapshot as it attaches. Let that one finish
    // first: a capture still in flight can read the store after the write and
    // report the new state by luck, which would pass this test with the reload
    // it is about missing entirely.
    settle_snapshot(cx, &view);
    let ethereum = cx.update_entity(&view, |wallet, _| {
        wallet
            .cached_networks()
            .expect("the shipped networks must be listed")
            .iter()
            .find(|network| network.chain_id == 1)
            .expect("Ethereum is one of the shipped networks")
            .clone()
    });
    assert!(!ethereum.disabled, "Ethereum starts enabled");

    cx.update_entity(&view, |wallet, cx| {
        wallet.set_network_disabled(ethereum.clone(), true, cx);
    });
    // The write goes out over the tokio bridge this scheduler does not drive,
    // so settling means waiting rather than draining a queue.
    for _ in 0..200 {
        cx.run_until_parked();
        std::thread::sleep(std::time::Duration::from_millis(5));
        if cx.update_entity(&view, |wallet, _| wallet.network_action_busy.is_empty()) {
            break;
        }
    }

    // Asserted the moment the action is done and before any capture is waited
    // on, because that is the moment the reader is looking at: the card leaves
    // its busy state here, and a snapshot still describing the network as
    // enabled is a card that says Enabled about a network that is not.
    assert!(
        cx.update_entity(&view, |wallet, _| {
            wallet.cached_networks().is_ok_and(|networks| {
                networks
                    .iter()
                    .any(|network| network.chain_id == 1 && network.disabled)
            })
        }),
        "the snapshot the networks page draws from must show the network as \
         disabled as soon as the write is done, without waiting on a capture \
         of everything else"
    );
    draw(cx, window, &view);

    release(cx, &view);
}

#[gpui::test]
fn network_editor_shows_rpc_endpoints_as_a_multiline_field(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    draw(cx, window, &view);
    let form_view = cx.new(|_| NetworkEditorFormTestView {
        wallet: view.clone(),
    });
    let mut visual = gpui::VisualTestContext::from_window(window, cx);
    visual.draw(gpui::point(px(0.0), px(0.0)), VIEWPORT, |_, _| {
        gpui::AnyView::from(form_view.clone()).into_any_element()
    });
    let rpc = visual
        .debug_bounds("network-rpc-endpoints-input")
        .expect("the RPC endpoints field must be laid out");
    visual.run_until_parked();
    assert!(
        rpc.size.height >= px(140.0),
        "the RPC endpoint list must visibly present as a multiline textbox: {:?}",
        rpc.size.height
    );
    drop(form_view);
    release(cx, &view);
}

#[gpui::test]
fn an_action_button_is_the_width_of_its_label(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    // A flex column stretches its children, so this button was as wide as the
    // page — a bar with "Add token…" floating in the middle of it.
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::Tokens));
    let measured = measure(cx, window, &view, &["add-token-button"]);
    let button = measured[0].expect("the add-token button must have been laid out");
    assert!(
        button.size.width < px(240.0),
        "an anchored button must take the width of its label, not of the page: \
         it was {:?} in a {:?} window",
        button.size.width,
        VIEWPORT.width
    );
    release(cx, &view);
}

#[gpui::test]
fn token_inventory_fills_the_remaining_page_height(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::Tokens));

    let measured = measure(
        cx,
        window,
        &view,
        &[
            "route-content-inner",
            "token-inventory-list",
            "token-inventory-search",
        ],
    );
    let content = measured[0].expect("the token page content must be laid out");
    let list = measured[1].expect("the token inventory must be laid out");
    let search = measured[2].expect("the token search control must be laid out");
    assert!(
        list.size.height > px(260.0),
        "the token inventory must grow beyond its minimum to use the viewport: {:?}",
        list.size.height
    );
    assert_eq!(
        list.origin.y + list.size.height,
        content.origin.y + content.size.height,
        "the inventory must end at the bottom of the available content area"
    );
    assert!(
        search.size.height >= px(52.0),
        "the token search control must be substantially larger than the old compact input: \
         {:?}",
        search.size.height
    );

    release(cx, &view);
}

#[gpui::test]
fn an_account_row_keeps_copy_visible_and_the_rest_in_a_menu(cx: &mut gpui::TestAppContext) {
    // Three buttons in every row, one of them a destructive red at rest, gave
    // the list no focal point and put Remove one slip away from the address
    // somebody was only reading. Copy is the frequent one, so it stays; the
    // two rare ones moved behind a trigger that is still visible, so nothing
    // depends on hover and the keyboard path belongs to the menu component.
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        }]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Accounts);
    });

    let measured = measure(cx, window, &view, &["account-menu"]);
    let trigger = measured[0].expect("the account row's menu trigger must be laid out");
    assert!(
        trigger.size.width > px(0.0) && trigger.size.height > px(0.0),
        "the trigger must be a real target, not a zero-sized element: {:?}",
        trigger.size
    );

    // The commands themselves are Actions, so the row no longer owns them and
    // the source is the only place that can say the buttons are gone.
    let source = include_str!("desktop.rs");
    assert!(!source.contains(r#""export-account-{export_id}""#));
    assert!(!source.contains(r#""remove-account-{removal_id}""#));
    assert!(source.contains("ExportAccountKey"));
    assert!(source.contains("RemoveAccount"));
    release(cx, &view);
}

#[gpui::test]
fn an_agents_case_is_read_at_the_height_of_the_frame(cx: &mut gpui::TestAppContext) {
    // The case used to be a 180-pixel box on the diff screen that could not
    // scroll, so a long rationale was simply cut off with no way to reach the
    // rest. On its own screen it takes the height the frame has left.
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    cx.update_entity(&view, |wallet, cx| {
        let account = WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        };
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Policies);
        let document = wallet
            .policy_json_input
            .as_ref()
            .expect("policy input is initialized")
            .read(cx)
            .value()
            .to_string();
        assert!(document.is_empty());

        let current = WalletPolicy::require_approval_for_everything();
        let proposed = WalletPolicy::allow_anything();
        let review = PolicyDraftReview {
            wallet_id: "primary".into(),
            source_revision: Some(2),
            document: String::new(),
            policy: proposed.clone(),
            diff: vec!["+ rule 1 grants every call".to_owned()],
        };
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(2),
            current_policy: Some(current),
            history: Vec::new(),
            history_selection: None,
            proposal: Some(PolicyProposal {
                wallet_instance_id: uuid::Uuid::nil(),
                wallet_id: "primary".into(),
                wallet_address: alloy::primitives::Address::ZERO,
                source_revision: 2,
                policy: proposed,
                // Longer than any fixed box would show.
                rationale: "This proposal widens signing authority. ".repeat(60),
                created_at: chrono::Utc::now(),
            }),
            validation: Some(Ok(review)),
        });
        wallet.policy_proposal_open = true;
        wallet.policy_review_open = false;
    });

    let bounds = measure(
        cx,
        window,
        &view,
        &[
            "policy-proposal-case",
            "policy-proposal-rationale",
            "policy-review-changes",
            "policy-editor-layout",
        ],
    );
    let case = bounds[0].expect("the agent's case must draw");
    let rationale = bounds[1].expect("the rationale must draw");
    assert!(
        bounds[2].is_none(),
        "the case screen stands in place of the diff, not above it"
    );
    let frame = bounds[3].expect("the editor frame must draw");

    // Taller than the box it replaces, by a lot: it takes what the screen has
    // rather than a number chosen in advance.
    assert!(
        rationale.size.height > px(180.0),
        "the rationale must not be bounded like the old box: {:?}",
        rationale.size.height
    );
    // And it stays inside the frame, so the actions under it are reachable
    // without the page growing past its own bottom edge.
    assert!(
        rationale.bottom() <= case.bottom() + px(1.0) && case.bottom() <= frame.bottom() + px(1.0),
        "the case must fit its frame: rationale {rationale:?}, case {case:?}, frame {frame:?}"
    );

    release(cx, &view);
}

#[gpui::test]
fn reviewing_a_policy_does_not_shrink_the_json_editor(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    cx.update_entity(&view, |wallet, cx| {
        let account = WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        };
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Policies);
        let document = wallet
            .policy_json_input
            .as_ref()
            .expect("policy input is initialized")
            .read(cx)
            .value()
            .to_string();
        let first_policy = WalletPolicy::deny_all();
        let policy = WalletPolicy::require_approval_for_everything();
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(2),
            current_policy: Some(policy.clone()),
            history: vec![
                StoredPolicy {
                    wallet_instance_id: uuid::Uuid::nil(),
                    wallet_id: "primary".into(),
                    wallet_address: alloy::primitives::Address::ZERO,
                    policy: first_policy,
                    revision: 1,
                    updated_at: chrono::Utc::now(),
                },
                StoredPolicy {
                    wallet_instance_id: uuid::Uuid::nil(),
                    wallet_id: "primary".into(),
                    wallet_address: alloy::primitives::Address::ZERO,
                    policy,
                    revision: 2,
                    updated_at: chrono::Utc::now(),
                },
            ],
            history_selection: Some(0),
            proposal: None,
            validation: None,
        });
        assert!(document.is_empty());
    });

    let before = measure(cx, window, &view, &["policy-full-screen-json-control"])[0]
        .expect("policy JSON control must be laid out");

    cx.update_entity(&view, |wallet, _| {
        wallet.policy_editor.as_mut().unwrap().validation = Some(Ok(PolicyDraftReview {
            wallet_id: "primary".into(),
            source_revision: Some(2),
            document: String::new(),
            policy: WalletPolicy::require_approval_for_everything(),
            diff: (1..=24)
                .map(|index| format!("+ rule {index} grants a deliberately long permission"))
                .collect(),
        }));
    });
    let after = measure(
        cx,
        window,
        &view,
        &[
            "policy-full-screen-json-control",
            "policy-change-summary",
            "install-policy-draft-full-screen",
        ],
    );
    let after_control = after[0].expect("policy JSON editor must remain laid out after review");
    assert!(
        after_control.size.height >= before.size.height,
        "the checked draft's summary must not shrink the JSON editor: \
         before {before:?}, after {after_control:?}"
    );
    assert!(
        after[1].is_some(),
        "a checked draft must say how much it changes without leaving the editor"
    );
    assert!(
        after[2].is_none(),
        "installing belongs on the screen that shows what is being installed, \
         not in the rail beside the JSON"
    );

    release(cx, &view);
}

/// A virtualized list that draws no rows is indistinguishable, from the
/// outside, from a list whose frame is the right size — which is exactly what
/// the first version of this shipped: three empty boxes where the holdings,
/// the waiting queue, and the history had been. Every one of these lists is
/// asserted by a row inside it, never by the frame around it.
#[gpui::test]
fn every_virtualized_list_draws_the_rows_it_was_given(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let account = WalletMetadata {
        instance_id: uuid::Uuid::nil(),
        id: "primary".into(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    };
    let network = ekubo_wallet_core::config::default_networks()
        .first()
        .expect("a shipped network")
        .clone();

    // The history: one finished record.
    cx.update_entity(&view, |wallet, cx| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account.clone()]);
        snapshot.activity = Ok(Arc::from(vec![OwnerActivityRecord::Transaction(Box::new(
            cleared_transaction_fixture(uuid::Uuid::new_v4()),
        ))]));
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Activity);
        wallet.set_inbox_tab(InboxTab::Decided, cx);
    });
    assert!(
        measure(cx, window, &view, &["activity-row"])[0].is_some(),
        "the history list must draw the record it holds"
    );

    // The waiting queue: one request needing a decision.
    cx.update_entity(&view, |wallet, cx| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account.clone()]);
        let mut queues = crate::authority::OwnerReviewQueues {
            transactions: Vec::new(),
            typed_data: Vec::new(),
            messages: Vec::new(),
            policy_proposals: Vec::new(),
            network_proposals: Vec::new(),
            token_proposals: Vec::new(),
        };
        queues
            .transactions
            .push(cleared_transaction_fixture(uuid::Uuid::new_v4()));
        snapshot.reviews = Ok(queues);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_inbox_tab(InboxTab::Waiting, cx);
    });
    assert!(
        measure(cx, window, &view, &["inbox-waiting-card"])[0].is_some(),
        "the waiting list must draw the request it holds"
    );

    // The portfolio: one balance and one open Ekubo position.
    cx.update_entity(&view, |wallet, _| {
        wallet.portfolio = PortfolioState::Ready(crate::authority::OwnerPortfolioSnapshot {
            accounts: vec![OwnerPortfolioAccount {
                wallet: account.clone(),
                networks: vec![crate::authority::OwnerPortfolioNetwork {
                    network: network.clone(),
                    result: Ok(ekubo_wallet_core::token_store::Portfolio {
                        address: "0x0000000000000000000000000000000000000000".to_owned(),
                        chain_id: network.chain_id.to_string(),
                        network: network.name.clone(),
                        native_balance: "1000000000000000000".to_owned(),
                        block_number: "1".to_owned(),
                        tokens: Vec::new(),
                        tokens_checked: 0,
                        tokens_skipped: None,
                        fork: None,
                    }),
                    ekubo_positions: Ok(crate::authority::OwnerEkuboPositions {
                        positions: vec![crate::authority::OwnerEkuboPosition {
                            id: "0x01".into(),
                            chain_id: network.chain_id,
                            positions_address: "0x0000000000000000000000000000000000000002".into(),
                            token0: crate::authority::OwnerPortfolioAsset {
                                address: "0x0000000000000000000000000000000000000000".into(),
                                symbol: Some("ETH".into()),
                                name: Some("Ether".into()),
                            },
                            token1: crate::authority::OwnerPortfolioAsset {
                                address: "0x04c46e830bb56ce22735d5d8fc9cb90309317d0f".into(),
                                symbol: Some("EKUBO".into()),
                                name: Some("Ekubo Protocol".into()),
                            },
                            lower_tick: 100,
                            upper_tick: 200,
                            current_tick: Some(150),
                        }],
                        total_items: 1,
                    }),
                }],
            }],
        });
        wallet.set_route(Route::Overview);
    });
    assert!(
        measure(
            cx,
            window,
            &view,
            &["portfolio-position-row", "portfolio-balance-row"]
        )
        .into_iter()
        .all(|bounds| bounds.is_some()),
        "the portfolio must draw both the position and balance it holds"
    );

    // The permission diff.
    cx.update_entity(&view, |wallet, cx| {
        wallet.set_route(Route::Policies);
        let policy = WalletPolicy::require_approval_for_everything();
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(2),
            current_policy: Some(policy.clone()),
            history: Vec::new(),
            history_selection: None,
            proposal: None,
            validation: Some(Ok(PolicyDraftReview {
                wallet_id: "primary".into(),
                source_revision: Some(2),
                document: String::new(),
                policy,
                diff: vec!["+ rule 1: starts allowing: to any address".to_owned()],
            })),
        });
        wallet.open_policy_review(cx);
    });
    assert!(
        measure(cx, window, &view, &["policy-diff-row"])[0].is_some(),
        "the review must draw the changed rule it holds"
    );

    release(cx, &view);
}

/// A chain's own currency has no token row to carry a value, so the question
/// "where do I set this one?" had no answer on any screen. It is set beside
/// the currency it belongs to, on the network's own card.
#[gpui::test]
fn a_chains_own_currency_is_valued_on_its_network_card(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::Networks));

    let bounds = measure(cx, window, &view, &["set-native-value-ethereum"]);
    assert!(
        bounds[0].is_some(),
        "the network card must offer somewhere to record what its currency is worth"
    );
    release(cx, &view);
}

/// The editor opens on the installed policy, and the only way back to it was
/// to leave the tab and return — which rebuilds the editor as a side effect
/// nobody could be expected to guess.
#[gpui::test]
fn the_policy_editor_can_be_put_back_to_the_installed_policy(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let installed = WalletPolicy::require_approval_for_everything();
    cx.update_entity(&view, |wallet, cx| {
        let account = WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        };
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Policies);
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(1),
            current_policy: Some(installed.clone()),
            history: Vec::new(),
            history_selection: None,
            proposal: None,
            validation: None,
        });
        let _ = cx;
    });

    // A draft nobody wants to keep, and the one control that undoes it.
    cx.update_window(window, |_, window, cx| {
        view.update(cx, |wallet, cx| {
            wallet
                .policy_json_input
                .as_ref()
                .expect("policy input is initialized")
                .update(cx, |input, cx| {
                    input.set_value("{ \"version\": 1, \"rules\": [] }", window, cx);
                });
            wallet.restore_current_policy(window, cx);
        });
    })
    .expect("the wallet window is open");

    let restored = cx.update_entity(&view, |wallet, cx| {
        wallet
            .policy_json_input
            .as_ref()
            .expect("policy input is initialized")
            .read(cx)
            .value()
            .to_string()
    });
    let restored: WalletPolicy = WalletPolicy::parse(serde_json::from_str(&restored).unwrap())
        .expect("the restored draft must be a policy");
    assert_eq!(
        restored, installed,
        "the draft must come back to exactly what is installed"
    );
    draw(cx, window, &view);

    release(cx, &view);
}

/// Scrolling a list redraws the window, and the window's render rebuilds
/// whatever it draws from. The Portfolio's rows are read out of base units,
/// formatted, priced and sorted, in proportion to what the account holds --
/// and none of that changes because a list moved. On a 120 Hz display a
/// scroll asks for that answer 120 times a second, so it is derived once per
/// reading and handed back for every frame in between.
#[gpui::test]
fn portfolio_rows_survive_the_frames_that_only_redraw_them(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let account = WalletMetadata {
        instance_id: uuid::Uuid::nil(),
        id: "primary".into(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    };
    let network = ekubo_wallet_core::config::default_networks()
        .first()
        .expect("a shipped network")
        .clone();

    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account.clone()]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.portfolio = PortfolioState::Ready(crate::authority::OwnerPortfolioSnapshot {
            accounts: vec![OwnerPortfolioAccount {
                wallet: account.clone(),
                networks: vec![crate::authority::OwnerPortfolioNetwork {
                    network: network.clone(),
                    result: Ok(ekubo_wallet_core::token_store::Portfolio {
                        address: "0x0000000000000000000000000000000000000000".to_owned(),
                        chain_id: network.chain_id.to_string(),
                        network: network.name.clone(),
                        native_balance: "1000000000000000000".to_owned(),
                        block_number: "1".to_owned(),
                        tokens: Vec::new(),
                        tokens_checked: 0,
                        tokens_skipped: None,
                        fork: None,
                    }),
                }],
            }],
        });
        wallet.set_route(Route::Overview);
    });

    cx.update_entity(&view, |wallet, _| wallet.portfolio_rows_derived.set(0));
    let drawn = measure(cx, window, &view, &["portfolio-balances"]);
    drawn[0].expect("the balances list must draw");
    assert_eq!(
        cx.read_entity(&view, |wallet, _| wallet.portfolio_rows_derived.get()),
        1,
        "the first frame has to derive the rows"
    );

    // What a scroll asks for: the same rows, again and again.
    for _ in 0..8 {
        draw(cx, window, &view);
    }
    assert_eq!(
        cx.read_entity(&view, |wallet, _| wallet.portfolio_rows_derived.get()),
        1,
        "a frame that only redraws the list must reuse the rows it already has"
    );

    // A reload that has only been *asked for* changes nothing about what is
    // on screen: the snapshot behind these rows is still the one they were
    // derived from. Keying on the request rather than on what it published
    // would re-derive here -- against the outgoing snapshot -- and then cache
    // that answer under the incoming snapshot's name.
    cx.update_entity(&view, |wallet, _| {
        wallet.desktop_snapshot_generation = wallet.desktop_snapshot_generation.wrapping_add(1);
        wallet.desktop_snapshot_loading = true;
    });
    draw(cx, window, &view);
    assert_eq!(
        cx.read_entity(&view, |wallet, _| wallet.portfolio_rows_derived.get()),
        1,
        "a reload in flight has published nothing, so the rows are unchanged"
    );

    // Publishing one is the thing that changes them.
    cx.update_entity(&view, |wallet, _| {
        wallet.desktop_snapshot_loading = false;
        wallet.desktop_snapshot_revision = wallet.desktop_snapshot_revision.wrapping_add(1);
    });
    draw(cx, window, &view);
    assert_eq!(
        cx.read_entity(&view, |wallet, _| wallet.portfolio_rows_derived.get()),
        2,
        "a landed snapshot must derive the rows again"
    );

    // The dust filter is one of the things they are derived from, so it has
    // to reach through too.
    cx.update_entity(&view, |wallet, _| {
        wallet.show_low_value_balances = !wallet.show_low_value_balances;
    });
    draw(cx, window, &view);
    assert_eq!(
        cx.read_entity(&view, |wallet, _| wallet.portfolio_rows_derived.get()),
        3,
        "changing what the list holds back must derive the rows again"
    );

    release(cx, &view);
}

/// The account row's menu hands over an identity, not a position. A row
/// removed between the menu being drawn and an item being pressed would
/// otherwise open somebody else's Portfolio -- and the two pages these open
/// are per-account, so landing on the wrong one is the whole failure.
#[gpui::test]
fn an_accounts_menu_opens_the_page_for_that_account(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let accounts = ["primary", "savings", "cold"]
        .iter()
        .map(|id| WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: (*id).into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        })
        .collect::<Vec<_>>();
    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(accounts.clone());
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Accounts);
    });

    cx.update_entity(&view, |wallet, cx| {
        wallet.show_account_portfolio("cold", cx);
    });
    assert_eq!(
        cx.read_entity(&view, |wallet, _| (
            wallet.route,
            wallet.portfolio_account_index
        )),
        (Route::Overview, 2),
        "the Portfolio must open on the account the row named"
    );

    // An id the list no longer holds leaves the page where it is rather than
    // opening whoever happens to be first.
    cx.update_entity(&view, |wallet, cx| {
        wallet.set_route(Route::Accounts);
        wallet.show_account_portfolio("removed", cx);
    });
    assert_eq!(
        cx.read_entity(&view, |wallet, _| (
            wallet.route,
            wallet.portfolio_account_index
        )),
        (Route::Accounts, 2),
        "an account that is gone must not navigate or move the selection"
    );

    cx.update_window(window, |_, window, cx| {
        view.update(cx, |wallet, cx| {
            wallet.show_account_policy("savings", window, cx);
        });
    })
    .expect("the wallet window is open");
    assert_eq!(
        cx.read_entity(&view, |wallet, _| (
            wallet.route,
            wallet.policy_account_id.clone()
        )),
        (Route::Policies, Some("savings".to_owned())),
        "the policy editor must open on the account the row named"
    );

    release(cx, &view);
}

/// A placeholder earns its place by being replaced without anything moving.
/// This one was a different shape from the rows it stood in for, so the tab
/// rearranged itself the moment the balances landed.
#[gpui::test]
fn the_loading_placeholder_stands_where_the_balances_land(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let account = WalletMetadata {
        instance_id: uuid::Uuid::nil(),
        id: "primary".into(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    };
    let network = ekubo_wallet_core::config::default_networks()
        .first()
        .expect("a shipped network")
        .clone();

    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account.clone()]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.portfolio = PortfolioState::Loading;
        wallet.set_route(Route::Overview);
    });
    let loading = measure(
        cx,
        window,
        &view,
        &[
            "portfolio-balances-card",
            "portfolio-loading-placeholder",
            "portfolio-placeholder-row",
        ],
    );
    let loading_card = loading[0].expect("the card must draw while the balances are being read");
    let placeholder = loading[1].expect("the placeholder rows must draw inside it");
    let placeholder_row = loading[2].expect("a placeholder row must draw");

    cx.update_entity(&view, |wallet, _| {
        wallet.portfolio = PortfolioState::Ready(crate::authority::OwnerPortfolioSnapshot {
            accounts: vec![OwnerPortfolioAccount {
                wallet: account.clone(),
                networks: vec![crate::authority::OwnerPortfolioNetwork {
                    network: network.clone(),
                    result: Ok(ekubo_wallet_core::token_store::Portfolio {
                        address: "0x0000000000000000000000000000000000000000".to_owned(),
                        chain_id: network.chain_id.to_string(),
                        network: network.name.clone(),
                        native_balance: "1000000000000000000".to_owned(),
                        block_number: "1".to_owned(),
                        tokens: Vec::new(),
                        tokens_checked: 0,
                        tokens_skipped: None,
                        fork: None,
                    }),
                    ekubo_positions: Ok(crate::authority::OwnerEkuboPositions {
                        positions: Vec::new(),
                        total_items: 0,
                    }),
                }],
            }],
        });
    });
    let ready = measure(
        cx,
        window,
        &view,
        &[
            "portfolio-balances-card",
            "portfolio-balances",
            "portfolio-balance-row",
        ],
    );
    let ready_card = ready[0].expect("the card must still draw once the balances land");
    let list = ready[1].expect("the list must draw inside it");
    let row = ready[2].expect("the balance row must draw");

    assert_eq!(
        loading_card, ready_card,
        "the balances must land in the card the placeholder was already in, \
         at the same place and the same size"
    );
    assert_eq!(
        placeholder.origin, list.origin,
        "the placeholder rows must stand where the list stands"
    );
    assert_eq!(
        placeholder.size.width, list.size.width,
        "and be as wide as it"
    );
    // A placeholder row is the real row's frame, so it stands the same height
    // as one balance rather than the height of some other card's line.
    assert!(
        (placeholder_row.size.height - row.size.height).abs() < px(12.0),
        "a placeholder row must be about the height of the row it stands in \
         for: {:?} against {:?}",
        placeholder_row.size.height,
        row.size.height
    );
    // Only the left edge: this selector matches every placeholder row, so the
    // bounds read back are the last one's, and the first row's position is
    // already pinned by the region assertions above.
    assert_eq!(
        placeholder_row.origin.x, row.origin.x,
        "and start at the same left edge as that row"
    );

    release(cx, &view);
}

/// A tab that quietly dropped holdings could be made to lie by one wrong
/// price, so whenever the dust filter hides anything it says how much, in both
/// states of its own switch.
#[gpui::test]
fn the_portfolio_says_how_much_dust_it_is_holding_back(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let account = WalletMetadata {
        instance_id: uuid::Uuid::nil(),
        id: "primary".into(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    };
    let network = ekubo_wallet_core::config::default_networks()
        .first()
        .expect("a shipped network")
        .clone();
    let token = |index: u32, price: Option<f64>| ekubo_wallet_core::token_store::PortfolioToken {
        address: format!("0x{index:040x}"),
        symbol: Some(format!("TKN{index}")),
        name: Some(format!("Token {index}")),
        decimals: Some(18),
        balance: "1000000000000000000".to_owned(),
        approximate_usd_price: price,
    };
    let portfolio = |tokens: Vec<ekubo_wallet_core::token_store::PortfolioToken>| {
        ekubo_wallet_core::token_store::Portfolio {
            address: "0x0000000000000000000000000000000000000000".to_owned(),
            chain_id: network.chain_id.to_string(),
            network: network.name.clone(),
            // Zero, so the native row does not stand in for the priced one
            // this test is looking for.
            native_balance: "0".to_owned(),
            block_number: "1".to_owned(),
            tokens_checked: tokens.len() as u64,
            tokens,
            tokens_skipped: None,
            fork: None,
        }
    };
    let ready = |wallet: &mut WalletWindow,
                 tokens: Vec<ekubo_wallet_core::token_store::PortfolioToken>| {
        wallet.portfolio = PortfolioState::Ready(crate::authority::OwnerPortfolioSnapshot {
            accounts: vec![OwnerPortfolioAccount {
                wallet: account.clone(),
                networks: vec![crate::authority::OwnerPortfolioNetwork {
                    network: network.clone(),
                    result: Ok(portfolio(tokens)),
                    ekubo_positions: Ok(crate::authority::OwnerEkuboPositions {
                        positions: Vec::new(),
                        total_items: 0,
                    }),
                }],
            }],
        });
    };

    cx.update_entity(&view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account.clone()]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        ready(
            wallet,
            vec![token(1, Some(500.0)), token(2, Some(0.02)), token(3, None)],
        );
        wallet.set_route(Route::Overview);
    });
    let hiding = measure(cx, window, &view, &["portfolio-dust-control"]);
    assert!(
        hiding[0].is_some(),
        "hiding a holding must be stated on the tab that hid it"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet.show_low_value_balances = true;
    });
    let showing = measure(cx, window, &view, &["portfolio-dust-control"]);
    assert!(
        showing[0].is_some(),
        "the count belongs on screen while the dust is showing too — it is what \
         explains the switch that is now on"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet.show_low_value_balances = false;
        ready(wallet, vec![token(1, Some(500.0))]);
    });
    let nothing_hidden = measure(cx, window, &view, &["portfolio-dust-control"]);
    assert!(
        nothing_hidden[0].is_none(),
        "with nothing hidden there is nothing to say, and no switch to offer"
    );

    // Until some value is recorded there is nothing to sort or hide by, and
    // every token would count as dust. A wallet nobody has priced anything in
    // must open onto its holdings, not onto a tab that hid all of them.
    cx.update_entity(&view, |wallet, _| {
        ready(wallet, vec![token(1, None), token(2, None), token(3, None)]);
    });
    let unpriced = measure(cx, window, &view, &["portfolio-dust-control"]);
    assert!(
        unpriced[0].is_none(),
        "with no recorded values at all, nothing is held back"
    );

    release(cx, &view);
}

/// The permission diff used to be read in the 264-pixel rail beside the JSON:
/// the narrowest column on the page, holding the longest lines on it. It is
/// its own state of the screen now, and it has to actually take the screen.
#[gpui::test]
fn reviewing_a_policy_change_takes_the_whole_frame(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    cx.update_entity(&view, |wallet, cx| {
        let account = WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        };
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Policies);
        let policy = WalletPolicy::require_approval_for_everything();
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(2),
            current_policy: Some(policy.clone()),
            history: Vec::new(),
            history_selection: None,
            proposal: None,
            validation: Some(Ok(PolicyDraftReview {
                wallet_id: "primary".into(),
                source_revision: Some(2),
                document: String::new(),
                policy,
                diff: vec![
                    "+ rule 1: starts allowing: to any address; any calldata, including \
                     batched calls to other contracts"
                        .to_owned(),
                    "~ rule 2 changed: allow: to 0xaaaa; calldata any → allow: to 0xbbbb; \
                     calldata any"
                        .to_owned(),
                    "- rule 3: stops allowing: to 0xcccc; calldata any".to_owned(),
                ],
            })),
        });
        wallet.open_policy_review(cx);
    });

    let bounds = measure(
        cx,
        window,
        &view,
        &[
            "policy-review",
            "policy-review-changes",
            "policy-change-summary",
            "close-policy-review",
            "install-policy-draft-full-screen",
            "policy-full-screen-json-control",
        ],
    );
    let review = bounds[0].expect("the review must draw");
    let changes = bounds[1].expect("the changed rules must draw");
    assert!(
        bounds[2].is_some(),
        "the review must open with a tally of how far the change moves"
    );
    assert!(
        bounds[3].is_some(),
        "the review must offer the way back to the draft it describes"
    );
    assert!(
        bounds[4].is_some(),
        "installing belongs under the changes being installed"
    );
    assert!(
        bounds[5].is_none(),
        "reviewing replaces the JSON editor rather than sharing the window with it"
    );
    assert!(
        changes.size.width > px(600.0),
        "the changes must get the frame's width rather than a rail's: {:?}",
        changes.size.width
    );
    assert!(
        changes.bottom() <= review.bottom() + px(1.0),
        "the changed rules must scroll inside the review rather than past its bottom: \
         {:?} against {:?}",
        changes.bottom(),
        review.bottom()
    );

    cx.update_entity(&view, |wallet, cx| {
        wallet.close_policy_review(cx);
    });
    let back = measure(cx, window, &view, &["policy-full-screen-json-control"]);
    assert!(
        back[0].is_some(),
        "leaving the review must land back on the draft it was describing"
    );

    release(cx, &view);
}

#[gpui::test]
fn policy_editor_is_the_only_policy_layout_and_sits_flush_with_navigation(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    cx.update_entity(&view, |wallet, _| {
        let account = WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        };
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Policies);
        let first_policy = WalletPolicy::deny_all();
        let policy = WalletPolicy::require_approval_for_everything();
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(2),
            current_policy: Some(policy.clone()),
            history: vec![
                StoredPolicy {
                    wallet_instance_id: uuid::Uuid::nil(),
                    wallet_id: "primary".into(),
                    wallet_address: alloy::primitives::Address::ZERO,
                    policy: first_policy,
                    revision: 1,
                    updated_at: chrono::Utc::now(),
                },
                StoredPolicy {
                    wallet_instance_id: uuid::Uuid::nil(),
                    wallet_id: "primary".into(),
                    wallet_address: alloy::primitives::Address::ZERO,
                    policy,
                    revision: 2,
                    updated_at: chrono::Utc::now(),
                },
            ],
            history_selection: Some(1),
            proposal: None,
            validation: None,
        });
    });
    cx.update(|cx| {
        cx.update_window(window, |_, window, cx| {
            view.update(cx, |wallet, cx| {
                wallet
                    .policy_json_input
                    .as_ref()
                    .expect("policy input is initialized")
                    .update(cx, |input, cx| {
                        input.set_value("{\n  \"default\": \"ask\"\n}".to_owned(), window, cx);
                    });
            });
        })
        .expect("wallet window remains available");
    });
    let bounds = measure(
        cx,
        window,
        &view,
        &[
            "wallet-sidebar",
            "policy-editor-layout",
            "policy-full-screen-editor",
            "policy-full-screen-json-control",
            "policy-full-screen-sidebar",
            "route-content-scroll",
            "open-policy-editor-full-screen",
            "close-policy-editor-full-screen",
            "policy-json-heading",
            "policy-json-guidance",
            "previous-policy-revision",
            "next-policy-revision",
            "policy-revision-restore",
            "restore-policy-revision",
            "policy-revision-position",
            "disable-signing-policy-draft-full-screen",
            "reset-policy-draft-full-screen",
            "allow-anything-policy-draft-full-screen",
        ],
    );
    let navigation = bounds[0].expect("navigation rail must remain laid out");
    let layout = bounds[1].expect("dedicated policy editor layout must be laid out");
    let editor = bounds[2].expect("policy JSON panel must be laid out");
    let control = bounds[3].expect("policy JSON control must be laid out");
    let sidebar = bounds[4].expect("policy review sidebar must be laid out");
    let heading = bounds[8].expect("Policy JSON heading must be laid out");
    let guidance = bounds[9].expect("policy JSON guidance must be laid out");
    assert!(bounds[10].is_some(), "Previous revision must be laid out");
    assert!(
        bounds[11..15].iter().all(Option::is_none),
        "no revision selector, label, next action, or restore action may remain"
    );
    assert_eq!(
        navigation.origin.x + navigation.size.width,
        layout.origin.x,
        "the editor layout must sit flush against the navigation rail"
    );
    assert_eq!(layout.origin.y, px(0.0));
    assert_eq!(layout.size.height, navigation.size.height);
    assert!(
        control.size.height >= px(600.0),
        "the JSON control must use the available policy-page height: {control:?}"
    );
    assert!(
        editor.origin.x + editor.size.width <= sidebar.origin.x,
        "the editor and review sidebar must not overlap: editor {editor:?}, sidebar {sidebar:?}"
    );
    assert!(
        sidebar.size.width <= px(264.0),
        "the narrower review sidebar must leave room for JSON at minimum widths: {sidebar:?}"
    );
    // Every button in the rail, not just the one that overflowed. These size to
    // their labels, so the rail's width is really a budget for the longest of
    // them — and before this assertion existed, "Disable transaction signing"
    // had been hanging 14px past the edge of a wider sidebar unnoticed.
    for (index, name) in [
        (10, "previous revision"),
        (15, "disable signing"),
        (16, "review every request"),
        (17, "allow anything"),
    ] {
        let button = bounds[index].unwrap_or_else(|| panic!("the {name} preset must be laid out"));
        assert!(
            button.origin.x >= sidebar.origin.x
                && button.origin.x + button.size.width <= sidebar.origin.x + sidebar.size.width,
            "the {name} preset must stay inside the sidebar: button {button:?}, sidebar {sidebar:?}"
        );
    }
    assert!(
        bounds[5].is_none(),
        "the old scrolling Policies page must not render behind the editor"
    );
    assert!(
        bounds[6].is_none() && bounds[7].is_none(),
        "there must be no enter or exit full-screen mode buttons"
    );
    assert!(
        guidance.origin.y >= heading.origin.y + heading.size.height,
        "the guidance must sit below the Policy JSON heading: heading {heading:?}, guidance {guidance:?}"
    );
    assert!(
        guidance.origin.x + guidance.size.width <= editor.origin.x + editor.size.width,
        "the wrapping guidance must remain inside the editor panel: editor {editor:?}, guidance {guidance:?}"
    );

    cx.read_entity(&view, |wallet, cx| {
        assert_eq!(
            wallet
                .policy_json_input
                .as_ref()
                .expect("draft must remain mounted")
                .read(cx)
                .value()
                .as_ref(),
            "{\n  \"default\": \"ask\"\n}"
        );
    });
    let first_revision = serde_json::to_string_pretty(&WalletPolicy::deny_all()).unwrap();
    cx.update(|cx| {
        cx.update_window(window, |_, window, cx| {
            view.update(cx, |wallet, cx| {
                wallet.view_previous_policy_revision(window, cx);
            });
        })
        .unwrap();
    });
    cx.read_entity(&view, |wallet, cx| {
        let editor = wallet.policy_editor.as_ref().unwrap();
        assert_eq!(editor.history_selection, Some(0));
        assert_eq!(
            wallet.policy_json_input.as_ref().unwrap().read(cx).value(),
            first_revision
        );
    });
    cx.update_entity(&view, |wallet, _| {
        wallet.policy_account_id = Some("primary".into());
        wallet.set_route(Route::Accounts);
        assert!(
            wallet.policy_editor.is_none(),
            "leaving Policies must discard the historical editor view"
        );
        wallet.set_route(Route::Policies);
        assert!(
            wallet.policy_editor.is_none(),
            "re-entry must reload through core instead of reviving the old draft"
        );
    });

    release(cx, &view);
}

#[gpui::test]
fn the_policy_editor_scrolls_inside_its_frame_rather_than_moving_it(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    cx.update_entity(&view, |wallet, _| {
        let account = WalletMetadata {
            instance_id: uuid::Uuid::nil(),
            id: "primary".into(),
            address: alloy::primitives::Address::ZERO,
            created_at: chrono::Utc::now(),
            source: ekubo_wallet_core::config::WalletSource::Created,
            exported_at: None,
        };
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![account]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.set_route(Route::Policies);
        let policy = WalletPolicy::require_approval_for_everything();
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(1),
            current_policy: Some(policy.clone()),
            history: vec![StoredPolicy {
                wallet_instance_id: uuid::Uuid::nil(),
                wallet_id: "primary".into(),
                wallet_address: alloy::primitives::Address::ZERO,
                policy,
                revision: 1,
                updated_at: chrono::Utc::now(),
            }],
            history_selection: Some(0),
            proposal: None,
            validation: None,
        });
    });

    // Narrow enough that long JSON lines cannot fit. An earlier attempt gave
    // the control a 120-column minimum width and scrolled the container around
    // it, which dragged the line-number gutter and the panel's own border off
    // screen with the text. Whatever the editor does about long lines, it has
    // to do inside the frame it was given.
    let viewport = gpui::Size {
        width: px(760.0),
        height: px(900.0),
    };
    let (panel, control, description) = {
        let mut visual = gpui::VisualTestContext::from_window(window, cx);
        // The window has to actually be this narrow. Drawing into a space of
        // this size is a different claim, and the layout reads the window.
        visual.simulate_resize(viewport);
        let drawn = view.clone();
        visual.draw(gpui::point(px(0.0), px(0.0)), viewport, |_, _| {
            gpui::AnyView::from(drawn).into_any_element()
        });
        let panel = visual
            .debug_bounds("policy-full-screen-editor")
            .expect("the policy JSON panel must be laid out");
        let control = visual
            .debug_bounds("policy-full-screen-json-control")
            .expect("the policy JSON control must be laid out");
        let description = visual
            .debug_bounds("policy-editor-description")
            .expect("the policy editor description must be laid out");
        visual.run_until_parked();
        (panel, control, description)
    };

    // The header band does not scroll, so the description has to fold rather
    // than run off the edge. One line of this text size measures about 22px,
    // so a height past 40 is the sentence actually on two lines — a clipped
    // single line would still report one line's height.
    assert!(
        description.size.height >= px(40.0),
        "the description must wrap onto a second line in a narrow window: \
         {description:?}"
    );
    assert!(
        description.origin.x + description.size.width <= viewport.width,
        "the wrapped description must stay inside the window: {description:?}"
    );
    assert!(
        control.size.width <= panel.size.width,
        "the control must stay inside its panel rather than overflowing into a \
         container scroll: control {control:?}, panel {panel:?}"
    );
    assert!(
        control.origin.x >= panel.origin.x
            && control.origin.x + control.size.width <= panel.origin.x + panel.size.width,
        "the control must sit within the panel's borders on both sides: \
         control {control:?}, panel {panel:?}"
    );

    release(cx, &view);
}

fn portfolio_account(id: &str) -> WalletMetadata {
    WalletMetadata {
        instance_id: uuid::Uuid::nil(),
        id: id.to_owned(),
        address: alloy::primitives::Address::ZERO,
        created_at: chrono::Utc::now(),
        source: ekubo_wallet_core::config::WalletSource::Created,
        exported_at: None,
    }
}

/// Stand the Portfolio tab up on two accounts with balances already in hand,
/// then leave the tab so the next navigation to it is an opening.
fn portfolio_at_rest(cx: &mut gpui::TestAppContext, view: &Entity<WalletWindow>) {
    cx.update_entity(view, |wallet, _| {
        let mut snapshot = quiet_snapshot();
        snapshot.accounts = Ok(vec![
            portfolio_account("primary"),
            portfolio_account("second"),
        ]);
        wallet.desktop_snapshot = Some(Arc::new(snapshot));
        wallet.portfolio = PortfolioState::Ready(OwnerPortfolioSnapshot {
            accounts: Vec::new(),
        });
        wallet.set_route(Route::Accounts);
    });
}

/// Open the Portfolio tab the way every entry point does, and report whether
/// that opening started a balance read.
///
/// The read is detected by the generation counter rather than by the state:
/// `refresh_portfolio` bumps it before anything awaits, so this stays true
/// without letting the spawned read land first and race the assertion.
fn opening_portfolio_reads(cx: &mut gpui::TestAppContext, view: &Entity<WalletWindow>) -> bool {
    let before = cx.update_entity(view, |wallet, cx| {
        let before = wallet.portfolio_generation;
        wallet.navigate_route(Route::Overview, cx);
        before
    });
    cx.update_entity(view, |wallet, _| {
        let read = wallet.portfolio_generation != before;
        // Put the tab back the way it was found so one call does not decide
        // what the next one measures.
        wallet.portfolio = PortfolioState::Ready(OwnerPortfolioSnapshot {
            accounts: Vec::new(),
        });
        wallet.set_route(Route::Accounts);
        read
    })
}

#[gpui::test]
fn opening_the_portfolio_tab_reads_balances_at_most_once_a_minute(cx: &mut gpui::TestAppContext) {
    let (_directory, view, _window) = wallet(cx);
    settle(cx, &view);
    portfolio_at_rest(cx, &view);

    assert!(
        opening_portfolio_reads(cx, &view),
        "an account with no reading behind it must be read on the first opening"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet
            .portfolio_refreshed_at
            .insert("primary".to_owned(), chrono::Utc::now());
    });
    assert!(
        !opening_portfolio_reads(cx, &view),
        "a reading under a minute old must be reused rather than read again"
    );

    cx.update_entity(&view, |wallet, _| {
        let stale = chrono::Utc::now() - chrono::TimeDelta::seconds(61);
        wallet
            .portfolio_refreshed_at
            .insert("primary".to_owned(), stale);
    });
    assert!(
        opening_portfolio_reads(cx, &view),
        "a reading older than a minute must be read again on opening"
    );

    release(cx, &view);
}

#[gpui::test]
fn reopening_the_window_onto_the_portfolio_tab_reads_stale_balances(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    portfolio_at_rest(cx, &view);

    // A window put away on the Portfolio tab, over balances read an hour ago.
    // Nothing navigates on the way back in, so the tab's own reopening is the
    // only thing that can notice they are stale.
    let generation = cx.update_entity(&view, |wallet, cx| {
        wallet.portfolio_refreshed_at.insert(
            "primary".to_owned(),
            chrono::Utc::now() - chrono::TimeDelta::hours(1),
        );
        wallet.set_route(Route::Overview);
        wallet.release_window_state(cx);
        wallet.portfolio_generation
    });

    draw(cx, window, &view);

    cx.read_entity(&view, |wallet, _| {
        assert_ne!(
            wallet.portfolio_generation, generation,
            "reopening the window onto the tab must read balances an hour old"
        );
    });

    release(cx, &view);
}

#[gpui::test]
fn the_portfolio_refresh_interval_is_kept_per_account(cx: &mut gpui::TestAppContext) {
    let (_directory, view, _window) = wallet(cx);
    settle(cx, &view);
    portfolio_at_rest(cx, &view);

    // A reading that just landed for the account the tab is focused on.
    cx.update_entity(&view, |wallet, _| {
        wallet
            .portfolio_refreshed_at
            .insert("primary".to_owned(), chrono::Utc::now());
    });
    assert!(
        !opening_portfolio_reads(cx, &view),
        "the focused account's own reading must hold the interval shut"
    );

    // Focus the other account. Its balances have never been read, so the
    // first account's recent reading must not speak for it.
    cx.update_entity(&view, |wallet, _| {
        wallet.portfolio_account_index = 1;
    });
    assert!(
        opening_portfolio_reads(cx, &view),
        "a second account must be read on its own schedule, not the first's"
    );

    release(cx, &view);
}

#[gpui::test]
fn the_portfolio_tab_reports_how_old_its_balances_are(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    portfolio_at_rest(cx, &view);

    cx.update_entity(&view, |wallet, _| {
        let read_at = chrono::Utc::now() - chrono::TimeDelta::minutes(3);
        wallet
            .portfolio_refreshed_at
            .insert("primary".to_owned(), read_at);
        // The balances path rather than the placeholder: the line has to sit
        // under a rendered list, which is where it was asked for.
        wallet.portfolio = PortfolioState::Ready(OwnerPortfolioSnapshot {
            accounts: vec![OwnerPortfolioAccount {
                wallet: portfolio_account("primary"),
                networks: Vec::new(),
            }],
        });
        wallet.set_route(Route::Overview);
    });

    let bounds = measure(cx, window, &view, &["portfolio-refreshed-at"]);
    assert!(
        bounds[0].is_some(),
        "the age of the balances must be laid out at the bottom of the tab"
    );
    cx.read_entity(&view, |wallet, _| {
        let read_at = wallet
            .focused_portfolio_refreshed_at()
            .expect("the focused account's reading must be found");
        assert_eq!(
            format!(
                "Refreshed {}",
                relative_time_label(read_at, chrono::Utc::now())
            ),
            "Refreshed 3 minutes ago"
        );
    });

    release(cx, &view);
}

/// A review document with the shape a real one has: a summary, effects, and
/// exact bytes to disclose.
fn review_document() -> ReviewDocument {
    let request = ApprovalRequest::new(
        ApprovalKind::Transaction,
        "Transaction",
        "Moves tokens on Ethereum.",
    )
    .fact("Account", "primary")
    .section_kind(ApprovalSectionKind::Effects, "Balance changes")
    .fact("USDC (0x0000000000000000000000000000000000000001)", "-1.00")
    .section_kind(ApprovalSectionKind::Action, "Call 1")
    .fact("What it does", "Transfers 1 USDC")
    .warning("This contract is not one you have used before.");
    ReviewDocument::from_request(request, vec!["{\"plan\":true}".to_owned()])
}

fn active_review(completion: ActiveReviewCompletion) -> ActiveReview {
    ActiveReview::new(review_document(), None, Some(completion))
}

#[gpui::test]
fn every_review_kind_lays_out_its_decision_row(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    // Account removal is the one whose decision row differs — the danger moves
    // to approve and Re-simulate is not drawn at all — so it is the one most
    // worth laying out rather than reasoning about.
    for completion in [
        ActiveReviewCompletion::AccountRemoval {
            wallet: WalletMetadata {
                instance_id: uuid::Uuid::nil(),
                id: "primary".into(),
                address: alloy::primitives::Address::ZERO,
                created_at: chrono::Utc::now(),
                source: ekubo_wallet_core::config::WalletSource::Created,
                exported_at: None,
            },
        },
        ActiveReviewCompletion::Message {
            request_id: uuid::Uuid::new_v4(),
            digest: "0xabc".into(),
        },
    ] {
        cx.update_entity(&view, |wallet, _| {
            wallet.active_review = Some(active_review(completion));
        });
        draw(cx, window, &view);
    }
    release(cx, &view);
}

#[gpui::test]
fn a_4096_call_security_review_with_large_exact_data_stays_virtual_and_scrollable(
    cx: &mut gpui::TestAppContext,
) {
    const CALLS: usize = 4_096;
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let mut request = ApprovalRequest::new(
        ApprovalKind::Transaction,
        "Large transaction",
        "Every call remains available without laying out the whole document.",
    );
    for index in 0..CALLS {
        request = request
            .section_kind(ApprovalSectionKind::Action, format!("Call {index}"))
            .fact("Target", format!("0x{index:040x}"));
    }
    let payload = (0..8_192)
        .map(|index| format!("\"field_{index}\": \"{}\"", "b".repeat(48)))
        .collect::<Vec<_>>()
        .join(",\n");
    let chunk_count = exact_payload_chunk_ranges(&payload).len();
    assert!(chunk_count > 100);
    let document = ReviewDocument::from_request(request, vec![payload]);
    cx.update_entity(&view, |wallet, _| {
        wallet.active_review = Some(ActiveReview::new(
            document,
            None,
            Some(ActiveReviewCompletion::Message {
                request_id: uuid::Uuid::new_v4(),
                digest: "0xabc".into(),
            }),
        ));
    });

    draw(cx, window, &view);
    let scroll_handle = cx.read_entity(&view, |wallet, _| {
        let review = wallet.active_review.as_ref().expect("active review");
        assert_eq!(
            review.scroll_handler_generation.get(),
            Some(review.state.generation()),
            "the virtual list's scroll callback is installed once for this review generation"
        );
        assert_eq!(
            review.scroll_handle.item_count(),
            CALLS + 3 + chunk_count,
            "the prelude, exact-data heading, payload heading, and bounded chunks are virtual rows"
        );
        assert_eq!(
            review
                .detail_rows
                .iter()
                .filter(|row| matches!(row, SecurityReviewDetailRow::Section(_)))
                .count(),
            CALLS
        );
        assert!(!review.end_rendered.load(Ordering::Acquire));
        assert!(!review.state.approve_enabled());
        review.scroll_handle.clone()
    });

    scroll_handle.scroll_to_end();
    draw(cx, window, &view);
    draw(cx, window, &view);
    let generation = cx.read_entity(&view, |wallet, _| {
        wallet
            .active_review
            .as_ref()
            .expect("active review")
            .state
            .generation()
    });
    for _ in 0..3 {
        cx.update_entity(&view, |wallet, cx| {
            wallet
                .active_review
                .as_mut()
                .expect("active review")
                .scroll_layout_ready = true;
            wallet.update_review_scroll_state(generation, cx);
        });
    }
    cx.read_entity(&view, |wallet, _| {
        let review = wallet.active_review.as_ref().expect("active review");
        assert!(review.end_rendered.load(Ordering::Acquire));
        assert!(review.state.approve_enabled());
    });
    release(cx, &view);
}

#[gpui::test]
fn the_legal_and_export_overlays_lay_out(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    cx.update_entity(&view, |wallet, cx| {
        wallet.legal_review = Some(WalletWindow::new_legal_review(
            LegalDocument::TermsOfService,
            "# Terms\n\nA paragraph long enough to wrap across the fixed row\nwidth the document list uses.\n\n- A bullet\n",
            "digest".to_owned(),
            true,
            cx,
        ));
    });
    draw(cx, window, &view);

    cx.update_entity(&view, |wallet, _| {
        wallet.legal_review = None;
        wallet.account_export = Some(AccountExport {
            token: uuid::Uuid::new_v4(),
            wallet_id: "primary".into(),
            lease: None,
            copied: false,
            authenticating: false,
            error: None,
        });
    });
    draw(cx, window, &view);
    release(cx, &view);
}

/// Rasterise the wallet's screens to PNGs and leave them on disk.
///
/// GPUI can render a window offscreen through Metal, so the interface can be
/// looked at on a machine with no panel attached — which is the situation this
/// was written in, and the reason it exists. Ignored by default because it
/// needs a GPU and writes files; run it deliberately:
///
/// ```sh
/// cargo test --lib screenshots -- --ignored --nocapture
/// ```
#[test]
#[ignore = "writes PNGs and needs a GPU; run deliberately"]
fn screenshots() {
    let directory = std::path::PathBuf::from(
        std::env::var("EKUBO_SHOT_DIR").unwrap_or_else(|_| "target/screenshots".to_owned()),
    );
    std::fs::create_dir_all(&directory).expect("shot directory");

    let platform = gpui_platform::current_platform(true);
    let mut cx = gpui::HeadlessAppContext::with_platform(
        platform.text_system(),
        Arc::new(crate::assets::WalletAssets::default()),
        gpui_platform::current_headless_renderer,
    );
    cx.allow_parking();

    let temp = tempfile::tempdir().expect("temp dir");
    let owner = cx.update(|cx| {
        gpui_component::init(cx);
        gpui_tokio::init(cx);
        load_application_fonts(cx).expect("fonts");
        apply_interface_palette(cx);
        OwnerApi::for_test(temp.path()).expect("owner")
    });
    let (review_presenter, _reviews) = GuiReviewPresenter::channel();
    let (walletconnect_presenter, _proposals) = ProposalPresenter::channel();
    let window = cx
        .open_window(VIEWPORT, |_, cx| {
            cx.new(|cx| {
                WalletWindow::new(
                    owner,
                    review_presenter,
                    Arc::new(Mutex::new(WalletConnectManager::default())),
                    walletconnect_presenter,
                    Rc::new(RefCell::new(None)),
                    Arc::new(Mutex::new(None)),
                    temp.path(),
                    cx,
                )
            })
        })
        .expect("window");
    cx.run_until_parked();

    let view = cx.update(|cx| window.root(cx).expect("root"));
    cx.update(|cx| {
        view.update(cx, |wallet, _| {
            wallet.desktop_snapshot = Some(Arc::new(quiet_snapshot()));
            wallet.desktop_snapshot_error = None;
            wallet.legal_gate = false;
            wallet.legal_review = None;
        });
    });

    // Both themes, at the default base font and at a larger one. The design
    // guide asks for exactly this pair of checks and neither can be made from
    // one shot: a colour that only works because the surface behind it is
    // white shows up in dark, and a fixed pixel height only betrays itself
    // when the text inside it grows and the box does not.
    //
    // The window here is a bare `WalletWindow`, not the `Root` the application
    // wraps it in, and `Root` is what copies `theme.font_size` onto the
    // window's rem. So the rem is set explicitly: without this the loop would
    // render every variant at 16px and prove nothing.
    for (mode, mode_name) in [(ThemeMode::Light, "light"), (ThemeMode::Dark, "dark")] {
        for base in [16u16, 20u16] {
            let rem = px(f32::from(base));
            cx.update(|cx| {
                Theme::change(mode, None, cx);
                // `Theme::change` reloads the colours from the mode's config,
                // so the product's palette goes back on top of it afterwards —
                // the same order the running application uses.
                apply_interface_palette(cx);
                Theme::global_mut(cx).font_size = rem;
                let _ = cx.update_window(window.into(), |_, window, _| window.set_rem_size(rem));
            });
            for route in Route::ALL {
                cx.update(|cx| {
                    view.update(cx, |wallet, _| {
                        // Re-applied each frame: the first render opens the legal gate,
                        // and that overlay covers whichever page is behind it.
                        let mut snapshot = quiet_snapshot();
                        // The Policies page is only meaningfully reviewable with an
                        // account selected and its real editor open. The renderer will
                        // load the default policy for this throwaway account on draw.
                        // An empty tab is a screenshot of a paragraph. The one worth
                        // looking at has something installed, something stopped, and a
                        // dry run open on it.
                        if route == Route::Automations {
                            let running = automation_fixture(AutomationState::Enabled, None);
                            let stopped = automation_fixture(
                                AutomationState::Disabled,
                                Some("the last three ticks reverted".to_owned()),
                            );
                            let runs = vec![
                                run_fixture(
                                    running.id,
                                    RunOutcome::Sent,
                                    Some(uuid::Uuid::new_v4()),
                                ),
                                run_fixture(running.id, RunOutcome::Idle, None),
                                run_fixture(running.id, RunOutcome::Failed, None),
                            ];
                            wallet.automation_dry_runs.insert(
                                running.id,
                                AutomationDryRunState::Ready(Box::new(dry_run_fixture())),
                            );
                            snapshot.automation_runs = BTreeMap::from([(running.id, runs)]);
                            snapshot.automations = Ok(vec![running, stopped]);
                        }
                        // An Accounts tab with no account is a picture of the
                        // form above the list, and the list is where the row
                        // geometry and the row's own menu live.
                        if route == Route::Accounts {
                            snapshot.accounts = Ok(vec![WalletMetadata {
                                instance_id: uuid::Uuid::nil(),
                                id: "primary".into(),
                                address: alloy::primitives::Address::ZERO,
                                created_at: chrono::Utc::now(),
                                source: ekubo_wallet_core::config::WalletSource::Created,
                                exported_at: None,
                            }]);
                        }
                        if route == Route::Policies {
                            snapshot.accounts = Ok(vec![WalletMetadata {
                                instance_id: uuid::Uuid::nil(),
                                id: "primary".into(),
                                address: alloy::primitives::Address::ZERO,
                                created_at: chrono::Utc::now(),
                                source: ekubo_wallet_core::config::WalletSource::Created,
                                exported_at: None,
                            }]);
                            wallet.policy_editor = Some(PolicyEditor {
                                wallet_id: "primary".into(),
                                source_revision: Some(1),
                                current_policy: Some(
                                    WalletPolicy::require_approval_for_everything(),
                                ),
                                history: Vec::new(),
                                history_selection: None,
                                proposal: None,
                                validation: Some(Ok(PolicyDraftReview {
                                    wallet_id: "primary".into(),
                                    source_revision: Some(1),
                                    document: String::new(),
                                    policy: WalletPolicy::require_approval_for_everything(),
                                    diff: vec![
                                        "+ Require approval for every transaction".into(),
                                        "+ Refuse automatic signing unless a rule permits it"
                                            .into(),
                                    ],
                                })),
                            });
                            wallet.policy_action_error = None;
                        }
                        wallet.desktop_snapshot = Some(Arc::new(snapshot));
                        wallet.desktop_snapshot_error = None;
                        wallet.legal_gate = false;
                        wallet.legal_review = None;
                        wallet.set_route(route);
                    });
                });
                cx.run_until_parked();
                // `render_to_image` rasterises the last drawn frame, so the window has
                // to be marked dirty and given a chance to draw or every shot is of
                // whatever was on screen before.
                cx.update(|cx| {
                    let _ = cx.update_window(window.into(), |_, window, _| window.refresh());
                });
                cx.run_until_parked();
                if route == Route::Policies {
                    cx.update(|cx| {
                        view.update(cx, |wallet, _| {
                            let max = wallet.route_scroll_handle.max_offset();
                            wallet
                                .route_scroll_handle
                                .set_offset(gpui::point(px(0.0), -max.y));
                        });
                        let _ = cx.update_window(window.into(), |_, window, _| window.refresh());
                    });
                    cx.run_until_parked();
                }
                let image = cx
                    .capture_screenshot(window.into())
                    .expect("offscreen render");
                let path = directory.join(format!(
                    "{}-{mode_name}-{base}.png",
                    route.label().to_lowercase()
                ));
                image.save(&path).expect("write png");
                println!("wrote {}", path.display());
            }
        }
    }
}

#[gpui::test]
fn the_guided_setup_follows_the_owner_onto_every_screen(cx: &mut gpui::TestAppContext) {
    // It is a card, not a page: somebody finishes these tasks by going to the
    // screens they live on, so a checklist that only appeared on one of them
    // would disappear the moment it was acted on.
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    for route in Route::ALL {
        cx.update_entity(&view, |wallet, _| wallet.set_route(route));
        let bounds = measure(cx, window, &view, &["guided-setup"]);

        assert!(
            bounds[0].is_some(),
            "the guided setup is missing from {}",
            route.label()
        );
    }
    release(cx, &view);
}

#[gpui::test]
fn the_guided_setup_stays_off_the_screen_that_has_to_be_accepted(cx: &mut gpui::TestAppContext) {
    // Accepting the terms is the one thing that has to happen before anything
    // else, including reading about what to try next.
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.legal_gate = true);

    let bounds = measure(cx, window, &view, &["guided-setup"]);

    assert!(
        bounds[0].is_none(),
        "the guided setup drew over the legal gate"
    );
    release(cx, &view);
}

#[gpui::test]
fn a_security_review_covers_the_guided_setup_rather_than_sharing_the_screen(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    let before = measure(cx, window, &view, &["guided-setup"]);
    assert!(before[0].is_some(), "the card should start visible");

    cx.update_entity(&view, |wallet, _| {
        wallet.active_review = Some(active_review(ActiveReviewCompletion::Message {
            request_id: uuid::Uuid::new_v4(),
            digest: "0xabc".into(),
        }));
    });
    let bounds = measure(
        cx,
        window,
        &view,
        &["guided-setup", "security-review-overlay"],
    );

    let card = bounds[0].expect("the card is still in the tree");
    let review = bounds[1].expect("the review overlay did not draw");
    // The review is added to the tree after the card and covers the whole
    // window, so every pixel of the card sits behind it. That is what makes a
    // decision the only thing on screen while it is up.
    assert!(
        review.origin.x <= card.origin.x
            && review.origin.y <= card.origin.y
            && review.origin.x + review.size.width >= card.origin.x + card.size.width
            && review.origin.y + review.size.height >= card.origin.y + card.size.height,
        "the review overlay {review:?} does not cover the guided setup {card:?}"
    );
    release(cx, &view);
}

#[gpui::test]
fn every_guided_setup_row_draws_and_the_dismiss_link_takes_the_card_away(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let selectors = [
        "guided-setup-create_account",
        "guided-setup-install_agent",
        "guided-setup-sign_message",
        "guided-setup-connect_dapp",
        "guided-setup-relax_policy",
    ];
    let bounds = measure(cx, window, &view, &selectors);
    for (selector, row) in selectors.iter().zip(&bounds) {
        assert!(row.is_some(), "{selector} did not draw");
    }

    // Pressed rather than called: the way out is a word at the bottom of the
    // card now, and a link nobody can hit is the same as no link at all.
    click(cx, window, &view, "guided-setup-dismiss");
    let after = measure(cx, window, &view, &["guided-setup"]);

    assert!(after[0].is_none(), "a dismissed card came back");
    release(cx, &view);
}

#[gpui::test]
fn the_title_folds_the_checklist_away_and_opens_it_again(cx: &mut gpui::TestAppContext) {
    // Somebody whose corner is covered should not have to give the checklist
    // up for the run to get it back, so the title folds the card down to a
    // line — count and all — and unfolds it.
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    let start = measure(
        cx,
        window,
        &view,
        &["guided-setup", "guided-setup-header", "guided-setup-toggle"],
    );
    let open = start[0].expect("the card starts open");
    let header = start[1].expect("the card header must draw");
    let toggle = start[2].expect("the fold control must draw");

    // The whole header takes the press, not just the words in it. The button
    // this is built from centres its own contents, so a full-width target and
    // a heading that stays at the left edge are two separate things that have
    // to hold at once.
    assert_eq!(
        toggle.size.width, header.size.width,
        "the fold control does not span the header: {toggle:?} in {header:?}"
    );
    assert!(
        toggle.origin.x <= header.origin.x,
        "the fold control is inset from the header: {toggle:?} in {header:?}"
    );

    click(cx, window, &view, "guided-setup-toggle");
    let folded = measure(
        cx,
        window,
        &view,
        &["guided-setup", "guided-setup-tasks", "guided-setup-toggle"],
    );
    let card = folded[0].expect("folding must not send the card away");
    assert!(
        folded[1].is_none(),
        "the task list is still drawn under a folded title: {:?}",
        folded[1]
    );
    assert!(
        folded[2].is_some(),
        "the title has to survive folding — it is the way back"
    );
    assert!(
        card.size.height < open.size.height,
        "the folded card is no shorter than the open one: {card:?} against {open:?}"
    );

    click(cx, window, &view, "guided-setup-toggle");
    let reopened = measure(cx, window, &view, &["guided-setup", "guided-setup-tasks"]);
    assert!(
        reopened[1].is_some(),
        "the title did not open the checklist again"
    );
    release(cx, &view);
}

#[gpui::test]
fn a_finished_row_does_nothing_when_it_is_pressed(cx: &mut gpui::TestAppContext) {
    // A row is a shortcut to the screen its task lives on, and a finished task
    // has nowhere left to send anybody. Ticking the box is not on offer
    // either: completion is read off the wallet, never set here.
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.guided_setup.latch(SetupObservation {
            account: true,
            ..SetupObservation::default()
        });
        wallet.set_route(Route::Settings);
    });

    click(cx, window, &view, "guided-setup-create_account");

    assert_eq!(
        cx.read_entity(&view, |wallet, _| wallet.route),
        Route::Settings,
        "a finished row navigated anyway"
    );

    // The control: an unfinished row in the same card does move, which is what
    // makes the assertion above about the row rather than about a press that
    // never landed.
    click(cx, window, &view, "guided-setup-connect_dapp");

    assert_eq!(
        cx.read_entity(&view, |wallet, _| wallet.route),
        Route::WalletConnect,
        "an unfinished row stopped being a shortcut"
    );
    release(cx, &view);
}

#[gpui::test]
fn the_guided_setup_card_stays_inside_the_smallest_window(cx: &mut gpui::TestAppContext) {
    // The window can be dragged down to 660x500, and the card does not scroll:
    // whatever it draws has to fit there outright.
    //
    // Which state is the tallest is not obvious, so it is not guessed at. Only
    // the task up next is explained, and the explanations are not the same
    // length — the longest belongs to the third task, which nobody sees until
    // they are two tasks in. An empty checklist is the state that gets looked
    // at; a card that overflowed here would do it to somebody who had already
    // done some of this.
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let smallest = gpui::size(px(660.0), px(500.0));
    for done in [
        SetupObservation::default(),
        SetupObservation {
            account: true,
            ..SetupObservation::default()
        },
        SetupObservation {
            account: true,
            agent: true,
            ..SetupObservation::default()
        },
        SetupObservation {
            account: true,
            agent: true,
            signature: true,
            ..SetupObservation::default()
        },
        SetupObservation {
            account: true,
            agent: true,
            signature: true,
            dapp: true,
            ..SetupObservation::default()
        },
    ] {
        cx.update_entity(&view, |wallet, _| {
            wallet.guided_setup.latch(done);
        });
        // The card sizes itself from the window rather than from the space it
        // is handed, because the window is what its margins are measured off —
        // so the window itself has to shrink for this to be the real case.
        cx.simulate_window_resize(window, smallest);
        let bounds = measure_at(
            cx,
            window,
            &view,
            smallest,
            &[
                "guided-setup",
                "guided-setup-header",
                "guided-setup-tasks",
                "guided-setup-dismiss",
            ],
        );
        let card = bounds[0].expect("the card must draw in a minimum-size window");
        let header = bounds[1].expect("the card header must draw");
        let tasks = bounds[2].expect("the task list must draw");
        let dismiss = bounds[3].expect("the way out must draw");

        assert!(
            card.origin.y >= px(0.0) && card.origin.y + card.size.height <= smallest.height,
            "the card does not fit a 660x500 window at {done:?}: {card:?}"
        );
        assert!(
            card.origin.x >= px(0.0) && card.origin.x + card.size.width <= smallest.width,
            "the card does not fit across a 660x500 window at {done:?}: {card:?}"
        );
        // The header carries the count and the fold, and the link is the way
        // out. Both are inside the card, so both follow from the fit above —
        // but they are what the fit is for, so they are asserted rather than
        // assumed.
        assert!(
            header.origin.y >= px(0.0) && header.origin.y + header.size.height <= smallest.height,
            "the header left the window at {done:?}: {header:?}"
        );
        assert!(
            dismiss.origin.y >= px(0.0)
                && dismiss.origin.y + dismiss.size.height <= smallest.height,
            "the dismiss link left the window at {done:?}: {dismiss:?}"
        );
        assert!(
            tasks.origin.y >= px(0.0) && tasks.origin.y + tasks.size.height <= smallest.height,
            "the task list ran off the window instead of fitting inside it at {done:?}: {tasks:?}"
        );
    }
    release(cx, &view);
}

#[gpui::test]
fn a_stopped_automation_leads_with_why_and_offers_to_start_it_again(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let running = automation_fixture(AutomationState::Enabled, None);
    let stopped = automation_fixture(
        AutomationState::AwaitingRelink,
        Some("the signing policy changed to revision 4".to_owned()),
    );
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Automations);
        if let Some(snapshot) = wallet.desktop_snapshot.as_ref() {
            let mut replacement = (**snapshot).clone();
            replacement.automations = Ok(vec![running, stopped]);
            wallet.desktop_snapshot = Some(std::sync::Arc::new(replacement));
        }
    });

    let laid_out = measure(
        cx,
        window,
        &view,
        &["automation-list", "stop-automation", "relink-automation"],
    );
    assert!(laid_out[0].is_some(), "the list must draw");
    // The running one offers Stop; the stopped one offers Start. Both are on
    // screen at once, which is the case that matters — an owner reading this
    // screen is deciding about one of several.
    assert!(laid_out[1].is_some(), "a running automation can be stopped");
    assert!(
        laid_out[2].is_some(),
        "a stopped automation must offer a way back, not just an explanation"
    );
    release(cx, &view);
}

#[gpui::test]
fn an_empty_automations_tab_says_what_one_would_be(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Automations);
    });
    let laid_out = measure(cx, window, &view, &["automation-list", "automations-empty"]);
    // No list at all rather than an empty frame, so the screen is never a
    // blank box the reader has to interpret.
    assert!(laid_out[0].is_none(), "an empty list must not draw");
    // Empty is the state most owners see, and it is the one chance the tab has
    // to explain what an automation is before anyone installs one.
    assert!(
        laid_out[1].is_some(),
        "the empty tab must say what an automation would be"
    );
    release(cx, &view);
}

/// The name is the owner's word for it and the key is the agent's. Reading
/// order follows: the label first, the address it is known by underneath.
#[gpui::test]
fn an_automations_key_sits_under_the_name_the_owner_gave_it(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    let automation = automation_fixture(AutomationState::Enabled, None);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Automations);
        if let Some(snapshot) = wallet.desktop_snapshot.as_ref() {
            let mut replacement = (**snapshot).clone();
            replacement.automations = Ok(vec![automation]);
            wallet.desktop_snapshot = Some(std::sync::Arc::new(replacement));
        }
    });

    let laid_out = measure(
        cx,
        window,
        &view,
        &[
            "automation-title",
            "automation-key",
            "automation-cadence",
            "automation-schedule",
        ],
    );
    let title = laid_out[0].expect("the name must draw");
    let key = laid_out[1].expect("the key must draw");
    assert!(
        key.origin.y > title.origin.y,
        "the key belongs under the name, not beside or above it: {title:?} {key:?}"
    );
    // The cadence in words leads, with the expression it was installed as
    // underneath: one is readable, the other is checkable, and neither
    // replaces the other.
    let cadence = laid_out[2].expect("the schedule must read as a sentence");
    let expression = laid_out[3].expect("the expression must stay on screen");
    assert!(
        expression.origin.y > cadence.origin.y,
        "the expression belongs under the sentence: {cadence:?} {expression:?}"
    );
    release(cx, &view);
}

/// Deleting is offered only once it is stopped: a delete mid-tick races the
/// scheduler, and "should this keep existing" is a second question anyway.
#[gpui::test]
fn only_a_stopped_automation_offers_to_be_deleted(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    let running = automation_fixture(AutomationState::Enabled, None);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Automations);
        if let Some(snapshot) = wallet.desktop_snapshot.as_ref() {
            let mut replacement = (**snapshot).clone();
            replacement.automations = Ok(vec![running]);
            wallet.desktop_snapshot = Some(std::sync::Arc::new(replacement));
        }
    });
    assert!(
        measure(cx, window, &view, &["delete-automation"])[0].is_none(),
        "a running automation must be stopped before it can be deleted"
    );

    let stopped = automation_fixture(
        AutomationState::Disabled,
        Some("you stopped this automation".to_owned()),
    );
    cx.update_entity(&view, |wallet, _| {
        if let Some(snapshot) = wallet.desktop_snapshot.as_ref() {
            let mut replacement = (**snapshot).clone();
            replacement.automations = Ok(vec![stopped]);
            wallet.desktop_snapshot = Some(std::sync::Arc::new(replacement));
        }
    });
    assert!(
        measure(cx, window, &view, &["delete-automation"])[0].is_some(),
        "a stopped automation must be removable without an agent"
    );
    release(cx, &view);
}

/// A dry run is offered in every state, including stopped — "what would this
/// do right now" is the one question a stopped automation can still answer.
#[gpui::test]
fn a_dry_run_can_be_asked_for_and_its_answer_stays_on_screen(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    let automation = automation_fixture(
        AutomationState::Disabled,
        Some("you stopped this automation".to_owned()),
    );
    let id = automation.id;
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Automations);
        if let Some(snapshot) = wallet.desktop_snapshot.as_ref() {
            let mut replacement = (**snapshot).clone();
            replacement.automations = Ok(vec![automation]);
            wallet.desktop_snapshot = Some(std::sync::Arc::new(replacement));
        }
    });
    let laid_out = measure(
        cx,
        window,
        &view,
        &["dry-run-automation", "automation-dry-run"],
    );
    assert!(laid_out[0].is_some(), "a dry run must be offerable");
    assert!(
        laid_out[1].is_none(),
        "nothing was run, so there is nothing to report"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet.automation_dry_runs.insert(
            id,
            crate::desktop::AutomationDryRunState::Ready(Box::new(dry_run_fixture())),
        );
    });
    assert!(
        measure(cx, window, &view, &["automation-dry-run"])[0].is_some(),
        "a finished dry run must stay on screen to be read"
    );
    release(cx, &view);
}

fn dry_run_fixture() -> crate::authority::AutomationDryRun {
    crate::authority::AutomationDryRun {
        ran_at: chrono::Utc::now(),
        block_number: Some(21_000_000),
        failure: None,
        calls: vec![ekubo_wallet_core::automation::PolledCall {
            to: alloy::primitives::Address::repeat_byte(0x22),
            value: alloy::primitives::U256::ZERO,
            data: alloy::primitives::Bytes::from_static(&[0x4e, 0x71, 0xd9, 0x2d]),
        }],
        verdict: Some(crate::authority::AutomationDryRunVerdict {
            policy_revision: 4,
            sends_automatically: false,
            simulation_succeeded: true,
            simulation_failure: None,
            findings: vec!["no rule matched call 1".to_owned()],
        }),
    }
}

fn automation_fixture(state: AutomationState, stopped_reason: Option<String>) -> Automation {
    Automation {
        id: uuid::Uuid::new_v4(),
        wallet_instance_id: uuid::Uuid::new_v4(),
        wallet_id: "primary".into(),
        wallet_address: alloy::primitives::Address::repeat_byte(0x11),
        chain_id: 1,
        key: "rebalance".into(),
        name: "rebalance the vault".into(),
        bytecode: alloy::primitives::Bytes::from_static(&[0x60, 0x00, 0xF3]),
        config: alloy::primitives::Bytes::new(),
        schedule: ekubo_wallet_core::automation::CronSchedule::parse("0 0 * * * *").unwrap(),
        policy_revision: 1,
        state,
        stopped_reason,
        consecutive_failures: 0,
        last_tick_at: None,
        last_outcome: None,
        last_request_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[gpui::test]
fn every_run_is_listed_and_the_ones_that_sent_link_to_their_transaction(
    cx: &mut gpui::TestAppContext,
) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);

    let automation = automation_fixture(AutomationState::Enabled, None);
    let sent = uuid::Uuid::new_v4();
    let runs = vec![
        run_fixture(automation.id, RunOutcome::Idle, None),
        run_fixture(automation.id, RunOutcome::Sent, Some(sent)),
    ];
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Automations);
        if let Some(snapshot) = wallet.desktop_snapshot.as_ref() {
            let mut replacement = (**snapshot).clone();
            replacement.automation_runs = BTreeMap::from([(automation.id, runs)]);
            replacement.automations = Ok(vec![automation]);
            wallet.desktop_snapshot = Some(std::sync::Arc::new(replacement));
        }
    });

    let laid_out = measure(
        cx,
        window,
        &view,
        &["automation-runs", "open-automation-transaction"],
    );
    assert!(
        laid_out[0].is_some(),
        "the run history is what the screen is for"
    );
    assert!(
        laid_out[1].is_some(),
        "a run that produced a transaction must offer a way into its details"
    );
    release(cx, &view);
}

/// A policy banner names an account and selects its tab on the way in.
///
/// An editor open on another account holds a draft nobody saved, so the click
/// has to wait for it the way it already waits for the token and network
/// editors, rather than pulling the tab out from under it.
#[gpui::test]
fn an_open_policy_editor_holds_a_notification_click(cx: &mut gpui::TestAppContext) {
    let (_directory, view, _window) = wallet(cx);
    settle(cx, &view);
    assert!(
        !cx.read_entity(&view, |wallet, _| wallet.notification_navigation_blocked()),
        "nothing owns the window yet"
    );

    cx.update_entity(&view, |wallet, _| {
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(1),
            current_policy: Some(WalletPolicy::require_approval_for_everything()),
            history: Vec::new(),
            history_selection: None,
            proposal: None,
            validation: None,
        });
    });

    assert!(
        cx.read_entity(&view, |wallet, _| wallet.notification_navigation_blocked()),
        "an unsaved policy draft must not be swapped out from under the owner"
    );
    release(cx, &view);
}

/// Deciding a proposal used to render nothing at all.
///
/// Only the failures ever spoke, so a rejection the owner chose and a proposal
/// disappearing underneath them drew exactly the same screen — which is why
/// the first person to try it said "I don't know, man. It's gone."
#[gpui::test]
fn deciding_a_policy_proposal_says_what_was_decided(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::Policies));

    let quiet = measure(cx, window, &view, &["policy-action-status"])[0];
    assert!(
        quiet.is_none(),
        "nothing has been decided, so there is nothing to report"
    );

    cx.update_entity(&view, |wallet, cx| {
        wallet.set_policy_status("Proposal rejected. The active policy is unchanged.", cx);
    });

    let reported = measure(cx, window, &view, &["policy-action-status"])[0];
    assert!(
        reported.is_some(),
        "the owner has to be able to read what their own decision did"
    );
    release(cx, &view);
}

#[gpui::test]
fn the_handoff_button_reports_what_the_clipboard_actually_held(cx: &mut gpui::TestAppContext) {
    let (_directory, view, _window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::WalletConnect));

    // Pressed with something else on the clipboard, the button says so rather
    // than looking inert.
    cx.update(|cx| {
        cx.write_to_clipboard(gpui::ClipboardItem::new_string(
            "ekubo.org is where the pool is".to_owned(),
        ));
    });
    cx.update_entity(&view, |wallet, cx| {
        wallet.connect_walletconnect_from_clipboard(cx);
    });
    let reported = cx.read_entity(&view, |wallet, _| {
        wallet.route_errors.get(&Route::WalletConnect).cloned()
    });
    assert!(
        reported.is_some_and(|error| error.contains("clipboard")),
        "a press with no link on the clipboard must say that is what happened"
    );
    assert!(
        cx.read_entity(&view, |wallet, _| wallet.walletconnect_connecting.is_none()),
        "text that is not a pairing link started a pairing"
    );

    // With a link on it, the press gets as far as the pairing. This wallet has
    // no account to expose, so it stops there and says why instead of failing
    // quietly.
    cx.update(|cx| {
        cx.write_to_clipboard(gpui::ClipboardItem::new_string(format!(
            "wc:{}@2?symKey={}",
            "a".repeat(64),
            "b".repeat(64)
        )));
    });
    cx.update_entity(&view, |wallet, cx| {
        wallet.connect_walletconnect_from_clipboard(cx);
    });
    let reported = cx.read_entity(&view, |wallet, _| {
        wallet.route_errors.get(&Route::WalletConnect).cloned()
    });
    assert!(
        reported.is_some_and(|error| error.contains("account")),
        "a pairing that cannot start must say why"
    );

    release(cx, &view);
}

#[gpui::test]
fn the_walletconnect_page_offers_the_handoff_as_one_press(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| wallet.set_route(Route::WalletConnect));

    let bounds = measure(cx, window, &view, &["paste-walletconnect-uri"]);
    assert!(
        bounds[0].is_some(),
        "the one-press handoff must be on the page a dapp connection starts from"
    );

    release(cx, &view);
}

fn run_fixture(
    automation_id: uuid::Uuid,
    outcome: RunOutcome,
    request_id: Option<uuid::Uuid>,
) -> ekubo_wallet_core::automation_store::AutomationRun {
    ekubo_wallet_core::automation_store::AutomationRun {
        run_id: uuid::Uuid::new_v4(),
        automation_id,
        ran_at: chrono::Utc::now(),
        outcome,
        detail: "ran".into(),
        request_id,
        calls: u32::from(request_id.is_some()),
    }
}
