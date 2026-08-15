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

/// A wallet window over a throwaway database, with the component library, the
/// tokio bridge, and the embedded fonts initialised the way `run_desktop` does.
fn wallet(
    cx: &mut gpui::TestAppContext,
) -> (
    tempfile::TempDir,
    Entity<WalletWindow>,
    gpui::AnyWindowHandle,
) {
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
    (directory, view, window.into())
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
        policies: BTreeMap::new(),
        legal_status: Ok(LegalStatus {
            signing_allowed: true,
            terms_of_service: accepted("terms"),
            privacy_policy: accepted("privacy"),
        }),
        networks: Ok(ekubo_wallet_core::config::default_networks()),
        message_documents: BTreeMap::new(),
        typed_data_documents: BTreeMap::new(),
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
    assert!(
        prose.size.width <= PROSE_MEASURE,
        "explanatory text must stay inside a readable measure: it was {:?}",
        prose.size.width
    );
    assert!(
        pane.size.width <= PAGE_CONTENT_MAX_WIDTH,
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
            header.size.width <= PAGE_CONTENT_MAX_WIDTH,
            "{} header exceeded the shared measure: {:?}",
            route.label(),
            header.size.width
        );
        assert!(
            content.size.width <= PAGE_CONTENT_MAX_WIDTH,
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

#[gpui::test]
fn claude_connector_instructions_require_detected_claude_desktop(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Settings);
        wallet.detected_agents = AgentDetectionState::Ready(Vec::new());
    });
    assert!(
        measure(cx, window, &view, &["claude-desktop-hosted-connector"],)[0].is_none(),
        "hosted connector instructions must stay hidden without Claude Desktop"
    );

    cx.update_entity(&view, |wallet, _| {
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
fn checking_for_updates_keeps_the_action_in_place(cx: &mut gpui::TestAppContext) {
    let (_directory, view, window) = wallet(cx);
    settle(cx, &view);
    cx.update_entity(&view, |wallet, _| {
        wallet.set_route(Route::Settings);
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
    // page — a primary bar with "Add token" floating in the middle of it.
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
        wallet.policy_editor = Some(PolicyEditor {
            wallet_id: "primary".into(),
            source_revision: Some(2),
            current_policy: Some(WalletPolicy::require_approval_for_everything()),
            proposal: None,
            validation: None,
        });
        assert!(document.is_empty());
    });

    let before = measure(
        cx,
        window,
        &view,
        &[
            "policy-agent-tip",
            "policy-json-editor",
            "policy-json-editor-input",
            "policy-json-control",
            "policy-preview-workflow",
            "policy-editor-status",
        ],
    );
    let tip = before[0].expect("the compact agent-policy tip must be laid out");
    assert!(
        tip.size.height <= px(64.0),
        "the agent-policy tip must remain a compact single row: {tip:?}"
    );
    assert!(
        before[5].is_none(),
        "an installed policy must not spend editor space on its revision number"
    );
    let panel = before[1].expect("policy panel must be laid out");
    let editor = before[2].expect("policy JSON editor must be laid out");
    let control = before[3].expect("policy JSON control must be laid out");
    let workflow = before[4].expect("policy review workflow must be laid out");
    assert!(
        editor.size.height >= px(320.0),
        "the initial editor must honor its usable minimum height"
    );
    assert!(
        control.origin.x + control.size.width <= panel.origin.x + panel.size.width,
        "the JSON control must stay inside the policy panel horizontally: \
         panel {panel:?}, control {control:?}"
    );
    assert!(
        control.origin.y + control.size.height <= panel.origin.y + panel.size.height,
        "the JSON control must stay inside the policy panel vertically: \
         panel {panel:?}, control {control:?}"
    );
    assert!(
        workflow.origin.y + workflow.size.height <= panel.origin.y + panel.size.height,
        "the complete workflow must stay inside the policy panel: \
         panel {panel:?}, workflow {workflow:?}"
    );

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
    let after = measure(cx, window, &view, &["policy-json-editor-input"])[0]
        .expect("policy JSON editor must remain laid out after review");
    assert!(
        after.size.height >= editor.size.height,
        "reviewing must extend the scrollable page instead of shrinking the editor: \
         before {:?}, after {:?}",
        editor.size.height,
        after.size.height
    );

    let max_offset = cx.read_entity(&view, |wallet, _| wallet.route_scroll_handle.max_offset());
    cx.read_entity(&view, |wallet, _| {
        wallet
            .route_scroll_handle
            .set_offset(gpui::point(px(0.0), -max_offset.y));
    });
    let bottom = measure(
        cx,
        window,
        &view,
        &[
            "route-content-scroll",
            "route-content-inner",
            "policies-content",
            "policy-json-editor",
            "policy-preview-workflow",
            "policy-permission-diff",
            "install-policy-draft",
        ],
    );
    let scroll = bottom[0].expect("policy scroll viewport must be laid out");
    let route_content = bottom[1].expect("route content must be laid out");
    let policies = bottom[2].expect("policy content must be laid out");
    let editor = bottom[3].expect("policy editor must be laid out");
    let workflow = bottom[4].expect("policy workflow must be laid out");
    let diff = bottom[5].expect("computed permission changes must be laid out");
    let install = bottom[6].expect("policy install action must be laid out");
    let scroll_state = cx.read_entity(&view, |wallet, _| {
        (
            wallet.route_scroll_handle.offset(),
            wallet.route_scroll_handle.max_offset(),
            wallet.route_scroll_handle.bounds(),
        )
    });
    assert!(
        install.origin.y + install.size.height <= diff.origin.y + diff.size.height,
        "the install action must remain inside the permission-diff border: \
         diff {diff:?}, install {install:?}"
    );
    assert!(
        diff.origin.y + diff.size.height + px(16.0) <= scroll.origin.y + scroll.size.height,
        "the bottom of the policy must retain visible scroll padding: \
         viewport {scroll:?}, route content {route_content:?}, policies {policies:?}, \
         editor {editor:?}, workflow {workflow:?}, diff {diff:?}, scroll state {scroll_state:?}"
    );

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

    for route in Route::ALL {
        cx.update(|cx| {
            view.update(cx, |wallet, _| {
                // Re-applied each frame: the first render opens the legal gate,
                // and that overlay covers whichever page is behind it.
                let mut snapshot = quiet_snapshot();
                // The Policies page is only meaningfully reviewable with an
                // account selected and its real editor open. The renderer will
                // load the default policy for this throwaway account on draw.
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
                        current_policy: Some(WalletPolicy::require_approval_for_everything()),
                        proposal: None,
                        validation: Some(Ok(PolicyDraftReview {
                            wallet_id: "primary".into(),
                            source_revision: Some(1),
                            document: String::new(),
                            policy: WalletPolicy::require_approval_for_everything(),
                            diff: vec![
                                "+ Require approval for every transaction".into(),
                                "+ Refuse automatic signing unless a rule permits it".into(),
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
        let path = directory.join(format!("{}.png", route.label().to_lowercase()));
        image.save(&path).expect("write png");
        println!("wrote {}", path.display());
    }
}
