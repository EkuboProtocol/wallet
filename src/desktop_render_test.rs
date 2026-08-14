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
    let mut visual = gpui::VisualTestContext::from_window(window, cx);
    let view = view.clone();
    visual.draw(gpui::point(px(0.0), px(0.0)), VIEWPORT, |_, _| {
        gpui::AnyView::from(view).into_any_element()
    });
    let bounds = selectors
        .iter()
        .map(|selector| visual.debug_bounds(selector))
        .collect();
    visual.run_until_parked();
    bounds
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
        pane.size.width <= px(720.0),
        "the settings pane must stay within its measure, not stretch to the \
         {VIEWPORT:?} window: it was {:?}",
        pane.size.width
    );
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
    ActiveReview {
        state: ReviewState::new(review_document()),
        simulation: None,
        completion: Some(completion),
        awaiting_refresh: false,
        scroll_handle: ScrollHandle::new(),
        scroll_check_scheduled: false,
        scroll_layout_ready: false,
        scroll_last_max: None,
        scroll_stable_samples: 0,
    }
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
                wallet.desktop_snapshot = Some(Arc::new(quiet_snapshot()));
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
        let image = cx
            .capture_screenshot(window.into())
            .expect("offscreen render");
        let path = directory.join(format!("{}.png", route.label().to_lowercase()));
        image.save(&path).expect("write png");
        println!("wrote {}", path.display());
    }
}
