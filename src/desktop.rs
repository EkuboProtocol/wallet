use crate::{
    BUILD_VERSION,
    agent_config::AgentAdapter,
    assets::{PENCIL_ICON, WalletAssets},
    authority::{
        ApplicationAuthority, ExportLease, OwnerActivityRecord, OwnerApi, OwnerPortfolioAccount,
        OwnerPortfolioSnapshot, OwnerReviewQueues, OwnerTransactionInspection,
        PRIVATE_KEY_REVEAL_DURATION,
    },
    automation::{Automation, AutomationState},
    automation_store::{AutomationRun, RunOutcome},
    gui_review::{GuiReviewCommand, GuiReviewPresenter, GuiReviewPrompt},
    ipc_server::McpIpcServer,
    notifications::{
        NotificationPreferences, NotificationRoute, NotificationService as _,
        PlatformNotificationService, TransactionContext, initialize_platform_notifications,
        notification_for,
    },
    release_check::ReleaseCheck,
    review::ReviewState,
    single_instance::{InstanceOutcome, SingleInstance},
    tray::{PlatformTray, TrayCommand, TrayService, TraySnapshot},
    walletconnect::{
        ProposalCommand, ProposalPresenter, ProposalPrompt, SessionSummary, WalletConnectManager,
        run_session,
    },
};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::approval::{
    ApprovalFact, ApprovalSection, ApprovalSectionKind, ReviewDecision, ReviewDocument,
};
use ekubo_wallet_core::config::{NativeCurrency, NetworkConfig, RpcStrategy, WalletMetadata};
use ekubo_wallet_core::core::policy::{WalletPolicy, diff_policies};
use ekubo_wallet_core::custody::PrivateKeyMaterial;
use ekubo_wallet_core::desktop_store::{AgentKind, AppearancePreference};
use ekubo_wallet_core::legal::{LegalDocument, LegalStatus};
use ekubo_wallet_core::message::MessageStatus;
use ekubo_wallet_core::pending::{PendingStatus, PendingTransaction};
use ekubo_wallet_core::policy_store::{PolicyProposal, StoredPolicy};
use ekubo_wallet_core::token_store::{ListedToken, StoredToken, TokenProposal};
use ekubo_wallet_core::typed_data::TypedDataStatus;
use gpui::{
    Anchor, AnyElement, AnyView, App, ClipboardItem, Context, CursorStyle, ElementId, Entity,
    FocusHandle, HitboxBehavior, Interactivity, KeyBinding, ListAlignment,
    ListState as VariableListState, MouseButton, MouseDownEvent, MouseMoveEvent, PathBuilder,
    Pixels, QuitMode, Render, RenderImage, RenderOnce, Role, ScrollAnchor, ScrollHandle,
    SharedString, StatefulInteractiveElement, Subscription, Task, UniformListScrollHandle,
    WeakEntity, Window, WindowAppearance, WindowBounds, WindowHandle, WindowOptions, actions,
    anchored, canvas, deferred, div, fill, font, img, list as variable_list, point, prelude::*, px,
    size, uniform_list,
};
use gpui_component::{
    ActiveTheme, Disableable, FocusTrapElement, Icon, IconName, IndexPath, Root, Selectable,
    Sizable, StyledExt, Theme, ThemeMode, ThemeTokens, WindowExt as _,
    alert::Alert,
    button::{Button, ButtonGroup, ButtonVariant, ButtonVariants},
    collapsible::Collapsible,
    dialog::{Dialog, DialogButtonProps, DialogFooter},
    form::{field, v_form},
    h_flex,
    input::{Input, InputContentType, InputEvent, InputState},
    list::{List, ListDelegate, ListEvent, ListItem, ListState},
    scroll::{ScrollableElement as _, ScrollbarHandle},
    skeleton::Skeleton,
    spinner::Spinner,
    switch::Switch,
    tab::{Tab, TabBar},
    text::TextView,
    v_flex,
};
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

actions!(
    ekubo_wallet,
    [
        OpenCommandPalette,
        CloseOverlay,
        CloseWindow,
        HideApplication,
        Quit
    ]
);

const UI_FONT_FAMILY: &str = "Suisse Intl";
const MONO_FONT_FAMILY: &str = "Suisse Intl Mono";
const NAVIGATION_RAIL_WIDTH: gpui::Pixels = px(80.0);
const NAVIGATION_BUTTON_SIZE: gpui::Pixels = px(52.0);
const BUTTON_HEIGHT: gpui::Pixels = px(44.0);
const PAGE_CONTENT_MAX_WIDTH: gpui::Pixels = px(720.0);
const ACTIVITY_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
/// How long a balance read stays fresh enough that reopening the Portfolio tab
/// reuses it instead of reading again.
///
/// Every network the account holds is read on each refresh, so opening the tab
/// is not a free action to repeat. A minute is short enough that the balances
/// on screen are the ones a person just acted on, and long enough that pacing
/// between tabs does not turn into a request per click.
const PORTFOLIO_REFRESH_INTERVAL: chrono::TimeDelta = chrono::TimeDelta::minutes(1);
/// How often the Portfolio tab redraws to keep its "refreshed …" line honest.
///
/// Nothing else redraws a tab that is merely being read, so without this the
/// line would keep claiming the age it had when the balances landed. Half the
/// label's own resolution keeps it from lagging a minute behind.
const PORTFOLIO_CLOCK_INTERVAL: Duration = Duration::from_secs(30);
const DESKTOP_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const COPY_BUTTON_HEIGHT: gpui::Pixels = px(32.0);
const CONTROL_RADIUS: gpui::Pixels = px(14.0);
const SURFACE_RADIUS: gpui::Pixels = px(16.0);
const POLICY_EDITOR_DESCRIPTION: &str =
    "Requests are automatically signed or refused, or require review.";
const LATEST_RELEASE_URL: &str = "https://github.com/EkuboProtocol/wallet/releases/latest";

fn app_button(id: impl Into<ElementId>) -> Button {
    Button::new(id)
        // Keep the component's semantic Medium size so icons and text retain
        // their intended metrics. Passing a pixel value to `with_size` scales
        // icons and padding; it does not set a button height.
        .h(BUTTON_HEIGHT)
        .px_3()
        .rounded(px(12.0))
        .font_medium()
}

fn next_overflow_indicator_offset(
    current: gpui::Pixels,
    maximum: gpui::Pixels,
    viewport_height: gpui::Pixels,
    multiplier: u16,
) -> gpui::Pixels {
    (current - viewport_height * 0.72 * f32::from(multiplier)).max(-maximum)
}

const OVERFLOW_PAGING_BURST_TIMEOUT: Duration = Duration::from_millis(400);

#[derive(Default)]
struct OverflowPagingState {
    last_press: Option<Instant>,
    multiplier: u16,
    animation_generation: u64,
    target_y: Option<gpui::Pixels>,
}

impl OverflowPagingState {
    fn begin_press(
        &mut self,
        now: Instant,
        current: gpui::Pixels,
        maximum: gpui::Pixels,
        viewport_height: gpui::Pixels,
    ) -> (gpui::Pixels, u64) {
        let continues_burst = self.last_press.is_some_and(|last_press| {
            now.saturating_duration_since(last_press) <= OVERFLOW_PAGING_BURST_TIMEOUT
        });
        self.multiplier = if continues_burst {
            self.multiplier.max(1).saturating_mul(2)
        } else {
            1
        };
        // A rapid press arrives before the previous animation has covered
        // much distance. Build from that animation's destination instead of
        // its intermediate offset, otherwise replacing the animation throws
        // most of the accelerated distance away.
        let origin = if continues_burst {
            self.target_y.unwrap_or(current)
        } else {
            current
        };
        let target_y =
            next_overflow_indicator_offset(origin, maximum, viewport_height, self.multiplier);
        self.last_press = Some(now);
        self.target_y = Some(target_y);
        self.animation_generation = self.animation_generation.wrapping_add(1);
        (target_y, self.animation_generation)
    }
}

const fn overflow_indicator_opacity(hovered: bool) -> f32 {
    if hovered { 1.0 } else { 0.82 }
}

fn sidebar_tooltip_position(
    button_bounds: gpui::Bounds<gpui::Pixels>,
) -> gpui::Point<gpui::Pixels> {
    let mut position = button_bounds.right_center();
    position.x += px(10.0);
    position
}

/// A bottom-edge affordance that exists only while more vertical content is
/// below the viewport. It paints directly from the live scroll handle, so it
/// neither contributes layout space nor needs a persistent scrollbar track.
#[derive(Clone)]
enum OverflowScrollHandle {
    Continuous(ScrollHandle),
    Uniform(UniformListScrollHandle),
    Variable(VariableListState),
}

impl ScrollbarHandle for OverflowScrollHandle {
    fn offset(&self) -> gpui::Point<gpui::Pixels> {
        match self {
            Self::Continuous(handle) => handle.offset(),
            Self::Uniform(handle) => handle.offset(),
            Self::Variable(handle) => handle.scroll_px_offset_for_scrollbar(),
        }
    }

    fn set_offset(&self, offset: gpui::Point<gpui::Pixels>) {
        match self {
            Self::Continuous(handle) => handle.set_offset(offset),
            Self::Uniform(handle) => handle.set_offset(offset),
            Self::Variable(handle) => handle.set_offset_from_scrollbar(offset),
        }
    }

    fn content_size(&self) -> gpui::Size<gpui::Pixels> {
        match self {
            Self::Continuous(handle) => handle.content_size(),
            Self::Uniform(handle) => handle.content_size(),
            Self::Variable(handle) => {
                let viewport = handle.viewport_bounds().size;
                size(
                    viewport.width,
                    viewport.height + handle.max_offset_for_scrollbar().y,
                )
            }
        }
    }
}

impl From<ScrollHandle> for OverflowScrollHandle {
    fn from(handle: ScrollHandle) -> Self {
        Self::Continuous(handle)
    }
}

impl From<UniformListScrollHandle> for OverflowScrollHandle {
    fn from(handle: UniformListScrollHandle) -> Self {
        Self::Uniform(handle)
    }
}

impl From<VariableListState> for OverflowScrollHandle {
    fn from(handle: VariableListState) -> Self {
        Self::Variable(handle)
    }
}

struct ScrollOverflowIndicatorView {
    scroll_handle: Rc<RefCell<OverflowScrollHandle>>,
    paging: Rc<RefCell<OverflowPagingState>>,
}

impl Render for ScrollOverflowIndicatorView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let prepaint_handle = self.scroll_handle.clone();
        let paint_handle = self.scroll_handle.clone();
        let paint_paging = self.paging.clone();
        let accent = cx.theme().primary;
        canvas(
            move |bounds, window, _| {
                let handle = prepaint_handle.borrow();
                let remaining =
                    (handle.content_size().height - bounds.size.height) + handle.offset().y;
                if remaining <= px(1.0) {
                    return None;
                }
                let hitbox_size = size(px(80.0), px(36.0));
                let hitbox_bounds = gpui::Bounds::new(
                    point(
                        bounds.origin.x + (bounds.size.width - hitbox_size.width) / 2.0,
                        bounds.origin.y + bounds.size.height - hitbox_size.height - px(6.0),
                    ),
                    hitbox_size,
                );
                Some((
                    window.insert_hitbox(hitbox_bounds, HitboxBehavior::Normal),
                    bounds.size.height,
                ))
            },
            move |_bounds, indicator, window, _cx| {
                let Some((hitbox, viewport_height)) = indicator else {
                    return;
                };
                let hovered = hitbox.is_hovered(window);
                let opacity = overflow_indicator_opacity(hovered);
                let view_id = window.current_view();
                window.set_cursor_style(CursorStyle::PointingHand, &hitbox);
                window.paint_quad(
                    fill(hitbox.bounds, accent.opacity(opacity * 0.28)).corner_radii(px(18.0)),
                );

                let center_x = hitbox.origin.x + hitbox.size.width / 2.0;
                let center_y = hitbox.origin.y + hitbox.size.height / 2.0;
                let mut chevron = PathBuilder::stroke(px(2.5));
                chevron.move_to(point(center_x - px(13.0), center_y - px(5.0)));
                chevron.line_to(point(center_x, center_y + px(5.0)));
                chevron.line_to(point(center_x + px(13.0), center_y - px(5.0)));
                if let Ok(path) = chevron.build() {
                    window.paint_path(path, accent.opacity(opacity));
                }

                window.on_mouse_event({
                    let hitbox = hitbox.clone();
                    move |_: &MouseMoveEvent, phase, window, cx| {
                        if phase.bubble() && hitbox.is_hovered(window) != hovered {
                            cx.notify(view_id);
                        }
                    }
                });
                window.on_mouse_event({
                    let hitbox = hitbox.clone();
                    let scroll_handle = paint_handle.clone();
                    move |event: &MouseDownEvent, phase, window, cx| {
                        if !phase.bubble()
                            || event.button != MouseButton::Left
                            || !hitbox.is_hovered(window)
                        {
                            return;
                        }
                        let scroll_handle = scroll_handle.borrow().clone();
                        let max =
                            (scroll_handle.content_size().height - viewport_height).max(px(0.0));
                        let offset = scroll_handle.offset();
                        let (target_y, animation_generation) = paint_paging
                            .borrow_mut()
                            .begin_press(Instant::now(), offset.y, max, viewport_height);
                        let animated_handle = scroll_handle.clone();
                        let animated_paging = paint_paging.clone();
                        window
                            .spawn(cx, async move |cx| {
                                const FRAMES: u16 = 20;
                                for frame in 1..=FRAMES {
                                    cx.background_executor()
                                        .timer(Duration::from_millis(8))
                                        .await;
                                    if animated_paging.borrow().animation_generation
                                        != animation_generation
                                    {
                                        break;
                                    }
                                    let progress = f32::from(frame) / f32::from(FRAMES);
                                    let eased = 1.0 - (1.0 - progress).powi(3);
                                    let y = offset.y + (target_y - offset.y) * eased;
                                    let frame_handle = animated_handle.clone();
                                    let _ = cx.update(move |_, cx| {
                                        frame_handle.set_offset(point(offset.x, y));
                                        cx.notify(view_id);
                                    });
                                }
                            })
                            .detach();
                        cx.stop_propagation();
                    }
                });
            },
        )
        .absolute()
        .inset_0()
    }
}

struct ScrollOverflowIndicator {
    scroll_handle: Rc<RefCell<OverflowScrollHandle>>,
    view: Entity<ScrollOverflowIndicatorView>,
}

impl ScrollOverflowIndicator {
    fn new(
        scroll_handle: impl Into<OverflowScrollHandle>,
        cx: &mut App,
    ) -> ScrollOverflowIndicator {
        let scroll_handle = Rc::new(RefCell::new(scroll_handle.into()));
        let view_handle = scroll_handle.clone();
        let paging = Rc::new(RefCell::new(OverflowPagingState::default()));
        let view = cx.new(|_| ScrollOverflowIndicatorView {
            scroll_handle: view_handle,
            paging,
        });
        Self {
            scroll_handle,
            view,
        }
    }

    fn set_scroll_handle(&self, scroll_handle: impl Into<OverflowScrollHandle>) {
        *self.scroll_handle.borrow_mut() = scroll_handle.into();
    }

    fn element(&self) -> AnyView {
        self.view.clone().into()
    }
}

/// A conventional bordered section with its heading inside the content flow.
/// Keeping the title in normal layout avoids border collisions and preserves
/// the same hierarchy on every settings surface.
#[derive(IntoElement)]
struct GroupBox {
    id: Option<ElementId>,
    title: Option<AnyElement>,
    children: Vec<AnyElement>,
    gap: gpui::Pixels,
}

impl GroupBox {
    fn new() -> Self {
        Self {
            id: None,
            title: None,
            children: Vec::new(),
            gap: px(16.0),
        }
    }

    fn id(mut self, id: impl Into<ElementId>) -> Self {
        self.id = Some(id.into());
        self
    }

    fn title(mut self, title: impl IntoElement) -> Self {
        self.title = Some(title.into_any_element());
        self
    }

    fn compact(mut self) -> Self {
        self.gap = px(8.0);
        self
    }
}

impl ParentElement for GroupBox {
    fn extend(&mut self, elements: impl IntoIterator<Item = AnyElement>) {
        self.children.extend(elements);
    }
}

impl RenderOnce for GroupBox {
    fn render(self, _: &mut Window, cx: &mut App) -> impl IntoElement {
        div()
            .id(self.id.unwrap_or_else(|| "group-box".into()))
            .w_full()
            .min_w_0()
            .p_4()
            .rounded(cx.theme().radius)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .text_color(cx.theme().group_box_foreground)
            .flex()
            .flex_col()
            .gap(self.gap)
            .when_some(self.title, |section, title| {
                section.child(
                    div()
                        .text_size(px(15.0))
                        .font_medium()
                        .text_color(cx.theme().group_box_foreground)
                        .child(title),
                )
            })
            .children(self.children)
    }
}

/// The component button exposes a stable accessibility ID but not an explicit
/// label for icon-only controls. This thin wrapper applies a screen-reader name
/// to the same underlying focusable button without changing its visual layout.
#[derive(IntoElement)]
struct AccessibleButton(Button);

impl InteractiveElement for AccessibleButton {
    fn interactivity(&mut self) -> &mut Interactivity {
        self.0.interactivity()
    }
}

impl StatefulInteractiveElement for AccessibleButton {}

impl RenderOnce for AccessibleButton {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        self.0
    }
}

fn accessible_button(button: Button, label: impl Into<SharedString>) -> AccessibleButton {
    AccessibleButton(button).aria_label(label)
}

fn app_input(state: &Entity<InputState>, cx: &App) -> Input {
    // The upstream medium control is only 32px tall. Large inputs meet the
    // 44px interaction target; the surface override matches the Figma field
    // fill while leaving the component's focus border intact.
    Input::new(state).large().bg(cx.theme().secondary)
}

/// Columns of policy JSON that stay on one display line no matter how narrow
/// the window gets.
const POLICY_EDITOR_MIN_COLUMNS: f32 = 120.0;

/// Columns of slack added on top of [`POLICY_EDITOR_MIN_COLUMNS`] to cover the
/// editor's line-number gutter, which it subtracts from its own wrap width.
/// Five digits is more line numbers than a policy document will ever have.
const POLICY_EDITOR_GUTTER_COLUMNS: f32 = 5.0;

/// The two fixed margins the code editor takes off its wrap width alongside the
/// gutter: `LINE_NUMBER_RIGHT_MARGIN` and `RIGHT_MARGIN`, both 10px upstream.
const POLICY_EDITOR_FIXED_MARGINS: Pixels = px(20.0);

/// The narrowest the policy JSON control is allowed to be laid out.
///
/// The code editor soft-wraps at whatever width it is handed, so in a narrow
/// window a policy folds at a few dozen columns and stops reading as JSON.
/// Floor the control here and let the pane scroll horizontally underneath,
/// rather than letting the window dictate how short a line may get.
///
/// The floor is on the *text*, so it has to out-cover the chrome the editor
/// subtracts from its own wrap width before wrapping the remainder.
fn policy_editor_min_width(cx: &App) -> Pixels {
    // `app_input` builds every input `.large()`, which resolves to `text_base`
    // — one rem — and gpui-component pins the window's rem size to the theme
    // font size. Measuring at that size keeps the floor correct if either moves.
    let font_size = cx.theme().font_size;
    let text_system = cx.text_system();
    let font_id = text_system.resolve_font(&font(MONO_FONT_FAMILY));
    // Suisse Intl Mono ships embedded, so the measurement only misses if font
    // loading itself did; 0.6em is the usual advance for a monospace face.
    let column = text_system
        .advance(font_id, font_size, '0')
        .map_or(font_size * 0.6, |advance| advance.width);
    column * (POLICY_EDITOR_MIN_COLUMNS + POLICY_EDITOR_GUTTER_COLUMNS)
        + POLICY_EDITOR_FIXED_MARGINS
}

fn field_error(
    id: impl Into<SharedString>,
    message: impl Into<SharedString>,
    cx: &App,
) -> impl IntoElement {
    let id = id.into();
    let message = message.into();
    div()
        .id(id.clone())
        .role(Role::Alert)
        .text_sm()
        .text_color(cx.theme().danger)
        .child(selectable_text(format!("{id}-text"), &message))
}

#[derive(Default)]
struct CopyFeedbackState {
    copied: bool,
}

#[derive(IntoElement)]
struct CopyButton {
    id: ElementId,
    value: CopyButtonValue,
    accessibility_label: SharedString,
    large: bool,
}

enum CopyButtonValue {
    Owned(String),
    Lazy(Rc<dyn Fn() -> String>),
}

impl CopyButton {
    fn large(mut self) -> Self {
        self.large = true;
        self
    }
}

impl RenderOnce for CopyButton {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let state =
            window.use_keyed_state(self.id.clone(), cx, |_, _| CopyFeedbackState::default());
        let copied = state.read(cx).copied;
        let value = self.value;
        let state_for_click = state.clone();
        app_button(self.id)
            .when(!self.large, |button| {
                button
                    .small()
                    .h(COPY_BUTTON_HEIGHT)
                    .px_2()
                    .rounded(px(10.0))
            })
            .ghost()
            .icon(if copied {
                IconName::Check
            } else {
                IconName::Copy
            })
            .label(if copied { "Copied" } else { "Copy" })
            .tooltip(self.accessibility_label)
            .when(!copied, |button| {
                button.on_click(move |_, _, cx| {
                    let value = match &value {
                        CopyButtonValue::Owned(value) => value.clone(),
                        CopyButtonValue::Lazy(value) => value(),
                    };
                    cx.write_to_clipboard(ClipboardItem::new_string(value));
                    state_for_click.update(cx, |state, cx| {
                        state.copied = true;
                        cx.notify();
                    });
                    let state = state_for_click.clone();
                    cx.spawn(async move |cx| {
                        cx.background_executor().timer(Duration::from_secs(1)).await;
                        state.update(cx, |state, cx| {
                            state.copied = false;
                            cx.notify();
                        });
                    })
                    .detach();
                })
            })
    }
}

fn copy_button(
    id: impl Into<ElementId>,
    value: String,
    accessibility_label: impl Into<SharedString>,
) -> CopyButton {
    CopyButton {
        id: id.into(),
        value: CopyButtonValue::Owned(value),
        accessibility_label: accessibility_label.into(),
        large: false,
    }
}

fn lazy_copy_button(
    id: impl Into<ElementId>,
    value: Rc<dyn Fn() -> String>,
    accessibility_label: impl Into<SharedString>,
) -> CopyButton {
    CopyButton {
        id: id.into(),
        value: CopyButtonValue::Lazy(value),
        accessibility_label: accessibility_label.into(),
        large: false,
    }
}

/// Which account tab the policies page shows as selected. The editor owns the
/// selection, so an account whose editor has not opened yet — or that has been
/// deleted out from under the editor — falls back to the first tab.
fn policy_selected_account_index(
    account_labels: &[String],
    editor_wallet_id: Option<&str>,
) -> usize {
    editor_wallet_id
        .and_then(|wallet_id| account_labels.iter().position(|label| label == wallet_id))
        .unwrap_or_default()
}

/// The pending proposal, if any, belonging to the account whose policy tab is
/// open. Proposals for other accounts stay with their own tabs.
fn policy_proposal_for_account<'a>(
    proposals: &'a [PolicyProposal],
    editor_wallet_id: &str,
) -> Option<&'a PolicyProposal> {
    proposals
        .iter()
        .find(|proposal| proposal.wallet_id == editor_wallet_id)
}

/// Balance rows that have not arrived yet, drawn in the card and at the row
/// pitch the real ones use. A spinner says only that the app is busy; these
/// say a list of tokens is what is coming, and where it will be.
fn portfolio_loading_placeholder(cx: &App) -> gpui::Div {
    // Uneven widths, because equal-length bars read as a rendered table rather
    // than as a placeholder for one.
    const ROWS: [(gpui::Pixels, gpui::Pixels, gpui::Pixels); 3] = [
        (px(184.0), px(96.0), px(248.0)),
        (px(136.0), px(72.0), px(212.0)),
        (px(208.0), px(112.0), px(264.0)),
    ];
    let mut card = div()
        .w_full()
        .min_w_0()
        .p_4()
        .rounded(cx.theme().radius_lg)
        .border_1()
        .border_color(cx.theme().border)
        .bg(cx.theme().secondary)
        .flex()
        .flex_col();
    for (index, (identity, balance, metadata)) in ROWS.into_iter().enumerate() {
        card = card.child(
            div()
                .w_full()
                .min_w_0()
                .py_2()
                .when(index + 1 < ROWS.len(), |row| {
                    row.border_b_1().border_color(cx.theme().border)
                })
                .flex()
                .flex_col()
                .gap_1p5()
                .child(
                    div()
                        .w_full()
                        .min_w_0()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(Skeleton::new().h_5().w(identity).max_w_full())
                        .child(Skeleton::new().h_5().w(balance).flex_none()),
                )
                .child(Skeleton::new().secondary().h_3().w(metadata).max_w_full()),
        );
    }
    card
}

fn account_switcher(
    id: impl Into<ElementId>,
    account_labels: &[String],
    selected_index: usize,
    on_click: impl Fn(&usize, &mut Window, &mut App) + 'static,
) -> TabBar {
    TabBar::new(id)
        .w_full()
        .segmented()
        .large()
        .selected_index(selected_index)
        .on_click(on_click)
        .children(
            account_labels
                .iter()
                .cloned()
                .map(|label| Tab::new().label(label)),
        )
}

/// Literal text for a renderer that reads markup. HTML is the format that can
/// express "this is text": five characters have meaning and escaping them is
/// positionless and complete.
///
/// Markdown cannot. Backslash escapes are ignored inside the constructs that
/// swallow punctuation. HTML keeps the escaped text literal.
fn html_escaped_plain_text(value: &str) -> SharedString {
    let mut html = String::with_capacity(value.len());
    for (index, line) in value.split('\n').enumerate() {
        if index > 0 {
            // A newline the caller wrote is a line the reader should see.
            // Markdown joined those lines into a paragraph.
            html.push_str("<br>");
        }
        push_html_escaped(&mut html, line);
    }
    html.into()
}

fn selectable_text(id: impl Into<ElementId>, value: &str) -> TextView {
    TextView::html(id, html_escaped_plain_text(value)).selectable(true)
}

fn push_html_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
}

/// Legal documents are trusted, bundled text, but still need HTML escaping.
/// Rendering them as HTML keeps ordinary punctuation literal and lets the
/// component's native link handler open only validated HTTP(S) URLs.
fn legal_row_html(value: &str) -> SharedString {
    let mut html = String::with_capacity(value.len());
    for (index, word) in value.split(' ').enumerate() {
        if index > 0 {
            html.push(' ');
        }
        let candidate = word.trim_end_matches(['.', ',', ';', ':', ')', ']']);
        let suffix = &word[candidate.len()..];
        let parsed = url::Url::parse(candidate)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some());
        if let Some(url) = parsed {
            html.push_str("<a href=\"");
            push_html_escaped(&mut html, url.as_str());
            html.push_str("\">");
            push_html_escaped(&mut html, candidate);
            html.push_str("</a>");
            push_html_escaped(&mut html, suffix);
        } else {
            push_html_escaped(&mut html, word);
        }
    }
    html.into()
}

fn selectable_legal_text(
    id: impl Into<ElementId>,
    value: &str,
    link_url: Option<&str>,
) -> TextView {
    let html = if let Some(link_url) = link_url {
        let mut html = String::with_capacity(value.len() + link_url.len() + 32);
        html.push_str("<a href=\"");
        push_html_escaped(&mut html, link_url);
        html.push_str("\">");
        push_html_escaped(&mut html, value);
        html.push_str("</a>");
        html.into()
    } else {
        legal_row_html(value)
    };
    TextView::html(id, html).selectable(true)
}

/// Selectable copy for singular labels, descriptions, status messages, and
/// alerts. `track_caller` gives each call site a stable element identity; list
/// rows use `selectable_text` directly with their record identity instead.
#[track_caller]
fn selectable_label(value: impl Into<SharedString>) -> TextView {
    let value = value.into();
    gpui_component::text::html(html_escaped_plain_text(&value)).selectable(true)
}

fn selectable_error_alert(id: impl Into<SharedString>, message: impl Into<SharedString>) -> Alert {
    let id = id.into();
    let message = message.into();
    Alert::error(
        id.clone(),
        selectable_text(format!("{id}-message"), &message),
    )
}

fn selectable_warning_alert(
    id: impl Into<SharedString>,
    message: impl Into<SharedString>,
) -> Alert {
    let id = id.into();
    let message = message.into();
    Alert::warning(
        id.clone(),
        selectable_text(format!("{id}-message"), &message),
    )
}

fn markdown_fenced_code(value: &str) -> SharedString {
    let longest_run = value
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or_default();
    let fence = "`".repeat(longest_run.saturating_add(1).max(3));
    format!("{fence}text\n{value}\n{fence}").into()
}

fn selectable_code_text(id: impl Into<ElementId>, value: &str) -> TextView {
    TextView::markdown(id, markdown_fenced_code(value)).selectable(true)
}

/// What the digest row is called, which depends on whether anything signed it.
///
/// It read "Digest that was signed" in every state, including directly under
/// an explanation saying "You turned this down, so no signature was ever
/// produced." One of the two was lying, and the label is the one a reader
/// skims.
const fn digest_label(signed: bool) -> &'static str {
    if signed {
        "Digest that was signed"
    } else {
        "Digest this would have signed"
    }
}

fn copyable_value(id: impl Into<SharedString>, label: &'static str, value: String) -> gpui::Div {
    let id = id.into();
    let text_id = SharedString::from(format!("{id}-text"));
    let button_id = SharedString::from(format!("{id}-copy"));
    div()
        .w_full()
        .min_w_0()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_sm()
                .font_medium()
                .child(selectable_text(format!("{id}-label"), label)),
        )
        .child(
            h_flex()
                .w_full()
                .min_w_0()
                .gap_2()
                .child(
                    selectable_text(text_id, &value)
                        .min_w_0()
                        .flex_1()
                        .truncate()
                        .font_family(MONO_FONT_FAMILY)
                        .text_sm(),
                )
                .child(copy_button(button_id, value, format!("Copy {label}"))),
        )
}

fn primary_enter(event: &InputEvent) -> bool {
    matches!(
        event,
        InputEvent::PressEnter {
            secondary: false,
            shift: false
        }
    )
}

const EMBEDDED_FONTS: &[&[u8]] = &[
    include_bytes!("../assets/fonts/SuisseIntl-Regular.ttf"),
    include_bytes!("../assets/fonts/SuisseIntl-Medium.ttf"),
    include_bytes!("../assets/fonts/SuisseIntl-SemiBold.ttf"),
    include_bytes!("../assets/fonts/SuisseIntl-Bold.ttf"),
    include_bytes!("../assets/fonts/SuisseIntlMono-Regular.ttf"),
    include_bytes!("../assets/fonts/SuisseIntlMono-Bold.ttf"),
];

fn load_application_fonts(cx: &mut App) -> Result<()> {
    cx.text_system().add_fonts(
        EMBEDDED_FONTS
            .iter()
            .map(|font| Cow::Borrowed(*font))
            .collect(),
    )?;
    let theme = cx.global_mut::<Theme>();
    theme.font_family = UI_FONT_FAMILY.into();
    theme.mono_font_family = MONO_FONT_FAMILY.into();
    Ok(())
}

#[derive(Clone, PartialEq, gpui::Action)]
#[action(namespace = ekubo_wallet, no_json)]
struct NavigateRoute {
    route: Route,
}

struct DesktopRuntime {
    _instance: Arc<Mutex<Option<SingleInstance>>>,
    _server: Arc<Mutex<Option<McpIpcServer>>>,
    _walletconnect: Arc<Mutex<crate::walletconnect::WalletConnectManager>>,
    _tray: Rc<RefCell<Option<PlatformTray>>>,
    _pending_update: Arc<Mutex<Option<PreparedUpdate>>>,
}

impl gpui::Global for DesktopRuntime {}

fn next_required_legal(status: &LegalStatus) -> Option<LegalDocument> {
    if !status.terms_of_service.accepted {
        Some(LegalDocument::TermsOfService)
    } else if !status.privacy_policy.accepted {
        Some(LegalDocument::PrivacyPolicy)
    } else {
        None
    }
}

fn legal_requires_acceptance(document: LegalDocument) -> bool {
    matches!(
        document,
        LegalDocument::TermsOfService | LegalDocument::PrivacyPolicy
    )
}

fn legal_review_requires_acceptance(document: LegalDocument, status: Option<&LegalStatus>) -> bool {
    legal_requires_acceptance(document)
        && status.is_none_or(|status| match document {
            LegalDocument::TermsOfService => !status.terms_of_service.accepted,
            LegalDocument::PrivacyPolicy => !status.privacy_policy.accepted,
            LegalDocument::ApplicationLicense | LegalDocument::ThirdPartyLicenses => false,
        })
}

/// The readable width for a line of explanatory text.
///
/// A settings row wants the full measure — its control belongs at the right
/// edge — but the sentence under the row does not. Measured, the prose in this
/// pane ran 634px, which at 14px is about ninety characters a line; the
/// comfortable band is nearer sixty-five to seventy-five. Capping the prose
/// rather than the pane keeps the rows where the platform puts them.
const PROSE_MEASURE: gpui::Pixels = px(520.0);

/// Where the add/edit network dialog sits, and how tall it may grow.
struct NetworkEditorMetrics {
    width: gpui::Pixels,
    top: gpui::Pixels,
    max_height: gpui::Pixels,
}

/// Size the network editor against the window it opens in.
///
/// `Dialog` places its own top at a tenth of the viewport unless it is told
/// otherwise, so a height capped at the viewport once put the footer — Cancel
/// and Save — below the bottom of the window, and the body's scroll never
/// engaged because the dialog was never the thing that ran out of room. Pinning
/// the top and subtracting the inset twice makes the cap real: the dialog stops
/// inside the window, the footer stays put, and the form scrolls within it.
///
/// [`NetworkEditorMetrics::max_height`] is a ceiling and nothing else. The
/// dialog is as tall as its form and stops growing an inset short of the
/// bottom of the window, so a window tall enough to hold the whole form holds
/// it without a scrollbar, and a window that is not scrolls the form inside a
/// dialog that still ends on screen. A fixed height did neither: it was too
/// short to ever show the whole form on a large display and it left a short
/// form padded out to a size nothing had asked for.
fn network_editor_metrics(viewport: gpui::Size<gpui::Pixels>) -> NetworkEditorMetrics {
    // Preserve breathing room where possible without ever making the modal
    // larger than the window that contains it.
    let horizontal_inset = viewport.width.min(px(32.0));
    let vertical_inset = (viewport.height / 8.0).min(px(24.0));
    NetworkEditorMetrics {
        width: (viewport.width - horizontal_inset).min(px(760.0)),
        top: vertical_inset,
        max_height: (viewport.height - vertical_inset * 2.0).max(px(120.0)),
    }
}

fn settings_section(title: &'static str, content: GroupBox) -> gpui::Div {
    div().w_full().child(content.title(title))
}

fn untitled_settings_section(content: GroupBox) -> gpui::Div {
    div().w_full().child(content)
}

/// The portfolio and the policy editor dead-end on the same missing account,
/// and each used to say so in a panel of its own shape — one a bordered card
/// with a bold heading, the other a `GroupBox`. Two looks for one condition
/// read as two different problems, so both pages ask for the account here.
fn account_required_panel(
    panel_id: &'static str,
    button_id: &'static str,
    message: &'static str,
    cx: &mut Context<WalletWindow>,
) -> GroupBox {
    GroupBox::new()
        .id(panel_id)
        .title("Create your first account")
        .child(selectable_label(message))
        .child(
            app_button(button_id)
                .self_start()
                .label("Go to Accounts")
                .primary()
                .on_click(cx.listener(|view, _, _, cx| {
                    view.set_route(Route::Accounts);
                    cx.notify();
                })),
        )
}

/// One row of the About panel: a name, an optional status line beneath it, and
/// a single action on the right. Each row used to assemble its own container,
/// so the buttons did not share a column and the status hung off the name
/// behind a `·` where a second line reads more easily.
fn about_row(
    title: &'static str,
    detail: Option<(SharedString, gpui::Hsla)>,
    action: impl IntoElement,
    ruled: bool,
    cx: &App,
) -> gpui::Div {
    h_flex()
        .w_full()
        .items_center()
        .justify_between()
        .gap_4()
        // Each row is a name, a fact about it, and one control, and the
        // control sits a column away from the name. A rule between rows is
        // what keeps the pairing obvious without asking the eye to track
        // across a gap. The final rule separates the actionable rows from the
        // informational copyright footer below them.
        .when(ruled, |row| {
            row.pb_2().border_b_1().border_color(cx.theme().border)
        })
        .child(
            div()
                .min_w_0()
                .flex_1()
                .flex()
                .flex_col()
                .gap_1()
                .child(selectable_label(title))
                .when_some(detail, |column, (status, color)| {
                    column.child(
                        div()
                            .text_sm()
                            .text_color(color)
                            .child(selectable_label(status)),
                    )
                }),
        )
        .child(div().flex_none().child(action))
}

fn scroll_reached_end(offset_y: gpui::Pixels, max_offset_y: gpui::Pixels) -> bool {
    -offset_y >= max_offset_y - px(1.0)
}

fn legal_acceptance_label(status: &ekubo_wallet_core::legal::DocumentStatus) -> String {
    match (status.accepted, status.accepted_at.as_ref()) {
        (true, Some(accepted_at)) => {
            format!("Accepted {}", accepted_at.format("%Y-%m-%d %H:%M UTC"))
        }
        (true, None) => "Accepted".into(),
        (false, _) => "Review required".into(),
    }
}

/// The acceptance line under a legal document's name, toned so a document that
/// still needs a decision is visibly different from one already accepted.
fn legal_acceptance_detail(
    status: &ekubo_wallet_core::legal::DocumentStatus,
    cx: &App,
) -> (SharedString, gpui::Hsla) {
    let color = if status.accepted {
        cx.theme().muted_foreground
    } else {
        cx.theme().warning
    };
    (legal_acceptance_label(status).into(), color)
}

fn format_asset_amount(raw: &str, decimals: Option<u8>, base_unit: &str) -> String {
    let Some(decimals) = decimals else {
        return format!("{raw} {base_unit}");
    };
    ekubo_wallet_core::approval_summary::format_fixed_point(raw, decimals)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PortfolioBalanceRow {
    chain_id: u64,
    network_name: String,
    asset_address: String,
    token_symbol: Option<String>,
    token_name: Option<String>,
    native: bool,
    balance: String,
    explorer_url: Option<String>,
}

fn portfolio_balance_rows(account: &OwnerPortfolioAccount) -> Vec<PortfolioBalanceRow> {
    const NATIVE_ASSET_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
    let mut rows = Vec::new();
    for item in &account.networks {
        let Ok(portfolio) = &item.result else {
            continue;
        };
        let network_name = item
            .network
            .display_name
            .as_deref()
            .unwrap_or(&item.network.name)
            .to_owned();
        if portfolio.native_balance != "0" {
            let native = item.network.native_currency.as_ref();
            rows.push(PortfolioBalanceRow {
                chain_id: item.network.chain_id,
                network_name: network_name.clone(),
                asset_address: NATIVE_ASSET_ADDRESS.to_owned(),
                token_symbol: native.map(|currency| currency.symbol.clone()),
                token_name: native.map(|currency| currency.name.clone()),
                native: true,
                balance: format_asset_amount(
                    &portfolio.native_balance,
                    native.map(|currency| currency.decimals),
                    "wei",
                ),
                explorer_url: None,
            });
        }
        rows.extend(portfolio.tokens.iter().map(|token| PortfolioBalanceRow {
            chain_id: item.network.chain_id,
            network_name: network_name.clone(),
            asset_address: token.address.clone(),
            token_symbol: token.symbol.clone(),
            token_name: token.name.clone(),
            native: false,
            balance: format_asset_amount(&token.balance, token.decimals, "base units"),
            explorer_url: block_explorer_token_url(&item.network, &token.address),
        }));
    }
    sort_portfolio_balance_rows(&mut rows);
    rows
}

fn sort_portfolio_balance_rows(rows: &mut [PortfolioBalanceRow]) {
    rows.sort_by(|left, right| {
        left.chain_id.cmp(&right.chain_id).then_with(|| {
            left.asset_address
                .to_ascii_lowercase()
                .cmp(&right.asset_address.to_ascii_lowercase())
        })
    });
}

fn clamped_portfolio_account_index(account_count: usize, selected: usize) -> usize {
    selected.min(account_count.saturating_sub(1))
}

fn token_list_url_draft(value: &str) -> Result<String> {
    let value = value.trim();
    ensure!(!value.is_empty(), "enter the published token-list URL");
    let parsed = url::Url::parse(value).context("token-list URL is not valid")?;
    ensure!(parsed.scheme() == "https", "token-list URL must use https");
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "token-list URL must not carry credentials"
    );
    ensure!(
        parsed.fragment().is_none(),
        "token-list URL must not carry a fragment"
    );
    ensure!(
        parsed.port().is_none(),
        "token-list URL must use the default https port"
    );
    ensure!(parsed.host().is_some(), "token-list URL has no host");
    Ok(value.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// These are independent capabilities of one persisted lifecycle state; an
// enum would still need to enumerate every valid combination.
#[allow(clippy::struct_excessive_bools)]
struct TransactionActions {
    send: bool,
    cancel: bool,
    discard: bool,
}

fn transaction_actions(status: PendingStatus) -> TransactionActions {
    TransactionActions {
        send: matches!(status, PendingStatus::Signed | PendingStatus::Broadcast),
        cancel: matches!(
            status,
            PendingStatus::Submitting | PendingStatus::Broadcast | PendingStatus::Cancelling
        ),
        discard: status == PendingStatus::Signed,
    }
}

/// How a lifecycle state should read to the eye before it is read as words.
/// Kept separate from the theme so the mapping stays a pure, testable fact
/// about the state rather than about the palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusTone {
    /// Finished, and it did what it said it would.
    Done,
    /// Nothing is moving until the owner decides something.
    NeedsYou,
    /// Moving on its own; no decision is required right now.
    Working,
    /// Finished badly, or ended without doing anything.
    Failed,
}

impl StatusTone {
    fn color(self, cx: &App) -> gpui::Hsla {
        match self {
            Self::Done => cx.theme().primary,
            Self::NeedsYou => cx.theme().warning,
            Self::Working => cx.theme().muted_foreground,
            Self::Failed => cx.theme().danger,
        }
    }
}

/// Whether an agent can reach this wallet right now.
///
/// The listener status drives tray availability and the actionable Settings
/// error. Bridges keep running independently, so an offline listener means
/// they will wait and reconnect when the wallet makes same-user IPC available
/// again.
#[derive(Clone)]
enum McpGatewayStatus {
    Starting,
    Online,
    Offline(SharedString),
}

impl McpGatewayStatus {
    /// Only a failure has detail: the reason the local endpoint could not be
    /// served is actionable even though routine reachability is not shown.
    fn detail(&self) -> Option<SharedString> {
        match self {
            Self::Starting | Self::Online => None,
            Self::Offline(error) => Some(error.clone()),
        }
    }
}

const fn transaction_status_tone(status: PendingStatus) -> StatusTone {
    match status {
        PendingStatus::Confirmed => StatusTone::Done,
        PendingStatus::AwaitingApproval | PendingStatus::Signed => StatusTone::NeedsYou,
        PendingStatus::Submitting | PendingStatus::Broadcast | PendingStatus::Cancelling => {
            StatusTone::Working
        }
        PendingStatus::Rejected
        | PendingStatus::Reverted
        | PendingStatus::Cancelled
        | PendingStatus::Replaced => StatusTone::Failed,
    }
}

fn transaction_receipt_is_provisional(record: &PendingTransaction) -> bool {
    matches!(
        record.status,
        PendingStatus::Confirmed | PendingStatus::Reverted | PendingStatus::Cancelled
    ) && record.settlement_transaction_hash.is_some()
        && record.finalized_at.is_none()
}

/// Whether the network can still advance this row without another owner
/// action. Signed-but-unsent bytes deliberately do not qualify: only pressing
/// Send can change them. A terminal receipt remains refreshable until its
/// block is final, because a reorg can still change that apparent outcome.
const fn transaction_status_needs_automatic_refresh(status: PendingStatus) -> bool {
    matches!(
        status,
        PendingStatus::Submitting | PendingStatus::Broadcast | PendingStatus::Cancelling
    )
}

fn transaction_needs_status_refresh(record: &PendingTransaction) -> bool {
    transaction_status_needs_automatic_refresh(record.status)
        || transaction_receipt_is_provisional(record)
}

fn transaction_record_tone(record: &PendingTransaction) -> StatusTone {
    if transaction_receipt_is_provisional(record) {
        StatusTone::Working
    } else {
        transaction_status_tone(record.status)
    }
}

fn transaction_record_label(record: &PendingTransaction) -> &'static str {
    if transaction_receipt_is_provisional(record) {
        match record.status {
            PendingStatus::Confirmed => "Succeeded, confirming",
            PendingStatus::Reverted => "Failed on chain, confirming",
            PendingStatus::Cancelled => "Cancellation confirming",
            _ => record.status.label(),
        }
    } else {
        record.status.label()
    }
}

fn transaction_record_explanation(record: &PendingTransaction) -> &'static str {
    if transaction_receipt_is_provisional(record) {
        "A receipt was observed, but its block is not final yet. The wallet is rechecking it and will not sign another transaction for this account and network meanwhile."
    } else {
        record.status.explanation()
    }
}

const fn message_status_tone(status: MessageStatus) -> StatusTone {
    match status {
        MessageStatus::AwaitingApproval => StatusTone::NeedsYou,
        MessageStatus::Rejected => StatusTone::Failed,
        MessageStatus::Signed => StatusTone::Done,
    }
}

const fn message_status_explanation(status: MessageStatus) -> &'static str {
    match status {
        MessageStatus::AwaitingApproval => {
            "Nothing has been signed. This message is waiting for your decision."
        }
        MessageStatus::Rejected => "You turned this down, so no signature was ever produced.",
        MessageStatus::Signed => {
            "You approved this and the wallet signed it. The signature was returned to whoever asked."
        }
    }
}

const fn typed_data_status_tone(status: TypedDataStatus) -> StatusTone {
    match status {
        TypedDataStatus::AwaitingApproval => StatusTone::NeedsYou,
        TypedDataStatus::Rejected => StatusTone::Failed,
        TypedDataStatus::Signed => StatusTone::Done,
    }
}

const fn typed_data_status_explanation(status: TypedDataStatus) -> &'static str {
    match status {
        TypedDataStatus::AwaitingApproval => {
            "Nothing has been signed. This structured message is waiting for your decision."
        }
        TypedDataStatus::Rejected => "You turned this down, so no signature was ever produced.",
        TypedDataStatus::Signed => {
            "You approved this and the wallet signed it. A signed permission of this kind can usually be used until it expires."
        }
    }
}

/// "3 minutes ago" instead of an RFC 3339 timestamp. Anything older than a
/// week reads as a calendar date, because "63 days ago" is not something a
/// person can place.
fn relative_time_label(
    moment: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let elapsed = now.signed_duration_since(moment);
    let seconds = elapsed.num_seconds();
    if seconds < 45 {
        // Clock skew between the writer and this render can make a fresh
        // record look like it arrived from the future. "Just now" is true
        // either way, and a negative age never reaches the arms below.
        return "just now".to_owned();
    }
    let plural = |count: i64, unit: &str| {
        if count == 1 {
            format!("1 {unit} ago")
        } else {
            format!("{count} {unit}s ago")
        }
    };
    if seconds < 3_600 {
        return plural(elapsed.num_minutes().max(1), "minute");
    }
    if seconds < 86_400 {
        return plural(elapsed.num_hours(), "hour");
    }
    if seconds < 7 * 86_400 {
        return plural(elapsed.num_days(), "day");
    }
    moment
        .with_timezone(&chrono::Local)
        .format("%-d %b %Y")
        .to_string()
}

/// The exact moment in the reader's own timezone. UTC is precise and useless
/// for placing an event against your own day, so it is not shown.
fn absolute_time_label(moment: chrono::DateTime<chrono::Utc>) -> String {
    moment
        .with_timezone(&chrono::Local)
        .format("%-d %b %Y at %H:%M")
        .to_string()
}

fn walletconnect_expiry_label(expires_at: i64, now: chrono::DateTime<chrono::Utc>) -> String {
    let remaining = expires_at.saturating_sub(now.timestamp());
    if remaining <= 0 {
        return "Expired; reconnect to renew".to_owned();
    }
    if remaining < 60 {
        return "Expires in less than a minute; reconnect to renew".to_owned();
    }
    let (count, unit) = if remaining < 3_600 {
        (remaining.saturating_add(59) / 60, "minute")
    } else if remaining < 86_400 {
        (remaining.saturating_add(3_599) / 3_600, "hour")
    } else {
        (remaining.saturating_add(86_399) / 86_400, "day")
    };
    format!(
        "Expires in {count} {unit}{}; reconnect to renew",
        if count == 1 { "" } else { "s" }
    )
}

/// "1 request" / "3 requests" — the `(s)` suffix reads like a form field.
fn pluralize(count: usize, singular: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {singular}s")
    }
}

fn set_agent_installed(kind: AgentKind, installed: bool) -> Result<()> {
    let adapter = AgentAdapter::supported()?
        .into_iter()
        .find(|adapter| adapter.kind == kind)
        .with_context(|| format!("{} is not a supported agent", kind.label()))?;
    let preview = if installed {
        adapter.preview_install()?
    } else {
        adapter.preview_remove()?
    };
    let batch = crate::agent_config::ConfigBatchInstall::install(vec![preview])?;
    batch.commit();
    Ok(())
}

fn detect_agents() -> Result<Vec<DetectedAgent>> {
    Ok(AgentAdapter::supported()?
        .into_iter()
        .filter(AgentAdapter::detected)
        .map(|adapter| DetectedAgent {
            kind: adapter.kind,
            display_name: adapter.display_name,
            config_path: adapter.config_path.display().to_string(),
            installed: adapter
                .preview_install()
                .map(|preview| !preview.has_changes())
                .map_err(|error| format!("{error:#}").into()),
        })
        .collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Route {
    Overview,
    Activity,
    Accounts,
    Policies,
    Automations,
    Networks,
    Tokens,
    WalletConnect,
    Settings,
}

impl Route {
    /// Rail order, top to bottom, and therefore also the numeric shortcut
    /// order. It runs setup → activity → rules → connections → reference data:
    /// an account has to exist before anything else in the wallet can happen,
    /// so `Accounts` is both the first tab and the screen a new install opens
    /// on. `Activity` follows because it is where an agent's requests land and
    /// where the day's decisions are made.
    const ALL: [Self; 9] = [
        Self::Accounts,
        Self::Activity,
        Self::Overview,
        Self::Policies,
        // Directly after Policies, because an automation is only ever as
        // capable as the policy above it: the two screens are read together
        // when something has stopped running.
        Self::Automations,
        Self::WalletConnect,
        Self::Tokens,
        Self::Networks,
        Self::Settings,
    ];

    /// The screen a freshly opened window shows when nothing has asked for a
    /// particular one. It is deliberately the same as the first rail entry.
    const DEFAULT: Self = Self::ALL[0];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Portfolio",
            Self::Activity => "Inbox",
            Self::Accounts => "Accounts",
            Self::Policies => "Policies",
            Self::Automations => "Automations",
            Self::Networks => "Networks",
            Self::Tokens => "Tokens",
            Self::WalletConnect => "WalletConnect",
            Self::Settings => "Settings",
        }
    }

    /// One line under the page title saying what the screen is for. Every
    /// route names the reader's own task, not the data structure behind it.
    const fn description(self) -> &'static str {
        match self {
            Self::Accounts => {
                "The keys this wallet holds. Create or import an account before connecting an agent."
            }
            Self::Activity => {
                "Requests waiting on your decision, and everything this wallet has signed or sent."
            }
            Self::Overview => "What each account holds, across every network you have enabled.",
            Self::Policies => {
                "The rules that decide which agent requests go through, which need you, and which are refused."
            }
            Self::Automations => {
                "Code an agent installed that this wallet runs on a schedule. Every transaction one produces still goes through your policy."
            }
            Self::WalletConnect => {
                "Connect your wallet to dapps via WalletConnect and use them like you would with any other wallet."
            }
            Self::Tokens => "Token metadata that helps you understand transaction amounts.",
            Self::Networks => {
                "The chains this wallet will sign for, and the RPC endpoints it uses."
            }
            Self::Settings => "Appearance, agent setup, updates, and the legal documents.",
        }
    }

    fn menu_order(self) -> usize {
        Self::ALL
            .iter()
            .position(|candidate| *candidate == self)
            .unwrap_or(usize::MAX)
    }

    const fn icon(self) -> IconName {
        match self {
            Self::Overview => IconName::LayoutDashboard,
            Self::Activity => IconName::Inbox,
            Self::Accounts => IconName::User,
            Self::Policies => IconName::Inspector,
            Self::Automations => IconName::Bot,
            Self::Networks => IconName::Network,
            Self::Tokens => IconName::Star,
            Self::WalletConnect => IconName::Globe,
            Self::Settings => IconName::Settings,
        }
    }

    /// Rail position drives both the displayed shortcut and the registered
    /// binding, so reordering `ALL` can never leave the first tab on ⌘3.
    #[cfg(target_os = "macos")]
    const SHORTCUT_KEYS: [&'static str; 9] = ["⌘1", "⌘2", "⌘3", "⌘4", "⌘5", "⌘6", "⌘7", "⌘8", "⌘9"];
    #[cfg(not(target_os = "macos"))]
    const SHORTCUT_KEYS: [&'static str; 9] = [
        "Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4", "Ctrl+5", "Ctrl+6", "Ctrl+7", "Ctrl+8", "Ctrl+9",
    ];

    #[cfg(target_os = "macos")]
    const KEY_BINDINGS: [&'static str; 9] = [
        "cmd-1", "cmd-2", "cmd-3", "cmd-4", "cmd-5", "cmd-6", "cmd-7", "cmd-8", "cmd-9",
    ];
    #[cfg(not(target_os = "macos"))]
    const KEY_BINDINGS: [&'static str; 9] = [
        "ctrl-1", "ctrl-2", "ctrl-3", "ctrl-4", "ctrl-5", "ctrl-6", "ctrl-7", "ctrl-8", "ctrl-9",
    ];

    fn shortcut(self) -> SharedString {
        let key = Self::SHORTCUT_KEYS
            .get(self.menu_order())
            .copied()
            .unwrap_or_default();
        if self == Self::Settings {
            // The platform's own preferences shortcut also opens Settings, and
            // it stays with the route rather than with whichever slot it sits
            // in.
            SharedString::from(format!("{key} / {SETTINGS_ALTERNATE_SHORTCUT}"))
        } else {
            SharedString::from(key)
        }
    }

    fn key_binding(self) -> &'static str {
        Self::KEY_BINDINGS
            .get(self.menu_order())
            .copied()
            .unwrap_or_default()
    }
}

#[cfg(target_os = "macos")]
const SETTINGS_ALTERNATE_KEY_BINDING: &str = "cmd-,";
#[cfg(not(target_os = "macos"))]
const SETTINGS_ALTERNATE_KEY_BINDING: &str = "ctrl-,";
#[cfg(target_os = "macos")]
const SETTINGS_ALTERNATE_SHORTCUT: &str = "⌘,";
#[cfg(not(target_os = "macos"))]
const SETTINGS_ALTERNATE_SHORTCUT: &str = "Ctrl+,";

fn reset_route_scroll_if_changed(current: Route, next: Route, scroll: &ScrollHandle) {
    if current != next {
        scroll.set_offset(gpui::point(px(0.0), px(0.0)));
    }
}

// These flags describe independent controls and async operations. Combining
// them into one state machine would admit fewer valid combinations, not make
// the state safer.
#[allow(clippy::struct_excessive_bools)]
pub struct WalletWindow {
    owner: OwnerApi,
    desktop_snapshot: Option<Arc<DesktopSnapshot>>,
    desktop_snapshot_generation: u64,
    desktop_snapshot_loading: bool,
    desktop_snapshot_dirty: bool,
    desktop_snapshot_error: Option<SharedString>,
    tray: Rc<RefCell<Option<PlatformTray>>>,
    sidebar_logo_light: Arc<RenderImage>,
    sidebar_logo_dark: Arc<RenderImage>,
    appearance_subscription: Option<Subscription>,
    review_presenter: GuiReviewPresenter,
    route: Route,
    sidebar_hovered_route: Option<Route>,
    sidebar_route_bounds: BTreeMap<Route, Rc<Cell<Option<gpui::Bounds<gpui::Pixels>>>>>,
    command_palette: bool,
    command_palette_list: Option<Entity<ListState<RouteListDelegate>>>,
    command_palette_subscription: Option<Subscription>,
    form_input_subscriptions: Vec<Subscription>,
    token_list: Option<Entity<ListState<TokenListDelegate>>>,
    token_search_input: Option<Entity<InputState>>,
    token_proposal_list: Option<Entity<ListState<TokenProposalListDelegate>>>,
    token_list_url_input: Option<Entity<InputState>>,
    token_chain_id_input: Option<Entity<InputState>>,
    token_address_input: Option<Entity<InputState>>,
    token_symbol_input: Option<Entity<InputState>>,
    token_name_input: Option<Entity<InputState>>,
    token_decimals_input: Option<Entity<InputState>>,
    token_editor_open: bool,
    token_editor_errors: TokenEditorErrors,
    token_editor_busy: bool,
    token_list_import_open: bool,
    token_import_state: TokenImportState,
    token_import_error: Option<SharedString>,
    token_import_status: Option<SharedString>,
    token_proposal_error: Option<SharedString>,
    token_list_generation: u64,
    mcp_status: McpGatewayStatus,
    selected_record: Option<uuid::Uuid>,
    inbox_tab: InboxTab,
    activity_busy: BTreeSet<uuid::Uuid>,
    activity_refreshing: BTreeSet<uuid::Uuid>,
    activity_refresh_task: Option<Task<()>>,
    activity_feedback: BTreeMap<uuid::Uuid, ActivityFeedback>,
    /// Names the newest note on each row, so a timer set for an older one
    /// cannot take a newer one off the screen with it.
    activity_feedback_seq: u64,
    history_clearing: bool,
    history_clear_error: Option<SharedString>,
    activity_inspections: BTreeMap<uuid::Uuid, ActivityInspectionState>,
    /// Records whose exact machine payload the owner has asked to see. The
    /// bytes stay collapsed by default so the human account of what happened
    /// is what a reader meets first.
    activity_payloads_expanded: BTreeSet<(uuid::Uuid, String)>,
    active_review: Option<ActiveReview>,
    queued_reviews: SerialQueue<QueuedReview>,
    review_flow: ReviewFlowState,
    /// The most recent notification the owner clicked while a decision or
    /// editor owned the window. Navigation is intent, not a work queue: a
    /// later click supersedes an earlier one and must be the screen that opens
    /// when the blocker leaves.
    notification_navigation: NotificationNavigation,
    agent_reinstall: AgentReinstallState,
    detected_agents: AgentDetectionState,
    detected_agents_generation: u64,
    account_id_input: Option<Entity<InputState>>,
    private_key_input: Option<Entity<InputState>>,
    account_entry_mode: AccountEntryMode,
    account_operation: Option<AccountOperation>,
    account_status: Option<SharedString>,
    /// Names the newest note, so a timer set for an older one cannot take a
    /// newer one off the screen with it.
    account_status_seq: u64,
    account_id_error: Option<SharedString>,
    private_key_error: Option<SharedString>,
    account_action_errors: BTreeMap<String, SharedString>,
    account_export: Option<AccountExport>,
    export_clipboard: Arc<Mutex<Option<Zeroizing<String>>>>,
    legal_review: Option<LegalReview>,
    legal_gate: bool,
    route_errors: BTreeMap<Route, SharedString>,
    appearance_preference: AppearancePreference,
    testnet_mode: bool,
    portfolio: PortfolioState,
    portfolio_generation: u64,
    portfolio_account_index: usize,
    /// When the balances on screen were last read, per account.
    ///
    /// Keyed by account because the read is per account: that one account's
    /// balances are a minute old says nothing about how stale another's are,
    /// and the tab reopens onto whichever account was focused last.
    ///
    /// Only successful reads land here, so a failed refresh leaves the tab
    /// eligible to try again the next time it is opened.
    portfolio_refreshed_at: BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    portfolio_clock_task: Option<Task<()>>,
    route_scroll_handle: ScrollHandle,
    route_overflow_indicator: ScrollOverflowIndicator,
    policy_editor_anchor: ScrollAnchor,
    modal_focus: FocusHandle,
    walletconnect: Arc<Mutex<WalletConnectManager>>,
    walletconnect_sessions: Vec<SessionSummary>,
    /// The pairing started by the last press of Connect, until it produces a
    /// proposal, settles, or ends.
    ///
    /// A pairing URI is good for one session, and pressing Connect took the
    /// whole round trip to the relay before anything on screen changed — so
    /// the second half of a double click landed on a button that still looked
    /// idle and burned the URI on a second pairing that could never settle.
    /// While this is set the button is busy and the press is refused.
    walletconnect_connecting: Option<uuid::Uuid>,
    walletconnect_presenter: ProposalPresenter,
    walletconnect_uri_input: Option<Entity<InputState>>,
    network_editor_open: bool,
    network_editor_scroll_handle: ScrollHandle,
    network_editor_overflow_indicator: ScrollOverflowIndicator,
    network_editor_original: Option<NetworkConfig>,
    network_editor_disabled: bool,
    network_editor_testnet: bool,
    network_editor_rpc_strategy: RpcStrategy,
    /// The optional fields live behind a disclosure so the required ones fit
    /// without scrolling. Edit opens it when the network already uses one,
    /// because a gas cap nobody can see is worse than a longer form.
    network_editor_advanced_open: bool,
    network_editor_busy: bool,
    network_editor_errors: NetworkEditorErrors,
    network_name_input: Option<Entity<InputState>>,
    network_display_name_input: Option<Entity<InputState>>,
    network_aliases_input: Option<Entity<InputState>>,
    network_chain_id_input: Option<Entity<InputState>>,
    network_rpc_urls_input: Option<Entity<InputState>>,
    network_native_name_input: Option<Entity<InputState>>,
    network_native_symbol_input: Option<Entity<InputState>>,
    network_native_decimals_input: Option<Entity<InputState>>,
    network_explorer_url_input: Option<Entity<InputState>>,
    network_documentation_url_input: Option<Entity<InputState>>,
    network_action_busy: BTreeSet<String>,
    network_action_errors: BTreeMap<String, SharedString>,
    network_proposal_error: Option<SharedString>,
    review_overflow_indicator: ScrollOverflowIndicator,
    legal_overflow_indicator: ScrollOverflowIndicator,
    activity_detail_scroll_handle: ScrollHandle,
    activity_detail_overflow_indicator: ScrollOverflowIndicator,
    activity_detail_record: Cell<Option<uuid::Uuid>>,
    policy_json_input: Option<Entity<InputState>>,
    policy_editor: Option<PolicyEditor>,
    policy_account_id: Option<String>,
    policy_installing: bool,
    policy_action_error: Option<SharedString>,
    token_proposal_busy: bool,
    network_proposal_busy: bool,
    /// The automation whose stop or restart is in flight, so its own row shows
    /// the spinner rather than the whole list going busy.
    automation_busy: Option<uuid::Uuid>,
    automation_error: Option<SharedString>,
    release_state: ReleaseDisplayState,
    pending_update: Arc<Mutex<Option<PreparedUpdate>>>,
    update_data_dir: PathBuf,
}

/// How many of an automation's runs the tab shows.
///
/// The store keeps thousands; this screen answers "what has it been doing
/// lately", and a page rendering a per-second automation's whole history is a
/// page nobody scrolls to the end of.
const AUTOMATION_RUNS_SHOWN: usize = 20;

#[derive(Clone)]
struct DesktopSnapshot {
    reviews: std::result::Result<OwnerReviewQueues, SharedString>,
    activity: std::result::Result<Arc<[OwnerActivityRecord]>, SharedString>,
    /// Which agent asked for each record, where one did. Empty rather than an
    /// error when the lookup fails: a row still names its source from the plan
    /// it carries, and a history list is not worth failing to draw over the
    /// attribution it could not read.
    activity_sources: BTreeMap<uuid::Uuid, SharedString>,
    accounts: std::result::Result<Vec<WalletMetadata>, SharedString>,
    policies: BTreeMap<String, std::result::Result<Option<StoredPolicy>, SharedString>>,
    legal_status: std::result::Result<LegalStatus, SharedString>,
    networks: std::result::Result<Vec<NetworkConfig>, SharedString>,
    automations: std::result::Result<Vec<Automation>, SharedString>,
    /// The recent runs of each automation. Captured with the automations
    /// themselves so the tab draws a complete row in one pass rather than
    /// fetching per card while the reader watches.
    automation_runs: BTreeMap<uuid::Uuid, Vec<AutomationRun>>,
    message_documents: BTreeMap<uuid::Uuid, std::result::Result<ReviewDocument, SharedString>>,
    typed_data_documents: BTreeMap<uuid::Uuid, std::result::Result<ReviewDocument, SharedString>>,
}

impl DesktopSnapshot {
    fn capture(owner: &OwnerApi) -> Self {
        let reviews = cache_result(owner.reviews(None));
        let automations = cache_result(owner.automations());
        let automation_runs = automations.as_ref().map_or_else(
            |_| BTreeMap::new(),
            |automations| {
                automations
                    .iter()
                    .filter_map(|automation| {
                        owner
                            .automation_runs(automation.id, AUTOMATION_RUNS_SHOWN)
                            .ok()
                            .map(|runs| (automation.id, runs))
                    })
                    .collect()
            },
        );
        let activity =
            cache_result(owner.activity(None, 200)).map(Arc::<[OwnerActivityRecord]>::from);
        let activity_sources = owner
            .activity_sources()
            .unwrap_or_default()
            .into_iter()
            .map(|(request_id, name)| {
                // The name an agent chose for itself. Registration already
                // holds it to a terminal-safe line, and this holds it again at
                // the surface that draws it, where the bound on its width is
                // also a bound on how much of the row it can take over.
                (
                    request_id,
                    SharedString::from(ekubo_wallet_core::sanitize::stripped_capped(&name, 64)),
                )
            })
            .collect();
        let accounts = cache_result(owner.accounts());
        let legal_status = cache_result(owner.legal_status());
        let networks = cache_result(owner.networks());
        let mut policies = BTreeMap::new();
        if let Ok(accounts) = &accounts {
            for account in accounts {
                policies.insert(account.id.clone(), cache_result(owner.policy(&account.id)));
            }
        }
        let mut message_documents = BTreeMap::new();
        let mut typed_data_documents = BTreeMap::new();
        if let Ok(activity) = &activity {
            for record in activity.iter() {
                match record {
                    OwnerActivityRecord::Message(record) => {
                        message_documents.insert(
                            record.request_id,
                            cache_result(owner.message_review_document(record.request_id)),
                        );
                    }
                    OwnerActivityRecord::TypedData(record) => {
                        typed_data_documents.insert(
                            record.request_id,
                            cache_result(owner.typed_data_review_document(record.request_id)),
                        );
                    }
                    OwnerActivityRecord::Transaction(_) => {}
                }
            }
        }
        Self {
            reviews,
            activity,
            activity_sources,
            accounts,
            policies,
            legal_status,
            networks,
            automations,
            automation_runs,
            message_documents,
            typed_data_documents,
        }
    }
}

fn cache_result<T>(result: Result<T>) -> std::result::Result<T, SharedString> {
    result.map_err(|error| format!("{error:#}").into())
}

enum ReleaseDisplayState {
    Idle,
    Checking,
    Ready {
        check: ReleaseCheck,
        update: Option<Box<crate::release_check::InstallableUpdate>>,
    },
    Downloading,
    Failed(SharedString),
}

struct PreparedUpdate {
    prepared: ekubo_wallet_core::update_trust::PreparedUpdate,
    authorization: ekubo_wallet_core::update_trust::UpdateAuthorization,
}

enum PortfolioState {
    Idle,
    Loading,
    Ready(OwnerPortfolioSnapshot),
    Failed(SharedString),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AgentReinstallState {
    Idle,
    Running,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReviewFlowState {
    Ready,
    Loading,
    Busy,
}

impl ReviewFlowState {
    fn begin_transaction(&mut self) -> bool {
        if *self != Self::Ready {
            return false;
        }
        *self = Self::Loading;
        true
    }

    fn activate_transaction_prompt(&mut self) -> bool {
        if *self != Self::Loading {
            return false;
        }
        *self = Self::Busy;
        true
    }

    const fn is_in_progress(self) -> bool {
        !matches!(self, Self::Ready)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenImportState {
    Idle,
    Fetching,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountEntryMode {
    Create,
    Import,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InboxTab {
    Waiting,
    Decided,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccountOperation {
    Creating,
    Importing,
}

fn render_embedded_png(bytes: &[u8]) -> Result<Arc<RenderImage>> {
    let buffer = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .context("embedded PNG could not be decoded")?
        .into_rgba8();
    Ok(Arc::new(RenderImage::new([image::Frame::new(buffer)])))
}

// The persistent list state keeps long legal documents virtualized between
// frames; only the digest is retained for the eventual acceptance write.
struct LegalReview {
    document: LegalDocument,
    digest: String,
    rows: Arc<[LegalDisplayRow]>,
    scroll_handle: UniformListScrollHandle,
    end_rendered: Arc<AtomicBool>,
    acceptance_required: bool,
    scroll_check_scheduled: bool,
    viewed_to_end: bool,
    error: Option<SharedString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegalRowKind {
    Heading,
    Body,
    Code,
    Blank,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LegalDisplayRow {
    text: SharedString,
    kind: LegalRowKind,
    link_url: Option<SharedString>,
}

struct AccountExport {
    token: uuid::Uuid,
    wallet_id: String,
    lease: Option<ExportLease>,
    copied: bool,
    authenticating: bool,
    error: Option<SharedString>,
}

#[derive(Clone, Debug)]
struct PolicyDraftReview {
    wallet_id: String,
    source_revision: Option<u64>,
    document: String,
    policy: WalletPolicy,
    diff: Vec<String>,
}

struct PolicyEditor {
    wallet_id: String,
    source_revision: Option<u64>,
    current_policy: Option<WalletPolicy>,
    history: Vec<StoredPolicy>,
    history_selection: Option<usize>,
    proposal: Option<PolicyProposal>,
    validation: Option<std::result::Result<PolicyDraftReview, SharedString>>,
}

#[allow(clippy::struct_excessive_bools)]
struct ActiveReview {
    state: ReviewState,
    simulation: Option<Arc<ekubo_wallet_core::simulation::SimulationResult>>,
    completion: Option<ActiveReviewCompletion>,
    awaiting_refresh: bool,
    detail_rows: Arc<[SecurityReviewDetailRow]>,
    wallet_connect_accounts: Option<Arc<[String]>>,
    scroll_handle: VariableListState,
    scroll_handler_generation: Cell<Option<u64>>,
    end_rendered: Arc<AtomicBool>,
    scroll_check_scheduled: bool,
    scroll_layout_ready: bool,
    scroll_last_max: Option<gpui::Pixels>,
    scroll_stable_samples: u8,
}

impl ActiveReview {
    fn new(
        document: ReviewDocument,
        simulation: Option<ekubo_wallet_core::simulation::SimulationResult>,
        completion: Option<ActiveReviewCompletion>,
    ) -> Self {
        let state = ReviewState::new(document);
        let mut review = Self {
            state,
            simulation: simulation.map(Arc::new),
            completion,
            awaiting_refresh: false,
            detail_rows: Arc::from([]),
            wallet_connect_accounts: None,
            scroll_handle: virtual_review_detail_list(0),
            scroll_handler_generation: Cell::new(None),
            end_rendered: Arc::new(AtomicBool::new(false)),
            scroll_check_scheduled: false,
            scroll_layout_ready: false,
            scroll_last_max: None,
            scroll_stable_samples: 0,
        };
        review.rebuild_detail_list();
        review
    }

    fn selection_is_complete(&self) -> bool {
        review_selection_is_complete(self.completion.as_ref())
    }

    fn rebuild_detail_list(&mut self) {
        self.wallet_connect_accounts = self.completion.as_ref().and_then(|completion| {
            let ActiveReviewCompletion::WalletConnect { choices, .. } = completion else {
                return None;
            };
            Some(Arc::from(
                choices
                    .iter()
                    .map(|choice| choice.account.id.clone())
                    .collect::<Vec<_>>(),
            ))
        });
        self.detail_rows = Arc::from(security_review_detail_rows(
            self.state.document(),
            self.wallet_connect_accounts.is_some(),
        ));
        self.scroll_handle = virtual_review_detail_list(self.detail_rows.len());
        self.scroll_handler_generation.set(None);
        self.end_rendered = Arc::new(AtomicBool::new(false));
        self.scroll_check_scheduled = false;
        self.scroll_layout_ready = false;
        self.scroll_last_max = None;
        self.scroll_stable_samples = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecurityReviewDetailRow {
    Prelude,
    Section(usize),
    WarningsHeading,
    Warning(usize),
    WalletConnectAccounts,
    RequestDetails,
    ExactDataHeading,
    ExactPayloadHeading(usize),
    ExactPayloadChunk {
        payload_index: usize,
        start: usize,
        end: usize,
    },
}

const EXACT_PAYLOAD_CHUNK_BYTES: usize = 4 * 1024;

fn exact_payload_chunk_ranges(payload: &str) -> Vec<(usize, usize)> {
    if payload.is_empty() {
        return vec![(0, 0)];
    }

    let mut ranges = Vec::with_capacity(payload.len().div_ceil(EXACT_PAYLOAD_CHUNK_BYTES));
    let mut start = 0;
    while start < payload.len() {
        let mut end = (start + EXACT_PAYLOAD_CHUNK_BYTES).min(payload.len());
        while !payload.is_char_boundary(end) {
            end -= 1;
        }
        if end < payload.len()
            && let Some(newline) = payload[start..end].rfind('\n')
            && newline > 0
        {
            end = start + newline + 1;
        }
        if end == start {
            end = payload[start..]
                .char_indices()
                .nth(1)
                .map_or(payload.len(), |(offset, _)| start + offset);
        }
        ranges.push((start, end));
        start = end;
    }
    ranges
}

fn security_review_detail_rows(
    document: &ReviewDocument,
    wallet_connect_accounts: bool,
) -> Vec<SecurityReviewDetailRow> {
    let mut effects = Vec::new();
    let mut remaining = Vec::new();
    for (index, section) in document.request.sections.iter().enumerate() {
        if section.kind == ApprovalSectionKind::Effects {
            effects.push(index);
        } else {
            remaining.push(index);
        }
    }
    remaining.sort_by_key(|index| review_section_priority(document.request.sections[*index].kind));

    let mut rows = Vec::with_capacity(
        1 + effects.len()
            + remaining.len()
            + document.request.warnings.len()
            + usize::from(!document.request.warnings.is_empty())
            + usize::from(wallet_connect_accounts)
            + usize::from(!document.request.facts.is_empty())
            + document
                .exact_payloads
                .iter()
                .map(|payload| 1 + exact_payload_chunk_ranges(payload).len())
                .sum::<usize>()
            + usize::from(!document.exact_payloads.is_empty()),
    );
    rows.push(SecurityReviewDetailRow::Prelude);
    rows.extend(effects.into_iter().map(SecurityReviewDetailRow::Section));
    if !document.request.warnings.is_empty() {
        rows.push(SecurityReviewDetailRow::WarningsHeading);
        rows.extend((0..document.request.warnings.len()).map(SecurityReviewDetailRow::Warning));
    }
    if wallet_connect_accounts {
        rows.push(SecurityReviewDetailRow::WalletConnectAccounts);
    }
    rows.extend(remaining.into_iter().map(SecurityReviewDetailRow::Section));
    if !document.request.facts.is_empty() {
        rows.push(SecurityReviewDetailRow::RequestDetails);
    }
    if !document.exact_payloads.is_empty() {
        rows.push(SecurityReviewDetailRow::ExactDataHeading);
        for (payload_index, payload) in document.exact_payloads.iter().enumerate() {
            rows.push(SecurityReviewDetailRow::ExactPayloadHeading(payload_index));
            rows.extend(
                exact_payload_chunk_ranges(payload)
                    .into_iter()
                    .map(|(start, end)| SecurityReviewDetailRow::ExactPayloadChunk {
                        payload_index,
                        start,
                        end,
                    }),
            );
        }
    }
    rows
}

enum ActiveReviewCompletion {
    Transaction(oneshot::Sender<GuiReviewCommand>),
    Message {
        request_id: uuid::Uuid,
        digest: String,
    },
    TypedData {
        request_id: uuid::Uuid,
        digest: String,
    },
    WalletConnect {
        choices: Vec<crate::walletconnect::ProposalChoice>,
        /// Which account the owner chose to expose, once they have chosen.
        ///
        /// It used to start at the first account, which meant the default
        /// answer to "which account may this dapp see" was whichever one
        /// happened to sort first — and a connection can go on to propose
        /// transactions that a policy signs without a second review. Nothing
        /// is exposed until this is `Some`.
        selected_account: Option<usize>,
        response: oneshot::Sender<ProposalCommand>,
    },
    AccountRemoval {
        wallet: WalletMetadata,
    },
}

/// What a review calls its two decisions, and which one costs something.
struct ReviewDecisionLabels {
    reject: &'static str,
    approve: &'static str,
    approve_is_destructive: bool,
}

/// Whether the pairing the connect button is waiting on has yet to arrive
/// anywhere.
///
/// Gone from the manager means it ended — by failing before it settled, or by
/// being cancelled. Settled means it became a connection. Either way the
/// button has its answer and stops spinning.
fn walletconnect_pairing_is_in_flight(sessions: &[SessionSummary], connecting: uuid::Uuid) -> bool {
    sessions
        .iter()
        .any(|session| session.id == connecting && !session.settled)
}

/// Whether the review is missing an answer the owner still has to give.
///
/// Only a dapp connection asks for one: which account it may see. Having read
/// a document to the end is not the same as having chosen, so this is checked
/// alongside `approve_enabled` rather than folded into it.
const fn review_selection_is_complete(completion: Option<&ActiveReviewCompletion>) -> bool {
    match completion {
        Some(ActiveReviewCompletion::WalletConnect {
            selected_account, ..
        }) => selected_account.is_some(),
        _ => true,
    }
}

const fn review_decision_labels(
    completion: Option<&ActiveReviewCompletion>,
) -> ReviewDecisionLabels {
    match completion {
        Some(ActiveReviewCompletion::WalletConnect { .. }) => ReviewDecisionLabels {
            reject: "Decline connection",
            approve: "Authenticate & connect",
            approve_is_destructive: false,
        },
        Some(ActiveReviewCompletion::AccountRemoval { .. }) => ReviewDecisionLabels {
            reject: "Keep this account",
            approve: "Authenticate & remove",
            approve_is_destructive: true,
        },
        _ => ReviewDecisionLabels {
            reject: "Reject request",
            approve: "Authenticate & approve",
            approve_is_destructive: false,
        },
    }
}

enum QueuedReview {
    Transaction(Box<GuiReviewPrompt>),
    WalletConnect(Box<ProposalPrompt>),
}

struct SerialQueue<T> {
    pending: VecDeque<T>,
}

impl<T> Default for SerialQueue<T> {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
        }
    }
}

impl<T> SerialQueue<T> {
    fn receive(&mut self, active: bool, item: T) -> Option<T> {
        if active {
            self.pending.push_back(item);
            None
        } else {
            Some(item)
        }
    }

    #[cfg(test)]
    fn next(&mut self, active: bool) -> Option<T> {
        (!active).then(|| self.pending.pop_front()).flatten()
    }

    fn push(&mut self, item: T) {
        self.pending.push_back(item);
    }

    fn next_where(&mut self, predicate: impl FnMut(&T) -> bool) -> Option<T> {
        let index = self.pending.iter().position(predicate)?;
        self.pending.remove(index)
    }

    fn len(&self) -> usize {
        self.pending.len()
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Default)]
struct NotificationNavigation {
    pending: Option<NotificationRoute>,
}

impl NotificationNavigation {
    fn receive(&mut self, route: NotificationRoute) {
        // Navigation is intent, not a work queue: the newest explicit click
        // supersedes an older one that has not been shown yet.
        self.pending = Some(route);
    }

    fn take(&mut self, blocked: bool) -> Option<NotificationRoute> {
        if blocked {
            return None;
        }
        self.pending.take()
    }
}

struct RouteListDelegate {
    routes: Vec<Route>,
    selected: Option<IndexPath>,
}

struct TokenListDelegate {
    owner: OwnerApi,
    all_tokens: Vec<StoredToken>,
    visible_tokens: Vec<StoredToken>,
    query: String,
    loading: bool,
    error: Option<SharedString>,
    action_errors: BTreeMap<(u64, alloy::primitives::Address), SharedString>,
    selected: Option<IndexPath>,
    removing: BTreeSet<(u64, alloy::primitives::Address)>,
    network_names: BTreeMap<u64, SharedString>,
    visible_chain_ids: BTreeSet<u64>,
    configured_chain_ids: BTreeSet<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct TokenEditorErrors {
    chain_id: Option<String>,
    address: Option<String>,
    symbol: Option<String>,
    name: Option<String>,
    decimals: Option<String>,
    form: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NetworkEditorErrors {
    name: Option<String>,
    display_name: Option<String>,
    aliases: Option<String>,
    chain_id: Option<String>,
    rpc_urls: Option<String>,
    native_currency: Option<String>,
    block_explorer_url: Option<String>,
    documentation_url: Option<String>,
    form: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct NetworkEditorDraft {
    name: String,
    display_name: String,
    aliases: String,
    chain_id: String,
    rpc_urls: String,
    native_currency_name: String,
    native_currency_symbol: String,
    native_currency_decimals: String,
    block_explorer_url: String,
    documentation_url: String,
}

/// A note one row is showing about the last thing the owner asked it to do.
///
/// Two kinds, and they have different lifespans. A note that something went
/// wrong stays until the next attempt on that row, because it is the only
/// account of a failure the row's own status cannot show. A note that
/// something went as asked is a receipt for a press, and the row already
/// carries the result — so it says so briefly and then gets out of the way.
/// Automatic status checks never create one: their spinner is the complete
/// feedback, and the refreshed lifecycle label is their result.
#[derive(Clone)]
struct ActivityFeedback {
    message: SharedString,
    error: bool,
    /// Which note this is, in the order the view set them. Stamped by
    /// [`WalletWindow::set_activity_feedback`], the only thing that puts one
    /// of these on a row, so the value at construction is never read.
    seq: u64,
}

/// How long a note about something that worked stays on the screen.
///
/// Both places one appears: an inbox row's note about the last thing the owner
/// asked it to do, and the line under the account form saying an account was
/// created. Each is a receipt for a press whose result is already visible
/// beside it, so each says so briefly and then gets out of the way.
const SUCCESS_NOTE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(8);

impl ActivityFeedback {
    fn note(message: impl Into<SharedString>) -> Self {
        Self {
            message: message.into(),
            error: false,
            seq: 0,
        }
    }

    fn failure(message: impl Into<SharedString>) -> Self {
        Self {
            message: message.into(),
            error: true,
            seq: 0,
        }
    }
}

enum ActivityInspectionState {
    Loading,
    Ready(Rc<ReadyActivityInspection>),
    Failed(SharedString),
}

struct ReadyActivityInspection {
    inspection: OwnerTransactionInspection,
    detail_rows: RefCell<Arc<[TransactionActivityDetailRow]>>,
    detail_list: VariableListState,
}

impl ReadyActivityInspection {
    fn new(inspection: OwnerTransactionInspection) -> Self {
        let detail_rows = Arc::<[TransactionActivityDetailRow]>::from(
            transaction_activity_detail_rows(&inspection.document, false),
        );
        let detail_list = virtual_review_detail_list(detail_rows.len());
        Self {
            inspection,
            detail_rows: RefCell::new(detail_rows),
            detail_list,
        }
    }

    fn set_exact_payload_expanded(&self, expanded: bool) {
        let rows = Arc::<[TransactionActivityDetailRow]>::from(transaction_activity_detail_rows(
            &self.inspection.document,
            expanded,
        ));
        let offset = self.detail_list.scroll_px_offset_for_scrollbar();
        self.detail_list
            .reset_with_uniform_height(rows.len(), ACTIVITY_DETAIL_ITEM_HEIGHT_HINT);
        self.detail_list.set_offset_from_scrollbar(offset);
        self.detail_rows.replace(rows);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionActivityDetailRow {
    Prelude,
    Section(usize),
    WarningsHeading,
    Warning(usize),
    RecordKeeping,
    ExactPayloadDisclosure,
    ExactPayloadChunk { start: usize, end: usize },
}

const ACTIVITY_DETAIL_ITEM_HEIGHT_HINT: gpui::Pixels = px(180.0);
const ACTIVITY_DETAIL_LIST_OVERDRAW: gpui::Pixels = px(480.0);

fn virtual_review_detail_list(row_count: usize) -> VariableListState {
    VariableListState::new(row_count, ListAlignment::Top, ACTIVITY_DETAIL_LIST_OVERDRAW)
        // Review cards are not uniform, but this gives the unmeasured tail a
        // useful scrollbar estimate without eagerly laying out thousands of
        // calls. Each visible card replaces its hint with its exact height.
        .with_uniform_item_height(ACTIVITY_DETAIL_ITEM_HEIGHT_HINT)
}

fn transaction_activity_detail_rows(
    document: &ReviewDocument,
    exact_payload_expanded: bool,
) -> Vec<TransactionActivityDetailRow> {
    let mut section_indices = (0..document.request.sections.len()).collect::<Vec<_>>();
    section_indices
        .sort_by_key(|index| review_section_priority(document.request.sections[*index].kind));

    let mut rows = Vec::with_capacity(
        1 + section_indices.len()
            + document.request.warnings.len()
            + usize::from(!document.request.warnings.is_empty())
            + usize::from(!document.request.facts.is_empty())
            + usize::from(!document.exact_payloads.is_empty())
            + if exact_payload_expanded {
                document
                    .exact_payloads
                    .first()
                    .map_or(0, |payload| exact_payload_chunk_ranges(payload).len())
            } else {
                0
            },
    );
    rows.push(TransactionActivityDetailRow::Prelude);
    rows.extend(
        section_indices
            .into_iter()
            .map(TransactionActivityDetailRow::Section),
    );
    if !document.request.warnings.is_empty() {
        rows.push(TransactionActivityDetailRow::WarningsHeading);
        rows.extend(
            (0..document.request.warnings.len()).map(TransactionActivityDetailRow::Warning),
        );
    }
    if !document.request.facts.is_empty() {
        rows.push(TransactionActivityDetailRow::RecordKeeping);
    }
    if !document.exact_payloads.is_empty() {
        rows.push(TransactionActivityDetailRow::ExactPayloadDisclosure);
        if exact_payload_expanded {
            rows.extend(
                exact_payload_chunk_ranges(&document.exact_payloads[0])
                    .into_iter()
                    .map(
                        |(start, end)| TransactionActivityDetailRow::ExactPayloadChunk {
                            start,
                            end,
                        },
                    ),
            );
        }
    }
    rows
}

fn activity_record_is_awaiting_approval(record: &OwnerActivityRecord) -> bool {
    match record {
        OwnerActivityRecord::Transaction(item) => item.status == PendingStatus::AwaitingApproval,
        OwnerActivityRecord::Message(item) => item.status == MessageStatus::AwaitingApproval,
        OwnerActivityRecord::TypedData(item) => item.status == TypedDataStatus::AwaitingApproval,
    }
}

fn activity_record_chain_id(record: &OwnerActivityRecord) -> Option<u64> {
    match record {
        OwnerActivityRecord::Transaction(item) => item.chain_id.parse().ok(),
        OwnerActivityRecord::Message(item) => item.chain_id.as_deref()?.parse().ok(),
        OwnerActivityRecord::TypedData(item) => item.chain_id.parse().ok(),
    }
}

fn visible_network_chain_ids(networks: &[NetworkConfig], testnet_mode: bool) -> BTreeSet<u64> {
    networks
        .iter()
        .filter(|network| testnet_mode || !network.testnet)
        .map(|network| network.chain_id)
        .collect()
}

fn chain_is_visible(
    chain_id: Option<u64>,
    visible_chain_ids: &BTreeSet<u64>,
    configured_chain_ids: &BTreeSet<u64>,
) -> bool {
    chain_id.is_none_or(|chain_id| {
        visible_chain_ids.contains(&chain_id) || !configured_chain_ids.contains(&chain_id)
    })
}

fn review_fact_chain_id(fact: &ApprovalFact) -> Option<u64> {
    if !matches!(fact.label.as_str(), "Chain" | "Chain ID") {
        return None;
    }
    fact.value
        .trim()
        .strip_prefix("eip155:")
        .unwrap_or(fact.value.trim())
        .parse()
        .ok()
}

fn review_document_chain_ids(document: &ReviewDocument) -> Vec<u64> {
    document
        .request
        .facts
        .iter()
        .chain(
            document
                .request
                .sections
                .iter()
                .flat_map(|section| section.facts.iter()),
        )
        .filter_map(review_fact_chain_id)
        .collect()
}

fn review_document_is_visible(
    document: &ReviewDocument,
    networks: &[NetworkConfig],
    testnet_mode: bool,
) -> bool {
    if testnet_mode {
        return true;
    }
    let visible_chain_ids = visible_network_chain_ids(networks, false);
    let configured_chain_ids = networks
        .iter()
        .map(|network| network.chain_id)
        .collect::<BTreeSet<_>>();
    review_document_chain_ids(document)
        .into_iter()
        .all(|chain_id| chain_is_visible(Some(chain_id), &visible_chain_ids, &configured_chain_ids))
}

/// Decide whether this lifecycle change deserves a banner, and if so read the
/// two facts the banner will name.
///
/// One lookup answers both questions: the record has to be fetched anyway to
/// check that its chain is one the owner has chosen to see, and it is also
/// where the account and network names live.
fn transaction_notification_context(
    owner: &OwnerApi,
    event: &crate::events::DomainEvent,
) -> Option<TransactionContext> {
    let crate::events::DomainEventKind::Transaction { request_id, .. } = &event.kind else {
        return None;
    };
    let record = owner.transaction(*request_id).ok()?;
    let networks = owner.networks().ok()?;
    let testnet_mode = owner.testnet_mode().ok()?;
    let visible_chain_ids = visible_network_chain_ids(&networks, testnet_mode);
    let configured_chain_ids = networks
        .iter()
        .map(|network| network.chain_id)
        .collect::<BTreeSet<_>>();
    let chain_id = record.chain_id.parse().ok();
    if !chain_is_visible(chain_id, &visible_chain_ids, &configured_chain_ids) {
        return None;
    }
    Some(TransactionContext {
        account: record.wallet_id,
        // Not `record.network_name`. That is the internal handle an agent
        // types — "robinhood" — and aliases exist so a person can abbreviate
        // in conversation, not so the wallet can abbreviate back at them. A
        // banner says the name the network is actually called.
        network: chain_label(chain_id, &token_network_names(&networks)),
    })
}

/// A coloured dot beside a plain word. It repeats the state in two channels so
/// the row is scannable at a glance and still readable without colour.
fn status_pill(label: &'static str, tone: StatusTone, cx: &App) -> gpui::Div {
    let color = tone.color(cx);
    h_flex()
        .flex_none()
        .items_center()
        .gap_1p5()
        .px_2()
        .py_0p5()
        .rounded_full()
        .border_1()
        .border_color(color.opacity(0.35))
        .bg(color.opacity(0.12))
        .child(div().w(px(7.0)).h(px(7.0)).rounded_full().bg(color))
        .child(div().text_xs().font_medium().text_color(color).child(label))
}

/// The chain's configured display name, falling back to the bare number only
/// when the wallet has no network configured for it.
fn chain_label(chain_id: Option<u64>, networks: &BTreeMap<u64, SharedString>) -> String {
    match chain_id {
        Some(chain_id) => networks
            .get(&chain_id)
            .map_or_else(|| format!("chain {chain_id}"), ToString::to_string),
        None => "no network".to_owned(),
    }
}

/// Text somebody else authored, cut to what one line of a row can carry.
///
/// Both the stores it comes from already refuse control and bidirectional
/// characters on the way in. This is the same claim made again at the surface
/// that draws it, where the cap on width is also a cap on how much of the row
/// a name can take for itself.
fn sanitized_source(value: &str) -> String {
    ekubo_wallet_core::sanitize::stripped_capped(value, 64)
}

/// Who asked for a transaction, in the words its row uses.
///
/// Three answers, most specific first: the agent this wallet authenticated,
/// the provenance the plan itself carried, and — for a plan this wallet built
/// out of something the owner typed — the wallet. The list used to give none
/// of them, so a transfer somebody made by hand and one an agent asked for
/// read identically.
fn activity_source_label(plan_source: Option<&str>, agent: Option<&SharedString>) -> String {
    if let Some(agent) = agent {
        return format!("via {agent}");
    }
    let Some(source) = plan_source else {
        return "built by this wallet".to_owned();
    };
    if let Some(dapp) = source.strip_prefix(ekubo_wallet_core::pending::DAPP_PLAN_SOURCE_PREFIX) {
        return format!("via {} over WalletConnect", sanitized_source(dapp));
    }
    match source {
        "inline data URI" => "from a plan given inline".to_owned(),
        "a file on this machine" => "from a plan file on this machine".to_owned(),
        host => format!("from a plan served by {}", sanitized_source(host)),
    }
}

/// The same question for the two signature queues, which record the asker's
/// own claim about itself. That claim is what the review screen showed, so the
/// row keeps it; the authenticated agent answers only for the rows where
/// nobody claimed anything, which is every request an MCP client made.
fn signature_source_label(requester: Option<&str>, agent: Option<&SharedString>) -> String {
    match requester
        .map(str::trim)
        .filter(|requester| !requester.is_empty())
    {
        Some(requester) => format!("via {}", sanitized_source(requester)),
        None => agent.map_or_else(
            || "from an unnamed requester".to_owned(),
            |agent| format!("via {agent}"),
        ),
    }
}

/// Title, subtitle, state word, and state colour for one inbox row.
///
/// Every field is a sentence a person could have written. The request UUID is
/// deliberately absent: it identifies the row to the wallet, never to the
/// reader, and it used to be the most prominent thing on the card.
struct ActivityRowSummary {
    title: String,
    subtitle: String,
    status: &'static str,
    tone: StatusTone,
}

fn activity_row_summary(
    record: &OwnerActivityRecord,
    networks: &BTreeMap<u64, SharedString>,
    agent: Option<&SharedString>,
    now: chrono::DateTime<chrono::Utc>,
) -> ActivityRowSummary {
    match record {
        OwnerActivityRecord::Transaction(item) => ActivityRowSummary {
            title: format!(
                "Transaction on {}",
                chain_label(item.chain_id.parse().ok(), networks)
            ),
            subtitle: format!(
                "{} · {} · {}",
                item.wallet_id,
                activity_source_label(item.plan_source.as_deref(), agent),
                relative_time_label(item.created_at, now)
            ),
            status: transaction_record_label(item),
            tone: transaction_record_tone(item),
        },
        OwnerActivityRecord::Message(item) => ActivityRowSummary {
            title: "Message signature".to_owned(),
            subtitle: format!(
                "{} · {} · {}",
                item.wallet_id,
                signature_source_label(item.requester.as_deref(), agent),
                relative_time_label(item.created_at, now)
            ),
            status: item.status.label(),
            tone: message_status_tone(item.status),
        },
        OwnerActivityRecord::TypedData(item) => ActivityRowSummary {
            title: format!(
                "Typed-data signature on {}",
                chain_label(item.chain_id.parse().ok(), networks)
            ),
            subtitle: format!(
                "{} · {} · {}",
                item.wallet_id,
                signature_source_label(item.requester.as_deref(), agent),
                relative_time_label(item.created_at, now)
            ),
            status: item.status.label(),
            tone: typed_data_status_tone(item.status),
        },
    }
}

fn render_activity_row(
    record: &OwnerActivityRecord,
    selected: bool,
    busy: bool,
    refreshing: bool,
    feedback: Option<ActivityFeedback>,
    networks: &BTreeMap<u64, SharedString>,
    agent: Option<&SharedString>,
    now: chrono::DateTime<chrono::Utc>,
    editor: WeakEntity<WalletWindow>,
    cx: &mut App,
) -> gpui::Div {
    let request_id = record.request_id();
    let summary = activity_row_summary(record, networks, agent, now);
    // Always "Details": the detail opens over the list, so the row's own
    // button is never the thing that closes it.
    let detail_label = "Details";
    let actions = match record {
        OwnerActivityRecord::Transaction(item) => {
            let status = item.status;
            let available = transaction_actions(status);
            let inspect_editor = editor.clone();
            let send_editor = editor.clone();
            let cancel_editor = editor.clone();
            let discard_editor = editor;
            h_flex()
                .flex_wrap()
                .justify_end()
                .gap_2()
                .child(
                    app_button(SharedString::from(format!(
                        "inspect-transaction-{request_id}"
                    )))
                    .label(detail_label)
                    .on_click(move |_, _, cx| {
                        let _ = inspect_editor.update(cx, |view, cx| {
                            view.inspect_transaction(request_id, cx);
                        });
                    }),
                )
                .when(available.send, |buttons| {
                    buttons.child(
                        app_button(SharedString::from(format!(
                            "rebroadcast-transaction-{request_id}"
                        )))
                        .label(if status == PendingStatus::Signed {
                            "Send now"
                        } else {
                            "Send again"
                        })
                        .disabled(busy)
                        .on_click(move |_, _, cx| {
                            let _ = send_editor.update(cx, |view, cx| {
                                view.rebroadcast_transaction(request_id, cx);
                            });
                        }),
                    )
                })
                .when(available.cancel, |buttons| {
                    buttons.child(
                        app_button(SharedString::from(format!(
                            "cancel-transaction-{request_id}"
                        )))
                        .label(if status == PendingStatus::Cancelling {
                            "Try cancelling again"
                        } else {
                            "Cancel"
                        })
                        .danger()
                        .disabled(busy)
                        .on_click(move |_, window, cx| {
                            let _ = cancel_editor.update(cx, |view, cx| {
                                view.confirm_transaction_cancellation(request_id, window, cx);
                            });
                        }),
                    )
                })
                .when(available.discard, |buttons| {
                    buttons.child(
                        app_button(SharedString::from(format!("discard-{request_id}")))
                            .label("Discard")
                            .danger()
                            .disabled(busy)
                            .on_click(move |_, _, cx| {
                                let _ = discard_editor.update(cx, |view, cx| {
                                    view.discard_unsent_transaction(request_id, cx);
                                });
                            }),
                    )
                })
        }
        OwnerActivityRecord::Message(item) => {
            let awaiting = item.status == MessageStatus::AwaitingApproval;
            let inspect_editor = editor.clone();
            let review_editor = editor;
            h_flex()
                .flex_wrap()
                .justify_end()
                .gap_2()
                .child(
                    app_button(SharedString::from(format!("inspect-message-{request_id}")))
                        .label(detail_label)
                        .on_click(move |_, _, cx| {
                            let _ = inspect_editor.update(cx, |view, cx| {
                                view.toggle_activity_detail(request_id, cx);
                            });
                        }),
                )
                .when(awaiting, |buttons| {
                    buttons.child(
                        app_button(SharedString::from(format!(
                            "review-message-activity-{request_id}"
                        )))
                        .label("Review")
                        .primary()
                        .on_click(move |_, _, cx| {
                            let _ = review_editor.update(cx, |view, cx| {
                                view.begin_message_review(request_id, cx);
                            });
                        }),
                    )
                })
        }
        OwnerActivityRecord::TypedData(item) => {
            let awaiting = item.status == TypedDataStatus::AwaitingApproval;
            let inspect_editor = editor.clone();
            let review_editor = editor;
            h_flex()
                .flex_wrap()
                .justify_end()
                .gap_2()
                .child(
                    app_button(SharedString::from(format!(
                        "inspect-typed-data-{request_id}"
                    )))
                    .label(detail_label)
                    .on_click(move |_, _, cx| {
                        let _ = inspect_editor.update(cx, |view, cx| {
                            view.toggle_activity_detail(request_id, cx);
                        });
                    }),
                )
                .when(awaiting, |buttons| {
                    buttons.child(
                        app_button(SharedString::from(format!(
                            "review-typed-data-activity-{request_id}"
                        )))
                        .label("Review")
                        .primary()
                        .on_click(move |_, _, cx| {
                            let _ = review_editor.update(cx, |view, cx| {
                                view.begin_typed_data_review(request_id, cx);
                            });
                        }),
                    )
                })
        }
    };

    let mut card = div()
        .w_full()
        .min_w_0()
        .p_3()
        .rounded(cx.theme().radius_lg)
        .border_1()
        .border_color(if selected {
            cx.theme().primary
        } else {
            cx.theme().border
        })
        .bg(cx.theme().secondary)
        .flex()
        .flex_col()
        .gap_2()
        .child(
            h_flex()
                .w_full()
                .flex_wrap()
                .items_start()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            h_flex()
                                .flex_wrap()
                                .items_center()
                                .gap_2()
                                .child(status_pill(summary.status, summary.tone, cx))
                                .when(refreshing, |status| status.child(Spinner::new().small()))
                                .child(
                                    selectable_text(
                                        format!("activity-row-title-{request_id}"),
                                        &summary.title,
                                    )
                                    .font_medium(),
                                ),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(selectable_text(
                                    format!("activity-row-meta-{request_id}"),
                                    &summary.subtitle,
                                )),
                        ),
                )
                .child(actions),
        );
    if let Some(feedback) = feedback {
        card = card.child(
            div()
                .text_sm()
                .whitespace_normal()
                .text_color(if feedback.error {
                    cx.theme().danger
                } else {
                    cx.theme().muted_foreground
                })
                .child(selectable_text(
                    format!("activity-feedback-{request_id}"),
                    &feedback.message,
                )),
        );
    }
    div().w_full().min_w_0().pb_2().child(card)
}

#[derive(Clone)]
struct DetectedAgent {
    kind: AgentKind,
    display_name: &'static str,
    config_path: String,
    installed: std::result::Result<bool, SharedString>,
}

enum AgentDetectionState {
    Loading,
    Ready(Vec<DetectedAgent>),
    Failed(SharedString),
}

struct TokenProposalListDelegate {
    source: Option<String>,
    proposals: Vec<TokenProposal>,
    selected: Option<IndexPath>,
    viewed_to_end: bool,
    network_names: BTreeMap<u64, SharedString>,
}

impl TokenProposalListDelegate {
    fn new() -> Self {
        Self {
            source: None,
            proposals: Vec::new(),
            selected: None,
            viewed_to_end: false,
            network_names: BTreeMap::new(),
        }
    }

    fn replace(&mut self, source: String, proposals: Vec<TokenProposal>) {
        self.source = Some(source);
        self.proposals = proposals;
        self.selected = None;
        self.viewed_to_end = false;
    }

    fn clear(&mut self) {
        self.source = None;
        self.proposals.clear();
        self.selected = None;
        self.viewed_to_end = false;
    }

    fn replace_networks(&mut self, networks: &[NetworkConfig]) {
        self.network_names = token_network_names(networks);
    }
}

impl TokenListDelegate {
    fn new(owner: OwnerApi) -> Self {
        Self {
            owner,
            all_tokens: Vec::new(),
            visible_tokens: Vec::new(),
            query: String::new(),
            loading: true,
            error: None,
            action_errors: BTreeMap::new(),
            selected: None,
            removing: BTreeSet::new(),
            network_names: BTreeMap::new(),
            visible_chain_ids: BTreeSet::new(),
            configured_chain_ids: BTreeSet::new(),
        }
    }

    fn replace_tokens(&mut self, result: Result<Vec<StoredToken>>) {
        self.loading = false;
        match result {
            Ok(tokens) => {
                self.all_tokens = tokens;
                self.error = None;
                self.apply_filters();
            }
            Err(error) => {
                self.error = Some(format!("Tokens unavailable: {error:#}").into());
                self.visible_tokens.clear();
            }
        }
    }

    fn apply_filters(&mut self) {
        self.visible_tokens = self
            .all_tokens
            .iter()
            .filter(|token| {
                let chain_id = token.chain_id.parse::<u64>().ok();
                chain_is_visible(
                    chain_id,
                    &self.visible_chain_ids,
                    &self.configured_chain_ids,
                ) && token_matches_search(token, &self.query)
            })
            .cloned()
            .collect();
        let query = self.query.trim().to_lowercase();
        if !query.is_empty() {
            self.visible_tokens.sort_by_key(|token| {
                (
                    token_search_rank(token, &query),
                    token.chain_id.parse::<u64>().unwrap_or(u64::MAX),
                    token.address.clone(),
                )
            });
        }
        self.selected = None;
    }

    fn replace_networks(&mut self, networks: &[NetworkConfig], testnet_mode: bool) {
        let visible = networks
            .iter()
            .filter(|network| testnet_mode || !network.testnet)
            .cloned()
            .collect::<Vec<_>>();
        self.network_names = token_network_names(&visible);
        self.visible_chain_ids = visible_network_chain_ids(networks, testnet_mode);
        self.configured_chain_ids = networks.iter().map(|network| network.chain_id).collect();
        self.apply_filters();
    }
}

fn token_network_names(networks: &[NetworkConfig]) -> BTreeMap<u64, SharedString> {
    networks
        .iter()
        .map(|network| {
            (
                network.chain_id,
                SharedString::from(network.display_label().to_owned()),
            )
        })
        .collect()
}

fn token_matches_search(token: &StoredToken, query: &str) -> bool {
    let query = query.to_lowercase();
    query.is_empty()
        || token.chain_id.contains(&query)
        || token.address.to_lowercase().contains(&query)
        || token
            .symbol
            .as_deref()
            .is_some_and(|value| value.to_lowercase().contains(&query))
        || token
            .name
            .as_deref()
            .is_some_and(|value| value.to_lowercase().contains(&query))
}

fn token_search_rank(token: &StoredToken, query: &str) -> (usize, usize, usize) {
    let symbol = token.symbol.as_deref().unwrap_or_default().to_lowercase();
    let name = token.name.as_deref().unwrap_or_default().to_lowercase();
    let address = token.address.to_lowercase();
    let chain_id = token.chain_id.to_lowercase();
    let fields = [
        symbol.as_str(),
        name.as_str(),
        address.as_str(),
        chain_id.as_str(),
    ];

    fields
        .iter()
        .enumerate()
        .filter_map(|(field_index, value)| {
            let position = value.find(query)?;
            let match_kind = if value.len() == query.len() {
                0
            } else if position == 0 {
                1
            } else {
                2
            };
            Some((match_kind, position, value.len() - query.len(), field_index))
        })
        .min()
        .map_or(
            (usize::MAX, usize::MAX, usize::MAX),
            |(match_kind, position, extra, field_index)| {
                (match_kind * fields.len() + field_index, position, extra)
            },
        )
}

fn parse_token_editor_fields(
    chain_id: &str,
    address: &str,
    symbol: &str,
    name: &str,
    decimals: &str,
) -> (Option<ListedToken>, TokenEditorErrors) {
    let mut errors = TokenEditorErrors::default();
    let chain_id = match chain_id.trim().parse::<u64>() {
        Ok(value) if value > 0 => Some(value),
        _ => {
            errors.chain_id = Some("Enter a positive decimal chain ID.".to_owned());
            None
        }
    };
    let address = if let Ok(value) = address.trim().parse::<alloy::primitives::Address>() {
        Some(value)
    } else {
        errors.address = Some("Enter a 0x-prefixed 20-byte address.".to_owned());
        None
    };
    let symbol = validate_token_text(symbol, "symbol", false, &mut errors.symbol);
    let name = validate_token_text(name, "name", true, &mut errors.name);
    let decimals = if let Ok(value) = decimals.trim().parse::<u8>() {
        Some(value)
    } else {
        errors.decimals = Some("Enter a whole number from 0 through 255.".to_owned());
        None
    };

    let token = chain_id.zip(address).zip(symbol).zip(decimals).map(
        |(((chain_id, address), symbol), decimals)| ListedToken {
            chain_id,
            address,
            symbol,
            name,
            decimals,
        },
    );
    if errors.chain_id.is_some()
        || errors.address.is_some()
        || errors.symbol.is_some()
        || errors.name.is_some()
        || errors.decimals.is_some()
    {
        (None, errors)
    } else {
        (token, errors)
    }
}

fn validate_token_text(
    value: &str,
    label: &str,
    optional: bool,
    error: &mut Option<String>,
) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        if optional {
            return None;
        }
        *error = Some(format!("Enter a token {label}."));
        return None;
    }
    let sanitized = ekubo_wallet_core::sanitize::stripped_capped(value, 64);
    if sanitized != value || value.chars().count() > 64 {
        *error = Some(format!(
            "Token {label} must be at most 64 characters and contain no control characters."
        ));
        return None;
    }
    Some(value.to_owned())
}

// One exact-height row gives `uniform_list` the complete scroll extent on its
// first layout. At the minimum window width 64 Suisse characters fit beside
// the navigation rail; longer words (including URLs) are hard-wrapped so no
// legal text can escape its viewport.
const LEGAL_WRAP_COLUMNS: usize = 64;
const LEGAL_ROW_HEIGHT: gpui::Pixels = px(25.0);

fn push_wrapped_legal_rows(
    rows: &mut Vec<LegalDisplayRow>,
    text: &str,
    kind: LegalRowKind,
    first_prefix: &str,
    continuation_prefix: &str,
) {
    let mut line = first_prefix.to_owned();
    let mut line_len = line.chars().count();
    let mut prefix_len = line_len;
    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        let url_candidate = word.trim_end_matches(['.', ',', ';', ':', ')', ']']);
        let link_url = url::Url::parse(url_candidate)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
            .map(|url| SharedString::from(url.to_string()));
        if word_len > LEGAL_WRAP_COLUMNS.saturating_sub(prefix_len)
            && let Some(link_url) = link_url
        {
            if line_len > prefix_len {
                rows.push(LegalDisplayRow {
                    text: std::mem::take(&mut line).into(),
                    kind,
                    link_url: None,
                });
            }
            let available = LEGAL_WRAP_COLUMNS.saturating_sub(continuation_prefix.chars().count());
            let characters = word.chars().collect::<Vec<_>>();
            for chunk in characters.chunks(available.max(1)) {
                let mut text = continuation_prefix.to_owned();
                text.extend(chunk);
                rows.push(LegalDisplayRow {
                    text: text.into(),
                    kind,
                    link_url: Some(link_url.clone()),
                });
            }
            continuation_prefix.clone_into(&mut line);
            line_len = line.chars().count();
            prefix_len = line_len;
            continue;
        }
        let separator = usize::from(line_len > prefix_len);
        if line_len + separator + word_len <= LEGAL_WRAP_COLUMNS {
            if separator == 1 {
                line.push(' ');
                line_len += 1;
            }
            line.push_str(word);
            line_len += word_len;
            continue;
        }
        if line_len > prefix_len {
            rows.push(LegalDisplayRow {
                text: std::mem::take(&mut line).into(),
                kind,
                link_url: None,
            });
            continuation_prefix.clone_into(&mut line);
            line_len = line.chars().count();
            prefix_len = line_len;
        }
        for character in word.chars() {
            if line_len == LEGAL_WRAP_COLUMNS {
                rows.push(LegalDisplayRow {
                    text: std::mem::take(&mut line).into(),
                    kind,
                    link_url: None,
                });
                continuation_prefix.clone_into(&mut line);
                line_len = line.chars().count();
                prefix_len = line_len;
            }
            line.push(character);
            line_len += 1;
        }
    }
    if line_len > prefix_len || rows.is_empty() {
        rows.push(LegalDisplayRow {
            text: line.into(),
            kind,
            link_url: None,
        });
    }
}

fn legal_markdown_rows(text: &str) -> Arc<[LegalDisplayRow]> {
    let mut rows = Vec::new();
    let mut paragraph = String::new();
    let mut in_code = false;
    let flush_paragraph = |rows: &mut Vec<LegalDisplayRow>, paragraph: &mut String| {
        if !paragraph.is_empty() {
            push_wrapped_legal_rows(rows, paragraph, LegalRowKind::Body, "", "");
            paragraph.clear();
        }
    };
    for source_line in text.lines() {
        let line = source_line.trim();
        if line.starts_with("```") || line.starts_with("~~~") {
            flush_paragraph(&mut rows, &mut paragraph);
            in_code = !in_code;
            continue;
        }
        if in_code {
            push_wrapped_legal_rows(&mut rows, source_line, LegalRowKind::Code, "", "");
        } else if line.is_empty() {
            flush_paragraph(&mut rows, &mut paragraph);
            if rows
                .last()
                .is_some_and(|row| row.kind != LegalRowKind::Blank)
            {
                rows.push(LegalDisplayRow {
                    text: "".into(),
                    kind: LegalRowKind::Blank,
                    link_url: None,
                });
            }
        } else if let Some(heading) = line.strip_prefix('#') {
            flush_paragraph(&mut rows, &mut paragraph);
            let heading = heading.trim_start_matches('#').trim();
            push_wrapped_legal_rows(&mut rows, heading, LegalRowKind::Heading, "", "");
        } else if let Some(item) = line.strip_prefix("- ").or_else(|| line.strip_prefix("* ")) {
            flush_paragraph(&mut rows, &mut paragraph);
            push_wrapped_legal_rows(&mut rows, item, LegalRowKind::Body, "• ", "  ");
        } else {
            if !paragraph.is_empty() {
                paragraph.push(' ');
            }
            paragraph.push_str(line);
        }
    }
    flush_paragraph(&mut rows, &mut paragraph);
    while rows
        .last()
        .is_some_and(|row| row.kind == LegalRowKind::Blank)
    {
        rows.pop();
    }
    rows.into()
}

fn legal_list_reached_end(state: &UniformListScrollHandle, end_rendered: &AtomicBool) -> bool {
    end_rendered.load(Ordering::Acquire) || state.is_scrolled_to_end() == Some(true)
}

/// The name the network card shows for a network.
fn network_display_label(network: &NetworkConfig) -> &str {
    network.display_name.as_deref().unwrap_or(&network.name)
}

/// Enabled networks first, then each group alphabetically by the label the card
/// shows, ignoring case. Chain ID is the tiebreak so two networks that share a
/// label keep a stable order. Numeric chain-id order was an accident of how the
/// defaults were written down; nobody scanning this list knows a chain by its
/// number, and the networks that are actually signed for belong at the top.
fn networks_for_display(networks: &[NetworkConfig], testnet_mode: bool) -> Vec<&NetworkConfig> {
    let mut networks = networks
        .iter()
        .filter(|network| testnet_mode || !network.testnet)
        .collect::<Vec<_>>();
    networks.sort_by_cached_key(|network| {
        (
            network.disabled,
            network_display_label(network).to_lowercase(),
            network.chain_id,
        )
    });
    networks
}

fn block_explorer_transaction_url(
    networks: &[NetworkConfig],
    chain_id: u64,
    transaction_hash: &str,
) -> Option<String> {
    let base = networks
        .iter()
        .find(|network| network.chain_id == chain_id)?
        .block_explorer_url
        .as_ref()?;
    Some(block_explorer_resource_url(base, "tx", transaction_hash))
}

fn block_explorer_token_url(network: &NetworkConfig, token_address: &str) -> Option<String> {
    network
        .block_explorer_url
        .as_ref()
        .map(|base| block_explorer_resource_url(base, "token", token_address))
}

fn block_explorer_resource_url(base: &url::Url, resource: &str, identifier: &str) -> String {
    let mut url = base.clone();
    let root = url.path().trim_end_matches('/');
    url.set_path(&format!("{root}/{resource}/{identifier}"));
    url.into()
}

fn parse_network_editor_draft(
    draft: &NetworkEditorDraft,
    disabled: bool,
    testnet: bool,
    rpc_strategy: RpcStrategy,
    finality_confirmations: u16,
) -> (Option<NetworkConfig>, NetworkEditorErrors) {
    let mut errors = NetworkEditorErrors::default();
    let name = draft.name.trim();
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        errors.name = Some(
            "Use 1–64 letters, numbers, underscores, or hyphens for the internal name.".into(),
        );
    }
    let display_name = draft.display_name.trim();
    if !display_name.is_empty()
        && (display_name.len() > 128
            || display_name
                .chars()
                .any(ekubo_wallet_core::sanitize::is_disallowed))
    {
        errors.display_name =
            Some("Use at most 128 characters with no invisible or control characters.".into());
    }
    let aliases = draft
        .aliases
        .split(',')
        .map(str::trim)
        .filter(|alias| !alias.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if aliases.len() > ekubo_wallet_core::config::MAX_NETWORK_ALIASES
        || aliases.iter().any(|alias| {
            alias.len() > 64
                || !alias
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        || aliases.iter().collect::<BTreeSet<_>>().len() != aliases.len()
        || aliases.iter().any(|alias| alias == name)
    {
        errors.aliases = Some(format!(
            "Enter at most {} unique aliases using letters, numbers, underscores, or hyphens.",
            ekubo_wallet_core::config::MAX_NETWORK_ALIASES
        ));
    }
    let chain_id = match draft.chain_id.trim().parse::<u64>() {
        Ok(chain_id) if chain_id > 0 => Some(chain_id),
        _ => {
            errors.chain_id = Some("Enter a positive decimal chain ID.".into());
            None
        }
    };
    let mut rpc_urls = Vec::new();
    for value in draft
        .rpc_urls
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let value = value.strip_suffix(',').unwrap_or(value).trim_end();
        match value.parse::<url::Url>() {
            Ok(url)
                if matches!(url.scheme(), "http" | "https")
                    && url.username().is_empty()
                    && url.password().is_none() =>
            {
                rpc_urls.push(url);
            }
            _ => {
                errors.rpc_urls = Some(
                    "Enter one valid http:// or https:// RPC URL per line, with a comma after every line except the last and no embedded credentials."
                        .into(),
                );
                break;
            }
        }
    }
    if rpc_urls.is_empty()
        || rpc_urls.len() > ekubo_wallet_core::config::MAX_NETWORK_RPC_URLS
        || rpc_urls.iter().collect::<BTreeSet<_>>().len() != rpc_urls.len()
    {
        errors.rpc_urls = Some(format!(
            "Enter 1–{} unique RPC URLs, one per line and comma-separated.",
            ekubo_wallet_core::config::MAX_NETWORK_RPC_URLS
        ));
    }

    let native_values = [
        draft.native_currency_name.trim(),
        draft.native_currency_symbol.trim(),
        draft.native_currency_decimals.trim(),
    ];
    let native_currency = if native_values.iter().any(|value| value.is_empty()) {
        errors.native_currency =
            Some("Enter the native currency name, symbol, and decimals.".into());
        None
    } else {
        match native_values[2].parse::<u8>() {
            Ok(decimals)
                if native_values[0].len() <= 64
                    && native_values[1].len() <= 32
                    && !native_values[0]
                        .chars()
                        .any(ekubo_wallet_core::sanitize::is_disallowed)
                    && !native_values[1]
                        .chars()
                        .any(ekubo_wallet_core::sanitize::is_disallowed) =>
            {
                Some(NativeCurrency {
                    name: native_values[0].to_owned(),
                    symbol: native_values[1].to_owned(),
                    decimals,
                })
            }
            _ => {
                errors.native_currency = Some(
                    "Use a 1–64 character name, a 1–32 character symbol, and decimals from 0 through 255."
                        .into(),
                );
                None
            }
        }
    };

    let parse_optional_base_url = |value: &str| -> std::result::Result<Option<url::Url>, ()> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(None);
        }
        let url = value.parse::<url::Url>().map_err(|_| ())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(());
        }
        Ok(Some(url))
    };
    let block_explorer_url =
        parse_optional_base_url(&draft.block_explorer_url).unwrap_or_else(|()| {
            errors.block_explorer_url = Some(
                "Enter an http:// or https:// base URL with no query string or fragment.".into(),
            );
            None
        });
    if block_explorer_url.is_none() && errors.block_explorer_url.is_none() {
        errors.block_explorer_url = Some("Enter the network's block explorer base URL.".into());
    }
    let documentation_url =
        parse_optional_base_url(&draft.documentation_url).unwrap_or_else(|()| {
            errors.documentation_url =
                Some("Enter an http:// or https:// URL with no query string or fragment.".into());
            None
        });
    if documentation_url.is_none() && errors.documentation_url.is_none() {
        errors.documentation_url = Some("Enter the network's documentation URL.".into());
    }

    if errors != NetworkEditorErrors::default() {
        return (None, errors);
    }
    let network = NetworkConfig {
        name: name.to_owned(),
        disabled,
        testnet,
        display_name: (!display_name.is_empty()).then(|| display_name.to_owned()),
        aliases,
        chain_id: chain_id.expect("validated above"),
        rpc_urls,
        rpc_strategy,
        finality_confirmations,
        native_currency,
        block_explorer_url,
        documentation_url,
    };
    if let Some(known) = ekubo_wallet_core::networks::known_network(network.chain_id)
        && known.config.testnet != network.testnet
    {
        errors.form = Some(format!(
            "Chain {} is classified as {} by the built-in network registry.",
            network.chain_id,
            if known.config.testnet {
                "a testnet"
            } else {
                "a mainnet"
            }
        ));
        return (None, errors);
    }
    if let Err(error) = ekubo_wallet_core::config::validate_network(&network) {
        errors.form = Some(format!("Network settings are invalid: {error:#}"));
        (None, errors)
    } else {
        (Some(network), errors)
    }
}

fn replace_input_value(
    input: Option<&Entity<InputState>>,
    value: impl Into<SharedString>,
    window: &mut Window,
    cx: &mut App,
) {
    if let Some(input) = input {
        input.update(cx, |input, cx| {
            input.set_value(value.into(), window, cx);
        });
    }
}

/// One endpoint per line, which is the only readable shape for a field that
/// routinely holds three or four URLs. It is also why the field it fills has
/// to be a multi-line input: see `RPC_URLS_PLACEHOLDER`.
fn rpc_urls_for_editor(urls: &[url::Url]) -> String {
    urls.iter()
        .map(url::Url::as_str)
        .collect::<Vec<_>>()
        .join(",\n")
}

/// Shows the same one-per-line shape the field accepts.
///
/// Kept next to `rpc_urls_for_editor` because the two together are the reason
/// this field cannot be a single-line input: gpui shapes a single line with
/// `shape_line`, which panics on a newline rather than wrapping or truncating.
const RPC_URLS_PLACEHOLDER: &str =
    "https://rpc.my-rollup.example,\nhttps://rpc-backup.my-rollup.example";

const TOKEN_INVENTORY_PAGE_SIZE: usize = 10_000;
const MAX_DESKTOP_TOKEN_INVENTORY: usize = 100_000;

fn collect_token_inventory(
    mut fetch: impl FnMut(usize, usize) -> Result<Vec<StoredToken>>,
) -> Result<Vec<StoredToken>> {
    let mut tokens = Vec::new();
    loop {
        let page = fetch(TOKEN_INVENTORY_PAGE_SIZE, tokens.len())?;
        ensure!(
            tokens.len().saturating_add(page.len()) <= MAX_DESKTOP_TOKEN_INVENTORY,
            "token inventory exceeds the desktop limit of {MAX_DESKTOP_TOKEN_INVENTORY} rows"
        );
        let complete = page.len() < TOKEN_INVENTORY_PAGE_SIZE;
        tokens.extend(page);
        if complete {
            return Ok(tokens);
        }
    }
}

fn review_queue_decision_count(
    queues: &OwnerReviewQueues,
    networks: &[NetworkConfig],
    testnet_mode: bool,
) -> usize {
    let visible_chain_ids = visible_network_chain_ids(networks, testnet_mode);
    let configured_chain_ids = networks
        .iter()
        .map(|network| network.chain_id)
        .collect::<BTreeSet<_>>();
    let token_sources = queues
        .token_proposals
        .iter()
        .filter(|proposal| {
            chain_is_visible(
                Some(proposal.token.chain_id),
                &visible_chain_ids,
                &configured_chain_ids,
            )
        })
        .map(|proposal| proposal.source.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    queues
        .transactions
        .iter()
        .filter(|request| {
            chain_is_visible(
                request.chain_id.parse().ok(),
                &visible_chain_ids,
                &configured_chain_ids,
            )
        })
        .count()
        + queues
            .typed_data
            .iter()
            .filter(|request| {
                chain_is_visible(
                    request.chain_id.parse().ok(),
                    &visible_chain_ids,
                    &configured_chain_ids,
                )
            })
            .count()
        + queues
            .messages
            .iter()
            .filter(|request| {
                chain_is_visible(
                    request
                        .chain_id
                        .as_deref()
                        .and_then(|chain| chain.parse().ok()),
                    &visible_chain_ids,
                    &configured_chain_ids,
                )
            })
            .count()
        + queues.policy_proposals.len()
        + queues
            .network_proposals
            .iter()
            .filter(|proposal| testnet_mode || !proposal.testnet)
            .count()
        + token_sources
}

fn review_section_priority(kind: ApprovalSectionKind) -> u8 {
    match kind {
        ApprovalSectionKind::Effects => 0,
        ApprovalSectionKind::Action => 1,
        ApprovalSectionKind::Fees => 2,
        ApprovalSectionKind::Details => 3,
    }
}

#[cfg(test)]
fn review_sections_for_display(document: &ReviewDocument) -> Vec<&ApprovalSection> {
    let mut sections = document.request.sections.iter().collect::<Vec<_>>();
    sections.sort_by_key(|section| review_section_priority(section.kind));
    sections
}

fn balance_effect_asset(label: &str) -> (String, Option<String>) {
    if let Some(address) = label.strip_suffix(" (unlisted token)")
        && address.starts_with("0x")
    {
        return ("Unlisted token".into(), Some(address.into()));
    }
    if let Some(symbol) = label.strip_suffix(" (native)") {
        return (symbol.into(), Some("Native asset".into()));
    }
    if let Some((symbol, address)) = label.rsplit_once(" (")
        && let Some(address) = address.strip_suffix(')')
        && address.starts_with("0x")
    {
        return (symbol.into(), Some(address.into()));
    }
    (label.into(), None)
}

impl RouteListDelegate {
    fn new() -> Self {
        Self {
            routes: Route::ALL.into(),
            selected: Some(IndexPath::default()),
        }
    }

    fn route(&self, index: IndexPath) -> Option<Route> {
        self.routes.get(index.row).copied()
    }
}

impl ListDelegate for RouteListDelegate {
    type Item = ListItem;

    fn items_count(&self, _: usize, _: &App) -> usize {
        self.routes.len()
    }

    fn perform_search(
        &mut self,
        query: &str,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) -> Task<()> {
        let mut matches = Route::ALL
            .into_iter()
            .filter_map(|route| fuzzy_route_score(route.label(), query).map(|score| (score, route)))
            .collect::<Vec<_>>();
        matches.sort_by_key(|(score, route)| (*score, route.menu_order()));
        self.routes = matches.into_iter().map(|(_, route)| route).collect();
        self.selected = (!self.routes.is_empty()).then(IndexPath::default);
        Task::ready(())
    }

    fn set_selected_index(
        &mut self,
        index: Option<IndexPath>,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) {
        self.selected = index;
    }

    fn render_item(
        &mut self,
        index: IndexPath,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) -> Option<Self::Item> {
        let route = self.route(index)?;
        Some(
            ListItem::new(("command-route", index.row)).child(
                h_flex()
                    .gap_3()
                    .child(Icon::new(route.icon()))
                    .child(route.label()),
            ),
        )
    }
}

impl ListDelegate for TokenListDelegate {
    type Item = ListItem;

    fn items_count(&self, _: usize, _: &App) -> usize {
        self.visible_tokens.len()
    }

    fn perform_search(
        &mut self,
        query: &str,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) -> Task<()> {
        query.clone_into(&mut self.query);
        self.apply_filters();
        Task::ready(())
    }

    fn set_selected_index(
        &mut self,
        index: Option<IndexPath>,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) {
        self.selected = index;
    }

    fn render_item(
        &mut self,
        index: IndexPath,
        _: &mut Window,
        cx: &mut Context<ListState<Self>>,
    ) -> Option<Self::Item> {
        let token = self.visible_tokens.get(index.row)?.clone();
        let chain_id = token.chain_id.parse::<u64>().ok();
        let address = token.address.parse::<alloy::primitives::Address>().ok();
        let network_name = chain_id
            .and_then(|chain_id| self.network_names.get(&chain_id).cloned())
            .unwrap_or_else(|| format!("Unknown network · chain {}", token.chain_id).into());
        let state = cx.entity().downgrade();
        let removal_token = token.clone();
        let removing = chain_id
            .zip(address)
            .is_some_and(|identity| self.removing.contains(&identity));
        let action_error = chain_id
            .zip(address)
            .and_then(|identity| self.action_errors.get(&identity).cloned());
        let row_id = format!("token-{}-{}", token.chain_id, token.address);
        let address_text_id = SharedString::from(format!("{row_id}-address"));
        let owner = self.owner.clone();
        let actions = app_button(("remove-token", index.row))
            .label(if removing { "Removing…" } else { "Remove" })
            .danger()
            .disabled(chain_id.zip(address).is_none() || removing)
            .on_click(move |_, _, cx| {
                let Some((chain_id, address)) = chain_id.zip(address) else {
                    return;
                };
                let started = state
                    .update(cx, |list, cx| {
                        let delegate = list.delegate_mut();
                        if !delegate.removing.insert((chain_id, address)) {
                            return false;
                        }
                        delegate.action_errors.remove(&(chain_id, address));
                        cx.notify();
                        true
                    })
                    .unwrap_or(false);
                if !started {
                    return;
                }
                let owner = owner.clone();
                let state = state.clone();
                let removal_token = removal_token.clone();
                let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                    owner.remove_token(&removal_token)
                });
                cx.spawn(async move |cx| {
                    let result = task.await;
                    let _ = state.update(cx, |list, cx| {
                        let delegate = list.delegate_mut();
                        delegate.removing.remove(&(chain_id, address));
                        match result {
                            Ok(()) => {
                                delegate.action_errors.remove(&(chain_id, address));
                                delegate.all_tokens.retain(|item| {
                                    !(item.chain_id.parse::<u64>().ok() == Some(chain_id)
                                        && item.address.parse::<alloy::primitives::Address>().ok()
                                            == Some(address))
                                });
                                delegate.apply_filters();
                            }
                            Err(error) => {
                                delegate.action_errors.insert(
                                    (chain_id, address),
                                    format!("Could not remove token: {error:#}").into(),
                                );
                            }
                        }
                        cx.notify();
                    });
                })
                .detach();
            });
        Some(
            ListItem::new(SharedString::from(row_id))
                .selected(self.selected == Some(index))
                .child(
                    div()
                        .w_full()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            h_flex()
                                .w_full()
                                .flex_wrap()
                                .justify_between()
                                .gap_4()
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .child(
                                            div()
                                                .w_full()
                                                .flex()
                                                .flex_col()
                                                .gap_0p5()
                                                .child(
                                                    div().w_full().truncate().child(
                                                        selectable_text(
                                                            ("token-symbol", index.row),
                                                            token
                                                                .symbol
                                                                .as_deref()
                                                                .unwrap_or("Unnamed token"),
                                                        ),
                                                    ),
                                                )
                                                .child(
                                                    div()
                                                        .w_full()
                                                        .min_w_0()
                                                        .text_sm()
                                                        .text_color(cx.theme().muted_foreground)
                                                        .truncate()
                                                        .child(selectable_text(
                                                            ("token-metadata", index.row),
                                                            &format!(
                                                                "{} · {network_name}",
                                                                token
                                                                    .name
                                                                    .as_deref()
                                                                    .unwrap_or("No full name")
                                                            ),
                                                        )),
                                                ),
                                        )
                                        .child(
                                            selectable_text(address_text_id, &token.address)
                                                .font_family(MONO_FONT_FAMILY)
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .truncate(),
                                        )
                                        .child(
                                            div()
                                                .min_w_0()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .truncate()
                                                .child(selectable_text(
                                                    ("token-decimals-source", index.row),
                                                    &format!(
                                                        "{} decimals · {}",
                                                        token.decimals.map_or_else(
                                                            || "unknown".to_owned(),
                                                            |value| value.to_string()
                                                        ),
                                                        token.source
                                                    ),
                                                )),
                                        ),
                                )
                                .child(actions),
                        )
                        .when_some(action_error, |row, error| {
                            row.child(
                                div().text_sm().text_color(cx.theme().danger).child(
                                    selectable_text(("token-action-error", index.row), &error),
                                ),
                            )
                        }),
                ),
        )
    }

    fn loading(&self, _: &App) -> bool {
        self.loading
    }

    fn render_empty(
        &mut self,
        _: &mut Window,
        cx: &mut Context<ListState<Self>>,
    ) -> impl IntoElement {
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .text_color(cx.theme().muted_foreground)
            .child(selectable_text(
                "token-list-empty-message",
                &self
                    .error
                    .clone()
                    .unwrap_or_else(|| "No tokens match these filters.".into()),
            ))
    }
}

impl ListDelegate for TokenProposalListDelegate {
    type Item = ListItem;

    fn items_count(&self, _: usize, _: &App) -> usize {
        self.proposals.len()
    }

    fn set_selected_index(
        &mut self,
        index: Option<IndexPath>,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) {
        self.selected = index;
    }

    fn render_item(
        &mut self,
        index: IndexPath,
        _: &mut Window,
        cx: &mut Context<ListState<Self>>,
    ) -> Option<Self::Item> {
        let proposal = self.proposals.get(index.row)?;
        let token = &proposal.token;
        let token_address = token.address.to_checksum(None);
        let network_name = self
            .network_names
            .get(&token.chain_id)
            .cloned()
            .unwrap_or_else(|| format!("Unknown network · chain {}", token.chain_id).into());
        Some(
            ListItem::new(("token-proposal", index.row))
                .selected(self.selected == Some(index))
                .child(
                    div()
                        .w_full()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            h_flex()
                                .w_full()
                                .gap_3()
                                .child(div().flex_1().min_w_0().truncate().child(selectable_text(
                                    ("token-proposal-symbol", index.row),
                                    &token.symbol,
                                )))
                                .child(
                                    div()
                                        .flex_none()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(selectable_text(
                                            ("token-proposal-network", index.row),
                                            &network_name,
                                        )),
                                ),
                        )
                        .child(
                            selectable_text(("token-proposal-address", index.row), &token_address)
                                .font_family(MONO_FONT_FAMILY)
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .truncate(),
                        )
                        .child(
                            div()
                                .min_w_0()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .truncate()
                                .child(selectable_text(
                                    ("token-proposal-metadata", index.row),
                                    &format!(
                                        "{} · {} decimals",
                                        token.name.as_deref().unwrap_or("No full name"),
                                        token.decimals
                                    ),
                                )),
                        ),
                ),
        )
    }

    fn has_more(&self, _: &App) -> bool {
        !self.proposals.is_empty() && !self.viewed_to_end
    }

    fn load_more_threshold(&self) -> usize {
        1
    }

    fn load_more(&mut self, _: &mut Window, cx: &mut Context<ListState<Self>>) {
        self.viewed_to_end = true;
        cx.notify();
    }
}

fn fuzzy_route_score(label: &str, query: &str) -> Option<usize> {
    let label = label
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<Vec<_>>();
    let query = query
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<Vec<_>>();
    if query.is_empty() {
        return Some(0);
    }
    let mut cursor = 0;
    let mut previous = None;
    let mut score = 0;
    for wanted in query {
        let relative = label
            .get(cursor..)?
            .iter()
            .position(|value| *value == wanted)?;
        let position = cursor + relative;
        score += previous.map_or(position, |previous| position.saturating_sub(previous + 1));
        previous = Some(position);
        cursor = position + 1;
    }
    Some(score)
}

fn review_policy_draft(
    wallet_id: &str,
    source_revision: Option<u64>,
    current_policy: Option<&WalletPolicy>,
    document: &str,
) -> Result<PolicyDraftReview> {
    ensure!(!document.trim().is_empty(), "policy document is empty");
    let value: serde_json::Value =
        serde_json::from_str(document).context("policy document is not valid JSON")?;
    let policy = WalletPolicy::parse(value)?;
    let document = serde_json::to_string_pretty(&policy)?;
    let baseline = current_policy
        .cloned()
        .unwrap_or_else(WalletPolicy::require_approval_for_everything);
    let diff = diff_policies(&baseline, &policy);
    Ok(PolicyDraftReview {
        wallet_id: wallet_id.to_owned(),
        source_revision,
        document,
        policy,
        diff,
    })
}

fn previous_policy_revision(current_index: Option<usize>, revision_count: usize) -> Option<usize> {
    current_index.unwrap_or(revision_count).checked_sub(1)
}

fn latest_policy_revision(revision_count: usize) -> Option<usize> {
    revision_count.checked_sub(1)
}

fn policy_account_to_open<'a>(
    accounts: &'a [WalletMetadata],
    selected_wallet_id: Option<&str>,
) -> Option<&'a str> {
    selected_wallet_id
        .and_then(|selected| accounts.iter().find(|account| account.id == selected))
        .or_else(|| accounts.first())
        .map(|account| account.id.as_str())
}

fn allow_anything_policy_document() -> Result<String> {
    Ok(serde_json::to_string_pretty(
        &WalletPolicy::allow_anything(),
    )?)
}

fn disable_signing_policy_document() -> Result<String> {
    Ok(serde_json::to_string_pretty(&WalletPolicy::deny_all())?)
}

impl WalletWindow {
    fn new(
        owner: OwnerApi,
        review_presenter: GuiReviewPresenter,
        walletconnect: Arc<Mutex<WalletConnectManager>>,
        walletconnect_presenter: ProposalPresenter,
        tray: Rc<RefCell<Option<PlatformTray>>>,
        pending_update: Arc<Mutex<Option<PreparedUpdate>>>,
        data_dir: &Path,
        cx: &mut Context<Self>,
    ) -> Self {
        let appearance_preference = owner.appearance_preference().unwrap_or_default();
        let testnet_mode = owner.testnet_mode().unwrap_or(false);
        let route_scroll_handle = ScrollHandle::new();
        let route_overflow_indicator =
            ScrollOverflowIndicator::new(route_scroll_handle.clone(), cx);
        let network_editor_scroll_handle = ScrollHandle::new();
        let network_editor_overflow_indicator =
            ScrollOverflowIndicator::new(network_editor_scroll_handle.clone(), cx);
        let review_overflow_indicator = ScrollOverflowIndicator::new(ScrollHandle::new(), cx);
        let legal_overflow_indicator =
            ScrollOverflowIndicator::new(UniformListScrollHandle::new(), cx);
        let activity_detail_scroll_handle = ScrollHandle::new();
        let activity_detail_overflow_indicator =
            ScrollOverflowIndicator::new(activity_detail_scroll_handle.clone(), cx);
        let sidebar_route_bounds = Route::ALL
            .into_iter()
            .map(|route| (route, Rc::new(Cell::new(None))))
            .collect();
        let sidebar_logo_light =
            render_embedded_png(include_bytes!("../assets/tray/light_mode_tray_icon.png"))
                .expect("embedded light tray icon must be valid");
        let sidebar_logo_dark =
            render_embedded_png(include_bytes!("../assets/tray/dark_mode_tray_icon.png"))
                .expect("embedded dark tray icon must be valid");
        let mut window = Self {
            owner,
            desktop_snapshot: None,
            desktop_snapshot_generation: 0,
            desktop_snapshot_loading: false,
            desktop_snapshot_dirty: false,
            desktop_snapshot_error: None,
            tray,
            sidebar_logo_light,
            sidebar_logo_dark,
            appearance_subscription: None,
            review_presenter,
            route: Route::DEFAULT,
            sidebar_hovered_route: None,
            sidebar_route_bounds,
            command_palette: false,
            command_palette_list: None,
            command_palette_subscription: None,
            form_input_subscriptions: Vec::new(),
            token_list: None,
            token_search_input: None,
            token_proposal_list: None,
            token_list_url_input: None,
            token_chain_id_input: None,
            token_address_input: None,
            token_symbol_input: None,
            token_name_input: None,
            token_decimals_input: None,
            token_editor_open: false,
            token_editor_errors: TokenEditorErrors::default(),
            token_editor_busy: false,
            token_list_import_open: false,
            token_import_state: TokenImportState::Idle,
            token_import_error: None,
            token_import_status: None,
            token_proposal_error: None,
            token_list_generation: 0,
            mcp_status: McpGatewayStatus::Starting,
            selected_record: None,
            inbox_tab: InboxTab::Waiting,
            activity_busy: BTreeSet::new(),
            activity_refreshing: BTreeSet::new(),
            activity_refresh_task: None,
            activity_feedback: BTreeMap::new(),
            activity_feedback_seq: 0,
            history_clearing: false,
            history_clear_error: None,
            activity_inspections: BTreeMap::new(),
            activity_payloads_expanded: BTreeSet::new(),
            active_review: None,
            queued_reviews: SerialQueue::default(),
            review_flow: ReviewFlowState::Ready,
            notification_navigation: NotificationNavigation::default(),
            agent_reinstall: AgentReinstallState::Idle,
            detected_agents: AgentDetectionState::Loading,
            detected_agents_generation: 0,
            account_id_input: None,
            private_key_input: None,
            account_entry_mode: AccountEntryMode::Create,
            account_operation: None,
            account_status: None,
            account_status_seq: 0,
            account_id_error: None,
            private_key_error: None,
            account_action_errors: BTreeMap::new(),
            account_export: None,
            export_clipboard: Arc::new(Mutex::new(None)),
            legal_review: None,
            legal_gate: false,
            route_errors: BTreeMap::new(),
            appearance_preference,
            testnet_mode,
            portfolio: PortfolioState::Idle,
            portfolio_generation: 0,
            portfolio_account_index: 0,
            portfolio_refreshed_at: BTreeMap::new(),
            portfolio_clock_task: None,
            policy_editor_anchor: ScrollAnchor::for_handle(route_scroll_handle.clone()),
            route_scroll_handle,
            route_overflow_indicator,
            modal_focus: cx.focus_handle(),
            walletconnect,
            walletconnect_sessions: Vec::new(),
            walletconnect_connecting: None,
            walletconnect_presenter,
            walletconnect_uri_input: None,
            network_editor_open: false,
            network_editor_scroll_handle,
            network_editor_overflow_indicator,
            network_editor_original: None,
            network_editor_disabled: false,
            network_editor_testnet: false,
            network_editor_rpc_strategy: RpcStrategy::Ordered,
            network_editor_advanced_open: false,
            network_editor_busy: false,
            network_editor_errors: NetworkEditorErrors::default(),
            network_name_input: None,
            network_display_name_input: None,
            network_aliases_input: None,
            network_chain_id_input: None,
            network_rpc_urls_input: None,
            network_native_name_input: None,
            network_native_symbol_input: None,
            network_native_decimals_input: None,
            network_explorer_url_input: None,
            network_documentation_url_input: None,
            network_action_busy: BTreeSet::new(),
            network_action_errors: BTreeMap::new(),
            network_proposal_error: None,
            review_overflow_indicator,
            legal_overflow_indicator,
            activity_detail_scroll_handle,
            activity_detail_overflow_indicator,
            activity_detail_record: Cell::new(None),
            policy_json_input: None,
            policy_editor: None,
            policy_account_id: None,
            policy_installing: false,
            policy_action_error: None,
            token_proposal_busy: false,
            network_proposal_busy: false,
            automation_busy: None,
            automation_error: None,
            release_state: ReleaseDisplayState::Idle,
            pending_update,
            update_data_dir: data_dir.to_path_buf(),
        };
        window.open_next_required_legal(cx);
        window.reload_detected_agents(cx);
        window.reload_desktop_snapshot(cx);
        window
    }

    fn attach_window(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mut token_lists_created = false;
        if self.activity_refresh_task.is_none() {
            self.activity_refresh_task = Some(cx.spawn(async move |view, cx| {
                loop {
                    cx.background_executor()
                        .timer(ACTIVITY_REFRESH_INTERVAL)
                        .await;
                    if view
                        .update(cx, |view, cx| {
                            view.refresh_visible_pending_transactions(cx);
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }));
        }
        if self.portfolio_clock_task.is_none() {
            // Reopening the window onto the Portfolio tab is an opening too.
            // Closing it keeps both the route and the balances, and no
            // navigation happens on the way back in, so without this the tab
            // would show whatever it held when the window went away until the
            // user clicked off it and back. This block runs once per window
            // attach, which is what keeps it from becoming a per-render poll.
            if self.route == Route::Overview {
                self.refresh_portfolio_if_stale(cx);
            }
            self.portfolio_clock_task = Some(cx.spawn(async move |view, cx| {
                loop {
                    cx.background_executor()
                        .timer(PORTFOLIO_CLOCK_INTERVAL)
                        .await;
                    if view
                        .update(cx, |view, cx| {
                            // Redraw only what the tick is for. Notifying while
                            // another tab is open would rebuild that page every
                            // half minute to age a line nobody is looking at.
                            if view.route == Route::Overview
                                && view.focused_portfolio_refreshed_at().is_some()
                            {
                                cx.notify();
                            }
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }));
        }
        if self.appearance_subscription.is_none() {
            let tray = self.tray.clone();
            self.appearance_subscription = Some(cx.observe_window_appearance(
                window,
                move |view, window, cx| {
                    if let Some(tray) = tray.borrow_mut().as_mut() {
                        tray.set_dark_mode(dark_appearance(window.appearance()));
                    }
                    if view.appearance_preference == AppearancePreference::System {
                        Theme::sync_system_appearance(Some(window), cx);
                        apply_interface_palette(cx);
                        cx.notify();
                    }
                },
            ));
        }
        if self.command_palette_list.is_none() {
            let list =
                cx.new(|cx| ListState::new(RouteListDelegate::new(), window, cx).searchable(true));
            list.update(cx, |list, cx| {
                list.set_selected_index(Some(IndexPath::default()), window, cx);
            });
            self.command_palette_subscription = Some(cx.subscribe(
                &list,
                |view, list, event: &ListEvent, cx| match event {
                    ListEvent::Confirm(index) => {
                        if let Some(route) = list.read(cx).delegate().route(*index) {
                            view.navigate_route(route, cx);
                        }
                        view.command_palette = false;
                        cx.notify();
                    }
                    ListEvent::Cancel => {
                        view.command_palette = false;
                        cx.notify();
                    }
                    ListEvent::Select(_) => {}
                },
            ));
            self.command_palette_list = Some(list);
        }
        if self.token_list.is_none() {
            let owner = self.owner.clone();
            self.token_list = Some(cx.new(|cx| {
                ListState::new(TokenListDelegate::new(owner), window, cx).selectable(false)
            }));
            token_lists_created = true;
            self.reload_tokens(cx);
        }
        if self.token_search_input.is_none()
            && let Some(token_list) = self.token_list.clone()
        {
            let input = cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Search token name, symbol, chain ID, or address")
            });
            self.form_input_subscriptions.push(cx.subscribe_in(
                &input,
                window,
                move |_, input, event: &InputEvent, _, cx| {
                    if !matches!(event, InputEvent::Change) {
                        return;
                    }
                    let query = input.read(cx).value().trim().to_owned();
                    token_list.update(cx, |list, cx| {
                        let delegate = list.delegate_mut();
                        delegate.query = query;
                        delegate.apply_filters();
                        cx.notify();
                    });
                },
            ));
            self.token_search_input = Some(input);
        }
        if self.token_proposal_list.is_none() {
            self.token_proposal_list = Some(cx.new(|cx| {
                ListState::new(TokenProposalListDelegate::new(), window, cx).selectable(false)
            }));
            token_lists_created = true;
        }
        if token_lists_created
            && let Some(networks) = self
                .desktop_snapshot
                .as_deref()
                .and_then(|snapshot| snapshot.networks.as_ref().ok())
        {
            if let Some(list) = self.token_list.as_ref() {
                list.update(cx, |list, cx| {
                    list.delegate_mut()
                        .replace_networks(networks, self.testnet_mode);
                    cx.notify();
                });
            }
            if let Some(list) = self.token_proposal_list.as_ref() {
                let visible = networks
                    .iter()
                    .filter(|network| self.testnet_mode || !network.testnet)
                    .cloned()
                    .collect::<Vec<_>>();
                list.update(cx, |list, cx| {
                    list.delegate_mut().replace_networks(&visible);
                    cx.notify();
                });
            }
        }
        if self.token_list_url_input.is_none() {
            let input = cx.new(|cx| {
                InputState::new(window, cx).placeholder("https://tokens.example.org/tokens.json")
            });
            self.form_input_subscriptions.push(cx.subscribe_in(
                &input,
                window,
                |view, _, event: &InputEvent, _, cx| {
                    if primary_enter(event) {
                        view.import_token_list_for_review(cx);
                    }
                },
            ));
            self.token_list_url_input = Some(input);
        }
        if self.token_chain_id_input.is_none() {
            self.token_chain_id_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("1")));
        }
        if self.token_address_input.is_none() {
            self.token_address_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("0x0000000000000000000000000000000000000000")
            }));
        }
        if self.token_symbol_input.is_none() {
            self.token_symbol_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("USDC")));
        }
        if self.token_name_input.is_none() {
            self.token_name_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("USD Coin (optional)")));
        }
        if self.token_decimals_input.is_none() {
            let input = cx.new(|cx| InputState::new(window, cx).placeholder("18"));
            self.form_input_subscriptions.push(cx.subscribe_in(
                &input,
                window,
                |view, _, event: &InputEvent, _, cx| {
                    if primary_enter(event) && view.token_editor_open {
                        view.save_token_editor(cx);
                    }
                },
            ));
            self.token_decimals_input = Some(input);
        }
        if self.account_id_input.is_none() {
            let input = cx.new(|cx| {
                InputState::new(window, cx).placeholder("Account name, for example primary")
            });
            self.form_input_subscriptions.push(cx.subscribe_in(
                &input,
                window,
                |view, _, event: &InputEvent, window, cx| {
                    if primary_enter(event) {
                        view.create_account(window, cx);
                    }
                },
            ));
            self.account_id_input = Some(input);
        }
        if self.private_key_input.is_none() {
            let input = cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("0x-prefixed 32-byte private key")
                    .masked(true)
            });
            self.form_input_subscriptions.push(cx.subscribe_in(
                &input,
                window,
                |view, _, event: &InputEvent, window, cx| {
                    if primary_enter(event) {
                        view.import_account(window, cx);
                    }
                },
            ));
            self.private_key_input = Some(input);
        }
        if self.walletconnect_uri_input.is_none() {
            let input = cx.new(|cx| InputState::new(window, cx).placeholder("wc: pairing URI"));
            self.form_input_subscriptions.push(cx.subscribe_in(
                &input,
                window,
                |view, _, event: &InputEvent, window, cx| {
                    if primary_enter(event) {
                        view.connect_walletconnect(window, cx);
                    }
                },
            ));
            self.walletconnect_uri_input = Some(input);
        }
        if self.network_name_input.is_none() {
            self.network_name_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("my-rollup")));
        }
        if self.network_display_name_input.is_none() {
            self.network_display_name_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("My Rollup")));
        }
        if self.network_aliases_input.is_none() {
            self.network_aliases_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("my-rollup-testnet, rollup-test")
            }));
        }
        if self.network_chain_id_input.is_none() {
            self.network_chain_id_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("123456")));
        }
        if self.network_rpc_urls_input.is_none() {
            self.network_rpc_urls_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    // `rows` alone leaves the field single-line, and a
                    // single-line input shapes its text with `shape_line`,
                    // which panics on a newline instead of degrading. Both
                    // this placeholder and the value the editor seeds from an
                    // existing network span lines, so opening the network
                    // editor aborted the process without this.
                    .multi_line(true)
                    .rows(5)
                    .placeholder(RPC_URLS_PLACEHOLDER)
            }));
        }
        if self.network_native_name_input.is_none() {
            self.network_native_name_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("Ether")));
        }
        if self.network_native_symbol_input.is_none() {
            self.network_native_symbol_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("ETH")));
        }
        if self.network_native_decimals_input.is_none() {
            self.network_native_decimals_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("18")));
        }
        if self.network_explorer_url_input.is_none() {
            self.network_explorer_url_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("https://explorer.my-rollup.example")
            }));
        }
        if self.network_documentation_url_input.is_none() {
            // No per-input Enter subscription here: the network dialog's
            // `on_ok` already saves on Enter from any of its single-line
            // fields, so one field carrying its own submit handler would only
            // run the same save twice.
            self.network_documentation_url_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("https://docs.my-rollup.example")
            }));
        }
        if self.policy_json_input.is_none() {
            self.policy_json_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .code_editor("json")
                    .rows(20)
                    .placeholder("Select an account to inspect and edit its policy")
            }));
        }
    }

    /// Drop every window-scoped entity this view owns.
    ///
    /// Reopening the window rebuilds all of them, and each one left behind is
    /// an input still subscribed to a window that no longer exists. It is also
    /// the list that has to grow whenever a field does, which is why it lives
    /// beside the fields rather than being spelled out at a call site.
    fn release_window_state(&mut self, cx: &mut Context<Self>) {
        self.activity_refresh_task = None;
        self.activity_refreshing.clear();
        self.portfolio_clock_task = None;
        self.command_palette = false;
        self.command_palette_list = None;
        self.command_palette_subscription = None;
        self.form_input_subscriptions.clear();
        self.appearance_subscription = None;
        self.token_list = None;
        self.token_search_input = None;
        self.token_proposal_list = None;
        self.token_list_url_input = None;
        self.token_chain_id_input = None;
        self.token_address_input = None;
        self.token_symbol_input = None;
        self.token_name_input = None;
        self.token_decimals_input = None;
        self.token_editor_open = false;
        self.token_list_generation = self.token_list_generation.wrapping_add(1);
        self.account_id_input = None;
        self.private_key_input = None;
        self.walletconnect_uri_input = None;
        self.network_name_input = None;
        self.network_display_name_input = None;
        self.network_aliases_input = None;
        self.network_chain_id_input = None;
        self.network_rpc_urls_input = None;
        self.network_native_name_input = None;
        self.network_native_symbol_input = None;
        self.network_native_decimals_input = None;
        self.network_explorer_url_input = None;
        self.network_documentation_url_input = None;
        self.network_editor_open = false;
        self.network_editor_original = None;
        self.policy_json_input = None;
        self.policy_editor = None;
        self.policy_installing = false;
        self.token_proposal_busy = false;
        self.network_proposal_busy = false;
        cx.notify();
    }

    fn set_route_error(&mut self, route: Route, error: impl Into<SharedString>) {
        self.route_errors.insert(route, error.into());
    }

    fn clear_route_error(&mut self, route: Route) {
        self.route_errors.remove(&route);
    }

    fn reload_detected_agents(&mut self, cx: &mut Context<Self>) {
        self.detected_agents_generation = self.detected_agents_generation.wrapping_add(1);
        let generation = self.detected_agents_generation;
        // Detection is a few file reads, and it re-runs after every install.
        // Blanking the list back to "Detecting…" each time made a list that
        // barely changes flash on every visit; the previous answer stays up
        // until the new one replaces it.
        if matches!(self.detected_agents, AgentDetectionState::Failed(_)) {
            self.detected_agents = AgentDetectionState::Loading;
        }
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(detect_agents)
                .await
                .context("agent detection task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                if view.detected_agents_generation != generation {
                    return;
                }
                view.detected_agents = match result {
                    Ok(agents) => AgentDetectionState::Ready(agents),
                    Err(error) => AgentDetectionState::Failed(format!("{error:#}").into()),
                };
                cx.notify();
            });
        })
        .detach();
    }

    fn reload_desktop_snapshot(&mut self, cx: &mut Context<Self>) {
        if self.desktop_snapshot_loading {
            self.desktop_snapshot_dirty = true;
            return;
        }
        self.desktop_snapshot_generation = self.desktop_snapshot_generation.wrapping_add(1);
        let generation = self.desktop_snapshot_generation;
        self.desktop_snapshot_loading = true;
        self.desktop_snapshot_error = None;
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || DesktopSnapshot::capture(&owner))
                .await
                .context("desktop snapshot task failed")
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                if view.desktop_snapshot_generation != generation {
                    return;
                }
                view.desktop_snapshot_loading = false;
                match result {
                    Ok(snapshot) => {
                        if let Ok(networks) = &snapshot.networks {
                            if let Some(list) = view.token_list.as_ref() {
                                list.update(cx, |list, cx| {
                                    list.delegate_mut()
                                        .replace_networks(networks, view.testnet_mode);
                                    cx.notify();
                                });
                            }
                            if let Some(list) = view.token_proposal_list.as_ref() {
                                let visible = networks
                                    .iter()
                                    .filter(|network| view.testnet_mode || !network.testnet)
                                    .cloned()
                                    .collect::<Vec<_>>();
                                list.update(cx, |list, cx| {
                                    list.delegate_mut().replace_networks(&visible);
                                    cx.notify();
                                });
                            }
                        }
                        view.desktop_snapshot = Some(Arc::new(snapshot));
                        view.desktop_snapshot_error = None;
                    }
                    Err(error) => {
                        view.desktop_snapshot_error =
                            Some(format!("Could not refresh wallet data: {error:#}").into());
                    }
                }
                if view.desktop_snapshot_dirty {
                    view.desktop_snapshot_dirty = false;
                    view.reload_desktop_snapshot(cx);
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn snapshot(&self) -> Result<&DesktopSnapshot> {
        self.desktop_snapshot
            .as_deref()
            .context("Wallet data is loading")
    }

    fn cached_reviews(&self) -> Result<&OwnerReviewQueues> {
        self.snapshot()?
            .reviews
            .as_ref()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn cached_activity_records(&self) -> Result<Arc<[OwnerActivityRecord]>> {
        self.snapshot()?
            .activity
            .as_ref()
            .cloned()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn cached_accounts(&self) -> Result<&[WalletMetadata]> {
        self.snapshot()?
            .accounts
            .as_deref()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn cached_policy(&self, wallet_id: &str) -> Result<Option<&StoredPolicy>> {
        self.snapshot()?
            .policies
            .get(wallet_id)
            .context("Wallet policy is loading")?
            .as_ref()
            .map(Option::as_ref)
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn cached_legal_status(&self) -> Result<&LegalStatus> {
        self.snapshot()?
            .legal_status
            .as_ref()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn cached_networks(&self) -> Result<&[NetworkConfig]> {
        self.snapshot()?
            .networks
            .as_deref()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    /// Chain IDs mapped to the names the owner configured for them, so no
    /// surface has to print a bare number at a reader.
    fn network_display_names(&self) -> BTreeMap<u64, SharedString> {
        self.cached_networks()
            .map(token_network_names)
            .unwrap_or_default()
    }

    fn chain_id_is_visible(&self, chain_id: Option<u64>) -> bool {
        if self.testnet_mode {
            return true;
        }
        self.cached_networks().map_or(true, |networks| {
            chain_id.is_none_or(|chain_id| {
                networks
                    .iter()
                    .find(|network| network.chain_id == chain_id)
                    .is_none_or(|network| !network.testnet)
            })
        })
    }

    fn token_proposal_is_visible(&self, proposal: &TokenProposal) -> bool {
        self.chain_id_is_visible(Some(proposal.token.chain_id))
    }

    fn review_document_is_visible(&self, document: &ReviewDocument) -> bool {
        self.cached_networks().map_or(true, |networks| {
            review_document_is_visible(document, networks, self.testnet_mode)
        })
    }

    fn cached_message_document(&self, request_id: uuid::Uuid) -> Result<&ReviewDocument> {
        self.snapshot()?
            .message_documents
            .get(&request_id)
            .context("Message details are loading")?
            .as_ref()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn cached_typed_data_document(&self, request_id: uuid::Uuid) -> Result<&ReviewDocument> {
        self.snapshot()?
            .typed_data_documents
            .get(&request_id)
            .context("Typed-data details are loading")?
            .as_ref()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    fn reload_tokens(&mut self, cx: &mut Context<Self>) {
        let Some(list) = self.token_list.clone() else {
            return;
        };
        self.token_list_generation = self.token_list_generation.wrapping_add(1);
        let generation = self.token_list_generation;
        list.update(cx, |list, cx| {
            list.delegate_mut().loading = true;
            cx.notify();
        });
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || {
                collect_token_inventory(|limit, offset| owner.tokens(None, limit, offset))
            })
            .await
            .context("token inventory task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                if view.token_list_generation != generation {
                    return;
                }
                list.update(cx, |list, cx| {
                    list.delegate_mut().replace_tokens(result);
                    cx.notify();
                });
            });
        })
        .detach();
    }

    fn open_new_token_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(chain_id) = self.token_chain_id_input.clone() else {
            return;
        };
        let Some(address) = self.token_address_input.clone() else {
            return;
        };
        let Some(symbol) = self.token_symbol_input.clone() else {
            return;
        };
        let Some(name) = self.token_name_input.clone() else {
            return;
        };
        let Some(decimals) = self.token_decimals_input.clone() else {
            return;
        };
        for input in [&chain_id, &address, &symbol, &name, &decimals] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.token_editor_open = true;
        self.token_editor_errors = TokenEditorErrors::default();
        let chain_id_focus = chain_id.clone();
        let view = cx.entity().downgrade();
        window.open_dialog(cx, move |dialog, _, cx| {
            let Some(entity) = view.upgrade() else {
                return dialog.title("Add token").child("Token form unavailable.");
            };
            let (busy, errors, chain_hint) = {
                let window = entity.read(cx);
                // Which network the number in the field actually names. The
                // form asked for a chain ID and said nothing back, so adding a
                // token meant knowing that Base is 8453 and trusting you had
                // typed it — and a wrong-but-configured chain saved happily
                // under the wrong network.
                let hint = window.token_editor_chain_hint(cx);
                (
                    window.token_editor_busy,
                    window.token_editor_errors.clone(),
                    hint,
                )
            };
            let add_view = view.clone();
            let close_view = view.clone();
            let on_close_view = view.clone();
            dialog
                .w(px(640.0))
                .title("Add token")
                .overlay_closable(!busy)
                .keyboard(!busy)
                .close_button(!busy)
                .on_close(move |_, _, cx| {
                    let _ = on_close_view.update(cx, |view, cx| {
                        view.token_editor_open = false;
                        view.token_editor_errors = TokenEditorErrors::default();
                        view.activate_next_waiting_surface(cx);
                        cx.notify();
                    });
                })
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(selectable_label("Add display metadata for a token on a configured network. Adding it requires operating-system authentication.")),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap_3()
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .flex_1()
                                        .min_w(px(150.0))
                                        .child(div().text_sm().child("Chain ID"))
                                        .child(
                                            app_input(&chain_id, cx)
                                                .aria_label("Chain ID")
                                                .disabled(busy),
                                        )
                                        .when_some(chain_hint, |field, hint| {
                                            field.child(
                                                div()
                                                    .text_xs()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child(selectable_label(hint)),
                                            )
                                        })
                                        .when_some(errors.chain_id.clone(), |field, error| {
                                            field.child(field_error(
                                                "token-editor-chain-id-error",
                                                error,
                                                cx,
                                            ))
                                        }),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .flex_1()
                                        .min_w(px(150.0))
                                        .child(div().text_sm().child("Symbol"))
                                        .child(
                                            app_input(&symbol, cx)
                                                .aria_label("Token symbol")
                                                .disabled(busy),
                                        )
                                        .when_some(errors.symbol.clone(), |field, error| {
                                            field.child(field_error(
                                                "token-editor-symbol-error",
                                                error,
                                                cx,
                                            ))
                                        }),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .flex_1()
                                        .min_w(px(150.0))
                                        .child(div().text_sm().child("Decimals"))
                                        .child(
                                            app_input(&decimals, cx)
                                                .aria_label("Token decimals")
                                                .disabled(busy),
                                        )
                                        .when_some(errors.decimals.clone(), |field, error| {
                                            field.child(field_error(
                                                "token-editor-decimals-error",
                                                error,
                                                cx,
                                            ))
                                        }),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(div().text_sm().child("Token address"))
                                .child(
                                    app_input(&address, cx)
                                        .aria_label("Token address")
                                        .disabled(busy),
                                )
                                .when_some(errors.address.clone(), |field, error| {
                                    field.child(field_error(
                                        "token-editor-address-error",
                                        error,
                                        cx,
                                    ))
                                }),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(div().text_sm().child("Full name (optional)"))
                                .child(
                                    app_input(&name, cx)
                                        .aria_label("Full token name")
                                        .disabled(busy),
                                )
                                .when_some(errors.name.clone(), |field, error| {
                                    field.child(field_error(
                                        "token-editor-name-error",
                                        error,
                                        cx,
                                    ))
                                }),
                        )
                        .when_some(errors.form.clone(), |form, error| {
                            form.child(field_error("token-editor-form-error", error, cx))
                        }),
                )
                .footer(
                    h_flex()
                        .justify_end()
                        .gap_2()
                        .child(
                            app_button("cancel-add-token")
                                .label("Cancel")
                                .disabled(busy)
                                .on_click(move |_, window, cx| {
                                    let can_close = close_view
                                        .update(cx, |view, cx| {
                                            if view.token_editor_busy {
                                                return false;
                                            }
                                            view.token_editor_open = false;
                                            view.token_editor_errors =
                                                TokenEditorErrors::default();
                                            cx.notify();
                                            true
                                        })
                                        .unwrap_or(false);
                                    if can_close {
                                        window.close_dialog(cx);
                                    }
                                }),
                        )
                        .child(
                            app_button("confirm-add-token")
                                .label(if busy {
                                    "Authenticating…"
                                } else {
                                    "Authenticate & add"
                                })
                                .primary()
                                .loading(busy)
                                .disabled(busy)
                                .on_click(move |_, _, cx| {
                                    let _ = add_view.update(cx, |view, cx| {
                                        view.save_token_editor(cx);
                                    });
                                }),
                        ),
                )
        });
        chain_id_focus.update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    /// What the chain ID currently in the token form names, said back to the
    /// reader while they type it.
    ///
    /// The wallet knows every configured network by name, and the form asked
    /// for the number anyway and answered nothing — so adding a token meant
    /// remembering that Base is 8453, and a plausible wrong number that
    /// happened to be configured saved without complaint under the wrong
    /// network. An empty field says nothing, because a hint about a field
    /// nobody has filled in yet is noise.
    fn token_editor_chain_hint(&self, cx: &App) -> Option<SharedString> {
        let input = self.token_chain_id_input.as_ref()?;
        let typed = input.read(cx).value();
        let typed = typed.trim();
        if typed.is_empty() {
            return None;
        }
        let Ok(chain_id) = typed.parse::<u64>() else {
            return Some("Not a chain ID. Enter the network's decimal number.".into());
        };
        let configured = self
            .cached_networks()
            .ok()?
            .iter()
            .find(|network| network.chain_id == chain_id);
        Some(match configured {
            Some(network) if self.testnet_mode || !network.testnet => {
                network.display_label().to_owned().into()
            }
            // Configured, but hidden right now. Sending the reader to add it
            // would send them to a page where they cannot see it either, to
            // create a network that already exists. Saving already says this;
            // the field says it before the form is filled in.
            Some(_) => "Configured as a test network. Turn on testnet mode to use it.".into(),
            None => "No network configured here. Add it under Networks first.".into(),
        })
    }

    fn save_token_editor(&mut self, cx: &mut Context<Self>) {
        if self.token_editor_busy {
            return;
        }
        let Some(chain_id_input) = self.token_chain_id_input.as_ref() else {
            return;
        };
        let Some(address_input) = self.token_address_input.as_ref() else {
            return;
        };
        let Some(symbol_input) = self.token_symbol_input.as_ref() else {
            return;
        };
        let Some(name_input) = self.token_name_input.as_ref() else {
            return;
        };
        let Some(decimals_input) = self.token_decimals_input.as_ref() else {
            return;
        };
        let (token, mut errors) = parse_token_editor_fields(
            &chain_id_input.read(cx).value(),
            &address_input.read(cx).value(),
            &symbol_input.read(cx).value(),
            &name_input.read(cx).value(),
            &decimals_input.read(cx).value(),
        );
        let Some(token) = token else {
            self.token_editor_errors = errors;
            cx.notify();
            return;
        };
        match self.cached_networks() {
            Ok(networks)
                if networks.iter().any(|network| {
                    network.chain_id == token.chain_id && (self.testnet_mode || !network.testnet)
                }) => {}
            Ok(_) => {
                errors.chain_id = Some(
                    "Choose a chain ID currently visible in Networks. Enable testnet mode to add testnet tokens."
                        .to_owned(),
                );
                self.token_editor_errors = errors;
                cx.notify();
                return;
            }
            Err(error) => {
                errors.form = Some(format!("Could not validate the network: {error:#}"));
                self.token_editor_errors = errors;
                cx.notify();
                return;
            }
        }

        self.token_editor_errors = TokenEditorErrors::default();
        self.token_editor_busy = true;
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move { owner.add_token(token).await });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update_in(cx, |view, window, cx| {
                view.token_editor_busy = false;
                match result {
                    Ok(_) => {
                        view.token_editor_open = false;
                        window.close_dialog(cx);
                        view.reload_tokens(cx);
                        view.reload_desktop_snapshot(cx);
                    }
                    Err(error) => {
                        view.token_editor_errors.form =
                            Some(format!("Could not save token: {error:#}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn connect_walletconnect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(input) = self.walletconnect_uri_input.clone() else {
            return;
        };
        // The button renders disabled while a pairing is in flight, but a
        // render-time property is not what decides this: refuse the press
        // here, where the second click of a double click arrives.
        if self.walletconnect_connecting.is_some() {
            return;
        }
        match self.cached_accounts() {
            Ok([]) => {
                self.set_route_error(
                    Route::WalletConnect,
                    "Create an account before starting a WalletConnect pairing.",
                );
                cx.notify();
                return;
            }
            Err(error) => {
                self.set_route_error(
                    Route::WalletConnect,
                    format!("Could not verify a signing account: {error:#}"),
                );
                cx.notify();
                return;
            }
            Ok(_) => {}
        }
        let uri = Zeroizing::new(input.read(cx).value().trim().to_owned());
        if let Err(error) = self.begin_walletconnect_uri(&uri, cx) {
            self.set_route_error(
                Route::WalletConnect,
                format!("Could not connect: {error:#}"),
            );
            cx.notify();
            return;
        }
        input.update(cx, |input, cx| input.set_value("", window, cx));
    }

    fn begin_walletconnect_uri(&mut self, uri: &str, cx: &mut Context<Self>) -> Result<()> {
        match self.cached_accounts() {
            Ok([]) => anyhow::bail!("create an account before starting a WalletConnect pairing"),
            Err(error) => anyhow::bail!("could not verify a signing account: {error:#}"),
            Ok(_) => {}
        }
        let start = self
            .walletconnect
            .lock()
            .map_err(|_| anyhow::anyhow!("WalletConnect session state is unavailable"))?
            .begin_uri(uri)?
            .0;
        let session_id = start.id;
        self.walletconnect_connecting = Some(session_id);
        self.clear_route_error(Route::WalletConnect);
        self.owner
            .event_bus()
            .publish(crate::events::DomainEventKind::WalletConnectChanged {
                session_id: start.id.to_string(),
            });
        let owner = self.owner.clone();
        let presenter = self.walletconnect_presenter.clone();
        let manager = self.walletconnect.clone();
        let events = self.owner.event_bus();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || {
                tokio::runtime::Handle::current()
                    .block_on(run_session(start, owner, presenter, manager, events))
            })
            .await
            .context("WalletConnect session task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.finish_walletconnect_connecting(session_id);
                match result {
                    Ok(()) => view.clear_route_error(Route::WalletConnect),
                    Err(error) => view.set_route_error(
                        Route::WalletConnect,
                        format!("WalletConnect session failed: {error:#}"),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
        Ok(())
    }

    /// Stop showing Connect as busy, if it was busy on this pairing.
    ///
    /// Called from every way a pairing can stop being in flight, so a spinner
    /// cannot outlive the thing it describes.
    fn finish_walletconnect_connecting(&mut self, session_id: uuid::Uuid) {
        if self.walletconnect_connecting == Some(session_id) {
            self.walletconnect_connecting = None;
        }
    }

    /// Take a fresh session list, and let it settle the connect button.
    ///
    /// The list holds unsettled pairings too, which the connection list does
    /// not draw. They are what tells the button whether its pairing is still
    /// on its way: gone, or settled, means the wait is over.
    fn set_walletconnect_sessions(&mut self, sessions: Vec<SessionSummary>) {
        if self
            .walletconnect_connecting
            .is_some_and(|connecting| !walletconnect_pairing_is_in_flight(&sessions, connecting))
        {
            self.walletconnect_connecting = None;
        }
        self.walletconnect_sessions = sessions;
    }

    /// The dapps the owner let in — the only ones the connection list draws.
    fn approved_walletconnect_sessions(&self) -> impl Iterator<Item = &SessionSummary> {
        self.walletconnect_sessions
            .iter()
            .filter(|session| session.settled)
    }

    fn disconnect_walletconnect(&mut self, session_id: uuid::Uuid, cx: &mut Context<Self>) {
        let result = self
            .walletconnect
            .lock()
            .map_err(|_| anyhow::anyhow!("WalletConnect session state is unavailable"))
            .and_then(|mut manager| manager.disconnect(session_id).map(|_| ()));
        self.finish_walletconnect_connecting(session_id);
        match result {
            Ok(()) => self.clear_route_error(Route::WalletConnect),
            Err(error) => self.set_route_error(
                Route::WalletConnect,
                format!("Could not disconnect session: {error:#}"),
            ),
        }
        self.owner
            .event_bus()
            .publish(crate::events::DomainEventKind::WalletConnectChanged {
                session_id: session_id.to_string(),
            });
        cx.notify();
    }

    fn receive_walletconnect_prompt(&mut self, prompt: ProposalPrompt) {
        if !prompt
            .choices
            .iter()
            .all(|choice| self.review_document_is_visible(&choice.document))
        {
            self.queued_reviews
                .push(QueuedReview::WalletConnect(Box::new(prompt)));
            return;
        }
        let Some(QueuedReview::WalletConnect(prompt)) = self.queued_reviews.receive(
            self.legal_gate || self.active_review.is_some() || self.review_flow.is_in_progress(),
            QueuedReview::WalletConnect(Box::new(prompt)),
        ) else {
            return;
        };
        self.activate_walletconnect_prompt(*prompt);
    }

    fn activate_walletconnect_prompt(&mut self, prompt: ProposalPrompt) {
        // The connect button stays busy through the review rather than
        // stopping when the proposal lands: a proposal under review is not a
        // connection, and nothing else on the screen behind stands for it.
        // Both endings clear it — approving settles the session into the list
        // below, declining ends the pairing outright.
        self.active_review = Some(ActiveReview::new(
            prompt.unselected_document,
            None,
            Some(ActiveReviewCompletion::WalletConnect {
                choices: prompt.choices,
                selected_account: None,
                response: prompt.response,
            }),
        ));
    }

    fn activate_next_queued_review(&mut self) {
        if self.legal_gate || self.active_review.is_some() || self.review_flow.is_in_progress() {
            return;
        }
        let networks = self.cached_networks().unwrap_or_default().to_vec();
        let testnet_mode = self.testnet_mode;
        let next = self.queued_reviews.next_where(|review| match review {
            QueuedReview::Transaction(prompt) => {
                review_document_is_visible(&prompt.document, &networks, testnet_mode)
            }
            QueuedReview::WalletConnect(prompt) => prompt.choices.iter().all(|choice| {
                review_document_is_visible(&choice.document, &networks, testnet_mode)
            }),
        });
        match next {
            Some(QueuedReview::Transaction(prompt)) => self.activate_transaction_prompt(*prompt),
            Some(QueuedReview::WalletConnect(prompt)) => {
                self.activate_walletconnect_prompt(*prompt);
            }
            None => {}
        }
    }

    fn active_review_route(&self) -> Route {
        if self.active_review.as_ref().is_some_and(|active| {
            matches!(
                active.completion,
                Some(ActiveReviewCompletion::WalletConnect { .. })
            )
        }) {
            Route::WalletConnect
        } else {
            Route::Activity
        }
    }

    fn finish_review_flow(&mut self, cx: &mut Context<Self>) {
        self.review_flow = ReviewFlowState::Ready;
        self.activate_next_waiting_surface(cx);
    }

    /// Resume the owner's latest explicit notification navigation before an
    /// unsolicited queued prompt. If there is no click waiting, continue the
    /// ordinary serial review flow.
    fn activate_next_waiting_surface(&mut self, cx: &mut Context<Self>) {
        if self.legal_gate {
            return;
        }
        if self.activate_pending_notification(cx) {
            return;
        }
        self.activate_next_queued_review();
        if self.active_review.is_some() {
            let route = self.active_review_route();
            self.set_route(route);
        }
    }

    fn select_walletconnect_account(
        &mut self,
        generation: u64,
        index: usize,
        cx: &mut Context<Self>,
    ) {
        let Some(active) = self.active_review.as_mut() else {
            return;
        };
        if active.state.generation() != generation {
            return;
        }
        let Some(ActiveReviewCompletion::WalletConnect {
            choices,
            selected_account,
            ..
        }) = active.completion.as_mut()
        else {
            return;
        };
        let Some(choice) = choices.get(index) else {
            return;
        };
        *selected_account = Some(index);
        active.state = ReviewState::new(choice.document.clone());
        active.rebuild_detail_list();
        cx.notify();
    }

    /// A note that an account was created or imported, which then leaves.
    ///
    /// It used to stay for the life of the process: "Account primary was
    /// created." sat under the form while the reader went to Settings, set up
    /// an agent, came back, and read it again — about something the list
    /// directly below had been showing the whole time.
    fn set_account_status(&mut self, message: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.account_status_seq = self.account_status_seq.wrapping_add(1);
        let seq = self.account_status_seq;
        self.account_status = Some(message.into());
        cx.spawn(async move |view, cx| {
            cx.background_executor().timer(SUCCESS_NOTE_LIFETIME).await;
            let _ = view.update(cx, |view, cx| {
                if view.account_status_seq == seq {
                    view.account_status = None;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    fn set_account_entry_mode(&mut self, mode: AccountEntryMode, cx: &mut Context<Self>) {
        if self.account_operation.is_some() || self.account_entry_mode == mode {
            return;
        }
        self.account_entry_mode = mode;
        self.account_id_error = None;
        self.private_key_error = None;
        self.account_status = None;
        cx.notify();
    }

    fn set_inbox_tab(&mut self, tab: InboxTab, cx: &mut Context<Self>) {
        if self.inbox_tab == tab {
            return;
        }
        self.inbox_tab = tab;
        self.selected_record = None;
        self.route_scroll_handle
            .set_offset(gpui::point(px(0.0), px(0.0)));
        if tab == InboxTab::Decided {
            self.refresh_visible_pending_transactions(cx);
        }
        cx.notify();
    }

    fn create_account(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if self.account_operation.is_some() {
            return;
        }
        let Some(input) = self.account_id_input.as_ref() else {
            return;
        };
        let wallet_id = input.read(cx).value().trim().to_owned();
        self.account_id_error = None;
        self.private_key_error = None;
        if let Err(error) = ekubo_wallet_core::config::validate_wallet_id(&wallet_id) {
            self.account_id_error = Some(format!("{error:#}").into());
            cx.notify();
            return;
        }
        let owner = self.owner.clone();
        self.account_operation = Some(AccountOperation::Creating);
        self.account_status = None;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || {
                owner.create_account(&wallet_id, &WalletPolicy::require_approval_for_everything())
            })
            .await
            .context("account creation task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update_in(cx, |view, window, cx| {
                view.account_operation = None;
                match result {
                    Ok(account) => {
                        if let Some(input) = view.account_id_input.as_ref() {
                            input.update(cx, |input, cx| input.set_value("", window, cx));
                        }
                        view.account_action_errors.remove(&account.id);
                        view.set_account_status(format!("Account {} was created.", account.id), cx);
                        view.reload_desktop_snapshot(cx);
                        view.invalidate_portfolio();
                    }
                    Err(error) => {
                        view.account_id_error =
                            Some(format!("Could not create account: {error:#}").into());
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn import_account(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.account_operation.is_some() {
            return;
        }
        let (Some(id_input), Some(key_input)) = (
            self.account_id_input.as_ref(),
            self.private_key_input.as_ref(),
        ) else {
            return;
        };
        let wallet_id = id_input.read(cx).value().trim().to_owned();
        self.account_id_error = None;
        self.private_key_error = None;
        if let Err(error) = ekubo_wallet_core::config::validate_wallet_id(&wallet_id) {
            self.account_id_error = Some(format!("{error:#}").into());
            cx.notify();
            return;
        }
        let secret = zeroize::Zeroizing::new(key_input.read(cx).value().trim().to_owned());
        key_input.update(cx, |input, cx| {
            input.set_value("", window, cx);
            input.set_masked(true, window, cx);
        });
        let key = match PrivateKeyMaterial::from_hex(&secret) {
            Ok(key) => key,
            Err(error) => {
                self.private_key_error = Some(format!("{error:#}").into());
                cx.notify();
                return;
            }
        };
        let owner = self.owner.clone();
        self.account_operation = Some(AccountOperation::Importing);
        self.account_status = None;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || owner.import_account(&wallet_id, key))
                .await
                .context("account import task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update_in(cx, |view, window, cx| {
                view.account_operation = None;
                match result {
                    Ok(account) => {
                        if let Some(input) = view.account_id_input.as_ref() {
                            input.update(cx, |input, cx| input.set_value("", window, cx));
                        }
                        view.account_action_errors.remove(&account.id);
                        view.set_account_status(
                            format!("Account {} was imported.", account.id),
                            cx,
                        );
                        view.reload_desktop_snapshot(cx);
                        view.invalidate_portfolio();
                    }
                    Err(error) => {
                        view.account_id_error =
                            Some(format!("Could not import account: {error:#}").into());
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn begin_account_export(&mut self, wallet_id: String, cx: &mut Context<Self>) {
        self.account_export = Some(AccountExport {
            token: uuid::Uuid::new_v4(),
            wallet_id,
            lease: None,
            copied: false,
            authenticating: false,
            error: None,
        });
        cx.notify();
    }

    fn authenticate_account_export(&mut self, cx: &mut Context<Self>) {
        let Some(export) = self.account_export.as_mut() else {
            return;
        };
        if export.authenticating {
            return;
        }
        export.authenticating = true;
        export.error = None;
        let token = export.token;
        let wallet_id = export.wallet_id.clone();
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, {
            let wallet_id = wallet_id.clone();
            async move { owner.begin_private_key_export(&wallet_id).await }
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                match result {
                    Ok(lease) => {
                        if let Some(export) = view.account_export.as_mut()
                            && export.token == token
                        {
                            export.authenticating = false;
                            export.lease = Some(lease);
                            export.copied = false;
                            export.error = None;
                        }
                    }
                    Err(error) => {
                        if let Some(export) = view.account_export.as_mut()
                            && export.token == token
                        {
                            export.authenticating = false;
                            export.error =
                                Some(format!("Private-key export cancelled: {error:#}").into());
                        }
                    }
                }
                cx.notify();
            });
            // Re-render every second so the countdown moves and the panel
            // flips itself to "hidden" the moment the lease expires.
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                let revealed = view.update(cx, |view, cx| {
                    cx.notify();
                    let revealed = view
                        .account_export
                        .as_ref()
                        .and_then(|export| export.lease.as_ref())
                        .is_some_and(|lease| !lease.concealed());
                    if !revealed {
                        view.clear_export_clipboard(cx);
                    }
                    revealed
                });
                if !matches!(revealed, Ok(true)) {
                    break;
                }
            }
        })
        .detach();
        cx.notify();
    }

    fn copy_account_export(&mut self, cx: &mut Context<Self>) {
        self.clear_export_clipboard(cx);
        let Some(export) = self.account_export.as_mut() else {
            return;
        };
        let Some(value) = export.lease.as_ref().and_then(ExportLease::visible_value) else {
            export.error = Some("The private-key reveal has expired.".into());
            cx.notify();
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        if let Ok(mut clipboard) = self.export_clipboard.lock() {
            *clipboard = Some(value);
        }
        let remaining = export
            .lease
            .as_ref()
            .map_or(Duration::ZERO, ExportLease::remaining);
        export.copied = true;
        export.error = None;
        cx.spawn(async move |view, cx| {
            cx.background_executor().timer(Duration::from_secs(1)).await;
            let _ = view.update(cx, |view, cx| {
                if let Some(export) = view.account_export.as_mut() {
                    export.copied = false;
                }
                cx.notify();
            });
            cx.background_executor()
                .timer(remaining.saturating_sub(Duration::from_secs(1)))
                .await;
            let _ = view.update(cx, |view, cx| {
                view.clear_export_clipboard(cx);
            });
        })
        .detach();
        cx.notify();
    }

    fn clear_export_clipboard(&mut self, cx: &mut Context<Self>) {
        let Ok(mut stored) = self.export_clipboard.lock() else {
            return;
        };
        let Some(secret) = stored.as_ref() else {
            return;
        };
        if cx
            .read_from_clipboard()
            .and_then(|item| item.text())
            .as_deref()
            == Some(secret.as_str())
        {
            cx.write_to_clipboard(ClipboardItem::new_string(String::new()));
        }
        stored.take();
    }

    fn open_policy_editor(&mut self, wallet_id: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(input) = self.policy_json_input.as_ref() else {
            return;
        };
        self.policy_account_id = Some(wallet_id.to_owned());
        match self.owner.policy_history(wallet_id) {
            Ok(history) => {
                let current = history.last();
                let source_revision = current.map(|policy| policy.revision);
                let current_policy = current.map(|policy| policy.policy.clone());
                let history_selection = latest_policy_revision(history.len());
                let document = serde_json::to_string_pretty(
                    current_policy
                        .as_ref()
                        .unwrap_or(&WalletPolicy::require_approval_for_everything()),
                );
                match document {
                    Ok(document) => {
                        input.update(cx, |input, cx| {
                            input.set_value(document, window, cx);
                            input.set_selected_range(0..input.value().len(), cx);
                            input.focus(window, cx);
                        });
                        self.policy_editor = Some(PolicyEditor {
                            wallet_id: wallet_id.to_owned(),
                            source_revision,
                            current_policy,
                            history,
                            history_selection,
                            proposal: None,
                            validation: None,
                        });
                        self.policy_action_error = None;
                        self.policy_editor_anchor.scroll_to(window, cx);
                    }
                    Err(error) => {
                        self.policy_action_error =
                            Some(format!("Could not serialize policy: {error:#}").into());
                    }
                }
            }
            Err(error) => {
                self.policy_action_error = Some(format!("Could not read policy: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn open_policy_proposal(
        &mut self,
        proposal: PolicyProposal,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(input) = self.policy_json_input.as_ref() else {
            return;
        };
        self.policy_account_id = Some(proposal.wallet_id.clone());
        match self.owner.policy_history(&proposal.wallet_id) {
            Ok(history) => {
                // A proposal is not itself an installed revision. Its first
                // Previous revision action opens the latest installed policy.
                let history_selection = None;
                let current_policy = history.last().map(|policy| policy.policy.clone());
                let review = serde_json::to_string_pretty(&proposal.policy)
                    .context("could not serialize proposed policy")
                    .and_then(|document| {
                        review_policy_draft(
                            &proposal.wallet_id,
                            Some(proposal.source_revision),
                            current_policy.as_ref(),
                            &document,
                        )
                    });
                match review {
                    Ok(review) => {
                        input.update(cx, |input, cx| {
                            input.set_value(review.document.clone(), window, cx);
                        });
                        self.policy_editor = Some(PolicyEditor {
                            wallet_id: proposal.wallet_id.clone(),
                            source_revision: Some(proposal.source_revision),
                            current_policy,
                            history,
                            history_selection,
                            proposal: Some(proposal),
                            validation: Some(Ok(review)),
                        });
                        self.policy_action_error = None;
                    }
                    Err(error) => {
                        self.policy_action_error =
                            Some(format!("Could not prepare proposal review: {error:#}").into());
                    }
                }
            }
            Err(error) => {
                self.policy_action_error =
                    Some(format!("Could not read the active policy: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn view_previous_policy_revision(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_mut(), self.policy_json_input.as_ref())
        else {
            return;
        };
        let Some(target) = previous_policy_revision(editor.history_selection, editor.history.len())
        else {
            return;
        };
        match serde_json::to_string_pretty(&editor.history[target].policy) {
            Ok(document) => {
                input.update(cx, |input, cx| {
                    input.set_value(document, window, cx);
                });
                editor.history_selection = Some(target);
                editor.validation = None;
                self.policy_action_error = None;
            }
            Err(error) => {
                self.policy_action_error =
                    Some(format!("Could not display policy revision: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn reject_policy_proposal(&mut self, proposal: &PolicyProposal, cx: &mut Context<Self>) {
        self.policy_action_error = match self.owner.reject_policy_proposal(proposal) {
            Ok(true) => {
                if self
                    .policy_editor
                    .as_ref()
                    .and_then(|editor| editor.proposal.as_ref())
                    == Some(proposal)
                {
                    self.policy_editor = None;
                }
                None
            }
            Ok(false) => {
                Some("The proposal changed while it was open. Review the current one.".into())
            }
            Err(error) => Some(format!("Could not reject proposal: {error:#}").into()),
        };
        cx.notify();
    }

    fn apply_allow_anything_policy(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_mut(), self.policy_json_input.as_ref())
        else {
            return;
        };
        match allow_anything_policy_document() {
            Ok(document) => {
                input.update(cx, |input, cx| input.set_value(document, window, cx));
                editor.validation = None;
                self.policy_action_error = None;
            }
            Err(error) => {
                self.policy_action_error =
                    Some(format!("Could not prepare the allow-anything policy: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn apply_disable_signing_policy(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_mut(), self.policy_json_input.as_ref())
        else {
            return;
        };
        match disable_signing_policy_document() {
            Ok(document) => {
                input.update(cx, |input, cx| input.set_value(document, window, cx));
                editor.validation = None;
                self.policy_action_error = None;
            }
            Err(error) => {
                self.policy_action_error =
                    Some(format!("Could not prepare the disable-signing policy: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn reset_policy_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_mut(), self.policy_json_input.as_ref())
        else {
            return;
        };
        match serde_json::to_string_pretty(&WalletPolicy::require_approval_for_everything()) {
            Ok(document) => {
                input.update(cx, |input, cx| input.set_value(document, window, cx));
                editor.validation = None;
                self.policy_action_error = None;
            }
            Err(error) => {
                self.policy_action_error =
                    Some(format!("Could not prepare the reset policy: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn validate_policy_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_mut(), self.policy_json_input.as_ref())
        else {
            return;
        };
        let document = input.read(cx).value().to_string();
        let review = review_policy_draft(
            &editor.wallet_id,
            editor.source_revision,
            editor.current_policy.as_ref(),
            &document,
        );
        editor.validation = Some(match review {
            Ok(review) => {
                input.update(cx, |input, cx| {
                    input.set_value(review.document.clone(), window, cx);
                });
                self.policy_action_error = None;
                Ok(review)
            }
            Err(error) => {
                let message: SharedString = format!("Policy validation failed: {error:#}").into();
                Err(message)
            }
        });
        cx.notify();
    }

    fn install_policy_editor(&mut self, cx: &mut Context<Self>) {
        if self.policy_installing {
            return;
        }
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_ref(), self.policy_json_input.as_ref())
        else {
            return;
        };
        let Some(Ok(review)) = editor.validation.as_ref() else {
            self.policy_action_error =
                Some("Validate the policy and review its diff first.".into());
            cx.notify();
            return;
        };
        if input.read(cx).value().as_ref() != review.document {
            self.policy_action_error = Some(
                "The policy changed after validation. Validate it again before installing.".into(),
            );
            cx.notify();
            return;
        }
        let review = review.clone();
        let proposal = editor.proposal.clone();
        let owner = self.owner.clone();
        let proposal_is_exact = proposal.as_ref().is_some_and(|proposal| {
            proposal.wallet_id == review.wallet_id
                && Some(proposal.source_revision) == review.source_revision
                && proposal.policy == review.policy
        });
        let task_review = review.clone();
        let task_proposal = proposal.clone();
        self.policy_installing = true;
        self.policy_action_error = None;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            let installed = if proposal_is_exact {
                owner
                    .apply_policy_proposal(task_proposal.as_ref().expect("checked above"))
                    .await
            } else {
                owner
                    .install_policy(
                        &task_review.wallet_id,
                        &task_review.policy,
                        task_review.source_revision,
                    )
                    .await
            }?;
            let proposal_cleanup = if proposal_is_exact {
                Ok(None)
            } else {
                task_proposal
                    .as_ref()
                    .map(|proposal| owner.reject_policy_proposal(proposal))
                    .transpose()
            };
            Ok::<_, anyhow::Error>((installed, proposal_cleanup))
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.policy_installing = false;
                match result {
                    Ok((installed, proposal_cleanup)) => {
                        if let Some(editor) = view.policy_editor.as_mut()
                            && editor.wallet_id == review.wallet_id
                        {
                            editor.source_revision = Some(installed.revision);
                            editor.current_policy = Some(installed.policy.clone());
                            editor
                                .history
                                .retain(|policy| policy.revision != installed.revision);
                            editor.history.push(installed.clone());
                            editor.history.sort_by_key(|policy| policy.revision);
                            editor.history_selection = latest_policy_revision(editor.history.len());
                            editor.proposal = None;
                            editor.validation = None;
                        }
                        view.policy_action_error = proposal_cleanup.err().map(|error| {
                            format!(
                                "Installed policy revision {} for {}, but could not clear the superseded proposal: {error:#}",
                                installed.revision, review.wallet_id
                            )
                            .into()
                        });
                    }
                    Err(error) => {
                        view.policy_action_error =
                            Some(format!("Policy installation cancelled: {error:#}").into());
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn begin_account_removal(&mut self, wallet_id: String, cx: &mut Context<Self>) {
        if self.active_review.is_some() || self.review_flow.is_in_progress() {
            self.account_action_errors.insert(
                wallet_id,
                "Finish or close the current review first.".into(),
            );
            cx.notify();
            return;
        }
        match self.owner.account_removal_document(&wallet_id) {
            Ok(review) => {
                self.account_action_errors.remove(&wallet_id);
                self.active_review = Some(ActiveReview::new(
                    review.document,
                    None,
                    Some(ActiveReviewCompletion::AccountRemoval {
                        wallet: review.wallet,
                    }),
                ));
            }
            Err(error) => {
                self.account_action_errors.insert(
                    wallet_id,
                    format!("Could not prepare account removal: {error:#}").into(),
                );
            }
        }
        cx.notify();
    }

    fn open_legal_review(&mut self, document: LegalDocument, cx: &mut Context<Self>) {
        let (text, digest) = self.owner.legal_document(document);
        let status = self.owner.legal_status().ok();
        let acceptance_required = legal_review_requires_acceptance(document, status.as_ref());
        self.legal_review = Some(Self::new_legal_review(
            document,
            &text,
            digest,
            acceptance_required,
            cx,
        ));
        cx.notify();
    }

    fn new_legal_review(
        document: LegalDocument,
        text: &str,
        digest: String,
        acceptance_required: bool,
        _cx: &mut Context<Self>,
    ) -> LegalReview {
        let rows = legal_markdown_rows(text);
        LegalReview {
            document,
            digest,
            rows,
            scroll_handle: UniformListScrollHandle::new(),
            end_rendered: Arc::new(AtomicBool::new(false)),
            acceptance_required,
            scroll_check_scheduled: false,
            viewed_to_end: false,
            error: None,
        }
    }

    fn open_next_required_legal(&mut self, cx: &mut Context<Self>) {
        let document = match self.owner.legal_status() {
            Ok(status) => next_required_legal(&status),
            Err(_) => Some(LegalDocument::TermsOfService),
        };
        self.legal_gate = document.is_some();
        self.legal_review = document.map(|document| {
            let (text, digest) = self.owner.legal_document(document);
            Self::new_legal_review(document, &text, digest, true, cx)
        });
    }

    fn update_legal_scroll_state(&mut self, digest: &str, cx: &mut Context<Self>) {
        let Some(review) = self.legal_review.as_mut() else {
            return;
        };
        review.scroll_check_scheduled = false;
        if review.acceptance_required
            && review.digest == digest
            && !review.viewed_to_end
            && legal_list_reached_end(&review.scroll_handle, &review.end_rendered)
        {
            review.viewed_to_end = true;
            cx.notify();
        }
    }

    fn accept_legal(&mut self, cx: &mut Context<Self>) {
        let Some(review) = self.legal_review.as_ref() else {
            return;
        };
        if !review.acceptance_required
            || (!review.viewed_to_end
                && !legal_list_reached_end(&review.scroll_handle, &review.end_rendered))
        {
            return;
        }
        let document = review.document;
        match self.owner.accept_legal(document, &review.digest) {
            Ok(()) => {
                self.open_next_required_legal(cx);
                if !self.legal_gate {
                    self.activate_next_waiting_surface(cx);
                }
                // Acceptance is written straight to the legal store, which
                // raises no domain event, so nothing else was ever going to
                // refresh the snapshot. Settings reads its acceptance dates
                // from that snapshot and went on saying "Review required"
                // about a document the reader had just accepted.
                self.reload_desktop_snapshot(cx);
            }
            Err(error) => {
                if let Some(review) = self.legal_review.as_mut() {
                    review.error = Some(format!("Could not accept document: {error:#}").into());
                }
            }
        }
        cx.notify();
    }

    fn close_overlay(&mut self, cx: &mut Context<Self>) {
        if self.legal_review.is_some() && !self.legal_gate {
            self.legal_review = None;
            cx.notify();
        }
        // Escape dismisses the record detail. It is read-only, so unlike the
        // security review there is nothing to decide before leaving it.
        if self.selected_record.is_some() {
            self.selected_record = None;
            self.activate_next_waiting_surface(cx);
            cx.notify();
        }
        // Escape also closes the export panel. Leaving it open was the one
        // modal in the app that trapped focus with no keyboard way out, and
        // dropping the lease conceals the key sooner rather than later.
        if self.account_export.is_some() {
            self.clear_export_clipboard(cx);
            self.account_export = None;
            self.activate_next_waiting_surface(cx);
            cx.notify();
        }
    }

    fn set_detected_agent_installed(
        &mut self,
        kind: AgentKind,
        installed: bool,
        cx: &mut Context<Self>,
    ) {
        if self.agent_reinstall == AgentReinstallState::Running {
            return;
        }
        self.clear_route_error(Route::Settings);
        self.agent_reinstall = AgentReinstallState::Running;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || set_agent_installed(kind, installed))
                .await
                .context("agent configuration task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.agent_reinstall = AgentReinstallState::Idle;
                if let Err(error) = result {
                    view.set_route_error(
                        Route::Settings,
                        format!(
                            "Could not {} {}: {error:#}",
                            if installed {
                                "install for"
                            } else {
                                "remove from"
                            },
                            kind.label()
                        ),
                    );
                }
                view.reload_detected_agents(cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    /// The accounts list is background-cached and never depends on the
    /// portfolio read, so the selector keeps working — and keeps its label —
    /// while balances load, fail, or have never been fetched.
    fn portfolio_accounts(&self) -> &[WalletMetadata] {
        self.cached_accounts().unwrap_or_default()
    }

    fn selected_portfolio_account(&self) -> Option<&WalletMetadata> {
        let accounts = self.portfolio_accounts();
        accounts.get(clamped_portfolio_account_index(
            accounts.len(),
            self.portfolio_account_index,
        ))
    }

    fn refresh_portfolio(&mut self, cx: &mut Context<Self>) {
        if self.legal_gate || matches!(self.portfolio, PortfolioState::Loading) {
            return;
        }
        // Without a selected account there is nothing to read. Leaving the
        // state `Idle` lets the render-time trigger try again once the
        // background accounts snapshot arrives.
        let Some(wallet_id) = self
            .selected_portfolio_account()
            .map(|account| account.id.clone())
        else {
            return;
        };
        self.portfolio_generation = self.portfolio_generation.wrapping_add(1);
        let generation = self.portfolio_generation;
        self.portfolio = PortfolioState::Loading;
        let owner = self.owner.clone();
        let refreshed_account = wallet_id.clone();
        let task =
            gpui_tokio::Tokio::spawn_result(
                cx,
                async move { owner.portfolio(Some(&wallet_id)).await },
            );
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                if view.portfolio_generation != generation {
                    return;
                }
                view.portfolio = match result {
                    Ok(snapshot) => {
                        // Stamped where the read lands rather than where it
                        // starts, so both the age on screen and the interval
                        // that throttles the next read describe the balances
                        // rather than the intent to fetch them.
                        view.portfolio_refreshed_at
                            .insert(refreshed_account, chrono::Utc::now());
                        PortfolioState::Ready(snapshot)
                    }
                    Err(error) => PortfolioState::Failed(
                        format!("Could not load portfolio: {error:#}").into(),
                    ),
                };
                cx.notify();
            });
        })
        .detach();
    }

    /// When the balances shown for the focused account were read.
    fn focused_portfolio_refreshed_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        let account = self.selected_portfolio_account()?;
        self.portfolio_refreshed_at.get(&account.id).copied()
    }

    /// Read balances for the focused account unless a recent read still stands.
    ///
    /// This is the tab-open path, which is a navigation rather than a request
    /// for fresh data — so it defers to [`PORTFOLIO_REFRESH_INTERVAL`] where
    /// the header's Refresh button, being an explicit ask, does not.
    fn refresh_portfolio_if_stale(&mut self, cx: &mut Context<Self>) {
        // A reading from the future means the clock moved under us, which says
        // nothing about the balances. Comparing the signed difference keeps
        // that on the fresh side instead of reading on every tab open until
        // the clock catches up.
        let fresh = self
            .focused_portfolio_refreshed_at()
            .is_some_and(|refreshed_at| {
                chrono::Utc::now().signed_duration_since(refreshed_at) < PORTFOLIO_REFRESH_INTERVAL
            });
        if fresh {
            return;
        }
        self.refresh_portfolio(cx);
    }

    fn invalidate_portfolio(&mut self) {
        self.portfolio_generation = self.portfolio_generation.wrapping_add(1);
        self.portfolio = PortfolioState::Idle;
    }

    fn select_portfolio_account(&mut self, index: usize, cx: &mut Context<Self>) {
        let index = clamped_portfolio_account_index(self.portfolio_accounts().len(), index);
        if index == self.portfolio_account_index {
            return;
        }
        self.portfolio_account_index = index;
        // Balances are read one account at a time, so the shown snapshot
        // belongs to the account that was selected a moment ago.
        self.invalidate_portfolio();
        self.refresh_portfolio(cx);
        cx.notify();
    }

    fn current_network_editor_draft(&self, cx: &App) -> Option<NetworkEditorDraft> {
        Some(NetworkEditorDraft {
            name: self
                .network_name_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            display_name: self
                .network_display_name_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            aliases: self
                .network_aliases_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            chain_id: self
                .network_chain_id_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            rpc_urls: self
                .network_rpc_urls_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            native_currency_name: self
                .network_native_name_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            native_currency_symbol: self
                .network_native_symbol_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            native_currency_decimals: self
                .network_native_decimals_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            block_explorer_url: self
                .network_explorer_url_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            documentation_url: self
                .network_documentation_url_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
        })
    }

    fn open_new_network_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(focus) = self.network_chain_id_input.clone() else {
            return;
        };
        for input in [
            self.network_name_input.as_ref(),
            self.network_display_name_input.as_ref(),
            self.network_aliases_input.as_ref(),
            self.network_chain_id_input.as_ref(),
            self.network_rpc_urls_input.as_ref(),
            self.network_native_name_input.as_ref(),
            self.network_native_symbol_input.as_ref(),
            self.network_native_decimals_input.as_ref(),
            self.network_explorer_url_input.as_ref(),
            self.network_documentation_url_input.as_ref(),
        ] {
            replace_input_value(input, "", window, cx);
        }
        self.network_editor_open = true;
        self.network_editor_scroll_handle = ScrollHandle::new();
        self.network_editor_overflow_indicator
            .set_scroll_handle(self.network_editor_scroll_handle.clone());
        self.network_editor_original = None;
        self.network_editor_disabled = false;
        self.network_editor_testnet = false;
        self.network_editor_rpc_strategy = RpcStrategy::Ordered;
        self.network_editor_advanced_open = false;
        self.network_editor_errors = NetworkEditorErrors::default();
        Self::open_network_editor_modal(&focus, window, cx);
        cx.notify();
    }

    fn close_network_editor(&mut self, cx: &mut Context<Self>) {
        if self.network_editor_busy {
            return;
        }
        self.network_editor_open = false;
        self.network_editor_original = None;
        self.network_editor_errors = NetworkEditorErrors::default();
        self.activate_next_waiting_surface(cx);
        cx.notify();
    }

    /// Add and edit intentionally share this dialog. The prepared input state
    /// and `network_editor_original` determine which operation is performed.
    fn open_network_editor_modal(
        focus: &Entity<InputState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let focus = focus.clone();
        // Opening on the next frame ensures the dialog observes the freshly
        // populated edit state and avoids competing with the network card's
        // click dispatch.
        cx.on_next_frame(window, move |wallet, window, cx| {
            if !wallet.network_editor_open {
                return;
            }
            let view = cx.entity().downgrade();
            window.open_dialog(cx, move |dialog, window, cx| {
                Self::build_network_editor_dialog(dialog, &view, window, cx)
            });
            focus.update(cx, |input, cx| input.focus(window, cx));
        });
    }

    /// Lay the network editor into the dialog the component library hands it.
    ///
    /// Named rather than written inline in the `open_dialog` builder so a
    /// render test can draw the dialog itself. It cannot open one: `Root`
    /// installs a macOS hit-test forwarder over the platform window, which a
    /// test window does not have, so a test that opened the dialog the way a
    /// click does would abort before it drew anything.
    fn build_network_editor_dialog(
        dialog: Dialog,
        view: &WeakEntity<Self>,
        window: &mut Window,
        cx: &mut App,
    ) -> Dialog {
        let view = view.clone();
        let Some(entity) = view.upgrade() else {
            return dialog.title("Network").child("Network form unavailable.");
        };
        let metrics = network_editor_metrics(window.viewport_size());
        let (busy, editing, footer) = {
            let wallet = entity.read(cx);
            (
                wallet.network_editor_busy,
                wallet.network_editor_original.is_some(),
                wallet.render_network_editor_footer(&view),
            )
        };
        let on_close_view = view.clone();
        let on_ok_view = view.clone();
        dialog
            .w(metrics.width)
            .max_w(metrics.width)
            .margin_top(metrics.top)
            .max_h(metrics.max_height)
            .title(if editing {
                "Edit network"
            } else {
                "Add custom network"
            })
            .overlay_closable(!busy)
            .keyboard(!busy)
            .close_button(!busy)
            // Enter in a single-line input propagates to the dialog,
            // whose default confirmation closes it. That discarded a
            // filled-in form. Route it to the same save the footer
            // runs and never let it close the dialog itself: the save
            // task closes on success and leaves it open on failure so
            // the field errors are still on screen.
            .on_ok(move |_, _, cx| {
                let _ = on_ok_view.update(cx, |view, cx| {
                    view.save_network_editor(cx);
                });
                false
            })
            .on_close(move |_, _, cx| {
                let _ = on_close_view.update(cx, |view, cx| {
                    view.close_network_editor(cx);
                });
            })
            // `content` rather than `child`. A dialog's children are laid
            // into a scroll area of the library's own, which refuses to
            // shrink and scrolls the form under this dialog's footer
            // instead. `content` is a plain flex child, so the form's
            // height is the dialog's height until `max_height` stops it
            // and then, being allowed to shrink, the form gives the rest
            // back and scrolls in the space it has.
            .content({
                let view = view.clone();
                move |content, _, cx| {
                    let Some(entity) = view.upgrade() else {
                        return content;
                    };
                    let wallet = entity.read(cx);
                    // Without `min_h_0` the content container's automatic
                    // minimum height is its content's, and that is a floor no
                    // shrinking gets under: the form kept its full height and
                    // ran under the footer instead of scrolling.
                    content.min_h_0().child(
                        // Every box from here down is sized by the form and
                        // may shrink, and none of them is given a height.
                        // `flex_1` would set a flex basis of zero, which tells
                        // the dialog its body is nothing and collapses it to
                        // the minimum; a height of 100% measures zero against
                        // a parent that has none, which does the same.
                        // `flex_shrink` and `min_h_0` on each of them is what
                        // turns the excess into scrolling once `max_height`
                        // stops the dialog growing.
                        v_flex()
                            .relative()
                            .w_full()
                            .flex_shrink_1()
                            .min_h_0()
                            .debug_selector(|| "network-editor-body".to_owned())
                            .child(
                                // The pane has to shrink with the body: one
                                // still as tall as everything in it is not a
                                // viewport, and the form was cut off at the
                                // bottom of the dialog rather than scrolled
                                // inside it. `v_flex` above is load-bearing
                                // for that — a plain `div` displays as a
                                // block, whose children are not flex items and
                                // do not shrink, whatever is asked of them
                                // here.
                                div()
                                    .id("network-editor-scroll")
                                    .debug_selector(|| "network-editor-scroll".to_owned())
                                    .w_full()
                                    .flex_shrink_1()
                                    .min_h_0()
                                    .track_scroll(&wallet.network_editor_scroll_handle)
                                    .overflow_y_scroll()
                                    .child(wallet.render_network_editor_form(&view, cx)),
                            )
                            .child(wallet.network_editor_overflow_indicator.element()),
                    )
                }
            })
            .footer(footer)
    }

    fn set_network_editor_strategy(&mut self, strategy: RpcStrategy, cx: &mut Context<Self>) {
        self.network_editor_rpc_strategy = strategy;
        cx.notify();
    }

    fn edit_network(
        &mut self,
        network: &NetworkConfig,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(focus) = self.network_display_name_input.clone() else {
            return;
        };
        replace_input_value(
            self.network_name_input.as_ref(),
            network.name.clone(),
            window,
            cx,
        );
        replace_input_value(
            self.network_display_name_input.as_ref(),
            network.display_name.clone().unwrap_or_default(),
            window,
            cx,
        );
        replace_input_value(
            self.network_aliases_input.as_ref(),
            network.aliases.join(", "),
            window,
            cx,
        );
        replace_input_value(
            self.network_chain_id_input.as_ref(),
            network.chain_id.to_string(),
            window,
            cx,
        );
        replace_input_value(
            self.network_rpc_urls_input.as_ref(),
            rpc_urls_for_editor(&network.rpc_urls),
            window,
            cx,
        );
        replace_input_value(
            self.network_native_name_input.as_ref(),
            network
                .native_currency
                .as_ref()
                .map(|currency| currency.name.clone())
                .unwrap_or_default(),
            window,
            cx,
        );
        replace_input_value(
            self.network_native_symbol_input.as_ref(),
            network
                .native_currency
                .as_ref()
                .map(|currency| currency.symbol.clone())
                .unwrap_or_default(),
            window,
            cx,
        );
        replace_input_value(
            self.network_native_decimals_input.as_ref(),
            network
                .native_currency
                .as_ref()
                .map(|currency| currency.decimals.to_string())
                .unwrap_or_default(),
            window,
            cx,
        );
        replace_input_value(
            self.network_explorer_url_input.as_ref(),
            network
                .block_explorer_url
                .as_ref()
                .map(url::Url::to_string)
                .unwrap_or_default(),
            window,
            cx,
        );
        replace_input_value(
            self.network_documentation_url_input.as_ref(),
            network
                .documentation_url
                .as_ref()
                .map(url::Url::to_string)
                .unwrap_or_default(),
            window,
            cx,
        );
        self.network_editor_open = true;
        self.network_editor_scroll_handle = ScrollHandle::new();
        self.network_editor_overflow_indicator
            .set_scroll_handle(self.network_editor_scroll_handle.clone());
        self.network_editor_original = Some(network.clone());
        self.network_editor_disabled = network.disabled;
        self.network_editor_testnet = network.testnet;
        self.network_editor_rpc_strategy = network.rpc_strategy;
        self.network_editor_advanced_open = !network.aliases.is_empty();
        self.network_editor_errors = NetworkEditorErrors::default();
        focus.update(cx, |input, cx| {
            input.set_selected_range(0..input.value().len(), cx);
        });
        Self::open_network_editor_modal(&focus, window, cx);
        cx.notify();
    }

    fn save_network_editor(&mut self, cx: &mut Context<Self>) {
        if self.network_editor_busy {
            return;
        }
        let Some(draft) = self.current_network_editor_draft(cx) else {
            return;
        };
        let (network, errors) = parse_network_editor_draft(
            &draft,
            self.network_editor_disabled,
            self.network_editor_testnet,
            self.network_editor_rpc_strategy,
            self.network_editor_original.as_ref().map_or(
                ekubo_wallet_core::config::DEFAULT_FINALITY_CONFIRMATIONS,
                |network| network.finality_confirmations,
            ),
        );
        // An error under a collapsed disclosure is invisible, so a rejected
        // save always reveals the field it is complaining about.
        self.network_editor_advanced_open |= errors.aliases.is_some();
        self.network_editor_errors = errors;
        let Some(network) = network else {
            cx.notify();
            return;
        };
        self.network_editor_busy = true;
        let owner = self.owner.clone();
        let original = self.network_editor_original.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            match original {
                Some(reviewed) => owner.replace_network(&reviewed, network).await,
                None => owner.add_network(network).await,
            }
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update_in(cx, |view, window, cx| {
                view.network_editor_busy = false;
                match result {
                    Ok(()) => {
                        view.network_editor_open = false;
                        view.network_editor_original = None;
                        view.network_editor_errors = NetworkEditorErrors::default();
                        window.close_dialog(cx);
                        view.reload_desktop_snapshot(cx);
                        view.activate_next_waiting_surface(cx);
                    }
                    Err(error) => {
                        view.network_editor_errors.form =
                            Some(format!("Network was not saved: {error:#}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn set_network_disabled(
        &mut self,
        reviewed: NetworkConfig,
        disabled: bool,
        cx: &mut Context<Self>,
    ) {
        let name = reviewed.name.clone();
        if !self.network_action_busy.insert(name.clone()) {
            return;
        }
        self.network_action_errors.remove(&name);
        let owner = self.owner.clone();
        let action_name = name.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.set_network_disabled(&reviewed, disabled).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.network_action_busy.remove(&action_name);
                match result {
                    Ok(updated) => {
                        // The write publishes `ConfigurationChanged`, so a
                        // reload is already on its way — but it is a capture of
                        // everything the wallet knows, and until it lands the
                        // page is drawing from a snapshot taken before the
                        // toggle. The card came out of its busy state saying
                        // Enabled about a network that had just been switched
                        // off. The one row that changed is known here, so it is
                        // written into the cached snapshot now and the reload
                        // reconciles the rest whenever it arrives.
                        view.apply_network_update(updated);
                        view.invalidate_portfolio();
                    }
                    Err(error) => {
                        view.network_action_errors.insert(
                            action_name,
                            format!("Could not update network: {error:#}").into(),
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    /// Write one network back into the snapshot the pages draw from.
    ///
    /// Networks are keyed by name — the same key `network_action_busy` uses —
    /// so a rename is a different network here and simply finds no row, which
    /// leaves the reload to do the work.
    fn apply_network_update(&mut self, updated: NetworkConfig) {
        let Some(snapshot) = self.desktop_snapshot.as_mut() else {
            return;
        };
        if let Ok(networks) = Arc::make_mut(snapshot).networks.as_mut()
            && let Some(slot) = networks
                .iter_mut()
                .find(|network| network.name == updated.name)
        {
            *slot = updated;
        }
    }

    fn accept_network_proposal(&mut self, proposal: NetworkConfig, cx: &mut Context<Self>) {
        if self.network_proposal_busy {
            return;
        }
        let owner = self.owner.clone();
        self.network_proposal_busy = true;
        self.network_proposal_error = None;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner
                .accept_network_proposal(&proposal)
                .await
                .map(|()| proposal)
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.network_proposal_busy = false;
                if let Err(error) = result {
                    view.network_proposal_error =
                        Some(format!("Network proposal was not installed: {error:#}").into());
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn reject_network_proposal(&mut self, proposal: &NetworkConfig, cx: &mut Context<Self>) {
        self.network_proposal_error = match self.owner.reject_network_proposal(proposal) {
            Ok(true) => None,
            Ok(false) => Some("The network proposal changed. Review the current profile.".into()),
            Err(error) => Some(format!("Could not reject network proposal: {error:#}").into()),
        };
        cx.notify();
    }

    fn review_token_proposal_group(
        &mut self,
        source: String,
        proposals: Vec<TokenProposal>,
        cx: &mut Context<Self>,
    ) {
        let Some(list) = self.token_proposal_list.as_ref() else {
            return;
        };
        list.update(cx, |list, cx| {
            list.delegate_mut().replace(source, proposals);
            cx.notify();
        });
        cx.notify();
    }

    fn toggle_token_list_import(&mut self, cx: &mut Context<Self>) {
        if self.token_import_state == TokenImportState::Fetching {
            return;
        }
        self.token_list_import_open = !self.token_list_import_open;
        self.token_import_error = None;
        cx.notify();
    }

    fn import_token_list_for_review(&mut self, cx: &mut Context<Self>) {
        if self.token_import_state == TokenImportState::Fetching {
            return;
        }
        let Some(input) = self.token_list_url_input.as_ref() else {
            return;
        };
        let url = match token_list_url_draft(input.read(cx).value().as_ref()) {
            Ok(url) => url,
            Err(error) => {
                self.token_import_error = Some(format!("{error:#}").into());
                self.token_import_status = None;
                cx.notify();
                return;
            }
        };
        let requested_chains: Vec<u64> = match self.cached_networks() {
            Ok(networks) => networks
                .iter()
                .filter(|network| !network.disabled && (self.testnet_mode || !network.testnet))
                .map(|network| network.chain_id)
                .collect(),
            Err(error) => {
                self.token_import_error =
                    Some(format!("Could not load visible networks: {error:#}").into());
                cx.notify();
                return;
            }
        };
        let owner = self.owner.clone();
        let proposal_list = self.token_proposal_list.clone();
        self.token_import_state = TokenImportState::Fetching;
        self.token_import_error = None;
        self.token_import_status = None;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner
                .import_token_list_for_review(&url, &requested_chains)
                .await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            if let Ok(imported) = &result
                && !imported.proposals.is_empty()
                && let Some(list) = proposal_list
            {
                let source = imported.source.clone();
                let proposals = imported.proposals.clone();
                list.update(cx, |list, cx| {
                    list.delegate_mut().replace(source, proposals);
                    cx.notify();
                });
            }
            let _ = view.update(cx, |view, cx| {
                view.token_import_state = TokenImportState::Idle;
                match result {
                    Ok(imported) => {
                        view.token_import_error = None;
                        let revision = imported
                            .declared_version
                            .as_deref()
                            .map_or_else(|| "version not declared".to_owned(), |version| {
                                format!("version {version}")
                            });
                        let timestamp = imported
                            .declared_timestamp
                            .as_deref()
                            .map_or_else(|| "timestamp not declared".to_owned(), |timestamp| {
                                format!("timestamp {timestamp}")
                            });
                        view.token_import_status = Some(
                            format!(
                                "Fetched {} from {} ({revision}; {timestamp}) for {} enabled network(s): {} awaiting review, {} already confirmed, {} skipped.",
                                imported.source,
                                imported.host,
                                imported.chains_selected.len(),
                                imported.summary.pending,
                                imported.summary.already_confirmed,
                                imported.skipped_non_evm + imported.skipped_other_chain,
                            )
                            .into(),
                        );
                    }
                    Err(error) => {
                        view.token_import_error = Some(format!("{error:#}").into());
                        view.token_import_status = None;
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn accept_token_proposal_group(&mut self, cx: &mut Context<Self>) {
        if self.token_proposal_busy {
            return;
        }
        let Some(list) = self.token_proposal_list.clone() else {
            return;
        };
        let (source, proposals, viewed_to_end) = {
            let delegate = list.read(cx).delegate();
            (
                delegate.source.clone(),
                delegate.proposals.clone(),
                delegate.viewed_to_end,
            )
        };
        let Some(_source) = source else {
            return;
        };
        if !viewed_to_end {
            self.token_proposal_error =
                Some("Scroll through the complete token proposal before accepting it.".into());
            cx.notify();
            return;
        }
        let owner = self.owner.clone();
        self.token_proposal_busy = true;
        self.token_proposal_error = None;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.accept_token_proposals(&proposals).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            if result.is_ok() {
                list.update(cx, |list, cx| {
                    list.delegate_mut().clear();
                    cx.notify();
                });
            }
            let _ = view.update(cx, |view, cx| {
                view.token_proposal_busy = false;
                view.token_proposal_error = result
                    .err()
                    .map(|error| format!("Token proposals were not accepted: {error:#}").into());
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn reject_token_proposal_group(&mut self, cx: &mut Context<Self>) {
        if self.token_proposal_busy {
            return;
        }
        let Some(list) = self.token_proposal_list.clone() else {
            return;
        };
        let (source, proposals) = {
            let delegate = list.read(cx).delegate();
            (delegate.source.clone(), delegate.proposals.clone())
        };
        let Some(_source) = source else {
            return;
        };
        let owner = self.owner.clone();
        self.token_proposal_busy = true;
        self.token_proposal_error = None;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || owner.reject_token_proposals(&proposals))
                .await
                .context("token proposal rejection task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            if result.is_ok() {
                list.update(cx, |list, cx| {
                    list.delegate_mut().clear();
                    cx.notify();
                });
            }
            let _ = view.update(cx, |view, cx| {
                view.token_proposal_busy = false;
                view.token_proposal_error = result
                    .err()
                    .map(|error| format!("Could not reject token proposals: {error:#}").into());
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn discard_unsent_transaction(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        let feedback = match self.owner.discard_unsent_transaction(request_id) {
            Ok(_) => ActivityFeedback::note("Discarded signed bytes that were never submitted."),
            Err(error) => {
                ActivityFeedback::failure(format!("Could not discard transaction: {error:#}"))
            }
        };
        self.set_activity_feedback(request_id, feedback, cx);
        self.selected_record = Some(request_id);
        cx.notify();
    }

    /// Put a note on a row, and take it back off when it has been read.
    ///
    /// Only the notes that report success expire. A failure is the row's whole
    /// account of what went wrong, and every action that could produce another
    /// one clears it on the way in, so it stays until the owner tries again.
    fn set_activity_feedback(
        &mut self,
        request_id: uuid::Uuid,
        mut feedback: ActivityFeedback,
        cx: &mut Context<Self>,
    ) {
        self.activity_feedback_seq += 1;
        let seq = self.activity_feedback_seq;
        feedback.seq = seq;
        let expiring = !feedback.error;
        self.activity_feedback.insert(request_id, feedback);
        if expiring {
            cx.spawn(async move |view, cx| {
                cx.background_executor().timer(SUCCESS_NOTE_LIFETIME).await;
                let _ = view.update(cx, |view, cx| {
                    // Only this note. A later press on the same row put its own
                    // note there, and that one has its own timer.
                    if view
                        .activity_feedback
                        .get(&request_id)
                        .is_some_and(|current| current.seq == seq)
                    {
                        view.activity_feedback.remove(&request_id);
                        cx.notify();
                    }
                });
            })
            .detach();
        }
        cx.notify();
    }

    fn toggle_activity_detail(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.selected_record = if self.selected_record == Some(request_id) {
            None
        } else {
            Some(request_id)
        };
        cx.notify();
    }

    fn inspect_transaction(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.selected_record == Some(request_id) {
            self.selected_record = None;
            cx.notify();
            return;
        }
        self.selected_record = Some(request_id);
        if self.activity_inspections.contains_key(&request_id) {
            cx.notify();
        } else {
            self.load_transaction_inspection(request_id, cx);
        }
    }

    fn load_transaction_inspection(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.activity_inspections
            .insert(request_id, ActivityInspectionState::Loading);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.transaction_inspection(request_id).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.activity_inspections.insert(
                    request_id,
                    match result {
                        Ok(inspection) => ActivityInspectionState::Ready(Rc::new(
                            ReadyActivityInspection::new(inspection),
                        )),
                        Err(error) => ActivityInspectionState::Failed(
                            format!("Could not inspect transaction: {error:#}").into(),
                        ),
                    },
                );
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn synchronize_transaction_activity(
        &mut self,
        request_id: uuid::Uuid,
        updated: Option<PendingTransaction>,
        cx: &mut Context<Self>,
    ) {
        if let Some(updated) = updated
            && let Some(snapshot) = self.desktop_snapshot.as_mut()
            && let Ok(activity) = &mut Arc::make_mut(snapshot).activity
            && let Some(record) = Arc::make_mut(activity).iter_mut().find(|record| {
                matches!(
                    record,
                    OwnerActivityRecord::Transaction(existing)
                        if existing.request_id == request_id
                )
            })
        {
            *record = OwnerActivityRecord::Transaction(Box::new(updated));
        }
        self.activity_inspections.remove(&request_id);
        if self.selected_record == Some(request_id) {
            self.load_transaction_inspection(request_id, cx);
        }
        // An action may persist a terminal status and then return an error
        // (notably cancellation discovering that the original already mined),
        // so reload on every outcome rather than only on a domain event.
        self.reload_desktop_snapshot(cx);
    }

    fn refresh_visible_pending_transactions(&mut self, cx: &mut Context<Self>) {
        if self.route != Route::Activity
            || self.inbox_tab != InboxTab::Decided
            || self.legal_gate
            || self.active_review.is_some()
        {
            return;
        }
        let Ok(records) = self.cached_activity_records() else {
            return;
        };
        let request_ids = records
            .iter()
            .filter_map(|record| match record {
                OwnerActivityRecord::Transaction(record)
                    if transaction_needs_status_refresh(record)
                        && self.chain_id_is_visible(record.chain_id.parse().ok()) =>
                {
                    Some(record.request_id)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for request_id in request_ids {
            self.refresh_transaction(request_id, cx);
        }
    }

    fn refresh_transaction(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if !self.activity_busy.insert(request_id) {
            return;
        }
        self.activity_refreshing.insert(request_id);
        self.activity_feedback.remove(&request_id);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.refresh_transaction(request_id).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.activity_busy.remove(&request_id);
                view.activity_refreshing.remove(&request_id);
                let updated = result.as_ref().ok().cloned();
                view.synchronize_transaction_activity(request_id, updated, cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn rebroadcast_transaction(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if !self.activity_busy.insert(request_id) {
            return;
        }
        self.activity_feedback.remove(&request_id);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.rebroadcast_transaction(request_id).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.activity_busy.remove(&request_id);
                view.selected_record = Some(request_id);
                let updated = result.as_ref().ok().map(|action| action.record.clone());
                let feedback = match result {
                    Ok(action) => match action
                        .broadcast
                        .as_ref()
                        .and_then(|broadcast| broadcast.broadcast_error.as_deref())
                    {
                        Some(error) => ActivityFeedback::failure(format!(
                            "No endpoint accepted the exact signed bytes: {error}"
                        )),
                        None => ActivityFeedback::note(format!(
                            "Nothing new was sent. {}",
                            action.record.status.explanation()
                        )),
                    },
                    Err(error) => ActivityFeedback::failure(format!(
                        "Could not send exact signed bytes: {error:#}"
                    )),
                };
                view.set_activity_feedback(request_id, feedback, cx);
                view.synchronize_transaction_activity(request_id, updated, cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn confirm_transaction_cancellation(
        &mut self,
        request_id: uuid::Uuid,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.activity_busy.contains(&request_id) {
            return;
        }
        let view = cx.entity().downgrade();
        window.open_alert_dialog(cx, move |alert, _, _| {
            let view = view.clone();
            alert
                .title("Attempt transaction cancellation?")
                .description(
                    "The wallet will sign and broadcast a 0-value self-send at the same nonce. It costs gas, and the original transaction may still win the race.",
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("Attempt cancellation")
                        .ok_variant(ButtonVariant::Danger)
                        .cancel_text("Keep transaction")
                        .show_cancel(true),
                )
                .on_ok(move |_, _, cx| {
                    let _ = view.update(cx, |view, cx| {
                        view.attempt_transaction_cancellation(request_id, cx);
                    });
                    true
                })
        });
    }

    fn attempt_transaction_cancellation(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if !self.activity_busy.insert(request_id) {
            return;
        }
        self.activity_feedback.remove(&request_id);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.attempt_transaction_cancellation(request_id).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.activity_busy.remove(&request_id);
                view.selected_record = Some(request_id);
                let updated = result.as_ref().ok().map(|action| action.record.clone());
                let feedback = match result {
                    Ok(action) => match action
                        .broadcast
                        .as_ref()
                        .and_then(|broadcast| broadcast.broadcast_error.as_deref())
                    {
                        Some(error) => ActivityFeedback::failure(format!(
                            "Cancellation broadcast was not accepted: {error}"
                        )),
                        None => ActivityFeedback::note(format!(
                            "No cancellation was needed. {}",
                            action.record.status.explanation()
                        )),
                    },
                    Err(error) => ActivityFeedback::failure(format!(
                        "Could not cancel transaction: {error:#}"
                    )),
                };
                view.set_activity_feedback(request_id, feedback, cx);
                view.synchronize_transaction_activity(request_id, updated, cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    /// Ask before forgetting the list, in the words of what is actually lost.
    ///
    /// Deleting local history is not a chain action and undoes nothing that
    /// was sent — but it is the only record this wallet keeps of what its
    /// agents asked it to do, and there is no copy anywhere else.
    fn confirm_activity_history_clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.history_clearing {
            return;
        }
        let view = cx.entity().downgrade();
        window.open_alert_dialog(cx, move |alert, _, _| {
            let view = view.clone();
            alert
                .title("Clear decided history?")
                .description(
                    "Every record this wallet has finished with is deleted from this machine: sent, confirmed, reverted, rejected, and cancelled — for every account, including networks this window is not showing. Anything still waiting on you, or still able to reach the chain, stays. Nothing on chain changes, and deleted records cannot be brought back.",
                )
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("Clear history")
                        .ok_variant(ButtonVariant::Danger)
                        .cancel_text("Keep history")
                        .show_cancel(true),
                )
                .on_ok(move |_, _, cx| {
                    let _ = view.update(cx, |view, cx| {
                        view.clear_activity_history(cx);
                    });
                    true
                })
        });
    }

    fn clear_activity_history(&mut self, cx: &mut Context<Self>) {
        if self.history_clearing {
            return;
        }
        self.history_clearing = true;
        self.history_clear_error = None;
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || owner.clear_activity_history())
                .await
                .context("history clearing task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.history_clearing = false;
                match result {
                    Ok(_) => {
                        // The emptied list is the entire report, so there is no
                        // note to leave about it. What has to go is the view
                        // state keyed by records that no longer exist: notes on
                        // rows nobody can see, receipts fetched for them, and a
                        // selection whose detail would open onto nothing.
                        view.activity_feedback.clear();
                        view.activity_inspections.clear();
                        view.activity_payloads_expanded.clear();
                        view.selected_record = None;
                    }
                    Err(error) => {
                        view.history_clear_error =
                            Some(format!("History could not be cleared: {error:#}").into());
                    }
                }
                view.reload_desktop_snapshot(cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn check_latest_release(&mut self, cx: &mut Context<Self>) {
        if matches!(self.release_state, ReleaseDisplayState::Checking) {
            return;
        }
        self.release_state = ReleaseDisplayState::Checking;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            let check = crate::release_check::check().await;
            let update = if check.update_available && !crate::UPDATER_PUBLIC_KEY.is_empty() {
                tokio::task::spawn_blocking(crate::release_check::check_installable)
                    .await
                    .context("signed updater task failed")??
            } else {
                None
            };
            Ok::<_, anyhow::Error>((check, update))
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.release_state = match result {
                    Ok((check, update)) => ReleaseDisplayState::Ready {
                        check,
                        update: update.map(Box::new),
                    },
                    Err(error) => ReleaseDisplayState::Failed(
                        format!("Could not check the latest release: {error:#}").into(),
                    ),
                };
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn confirm_update_installation(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ReleaseDisplayState::Ready {
            update: Some(update),
            ..
        } = &self.release_state
        else {
            return;
        };
        let version = update.version().to_owned();
        let view = cx.entity().downgrade();
        window.open_alert_dialog(cx, move |alert, _, _| {
            let view = view.clone();
            alert
                .title(format!("Install Ekubo Wallet {version}?"))
                .description(format!("Version {version}, published by Ekubo, Inc., will be downloaded and verified before the wallet closes. WalletConnect sessions will disconnect and the local MCP server will stop before installation."))
                .button_props(
                    DialogButtonProps::default()
                        .ok_text("Download & install")
                        .cancel_text("Not now")
                        .show_cancel(true),
                )
                .on_ok(move |_, _, cx| {
                    let _ = view.update(cx, WalletWindow::download_update);
                    true
                })
        });
    }

    fn download_update(&mut self, cx: &mut Context<Self>) {
        let ReleaseDisplayState::Ready {
            update: Some(update),
            ..
        } = &self.release_state
        else {
            return;
        };
        let update = update.as_ref().clone();
        let owner = self.owner.clone();
        self.release_state = ReleaseDisplayState::Downloading;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            let downloaded_update = update.clone();
            let prepared = tokio::task::spawn_blocking(move || downloaded_update.download())
                .await
                .context("update download task failed")??;
            let review = prepared.review();
            let authorization = owner.authorize_update_install(&review).await?;
            Ok::<_, anyhow::Error>(PreparedUpdate {
                prepared,
                authorization,
            })
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| match result {
                Ok(prepared) => {
                    if let Ok(mut slot) = view.pending_update.lock() {
                        *slot = Some(prepared);
                        let _ = crate::release_check::record_update_diagnostic(
                            &view.update_data_dir,
                            "verified update downloaded and authorized; requesting application shutdown",
                        );
                        cx.quit();
                    } else {
                        view.release_state = ReleaseDisplayState::Failed(
                            "Could not prepare the verified update for installation.".into(),
                        );
                        cx.notify();
                    }
                }
                Err(error) => {
                    view.release_state = ReleaseDisplayState::Failed(
                        format!("Could not download and verify the update: {error:#}").into(),
                    );
                    cx.notify();
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn receive_transaction_prompt(&mut self, prompt: GuiReviewPrompt) {
        if let Some(active) = self.active_review.as_mut()
            && active.awaiting_refresh
            && active.completion.is_none()
        {
            active.state.refresh(prompt.document);
            active.simulation = Some(Arc::new(prompt.simulation));
            active.completion = Some(ActiveReviewCompletion::Transaction(prompt.response));
            active.awaiting_refresh = false;
            active.rebuild_detail_list();
            return;
        }
        if !self.review_document_is_visible(&prompt.document) {
            self.queued_reviews
                .push(QueuedReview::Transaction(Box::new(prompt)));
            return;
        }
        if self.active_review.is_none() && self.review_flow.activate_transaction_prompt() {
            self.activate_transaction_prompt(prompt);
            return;
        }
        let Some(QueuedReview::Transaction(prompt)) = self.queued_reviews.receive(
            self.legal_gate || self.active_review.is_some() || self.review_flow.is_in_progress(),
            QueuedReview::Transaction(Box::new(prompt)),
        ) else {
            return;
        };
        self.activate_transaction_prompt(*prompt);
    }

    fn activate_transaction_prompt(&mut self, prompt: GuiReviewPrompt) {
        self.review_flow = ReviewFlowState::Busy;
        self.active_review = Some(ActiveReview::new(
            prompt.document,
            Some(prompt.simulation),
            Some(ActiveReviewCompletion::Transaction(prompt.response)),
        ));
    }

    fn begin_message_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.legal_gate || self.active_review.is_some() || self.review_flow.is_in_progress() {
            self.set_route_error(Route::Activity, "Finish or close the current review first.");
            cx.notify();
            return;
        }
        match self.owner.message_review_document(request_id) {
            Ok(document) => {
                let digest = document.request.digest.clone().unwrap_or_default();
                self.active_review = Some(ActiveReview::new(
                    document,
                    None,
                    Some(ActiveReviewCompletion::Message { request_id, digest }),
                ));
                self.clear_route_error(Route::Activity);
            }
            Err(error) => {
                self.set_route_error(
                    Route::Activity,
                    format!("Could not open message review: {error:#}"),
                );
            }
        }
        cx.notify();
    }

    fn begin_typed_data_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.legal_gate || self.active_review.is_some() || self.review_flow.is_in_progress() {
            self.set_route_error(Route::Activity, "Finish or close the current review first.");
            cx.notify();
            return;
        }
        match self.owner.typed_data_review_document(request_id) {
            Ok(document) => {
                let digest = document.request.digest.clone().unwrap_or_default();
                self.active_review = Some(ActiveReview::new(
                    document,
                    None,
                    Some(ActiveReviewCompletion::TypedData { request_id, digest }),
                ));
                self.clear_route_error(Route::Activity);
            }
            Err(error) => {
                self.set_route_error(
                    Route::Activity,
                    format!("Could not open typed-data review: {error:#}"),
                );
            }
        }
        cx.notify();
    }

    fn begin_transaction_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.legal_gate || self.active_review.is_some() || !self.review_flow.begin_transaction()
        {
            self.set_route_error(Route::Activity, "Finish or close the current review first.");
            cx.notify();
            return;
        }
        self.clear_route_error(Route::Activity);
        let owner = self.owner.clone();
        let presenter = self.review_presenter.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || {
                tokio::runtime::Handle::current()
                    .block_on(owner.review_transaction(request_id, &presenter))
            })
            .await
            .context("transaction review task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ =
                view.update(cx, |view, cx| {
                    if view.active_review.as_ref().is_some_and(|active| {
                        active.awaiting_refresh && active.completion.is_none()
                    }) {
                        view.active_review = None;
                    }
                    view.finish_review_flow(cx);
                    match result {
                        Ok(_) => view.clear_route_error(Route::Activity),
                        Err(error) if error.to_string().contains("closed without a decision") => {
                            view.clear_route_error(Route::Activity);
                        }
                        Err(error) => view
                            .set_route_error(Route::Activity, format!("Review failed: {error:#}")),
                    }
                    cx.notify();
                });
        })
        .detach();
        cx.notify();
    }

    fn update_review_scroll_state(&mut self, generation: u64, cx: &mut Context<Self>) {
        let Some(review) = self.active_review.as_mut() else {
            return;
        };
        if review.state.generation() != generation {
            return;
        }
        let max_offset = review.scroll_handle.max_offset_for_scrollbar().y;
        if review.scroll_last_max == Some(max_offset) {
            review.scroll_stable_samples = review.scroll_stable_samples.saturating_add(1);
        } else {
            review.scroll_last_max = Some(max_offset);
            review.scroll_stable_samples = 1;
        }
        if review.scroll_stable_samples < 2 {
            cx.notify();
            return;
        }
        if review.scroll_layout_ready
            && !review.state.approve_enabled()
            && review.end_rendered.load(Ordering::Acquire)
            && scroll_reached_end(
                review.scroll_handle.scroll_px_offset_for_scrollbar().y,
                max_offset,
            )
            && review.state.mark_viewed_to_end(generation)
        {
            cx.notify();
        }
    }

    fn send_review_command(
        &mut self,
        generation: u64,
        command: GuiReviewCommand,
        cx: &mut Context<Self>,
    ) {
        let Some(active) = self.active_review.as_mut() else {
            return;
        };
        if active.state.generation() != generation {
            return;
        }
        let permitted = match command {
            GuiReviewCommand::Approve => {
                !self.legal_gate
                    && active.state.selected() == ReviewDecision::Approve
                    && active.state.approve_enabled()
                    && active.selection_is_complete()
            }
            GuiReviewCommand::Reject => active.state.selected() == ReviewDecision::Reject,
            GuiReviewCommand::Refresh | GuiReviewCommand::Close => true,
        };
        if !permitted {
            return;
        }
        let completion = active.completion.take();
        let owner = self.owner.clone();
        let mut wait_for_flow = false;
        match (command, completion) {
            (GuiReviewCommand::Refresh, Some(ActiveReviewCompletion::Transaction(response))) => {
                active.awaiting_refresh = true;
                if response.send(command).is_err() {
                    self.set_route_error(
                        Route::Activity,
                        "The review request is no longer active.",
                    );
                    self.active_review = None;
                }
            }
            (GuiReviewCommand::Close, Some(ActiveReviewCompletion::Transaction(response))) => {
                wait_for_flow = true;
                let _ = response.send(command);
                self.active_review = None;
            }
            (
                GuiReviewCommand::Approve | GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::Transaction(response)),
            ) => {
                wait_for_flow = true;
                if response.send(command).is_err() {
                    self.set_route_error(
                        Route::Activity,
                        "The review request is no longer active.",
                    );
                }
                self.active_review = None;
            }
            (
                GuiReviewCommand::Close,
                Some(
                    ActiveReviewCompletion::Message { .. }
                    | ActiveReviewCompletion::TypedData { .. },
                ),
            ) => {
                self.active_review = None;
                self.clear_route_error(Route::Activity);
            }
            (
                GuiReviewCommand::Close | GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::AccountRemoval { wallet }),
            ) => {
                self.active_review = None;
                self.account_action_errors.remove(&wallet.id);
            }
            (
                GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::Message { request_id, .. }),
            ) => {
                self.active_review = None;
                match owner.reject_message(request_id) {
                    Ok(_) => self.clear_route_error(Route::Activity),
                    Err(error) => self.set_route_error(
                        Route::Activity,
                        format!("Could not reject message: {error:#}"),
                    ),
                }
            }
            (
                GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::TypedData { request_id, .. }),
            ) => {
                self.active_review = None;
                match owner.reject_typed_data(request_id) {
                    Ok(_) => self.clear_route_error(Route::Activity),
                    Err(error) => self.set_route_error(
                        Route::Activity,
                        format!("Could not reject typed data: {error:#}"),
                    ),
                }
            }
            (
                GuiReviewCommand::Approve,
                Some(ActiveReviewCompletion::Message { request_id, digest }),
            ) => {
                wait_for_flow = true;
                self.active_review = None;
                let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                    tokio::task::spawn_blocking(move || {
                        tokio::runtime::Handle::current()
                            .block_on(owner.sign_message(request_id, &digest))
                    })
                    .await
                    .context("message signing task failed")?
                });
                cx.spawn(async move |view, cx| {
                    let result = task.await;
                    let _ = view.update(cx, |view, cx| {
                        view.finish_review_flow(cx);
                        match result {
                            Ok(_) => view.clear_route_error(Route::Activity),
                            Err(error) => view.set_route_error(
                                Route::Activity,
                                format!("Message signing failed: {error:#}"),
                            ),
                        }
                        cx.notify();
                    });
                })
                .detach();
            }
            (
                GuiReviewCommand::Approve,
                Some(ActiveReviewCompletion::TypedData { request_id, digest }),
            ) => {
                wait_for_flow = true;
                self.active_review = None;
                let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                    tokio::task::spawn_blocking(move || {
                        tokio::runtime::Handle::current()
                            .block_on(owner.sign_typed_data(request_id, &digest))
                    })
                    .await
                    .context("typed-data signing task failed")?
                });
                cx.spawn(async move |view, cx| {
                    let result = task.await;
                    let _ = view.update(cx, |view, cx| {
                        view.finish_review_flow(cx);
                        match result {
                            Ok(_) => view.clear_route_error(Route::Activity),
                            Err(error) => view.set_route_error(
                                Route::Activity,
                                format!("Typed-data signing failed: {error:#}"),
                            ),
                        }
                        cx.notify();
                    });
                })
                .detach();
            }
            (
                GuiReviewCommand::Approve,
                Some(ActiveReviewCompletion::AccountRemoval { wallet }),
            ) => {
                wait_for_flow = true;
                self.active_review = None;
                let wallet_id = wallet.id.clone();
                let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                    owner.remove_account(&wallet).await
                });
                cx.spawn(async move |view, cx| {
                    let result = task.await;
                    let _ = view.update(cx, |view, cx| {
                        view.finish_review_flow(cx);
                        match result {
                            Ok(_) => {
                                view.account_action_errors.remove(&wallet_id);
                            }
                            Err(error) => {
                                view.account_action_errors.insert(
                                    wallet_id,
                                    format!("Could not remove account: {error:#}").into(),
                                );
                            }
                        }
                        cx.notify();
                    });
                })
                .detach();
            }
            (
                GuiReviewCommand::Approve,
                Some(ActiveReviewCompletion::WalletConnect {
                    choices,
                    selected_account,
                    response,
                }),
            ) => {
                wait_for_flow = true;
                self.active_review = None;
                let Some((index, choice)) = selected_account
                    .and_then(|index| choices.get(index).map(|choice| (index, choice)))
                else {
                    let _ = response.send(ProposalCommand::Reject);
                    self.set_route_error(
                        Route::WalletConnect,
                        "The selected account is no longer available.",
                    );
                    return;
                };
                let document = choice.document.clone();
                let account = choice.account.clone();
                let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                    owner.authorize_dapp_connection(&document, &account).await
                });
                cx.spawn(async move |view, cx| {
                    let result = task.await;
                    let _ = view.update(cx, |view, cx| {
                        view.finish_review_flow(cx);
                        match result {
                            Ok(authorization) => {
                                if response
                                    .send(ProposalCommand::Approve {
                                        index,
                                        authorization,
                                    })
                                    .is_err()
                                {
                                    view.set_route_error(
                                        Route::WalletConnect,
                                        "The connection proposal is no longer active.",
                                    );
                                } else {
                                    view.clear_route_error(Route::WalletConnect);
                                }
                            }
                            Err(error) => {
                                let _ = response.send(ProposalCommand::Reject);
                                view.set_route_error(
                                    Route::WalletConnect,
                                    format!("Dapp connection was not authorized: {error:#}"),
                                );
                            }
                        }
                        cx.notify();
                    });
                })
                .detach();
            }
            (
                GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::WalletConnect { response, .. }),
            ) => {
                self.active_review = None;
                let _ = response.send(ProposalCommand::Reject);
                self.clear_route_error(Route::WalletConnect);
            }
            (
                GuiReviewCommand::Close,
                Some(ActiveReviewCompletion::WalletConnect { response, .. }),
            ) => {
                self.active_review = None;
                let _ = response.send(ProposalCommand::Close);
                self.clear_route_error(Route::WalletConnect);
            }
            (GuiReviewCommand::Refresh, completion) => {
                active.completion = completion;
                self.set_route_error(
                    Route::Activity,
                    "Only transaction reviews can be re-simulated.",
                );
            }
            (_, None) => {
                self.set_route_error(Route::Activity, "The review request is no longer active.");
                self.active_review = None;
            }
        }
        if wait_for_flow {
            self.review_flow = ReviewFlowState::Busy;
        }
        self.activate_next_waiting_surface(cx);
        cx.notify();
    }

    fn toggle_palette(
        &mut self,
        _: &OpenCommandPalette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.legal_gate || self.network_editor_open {
            return;
        }
        self.command_palette = !self.command_palette;
        if self.command_palette
            && let Some(list) = self.command_palette_list.as_ref()
        {
            list.update(cx, |list, cx| list.focus(window, cx));
        }
        cx.notify();
    }

    fn set_route(&mut self, route: Route) {
        if self.network_editor_open && route != self.route {
            return;
        }
        if route != self.route {
            // The record detail belongs to the inbox. Leaving that screen with
            // it still open would strand a modal about a row nobody can see
            // over whichever page was asked for.
            self.selected_record = None;
            if self.route == Route::Policies {
                // Historical revisions are temporary views. Re-entering the
                // tab reconstructs the editor from core's latest installed
                // policy for the selected account.
                self.policy_editor = None;
                self.policy_action_error = None;
            }
        }
        reset_route_scroll_if_changed(self.route, route, &self.route_scroll_handle);
        self.route = route;
    }

    fn navigate_route(&mut self, route: Route, cx: &mut Context<Self>) {
        if self.legal_gate {
            return;
        }
        self.set_route(route);
        // Opening the tab is what asks for balances. The render-time trigger
        // below only fires on `Idle`, so without this a tab left on `Ready`
        // kept showing whatever was read the first time it was opened.
        if route == Route::Overview {
            self.refresh_portfolio_if_stale(cx);
        }
        if route == Route::Activity && self.inbox_tab == InboxTab::Decided {
            self.refresh_visible_pending_transactions(cx);
        }
        if route == Route::Settings && matches!(self.release_state, ReleaseDisplayState::Idle) {
            self.check_latest_release(cx);
        }
        self.command_palette = false;
        cx.notify();
    }

    fn notification_navigation_blocked(&self) -> bool {
        self.legal_gate
            || self.active_review.is_some()
            || self.review_flow.is_in_progress()
            || self.account_export.is_some()
            || self.token_editor_open
            || self.network_editor_open
    }

    fn take_pending_notification_route(&mut self) -> Option<NotificationRoute> {
        let blocked = self.notification_navigation_blocked();
        self.notification_navigation.take(blocked)
    }

    /// Open the latest notification click once no decision or editor owns the
    /// window. Returns whether an intent was consumed.
    fn activate_pending_notification(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(route) = self.take_pending_notification_route() else {
            return false;
        };
        // A read-only legal document is dismissible. Required legal review is
        // covered by `legal_gate` above and keeps the intent pending.
        self.legal_review = None;
        self.command_palette = false;
        self.set_route(Route::Activity);
        match route {
            NotificationRoute::Review(request_id) => {
                self.inbox_tab = InboxTab::Waiting;
                self.selected_record = None;
                self.begin_transaction_review(request_id, cx);
            }
            NotificationRoute::Activity(request_id) => {
                self.inbox_tab = InboxTab::Decided;
                self.selected_record = Some(request_id);
                if self.activity_inspections.contains_key(&request_id) {
                    cx.notify();
                } else {
                    self.load_transaction_inspection(request_id, cx);
                }
            }
        }
        cx.notify();
        true
    }

    fn open_notification(&mut self, route: NotificationRoute, cx: &mut Context<Self>) {
        // Navigation follows the most recent thing the owner explicitly
        // clicked. If another security surface owns the window, retain that
        // intent and resume it when the blocker finishes instead of silently
        // dropping it.
        self.notification_navigation.receive(route);
        self.activate_pending_notification(cx);
        cx.notify();
    }

    fn decide_review(&mut self, generation: u64, decision: ReviewDecision, cx: &mut Context<Self>) {
        let Some(active) = self.active_review.as_mut() else {
            return;
        };
        if !active.state.select(generation, decision) {
            return;
        }
        self.send_review_command(
            generation,
            match decision {
                ReviewDecision::Approve => GuiReviewCommand::Approve,
                ReviewDecision::Reject => GuiReviewCommand::Reject,
            },
            cx,
        );
    }

    fn set_appearance_preference(
        &mut self,
        preference: AppearancePreference,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.appearance_preference == preference {
            return;
        }
        match self.owner.set_appearance_preference(preference) {
            Ok(()) => {
                self.appearance_preference = preference;
                apply_appearance_preference(preference, Some(window), cx);
                if let Some(tray) = self.tray.borrow_mut().as_mut() {
                    tray.set_dark_mode(cx.theme().is_dark());
                }
                self.clear_route_error(Route::Settings);
            }
            Err(error) => self.set_route_error(
                Route::Settings,
                format!("Could not save appearance preference: {error:#}"),
            ),
        }
        cx.notify();
    }

    fn set_testnet_mode(&mut self, enabled: bool, cx: &mut Context<Self>) {
        if self.testnet_mode == enabled {
            return;
        }
        match self.owner.set_testnet_mode(enabled) {
            Ok(()) => {
                self.testnet_mode = enabled;
                self.invalidate_portfolio();
                if let Ok(networks) = self.cached_networks() {
                    let networks = networks.to_vec();
                    if let Some(list) = self.token_list.as_ref() {
                        list.update(cx, |list, cx| {
                            list.delegate_mut().replace_networks(&networks, enabled);
                            cx.notify();
                        });
                    }
                    if let Some(list) = self.token_proposal_list.as_ref() {
                        let visible = networks
                            .iter()
                            .filter(|network| enabled || !network.testnet)
                            .cloned()
                            .collect::<Vec<_>>();
                        list.update(cx, |list, cx| {
                            let delegate = list.delegate_mut();
                            delegate.replace_networks(&visible);
                            delegate.clear();
                            cx.notify();
                        });
                    }
                }
                if enabled {
                    self.activate_next_waiting_surface(cx);
                }
                self.clear_route_error(Route::Settings);
            }
            Err(error) => self.set_route_error(
                Route::Settings,
                format!("Could not save testnet mode: {error:#}"),
            ),
        }
        cx.notify();
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let pending_reviews = self
            .cached_reviews()
            .and_then(|queues| {
                Ok(review_queue_decision_count(
                    queues,
                    self.cached_networks()?,
                    self.testnet_mode,
                ))
            })
            .unwrap_or_default();
        // The mark identifies the application rather than any one screen, so
        // it sits above the rail instead of standing in for a tab's icon. That
        // also frees `Inbox` to carry the icon it has always had, and lets the
        // tab order change without moving the branding.
        let logo = if cx.theme().is_dark() {
            self.sidebar_logo_dark.clone()
        } else {
            self.sidebar_logo_light.clone()
        };
        let inbox_badge_color = if cx.theme().is_dark() {
            gpui::rgb(0x9f_22_1d).into()
        } else {
            cx.theme().red
        };
        let mut menu = div()
            .id("wallet-sidebar")
            .debug_selector(|| "wallet-sidebar".to_owned())
            .w(NAVIGATION_RAIL_WIDTH)
            .h_full()
            .flex_none()
            .overflow_y_scroll()
            .border_r_1()
            .border_color(cx.theme().sidebar_border)
            .bg(cx.theme().tokens.sidebar)
            .p_3()
            .flex()
            .flex_col()
            .items_center()
            .gap_2()
            .child(
                div()
                    .flex_none()
                    .mb_1()
                    .pb_2()
                    .w_full()
                    .flex()
                    .justify_center()
                    .border_b_1()
                    .border_color(cx.theme().sidebar_border)
                    .child(img(logo).w(px(36.0)).h(px(36.0))),
            );
        for route in Route::ALL {
            // The badge is the one thing on this rail that changes on its own,
            // and it was drawn for the eye alone: the button's tooltip and its
            // screen-reader name both said "Inbox" whether or not anything was
            // waiting in it.
            let waiting = (route == Route::Activity && pending_reviews > 0)
                .then(|| format!("{} waiting", pluralize(pending_reviews, "request")));
            let tooltip = match &waiting {
                Some(waiting) => format!("{} — {waiting}  {}", route.label(), route.shortcut()),
                None => format!("{}  {}", route.label(), route.shortcut()),
            };
            let button = app_button(SharedString::from(format!(
                "sidebar-route-{}",
                route.label()
            )))
            .w(NAVIGATION_BUTTON_SIZE)
            .h(NAVIGATION_BUTTON_SIZE)
            .ghost()
            .selected(route == self.route)
            .toggled(route == self.route)
            .disabled(self.legal_gate || self.network_editor_open)
            .on_click(cx.listener(move |this, _, _, cx| {
                this.navigate_route(route, cx);
            }))
            .child(Icon::new(route.icon()).size(px(30.0)));
            let button = accessible_button(
                button,
                match &waiting {
                    Some(waiting) => format!("{}, {waiting}", route.label()),
                    None => route.label().to_owned(),
                },
            );
            let count = if pending_reviews > 99 {
                "99+".to_owned()
            } else {
                pending_reviews.to_string()
            };
            let badge_width = if pending_reviews > 99 {
                px(30.0)
            } else {
                px(22.0)
            };
            let show_tooltip = self.sidebar_hovered_route == Some(route);
            let route_bounds = self
                .sidebar_route_bounds
                .get(&route)
                .expect("every sidebar route has a bounds cell")
                .clone();
            let tooltip_position = route_bounds.get().map(sidebar_tooltip_position);
            menu = menu.child(
                div()
                    .id(SharedString::from(format!(
                        "sidebar-route-wrapper-{}",
                        route.label()
                    )))
                    .relative()
                    .on_hover(cx.listener(move |view, hovered, _, cx| {
                        if *hovered {
                            view.sidebar_hovered_route = Some(route);
                        } else if view.sidebar_hovered_route == Some(route) {
                            view.sidebar_hovered_route = None;
                        }
                        cx.notify();
                    }))
                    .child(button)
                    .child(
                        canvas(
                            move |bounds, _, _| route_bounds.set(Some(bounds)),
                            |_, (), _, _| {},
                        )
                        .absolute()
                        .inset_0(),
                    )
                    .when(route == Route::Activity && pending_reviews > 0, |badge| {
                        badge.child(
                            div()
                                .id("inbox-review-badge")
                                .absolute()
                                .bottom(px(-3.0))
                                .right(px(-4.0))
                                .w(badge_width)
                                .h(px(22.0))
                                .flex()
                                .items_center()
                                .justify_center()
                                .rounded_full()
                                .border_2()
                                .border_color(cx.theme().sidebar)
                                .bg(inbox_badge_color)
                                .text_color(gpui_component::white())
                                .text_xs()
                                .font_semibold()
                                .child(count),
                        )
                    })
                    .when_some(
                        show_tooltip.then_some(tooltip_position).flatten(),
                        |wrapper, tooltip_position| {
                            wrapper.child(
                                deferred(
                                    anchored()
                                        .anchor(Anchor::LeftCenter)
                                        .snap_to_window_with_margin(px(8.0))
                                        .position(tooltip_position)
                                        .child(
                                            div()
                                                .whitespace_nowrap()
                                                .px_3()
                                                .py_1()
                                                .rounded(cx.theme().radius)
                                                .border_1()
                                                .border_color(cx.theme().primary.opacity(0.90))
                                                .bg(cx.theme().primary)
                                                .text_color(cx.theme().primary_foreground)
                                                .text_sm()
                                                .font_medium()
                                                .shadow_lg()
                                                .child(tooltip),
                                        ),
                                )
                                .with_priority(10),
                            )
                        },
                    ),
            );
        }
        menu
    }

    /// One waiting request: what it is, who asked and when, and the single
    /// button that acts on it. Every queue uses the same card so the section
    /// reads as one list rather than six differently-worded ones.
    fn render_review_card(
        id: &SharedString,
        title: &str,
        subtitle: &str,
        button: Button,
        cx: &App,
    ) -> gpui::Div {
        div()
            .w_full()
            .min_w_0()
            .max_w_full()
            .p_3()
            .border_1()
            .rounded(cx.theme().radius_lg)
            .border_color(cx.theme().border)
            .bg(cx.theme().secondary)
            .flex()
            .flex_wrap()
            .items_center()
            .justify_between()
            .gap_3()
            .child(
                div()
                    .min_w_0()
                    .flex_1()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        selectable_text(SharedString::from(format!("{id}-title")), title)
                            .font_medium()
                            .whitespace_normal(),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(
                                selectable_text(SharedString::from(format!("{id}-meta")), subtitle)
                                    .whitespace_normal(),
                            ),
                    ),
            )
            .child(button)
    }

    fn render_reviews(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div().flex().flex_col().gap_3();
        if self.review_flow == ReviewFlowState::Loading {
            content = content.child(
                h_flex()
                    .id("transaction-review-loading")
                    .gap_2()
                    .text_color(cx.theme().muted_foreground)
                    .child(Spinner::new().small())
                    .child(selectable_label("Opening the exact transaction review…")),
            );
        }
        let networks = self.network_display_names();
        let now = chrono::Utc::now();
        match self.cached_reviews() {
            Ok(queues) => {
                let total = self.cached_networks().map_or(0, |networks| {
                    review_queue_decision_count(queues, networks, self.testnet_mode)
                });
                if total > 0 {
                    content = content.child(selectable_label(format!(
                        "{} waiting for your decision. Nothing is signed or sent until you say so.",
                        pluralize(total, "request")
                    )));
                }
                for request in queues
                    .transactions
                    .iter()
                    .filter(|request| self.chain_id_is_visible(request.chain_id.parse().ok()))
                {
                    let request_id = request.request_id;
                    content = content.child(Self::render_review_card(
                        &SharedString::from(format!("review-transaction-{request_id}")),
                        &format!(
                            "Transaction on {}",
                            chain_label(request.chain_id.parse().ok(), &networks)
                        ),
                        &format!(
                            "{} · asked {}",
                            request.wallet_id,
                            relative_time_label(request.created_at, now)
                        ),
                        app_button(SharedString::from(format!(
                            "review-transaction-{request_id}"
                        )))
                        .label("Review")
                        .primary()
                        .disabled(self.review_flow.is_in_progress())
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.begin_transaction_review(request_id, cx);
                        })),
                        cx,
                    ));
                }
                for request in queues
                    .typed_data
                    .iter()
                    .filter(|request| self.chain_id_is_visible(request.chain_id.parse().ok()))
                {
                    let request_id = request.request_id;
                    content = content.child(Self::render_review_card(
                        &SharedString::from(format!("review-typed-data-{request_id}")),
                        &format!(
                            "Typed-data signature on {}",
                            chain_label(request.chain_id.parse().ok(), &networks)
                        ),
                        &format!(
                            "{} · {} · asked {}",
                            request.wallet_id,
                            request.requester.as_deref().unwrap_or("unnamed requester"),
                            relative_time_label(request.created_at, now)
                        ),
                        app_button(SharedString::from(format!(
                            "review-typed-data-{request_id}"
                        )))
                        .label("Review")
                        .primary()
                        // The same guard the transaction card above carries.
                        // Without it these two answered a press with an error
                        // telling the reader to finish the review that was
                        // already on the screen in front of them.
                        .disabled(self.review_flow.is_in_progress())
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.begin_typed_data_review(request_id, cx);
                        })),
                        cx,
                    ));
                }
                for request in queues.messages.iter().filter(|request| {
                    self.chain_id_is_visible(
                        request
                            .chain_id
                            .as_deref()
                            .and_then(|chain| chain.parse().ok()),
                    )
                }) {
                    let request_id = request.request_id;
                    content = content.child(Self::render_review_card(
                        &SharedString::from(format!("review-message-{request_id}")),
                        "Message signature",
                        &format!(
                            "{} · {} · asked {}",
                            request.wallet_id,
                            request.requester.as_deref().unwrap_or("unnamed requester"),
                            relative_time_label(request.created_at, now)
                        ),
                        app_button(SharedString::from(format!("review-message-{request_id}")))
                            .label("Review")
                            .primary()
                            .disabled(self.review_flow.is_in_progress())
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.begin_message_review(request_id, cx);
                            })),
                        cx,
                    ));
                }
                for proposal in &queues.policy_proposals {
                    let wallet_id = proposal.wallet_id.clone();
                    let proposal_wallet_id = wallet_id.clone();
                    content = content.child(Self::render_review_card(
                        &SharedString::from(format!("review-policy-{wallet_id}")),
                        &format!("Proposed policy change for {wallet_id}"),
                        &format!(
                            "An agent has suggested new signing rules, written against revision {}.",
                            proposal.source_revision
                        ),
                        app_button(SharedString::from(format!(
                            "open-policy-proposal-{wallet_id}"
                        )))
                        .label("Open Policies")
                        .primary()
                        .on_click(cx.listener(move |view, _, window, cx| {
                            view.set_route(Route::Policies);
                            view.open_policy_editor(&proposal_wallet_id, window, cx);
                            cx.notify();
                        })),
                        cx,
                    ));
                }
                for proposal in queues
                    .network_proposals
                    .iter()
                    .filter(|proposal| self.testnet_mode || !proposal.testnet)
                {
                    let chain_id = proposal.chain_id;
                    content = content.child(Self::render_review_card(
                        &SharedString::from(format!("review-network-{chain_id}")),
                        &format!("Proposed network: {}", proposal.name),
                        &format!(
                            "This wallet would start signing for chain {chain_id} once you accept it."
                        ),
                        app_button(SharedString::from(format!(
                            "open-network-proposal-{chain_id}"
                        )))
                        .label("Open Networks")
                        .primary()
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.set_route(Route::Networks);
                            cx.notify();
                        })),
                        cx,
                    ));
                }
                let mut token_groups = std::collections::BTreeMap::<String, usize>::new();
                for proposal in queues
                    .token_proposals
                    .iter()
                    .filter(|proposal| self.token_proposal_is_visible(proposal))
                {
                    *token_groups.entry(proposal.source.clone()).or_default() += 1;
                }
                for (index, (source, count)) in token_groups.into_iter().enumerate() {
                    content = content.child(Self::render_review_card(
                        &SharedString::from(format!("review-token-{index}")),
                        &format!("{} proposed by {source}", pluralize(count, "token name")),
                        "Accepting these only changes how amounts are described to you. It grants nothing.",
                        app_button(("open-token-proposal", index))
                            .label("Open Tokens")
                            .primary()
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_route(Route::Tokens);
                                cx.notify();
                            })),
                        cx,
                    ));
                }
                if total == 0 {
                    content = content.child(
                        div()
                            .p_5()
                            .rounded(cx.theme().radius_lg)
                            .border_1()
                            .border_color(cx.theme().border)
                            .bg(cx.theme().secondary)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .font_semibold()
                                    .child(selectable_label("Nothing needs you right now")),
                            )
                            .child(
                                div()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(selectable_label("When an agent or a dapp asks this wallet to sign or send something your policy will not decide on its own, it waits here.")),
                            ),
                    );
                }
            }
            Err(error) => {
                content = content.child(selectable_error_alert(
                    "review-queue-error",
                    format!("Waiting requests could not be read: {error:#}"),
                ));
            }
        }
        content
    }

    fn render_activity_detail_header(
        request_id: uuid::Uuid,
        title: &'static str,
        status: &'static str,
        tone: StatusTone,
        explanation: &'static str,
        meta: &str,
        cx: &App,
    ) -> gpui::Div {
        // Title, current state, and the one sentence that explains the state.
        // The request UUID is not here: it names the row to the wallet, not to
        // the reader, and it used to be the second line of every detail pane.
        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_2()
            // No Close button in here. This header scrolls with the rest of
            // the record, and a settled transaction's detail runs taller than
            // the window — so the only way out sat above the top of the
            // viewport for as long as anybody was reading. It lives in the
            // modal's fixed footer instead.
            .child(
                h_flex()
                    .w_full()
                    .min_w_0()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .child(
                        selectable_text(
                            SharedString::from(format!("activity-heading-{request_id}")),
                            title,
                        )
                        .text_lg()
                        .font_semibold(),
                    )
                    .child(status_pill(status, tone, cx)),
            )
            .child(
                selectable_text(
                    SharedString::from(format!("activity-heading-explanation-{request_id}")),
                    explanation,
                )
                .whitespace_normal()
                .text_color(cx.theme().muted_foreground),
            )
            .child(
                selectable_text(
                    SharedString::from(format!("activity-heading-meta-{request_id}")),
                    meta,
                )
                .whitespace_normal()
                .text_sm()
                .text_color(cx.theme().muted_foreground),
            )
    }

    fn render_ready_transaction_activity_detail(
        &self,
        item: &PendingTransaction,
        ready: &Rc<ReadyActivityInspection>,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let request_id = item.request_id;
        let meta = SharedString::from(format!(
            "{} · {} · requested {} · last changed {}",
            item.wallet_id,
            chain_label(item.chain_id.parse().ok(), &self.network_display_names()),
            absolute_time_label(item.created_at),
            relative_time_label(item.updated_at, chrono::Utc::now()),
        ));
        let explorer_url = item
            .broadcast_transaction_hash
            .as_ref()
            .or(item.signed_transaction_hash.as_ref())
            .and_then(|hash| {
                item.chain_id.parse::<u64>().ok().and_then(|chain_id| {
                    self.cached_networks().ok().and_then(|networks| {
                        block_explorer_transaction_url(networks, chain_id, hash)
                    })
                })
            });
        let status = transaction_record_label(item);
        let tone = transaction_record_tone(item);
        let explanation = transaction_record_explanation(item);
        let can_refresh = item.status.can_reach_a_chain();
        let receipt_loaded = ready.inspection.receipt_loaded;
        let rows = ready.detail_rows.borrow().clone();
        let ready = ready.clone();
        let list_state = ready.detail_list.clone();
        let editor = cx.entity().downgrade();
        let exact_payload_expanded = self
            .activity_payloads_expanded
            .contains(&(request_id, "execution-plan".to_owned()));

        variable_list(list_state.clone(), move |row_index, _, cx| {
            let Some(row) = rows.get(row_index).copied() else {
                return div().into_any_element();
            };
            let content = match row {
                TransactionActivityDetailRow::Prelude => {
                    let refresh_editor = editor.clone();
                    let mut buttons = div().flex().flex_wrap().gap_2();
                    if let Some(explorer_url) = explorer_url.clone() {
                        buttons = buttons.child(
                            app_button(SharedString::from(format!(
                                "open-transaction-explorer-{request_id}"
                            )))
                            .label("View on block explorer")
                            .on_click(move |_, _, cx| cx.open_url(&explorer_url)),
                        );
                    }
                    // Nothing to look for on a request that was never signed:
                    // there can be no receipt for the network to return.
                    if can_refresh {
                        buttons = buttons.child(
                            app_button(SharedString::from(format!(
                                "refresh-transaction-inspection-{request_id}"
                            )))
                            .label(if receipt_loaded {
                                "Check the network again"
                            } else {
                                "Look for a receipt"
                            })
                            .on_click(move |_, _, cx| {
                                let _ = refresh_editor.update(cx, |view, cx| {
                                    view.load_transaction_inspection(request_id, cx);
                                });
                            }),
                        );
                    }
                    div()
                        .w_full()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .child(Self::render_activity_detail_header(
                            request_id,
                            "Transaction",
                            status,
                            tone,
                            explanation,
                            &meta,
                            cx,
                        ))
                        .child(buttons)
                        .child(
                            selectable_text(
                                format!("transaction-inspection-summary-{request_id}"),
                                &ready.inspection.document.request.summary,
                            )
                            .text_color(cx.theme().muted_foreground)
                            .whitespace_normal(),
                        )
                        .into_any_element()
                }
                TransactionActivityDetailRow::Section(section_index) => {
                    let Some(section) = ready
                        .inspection
                        .document
                        .request
                        .sections
                        .get(section_index)
                    else {
                        return div().into_any_element();
                    };
                    Self::render_review_section(
                        section,
                        &format!("activity-{request_id}-{section_index}"),
                        cx,
                    )
                    .into_any_element()
                }
                TransactionActivityDetailRow::WarningsHeading => h_flex()
                    .gap_2()
                    .text_color(cx.theme().warning)
                    .child(Icon::new(IconName::TriangleAlert).small())
                    .child(div().font_semibold().child("Worth knowing"))
                    .into_any_element(),
                TransactionActivityDetailRow::Warning(warning_index) => {
                    let Some(warning) = ready
                        .inspection
                        .document
                        .request
                        .warnings
                        .get(warning_index)
                    else {
                        return div().into_any_element();
                    };
                    div()
                        .p_3()
                        .rounded(cx.theme().radius_lg)
                        .border_1()
                        .border_color(cx.theme().warning)
                        .child(selectable_text(
                            format!("activity-warning-{request_id}-{warning_index}"),
                            warning,
                        ))
                        .into_any_element()
                }
                TransactionActivityDetailRow::RecordKeeping => Self::render_review_section(
                    &ApprovalSection {
                        kind: ApprovalSectionKind::Details,
                        heading: "Record keeping".to_owned(),
                        facts: ready.inspection.document.request.facts.clone(),
                    },
                    &format!("activity-{request_id}-lifecycle"),
                    cx,
                )
                .into_any_element(),
                TransactionActivityDetailRow::ExactPayloadDisclosure => {
                    let Some(exact_plan) = ready.inspection.document.exact_payloads.first() else {
                        return div().into_any_element();
                    };
                    let copy_ready = ready.clone();
                    Self::render_exact_payload_block(
                        request_id,
                        "execution-plan",
                        "the exact execution plan",
                        exact_plan,
                        exact_payload_expanded,
                        editor.clone(),
                        false,
                        Some(Rc::new(move || {
                            copy_ready
                                .inspection
                                .document
                                .exact_payloads
                                .first()
                                .cloned()
                                .unwrap_or_default()
                        })),
                        cx,
                    )
                    .into_any_element()
                }
                TransactionActivityDetailRow::ExactPayloadChunk { start, end } => {
                    let Some(exact_plan) = ready.inspection.document.exact_payloads.first() else {
                        return div().into_any_element();
                    };
                    let Some(chunk) = exact_plan.get(start..end) else {
                        return div().into_any_element();
                    };
                    Self::render_exact_payload_chunk(
                        format!("activity-exact-payload-{request_id}-{start}"),
                        chunk,
                        cx,
                    )
                    .into_any_element()
                }
            };
            div()
                .w_full()
                .min_w_0()
                .pb_4()
                .child(content)
                .into_any_element()
        })
        .size_full()
        .pr_2()
        .into_any_element()
    }

    fn render_activity_detail(
        &self,
        record: &OwnerActivityRecord,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let request_id = record.request_id();
        match record {
            OwnerActivityRecord::Transaction(item) => {
                let mut detail = div()
                    .id(SharedString::from(format!("activity-detail-{request_id}")))
                    .w_full()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(Self::render_activity_detail_header(
                        request_id,
                        "Transaction",
                        transaction_record_label(item),
                        transaction_record_tone(item),
                        transaction_record_explanation(item),
                        &format!(
                            "{} · {} · requested {} · last changed {}",
                            item.wallet_id,
                            chain_label(item.chain_id.parse().ok(), &self.network_display_names()),
                            absolute_time_label(item.created_at),
                            relative_time_label(item.updated_at, chrono::Utc::now()),
                        ),
                        cx,
                    ));
                match self.activity_inspections.get(&request_id) {
                    Some(ActivityInspectionState::Loading) => {
                        detail = detail.child(
                            h_flex()
                                .gap_2()
                                .text_color(cx.theme().muted_foreground)
                                .child(Spinner::new())
                                .child(selectable_label(
                                    "Reading what this transaction did and checking the network for its receipt…",
                                )),
                        );
                    }
                    Some(ActivityInspectionState::Failed(error)) => {
                        detail =
                            detail
                                .child(selectable_error_alert(
                                    format!("transaction-inspection-error-{request_id}"),
                                    error.clone(),
                                ))
                                .child(
                                    app_button(SharedString::from(format!(
                                        "retry-transaction-inspection-{request_id}"
                                    )))
                                    .self_start()
                                    .label("Try again")
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.load_transaction_inspection(request_id, cx);
                                    })),
                                );
                    }
                    Some(ActivityInspectionState::Ready(inspection)) => {
                        return self.render_ready_transaction_activity_detail(item, inspection, cx);
                    }
                    None => {
                        detail = detail.child(
                            app_button(SharedString::from(format!(
                                "load-transaction-inspection-{request_id}"
                            )))
                            .self_start()
                            .label("Show what this transaction did")
                            .on_click(cx.listener(
                                move |view, _, _, cx| {
                                    view.load_transaction_inspection(request_id, cx);
                                },
                            )),
                        );
                    }
                }
                detail.into_any_element()
            }
            OwnerActivityRecord::Message(item) => {
                let document = self.cached_message_document(request_id);
                let networks = self.network_display_names();
                let mut facts = vec![
                    ("Account", item.wallet_id.clone()),
                    (
                        "Asked by",
                        item.requester
                            .clone()
                            .unwrap_or_else(|| "an unnamed requester".to_owned()),
                    ),
                    (
                        "Network",
                        chain_label(
                            item.chain_id
                                .as_deref()
                                .and_then(|chain| chain.parse().ok()),
                            &networks,
                        ),
                    ),
                    ("Requested", absolute_time_label(item.created_at)),
                ];
                if let Some(decided_at) = item.approved_at.or(item.rejected_at) {
                    facts.push((
                        if item.approved_at.is_some() {
                            "Approved"
                        } else {
                            "Rejected"
                        },
                        absolute_time_label(decided_at),
                    ));
                }
                let mut detail = div()
                    .id(SharedString::from(format!("activity-detail-{request_id}")))
                    .w_full()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(Self::render_activity_detail_header(
                        request_id,
                        "Message signature",
                        item.status.label(),
                        message_status_tone(item.status),
                        message_status_explanation(item.status),
                        &format!(
                            "{} · {}",
                            item.wallet_id,
                            relative_time_label(item.created_at, chrono::Utc::now())
                        ),
                        cx,
                    ))
                    .child(Self::render_fact_list(
                        "About this request",
                        &format!("activity-message-{request_id}"),
                        &facts,
                        cx,
                    ));
                if let Some(signature) = item.signature.as_ref() {
                    detail = detail.child(copyable_value(
                        format!("activity-message-signature-{request_id}"),
                        "Signature",
                        signature.clone(),
                    ));
                }
                detail = detail.child(copyable_value(
                    format!("activity-message-digest-{request_id}"),
                    digest_label(item.status == MessageStatus::Signed),
                    item.digest.clone(),
                ));
                match document {
                    Ok(document) => {
                        detail = detail.children(document.exact_payloads.iter().enumerate().map(
                            |(index, payload)| {
                                self.render_exact_payload(
                                    request_id,
                                    &format!("message-payload-{index}"),
                                    if item.status == MessageStatus::Signed {
                                        "the exact message that was signed"
                                    } else {
                                        "the exact message this would have signed"
                                    },
                                    payload,
                                    cx,
                                )
                            },
                        ));
                    }
                    Err(error) => {
                        detail = detail.child(div().text_color(cx.theme().danger).child(
                            selectable_text(
                                format!("message-payload-error-{request_id}"),
                                &format!("The exact message could not be read back: {error:#}"),
                            ),
                        ));
                    }
                }
                detail.into_any_element()
            }
            OwnerActivityRecord::TypedData(item) => {
                let document = self.cached_typed_data_document(request_id);
                let networks = self.network_display_names();
                let mut facts = vec![
                    ("Account", item.wallet_id.clone()),
                    (
                        "Asked by",
                        item.requester
                            .clone()
                            .unwrap_or_else(|| "an unnamed requester".to_owned()),
                    ),
                    (
                        "Network",
                        chain_label(item.chain_id.parse().ok(), &networks),
                    ),
                    ("Requested", absolute_time_label(item.created_at)),
                ];
                if let Some(decided_at) = item.approved_at.or(item.rejected_at) {
                    facts.push((
                        if item.approved_at.is_some() {
                            "Approved"
                        } else {
                            "Rejected"
                        },
                        absolute_time_label(decided_at),
                    ));
                }
                let mut detail = div()
                    .id(SharedString::from(format!("activity-detail-{request_id}")))
                    .w_full()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(Self::render_activity_detail_header(
                        request_id,
                        "Typed-data signature",
                        item.status.label(),
                        typed_data_status_tone(item.status),
                        typed_data_status_explanation(item.status),
                        &format!(
                            "{} · {}",
                            item.wallet_id,
                            relative_time_label(item.created_at, chrono::Utc::now())
                        ),
                        cx,
                    ))
                    .child(Self::render_fact_list(
                        "About this request",
                        &format!("activity-typed-data-{request_id}"),
                        &facts,
                        cx,
                    ));
                if let Some(signature) = item.signature.as_ref() {
                    detail = detail.child(copyable_value(
                        format!("activity-typed-data-signature-{request_id}"),
                        "Signature",
                        signature.clone(),
                    ));
                }
                detail = detail.child(copyable_value(
                    format!("activity-typed-data-digest-{request_id}"),
                    digest_label(item.status == TypedDataStatus::Signed),
                    item.digest.clone(),
                ));
                match document {
                    Ok(document) => {
                        detail = detail.children(document.exact_payloads.iter().enumerate().map(
                            |(index, payload)| {
                                self.render_exact_payload(
                                    request_id,
                                    &format!("typed-data-payload-{index}"),
                                    if item.status == TypedDataStatus::Signed {
                                        "the exact typed data that was signed"
                                    } else {
                                        "the exact typed data this would have signed"
                                    },
                                    payload,
                                    cx,
                                )
                            },
                        ));
                    }
                    Err(error) => {
                        detail = detail.child(div().text_color(cx.theme().danger).child(
                            selectable_text(
                                format!("typed-data-payload-error-{request_id}"),
                                &format!("The exact typed data could not be read back: {error:#}"),
                            ),
                        ));
                    }
                }
                detail.into_any_element()
            }
        }
    }

    /// The selected record's full account of itself, over the inbox.
    ///
    /// This used to expand inline, between the row it belonged to and the next
    /// one. A settled transaction's detail is taller than the window — effects,
    /// every decoded call, the fee, the bookkeeping — so opening one pushed the
    /// rest of the list out of sight and turned the inbox into a single record
    /// viewer. A modal keeps the list where it was and gives the detail the
    /// whole surface while it is open.
    fn render_activity_detail_overlay(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(request_id) = self.selected_record else {
            return div().into_any_element();
        };
        let Ok(records) = self.cached_activity_records() else {
            return div().into_any_element();
        };
        let Some(record) = records
            .iter()
            .find(|record| record.request_id() == request_id)
        else {
            // Unreachable in a settled frame: `render` drops a selection the
            // snapshot cannot account for before it gets here. Kept so a
            // record that leaves mid-frame draws nothing rather than panicking.
            return div().into_any_element();
        };
        let variable_detail_list = match record {
            OwnerActivityRecord::Transaction(_) => self
                .activity_inspections
                .get(&request_id)
                .and_then(|state| match state {
                    ActivityInspectionState::Ready(ready) => Some(ready.detail_list.clone()),
                    ActivityInspectionState::Loading | ActivityInspectionState::Failed(_) => None,
                }),
            OwnerActivityRecord::Message(_) | OwnerActivityRecord::TypedData(_) => None,
        };
        if self.activity_detail_record.get() != Some(request_id) {
            self.activity_detail_scroll_handle
                .set_offset(point(px(0.0), px(0.0)));
            if let Some(list) = &variable_detail_list {
                list.set_offset_from_scrollbar(point(px(0.0), px(0.0)));
            }
            self.activity_detail_record.set(Some(request_id));
        }
        if let Some(list) = &variable_detail_list {
            self.activity_detail_overflow_indicator
                .set_scroll_handle(list.clone());
        } else {
            self.activity_detail_overflow_indicator
                .set_scroll_handle(self.activity_detail_scroll_handle.clone());
        }
        let detail = self.render_activity_detail(record, cx);
        let detail_surface = if variable_detail_list.is_some() {
            div()
                .id(SharedString::from(format!(
                    "activity-detail-list-{request_id}"
                )))
                .size_full()
                .child(detail)
                .into_any_element()
        } else {
            div()
                .id(SharedString::from(format!(
                    "activity-detail-scroll-{request_id}"
                )))
                .size_full()
                .track_scroll(&self.activity_detail_scroll_handle)
                .pr_2()
                .overflow_y_scroll()
                .child(detail)
                .into_any_element()
        };
        div()
            .absolute()
            .inset_0()
            .flex()
            .items_center()
            .justify_center()
            // Dim the inbox rather than replace it: this is a detail about
            // something on the list behind it, and it stays visible as
            // context.
            .bg(cx.theme().background.opacity(0.85))
            // The scrim takes the mouse, so nothing behind it reacts: no press
            // aimed at the modal reaches a row underneath, and — the reason
            // this matters most here — the wheel no longer scrolls the inbox
            // out from under the receipt you are reading. An empty mouse-down
            // handler did not do this: it never stopped propagation, and the
            // page's scroll region only asks whether its own hitbox is under
            // the pointer, which it still was.
            .occlude()
            .p_4()
            .child(
                div()
                    .w_full()
                    .max_w(px(920.0))
                    .h_full()
                    .min_h_0()
                    .p_4()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().background)
                    .shadow_lg()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .relative()
                            .flex_1()
                            .min_h_0()
                            .child(detail_surface)
                            .child(self.activity_detail_overflow_indicator.element()),
                    )
                    // Fixed chrome, the way the security review's decision row
                    // is: the way out of a modal must not depend on how far
                    // through it you have read.
                    .child(
                        h_flex()
                            .w_full()
                            .flex_shrink_0()
                            .pt_3()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(selectable_label(
                                        "This is a record of what happened. Nothing here can be changed.",
                                    )),
                            )
                            .child(
                                app_button(SharedString::from(format!(
                                    "close-activity-detail-{request_id}"
                                )))
                                .label("Close")
                                .primary()
                                .on_click(cx.listener(|view, _, _, cx| {
                                    view.selected_record = None;
                                    view.activate_next_waiting_surface(cx);
                                    cx.notify();
                                })),
                            ),
                    ),
            )
            .focus_trap("activity-detail-focus", &self.modal_focus)
            .into_any_element()
    }

    /// A labelled key/value block, spelled the way the review sections are so
    /// the inbox reads as one surface rather than two.
    fn render_fact_list(
        heading: &'static str,
        id_prefix: &str,
        facts: &[(&'static str, String)],
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        Self::render_review_section(
            &ApprovalSection {
                kind: ApprovalSectionKind::Details,
                heading: heading.to_owned(),
                facts: facts
                    .iter()
                    .map(|(label, value)| ApprovalFact {
                        label: (*label).to_owned(),
                        value: value.clone(),
                    })
                    .collect(),
            },
            id_prefix,
            cx,
        )
    }

    /// The machine-exact bytes, behind a disclosure.
    ///
    /// They are evidence rather than explanation: somebody auditing a signature
    /// needs them verbatim, and everybody else needs them out of the way of the
    /// account of what happened.
    fn render_exact_payload(
        &self,
        request_id: uuid::Uuid,
        slot: &str,
        description: &'static str,
        payload: &str,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let key = (request_id, slot.to_owned());
        let expanded = self.activity_payloads_expanded.contains(&key);
        Self::render_exact_payload_block(
            request_id,
            slot,
            description,
            payload,
            expanded,
            cx.entity().downgrade(),
            true,
            None,
            cx,
        )
    }

    fn toggle_activity_payload(&mut self, key: &(uuid::Uuid, String), cx: &mut Context<Self>) {
        let expanded = if self.activity_payloads_expanded.remove(key) {
            false
        } else {
            self.activity_payloads_expanded.insert(key.clone());
            true
        };
        if key.1 == "execution-plan"
            && let Some(ActivityInspectionState::Ready(ready)) =
                self.activity_inspections.get(&key.0)
        {
            ready.set_exact_payload_expanded(expanded);
        }
        cx.notify();
    }

    fn render_exact_payload_chunk(id: impl Into<ElementId>, payload: &str, cx: &App) -> gpui::Div {
        div()
            .w_full()
            .min_w_0()
            .p_3()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().secondary)
            .child(selectable_code_text(id, payload))
    }

    #[allow(clippy::too_many_arguments)]
    fn render_exact_payload_block(
        request_id: uuid::Uuid,
        slot: &str,
        description: &'static str,
        payload: &str,
        expanded: bool,
        editor: WeakEntity<Self>,
        show_payload_inline: bool,
        copy_value: Option<Rc<dyn Fn() -> String>>,
        cx: &App,
    ) -> gpui::Div {
        let key = (request_id, slot.to_owned());
        let mut block = div().w_full().min_w_0().flex().flex_col().gap_2().child(
            h_flex()
                .w_full()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap_2()
                .child(
                    app_button(SharedString::from(format!(
                        "toggle-exact-payload-{request_id}-{slot}"
                    )))
                    .ghost()
                    .label(if expanded {
                        format!("Hide {description}")
                    } else {
                        format!("Show {description}")
                    })
                    .icon(if expanded {
                        IconName::ChevronDown
                    } else {
                        IconName::ChevronRight
                    })
                    .on_click(move |_, _, cx| {
                        let key = key.clone();
                        let _ = editor.update(cx, move |view, cx| {
                            view.toggle_activity_payload(&key, cx);
                        });
                    }),
                )
                .when(expanded, |row| {
                    let id = format!("copy-exact-payload-{request_id}-{slot}");
                    if let Some(copy_value) = copy_value {
                        row.child(lazy_copy_button(id, copy_value, "Copy"))
                    } else {
                        row.child(copy_button(id, payload.to_owned(), "Copy"))
                    }
                }),
        );
        if expanded && show_payload_inline {
            block = block.child(
                // No height cap and no scroll region of its own. Nested inside
                // the detail's scroll area, an inner one only swallowed the
                // wheel: the plan would not move and neither would the modal
                // under the pointer. The block runs to its full height and the
                // one scroll area that owns the surface carries it.
                Self::render_exact_payload_chunk(
                    format!("exact-payload-{request_id}-{slot}"),
                    payload,
                    cx,
                ),
            );
        }
        block
    }

    fn render_activity_history(&self, cx: &mut Context<Self>) -> gpui::Div {
        // No panel around the rows. The section's `GroupBox` is already a
        // bordered container, and wrapping a second one — same border, same
        // `secondary` fill as the cards inside it — drew a box around a box
        // around each row.
        let panel = div().w_full().flex().flex_col().gap_3();
        let records = match self.cached_activity_records() {
            Ok(records) => records,
            Err(error) => {
                return panel.child(selectable_error_alert(
                    "activity-history-error",
                    format!("This wallet's history could not be read: {error:#}"),
                ));
            }
        };
        let records = Arc::<[OwnerActivityRecord]>::from(
            records
                .iter()
                .filter(|record| {
                    !activity_record_is_awaiting_approval(record)
                        && self.chain_id_is_visible(activity_record_chain_id(record))
                })
                .cloned()
                .collect::<Vec<_>>(),
        );
        let items = records.as_ref();
        if items.is_empty() {
            return panel.child(
                // Same card as the "Waiting on you" empty state, so the two
                // halves of the inbox look like one screen.
                div()
                    .p_5()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().secondary)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .font_semibold()
                            .child(selectable_label("Nothing has happened yet")),
                    )
                    .child(div().text_color(cx.theme().muted_foreground).child(
                        selectable_label(
                            "Once this wallet signs or sends something, it stays here until you clear it — open any row to see what it did.",
                        ),
                    )),
            );
        }
        let selected_record = self.selected_record;
        let busy = Arc::new(self.activity_busy.clone());
        let refreshing = Arc::new(self.activity_refreshing.clone());
        let feedback = Arc::new(self.activity_feedback.clone());
        let no_sources = BTreeMap::new();
        let sources = self
            .snapshot()
            .map_or(&no_sources, |snapshot| &snapshot.activity_sources);
        let networks = self.network_display_names();
        let now = chrono::Utc::now();
        let editor = cx.entity().downgrade();
        let mut rows = div()
            .id("activity-records")
            .w_full()
            .min_w_0()
            .flex()
            .flex_col();
        for record in items {
            let request_id = record.request_id();
            // The detail is a modal now. Expanding it in place pushed every
            // later row off the screen, so reading one receipt cost you the
            // list you were reading it from.
            rows = rows.child(render_activity_row(
                record,
                selected_record == Some(request_id),
                busy.contains(&request_id),
                refreshing.contains(&request_id),
                feedback.get(&request_id).cloned(),
                &networks,
                sources.get(&request_id),
                now,
                editor.clone(),
                cx,
            ));
        }
        panel
            .child(self.render_activity_history_header(items.len(), cx))
            .child(rows)
    }

    /// How much history there is, and the one control that ends it.
    ///
    /// The count is the argument for the button being here at all: this list
    /// only grows, every row is a card the window lays out on every frame, and
    /// the person watching it get slower is the only one who can say which of
    /// it still matters.
    fn render_activity_history_header(&self, shown: usize, cx: &mut Context<Self>) -> gpui::Div {
        let mut header = div().w_full().flex().flex_col().gap_2();
        if let Some(error) = &self.history_clear_error {
            header = header.child(selectable_error_alert(
                "activity-history-clear-error",
                error.clone(),
            ));
        }
        header.child(
            h_flex()
                .w_full()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap_2()
                .child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        // "Shown", not "kept". This list is capped at the most
                        // recent records and filtered to the networks the owner
                        // is showing, so the number under it is not the number
                        // the button below deletes.
                        .child(selectable_label(if shown == 1 {
                            "1 record shown".to_owned()
                        } else {
                            format!("{shown} records shown")
                        })),
                )
                .child(
                    app_button("clear-activity-history")
                        .danger()
                        .label("Clear history")
                        .disabled(self.history_clearing)
                        .on_click(cx.listener(|view, _, window, cx| {
                            view.confirm_activity_history_clear(window, cx);
                        })),
                ),
        )
    }

    fn render_activity(&self, cx: &mut Context<Self>) -> gpui::Div {
        let waiting = self.inbox_tab == InboxTab::Waiting;
        div()
            .w_full()
            .p_5()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .flex()
            .flex_col()
            .gap_4()
            .child(
                TabBar::new("inbox-tabs")
                    .w_full()
                    .underline()
                    .large()
                    .selected_index(usize::from(!waiting))
                    .child(Tab::new().label("Waiting on you"))
                    .child(Tab::new().label("Already decided"))
                    .on_click(cx.listener(|view, index: &usize, _, cx| {
                        view.set_inbox_tab(
                            if *index == 0 {
                                InboxTab::Waiting
                            } else {
                                InboxTab::Decided
                            },
                            cx,
                        );
                    })),
            )
            .when(waiting, |inbox| {
                inbox.child(
                    div()
                        .id("activity-needs-review")
                        .debug_selector(|| "activity-waiting-panel".to_owned())
                        .child(self.render_reviews(cx)),
                )
            })
            .when(!waiting, |inbox| {
                inbox.child(
                    div()
                        .id("inbox-history")
                        .debug_selector(|| "activity-decided-panel".to_owned())
                        .child(self.render_activity_history(cx)),
                )
            })
    }

    fn render_settings(&self, cx: &mut Context<Self>) -> gpui::Div {
        let claude_desktop_detected = matches!(
            &self.detected_agents,
            AgentDetectionState::Ready(detected)
                if detected.iter().any(|agent| agent.kind == AgentKind::ClaudeDesktop)
        );
        let mut agents = div().flex().flex_col().gap_1();
        match &self.detected_agents {
            AgentDetectionState::Loading => {
                agents = agents.child(
                    h_flex()
                        .gap_2()
                        .child(Spinner::new())
                        .child(selectable_label("Detecting…")),
                );
            }
            AgentDetectionState::Failed(error) => {
                agents = agents.child(div().text_sm().text_color(cx.theme().danger).child(
                    selectable_label(format!("Agent detection unavailable: {error}")),
                ));
            }
            AgentDetectionState::Ready(detected) if detected.is_empty() => {
                agents = agents.child(
                    div()
                        .text_color(cx.theme().muted_foreground)
                        .max_w(PROSE_MEASURE)
                        .child(selectable_label(
                            "No supported agent installation was detected.",
                        )),
                );
            }
            AgentDetectionState::Ready(detected) => {
                for (index, agent) in detected.iter().enumerate() {
                    let installed = agent.installed.as_ref().copied().unwrap_or(false);
                    let config_error = agent.installed.as_ref().err().cloned();
                    let (icon, icon_color) = if installed {
                        (IconName::CircleCheck, cx.theme().success)
                    } else if config_error.is_some() {
                        (IconName::CircleX, cx.theme().danger)
                    } else {
                        (IconName::CircleX, cx.theme().muted_foreground)
                    };
                    let action_selector = format!("configure-detected-agent-{index}");
                    agents = agents.child(
                        ListItem::new(SharedString::from(format!("detected-agent-{index}"))).child(
                            div()
                                .w_full()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(
                                    h_flex()
                                        .w_full()
                                        .items_center()
                                        .gap_3()
                                        .child(
                                            div()
                                                .flex_none()
                                                .text_color(icon_color)
                                                .child(Icon::new(icon).large()),
                                        )
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .child(selectable_text(
                                                    ("detected-agent-name", index),
                                                    agent.display_name,
                                                ))
                                                .child(
                                                    div()
                                                        .text_sm()
                                                        .text_color(cx.theme().muted_foreground)
                                                        .max_w(PROSE_MEASURE)
                                                        .truncate()
                                                        .child(selectable_text(
                                                            ("detected-agent-path", index),
                                                            &agent.config_path,
                                                        )),
                                                ),
                                        )
                                        .child(
                                            app_button(action_selector.clone())
                                                .debug_selector(move || action_selector.clone())
                                                .label(if installed { "Remove" } else { "Install" })
                                                .when(!installed, ButtonVariants::primary)
                                                .disabled(
                                                    self.legal_gate
                                                        || self.agent_reinstall
                                                            == AgentReinstallState::Running,
                                                )
                                                .on_click(cx.listener({
                                                    let kind = agent.kind;
                                                    move |view, _, _, cx| {
                                                        view.set_detected_agent_installed(
                                                            kind, !installed, cx,
                                                        );
                                                    }
                                                })),
                                        ),
                                )
                                .when_some(config_error, |row, error| {
                                    row.child(div().text_sm().text_color(cx.theme().danger).child(
                                        selectable_text(
                                            format!("detected-agent-error-{index}"),
                                            &error,
                                        ),
                                    ))
                                }),
                        ),
                    );
                }
            }
        }

        div()
            // Named so the prose-specific render test can still inspect the
            // pane within the route-wide cap. `debug_selector` is a documented
            // no-op in release builds.
            .debug_selector(|| "settings-pane".to_owned())
            // A settings row puts its name at the left edge and its control at
            // the right, which is the desktop idiom and reads well until the
            // window is wide: at a thousand pixels the `View` beside a legal
            // document sat a hand's width from the document it opened, and the
            // pairing had to be inferred from vertical alignment alone. Every
            // settings pane worth copying caps its measure for this reason.
            // The shared route container now applies that same measure to
            // every screen, keeping each control beside its subject.
            .w_full()
            .flex()
            .flex_col()
            // A settings pane's groups need more air than the rows inside
            // them, or the whole page reads as one dense block — the same
            // thing the account form fixed for itself. The reference desktop
            // settings spacing is 20-28px between groups against 16px within
            // one; these were both 16.
            .gap_6()
            .child(settings_section(
                "Appearance",
                GroupBox::new()
                    .id("appearance-settings")
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
.max_w(PROSE_MEASURE)
                            .child(selectable_label("System follows your operating-system appearance and updates while the wallet is running.")),
                    )
                    .child(
                        h_flex()
                            .flex_wrap()
                            .gap_2()
                            .child(
                                app_button("appearance-system")
                                    .label("System")
                                    .selected(
                                        self.appearance_preference
                                            == AppearancePreference::System,
                                    )
                                    .toggled(
                                        self.appearance_preference
                                            == AppearancePreference::System,
                                    )
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.set_appearance_preference(
                                            AppearancePreference::System,
                                            window,
                                            cx,
                                        );
                                    })),
                            )
                            .child(
                                app_button("appearance-light")
                                    .label("Light")
                                    .selected(
                                        self.appearance_preference
                                            == AppearancePreference::Light,
                                    )
                                    .toggled(
                                        self.appearance_preference
                                            == AppearancePreference::Light,
                                    )
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.set_appearance_preference(
                                            AppearancePreference::Light,
                                            window,
                                            cx,
                                        );
                                    })),
                            )
                            .child(
                                app_button("appearance-dark")
                                    .label("Dark")
                                    .selected(
                                        self.appearance_preference
                                            == AppearancePreference::Dark,
                                    )
                                    .toggled(
                                        self.appearance_preference
                                            == AppearancePreference::Dark,
                                    )
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.set_appearance_preference(
                                            AppearancePreference::Dark,
                                            window,
                                            cx,
                                        );
                                    })),
                            ),
                    ),
            ))
            // No section heading here: the row's own "Testnet mode" label
            // already names it, and a "Test networks" title above it just
            // said the same thing twice.
            .child(untitled_settings_section(
                GroupBox::new()
                    .id("testnet-mode-settings")
                    .child(
                        h_flex()
                            .w_full()
                            .justify_between()
                            .gap_4()
                            .child(
                                div()
                                    .min_w_0()
                                    .flex_1()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(div().font_medium().child("Testnet mode"))
                                    .child(
                                        div()
                                            .debug_selector(|| "settings-prose".to_owned())
                                            .text_sm()
                                            .text_color(cx.theme().muted_foreground)
.max_w(PROSE_MEASURE)
                                            .child(selectable_label("Show configured test networks and their linked balances, tokens, requests, and activity. Testnet mode is off by default.")),
                                    ),
                            )
                            .child(
                                Switch::new("testnet-mode")
                                    .checked(self.testnet_mode)
                                    .on_click(cx.listener(|view, enabled, _, cx| {
                                        view.set_testnet_mode(*enabled, cx);
                                    })),
                            ),
                    ),
            ))
            .child(settings_section(
                "Detected agents",
                GroupBox::new()
                    .id("detected-agent-settings")
                    .when_some(self.mcp_status.detail(), |group, error| {
                        group.child(
                            selectable_error_alert(
                                "mcp-gateway-error",
                                format!(
                                    "No agent can reach this wallet until it is restarted: {error}"
                                ),
                            )
                            .title("The agent gateway could not start"),
                        )
                    })
                    // The endpoint every one of these installs points at. It
                    // was a compile-time constant the interface never showed,
                    // so an agent configured by hand had nothing to copy.
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
.max_w(PROSE_MEASURE)
                            .child(selectable_label(
                                "Installing adds a credential-free stdio entry to an agent's configuration. That agent starts the bridge when it uses the wallet; the bridge reaches this app through same-user operating-system IPC.",
                            )),
                    )
                    .child(agents)
                    .when(claude_desktop_detected, |group| {
                        group.child(
                            h_flex()
                                .debug_selector(|| {
                                    "claude-desktop-hosted-connector".to_owned()
                                })
                                .w_full()
                                .flex_wrap()
                                .items_center()
                                .justify_between()
                                .gap_3()
                                .child(
                                    div()
                                        .min_w_0()
                                        .flex_1()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(
                                            div()
                                                .text_sm()
                                                .font_medium()
                                                .child("Claude Desktop hosted connector"),
                                        )
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .max_w(PROSE_MEASURE)
                                                .child(selectable_label(
                                                    "In Claude Desktop, open Customize → Connectors, add a custom connector named Ekubo, then paste this URL. Remote connectors belong to your Claude account and cannot be installed through claude_desktop_config.json.",
                                                )),
                                        ),
                                )
                                .child(copy_button(
                                    "copy-claude-desktop-connector-url",
                                    crate::agent_config::COMPANION_SERVER_URL.to_owned(),
                                    "Copy Claude Desktop connector URL",
                                )),
                        )
                    }),
            ))
            .child(self.render_updates(cx))
            .child(self.render_legal(cx))
    }

    fn render_accounts(&self, cx: &mut Context<Self>) -> gpui::Div {
        let busy = self.account_operation.is_some();
        let creating = self.account_entry_mode == AccountEntryMode::Create;
        // Roomier than the account cards below it on purpose: this is the one
        // card on the page that is a form, and at the list card's `p_4`/`gap_3`
        // the tab bar, the explanation, the labelled field, and the primary
        // button were all the same distance apart and read as one dense block.
        let mut form = div()
            .p_5()
            .pb_6()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().secondary)
            .flex()
            .flex_col()
            .gap_4()
            .child(
                TabBar::new("account-entry-tabs")
                    .w_full()
                    .underline()
                    .large()
                    .selected_index(usize::from(!creating))
                    .child(Tab::new().label("Create account").disabled(busy))
                    .child(Tab::new().label("Import private key").disabled(busy))
                    .on_click(cx.listener(|view, index: &usize, _, cx| {
                        let mode = if *index == 0 {
                            AccountEntryMode::Create
                        } else {
                            AccountEntryMode::Import
                        };
                        view.set_account_entry_mode(mode, cx);
                    })),
            )
            .child(
                div()
                    .debug_selector(|| "policy-editor-status".to_owned())
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label(if creating {
                        "The wallet generates the key and hands it to this machine's secure storage; it is never shown or written to disk. A new account starts by asking you about every single transaction."
                    } else {
                        "The key goes straight into secure storage and is wiped from this form before the import starts. It is never logged and never leaves this machine."
                    })),
            );
        if let Some(input) = &self.account_id_input {
            // The error belongs to the field, so it lives in the field's own
            // column. As a sibling of the form it sat the full row gap away
            // and read as if it belonged to whatever came next.
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .font_medium()
                            .child(selectable_label("Account name")),
                    )
                    .child(
                        app_input(input, cx)
                            .aria_label("Account name")
                            .disabled(busy),
                    )
                    .when_some(self.account_id_error.clone(), |field, error| {
                        field.child(field_error("account-name-error", error, cx))
                    }),
            );
        }
        if !creating && let Some(input) = &self.private_key_input {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .font_medium()
                            .child(selectable_label("Private key")),
                    )
                    .child(
                        // No reveal toggle. A private key that can be unmasked
                        // is a private key that can be shoulder-surfed or
                        // caught by a screen recording, and nothing about
                        // pasting one in needs it visible.
                        app_input(input, cx)
                            .aria_label("Private key")
                            .content_type(InputContentType::Password)
                            .disabled(busy),
                    )
                    .when_some(self.private_key_error.clone(), |field, error| {
                        field.child(field_error("private-key-error", error, cx))
                    }),
            );
        }
        form = form
            .child(
                h_flex()
                    .gap_2()
                    .when(busy, |actions| actions.child(Spinner::new().small()))
                    .child(
                        app_button(if creating {
                            "create-account"
                        } else {
                            "import-account"
                        })
                        .label(match self.account_operation {
                            Some(AccountOperation::Creating) => "Creating account…",
                            Some(AccountOperation::Importing) => "Importing account…",
                            None if creating => "Create account",
                            None => "Import private key",
                        })
                        .primary()
                        .disabled(busy)
                        .on_click(cx.listener(
                            move |view, _, window, cx| {
                                if creating {
                                    view.create_account(window, cx);
                                } else {
                                    view.import_account(window, cx);
                                }
                            },
                        )),
                    ),
            )
            .when_some(self.account_status.clone(), |form, status| {
                form.child(
                    div()
                        .id("account-operation-status")
                        .role(Role::Alert)
                        .text_sm()
                        .text_color(cx.theme().success)
                        .child(selectable_label(status)),
                )
            });

        let mut accounts = div().w_full().min_w_0().flex().flex_col().gap_3();
        accounts = match self.cached_accounts() {
            Ok([]) => accounts.child(
                div()
                    .p_4()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().secondary)
                    .text_color(cx.theme().muted_foreground)
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .font_medium()
                            .text_color(cx.theme().foreground)
                            .child(selectable_label("No accounts yet")),
                    )
                    .child(selectable_label(
                        "Create one above. Everything else in this wallet — connecting an agent, holding a balance, approving a request — starts here.",
                    )),
            ),
            Ok(items) => accounts.children(items.iter().map(|item| {
                let export_id = item.id.clone();
                let removal_id = item.id.clone();
                let address = format!("{:#x}", item.address);
                let address_for_copy = address.clone();
                let address_text_id = SharedString::from(format!("account-address-{}", item.id));
                let address_copy_id =
                    SharedString::from(format!("copy-account-address-{}", item.id));
                let action_error = self.account_action_errors.get(&item.id).cloned();
                div()
                    .p_4()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().secondary)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .min_w_0()
                                    .flex_1()
                                    .flex_basis(px(260.0))
                                    .child(div().font_semibold().truncate().child(selectable_text(
                                        format!("account-name-{}", item.id),
                                        &item.id,
                                    )))
                                    .child(
                                        selectable_text(address_text_id, &address)
                                            .max_w_full()
                                            .truncate()
                                            .font_family(MONO_FONT_FAMILY)
                                            .text_sm()
                                            .text_color(cx.theme().muted_foreground),
                                    )
                                    // A key that has left the machine cannot
                                    // be un-exported, and until now the wallet
                                    // recorded that fact without ever showing
                                    // it.
                                    .when_some(item.exported_at, |identity, exported_at| {
                                        identity.child(
                                            selectable_text(
                                                format!("account-exported-{}", item.id),
                                                &format!(
                                                    "Key exported {}",
                                                    relative_time_label(exported_at, chrono::Utc::now())
                                                ),
                                            )
                                            .max_w_full()
                                            .truncate()
                                            .text_sm()
                                            .text_color(cx.theme().warning),
                                        )
                                    }),
                            )
                            .child(
                                div()
                                    .flex_none()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        copy_button(
                                            address_copy_id,
                                            address_for_copy,
                                            "Copy account address",
                                        )
                                        .large(),
                                    )
                                    .child(
                                        app_button(SharedString::from(format!(
                                            "export-account-{export_id}"
                                        )))
                                        .label("Export key")
                                        .on_click(
                                            cx.listener(move |view, _, _, cx| {
                                                view.begin_account_export(export_id.clone(), cx);
                                            }),
                                        ),
                                    )
                                    .child(
                                        app_button(SharedString::from(format!(
                                            "remove-account-{removal_id}"
                                        )))
                                        .label("Remove")
                                        .danger()
                                        .on_click(
                                            cx.listener(move |view, _, _, cx| {
                                                view.begin_account_removal(removal_id.clone(), cx);
                                            }),
                                        ),
                                    ),
                            ),
                    )
                    .when_some(action_error, |row, error| {
                        row.child(div().text_sm().text_color(cx.theme().danger).child(
                            selectable_text(format!("account-action-error-{}", item.id), &error),
                        ))
                    })
            })),
            Err(error) => accounts.child(
                div()
                    .p_4()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(cx.theme().danger)
                    .text_sm()
                    .text_color(cx.theme().danger)
                    .child(selectable_label(format!(
                        "The accounts on this device could not be read: {error:#}"
                    ))),
            ),
        };

        div()
            .w_full()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_4()
            .child(form)
            .child(accounts)
    }

    fn render_policies(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div()
            .debug_selector(|| "policies-content".to_owned())
            .w_full()
            .min_w_0()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .gap_4()
            .when_some(self.policy_action_error.clone(), |content, error| {
                content.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(selectable_label(error)),
                )
            });
        let accounts = match self.cached_accounts() {
            Ok(accounts) => accounts,
            Err(error) => {
                return content.child(selectable_error_alert(
                    "policy-account-error",
                    format!("Accounts unavailable: {error:#}"),
                ));
            }
        };
        if accounts.is_empty() {
            return content.child(account_required_panel(
                "policy-empty",
                "policy-go-to-accounts",
                "A wallet account is required before there are signing permissions to configure.",
                cx,
            ));
        }

        // The account selector lives in the fixed page header, so the body is
        // only the policy for whichever account it names.
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_ref(), self.policy_json_input.as_ref())
        else {
            return content.child(
                div()
                    .p_5()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(cx.theme().border)
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label(
                        "Select an account to inspect its exact policy document.",
                    )),
            );
        };

        content = content.child(
            h_flex()
                .id("policy-agent-tip")
                .debug_selector(|| "policy-agent-tip".to_owned())
                .w_full()
                .min_w_0()
                .flex_shrink_0()
                .gap_3()
                .p_3()
                .rounded(cx.theme().radius)
                .border_1()
                .border_color(cx.theme().info.opacity(0.35))
                .bg(cx.theme().info.opacity(0.10))
                .text_sm()
                .font_medium()
                .text_color(cx.theme().info)
                .child(Icon::new(IconName::Info).flex_none())
                .child(div().min_w_0().child(selectable_label(
                    "Try asking your connected agent to construct a policy for you",
                ))),
        );

        match self.cached_reviews().map(|reviews| {
            policy_proposal_for_account(&reviews.policy_proposals, &editor.wallet_id)
        }) {
            Ok(Some(proposal)) => {
                let current_result = self.cached_policy(&editor.wallet_id);
                let current_error = current_result
                    .as_ref()
                    .err()
                    .map(|error| format!("Could not read active policy: {error:#}"));
                let applicable = current_result
                    .ok()
                    .flatten()
                    .is_some_and(|policy| policy.revision == proposal.source_revision);
                let review_proposal = proposal.clone();
                let reject_proposal = proposal.clone();
                let proposal_card =
                    div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(div().text_sm().child(selectable_text(
                            format!("policy-proposal-rationale-{}", proposal.wallet_id),
                            &ekubo_wallet_core::sanitize::terminal_safe_multiline(
                                &proposal.rationale,
                            ),
                        )))
                        .when(!applicable && current_error.is_none(), |card| {
                            card.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().danger)
                                    .child(selectable_label("Superseded by a policy change")),
                            )
                        })
                        .when_some(current_error, |card, error| {
                            card.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().danger)
                                    .child(selectable_label(error)),
                            )
                        })
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap_2()
                                .child(
                                    app_button(SharedString::from(format!(
                                        "review-policy-proposal-{}",
                                        proposal.wallet_id
                                    )))
                                    .label("Review in editor")
                                    .primary()
                                    .disabled(!applicable)
                                    .on_click(cx.listener(move |view, _, window, cx| {
                                        view.open_policy_proposal(
                                            review_proposal.clone(),
                                            window,
                                            cx,
                                        );
                                    })),
                                )
                                .child(
                                    app_button(SharedString::from(format!(
                                        "reject-policy-proposal-{}",
                                        proposal.wallet_id
                                    )))
                                    .label("Reject proposal")
                                    .danger()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.reject_policy_proposal(&reject_proposal, cx);
                                    })),
                                ),
                        );
                content = content.child(
                    GroupBox::new()
                        .id("policy-proposal")
                        .title("Agent proposal")
                        .child(proposal_card),
                );
            }
            Ok(None) => {}
            Err(error) => {
                content = content.child(selectable_error_alert(
                    "policy-proposal-error",
                    format!("Policy proposal unavailable: {error:#}"),
                ));
            }
        }

        let current_document = input.read(cx).value();
        let allow_anything_draft = serde_json::from_str(current_document.as_ref())
            .ok()
            .and_then(|value| WalletPolicy::parse(value).ok())
            .is_some_and(|policy| policy == WalletPolicy::allow_anything());
        let validated = editor
            .validation
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        let reviewed_exact_document =
            validated.is_some_and(|review| current_document.as_ref() == review.document.as_str());
        let mut editor_panel = div()
            .id("policy-json-editor")
            .debug_selector(|| "policy-json-editor".to_owned())
            .anchor_scroll(Some(self.policy_editor_anchor.clone()))
            .w_full()
            .min_w_0()
            .min_h(px(420.0))
            .flex_shrink_0()
            .p_4()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().secondary)
            .flex()
            .flex_col()
            .gap_3()
            // No account name here: the header already names the account this
            // document belongs to, and repeating it pushed the policy itself
            // further down the page.
            .when(editor.source_revision.is_none(), |panel| {
                panel.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_text(
                            format!("policy-editor-revision-{}", editor.wallet_id),
                            "No installed policy · signing disabled",
                        )),
                )
            })
            .when_some(
                editor
                    .validation
                    .as_ref()
                    .and_then(|validation| validation.as_ref().err().cloned()),
                |panel, error| {
                    panel.child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().danger)
                            .child(selectable_label(error)),
                    )
                },
            );
        editor_panel = editor_panel
            .child(
                div()
                    .id("policy-json-editor-input")
                    .debug_selector(|| "policy-json-editor-input".to_owned())
                    .w_full()
                    .min_w_0()
                    .flex_1()
                    .min_h(px(320.0))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_sm()
                            .font_medium()
                            .child(selectable_label("Policy JSON")),
                    )
                    // The input's `h_full` is relative to this remaining-space
                    // wrapper, not to the column that also contains its label.
                    // Otherwise the label and gap are added above a 100%-high
                    // editor and push it through the panel's bottom border.
                    //
                    // The viewport is what makes the column floor affordable:
                    // the control below it may be wider than the panel, and
                    // this is where that overflow turns into a scroll rather
                    // than a clip. The editor swallows vertical wheel events
                    // for its own scrolling but leaves horizontal ones to
                    // propagate, so the two axes do not fight.
                    .child(
                        div()
                            .id("policy-json-viewport")
                            .debug_selector(|| "policy-json-viewport".to_owned())
                            .overflow_x_scroll()
                            .w_full()
                            .min_w_0()
                            .min_h_0()
                            .flex_1()
                            .flex()
                            .child(
                                div()
                                    .debug_selector(|| "policy-json-control".to_owned())
                                    .flex_1()
                                    .min_w(policy_editor_min_width(cx))
                                    .min_h_0()
                                    .h_full()
                                    .child(
                                        app_input(input, cx)
                                            .aria_label("Policy JSON")
                                            .font_family(MONO_FONT_FAMILY)
                                            .w_full()
                                            .min_w_0()
                                            .h_full(),
                                    ),
                            ),
                    ),
            )
            .when(allow_anything_draft, |panel| {
                panel.child(
                    div()
                        .id("policy-unrestricted-warning")
                        .role(Role::Alert)
                        .p_3()
                        .rounded(cx.theme().radius_lg)
                        .border_1()
                        .border_color(cx.theme().danger)
                        .text_color(cx.theme().danger)
                        .child(selectable_label("Danger: this policy automatically signs every call on every chain, including arbitrary calldata and native value.")),
                )
            })
            .child(
                GroupBox::new()
                    .id("policy-presets")
                    .title("Policy presets")
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_2()
                            .child(
                                app_button("reset-policy-draft")
                                    .label("Review every transaction")
                                    .disabled(self.policy_installing)
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.reset_policy_editor(window, cx);
                                    })),
                            )
                            .child(
                                app_button("disable-signing-policy-draft")
                                    .label("Disable transaction signing")
                                    .disabled(self.policy_installing)
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.apply_disable_signing_policy(window, cx);
                                    })),
                            )
                            .child(
                                app_button("allow-anything-policy-draft")
                                    .icon(IconName::TriangleAlert)
                                    .label("Allow anything")
                                    .disabled(self.policy_installing)
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.apply_allow_anything_policy(window, cx);
                                    })),
                            ),
                    ),
            )
            .child(
                div()
                    .debug_selector(|| "policy-preview-workflow".to_owned())
                    .w_full()
                    .min_w_0()
                    .child(
                        GroupBox::new()
                            .id("policy-preview-workflow")
                            .title("Review changes")
                            .child(
                                div()
                                    .text_sm()
                                    .child(selectable_label("Preview and review the computed permission changes before installation. Install remains unavailable until the preview matches this exact JSON document.")),
                            )
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(selectable_label(match editor.validation.as_ref() {
                                        Some(Ok(_)) if reviewed_exact_document => {
                                            "The computed permission changes below match this draft."
                                        }
                                        Some(Ok(_)) => {
                                            "This draft changed after its last preview. Refresh the computed changes."
                                        }
                                        Some(Err(_)) => {
                                            "Fix the JSON validation error, then preview its permission changes."
                                        }
                                        None => "Review the computed permission changes before you can install this policy.",
                                    })),
                            )
                            .child(
                                app_button("validate-policy-draft")
                                    .self_start()
                                    .label(if reviewed_exact_document {
                                        "Refresh preview"
                                    } else {
                                        "Preview changes"
                                    })
                                    .when(!reviewed_exact_document, ButtonVariants::primary)
                                    .disabled(self.policy_installing)
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.validate_policy_editor(window, cx);
                                    })),
                            ),
                    ),
            );
        content = content.child(editor_panel);

        match editor.validation.as_ref() {
            Some(Ok(review)) if reviewed_exact_document => {
                let mut changes = div().flex().flex_col().gap_2();
                for (index, line) in review.diff.iter().enumerate() {
                    changes = changes.child(
                        div()
                            .id(SharedString::from(format!("policy-diff-{index}")))
                            .p_2()
                            .rounded(cx.theme().radius)
                            .bg(cx.theme().secondary)
                            .font_family(MONO_FONT_FAMILY)
                            .text_sm()
                            .child(selectable_text(
                                ("policy-diff-line", index),
                                line,
                            )),
                    );
                }
                content.child(
                    div()
                        .debug_selector(|| "policy-permission-diff".to_owned())
                        .w_full()
                        .min_w_0()
                        // This card contributes its complete intrinsic height to
                        // the route scroller. Letting the flex column shrink it
                        // made the child rows overflow while the scrollbar still
                        // believed the page ended above the install action.
                        .flex_shrink_0()
                        .child(
                            GroupBox::new()
                                .id("policy-permission-diff")
                                .title("Computed permission changes")
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(selectable_label("Installing requires operating-system authentication and rechecks the policy revision immediately before the write.")),
                                )
                                .child(changes)
                                .child(
                                    app_button("install-policy-draft")
                                        .debug_selector(|| "install-policy-draft".to_owned())
                                        .self_start()
                                        .label(if self.policy_installing {
                                            "Authenticating…"
                                        } else {
                                            "Authenticate & install"
                                        })
                                        .primary()
                                        .loading(self.policy_installing)
                                        .disabled(self.policy_installing)
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            view.install_policy_editor(cx);
                                        })),
                                ),
                        ),
                )
            }
            Some(Ok(_)) => content.child(selectable_warning_alert(
                "policy-diff-stale",
                "The document changed after validation. Validate it again to refresh the permission diff.",
            )),
            Some(Err(_)) | None => content,
        }
    }

    fn render_legal(&self, cx: &mut Context<Self>) -> gpui::Div {
        // The version is the one thing here anybody has to reproduce
        // elsewhere — in a bug report, in a support thread — so it gets a copy
        // button rather than asking to be retyped from a screenshot.
        let version = format!("Version {BUILD_VERSION}");
        let panel = GroupBox::new()
            .id("legal-and-version")
            .compact()
            .child(about_row(
                "Ekubo Wallet",
                Some((version.clone().into(), cx.theme().muted_foreground)),
                copy_button("copy-version", version, "Copy version"),
                true,
                cx,
            ));
        let panel = match self.cached_legal_status() {
            Ok(status) => panel
                .child(about_row(
                    "Terms of Service",
                    Some(legal_acceptance_detail(&status.terms_of_service, cx)),
                    app_button("review-terms")
                        .label("View")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.open_legal_review(LegalDocument::TermsOfService, cx);
                        })),
                    true,
                    cx,
                ))
                .child(about_row(
                    "Privacy Policy",
                    Some(legal_acceptance_detail(&status.privacy_policy, cx)),
                    app_button("review-privacy")
                        .label("View")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.open_legal_review(LegalDocument::PrivacyPolicy, cx);
                        })),
                    true,
                    cx,
                )),
            // Only the two documents that carry an acceptance state depend on
            // this; the license rows below open a bundled file either way.
            Err(error) => panel.child(selectable_label(format!(
                "Legal status unavailable: {error:#}"
            ))),
        };
        settings_section(
            "About Ekubo Wallet",
            panel
                .child(about_row(
                    "Application License",
                    // The identifier, under the name, because "Application
                    // License" says a licence exists and not which one. It is
                    // read from the manifest, so it cannot drift from what the
                    // crate is actually published under.
                    Some((
                        env!("CARGO_PKG_LICENSE").into(),
                        cx.theme().muted_foreground,
                    )),
                    app_button("review-license")
                        .label("View")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.open_legal_review(LegalDocument::ApplicationLicense, cx);
                        })),
                    true,
                    cx,
                ))
                .child(about_row(
                    "Third-Party Licenses",
                    None,
                    app_button("review-licenses")
                        .label("View")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.open_legal_review(LegalDocument::ThirdPartyLicenses, cx);
                        })),
                    true,
                    cx,
                ))
                .child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_label("Copyright © 2026 Ekubo, Inc.")),
                ),
        )
    }

    fn render_walletconnect(&self, cx: &mut Context<Self>) -> gpui::Div {
        let account_error = match self.cached_accounts() {
            Ok([]) => Some("Create an account before starting a pairing.".into()),
            Err(error) => Some(format!("Signing accounts unavailable: {error:#}")),
            Ok(_) => None,
        };
        let account_unavailable = account_error.is_some();
        let connecting = self.walletconnect_connecting;
        let mut panel = div()
            .p_4()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().secondary)
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .text_lg()
                    .font_medium()
                    .child(selectable_label("Connect a dapp")),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label("Paste a WalletConnect v2 URI copied from the dapp. Pairings stay in memory and disconnect when you explicitly Quit.")),
            );
        if let Some(input) = self.walletconnect_uri_input.as_ref() {
            panel = panel
                .child(
                    div()
                        .text_sm()
                        .font_medium()
                        .child(selectable_label("Pairing URI")),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_end()
                        .gap_2()
                        .child(
                            div().min_w(px(220.0)).flex_1().child(
                                app_input(input, cx)
                                    .aria_label("WalletConnect pairing URI")
                                    .w_full(),
                            ),
                        )
                        .child(
                            app_button("connect-walletconnect")
                                .label(if connecting.is_some() {
                                    "Connecting"
                                } else {
                                    "Connect"
                                })
                                .primary()
                                .loading(connecting.is_some())
                                .disabled(account_unavailable || connecting.is_some())
                                .on_click(cx.listener(|view, _, window, cx| {
                                    view.connect_walletconnect(window, cx);
                                })),
                        )
                        // A pairing that is not drawn in the list below has no
                        // Disconnect button of its own, and a dapp that never
                        // proposes would otherwise leave the wallet waiting
                        // with no way out but quitting.
                        .when_some(connecting, |row, session_id| {
                            row.child(app_button("cancel-walletconnect").label("Cancel").on_click(
                                cx.listener(move |view, _, _, cx| {
                                    view.disconnect_walletconnect(session_id, cx);
                                }),
                            ))
                        }),
                );
            if connecting.is_some() {
                panel = panel.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_label(
                            "Paired. The review window opens when the dapp proposes a \
                             connection; Cancel drops the pairing.",
                        )),
                );
            }
            if let Some(error) = account_error {
                panel = panel.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(selectable_label(error)),
                );
            }
        }
        let mut sessions = div().w_full().min_w_0().flex().flex_col().gap_3();
        // Only dapps the owner approved. A pairing that has not been through
        // the review window is a stranger on a relay, and listing it beside
        // the real connections would read as though it had been let in.
        let approved: Vec<SessionSummary> = self
            .approved_walletconnect_sessions()
            .cloned()
            .collect::<Vec<_>>();
        if approved.is_empty() {
            return div().flex().flex_col().gap_4().child(panel).child(
                sessions.child(
                    div()
                        .p_4()
                        .rounded(cx.theme().radius_lg)
                        .border_1()
                        .border_color(cx.theme().border)
                        .bg(cx.theme().secondary)
                        .text_color(cx.theme().muted_foreground)
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .font_medium()
                                .text_color(cx.theme().foreground)
                                .child(selectable_label("No dapp is connected")),
                        )
                        .child(selectable_label(
                            "Pair one above. A session lives only as long as this wallet runs — quitting drops every pairing.",
                        )),
                ),
            );
        }
        sessions = sessions.children(approved.into_iter().map(|session| {
            let session_id = session.id;
            div()
                .w_full()
                .min_w_0()
                .p_3()
                .rounded(cx.theme().radius_lg)
                .border_1()
                .border_color(cx.theme().border)
                .bg(cx.theme().secondary)
                .flex()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .min_w_0()
                        .flex_1()
                        .flex()
                        .flex_col()
                        .child(div().w_full().min_w_0().truncate().font_medium().child(
                            selectable_text(
                                format!("walletconnect-session-title-{session_id}"),
                                &format!(
                                    "{} · {}",
                                    session.dapp_name.as_deref().unwrap_or("Unnamed dapp"),
                                    session.status.label()
                                ),
                            ),
                        ))
                        .child(
                            div()
                                .min_w_0()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(selectable_text(
                                    format!("walletconnect-session-requests-{session_id}"),
                                    &format!(
                                        "{} active {}",
                                        session.active_requests,
                                        if session.active_requests == 1 {
                                            "request"
                                        } else {
                                            "requests"
                                        }
                                    ),
                                )),
                        )
                        .when_some(session.expires_at, |column, expires_at| {
                            column.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(selectable_text(
                                        format!("walletconnect-session-expiry-{session_id}"),
                                        &walletconnect_expiry_label(expires_at, chrono::Utc::now()),
                                    )),
                            )
                        })
                        .when_some(session.last_error, |column, error| {
                            column.child(
                                div()
                                    .whitespace_normal()
                                    .text_sm()
                                    .text_color(cx.theme().danger)
                                    .child(selectable_text(
                                        format!("walletconnect-error-{session_id}"),
                                        &format!("Connection error: {error}"),
                                    )),
                            )
                        }),
                )
                .child(
                    app_button(SharedString::from(format!("disconnect-wc-{session_id}")))
                        .flex_none()
                        .label("Disconnect")
                        .danger()
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.disconnect_walletconnect(session_id, cx);
                        })),
                )
        }));
        div().flex().flex_col().gap_4().child(panel).child(sessions)
    }

    fn render_network_editor_form(&self, view: &WeakEntity<Self>, cx: &App) -> gpui::Div {
        let Some(name) = self.network_name_input.as_ref() else {
            return div();
        };
        let Some(display_name) = self.network_display_name_input.as_ref() else {
            return div();
        };
        let Some(aliases) = self.network_aliases_input.as_ref() else {
            return div();
        };
        let Some(chain_id) = self.network_chain_id_input.as_ref() else {
            return div();
        };
        let Some(rpc_urls) = self.network_rpc_urls_input.as_ref() else {
            return div();
        };
        let Some(native_name) = self.network_native_name_input.as_ref() else {
            return div();
        };
        let Some(native_symbol) = self.network_native_symbol_input.as_ref() else {
            return div();
        };
        let Some(native_decimals) = self.network_native_decimals_input.as_ref() else {
            return div();
        };
        let Some(explorer) = self.network_explorer_url_input.as_ref() else {
            return div();
        };
        let Some(documentation) = self.network_documentation_url_input.as_ref() else {
            return div();
        };
        let busy = self.network_editor_busy;
        let editing = self.network_editor_original.is_some();
        let advanced_open = self.network_editor_advanced_open;
        // Twelve inputs stacked one prose paragraph at a time did not fit any
        // ordinary window, and laying them out as wrapping flex rows let a long
        // label decide its own column's width and shove the field beside it
        // onto the next line. `Form` is a grid: every column gets the same
        // share whatever its label says, so a row stays a row. Required fields
        // carry the component's asterisk rather than an "(optional)" suffix on
        // everything else — shorter, and it agrees with what saving enforces.
        let text_field = |label: &'static str,
                          input: &Entity<InputState>,
                          error: Option<String>,
                          required: bool,
                          disabled: bool,
                          columns: u16| {
            field()
                .col_span(columns)
                .required(required)
                .label_fn(move |_, _| selectable_label(label))
                .child(
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(
                            app_input(input, cx)
                                .aria_label(label)
                                .disabled(disabled || busy),
                        )
                        .when_some(error, |column, error| {
                            column.child(field_error(
                                SharedString::from(format!("network-editor-error-{label}")),
                                error,
                                cx,
                            ))
                        }),
                )
        };
        v_flex()
            .w_full()
            .gap_5()
            .child(
                v_form()
                    .columns(6)
                    .child(
                        text_field(
                            "Chain ID",
                            chain_id,
                            self.network_editor_errors.chain_id.clone(),
                            true,
                            editing,
                            2,
                        )
                        .when(editing, |field| {
                            field.description("Fixed once the network exists.")
                        }),
                    )
                    .child(text_field(
                        "Internal name",
                        name,
                        self.network_editor_errors.name.clone(),
                        true,
                        false,
                        2,
                    ))
                    .child(text_field(
                        "Display name",
                        display_name,
                        self.network_editor_errors.display_name.clone(),
                        false,
                        false,
                        2,
                    ))
                    .child(text_field(
                        "Block explorer",
                        explorer,
                        self.network_editor_errors.block_explorer_url.clone(),
                        true,
                        false,
                        3,
                    ))
                    .child(text_field(
                        "Documentation",
                        documentation,
                        self.network_editor_errors.documentation_url.clone(),
                        true,
                        false,
                        3,
                    )),
            )
            .child(
                v_flex()
                    .w_full()
                    .gap_1()
                    // The endpoint-order choice belongs beside the endpoints it
                    // orders, and as one segmented control rather than two
                    // buttons that only look related when the right one
                    // happens to be lit.
                    .child(
                        h_flex()
                            .w_full()
                            // Wrapping here is the narrow-window escape hatch:
                            // the segmented control is wider than the label, so
                            // on a small viewport it drops below rather than
                            // running off the edge of the dialog.
                            .flex_wrap()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                h_flex()
                                    .flex_none()
                                    .gap_1()
                                    .text_sm()
                                    .font_medium()
                                    .child(selectable_label("RPC endpoints"))
                                    .child(div().text_color(cx.theme().danger).child("*")),
                            )
                            .child(
                                ButtonGroup::new("network-editor-rpc-strategy")
                                    .flex_none()
                                    .small()
                                    .disabled(busy)
                                    .child(
                                        Button::new("network-strategy-ordered")
                                            .label("Try in order")
                                            .tooltip("Endpoints are tried from the top down; a failure moves to the next one.")
                                            .selected(self.network_editor_rpc_strategy == RpcStrategy::Ordered),
                                    )
                                    .child(
                                        Button::new("network-strategy-random")
                                            .label("Shuffle each request")
                                            .tooltip("Endpoints are shuffled per request; a failure continues through that shuffled list.")
                                            .selected(self.network_editor_rpc_strategy == RpcStrategy::Random),
                                    )
                                    .on_click({
                                        let view = view.clone();
                                        move |clicked: &Vec<usize>, _, cx| {
                                            let strategy = if clicked.contains(&1) {
                                                RpcStrategy::Random
                                            } else {
                                                RpcStrategy::Ordered
                                            };
                                            let _ = view.update(cx, |view, cx| {
                                                view.set_network_editor_strategy(strategy, cx);
                                            });
                                        }
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(selectable_label("One http:// or https:// URL per line.")),
                    )
                    .child(
                        div()
                            .debug_selector(|| "network-rpc-endpoints-input".to_owned())
                            .w_full()
                            .h(px(144.0))
                            .child(
                                app_input(rpc_urls, cx)
                                    .aria_label("RPC endpoints")
                                    .w_full()
                                    .h_full()
                                    .disabled(busy),
                            ),
                    )
                    .when_some(
                        self.network_editor_errors.rpc_urls.clone(),
                        |section, error| {
                            section.child(field_error("network-editor-rpc-urls-error", error, cx))
                        },
                    ),
            )
            .child(
                v_flex()
                    .w_full()
                    .gap_2()
                    .child(
                        div()
                            .text_sm()
                            .font_semibold()
                            .child(selectable_label("Native currency")),
                    )
                    .child(
                        v_form()
                            .columns(6)
                            .child(text_field("Name", native_name, None, true, false, 2))
                            .child(text_field("Symbol", native_symbol, None, true, false, 2))
                            .child(text_field("Decimals", native_decimals, None, true, false, 2)),
                    )
                    .when_some(
                        self.network_editor_errors.native_currency.clone(),
                        |section, error| {
                            section.child(field_error(
                                "network-editor-native-currency-error",
                                error,
                                cx,
                            ))
                        },
                    ),
            )
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .child(
                        v_flex()
                            .min_w_0()
                            .flex_1()
                            .child(
                                div()
                                    .text_sm()
                                    .font_medium()
                                    .child(selectable_label("Test network")),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(selectable_label(
                                        "Hidden, with its balances, tokens, and activity, unless testnet mode is on.",
                                    )),
                            ),
                    )
                    .child(
                        Switch::new("network-editor-testnet")
                            .checked(self.network_editor_testnet)
                            .disabled(busy)
                            .on_click({
                                let view = view.clone();
                                move |checked, _, cx| {
                                    let _ = view.update(cx, |wallet, cx| {
                                        wallet.network_editor_testnet = *checked;
                                        cx.notify();
                                    });
                                }
                            }),
                    ),
            )
            // Four of the twelve fields are optional, and showing them all made
            // the required ones hard to find. They open on demand — and open
            // themselves when an existing network already sets one, so editing
            // never hides a value that is in force.
            .child(
                Collapsible::new()
                    .w_full()
                    .gap_3()
                    .open(advanced_open)
                    .child(
                        app_button("network-editor-advanced")
                            .ghost()
                            .self_start()
                            .label("Optional details")
                            .icon(if advanced_open {
                                IconName::ChevronDown
                            } else {
                                IconName::ChevronRight
                            })
                            .disabled(busy)
                            .on_click({
                                let view = view.clone();
                                move |_, _, cx| {
                                    let _ = view.update(cx, |wallet, cx| {
                                        wallet.network_editor_advanced_open =
                                            !wallet.network_editor_advanced_open;
                                        cx.notify();
                                    });
                                }
                            }),
                    )
                    .content(
                        v_form()
                            .columns(6)
                            .child(
                                text_field(
                                    "Aliases",
                                    aliases,
                                    self.network_editor_errors.aliases.clone(),
                                    false,
                                    false,
                                    6,
                                )
                                .description(
                                    "Other names this network answers to, separated by commas.",
                                ),
                            ),
                    ),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label(
                        "Saving checks every field, confirms the live chain answers to this chain ID, and asks you to authenticate.",
                    )),
            )
            .when_some(self.network_editor_errors.form.clone(), |panel, error| {
                panel.child(field_error("network-editor-form-error", error, cx))
            })
    }

    fn render_network_editor_footer(&self, view: &WeakEntity<Self>) -> DialogFooter {
        let busy = self.network_editor_busy;
        // No `flex_wrap` here. The footer is two buttons on one line; wrapping
        // only ever fired because the primary label was a sentence, and it put
        // Cancel on a row of its own under a right-aligned Save. The label is
        // short now and the sentence it used to carry sits above the footer,
        // where it is read before the click rather than on it.
        DialogFooter::new()
            .pt_2()
            .child(
                app_button("cancel-guided-network")
                    .label("Cancel")
                    .disabled(busy)
                    .on_click({
                        let view = view.clone();
                        move |_, window, cx| {
                            let can_close = view
                                .update(cx, |view, cx| {
                                    if view.network_editor_busy {
                                        return false;
                                    }
                                    view.close_network_editor(cx);
                                    true
                                })
                                .unwrap_or(false);
                            if can_close {
                                window.close_dialog(cx);
                            }
                        }
                    }),
            )
            .child(
                app_button("save-guided-network")
                    .debug_selector(|| "network-editor-save".to_owned())
                    .label(if busy { "Saving…" } else { "Save network" })
                    .primary()
                    .loading(busy)
                    .disabled(busy)
                    .on_click({
                        let view = view.clone();
                        move |_, _, cx| {
                            let _ = view.update(cx, |view, cx| {
                                view.save_network_editor(cx);
                            });
                        }
                    }),
            )
    }
    fn cached_automations(&self) -> Result<&Vec<Automation>> {
        self.snapshot()?
            .automations
            .as_ref()
            .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    /// Stop one automation, at the owner's request.
    fn stop_automation(&mut self, automation_id: uuid::Uuid, cx: &mut Context<Self>) {
        let owner = self.owner.clone();
        self.automation_busy = Some(automation_id);
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || owner.disable_automation(automation_id))
                .await
                .context("stopping the automation failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.automation_busy = None;
                view.automation_error = result
                    .err()
                    .map(|error| SharedString::from(format!("{error:#}")));
                view.reload_desktop_snapshot(cx);
            });
        })
        .detach();
    }

    /// Start one again under the policy that is active now.
    fn relink_automation(&mut self, automation_id: uuid::Uuid, cx: &mut Context<Self>) {
        let owner = self.owner.clone();
        self.automation_busy = Some(automation_id);
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || owner.relink_automation(automation_id))
                .await
                .context("restarting the automation failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.automation_busy = None;
                view.automation_error = result
                    .err()
                    .map(|error| SharedString::from(format!("{error:#}")));
                view.reload_desktop_snapshot(cx);
            });
        })
        .detach();
    }

    /// Open the transaction one automation run produced.
    ///
    /// Goes to the same activity detail any other transaction opens in: an
    /// automation's transaction is an ordinary transaction, and giving it a
    /// second, lesser viewer would be the wrong kind of special case.
    fn open_automation_transaction(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.set_route(Route::Activity);
        self.inbox_tab = InboxTab::Decided;
        self.selected_record = Some(request_id);
        if !self.activity_inspections.contains_key(&request_id) {
            self.load_transaction_inspection(request_id, cx);
        }
        cx.notify();
    }

    fn render_automations(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div().flex().flex_col().gap_4();
        content = content.when_some(self.automation_error.clone(), |content, error| {
            content.child(
                div()
                    .text_sm()
                    .text_color(cx.theme().danger)
                    .child(selectable_label(error)),
            )
        });

        let automations = match self.cached_automations() {
            Err(error) => {
                return content.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(selectable_label(format!("{error:#}"))),
                );
            }
            Ok(automations) => automations,
        };
        if automations.is_empty() {
            return content.child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label(
                        "No automations. An agent can install one to react to something on chain \
                         without waiting for you — it can only make transactions your policy \
                         already allows.",
                    )),
            );
        }

        let now = chrono::Utc::now();
        let mut rows = div()
            .debug_selector(|| "automation-list".to_owned())
            .flex()
            .flex_col()
            .gap_3();
        for automation in automations {
            let id = automation.id;
            let busy = self.automation_busy == Some(id);
            let stopped = automation.state != AutomationState::Enabled;
            // What it is, in the order a reader needs it: the name they were
            // told, the account it spends from, and how often it runs.
            let heading = format!(
                "{} · {} · chain {}",
                automation.name, automation.wallet_id, automation.chain_id
            );
            let schedule = match automation.state {
                AutomationState::Enabled => automation
                    .schedule
                    .next_after(automation.last_tick_at.unwrap_or(now))
                    .map_or_else(
                        || format!("{} · not scheduled to run again", automation.schedule),
                        |next| {
                            format!(
                                "{} · next at {} UTC",
                                automation.schedule,
                                next.format("%Y-%m-%d %H:%M:%S")
                            )
                        },
                    ),
                _ => format!("{} · not running", automation.schedule),
            };
            let mut card =
                div()
                    .p_3()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(if stopped {
                        cx.theme().danger
                    } else {
                        cx.theme().border
                    })
                    .bg(cx.theme().secondary)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        h_flex()
                            .w_full()
                            .justify_between()
                            .gap_3()
                            .child(
                                div().font_semibold().child(selectable_text(
                                    format!("automation-title-{id}"),
                                    &heading,
                                )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap_2()
                                    .when(stopped, |actions| {
                                        actions.child(
                                            app_button(SharedString::from(format!(
                                                "relink-automation-{id}"
                                            )))
                                            .debug_selector(|| "relink-automation".to_owned())
                                            .label("Run again")
                                            .primary()
                                            .loading(busy)
                                            .disabled(busy)
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.relink_automation(id, cx);
                                            })),
                                        )
                                    })
                                    .when(!stopped, |actions| {
                                        actions.child(
                                            app_button(SharedString::from(format!(
                                                "stop-automation-{id}"
                                            )))
                                            .debug_selector(|| "stop-automation".to_owned())
                                            .label("Stop")
                                            .danger()
                                            .loading(busy)
                                            .disabled(busy)
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.stop_automation(id, cx);
                                            })),
                                        )
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(selectable_label(schedule)),
                    );

            // Why it stopped comes before anything else about it. An
            // automation that is not running is the only thing on this screen
            // the reader has to act on, and burying the reason under the hash
            // would make them hunt for it.
            if let Some(reason) = automation.stopped_reason.as_ref() {
                card = card.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(selectable_label(reason.clone())),
                );
            }
            if let Some(outcome) = automation.last_outcome.as_ref() {
                let when = automation.last_tick_at.map_or_else(String::new, |at| {
                    format!(" ({})", relative_time_label(at, now))
                });
                card = card.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_label(format!("Last run: {outcome}{when}"))),
                );
            }
            // The bytecode cannot be shown as anything a person reads, so the
            // screen says what it honestly can: its hash, its size, and the
            // policy revision it is bound to.
            card = card.child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_text(
                        format!("automation-identity-{id}"),
                        &format!(
                            "{} · {} bytes · policy revision {} · key {}",
                            automation.bytecode_hash(),
                            automation.bytecode.len(),
                            automation.policy_revision,
                            automation.key
                        ),
                    )),
            );
            // The run history, which is the answer to "what has this been
            // doing" — and for every run that produced a transaction, a way
            // straight to that transaction's details. Those records are hidden
            // rather than deleted when history is cleared, so this link keeps
            // working however long ago the run happened.
            if let Some(runs) = self
                .snapshot()
                .ok()
                .and_then(|snapshot| snapshot.automation_runs.get(&id))
                .filter(|runs| !runs.is_empty())
            {
                let mut history = div()
                    .debug_selector(|| "automation-runs".to_owned())
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_xs()
                            .font_semibold()
                            .text_color(cx.theme().muted_foreground)
                            .child(selectable_label("Runs")),
                    );
                for run in runs {
                    let request_id = run.request_id;
                    history = history.child(
                        h_flex()
                            .w_full()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(if run.outcome == RunOutcome::Failed {
                                        cx.theme().danger
                                    } else {
                                        cx.theme().muted_foreground
                                    })
                                    .child(selectable_label(format!(
                                        "{} · {} · {}",
                                        relative_time_label(run.ran_at, now),
                                        run.outcome.label(),
                                        run.detail
                                    ))),
                            )
                            .when_some(request_id, |row, request_id| {
                                row.child(
                                    app_button(SharedString::from(format!(
                                        "open-automation-transaction-{}",
                                        run.run_id
                                    )))
                                    .debug_selector(|| "open-automation-transaction".to_owned())
                                    .label("Transaction")
                                    .small()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.open_automation_transaction(request_id, cx);
                                    })),
                                )
                            }),
                    );
                }
                card = card.child(history);
            }
            rows = rows.child(card);
        }
        content.child(rows)
    }

    fn render_networks(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div().flex().flex_col().gap_4();
        match self.cached_reviews().map(|reviews| {
            reviews
                .network_proposals
                .iter()
                .filter(|proposal| self.testnet_mode || !proposal.testnet)
                .collect::<Vec<_>>()
        }) {
            Ok(proposals) if !proposals.is_empty() => {
                let mut rows = div().flex().flex_col().gap_3();
                for proposal in proposals {
                    let accept = proposal.clone();
                    let reject = proposal.clone();
                    let exact = serde_json::to_string_pretty(&proposal)
                        .unwrap_or_else(|error| format!("Could not serialize proposal: {error:#}"));
                    rows = rows.child(
                        div()
                            .p_3()
                            .rounded(cx.theme().radius_lg)
                            .border_1()
                            .border_color(cx.theme().border)
                            .bg(cx.theme().secondary)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                h_flex()
                                    .w_full()
                                    .justify_between()
                                    .gap_3()
                                    .child(div().font_semibold().child(selectable_text(
                                        format!("network-proposal-title-{}", proposal.chain_id),
                                        &format!("{} · chain {}", proposal.name, proposal.chain_id),
                                    )))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .gap_2()
                                            .child(
                                                app_button(SharedString::from(format!(
                                                    "accept-network-proposal-{}",
                                                    proposal.chain_id
                                                )))
                                                .label("Verify and install")
                                                .primary()
                                                .disabled(self.network_proposal_busy)
                                                .on_click(cx.listener(move |view, _, _, cx| {
                                                    view.accept_network_proposal(
                                                        accept.clone(),
                                                        cx,
                                                    );
                                                })),
                                            )
                                            .child(
                                                app_button(SharedString::from(format!(
                                                    "reject-network-proposal-{}",
                                                    proposal.chain_id
                                                )))
                                                .label("Reject")
                                                .danger()
                                                .disabled(self.network_proposal_busy)
                                                .on_click(cx.listener(move |view, _, _, cx| {
                                                    view.reject_network_proposal(&reject, cx);
                                                })),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .p_3()
                                    .rounded(cx.theme().radius)
                                    .bg(cx.theme().secondary)
                                    .font_family(MONO_FONT_FAMILY)
                                    .text_sm()
                                    .child(selectable_code_text(
                                        format!("network-proposal-document-{}", proposal.chain_id),
                                        &exact,
                                    )),
                            ),
                    );
                }
                content = content.child(
                    GroupBox::new()
                        .id("network-proposals")
                        .title("Agent proposals")
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(selectable_label("The wallet contacts the proposed RPC and verifies its chain ID before authentication or installation.")),
                        )
                        .when_some(self.network_proposal_error.clone(), |group, error| {
                            group.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().danger)
                                    .child(selectable_label(error)),
                            )
                        })
                        .child(rows),
                );
            }
            Ok(_) => {}
            Err(error) => {
                content = content.child(selectable_error_alert(
                    "network-proposals-error",
                    format!("Network proposals unavailable: {error:#}"),
                ));
            }
        }
        content = match self.cached_networks() {
            // Nothing to list, and the reason matters: with testnet mode off,
            // a wallet whose networks are all test networks drew an empty page
            // under an Add button and no account of where they had gone. Every
            // other page in this wallet says what its own empty means.
            Ok(networks) if networks_for_display(networks, self.testnet_mode).is_empty() => content
                .child(
                    div()
                        .p_5()
                        .rounded(cx.theme().radius_lg)
                        .border_1()
                        .border_color(cx.theme().border)
                        .bg(cx.theme().secondary)
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .font_semibold()
                                .child(selectable_label("No network is configured")),
                        )
                        .child(div().text_color(cx.theme().muted_foreground).child(
                            selectable_label(if networks.is_empty() {
                                "This wallet will not sign for any chain until you add one above."
                            } else {
                                "Every configured network is a test network. Turn on testnet mode in Settings to see them, or add a network above."
                            }),
                        )),
                ),
            Ok(networks) => {
                // Enabled and disabled cards used to run together in one list,
                // so learning what this wallet will actually sign for meant
                // reading every badge on the page. They are two sections now,
                // and the networks in force come first.
                let (enabled, disabled_networks): (Vec<_>, Vec<_>) =
                    networks_for_display(networks, self.testnet_mode)
                        .into_iter()
                        .partition(|network| !network.disabled);
                let network_card = |network: &NetworkConfig, cx: &mut Context<Self>| {
                    let name = network.name.clone();
                    let edit = network.clone();
                    let toggle_network = network.clone();
                    let disabled = network.disabled;
                    let busy = self.network_action_busy.contains(&name);
                    let action_error = self.network_action_errors.get(&name).cloned();
                    div()
                        .p_4()
                        .rounded(cx.theme().radius_lg)
                        .border_1()
                        .border_color(cx.theme().border)
                        .bg(cx.theme().secondary)
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            h_flex()
                                .flex_wrap()
                                .items_center()
                                .w_full()
                                .justify_between()
                                .gap_3()
                                .child(
                                    div().min_w_0().flex_1().flex().flex_col().gap_2().child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .items_center()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .min_w_0()
                                                    .font_semibold()
                                                    .truncate()
                                                    .child(selectable_text(
                                                        format!("network-title-{name}"),
                                                        network
                                                            .display_name
                                                            .as_deref()
                                                            .unwrap_or(&name),
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .text_color(cx.theme().muted_foreground)
                                                    .child(selectable_text(
                                                        format!("network-metadata-{name}"),
                                                        &format!(
                                                            "{} · chain {}{}",
                                                            name,
                                                            network.chain_id,
                                                            if network.testnet {
                                                                " · testnet"
                                                            } else {
                                                                ""
                                                            },
                                                        ),
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .px_2()
                                                    .py_0p5()
                                                    .rounded_full()
                                                    .border_1()
                                                    .border_color(if disabled {
                                                        cx.theme().border
                                                    } else {
                                                        cx.theme().primary
                                                    })
                                                    .when(!disabled, |badge| {
                                                        badge.bg(cx.theme().primary)
                                                    })
                                                    .text_xs()
                                                    .text_color(if disabled {
                                                        cx.theme().muted_foreground
                                                    } else {
                                                        cx.theme().primary_foreground
                                                    })
                                                    .child(selectable_text(
                                                        format!("network-status-{name}"),
                                                        if disabled {
                                                            "Disabled"
                                                        } else {
                                                            "Enabled"
                                                        },
                                                    )),
                                            ),
                                    ),
                                )
                                .child(
                                    h_flex()
                                        .flex_none()
                                        .gap_2()
                                        .child(accessible_button(
                                            app_button(SharedString::from(format!(
                                                "edit-network-{name}"
                                            )))
                                            .icon(Icon::default().path(PENCIL_ICON))
                                            .label("Edit")
                                            .tooltip("Edit network")
                                            .disabled(busy)
                                            .on_click(cx.listener(
                                                move |view, _, window, cx| {
                                                    cx.stop_propagation();
                                                    view.edit_network(&edit, window, cx);
                                                },
                                            )),
                                            "Edit network",
                                        ))
                                        .child(
                                            app_button(SharedString::from(format!(
                                                "toggle-network-{name}"
                                            )))
                                            .label(if busy {
                                                "Authenticating…"
                                            } else if disabled {
                                                "Enable"
                                            } else {
                                                "Disable"
                                            })
                                            .disabled(busy)
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.set_network_disabled(
                                                    toggle_network.clone(),
                                                    !disabled,
                                                    cx,
                                                );
                                            })),
                                        ),
                                ),
                        )
                        .when_some(action_error, |card, error| {
                            card.child(div().text_sm().text_color(cx.theme().danger).child(
                                selectable_text(format!("network-action-error-{name}"), &error),
                            ))
                        })
            };
                let mut sections = content;
                for (id, title, group) in [
                    ("networks-enabled", "Enabled", enabled),
                    ("networks-disabled", "Disabled", disabled_networks),
                ] {
                    if group.is_empty() {
                        continue;
                    }
                    sections = sections.child(
                        GroupBox::new().id(id).title(title).children(
                            group
                                .into_iter()
                                .map(|network| network_card(network, cx))
                                .collect::<Vec<_>>(),
                        ),
                    );
                }
                sections
            }
            Err(error) => content.child(selectable_error_alert(
                "network-list-error",
                format!("Networks unavailable: {error:#}"),
            )),
        };
        content
    }

    fn render_portfolio(&self, cx: &mut Context<Self>) -> gpui::Div {
        // Rendering and scrolling must never open SQLCipher or consult the OS
        // credential store. The background snapshot already owns the exact
        // configured rows needed by this view.
        let enabled_network_count = self
            .cached_networks()
            .unwrap_or_default()
            .iter()
            .filter(|network| !network.disabled && (self.testnet_mode || !network.testnet))
            .count();
        // The account selector and the refresh control live in the fixed page
        // header, so this panel is only the balances themselves.
        let mut content = div().flex().flex_col().gap_4();
        if enabled_network_count == 0 {
            return content.child(
                div()
                    .p_5()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(cx.theme().border)
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label(
                        "Enable a network to load account balances.",
                    )),
            );
        }
        // Having no accounts is a fact of the background snapshot rather than
        // of the balance read, so it answers before any loading placeholder:
        // there is nothing to load until an account exists.
        if self
            .cached_accounts()
            .is_ok_and(<[WalletMetadata]>::is_empty)
        {
            return content.child(account_required_panel(
                "portfolio-empty",
                "portfolio-create-account",
                "A wallet account is required before there are balances to show.",
                cx,
            ));
        }
        let content = match &self.portfolio {
            // Placeholder rows shaped like balance rows, so the page shows
            // where the token list is about to appear instead of a spinner
            // that says only that something, somewhere, is happening.
            PortfolioState::Idle | PortfolioState::Loading => {
                content.child(portfolio_loading_placeholder(cx))
            }
            PortfolioState::Failed(error) => content.child(
                selectable_error_alert("portfolio-error", error.clone())
                    .title("Portfolio unavailable"),
            ),
            // One account is read per refresh, so the snapshot holds exactly
            // the selected account.
            PortfolioState::Ready(snapshot) => {
                let Some(account) = snapshot.accounts.first() else {
                    return content
                        .child(portfolio_loading_placeholder(cx))
                        .children(self.portfolio_refreshed_note(cx));
                };
                let rows = portfolio_balance_rows(account);
                let failures = account
                    .networks
                    .iter()
                    .filter_map(|item| {
                        item.result.as_ref().err().map(|error| {
                            (
                                item.network.chain_id,
                                item.network
                                    .display_name
                                    .as_deref()
                                    .unwrap_or(&item.network.name)
                                    .to_owned(),
                                error,
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                let row_count = rows.len();
                let mut balances = div().w_full().min_w_0().flex().flex_col();
                for (index, row) in rows.into_iter().enumerate() {
                    let address = row.asset_address.clone();
                    let token_identity =
                        match (row.token_name.as_deref(), row.token_symbol.as_deref()) {
                            (Some(name), Some(symbol)) if name != symbol => {
                                format!("{name} ({symbol})")
                            }
                            (Some(name), _) => name.to_owned(),
                            (_, Some(symbol)) => symbol.to_owned(),
                            _ if row.native => "Native asset".to_owned(),
                            _ => "Unlabeled token".to_owned(),
                        };
                    let identity = div()
                        .w_full()
                        .min_w_0()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            selectable_text(
                                format!(
                                    "portfolio-asset-token-{}-{}-{address}",
                                    account.wallet.id, row.chain_id
                                ),
                                &token_identity,
                            )
                            .min_w_0()
                            .flex_1()
                            .truncate()
                            .font_medium(),
                        );
                    let mut metadata = h_flex()
                        .w_full()
                        .min_w_0()
                        .flex_wrap()
                        .justify_start()
                        .gap_1()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_text(
                            SharedString::from(format!(
                                "portfolio-asset-network-{}-{}-{address}",
                                account.wallet.id, row.chain_id
                            )),
                            &format!(
                                "{}{}",
                                row.network_name,
                                if row.native { " · Native asset" } else { "" },
                            ),
                        ));
                    if !row.native {
                        let address_label = if address.len() > 22 {
                            format!("{}…{}", &address[..12], &address[address.len() - 8..])
                        } else {
                            address.clone()
                        };
                        metadata = metadata
                            .child(
                                div()
                                    .flex_none()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("·"),
                            )
                            .child(match row.explorer_url {
                                Some(explorer_url) => app_button(SharedString::from(format!(
                                    "portfolio-token-explorer-{}-{}-{address}",
                                    account.wallet.id, row.chain_id
                                )))
                                .label(address_label)
                                .link()
                                .h(px(22.0))
                                .max_w_full()
                                .min_w_0()
                                .px_0()
                                .text_xs()
                                .font_normal()
                                .font_family(MONO_FONT_FAMILY)
                                .text_color(cx.theme().muted_foreground)
                                .tooltip(address.clone())
                                .on_click(move |_, _, cx| cx.open_url(&explorer_url))
                                .into_any_element(),
                                None => selectable_text(
                                    SharedString::from(format!(
                                        "portfolio-asset-address-{}-{}-{address}",
                                        account.wallet.id, row.chain_id
                                    )),
                                    &address_label,
                                )
                                .min_w_0()
                                .truncate()
                                .text_xs()
                                .font_family(MONO_FONT_FAMILY)
                                .text_color(cx.theme().muted_foreground)
                                .into_any_element(),
                            });
                    }
                    balances = balances.child(
                        div()
                            .w_full()
                            .min_w_0()
                            .py_2()
                            .when(index + 1 < row_count, |row| {
                                row.border_b_1().border_color(cx.theme().border)
                            })
                            .flex()
                            .child(
                                div()
                                    .w_full()
                                    .min_w_0()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .justify_between()
                                    .gap_3()
                                    .child(
                                        div()
                                            .min_w(px(180.0))
                                            .flex_1()
                                            .flex_basis(px(260.0))
                                            .flex()
                                            .flex_col()
                                            .gap_0p5()
                                            .child(identity)
                                            .child(metadata),
                                    )
                                    .child(
                                        div()
                                            .min_w_0()
                                            .max_w_full()
                                            .flex_none()
                                            .id(SharedString::from(format!(
                                                "portfolio-balance-scroll-{}-{}-{address}",
                                                account.wallet.id, row.chain_id
                                            )))
                                            .overflow_x_scroll()
                                            .text_right()
                                            .font_family(MONO_FONT_FAMILY)
                                            .text_lg()
                                            .font_semibold()
                                            .child(
                                                selectable_text(
                                                    SharedString::from(format!(
                                                        "portfolio-asset-balance-{}-{}-{address}",
                                                        account.wallet.id, row.chain_id
                                                    )),
                                                    &row.balance,
                                                )
                                                .whitespace_nowrap(),
                                            ),
                                    ),
                            ),
                    );
                }
                if row_count == 0 {
                    balances = balances.child(
                        div()
                            .py_4()
                            .text_color(cx.theme().muted_foreground)
                            .child(selectable_label("No balances.")),
                    );
                }
                for (chain_id, network_name, error) in failures {
                    balances = balances.child(
                        div()
                            .w_full()
                            .py_2()
                            .text_sm()
                            .text_color(cx.theme().danger)
                            .child(selectable_text(
                                format!("portfolio-error-{}-{chain_id}", account.wallet.id),
                                &format!("{network_name} · Chain {chain_id}: {error}"),
                            )),
                    );
                }
                content = content.child(
                    div()
                        .w_full()
                        .min_w_0()
                        .p_4()
                        .rounded(cx.theme().radius_lg)
                        .border_1()
                        .border_color(cx.theme().border)
                        .bg(cx.theme().secondary)
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(balances),
                );
                // One line under the list, because the question it answers —
                // "why is my token missing?" — only comes up once the list is
                // on screen.
                content.child(
                    h_flex()
                        .flex_wrap()
                        .gap_1()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_label("Only non-zero balances are shown."))
                        .child(
                            app_button("portfolio-manage-tokens")
                                .label("Add a token")
                                .link()
                                .h(px(22.0))
                                .px_0()
                                .text_sm()
                                .font_normal()
                                .on_click(cx.listener(|view, _, _, cx| {
                                    view.set_route(Route::Tokens);
                                    cx.notify();
                                })),
                        ),
                )
            }
        };
        content.children(self.portfolio_refreshed_note(cx))
    }

    /// How old the balances on screen are, as the last line of the tab.
    ///
    /// Rendered in every state that has a reading behind it, not only the
    /// one showing balances: while a refresh is in flight the age of what is
    /// still on screen is the more useful fact, and after a failure it is the
    /// only one. `None` until this account has been read once, when there is
    /// no age to report.
    fn portfolio_refreshed_note(&self, cx: &App) -> Option<gpui::Div> {
        let refreshed_at = self.focused_portfolio_refreshed_at()?;
        Some(
            div()
                .debug_selector(|| "portfolio-refreshed-at".to_owned())
                .w_full()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child(selectable_text(
                    "portfolio-refreshed-at-text",
                    &format!(
                        "Refreshed {}",
                        relative_time_label(refreshed_at, chrono::Utc::now())
                    ),
                )),
        )
    }

    fn render_tokens(&self, cx: &mut Context<Self>) -> gpui::Div {
        let Some(list) = self.token_list.as_ref() else {
            return div().child(Spinner::new());
        };
        let Some(search_input) = self.token_search_input.as_ref() else {
            return div().child(Spinner::new());
        };
        let Some(proposal_list) = self.token_proposal_list.as_ref() else {
            return div().child(Spinner::new());
        };
        let delegate = list.read(cx).delegate();
        let visible = delegate.visible_tokens.len();
        let total = delegate.all_tokens.len();
        let (selected_source, selected_count, viewed_to_end) = {
            let delegate = proposal_list.read(cx).delegate();
            (
                delegate.source.clone(),
                delegate.proposals.len(),
                delegate.viewed_to_end,
            )
        };

        let mut content = div()
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .gap_3()
            .when_some(self.token_proposal_error.clone(), |content, error| {
                content.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(selectable_label(error)),
                )
            });
        // Two ways to get a token into this wallet, so they belong on one
        // line. Stacked, they read as a menu of unrelated commands and push
        // the list they act on further down the page.
        content = content.child(
            h_flex()
                .flex_wrap()
                .items_center()
                .gap_2()
                .child(
                    app_button("open-token-editor")
                        .debug_selector(|| "add-token-button".to_owned())
                        .label("Add token")
                        .primary()
                        .disabled(self.token_editor_open)
                        .on_click(cx.listener(|view, _, window, cx| {
                            view.open_new_token_editor(window, cx);
                        })),
                )
                .when_some(self.token_list_url_input.as_ref(), |row, _| {
                    row.child(
                        app_button("toggle-owner-token-list-import")
                            .label(if self.token_list_import_open {
                                "Close token-list import"
                            } else {
                                "Import a published token list…"
                            })
                            .icon(if self.token_list_import_open {
                                IconName::ChevronUp
                            } else {
                                IconName::ChevronDown
                            })
                            .disabled(self.token_import_state == TokenImportState::Fetching)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.toggle_token_list_import(cx);
                            })),
                    )
                }),
        );
        if let Some(input) = self.token_list_url_input.as_ref()
            && self.token_list_import_open
        {
            content = content.child(
                GroupBox::new()
                    .id("owner-token-list-import")
                    .title("Import published token list")
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(selectable_label("Fetch a public HTTPS token-list JSON for all enabled networks. Its entries are only used after you inspect and accept the exact resulting list below.")),
                    )
                    .child(
                        div()
                            .text_sm()
                            .font_medium()
                            .child(selectable_label("Published token-list URL")),
                    )
                    .child(
                        h_flex()
                            .w_full()
                            .flex_wrap()
                            .items_end()
                            .gap_2()
                            .child(
                                div().flex_1().min_w(px(220.0)).child(
                                    app_input(input, cx)
                                        .aria_label("Published token-list URL")
                                        .content_type(InputContentType::Url)
                                        .w_full(),
                                ),
                            )
                            .child(
                                app_button("import-owner-token-list")
                                    .label(
                                        if self.token_import_state == TokenImportState::Fetching {
                                            "Fetching…"
                                        } else {
                                            "Fetch for review"
                                        },
                                    )
                                    .primary()
                                    .disabled(
                                        self.token_import_state == TokenImportState::Fetching,
                                    )
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.import_token_list_for_review(cx);
                                    })),
                            ),
                    )
                    .when(
                        self.token_import_state == TokenImportState::Fetching,
                        |group| {
                            group.child(
                                h_flex()
                                    .gap_2()
                                    .child(Spinner::new().small())
                                    .child(selectable_label(
                                        "Fetching and validating the published list…",
                                    )),
                            )
                        },
                    )
                    .when_some(self.token_import_error.clone(), |group, error| {
                        group.child(
                            selectable_error_alert("token-list-import-error", error)
                                .title("Token list could not be fetched"),
                        )
                    })
                    .when_some(self.token_import_status.clone(), |group, status| {
                        group.child(
                            div()
                                .id("token-list-import-status")
                                .role(Role::Alert)
                                .p_3()
                                .rounded(cx.theme().radius)
                                .border_1()
                                .border_color(cx.theme().success)
                                .text_sm()
                                .text_color(cx.theme().success)
                                .child(selectable_label(status)),
                        )
                    }),
                );
        }
        match self.cached_reviews().map(|reviews| {
            reviews
                .token_proposals
                .iter()
                .filter(|proposal| self.token_proposal_is_visible(proposal))
                .collect::<Vec<_>>()
        }) {
            Ok(proposals) if !proposals.is_empty() => {
                let mut grouped = std::collections::BTreeMap::<String, Vec<TokenProposal>>::new();
                for proposal in proposals {
                    grouped
                        .entry(proposal.source.clone())
                        .or_default()
                        .push(proposal.clone());
                }
                let mut groups = div().flex().flex_col().gap_2();
                for (index, (source, proposals)) in grouped.into_iter().enumerate() {
                    let count = proposals.len();
                    let selected = selected_source.as_deref() == Some(source.as_str());
                    let review_source = source.clone();
                    groups = groups.child(
                        div()
                            .p_3()
                            .rounded(cx.theme().radius)
                            .border_1()
                            .border_color(cx.theme().border)
                            .bg(cx.theme().secondary)
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                div().flex_1().min_w_0().child(source).child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(format!(
                                            "{} awaiting review",
                                            pluralize(count, "token name")
                                        )),
                                ),
                            )
                            .child(
                                app_button(("review-token-proposal-group", index))
                                    .label(if selected { "Reviewing" } else { "Review" })
                                    .toggled(selected)
                                    .when(selected, ButtonVariants::primary)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.review_token_proposal_group(
                                            review_source.clone(),
                                            proposals.clone(),
                                            cx,
                                        );
                                    })),
                            ),
                    );
                }
                content = content.child(
                    GroupBox::new()
                        .id("token-proposal-groups")
                        .title("Agent proposals")
                        .child(groups),
                );
            }
            Ok(_) => {}
            Err(error) => {
                content = content.child(selectable_error_alert(
                    "token-proposals-error",
                    format!("Token proposals unavailable: {error:#}"),
                ));
            }
        }

        if let Some(source) = selected_source {
            content = content.child(
                GroupBox::new()
                    .id("token-proposal-review")
                    .title(format!("Review {source}"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "Inspect all {selected_count} exact address, symbol, decimals, name, and chain rows. Acceptance stays disabled until the end of this virtualized list has been viewed."
                            )),
                    )
                    .child(
                        List::new(proposal_list)
                            .h(px(340.0))
                            .w_full()
                            .border_1()
                            .border_color(cx.theme().border)
                            .rounded(cx.theme().radius),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_2()
                            .child(
                                app_button("accept-token-proposal-group")
                                    .label(if self.token_proposal_busy {
                                        "Working…"
                                    } else if viewed_to_end {
                                        "Accept exact list"
                                    } else {
                                        "View complete list to accept"
                                    })
                                    .primary()
                                    .disabled(self.token_proposal_busy || !viewed_to_end)
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.accept_token_proposal_group(cx);
                                    })),
                            )
                            .child(
                                app_button("reject-token-proposal-group")
                                    .label("Reject exact list")
                                    .danger()
                                    .disabled(self.token_proposal_busy)
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.reject_token_proposal_group(cx);
                                    })),
                            ),
                    ),
            );
        }

        let mut token_search = Input::new(search_input)
            .large()
            .prefix(
                Icon::new(IconName::Search)
                    .with_size(px(24.0))
                    .text_color(cx.theme().muted_foreground),
            )
            .p_0()
            .appearance(false);
        if !search_input.read(cx).value().is_empty() {
            let clear_input = search_input.clone();
            token_search = token_search.suffix(
                Button::new("clear-token-search")
                    .icon(Icon::new(IconName::CircleX).with_size(px(24.0)))
                    .ghost()
                    .h(px(36.0))
                    .w(px(36.0))
                    .p_0()
                    .tab_stop(false)
                    .text_color(cx.theme().muted_foreground)
                    .on_click(move |_, window, cx| {
                        clear_input.update(cx, |input, cx| input.set_value("", window, cx));
                    }),
            );
        }

        content
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label(format!(
                        "Showing {visible} of {}",
                        pluralize(total, "token")
                    ))),
            )
            .child(
                div()
                    .debug_selector(|| "token-inventory-list".to_owned())
                    .flex_1()
                    .min_h(px(260.0))
                    .w_full()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .w_full()
                            .border_1()
                            .border_color(cx.theme().border)
                            .bg(cx.theme().secondary)
                            .rounded(cx.theme().radius)
                            .overflow_hidden()
                            .flex_1()
                            .min_h_0()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .debug_selector(|| "token-inventory-search".to_owned())
                                    .flex_shrink_0()
                                    .px_3()
                                    .py_1()
                                    .border_b_1()
                                    .border_color(cx.theme().border)
                                    .child(token_search),
                            )
                            .child(
                                List::new(list)
                                    .scrollbar_visible(false)
                                    .flex_1()
                                    .min_h_0()
                                    .w_full(),
                            ),
                    ),
            )
    }

    fn render_updates(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut panel = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label(if crate::UPDATER_PUBLIC_KEY.is_empty() {
                        "This development build has no update verification key."
                    } else {
                        "Stable releases are downloaded and cryptographically verified before installation."
                    })),
            );
        panel = panel.child(
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(selectable_label(format!(
                    "Local update diagnostics: {}",
                    crate::release_check::update_diagnostics_path(&self.update_data_dir).display()
                ))),
        );
        panel = match &self.release_state {
            ReleaseDisplayState::Idle => panel.child(div().h(px(20.0))),
            ReleaseDisplayState::Checking => panel.child(
                h_flex()
                    .h(px(20.0))
                    .debug_selector(|| "release-check-progress".to_owned())
                    .gap_2()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(Spinner::new().small())
                    .child(selectable_label("Checking for updates…")),
            ),
            ReleaseDisplayState::Downloading => panel.child(
                h_flex()
                    .gap_2()
                    .child(Spinner::new())
                    .child(selectable_label("Downloading and verifying the update…")),
            ),
            ReleaseDisplayState::Ready { check, update } => panel
                .child(
                    div()
                        .font_semibold()
                        .child(check.latest_version.as_ref().map_or_else(
                            || "Latest version unavailable".to_owned(),
                            |version| format!("Latest published version: {version}"),
                        )),
                )
                .when(check.update_available, |panel| {
                    panel.child(selectable_label("A newer release is available."))
                })
                .when_some(update.as_ref(), |panel, update| {
                    panel.child(
                        app_button("install-signed-update")
                            .self_start()
                            .label(format!("Install {}", update.version()))
                            .primary()
                            .on_click(cx.listener(|view, _, window, cx| {
                                view.confirm_update_installation(window, cx);
                            })),
                    )
                })
                .when(check.update_available && update.is_none(), |panel| {
                    panel.child(
                        app_button("open-latest-release")
                            .self_start()
                            .label("View latest release")
                            .on_click(|_, _, cx| cx.open_url(LATEST_RELEASE_URL)),
                    )
                }),
            ReleaseDisplayState::Failed(error) => panel.child(
                div()
                    .text_color(cx.theme().danger)
                    .child(selectable_label(error.clone())),
            ),
        };
        let checking = matches!(&self.release_state, ReleaseDisplayState::Checking);
        let downloading = matches!(&self.release_state, ReleaseDisplayState::Downloading);
        panel = panel.child(
            app_button("check-latest-release")
                .debug_selector(|| "check-latest-release".to_owned())
                .self_start()
                // Keep the action in place; the status line above swaps to a
                // spinner and progress copy while this control is disabled.
                .label("Check latest version")
                .disabled(checking || downloading)
                .on_click(cx.listener(|view, _, _, cx| view.check_latest_release(cx))),
        );
        settings_section(
            "Updates",
            GroupBox::new().id("software-updates").child(panel),
        )
    }

    fn route_panel(&self, cx: &mut Context<Self>) -> gpui::Div {
        match self.route {
            Route::Overview => self.render_portfolio(cx),
            Route::Activity => self.render_activity(cx),
            Route::Accounts => self.render_accounts(cx),
            Route::Policies => self.render_policies(cx),
            Route::Networks => self.render_networks(cx),
            Route::Automations => self.render_automations(cx),
            Route::Tokens => self.render_tokens(cx),
            Route::WalletConnect => self.render_walletconnect(cx),
            Route::Settings => self.render_settings(cx),
        }
    }

    fn render_review_fact(
        fact: &ApprovalFact,
        section_kind: ApprovalSectionKind,
        section_id: &str,
        index: usize,
        cx: &App,
    ) -> gpui::Div {
        let fact_id = SharedString::from(format!("review-fact-{section_id}-{index}"));
        if section_kind == ApprovalSectionKind::Effects {
            if fact.label.is_empty() {
                return div().pl_3().child(
                    selectable_text(fact_id, &fact.value)
                        .text_sm()
                        .text_color(cx.theme().muted_foreground),
                );
            }
            let amount_color = if fact.value.trim_start().starts_with('-') {
                cx.theme().danger
            } else {
                cx.theme().foreground
            };
            let (asset, exact_asset) = balance_effect_asset(&fact.label);
            return div()
                .min_w_0()
                .flex()
                .flex_wrap()
                .items_start()
                .justify_between()
                .gap_3()
                .child(
                    div()
                        .min_w_0()
                        .flex_1()
                        .flex_basis(px(210.0))
                        .flex()
                        .flex_col()
                        .child(div().font_semibold().child(asset))
                        .when_some(exact_asset, |asset, exact| {
                            asset.child(
                                selectable_text(
                                    SharedString::from(format!("{fact_id}-asset")),
                                    &exact,
                                )
                                .min_w_0()
                                .max_w_full()
                                .truncate()
                                .font_family(MONO_FONT_FAMILY)
                                .text_xs()
                                .text_color(cx.theme().muted_foreground),
                            )
                        }),
                )
                .child(
                    selectable_text(SharedString::from(format!("{fact_id}-amount")), &fact.value)
                        .min_w_0()
                        .flex_1()
                        .flex_basis(px(240.0))
                        .text_lg()
                        .font_semibold()
                        .text_color(amount_color)
                        .whitespace_normal(),
                );
        }

        if section_kind == ApprovalSectionKind::Action && fact.label == "What it does" {
            return div()
                .flex()
                .flex_col()
                .gap_1()
                .child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child("HUMAN-READABLE INTERPRETATION"),
                )
                .child(
                    selectable_text(fact_id, &fact.value)
                        .text_lg()
                        .font_semibold(),
                );
        }

        let exact_value = matches!(fact.label.as_str(), "Address" | "Sender" | "Target")
            || fact.label.ends_with(" hash")
            || fact.label.ends_with(" digest");
        div()
            .min_w_0()
            .flex()
            .flex_wrap()
            .items_start()
            .gap_2()
            .child(
                div()
                    .flex_none()
                    .w(px(138.0))
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(if fact.label.is_empty() {
                        "·".to_owned()
                    } else {
                        fact.label.clone()
                    }),
            )
            .child(
                selectable_text(fact_id, &fact.value)
                    .min_w_0()
                    .flex_1()
                    .text_sm()
                    .when(exact_value, |value| value.font_family(MONO_FONT_FAMILY)),
            )
    }

    fn render_review_section(section: &ApprovalSection, section_id: &str, cx: &App) -> gpui::Div {
        let (icon, heading_color) = match section.kind {
            ApprovalSectionKind::Effects => (IconName::Star, cx.theme().foreground),
            ApprovalSectionKind::Action => (IconName::Inspector, cx.theme().foreground),
            ApprovalSectionKind::Fees => (IconName::Frame, cx.theme().muted_foreground),
            ApprovalSectionKind::Details => (IconName::Inspector, cx.theme().muted_foreground),
        };
        div()
            .w_full()
            .min_w_0()
            .p_4()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().secondary)
            .flex()
            .flex_col()
            .gap_3()
            .child(
                h_flex()
                    .gap_2()
                    .text_color(heading_color)
                    .child(Icon::new(icon).small())
                    .child(div().font_semibold().child(section.heading.clone())),
            )
            .children(section.facts.iter().enumerate().map(|(index, fact)| {
                Self::render_review_fact(fact, section.kind, section_id, index, cx)
            }))
    }

    fn render_review_simulation(
        simulation: &ekubo_wallet_core::simulation::SimulationResult,
        cx: &App,
    ) -> gpui::Div {
        let (icon, color, title) = if simulation.simulation.success {
            (
                IconName::CircleCheck,
                cx.theme().primary,
                "Simulation succeeded",
            )
        } else {
            (
                IconName::TriangleAlert,
                cx.theme().danger,
                "Simulation failed",
            )
        };
        let policy = match simulation.policy_outcome {
            ekubo_wallet_core::core::policy::PolicyOutcome::Allowed => {
                "The active policy allows this transaction."
            }
            ekubo_wallet_core::core::policy::PolicyOutcome::RequiresApproval => {
                "The active policy requires this human approval."
            }
            ekubo_wallet_core::core::policy::PolicyOutcome::Rejected => {
                "The active policy rejects this transaction."
            }
        };
        let execution = match simulation.execution_mode {
            ekubo_wallet_core::simulation::ExecutionMode::Direct => "direct transaction",
            ekubo_wallet_core::simulation::ExecutionMode::CaliburBatch => "atomic batch",
        };
        div()
            .w_full()
            .p_4()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(color)
            .flex()
            .flex_col()
            .gap_1()
            .child(
                h_flex()
                    .gap_2()
                    .text_color(color)
                    .child(Icon::new(icon).small())
                    .child(div().font_semibold().child(title)),
            )
            .child(div().text_sm().child(format!(
                "{policy} Results are from block {} using a {execution}.",
                simulation.block_number
            )))
    }

    fn render_review_overlay(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(active) = &self.active_review else {
            return div().into_any_element();
        };
        let generation = active.state.generation();
        let document = active.state.document_arc();
        let selection_is_complete = active.selection_is_complete();
        let approve_enabled =
            active.state.approve_enabled() && !active.awaiting_refresh && selection_is_complete;
        // Two different things hold approval back, and one instruction for
        // both would send a reader who has already scrolled to the end back to
        // scroll again.
        let approve_blocked_reason = if selection_is_complete {
            "Scroll to the end to enable approval"
        } else {
            "Choose an account to enable approval"
        };
        let can_refresh = matches!(
            active.completion,
            Some(ActiveReviewCompletion::Transaction(_))
        );
        // What the two decisions are called, and which of them is the
        // dangerous one.
        //
        // Reject was red and approve was purple in every review, which is
        // right when approving is what lets something happen. Removing an
        // account inverts it: approving destroys a key, and the red sat on the
        // button that keeps it. A reader who reads only the colour was being
        // pointed at the safe choice as though it were the costly one.
        let decisions = review_decision_labels(active.completion.as_ref());
        let rows = active.detail_rows.clone();
        let simulation = active.simulation.clone();
        let list_state = active.scroll_handle.clone();
        let end_rendered = active.end_rendered.clone();
        let row_count = rows.len();
        let selected_wallet_connect_account = active.completion.as_ref().and_then(|completion| {
            let ActiveReviewCompletion::WalletConnect {
                selected_account, ..
            } = completion
            else {
                return None;
            };
            *selected_account
        });
        let wallet_connect_accounts = active.wallet_connect_accounts.clone();
        let editor = cx.entity().downgrade();
        if active.scroll_handler_generation.get() != Some(generation) {
            active.scroll_handler_generation.set(Some(generation));
            let scroll_editor = editor.clone();
            list_state.set_scroll_handler(move |_, _, cx| {
                let scroll_editor = scroll_editor.clone();
                // GPUI invokes this callback while the list state's RefCell is
                // mutably borrowed. Defer the geometry read until that borrow
                // has been released.
                cx.defer(move |cx| {
                    let _ = scroll_editor.update(cx, |view, cx| {
                        view.update_review_scroll_state(generation, cx);
                    });
                });
            });
        }
        let review_body = variable_list(list_state.clone(), move |row_index, _, cx| {
            let Some(row) = rows.get(row_index).copied() else {
                return div().into_any_element();
            };
            if row_index + 1 == row_count && !end_rendered.swap(true, Ordering::AcqRel) {
                let end_editor = editor.clone();
                cx.defer(move |cx| {
                    let _ = end_editor.update(cx, |view, cx| {
                        view.update_review_scroll_state(generation, cx);
                    });
                });
            }
            let content = match row {
                SecurityReviewDetailRow::Prelude => {
                    let mut prelude = div()
                        .w_full()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap_4()
                        .child(
                            selectable_text(("review-title", generation), &document.request.title)
                                .text_3xl()
                                .font_medium(),
                        )
                        .child(
                            selectable_text(
                                ("review-summary", generation),
                                &document.request.summary,
                            )
                            .text_color(cx.theme().muted_foreground),
                        );
                    if let Some(simulation) = simulation.as_deref() {
                        prelude = prelude.child(Self::render_review_simulation(simulation, cx));
                    }
                    prelude.into_any_element()
                }
                SecurityReviewDetailRow::Section(section_index) => {
                    let Some(section) = document.request.sections.get(section_index) else {
                        return div().into_any_element();
                    };
                    Self::render_review_section(
                        section,
                        &format!("{generation}-section-{section_index}"),
                        cx,
                    )
                    .into_any_element()
                }
                SecurityReviewDetailRow::WarningsHeading => h_flex()
                    .gap_2()
                    .text_color(cx.theme().warning)
                    .child(Icon::new(IconName::TriangleAlert).small())
                    .child(div().font_semibold().child("Important warnings"))
                    .into_any_element(),
                SecurityReviewDetailRow::Warning(warning_index) => {
                    let Some(warning) = document.request.warnings.get(warning_index) else {
                        return div().into_any_element();
                    };
                    div()
                        .id(SharedString::from(format!(
                            "review-warning-{generation}-{warning_index}"
                        )))
                        .p_3()
                        .rounded(cx.theme().radius_lg)
                        .border_1()
                        .border_color(cx.theme().warning)
                        .child(selectable_text(
                            SharedString::from(format!(
                                "review-warning-text-{generation}-{warning_index}"
                            )),
                            warning,
                        ))
                        .into_any_element()
                }
                SecurityReviewDetailRow::WalletConnectAccounts => {
                    let Some(accounts) = wallet_connect_accounts.as_ref() else {
                        return div().into_any_element();
                    };
                    let selected_account = selected_wallet_connect_account;
                    let account_editor = editor.clone();
                    div()
                        .w_full()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(div().font_semibold().child("Account to expose"))
                        .child(
                            div()
                                .text_sm()
                                .text_color(if selected_account.is_none() {
                                    cx.theme().warning
                                } else {
                                    cx.theme().muted_foreground
                                })
                                .child(if selected_account.is_none() {
                                    "Choose which account this dapp may see. Nothing is exposed \
                                     until you pick one."
                                } else {
                                    "Only the account below is exposed to this dapp."
                                }),
                        )
                        .child(div().flex().flex_wrap().gap_2().children(
                            accounts.iter().enumerate().map(move |(index, account_id)| {
                                let account_editor = account_editor.clone();
                                let chosen = selected_account == Some(index);
                                app_button(SharedString::from(format!("wc-account-{index}")))
                                    .label(account_id.clone())
                                    .toggled(chosen)
                                    .when(chosen, ButtonVariants::primary)
                                    .on_click(move |_, _, cx| {
                                        let _ = account_editor.update(cx, |view, cx| {
                                            view.select_walletconnect_account(
                                                generation, index, cx,
                                            );
                                        });
                                    })
                            }),
                        ))
                        .into_any_element()
                }
                SecurityReviewDetailRow::RequestDetails => Self::render_review_section(
                    &ApprovalSection {
                        kind: ApprovalSectionKind::Details,
                        heading: "Request details".to_owned(),
                        facts: document.request.facts.clone(),
                    },
                    &format!("{generation}-request-details"),
                    cx,
                )
                .into_any_element(),
                SecurityReviewDetailRow::ExactDataHeading => div()
                    .w_full()
                    .p_4()
                    .rounded(cx.theme().radius_lg)
                    .border_1()
                    .border_color(cx.theme().border)
                    .bg(cx.theme().secondary)
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .min_w_0()
                            .child(div().font_semibold().child("Exact data"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("The complete bytes are always part of this review."),
                            ),
                    )
                    .into_any_element(),
                SecurityReviewDetailRow::ExactPayloadHeading(payload_index) => {
                    if document.exact_payloads.get(payload_index).is_none() {
                        return div().into_any_element();
                    }
                    let copy_document = document.clone();
                    div()
                        .w_full()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            h_flex()
                                .w_full()
                                .justify_between()
                                .gap_2()
                                .child(div().font_semibold().child(if payload_index == 0 {
                                    "Execution plan JSON".to_owned()
                                } else {
                                    format!("Action {payload_index} exact calldata")
                                }))
                                .child(lazy_copy_button(
                                    SharedString::from(format!(
                                        "copy-review-payload-{generation}-{payload_index}"
                                    )),
                                    Rc::new(move || {
                                        copy_document
                                            .exact_payloads
                                            .get(payload_index)
                                            .cloned()
                                            .unwrap_or_default()
                                    }),
                                    "Copy exact review data",
                                )),
                        )
                        .into_any_element()
                }
                SecurityReviewDetailRow::ExactPayloadChunk {
                    payload_index,
                    start,
                    end,
                } => {
                    let Some(chunk) = document
                        .exact_payloads
                        .get(payload_index)
                        .and_then(|payload| payload.get(start..end))
                    else {
                        return div().into_any_element();
                    };
                    Self::render_exact_payload_chunk(
                        format!("review-payload-{generation}-{payload_index}-{start}"),
                        chunk,
                        cx,
                    )
                    .into_any_element()
                }
            };
            div()
                .w_full()
                .min_w_0()
                .pb_4()
                .child(div().w_full().max_w(px(920.0)).mx_auto().child(content))
                .into_any_element()
        })
        .size_full()
        .pr_2();
        div()
            .absolute()
            .inset_0()
            .min_h_0()
            // Takes the mouse for the whole window: the page behind must not
            // scroll or answer clicks while a decision is on the screen.
            .occlude()
            .p_4()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .shadow_lg()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().flex().items_center().child(
                div().font_semibold().child("Security review").when(
                    !self.queued_reviews.is_empty(),
                    |title| {
                        title.child(
                            div()
                                .text_sm()
                                .font_normal()
                                .text_color(cx.theme().muted_foreground)
                                .child(format!(
                                    "{} more waiting behind this one",
                                    pluralize(self.queued_reviews.len(), "request")
                                )),
                        )
                    },
                ),
            ))
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .id(("review-scroll", generation))
                            .size_full()
                            .child(review_body),
                    )
                    .child({
                        self.review_overflow_indicator
                            .set_scroll_handle(active.scroll_handle.clone());
                        self.review_overflow_indicator.element()
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .justify_between()
                    .items_center()
                    // Only a transaction has a simulation to re-run. The other
                    // four kinds of review — a message, typed data, a
                    // connection, an account removal — rendered this button
                    // permanently greyed, which reads as a thing that is
                    // temporarily unavailable rather than one that was never
                    // going to apply. An empty slot keeps the decision buttons
                    // where they are.
                    .child(div().when(can_refresh, |slot| {
                        slot.child(
                            app_button(("review-refresh", generation))
                                .label("Re-simulate")
                                .loading(active.awaiting_refresh)
                                .disabled(active.awaiting_refresh)
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    view.send_review_command(
                                        generation,
                                        GuiReviewCommand::Refresh,
                                        cx,
                                    );
                                })),
                        )
                    }))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap_2()
                            .when(!approve_enabled, |buttons| {
                                buttons.child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(approve_blocked_reason),
                                )
                            })
                            .child(
                                app_button(("review-select-reject", generation))
                                    .label(decisions.reject)
                                    .when(!decisions.approve_is_destructive, ButtonVariants::danger)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.decide_review(generation, ReviewDecision::Reject, cx);
                                    })),
                            )
                            .child(
                                app_button(("review-select-approve", generation))
                                    .label(decisions.approve)
                                    .when_else(
                                        decisions.approve_is_destructive,
                                        ButtonVariants::danger,
                                        ButtonVariants::primary,
                                    )
                                    .disabled(!approve_enabled)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.decide_review(generation, ReviewDecision::Approve, cx);
                                    })),
                            ),
                    ),
            )
            .focus_trap("security-review-focus", &self.modal_focus)
            .into_any_element()
    }

    fn render_legal_overlay(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(review) = &self.legal_review else {
            return div().into_any_element();
        };
        let rows = review.rows.clone();
        let row_count = rows.len();
        let end_rendered = review.end_rendered.clone();
        let viewed_to_end = review.viewed_to_end
            || legal_list_reached_end(&review.scroll_handle, &review.end_rendered);
        let document_title = review.document.title();
        let document = uniform_list(
            SharedString::from(format!("legal-document-{document_title}")),
            row_count,
            move |visible_range, _, cx| {
                if visible_range.end >= row_count {
                    end_rendered.store(true, Ordering::Release);
                }
                visible_range
                    .map(|index| {
                        let row = &rows[index];
                        let line = div()
                            .h(LEGAL_ROW_HEIGHT)
                            .w_full()
                            .min_w_0()
                            .max_w_full()
                            .flex_none()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .when(row.kind == LegalRowKind::Heading, |line| {
                                line.text_lg()
                                    .font_semibold()
                                    .text_color(cx.theme().foreground)
                            })
                            .when(row.kind == LegalRowKind::Body, |line| {
                                line.text_color(cx.theme().foreground)
                            })
                            .when(row.kind == LegalRowKind::Code, |line| {
                                line.px_1()
                                    .font_family(MONO_FONT_FAMILY)
                                    .bg(cx.theme().muted)
                                    .text_color(cx.theme().muted_foreground)
                            })
                            .child(selectable_legal_text(
                                SharedString::from(format!("legal-row-{document_title}-{index}")),
                                row.text.as_ref(),
                                row.link_url.as_deref(),
                            ));
                        line.into_any_element()
                    })
                    .collect::<Vec<_>>()
            },
        )
        .size_full()
        .track_scroll(&review.scroll_handle);
        div()
            .absolute()
            .inset_0()
            .min_h_0()
            // Takes the mouse for the whole window. A document that has to be
            // read to the end especially cannot have the wheel land on the page
            // behind it.
            .occlude()
            .p_4()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .shadow_lg()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().font_semibold().child(review.document.title()))
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(
                        div()
                            .id("legal-document-scroll")
                            .size_full()
                            .p_3()
                            .overflow_y_scroll()
                            .on_scroll_wheel(cx.listener(|view, _, window, cx| {
                                let digest = view
                                    .legal_review
                                    .as_ref()
                                    .map(|review| review.digest.clone());
                                if let Some(digest) = digest {
                                    cx.defer_in(window, move |view, _, cx| {
                                        view.update_legal_scroll_state(&digest, cx);
                                    });
                                }
                            }))
                            .child(document),
                    )
                    .child({
                        self.legal_overflow_indicator
                            .set_scroll_handle(review.scroll_handle.clone());
                        self.legal_overflow_indicator.element()
                    }),
            )
            .when_some(review.error.clone(), |panel, error| {
                panel.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(selectable_label(error)),
                )
            })
            .when(review.acceptance_required, |panel| {
                panel.child(
                    h_flex()
                        .w_full()
                        .flex_shrink_0()
                        .justify_between()
                        .gap_3()
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(if viewed_to_end {
                                    "Document read to end"
                                } else {
                                    "Scroll to the end to accept"
                                }),
                        )
                        .child(
                            app_button("accept-legal")
                                .label("Accept")
                                .primary()
                                .disabled(!viewed_to_end)
                                .on_click(cx.listener(|view, _, _, cx| {
                                    view.accept_legal(cx);
                                })),
                        ),
                )
            })
            .when(!review.acceptance_required, |panel| {
                panel.child(
                    app_button("close-legal-review")
                        .label("Close")
                        .primary()
                        .w_full()
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.close_overlay(cx);
                        })),
                )
            })
            .focus_trap("legal-review-focus", &self.modal_focus)
            .into_any_element()
    }

    fn render_account_security_overlay(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(export) = self.account_export.as_ref() else {
            return div().into_any_element();
        };
        let visible = export.lease.as_ref().and_then(ExportLease::visible_value);
        let remaining = export
            .lease
            .as_ref()
            .map_or(Duration::ZERO, ExportLease::remaining);
        let expired = export.lease.is_some() && visible.is_none();
        let panel = div()
            .size_full()
            .p_4()
            .rounded(cx.theme().radius_lg)
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .shadow_lg()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .text_xl()
                    .font_semibold()
                    .child(selectable_label("Export private key")),
            )
            .child(selectable_label(format!("Account: {}", export.wallet_id)))
            .child(selectable_label("Anyone with this key can move every asset the account holds, on every network, forever. Never paste it into a website, chat, issue, log, or agent prompt."))
            // Before the OS prompt, say what the prompt is for and what
            // follows it. That the reveal runs on a clock is something to know
            // before you are looking at a key you have to read in time.
            .when(export.lease.is_none(), |panel| {
                panel.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_label(format!(
                            "Your device will ask you to confirm. The key is then shown for {} seconds and hidden again; you can reveal it as often as you need.",
                            PRIVATE_KEY_REVEAL_DURATION.as_secs()
                        ))),
                )
            })
            .when_some(visible.as_ref(), |panel, value| {
                panel
                    .child(
                        div()
                            .p_3()
                            .rounded(cx.theme().radius)
                            .border_1()
                            .border_color(cx.theme().border)
                            .bg(cx.theme().secondary)
                            .font_family(MONO_FONT_FAMILY)
                            .child(value.to_string()),
                    )
                    .child(
                        h_flex()
                            .flex_wrap()
                            .gap_2()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(selectable_label(format!(
                                "Hidden again in {} seconds.",
                                remaining.as_secs().max(1)
                            )))
                            .child(selectable_label(
                                "Copying it also clears the clipboard 30 seconds later.",
                            )),
                    )
            })
            .when(expired, |panel| {
                panel.child(selectable_label(
                    "The key is hidden again. Reveal it once more if you still need it.",
                ))
            })
            .when_some(export.error.clone(), |panel, error| {
                panel.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(selectable_label(error)),
                )
            })
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(
                        app_button("close-account-export")
                            .label(if visible.is_some() { "Done" } else { "Close" })
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.clear_export_clipboard(cx);
                                view.account_export = None;
                                view.activate_next_waiting_surface(cx);
                                cx.notify();
                            })),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            // An expired reveal used to leave the panel with
                            // nothing but Close, so seeing the key again meant
                            // guessing that reopening the panel worked.
                            .when(export.lease.is_none() || expired, |buttons| {
                                buttons.child(
                                    app_button("authenticate-account-export")
                                        .label(match (export.authenticating, expired) {
                                            (true, _) => "Waiting for confirmation…",
                                            (false, true) => "Reveal again",
                                            (false, false) => "Confirm & reveal",
                                        })
                                        .danger()
                                        .disabled(export.authenticating)
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            view.authenticate_account_export(cx);
                                        })),
                                )
                            })
                            .when(visible.is_some(), |buttons| {
                                buttons.child(
                                    app_button("copy-account-export")
                                        .w(px(112.0))
                                        .icon(if export.copied {
                                            IconName::Check
                                        } else {
                                            IconName::Copy
                                        })
                                        .label(if export.copied { "Copied" } else { "Copy" })
                                        .disabled(export.copied)
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            view.copy_account_export(cx);
                                        })),
                                )
                            }),
                    ),
            );
        // The panel is inset from the window edge, so it cannot take the mouse
        // for the whole window by itself: the gutter around it left the page
        // behind live to the wheel. A full-window container that occludes puts
        // the panel exactly where `inset_4` did and locks everything under it.
        div()
            .absolute()
            .inset_0()
            .occlude()
            .p_4()
            .child(panel)
            .focus_trap("account-security-focus", &self.modal_focus)
            .into_any_element()
    }

    /// Page-level actions belong in the fixed header, not in the scrolling
    /// body: a refresh control that scrolls away is a control you cannot find
    /// while looking at what you wanted to refresh.
    fn route_header_actions(&self, cx: &mut Context<Self>) -> Option<gpui::Div> {
        match self.route {
            Route::Overview => {
                // With no account there is nothing to refresh, and the page
                // below is asking for one instead of showing balances. This
                // reads the same fact `render_portfolio` does, so the header
                // and the empty panel cannot disagree.
                if self
                    .cached_accounts()
                    .is_ok_and(<[WalletMetadata]>::is_empty)
                {
                    return None;
                }
                let loading = matches!(self.portfolio, PortfolioState::Loading);
                let no_networks = self
                    .cached_networks()
                    .unwrap_or_default()
                    .iter()
                    .all(|network| network.disabled || (network.testnet && !self.testnet_mode));
                Some(
                    div().flex_none().child(
                        app_button("refresh-portfolio")
                            .debug_selector(|| "refresh-portfolio".to_owned())
                            .label(if loading { "Refreshing…" } else { "Refresh" })
                            .disabled(loading || no_networks)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.refresh_portfolio(cx);
                            })),
                    ),
                )
            }
            Route::Networks => Some(
                div()
                    .debug_selector(|| "network-header-action".to_owned())
                    .flex_none()
                    .child(
                        app_button("open-custom-network-editor")
                            .label("Add custom network")
                            .primary()
                            .icon(IconName::Plus)
                            .disabled(self.network_editor_open)
                            .on_click(cx.listener(|view, _, window, cx| {
                                cx.stop_propagation();
                                view.open_new_network_editor(window, cx);
                            })),
                    ),
            ),
            _ => None,
        }
    }

    /// The account a page is showing is a property of the page, not a row in
    /// its body: it stays visible while balances load and while the body
    /// scrolls, and it is the same control on every page that has one.
    fn route_account_selector(&self, cx: &mut Context<Self>) -> Option<gpui::Div> {
        if !matches!(self.route, Route::Overview | Route::Policies) {
            return None;
        }
        let accounts = self.cached_accounts().ok()?;
        let labels = accounts
            .iter()
            .map(|account| account.id.clone())
            .collect::<Vec<_>>();
        match labels.as_slice() {
            [] => return None,
            // A lone account needs naming, not choosing.
            [only] => {
                return Some(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_text(
                            SharedString::from(format!("route-account-{}", self.route.label())),
                            &format!("Account · {only}"),
                        )),
                );
            }
            _ => {}
        }
        let switcher = if self.route == Route::Overview {
            account_switcher(
                "portfolio-account-tabs",
                &labels,
                clamped_portfolio_account_index(labels.len(), self.portfolio_account_index),
                cx.listener(|view, index: &usize, _, cx| {
                    view.select_portfolio_account(*index, cx);
                }),
            )
        } else {
            let selected = policy_selected_account_index(
                &labels,
                self.policy_editor
                    .as_ref()
                    .map(|editor| editor.wallet_id.as_str())
                    .or(self.policy_account_id.as_deref()),
            );
            let switch_accounts = labels.clone();
            account_switcher(
                "policy-account-tabs",
                &labels,
                selected,
                cx.listener(move |view, index: &usize, window, cx| {
                    if let Some(wallet_id) = switch_accounts.get(*index) {
                        view.open_policy_editor(wallet_id, window, cx);
                    }
                }),
            )
        };
        Some(div().w_full().child(switcher))
    }

    fn render_policy_editor(&self, cx: &mut Context<Self>) -> gpui::Div {
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_ref(), self.policy_json_input.as_ref())
        else {
            return div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .child(selectable_label("The policy editor is unavailable."));
        };

        let document = input.read(cx).value().to_string();
        let allow_anything_draft = serde_json::from_str(&document)
            .ok()
            .and_then(|value| WalletPolicy::parse(value).ok())
            .is_some_and(|policy| policy == WalletPolicy::allow_anything());
        let validated = editor
            .validation
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        let reviewed_exact_document =
            validated.is_some_and(|review| document == review.document.as_str());
        let can_view_previous =
            previous_policy_revision(editor.history_selection, editor.history.len()).is_some();

        let mut preview = GroupBox::new()
            .id("policy-full-screen-preview")
            .title("Review changes")
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(selectable_label(match editor.validation.as_ref() {
                        Some(Ok(_)) if reviewed_exact_document => {
                            "The permission changes below match this exact draft."
                        }
                        Some(Ok(_)) => {
                            "This draft changed after its last preview. Validate it again."
                        }
                        Some(Err(_)) => {
                            "Fix the policy validation error, then preview its changes."
                        }
                        None => {
                            "Validate the JSON and review its permission changes before installation."
                        }
                    })),
            )
            .child(
                app_button("validate-policy-draft-full-screen")
                    .self_start()
                    .label(if reviewed_exact_document {
                        "Refresh preview"
                    } else {
                        "Validate & preview"
                    })
                    .when(!reviewed_exact_document, ButtonVariants::primary)
                    .disabled(self.policy_installing)
                    .on_click(cx.listener(|view, _, window, cx| {
                        view.validate_policy_editor(window, cx);
                    })),
            );

        if let Some(Ok(review)) = editor.validation.as_ref()
            && reviewed_exact_document
        {
            let mut changes = div().flex().flex_col().gap_2();
            if review.diff.is_empty() {
                changes = changes.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(selectable_label("No permission changes.")),
                );
            } else {
                for (index, line) in review.diff.iter().enumerate() {
                    changes = changes.child(
                        div()
                            .id(SharedString::from(format!(
                                "policy-full-screen-diff-{index}"
                            )))
                            .p_2()
                            .rounded(cx.theme().radius)
                            .bg(cx.theme().secondary)
                            .font_family(MONO_FONT_FAMILY)
                            .text_sm()
                            .child(selectable_text(
                                ("policy-full-screen-diff-line", index),
                                line,
                            )),
                    );
                }
            }
            preview = preview.child(changes).child(
                app_button("install-policy-draft-full-screen")
                    .debug_selector(|| "install-policy-draft-full-screen".to_owned())
                    .self_start()
                    .label(if self.policy_installing {
                        "Authenticating…"
                    } else {
                        "Authenticate & install"
                    })
                    .primary()
                    .loading(self.policy_installing)
                    .disabled(self.policy_installing)
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.install_policy_editor(cx);
                    })),
            );
        }

        let proposal_panel: Option<AnyElement> = match self.cached_reviews().map(|reviews| {
            policy_proposal_for_account(&reviews.policy_proposals, &editor.wallet_id)
        }) {
            Ok(Some(proposal)) => {
                let current_result = self.cached_policy(&editor.wallet_id);
                let current_error = current_result
                    .as_ref()
                    .err()
                    .map(|error| format!("Could not read active policy: {error:#}"));
                let applicable = current_result
                    .ok()
                    .flatten()
                    .is_some_and(|policy| policy.revision == proposal.source_revision);
                let review_proposal = proposal.clone();
                let reject_proposal = proposal.clone();
                Some(
                    GroupBox::new()
                        .id("policy-full-screen-proposal")
                        .title("Agent proposal")
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(div().text_sm().child(selectable_text(
                                    format!(
                                        "policy-full-screen-proposal-rationale-{}",
                                        proposal.wallet_id
                                    ),
                                    &ekubo_wallet_core::sanitize::terminal_safe_multiline(
                                        &proposal.rationale,
                                    ),
                                )))
                                .when(!applicable && current_error.is_none(), |card| {
                                    card.child(
                                        div().text_sm().text_color(cx.theme().danger).child(
                                            selectable_label("Superseded by a policy change"),
                                        ),
                                    )
                                })
                                .when_some(current_error, |card, error| {
                                    card.child(
                                        div()
                                            .text_sm()
                                            .text_color(cx.theme().danger)
                                            .child(selectable_label(error)),
                                    )
                                })
                                .child(
                                    div()
                                        .flex()
                                        .flex_wrap()
                                        .gap_2()
                                        .child(
                                            app_button("review-policy-proposal-full-screen")
                                                .label("Review in editor")
                                                .primary()
                                                .disabled(!applicable)
                                                .on_click(cx.listener(
                                                    move |view, _, window, cx| {
                                                        view.open_policy_proposal(
                                                            review_proposal.clone(),
                                                            window,
                                                            cx,
                                                        );
                                                    },
                                                )),
                                        )
                                        .child(
                                            app_button("reject-policy-proposal-full-screen")
                                                .label("Reject proposal")
                                                .danger()
                                                .on_click(cx.listener(move |view, _, _, cx| {
                                                    view.reject_policy_proposal(
                                                        &reject_proposal,
                                                        cx,
                                                    );
                                                })),
                                        ),
                                ),
                        )
                        .into_any_element(),
                )
            }
            Ok(None) => None,
            Err(error) => Some(
                selectable_error_alert(
                    "policy-full-screen-proposal-error",
                    format!("Policy proposal unavailable: {error:#}"),
                )
                .into_any_element(),
            ),
        };

        let sidebar = div()
            .debug_selector(|| "policy-full-screen-sidebar".to_owned())
            // Fifteen percent narrower than the previous 360px rail, leaving
            // the JSON editor useful at the window's minimum width.
            .w(px(306.0))
            .h_full()
            .min_h_0()
            .flex_none()
            .overflow_y_scrollbar()
            .flex()
            .flex_col()
            .gap_3()
            .when_some(self.policy_action_error.clone(), |sidebar, error| {
                sidebar.child(
                    div()
                        .id("policy-full-screen-action-error")
                        .role(Role::Alert)
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(selectable_label(error)),
                )
            })
            .when_some(
                editor
                    .validation
                    .as_ref()
                    .and_then(|validation| validation.as_ref().err().cloned()),
                |sidebar, error| {
                    sidebar.child(
                        div()
                            .id("policy-full-screen-validation-error")
                            .role(Role::Alert)
                            .p_3()
                            .rounded(cx.theme().radius)
                            .border_1()
                            .border_color(cx.theme().danger)
                            .text_sm()
                            .text_color(cx.theme().danger)
                            .child(selectable_label(error)),
                    )
                },
            )
            .when_some(proposal_panel, gpui::ParentElement::child)
            .child(
                GroupBox::new()
                    .id("policy-full-screen-presets")
                    .title("Policy presets")
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .items_start()
                            .gap_2()
                            .child(
                                app_button("reset-policy-draft-full-screen")
                                    .label("Review every transaction")
                                    .disabled(self.policy_installing)
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.reset_policy_editor(window, cx);
                                    })),
                            )
                            .child(
                                app_button("disable-signing-policy-draft-full-screen")
                                    .label("Disable transaction signing")
                                    .disabled(self.policy_installing)
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.apply_disable_signing_policy(window, cx);
                                    })),
                            )
                            .child(
                                app_button("allow-anything-policy-draft-full-screen")
                                    .icon(IconName::TriangleAlert)
                                    .label("Allow anything")
                                    .disabled(self.policy_installing)
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.apply_allow_anything_policy(window, cx);
                                    })),
                            ),
                    ),
            )
            .child(
                app_button("previous-policy-revision")
                    .debug_selector(|| "previous-policy-revision".to_owned())
                    .w_full()
                    .label("Previous revision")
                    .disabled(!can_view_previous || self.policy_installing)
                    .on_click(cx.listener(|view, _, window, cx| {
                        view.view_previous_policy_revision(window, cx);
                    })),
            )
            .child(preview);

        div()
            .debug_selector(|| "policy-editor-layout".to_owned())
            .flex_1()
            .h_full()
            .min_w_0()
            .min_h_0()
            .overflow_hidden()
            .flex()
            .flex_col()
            .bg(cx.theme().background)
            .child(
                div()
                    .flex_none()
                    .px_4()
                    .py_3()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .min_w_0()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(div().text_xl().font_semibold().child("Policy editor"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(selectable_label(POLICY_EDITOR_DESCRIPTION)),
                            ),
                    ),
            )
            .when_some(self.route_account_selector(cx), |editor, selector| {
                editor.child(
                    div()
                        .flex_none()
                        .px_4()
                        .py_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .child(selector),
                )
            })
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .p_4()
                    .flex()
                    .gap_4()
                    .child(
                        div()
                            .debug_selector(|| "policy-full-screen-editor".to_owned())
                            .min_w_0()
                            .min_h_0()
                            .flex_1()
                            .p_3()
                            .rounded(cx.theme().radius_lg)
                            .border_1()
                            .border_color(cx.theme().border)
                            .bg(cx.theme().secondary)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .w_full()
                                    .min_w_0()
                                    .flex_none()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .debug_selector(|| "policy-json-heading".to_owned())
                                            .text_sm()
                                            .font_medium()
                                            .child("Policy JSON"),
                                    )
                                    .child(
                                        div()
                                            .debug_selector(|| "policy-json-guidance".to_owned())
                                            .w_full()
                                            .min_w_0()
                                            .whitespace_normal()
                                            .text_xs()
                                            .text_color(cx.theme().muted_foreground)
                                            .child("JSON syntax and policy structure are checked when you preview"),
                                    ),
                            )
                            .when(allow_anything_draft, |editor| {
                                editor.child(
                                    div()
                                        .id("policy-full-screen-unrestricted-warning")
                                        .role(Role::Alert)
                                        .p_2()
                                        .rounded(cx.theme().radius)
                                        .border_1()
                                        .border_color(cx.theme().danger)
                                        .text_sm()
                                        .text_color(cx.theme().danger)
                                        .child(selectable_label("Danger: this policy automatically signs every call on every chain.")),
                                )
                            })
                            // Same column floor and scrolling viewport as the
                            // settings-page editor; both drive the one
                            // `policy_json_input`, so a line that wraps in one
                            // and not the other would be the surprise.
                            .child(
                                div()
                                    .id("policy-full-screen-json-viewport")
                                    .debug_selector(|| {
                                        "policy-full-screen-json-viewport".to_owned()
                                    })
                                    .overflow_x_scroll()
                                    .w_full()
                                    .min_w_0()
                                    .min_h_0()
                                    .flex_1()
                                    .flex()
                                    .child(
                                        div()
                                            .debug_selector(|| {
                                                "policy-full-screen-json-control".to_owned()
                                            })
                                            .flex_1()
                                            .min_w(policy_editor_min_width(cx))
                                            .min_h_0()
                                            .h_full()
                                            .child(
                                                app_input(input, cx)
                                                    .aria_label("Policy JSON")
                                                    .font_family(MONO_FONT_FAMILY)
                                                    .size_full()
                                                    .min_w_0()
                                                    .min_h_0(),
                                            ),
                                    ),
                            ),
                    )
                    .child(sidebar),
            )
    }

    fn render_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let route_panel = if self.desktop_snapshot.is_none() {
            div()
                .flex()
                .items_center()
                .gap_2()
                .text_color(cx.theme().muted_foreground)
                .child(Spinner::new())
                .child(selectable_label("Loading wallet data…"))
        } else {
            self.route_panel(cx)
        };
        let header = div()
            .debug_selector(|| "route-header-inner".to_owned())
            .w_full()
            .max_w(PAGE_CONTENT_MAX_WIDTH)
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .w_full()
                    .flex()
                    .items_start()
                    .gap_2()
                    .child(
                        div()
                            .min_w_0()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .truncate()
                                    .text_3xl()
                                    .font_medium()
                                    .child(self.route.label()),
                            )
                            // A page title names the screen; this line says
                            // what the screen is for, so nobody has to open a
                            // tab to find out whether it is the one they want.
                            .child(
                                div()
                                    .text_sm()
                                    .whitespace_normal()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(self.route.description()),
                            ),
                    )
                    .when_some(self.route_header_actions(cx), |header, actions| {
                        header.child(actions)
                    })
                    .when(
                        self.desktop_snapshot_loading && self.route != Route::Overview,
                        |header| {
                            header.child(
                                div()
                                    .id("route-header-loading")
                                    .child(Spinner::new().small()),
                            )
                        },
                    ),
            )
            .when_some(self.route_account_selector(cx), |header, selector| {
                header.child(selector)
            });
        let content = div()
            .debug_selector(|| "route-content-inner".to_owned())
            .w_full()
            .min_w_0()
            .max_w(PAGE_CONTENT_MAX_WIDTH)
            .mx_auto()
            .flex()
            .flex_col()
            .gap_4()
            .when(self.route == Route::Tokens, |content| {
                content.flex_1().min_h_0()
            })
            .when(self.route != Route::Tokens, |content| {
                content.flex_shrink_0()
            })
            .when_some(self.desktop_snapshot_error.clone(), |content, error| {
                content.child(
                    selectable_error_alert("desktop-snapshot-error", error)
                        .title("Wallet data unavailable"),
                )
            })
            .when_some(
                self.route_errors.get(&self.route).cloned(),
                |content, error| {
                    content.child(
                        selectable_error_alert(
                            SharedString::from(format!("route-error-{}", self.route.label())),
                            error,
                        )
                        .title("Action could not be completed"),
                    )
                },
            )
            .child(route_panel);
        let scroll_content = div()
            .debug_selector(|| "route-scroll-content".to_owned())
            .w_full()
            .min_w_0()
            .px_5()
            .pb_5()
            .when(self.route == Route::Tokens, |scroll_content| {
                scroll_content.h_full().min_h_0().flex().flex_col()
            })
            .child(content);
        div()
            .flex_1()
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            .overflow_hidden()
            .child(
                div()
                    .flex_shrink_0()
                    .px_5()
                    .pt_5()
                    .pb_3()
                    .bg(cx.theme().background)
                    .flex()
                    .flex_col()
                    .items_center()
                    .child(header),
            )
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .id("route-content-scroll")
                            .debug_selector(|| "route-content-scroll".to_owned())
                            .size_full()
                            .track_scroll(&self.route_scroll_handle)
                            .overflow_y_scroll()
                            .child(scroll_content),
                    )
                    .child(self.route_overflow_indicator.element()),
            )
    }

    fn render_palette(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = div()
            .absolute()
            .top(px(54.0))
            .left(px(58.0))
            .w(px(420.0))
            .max_h(px(460.0))
            .p_3()
            .rounded(cx.theme().radius_lg)
            .shadow_lg()
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().popover)
            // A press anywhere off the panel dismisses it, which is what every
            // other launcher does and what the scrim below makes possible to
            // aim at. Escape already worked; a mouse had no way out.
            .on_mouse_down_out(cx.listener(|view, _, _, cx| {
                view.command_palette = false;
                cx.notify();
            }))
            .child(
                h_flex()
                    .w_full()
                    .mb_2()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(div().font_semibold().child("Go to…"))
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("Esc to close"),
                    ),
            )
            .when_some(self.command_palette_list.as_ref(), |palette, list| {
                palette.child(
                    List::new(list)
                        .h(px(390.0))
                        .w_full()
                        .border_1()
                        .border_color(cx.theme().border)
                        .rounded(cx.theme().radius),
                )
            });
        // The palette used to float over a live page: the wheel scrolled
        // whatever was behind it, and a press landed on whichever control was
        // underneath. Every other surface that takes over this window
        // occludes; this one is no different for as long as it is open.
        div().absolute().inset_0().occlude().child(palette)
    }
}

impl Render for WalletWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.attach_window(window, cx);
        if let Some(review) = self.active_review.as_mut() {
            let generation = review.state.generation();
            if review.scroll_layout_ready {
                self.update_review_scroll_state(generation, cx);
            } else if !review.scroll_check_scheduled {
                review.scroll_check_scheduled = true;
                cx.on_next_frame(window, move |view, window, cx| {
                    if let Some(review) = view.active_review.as_mut()
                        && review.state.generation() == generation
                    {
                        review.scroll_layout_ready = true;
                    }
                    view.update_review_scroll_state(generation, cx);
                    if view.active_review.as_ref().is_some_and(|review| {
                        review.state.generation() == generation && !review.state.approve_enabled()
                    }) {
                        // Scroll geometry may settle one frame after the
                        // content first renders. Recheck once so a document
                        // that already fits never asks for a meaningless
                        // scroll gesture.
                        cx.on_next_frame(window, move |view, _, cx| {
                            view.update_review_scroll_state(generation, cx);
                        });
                    }
                });
            }
        }
        if let Some(review) = self.legal_review.as_mut()
            && !review.scroll_check_scheduled
        {
            review.scroll_check_scheduled = true;
            let digest = review.digest.clone();
            cx.on_next_frame(window, move |view, _, cx| {
                view.update_legal_scroll_state(&digest, cx);
            });
        }
        // A notification names a record by id, and the inbox keeps only the
        // most recent few hundred. Clicking a banner for one that has aged out
        // used to leave `selected_record` set: the detail overlay drew nothing,
        // but the window still counted a modal as open and moved focus into a
        // trap that was not on the screen. Drop the selection instead, so the
        // click lands on the inbox it was always about.
        if let Some(request_id) = self.selected_record
            && let Ok(records) = self.cached_activity_records()
            && !records
                .iter()
                .any(|record| record.request_id() == request_id)
        {
            self.selected_record = None;
        }
        let modal_open = self.active_review.is_some()
            || self.legal_review.is_some()
            || self.account_export.is_some()
            || self.selected_record.is_some();
        if modal_open && !self.modal_focus.contains_focused(window, cx) {
            self.modal_focus.focus(window, cx);
        }
        if self.route == Route::Overview
            && !self.legal_gate
            && matches!(self.portfolio, PortfolioState::Idle)
        {
            self.refresh_portfolio(cx);
        }
        if self.route == Route::Policies
            && !self.legal_gate
            && self.policy_editor.is_none()
            && self.policy_action_error.is_none()
        {
            let default_wallet = self.cached_accounts().ok().and_then(|accounts| {
                policy_account_to_open(accounts, self.policy_account_id.as_deref())
                    .map(str::to_owned)
            });
            if let Some(wallet_id) = default_wallet {
                self.open_policy_editor(&wallet_id, window, cx);
            }
        }
        let policy_editor_layout = self.route == Route::Policies
            && self.policy_editor.is_some()
            && self.policy_json_input.is_some();
        div()
            .key_context("Wallet")
            .on_action(cx.listener(Self::toggle_palette))
            .on_action(cx.listener(|view, _: &CloseOverlay, _, cx| {
                view.close_overlay(cx);
            }))
            .relative()
            .size_full()
            .flex()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(self.render_sidebar(cx))
            .when(!policy_editor_layout, |view| {
                view.child(self.render_content(cx))
            })
            .when(policy_editor_layout, |view| {
                view.child(self.render_policy_editor(cx))
            })
            .when(self.command_palette, |view| {
                view.child(self.render_palette(cx))
            })
            .when(self.active_review.is_some(), |view| {
                view.child(self.render_review_overlay(cx))
            })
            .when(self.legal_review.is_some(), |view| {
                view.child(self.render_legal_overlay(cx))
            })
            .when(self.account_export.is_some(), |view| {
                view.child(self.render_account_security_overlay(cx))
            })
            // Below the decision surfaces: a security review that arrives
            // while a receipt is open must be the thing in front.
            .when(
                self.selected_record.is_some() && self.active_review.is_none(),
                |view| view.child(self.render_activity_detail_overlay(cx)),
            )
    }
}

/// Hosts the component library's overlay layers outside `WalletWindow`.
/// Dialog builders may read the wallet entity while this separate entity is
/// rendering, avoiding both an omitted layer and a re-entrant entity read.
struct ComponentLayerHost {
    content: AnyView,
}

impl ComponentLayerHost {
    fn new(content: impl Into<AnyView>) -> Self {
        Self {
            content: content.into(),
        }
    }
}

impl Render for ComponentLayerHost {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let sheet_layer = Root::render_sheet_layer(window, cx);
        let dialog_layer = Root::render_dialog_layer(window, cx);
        let notification_layer = Root::render_notification_layer(window, cx);

        div()
            .relative()
            .size_full()
            .child(self.content.clone())
            .children(sheet_layer)
            .children(dialog_layer)
            .children(notification_layer)
    }
}

type WalletWindowSlot = Rc<RefCell<Option<WindowHandle<Root>>>>;
#[cfg(target_os = "macos")]
type DockReopenTarget = Rc<RefCell<Option<(Entity<WalletWindow>, WalletWindowSlot)>>>;

fn dark_appearance(appearance: WindowAppearance) -> bool {
    matches!(
        appearance,
        WindowAppearance::Dark | WindowAppearance::VibrantDark
    )
}

#[derive(Clone, Copy)]
struct InterfaceInteractionPalette {
    button: u32,
    button_hover: u32,
    button_active: u32,
    button_foreground: u32,
    primary: u32,
    primary_hover: u32,
    primary_active: u32,
    primary_foreground: u32,
    danger: u32,
    danger_hover: u32,
    danger_active: u32,
    danger_foreground: u32,
    success: u32,
    success_hover: u32,
    success_active: u32,
    success_foreground: u32,
    warning: u32,
    warning_hover: u32,
    warning_active: u32,
    warning_foreground: u32,
}

#[allow(clippy::unreadable_literal)] // Six-digit literals are RGB colors from the interface palette.
const fn interface_interaction_palette(dark: bool) -> InterfaceInteractionPalette {
    InterfaceInteractionPalette {
        button: if dark { 0x1d1d1d } else { 0xf6f6f9 },
        button_hover: if dark { 0x373737 } else { 0xe5e4e4 },
        button_active: if dark { 0x261b34 } else { 0xf3e7fe },
        button_foreground: if dark { 0xffffff } else { 0x101010 },
        // Primary and destructive actions use white labels in both themes;
        // dark mode uses deeper brand companions so every state retains AA
        // contrast without the visually awkward near-black label treatment.
        primary: 0x7a36d2,
        primary_hover: if dark { 0x8b4ade } else { 0x6828b9 },
        primary_active: if dark { 0x6828b9 } else { 0x57209e },
        primary_foreground: 0xffffff,
        danger: 0xb5124f,
        danger_hover: if dark { 0xc51b5b } else { 0x9d0f44 },
        danger_active: if dark { 0x9d0f44 } else { 0x850b39 },
        danger_foreground: 0xffffff,
        success: 0x26e7ad,
        success_hover: 0x48f2be,
        success_active: 0x26e7ad,
        success_foreground: 0x101010,
        warning: 0xdf7b32,
        warning_hover: 0xf08d42,
        warning_active: 0xdf7b32,
        warning_foreground: 0x101010,
    }
}

#[allow(clippy::unreadable_literal)] // Six-digit literals match the interface repository's RGB palette.
fn apply_interface_palette(cx: &mut App) {
    let dark = Theme::global(cx).is_dark();
    let color = |hex: u32| -> gpui::Hsla { gpui::rgb(hex).into() };
    let interaction = interface_interaction_palette(dark);
    let (background, surface, surface_hover, border, muted, foreground, muted_foreground) = if dark
    {
        (
            color(0x101010),
            color(0x1d1d1d),
            color(0x171717),
            color(0x373737),
            color(0x171717),
            color(0xffffff),
            color(0x878787),
        )
    } else {
        (
            color(0xfafafa),
            color(0xf6f6f9),
            color(0xffffff),
            color(0xe5e4e4),
            color(0xf6f6f9),
            color(0x101010),
            color(0x666666),
        )
    };
    let accent = color(0x9d5af2);
    // Skeleton placeholders sit both on the page background and on `surface`
    // cards, and the component animates them down to half opacity, so the
    // default (which matches `surface`) would vanish inside a card.
    let skeleton = color(if dark { 0x3a3a3a } else { 0xdedde0 });
    let primary = color(interaction.primary);
    let primary_active = color(interaction.primary_active);
    let button_danger = color(interaction.danger);
    let button_success = color(interaction.success);
    let button_warning = color(interaction.warning);
    // Semantic colors are also used as small text on the page background.
    // The light-theme variants are darker accessibility companions to the
    // exact brand fills used by buttons and badges.
    let semantic_primary = color(if dark { 0xb174ff } else { 0x7a36d2 });
    let danger = color(if dark { 0xeb1e74 } else { 0xc0165b });
    let success = color(if dark { 0x26e7ad } else { 0x08775a });
    let warning = color(if dark { 0xdf7b32 } else { 0x94501e });
    let theme = Theme::global_mut(cx);
    theme.radius = CONTROL_RADIUS;
    theme.radius_lg = SURFACE_RADIUS;
    let colors = &mut theme.colors;
    colors.background = background;
    colors.foreground = foreground;
    colors.border = border;
    colors.accent = surface_hover;
    colors.accent_foreground = foreground;
    colors.accordion = surface;
    colors.caret = accent;
    colors.button = color(interaction.button);
    colors.button_active = color(interaction.button_active);
    colors.button_foreground = color(interaction.button_foreground);
    colors.button_hover = color(interaction.button_hover);
    colors.button_primary = primary;
    colors.button_primary_active = primary_active;
    colors.button_primary_foreground = color(interaction.primary_foreground);
    colors.button_primary_hover = color(interaction.primary_hover);
    colors.button_secondary = color(interaction.button);
    colors.button_secondary_active = color(interaction.button_active);
    colors.button_secondary_foreground = color(interaction.button_foreground);
    colors.button_secondary_hover = color(interaction.button_hover);
    colors.button_danger = button_danger;
    colors.button_danger_active = color(interaction.danger_active);
    colors.button_danger_foreground = color(interaction.danger_foreground);
    colors.button_danger_hover = color(interaction.danger_hover);
    colors.button_success = button_success;
    colors.button_success_active = color(interaction.success_active);
    colors.button_success_foreground = color(interaction.success_foreground);
    colors.button_success_hover = color(interaction.success_hover);
    colors.button_warning = button_warning;
    colors.button_warning_active = color(interaction.warning_active);
    colors.button_warning_foreground = color(interaction.warning_foreground);
    colors.button_warning_hover = color(interaction.warning_hover);
    colors.group_box = surface;
    colors.group_box_foreground = foreground;
    colors.input = border;
    colors.list = surface;
    colors.list_active = color(interaction.button_active);
    colors.list_active_border = accent;
    colors.list_even = surface;
    colors.list_head = muted;
    colors.list_hover = surface_hover;
    colors.muted = muted;
    colors.muted_foreground = muted_foreground;
    colors.overlay = gpui::black().opacity(if dark { 0.30 } else { 0.15 });
    colors.popover = surface;
    colors.popover_foreground = foreground;
    colors.info = semantic_primary;
    colors.info_active = semantic_primary;
    colors.info_foreground = background;
    colors.info_hover = semantic_primary;
    colors.link = semantic_primary;
    colors.link_active = semantic_primary;
    colors.link_hover = color(if dark { 0xc49bff } else { 0x661cc4 });
    colors.primary = primary;
    colors.primary_active = primary_active;
    colors.primary_foreground = color(interaction.primary_foreground);
    colors.primary_hover = color(interaction.primary_hover);
    colors.progress_bar = accent;
    colors.ring = accent;
    colors.scrollbar = gpui::transparent_black();
    // Scrolling is communicated by the non-obstructing bottom chevron rather
    // than by tracks laid over content. This also hides the component
    // library's internal dialog scrollbar, which does not expose its handle.
    colors.scrollbar_thumb = gpui::transparent_black();
    colors.scrollbar_thumb_hover = gpui::transparent_black();
    colors.secondary = surface;
    colors.secondary_active = color(interaction.button_active);
    colors.secondary_foreground = foreground;
    colors.secondary_hover = surface_hover;
    colors.selection = accent.opacity(0.35);
    colors.skeleton = skeleton;
    colors.sidebar = surface;
    colors.sidebar_accent = color(interaction.button_active);
    colors.sidebar_accent_foreground = foreground;
    colors.sidebar_border = border;
    colors.sidebar_foreground = foreground;
    colors.sidebar_primary = primary;
    colors.sidebar_primary_foreground = color(interaction.primary_foreground);
    colors.danger = danger;
    colors.danger_foreground = background;
    colors.success = success;
    colors.success_foreground = background;
    colors.warning = warning;
    colors.warning_foreground = background;
    theme.tokens = ThemeTokens::from(&theme.colors);
}

fn apply_appearance_preference(
    preference: AppearancePreference,
    window: Option<&mut Window>,
    cx: &mut App,
) {
    match preference {
        AppearancePreference::System => {
            cx.set_window_appearance(None);
            Theme::sync_system_appearance(window, cx);
        }
        AppearancePreference::Light => {
            cx.set_window_appearance(Some(WindowAppearance::Light));
            Theme::change(ThemeMode::Light, window, cx);
        }
        AppearancePreference::Dark => {
            cx.set_window_appearance(Some(WindowAppearance::Dark));
            Theme::change(ThemeMode::Dark, window, cx);
        }
    }
    apply_interface_palette(cx);
}

fn wallet_window_title() -> String {
    format!("Ekubo Wallet {BUILD_VERSION}")
}

fn show_wallet_window(
    cx: &mut App,
    wallet_view: &Entity<WalletWindow>,
    window_slot: &WalletWindowSlot,
) -> Result<()> {
    let existing = *window_slot.borrow();
    if let Some(window_handle) = existing
        && window_handle
            .update(cx, |_, window, _| window.activate_window())
            .is_ok()
    {
        cx.activate(true);
        return Ok(());
    }

    wallet_view.update(cx, WalletWindow::release_window_state);
    let wallet_content = wallet_view.clone();
    let window_handle = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(960.0), px(650.0)), cx)),
            window_min_size: Some(size(px(660.0), px(500.0))),
            ..Default::default()
        },
        |window, cx| {
            window.set_window_title(&wallet_window_title());
            let layer_host = cx.new(|_| ComponentLayerHost::new(wallet_content));
            cx.new(|cx| Root::new(layer_host, window, cx))
        },
    )?;
    window_handle.update(cx, |_, window, _| window.activate_window())?;
    *window_slot.borrow_mut() = Some(window_handle);
    cx.activate(true);
    Ok(())
}

pub fn run_desktop() -> Result<()> {
    run_desktop_with_visibility(false)
}

pub fn run_desktop_hidden() -> Result<()> {
    run_desktop_with_visibility(true)
}

fn release_single_instance(instance_slot: &Arc<Mutex<Option<SingleInstance>>>) -> Result<()> {
    let instance = instance_slot
        .lock()
        .map_err(|_| anyhow::anyhow!("the single-instance lock state is unavailable"))?
        .take()
        .context("the running wallet no longer owns its single-instance lock")?;
    drop(instance);
    Ok(())
}

fn block_on_with_timeout<F>(
    tokio: &tokio::runtime::Handle,
    timeout: Duration,
    future: F,
) -> std::result::Result<F::Output, tokio::time::error::Elapsed>
where
    F: Future,
{
    // Construct the timer lazily after `block_on` enters the runtime. Tokio
    // panics if `timeout` itself is called on this ordinary shutdown thread.
    tokio.block_on(async move { tokio::time::timeout(timeout, future).await })
}

fn perform_desktop_shutdown(
    server: Option<McpIpcServer>,
    tokio: &tokio::runtime::Handle,
    prepared: Option<PreparedUpdate>,
    instance_slot: Arc<Mutex<Option<SingleInstance>>>,
    data_dir: &Path,
) -> Result<bool> {
    if let Some(server) = server {
        let stopped = block_on_with_timeout(tokio, DESKTOP_SERVER_SHUTDOWN_TIMEOUT, server.stop());
        let failure = match stopped {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(format!("local MCP server shutdown failed: {error:#}")),
            Err(_) => Some(format!(
                "local MCP server shutdown exceeded {} seconds",
                DESKTOP_SERVER_SHUTDOWN_TIMEOUT.as_secs()
            )),
        };
        if let Some(failure) = failure {
            let _ = crate::release_check::record_update_diagnostic(data_dir, &failure);
        }
    }
    let Some(prepared) = prepared else {
        return Ok(false);
    };

    let handoff_data_dir = data_dir.to_path_buf();
    crate::release_check::install_and_relaunch(
        prepared.prepared,
        prepared.authorization,
        move || {
            let _ = crate::release_check::record_update_diagnostic(
                &handoff_data_dir,
                "releasing the single-instance lock before relaunch",
            );
            release_single_instance(&instance_slot)
        },
    )?;
    Ok(true)
}

fn close_window_key_binding() -> KeyBinding {
    #[cfg(target_os = "macos")]
    const SHORTCUT: &str = "cmd-w";
    #[cfg(target_os = "linux")]
    const SHORTCUT: &str = "ctrl-w";
    #[cfg(target_os = "windows")]
    const SHORTCUT: &str = "alt-f4";
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    const SHORTCUT: &str = "ctrl-w";

    KeyBinding::new(SHORTCUT, CloseWindow, None)
}

fn close_active_window(_: &CloseWindow, cx: &mut App) {
    if let Some(window) = cx.active_window() {
        // Global actions run while the active window is already being updated.
        // Remove it on the next app turn to avoid a re-entrant window update.
        cx.defer(move |cx| {
            let _ = window.update(cx, |_, window, _| window.remove_window());
        });
    }
}

fn run_desktop_with_visibility(hidden_startup: bool) -> Result<()> {
    initialize_platform_notifications();
    let config = crate::config::ConfigStore::production()?;
    let (activation_tx, activation_rx) = std::sync::mpsc::channel();
    let instance = match SingleInstance::acquire(config.data_dir(), activation_tx)? {
        InstanceOutcome::Primary(instance) => instance,
        InstanceOutcome::ActivatedExisting => return Ok(()),
    };
    // Only after winning the instance lock, because the helper now lives at
    // one fixed path. A second launch of a *different* build would otherwise
    // overwrite the helper, hand the user off to the running primary, and
    // exit — leaving every bridge to version-mismatch against a wallet whose
    // bytes no longer match the installed helper.
    crate::agent_config::install_bridge_helper()?;
    let data_dir = config.data_dir().to_path_buf();
    let _ = crate::release_check::record_update_diagnostic(&data_dir, "wallet process started");
    let authority = ApplicationAuthority::open(config)?;
    let owner = authority.owner_api();
    let agent = authority.agent_api();
    let events = authority.events();
    let server_slot = Arc::new(Mutex::new(None::<McpIpcServer>));
    let pending_update = Arc::new(Mutex::new(None::<PreparedUpdate>));
    let instance_slot = Arc::new(Mutex::new(Some(instance)));
    let walletconnect = Arc::new(Mutex::new(
        crate::walletconnect::WalletConnectManager::default(),
    ));
    let (review_presenter, mut review_prompts) = GuiReviewPresenter::channel();
    let (walletconnect_presenter, mut walletconnect_prompts) = ProposalPresenter::channel();

    let application = gpui_platform::application();
    #[cfg(target_os = "macos")]
    let dock_reopen_target: DockReopenTarget = Rc::new(RefCell::new(None));
    #[cfg(target_os = "macos")]
    application.on_reopen({
        let dock_reopen_target = dock_reopen_target.clone();
        move |cx| {
            let Some((wallet_view, window_slot)) = dock_reopen_target.borrow().clone() else {
                return;
            };
            if let Err(error) = show_wallet_window(cx, &wallet_view, &window_slot) {
                tracing::error!(%error, "failed to reopen wallet from the macOS dock");
            }
        }
    });
    application
        .with_assets(WalletAssets::default())
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            apply_appearance_preference(
                owner.appearance_preference().unwrap_or_default(),
                None,
                cx,
            );
            load_application_fonts(cx).expect("embedded Suisse fonts must be valid");
            gpui_tokio::init(cx);
            cx.set_quit_mode(QuitMode::Explicit);
            let tray = Rc::new(RefCell::new(
                PlatformTray::new(dark_appearance(cx.window_appearance())).ok(),
            ));
            let initial_networks = owner.networks().unwrap_or_default();
            let initial_testnet_mode = owner.testnet_mode().unwrap_or(false);
            let initial_pending_reviews = owner.reviews(None).map_or(0, |queues| {
                review_queue_decision_count(&queues, &initial_networks, initial_testnet_mode)
            });
            if let Some(tray) = tray.borrow_mut().as_mut() {
                tray.update(&TraySnapshot {
                    pending_reviews: initial_pending_reviews,
                    mcp_online: false,
                    walletconnect_sessions: 0,
                });
            }
            // The automation cron. One supervisor task rather than one per
            // account and network: it re-reads the configuration every pass,
            // so accounts added, networks disabled, and endpoints edited take
            // effect without a restart and without any task bookkeeping.
            //
            // Started here, beside the other long-lived services, because it
            // needs the Tokio runtime `gpui_tokio::init` just installed. It
            // holds an `AgentExecutionAuthority` — the same narrow signing
            // capability the MCP server gets — and never a key store.
            {
                let automation_config = owner.config().clone();
                let automation_events = events.clone();
                gpui_tokio::Tokio::spawn(cx, async move {
                    let data_dir = automation_config.data_dir().to_path_buf();
                    let stores = (|| {
                        Ok::<_, anyhow::Error>((
                            ekubo_wallet_core::automation_store::AutomationStore::production(
                                &data_dir,
                            )?,
                            ekubo_wallet_core::pending::PendingStore::production(&data_dir)?,
                            ekubo_wallet_core::policy_store::PolicyStore::production(&data_dir)?,
                        ))
                    })();
                    let Ok((automations, pending, policies)) = stores else {
                        // Nothing to run against. The wallet is fully usable
                        // without automations, so this must not take the
                        // application down with it.
                        return;
                    };
                    let policies = Arc::new(Mutex::new(policies));
                    let scheduler =
                        ekubo_wallet_core::automation_scheduler::AutomationScheduler::new(
                            ekubo_wallet_core::agent_authority::AgentExecutionAuthority::production(
                                Arc::clone(&policies),
                            ),
                        );
                    let automations = Mutex::new(automations);
                    let pending = Mutex::new(pending);
                    ekubo_wallet_core::automation_scheduler::drive(
                        &scheduler,
                        &automation_config,
                        &automations,
                        &pending,
                        &policies,
                        |outcome| {
                            // Every pass that did something redraws the tab.
                            // Publishing only on change keeps an idle wallet
                            // from waking the UI on a timer.
                            if outcome.is_ok() {
                                automation_events.publish(
                                    crate::events::DomainEventKind::AutomationsChanged {
                                        wallet_id: String::new(),
                                    },
                                );
                            }
                        },
                    )
                    .await;
                })
                .detach();
            }
            cx.set_global(DesktopRuntime {
                _instance: instance_slot.clone(),
                _server: server_slot.clone(),
                _walletconnect: walletconnect.clone(),
                _tray: tray.clone(),
                _pending_update: pending_update.clone(),
            });
            let mut key_bindings = vec![
                KeyBinding::new("cmd-k", OpenCommandPalette, None),
                KeyBinding::new("ctrl-k", OpenCommandPalette, None),
                close_window_key_binding(),
                KeyBinding::new("escape", CloseOverlay, Some("Wallet")),
                #[cfg(target_os = "macos")]
                KeyBinding::new("cmd-h", HideApplication, None),
                #[cfg(target_os = "macos")]
                KeyBinding::new("cmd-q", Quit, None),
                #[cfg(not(target_os = "macos"))]
                KeyBinding::new("ctrl-q", Quit, None),
            ];
            key_bindings.extend(
                Route::ALL.into_iter().map(|route| {
                    KeyBinding::new(route.key_binding(), NavigateRoute { route }, None)
                }),
            );
            key_bindings.push(KeyBinding::new(
                SETTINGS_ALTERNATE_KEY_BINDING,
                NavigateRoute {
                    route: Route::Settings,
                },
                None,
            ));
            cx.bind_keys(key_bindings);
            cx.on_action(close_active_window);
            cx.on_action(|_: &HideApplication, cx| cx.hide());
            cx.on_action(|_: &Quit, cx| cx.quit());
            let shutdown_server = server_slot.clone();
            let shutdown_walletconnect = walletconnect.clone();
            let shutdown_update = pending_update.clone();
            let shutdown_instance = instance_slot.clone();
            let update_data_dir = data_dir.clone();
            let tokio = gpui_tokio::Tokio::handle(cx);
            cx.on_app_quit(move |_| {
                let update_data_dir = update_data_dir.clone();
                let shutdown_instance = shutdown_instance.clone();
                if let Ok(mut sessions) = shutdown_walletconnect.lock() {
                    sessions.disconnect_all();
                }
                let server = shutdown_server
                    .lock()
                    .ok()
                    .and_then(|mut server| server.take());
                let tokio = tokio.clone();
                let prepared = shutdown_update
                    .lock()
                    .ok()
                    .and_then(|mut update| update.take());
                let update_requested = prepared.is_some();
                if update_requested {
                    let _ = crate::release_check::record_update_diagnostic(
                        &update_data_dir,
                        "authorized update installation started",
                    );
                }
                let worker_data_dir = update_data_dir.clone();
                // GPUI gives ordinary quit futures only 200 ms. Create the
                // update worker before returning the future, then join it on
                // the first poll so the process cannot exit mid-replacement.
                let worker = std::thread::Builder::new()
                    .name("ekubo-desktop-shutdown".into())
                    .spawn(move || {
                        perform_desktop_shutdown(
                            server,
                            &tokio,
                            prepared,
                            shutdown_instance,
                            &worker_data_dir,
                        )
                    });
                async move {
                    let result = match worker {
                        Ok(worker) => worker.join().unwrap_or_else(|_| {
                            Err(anyhow::anyhow!("the desktop shutdown thread panicked"))
                        }),
                        Err(error) => Err(error.into()),
                    };
                    match result {
                        Ok(true) => {
                            let _ = crate::release_check::record_update_diagnostic(
                                &update_data_dir,
                                "updated wallet relaunch command completed",
                            );
                        }
                        Ok(false) => {}
                        Err(error) if update_requested => {
                            let message =
                                format!("authorized update installation failed: {error:#}");
                            let _ = crate::release_check::record_update_diagnostic(
                                &update_data_dir,
                                &message,
                            );
                            tracing::error!(%error, "authorized update installation failed");
                            let _ = notify_rust::Notification::new()
                                .summary("Ekubo Wallet update failed")
                                .body(&format!(
                                    "{message}. Details: {}",
                                    crate::release_check::update_diagnostics_path(&update_data_dir)
                                        .display()
                                ))
                                .show();
                        }
                        Err(error) => {
                            tracing::error!(%error, "desktop shutdown failed");
                        }
                    }
                }
            })
            .detach();

            let wallet_view = cx.new(|cx| {
                WalletWindow::new(
                    owner.clone(),
                    review_presenter.clone(),
                    walletconnect.clone(),
                    walletconnect_presenter.clone(),
                    tray.clone(),
                    pending_update.clone(),
                    &data_dir,
                    cx,
                )
            });
            let shutdown_clipboard = wallet_view.read(cx).export_clipboard.clone();
            cx.on_app_quit(move |cx| {
                if let Ok(mut stored) = shutdown_clipboard.lock()
                    && let Some(secret) = stored.as_ref()
                {
                    if cx
                        .read_from_clipboard()
                        .and_then(|item| item.text())
                        .as_deref()
                        == Some(secret.as_str())
                    {
                        cx.write_to_clipboard(ClipboardItem::new_string(String::new()));
                    }
                    stored.take();
                }
                async {}
            })
            .detach();
            let shortcut_view = wallet_view.clone();
            cx.on_action(move |action: &NavigateRoute, cx| {
                shortcut_view.update(cx, |view, cx| {
                    view.navigate_route(action.route, cx);
                });
            });
            let window_slot: WalletWindowSlot = Rc::new(RefCell::new(None));
            #[cfg(target_os = "macos")]
            dock_reopen_target
                .borrow_mut()
                .replace((wallet_view.clone(), window_slot.clone()));
            if !hidden_startup || tray.borrow().is_none() {
                show_wallet_window(cx, &wallet_view, &window_slot)
                    .expect("failed to open the wallet window");
            }
            let review_view = wallet_view.clone();
            let review_window = window_slot.clone();
            cx.spawn(async move |cx| {
                while let Some(prompt) = review_prompts.recv().await {
                    review_view.update(cx, |view, cx| {
                        view.receive_transaction_prompt(prompt);
                        let route = view.active_review_route();
                        view.set_route(route);
                        cx.notify();
                    });
                    let _ = cx.update(|cx| show_wallet_window(cx, &review_view, &review_window));
                }
            })
            .detach();
            let walletconnect_review_view = wallet_view.clone();
            let walletconnect_review_window = window_slot.clone();
            cx.spawn(async move |cx| {
                while let Some(prompt) = walletconnect_prompts.recv().await {
                    walletconnect_review_view.update(cx, |view, cx| {
                        view.receive_walletconnect_prompt(prompt);
                        let route = view.active_review_route();
                        view.set_route(route);
                        cx.notify();
                    });
                    let _ = cx.update(|cx| {
                        show_wallet_window(
                            cx,
                            &walletconnect_review_view,
                            &walletconnect_review_window,
                        )
                    });
                }
            })
            .detach();
            let mut view_events = events.subscribe();
            let event_view = wallet_view.clone();
            let event_owner = owner.clone();
            let event_tray = tray.clone();
            let event_walletconnect = walletconnect.clone();
            let event_tokio = gpui_tokio::Tokio::handle(cx);
            cx.spawn(async move |cx| {
                let mut mcp_online = false;
                loop {
                    let changed = match view_events.recv().await {
                        Ok(event) => {
                            let transaction_request = match &event.kind {
                                crate::events::DomainEventKind::Transaction {
                                    request_id, ..
                                } => Some(*request_id),
                                _ => None,
                            };
                            if let crate::events::DomainEventKind::McpStatusChanged { online } =
                                &event.kind
                            {
                                mcp_online = *online;
                            }
                            let portfolio_changed = matches!(
                                &event.kind,
                                crate::events::DomainEventKind::ConfigurationChanged
                                    | crate::events::DomainEventKind::Transaction {
                                        stage: crate::events::TransactionStage::Confirmed
                                            | crate::events::TransactionStage::Reverted
                                            | crate::events::TransactionStage::Replaced,
                                        ..
                                    }
                            );
                            let configuration_changed = matches!(
                                &event.kind,
                                crate::events::DomainEventKind::ConfigurationChanged
                            );
                            let snapshot_changed = matches!(
                                &event.kind,
                                crate::events::DomainEventKind::ConfigurationChanged
                                    | crate::events::DomainEventKind::ReviewChanged { .. }
                                    | crate::events::DomainEventKind::PolicyProposalChanged { .. }
                                    | crate::events::DomainEventKind::AutomationsChanged { .. }
                                    | crate::events::DomainEventKind::Transaction { .. }
                            );
                            if portfolio_changed || configuration_changed || snapshot_changed {
                                event_view.update(cx, |view, cx| {
                                    if portfolio_changed {
                                        view.invalidate_portfolio();
                                    }
                                    if configuration_changed {
                                        view.reload_tokens(cx);
                                    }
                                    if snapshot_changed {
                                        view.reload_desktop_snapshot(cx);
                                    }
                                    if let Some(request_id) = transaction_request {
                                        view.activity_inspections.remove(&request_id);
                                        if view.selected_record == Some(request_id) {
                                            view.load_transaction_inspection(request_id, cx);
                                        }
                                    }
                                });
                            }
                            true
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => false,
                    };
                    if changed {
                        let owner = event_owner.clone();
                        let walletconnect = event_walletconnect.clone();
                        let counts = event_tokio
                            .spawn_blocking(move || {
                                let sessions = walletconnect
                                    .lock()
                                    .map_or_else(|_| Vec::new(), |manager| manager.sessions());
                                let networks = owner.networks().unwrap_or_default();
                                let testnet_mode = owner.testnet_mode().unwrap_or(false);
                                (
                                    owner.reviews(None).map_or(0, |queues| {
                                        review_queue_decision_count(
                                            &queues,
                                            &networks,
                                            testnet_mode,
                                        )
                                    }),
                                    sessions,
                                )
                            })
                            .await
                            .unwrap_or_default();
                        if let Some(tray) = event_tray.borrow_mut().as_mut() {
                            tray.update(&TraySnapshot {
                                pending_reviews: counts.0,
                                mcp_online,
                                walletconnect_sessions: counts
                                    .1
                                    .iter()
                                    .filter(|session| session.settled)
                                    .count(),
                            });
                        }
                        event_view.update(cx, |view, cx| {
                            view.set_walletconnect_sessions(counts.1);
                            cx.notify();
                        });
                    } else {
                        break;
                    }
                }
            })
            .detach();
            let tray_window = window_slot.clone();
            let tray_view = wallet_view.clone();
            let (tray_commands, mut tray_command_rx) = tokio::sync::mpsc::unbounded_channel();
            let _tray_thread = std::thread::Builder::new()
                .name("ekubo-tray-events".into())
                .spawn(move || {
                    while let Some(command) = PlatformTray::recv_command() {
                        if tray_commands.send(command).is_err() {
                            break;
                        }
                    }
                });
            cx.spawn(async move |cx| {
                while let Some(command) = tray_command_rx.recv().await {
                    match command {
                        TrayCommand::OpenWallet => {
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::OpenRoute(route) => {
                            // `navigate_route`, not `set_route`: the rail's own
                            // buttons are disabled while the legal gate is up,
                            // and the tray must not be the one way to move the
                            // app out from under a decision it cannot dismiss.
                            tray_view.update(cx, |view, cx| {
                                view.navigate_route(route, cx);
                            });
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::Quit => {
                            cx.update(|cx| cx.quit());
                            return;
                        }
                    }
                }
            })
            .detach();

            let (notification_clicks, mut clicked_notifications) =
                tokio::sync::mpsc::unbounded_channel();
            let notification_service = PlatformNotificationService::new(notification_clicks);
            let mut domain_events = events.subscribe();
            let notification_owner = owner.clone();
            gpui_tokio::Tokio::spawn(cx, async move {
                loop {
                    match domain_events.recv().await {
                        Ok(event) => {
                            let owner = notification_owner.clone();
                            let described = tokio::task::spawn_blocking(move || {
                                let context = transaction_notification_context(&owner, &event)?;
                                let preferences = NotificationPreferences {
                                    detailed_previews: owner
                                        .detailed_notification_previews()
                                        .ok()?,
                                };
                                Some((event, context, preferences))
                            })
                            .await
                            .ok()
                            .flatten();
                            if let Some(notification) =
                                described
                                    .as_ref()
                                    .and_then(|(event, context, preferences)| {
                                        notification_for(event, context, *preferences)
                                    })
                            {
                                notification_service.show(notification);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
            .detach();

            let notification_window = window_slot.clone();
            let notification_view = wallet_view.clone();
            cx.spawn(async move |cx| {
                while let Some(route) = clicked_notifications.recv().await {
                    notification_view.update(cx, |view, cx| {
                        view.open_notification(route, cx);
                    });
                    let _ = cx.update(|cx| {
                        show_wallet_window(cx, &notification_view, &notification_window)
                    });
                }
            })
            .detach();

            let activation_window = window_slot;
            let activation_view = wallet_view.clone();
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
                    let _ = cx
                        .update(|cx| show_wallet_window(cx, &activation_view, &activation_window));
                }
            })
            .detach();

            let slot = server_slot.clone();
            let status_tray = tray.clone();
            let server_events = events.clone();
            let server_task = gpui_tokio::Tokio::spawn_result(cx, async move {
                McpIpcServer::start(&data_dir, agent, server_events)
            });
            cx.spawn(async move |cx| match server_task.await {
                Ok(server) => {
                    if let Ok(mut guard) = slot.lock() {
                        *guard = Some(server);
                    }
                    if let Some(tray) = status_tray.borrow_mut().as_mut() {
                        tray.set_mcp_online(true);
                    }
                    wallet_view.update(cx, |view, cx| {
                        view.mcp_status = McpGatewayStatus::Online;
                        cx.notify();
                    });
                }
                Err(error) => wallet_view.update(cx, |view, cx| {
                    view.mcp_status = McpGatewayStatus::Offline(format!("{error:#}").into());
                    cx.notify();
                }),
            })
            .detach();
        });
    Ok(())
}

#[cfg(test)]
#[path = "desktop_test.rs"]
mod tests;

#[cfg(test)]
#[path = "desktop_render_test.rs"]
mod render_tests;
