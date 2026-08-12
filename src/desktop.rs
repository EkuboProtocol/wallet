use crate::{
    BUILD_COMMIT, BUILD_VERSION,
    agent_config::{AgentAdapter, ConfigPreview},
    authority::{
        ApplicationAuthority, ExportLease, OwnerActivityRecord, OwnerApi, OwnerPortfolioSnapshot,
        OwnerReviewQueues, PRIVATE_KEY_REVEAL_DURATION,
    },
    gui_review::{GuiReviewCommand, GuiReviewPresenter, GuiReviewPrompt},
    http_server::McpHttpServer,
    notifications::{
        NotificationPreferences, NotificationRoute, NotificationService as _,
        PlatformNotificationService, initialize_platform_notifications, notification_for,
    },
    release_check::ReleaseCheck,
    review::ReviewState,
    single_instance::{InstanceOutcome, SingleInstance},
    tray::{PlatformTray, TrayCommand, TrayService, TraySnapshot},
    walletconnect::{
        ProposalCommand, ProposalPresenter, ProposalPrompt, QrChoices, QrPreview, SessionSummary,
        SystemScreenPicker, WalletConnectManager, run_session, scan_screen,
    },
};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::approval::{
    ApprovalFact, ApprovalSection, ApprovalSectionKind, ReviewDecision, ReviewDocument,
};
use ekubo_wallet_core::config::{NativeCurrency, NetworkConfig, RpcStrategy, WalletMetadata};
use ekubo_wallet_core::core::policy::{Effect, Rule, WalletPolicy, diff_policies};
use ekubo_wallet_core::custody::PrivateKeyMaterial;
use ekubo_wallet_core::desktop_store::{AgentKind, AppearancePreference, McpClient};
use ekubo_wallet_core::legal::{LegalDocument, LegalStatus};
use ekubo_wallet_core::message::MessageStatus;
use ekubo_wallet_core::networks::NetworkProfile;
use ekubo_wallet_core::pending::PendingStatus;
use ekubo_wallet_core::policy_store::{PolicyProposal, StoredPolicy};
use ekubo_wallet_core::token_store::{ListedToken, StoredToken, TokenProposal};
use ekubo_wallet_core::typed_data::TypedDataStatus;
use gpui::{
    App, ClipboardItem, Context, Entity, FocusHandle, KeyBinding, MouseButton, ObjectFit, QuitMode,
    Render, RenderImage, ScrollAnchor, ScrollHandle, SharedString, Subscription, Task,
    UniformListScrollHandle, WeakEntity, Window, WindowAppearance, WindowBounds, WindowHandle,
    WindowOptions, actions, div, img, prelude::*, px, size, uniform_list,
};
use gpui_component::{
    ActiveTheme, Colorize, Disableable, FocusTrapElement, Icon, IconName, IndexPath, Root,
    Selectable, Sizable, StyledExt, Theme, ThemeMode, ThemeTokens, WindowExt as _,
    alert::Alert,
    button::{Button, ButtonVariant, ButtonVariants},
    dialog::DialogButtonProps,
    group_box::{GroupBox, GroupBoxVariants as _},
    h_flex,
    input::{Input, InputState},
    list::{List, ListDelegate, ListEvent, ListItem, ListState},
    scroll::ScrollableElement,
    spinner::Spinner,
    switch::Switch,
};
use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

actions!(ekubo_wallet, [OpenCommandPalette, CloseOverlay, Quit]);

const UI_FONT_FAMILY: &str = "Suisse Intl";
const MONO_FONT_FAMILY: &str = "Suisse Intl Mono";
const NAVIGATION_RAIL_WIDTH: gpui::Pixels = px(80.0);
const NAVIGATION_BUTTON_SIZE: gpui::Pixels = px(52.0);
const REPOSITORY_URL: &str = "https://github.com/EkuboProtocol/wallet";
const LATEST_RELEASE_URL: &str = "https://github.com/EkuboProtocol/wallet/releases/latest";

fn application_license_url() -> String {
    if BUILD_COMMIT.is_empty() {
        format!("{REPOSITORY_URL}/blob/main/LICENSE")
    } else {
        format!("{REPOSITORY_URL}/blob/{BUILD_COMMIT}/LICENSE")
    }
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
    _server: Arc<Mutex<Option<McpHttpServer>>>,
    _walletconnect: Arc<Mutex<crate::walletconnect::WalletConnectManager>>,
    _tray: Rc<RefCell<Option<PlatformTray>>>,
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
            LegalDocument::ThirdPartyLicenses => false,
        })
}

fn settings_section(title: &'static str, content: impl IntoElement) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(div().text_lg().font_semibold().child(title))
        .child(content)
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

fn agent_session_expiry_label(
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> (String, bool) {
    let Some(expires_at) = expires_at else {
        return ("No active session (expired or not completed)".into(), true);
    };
    let timestamp = expires_at.format("%b %d, %Y at %H:%M UTC");
    if expires_at <= now {
        (format!("Expired {timestamp}"), true)
    } else {
        (format!("Expires {timestamp}"), false)
    }
}

fn visible_agent_sessions<'a>(
    clients: &'a [McpClient],
    hidden: &BTreeSet<uuid::Uuid>,
) -> Vec<&'a McpClient> {
    clients
        .iter()
        .filter(|client| client.revoked_at.is_none() && !hidden.contains(&client.id))
        .collect()
}

fn format_asset_balance(
    raw: &str,
    decimals: Option<u8>,
    symbol: Option<&str>,
    base_unit: &str,
) -> String {
    let Some(decimals) = decimals else {
        return format!("{raw} {base_unit}");
    };
    let amount = ekubo_wallet_core::approval_summary::format_fixed_point(raw, decimals);
    symbol.map_or(amount.clone(), |symbol| format!("{amount} {symbol}"))
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
    refresh: bool,
    send: bool,
    cancel: bool,
    discard: bool,
}

fn transaction_actions(status: PendingStatus) -> TransactionActions {
    TransactionActions {
        refresh: matches!(
            status,
            PendingStatus::Submitting
                | PendingStatus::Broadcast
                | PendingStatus::Cancelling
                | PendingStatus::Replaced
        ),
        send: matches!(status, PendingStatus::Signed | PendingStatus::Broadcast),
        cancel: matches!(
            status,
            PendingStatus::Submitting | PendingStatus::Broadcast | PendingStatus::Cancelling
        ),
        discard: status == PendingStatus::Signed,
    }
}

fn upsert_detected_agents() -> Result<String> {
    let adapters = AgentAdapter::supported()?
        .into_iter()
        .filter(AgentAdapter::detected)
        .collect::<Vec<_>>();
    if adapters.is_empty() {
        return Ok("No supported agent installations were detected.".into());
    }
    let detected = adapters.len();
    let previews = adapters
        .into_iter()
        .map(|adapter| adapter.preview_install(true))
        .collect::<Result<Vec<_>>>()?;
    let changed = previews
        .iter()
        .filter(|preview| preview.has_changes())
        .count();
    let batch = crate::agent_config::ConfigBatchInstall::install(previews)?;
    batch.commit();
    Ok(format!(
        "OAuth MCP URL is installed for {detected} detected agent(s); {changed} configuration file(s) changed. Authenticate from each agent when needed."
    ))
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
                .preview_install(true)
                .map(|preview| !preview.has_changes())
                .map_err(|error| format!("{error:#}").into()),
        })
        .collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Route {
    Overview,
    Reviews,
    Activity,
    Accounts,
    Policies,
    Networks,
    Tokens,
    WalletConnect,
    Settings,
}

impl Route {
    const ALL: [Self; 9] = [
        Self::Reviews,
        Self::Overview,
        Self::Activity,
        Self::Accounts,
        Self::Policies,
        Self::Networks,
        Self::Tokens,
        Self::WalletConnect,
        Self::Settings,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Portfolio",
            Self::Reviews => "Inbox",
            Self::Activity => "Activity",
            Self::Accounts => "Accounts",
            Self::Policies => "Policies",
            Self::Networks => "Networks",
            Self::Tokens => "Tokens",
            Self::WalletConnect => "WalletConnect",
            Self::Settings => "Settings",
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
            Self::Reviews => IconName::Inbox,
            Self::Activity => IconName::Frame,
            Self::Accounts => IconName::User,
            Self::Policies => IconName::Inspector,
            Self::Networks => IconName::Network,
            Self::Tokens => IconName::Star,
            Self::WalletConnect => IconName::Globe,
            Self::Settings => IconName::Settings,
        }
    }

    #[cfg(target_os = "macos")]
    const fn shortcut(self) -> &'static str {
        match self {
            Self::Reviews => "⌘1",
            Self::Overview => "⌘2",
            Self::Activity => "⌘3",
            Self::Accounts => "⌘4",
            Self::Policies => "⌘5",
            Self::Networks => "⌘6",
            Self::Tokens => "⌘7",
            Self::WalletConnect => "⌘8",
            Self::Settings => "⌘9 / ⌘,",
        }
    }

    #[cfg(not(target_os = "macos"))]
    const fn shortcut(self) -> &'static str {
        match self {
            Self::Reviews => "Ctrl+1",
            Self::Overview => "Ctrl+2",
            Self::Activity => "Ctrl+3",
            Self::Accounts => "Ctrl+4",
            Self::Policies => "Ctrl+5",
            Self::Networks => "Ctrl+6",
            Self::Tokens => "Ctrl+7",
            Self::WalletConnect => "Ctrl+8",
            Self::Settings => "Ctrl+9 / Ctrl+,",
        }
    }

    #[cfg(target_os = "macos")]
    const fn key_binding(self) -> &'static str {
        match self {
            Self::Reviews => "cmd-1",
            Self::Overview => "cmd-2",
            Self::Activity => "cmd-3",
            Self::Accounts => "cmd-4",
            Self::Policies => "cmd-5",
            Self::Networks => "cmd-6",
            Self::Tokens => "cmd-7",
            Self::WalletConnect => "cmd-8",
            Self::Settings => "cmd-9",
        }
    }

    #[cfg(not(target_os = "macos"))]
    const fn key_binding(self) -> &'static str {
        match self {
            Self::Reviews => "ctrl-1",
            Self::Overview => "ctrl-2",
            Self::Activity => "ctrl-3",
            Self::Accounts => "ctrl-4",
            Self::Policies => "ctrl-5",
            Self::Networks => "ctrl-6",
            Self::Tokens => "ctrl-7",
            Self::WalletConnect => "ctrl-8",
            Self::Settings => "ctrl-9",
        }
    }
}

#[cfg(target_os = "macos")]
const SETTINGS_ALTERNATE_KEY_BINDING: &str = "cmd-,";
#[cfg(not(target_os = "macos"))]
const SETTINGS_ALTERNATE_KEY_BINDING: &str = "ctrl-,";

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
    command_palette: bool,
    command_palette_list: Option<Entity<ListState<RouteListDelegate>>>,
    command_palette_subscription: Option<Subscription>,
    token_list: Option<Entity<ListState<TokenListDelegate>>>,
    token_proposal_list: Option<Entity<ListState<TokenProposalListDelegate>>>,
    token_list_url_input: Option<Entity<InputState>>,
    token_chain_id_input: Option<Entity<InputState>>,
    token_address_input: Option<Entity<InputState>>,
    token_symbol_input: Option<Entity<InputState>>,
    token_name_input: Option<Entity<InputState>>,
    token_decimals_input: Option<Entity<InputState>>,
    token_editor_open: bool,
    token_editor_original: Option<StoredToken>,
    token_editor_errors: TokenEditorErrors,
    token_editor_busy: bool,
    token_import_state: TokenImportState,
    token_import_error: Option<SharedString>,
    token_import_status: Option<SharedString>,
    token_proposal_error: Option<SharedString>,
    token_list_generation: u64,
    mcp_status: SharedString,
    selected_record: Option<uuid::Uuid>,
    activity_busy: BTreeSet<uuid::Uuid>,
    activity_feedback: BTreeMap<uuid::Uuid, ActivityFeedback>,
    active_review: Option<ActiveReview>,
    queued_reviews: SerialQueue<QueuedReview>,
    review_flow: ReviewFlowState,
    pending_agent_install: Option<PendingAgentInstall>,
    agent_reinstall: AgentReinstallState,
    detected_agents: AgentDetectionState,
    detected_agents_generation: u64,
    hidden_agent_sessions: BTreeSet<uuid::Uuid>,
    account_id_input: Option<Entity<InputState>>,
    private_key_input: Option<Entity<InputState>>,
    account_id_error: Option<SharedString>,
    private_key_error: Option<SharedString>,
    account_action_errors: BTreeMap<String, SharedString>,
    account_export: Option<AccountExport>,
    legal_review: Option<LegalReview>,
    legal_gate: bool,
    route_errors: BTreeMap<Route, SharedString>,
    detailed_notification_previews: Arc<AtomicBool>,
    appearance_preference: AppearancePreference,
    notification_preference_busy: bool,
    portfolio: PortfolioState,
    portfolio_generation: u64,
    portfolio_chain_id: Option<u64>,
    route_scroll_handle: ScrollHandle,
    network_editor_anchor: ScrollAnchor,
    token_editor_anchor: ScrollAnchor,
    policy_editor_anchor: ScrollAnchor,
    modal_focus: FocusHandle,
    walletconnect: Arc<Mutex<WalletConnectManager>>,
    walletconnect_sessions: Vec<SessionSummary>,
    walletconnect_presenter: ProposalPresenter,
    walletconnect_uri_input: Option<Entity<InputState>>,
    walletconnect_scan: WalletConnectScanState,
    walletconnect_scan_generation: u64,
    network_json_input: Option<Entity<InputState>>,
    network_json_error: Option<SharedString>,
    network_editor_open: bool,
    network_editor_original: Option<NetworkConfig>,
    network_editor_disabled: bool,
    network_editor_rpc_strategy: RpcStrategy,
    network_editor_advanced: bool,
    network_editor_busy: bool,
    network_editor_errors: NetworkEditorErrors,
    network_name_input: Option<Entity<InputState>>,
    network_display_name_input: Option<Entity<InputState>>,
    network_aliases_input: Option<Entity<InputState>>,
    network_chain_id_input: Option<Entity<InputState>>,
    network_rpc_urls_input: Option<Entity<InputState>>,
    network_max_gas_limit_input: Option<Entity<InputState>>,
    network_max_fee_per_gas_input: Option<Entity<InputState>>,
    network_native_name_input: Option<Entity<InputState>>,
    network_native_symbol_input: Option<Entity<InputState>>,
    network_native_decimals_input: Option<Entity<InputState>>,
    network_explorer_url_input: Option<Entity<InputState>>,
    network_documentation_url_input: Option<Entity<InputState>>,
    network_presets: Arc<[NetworkProfile]>,
    network_preset_search_input: Option<Entity<InputState>>,
    network_preset_search_subscription: Option<Subscription>,
    network_preset_busy: Option<u64>,
    network_preset_error: Option<SharedString>,
    network_reset_error: Option<SharedString>,
    pending_network_reset: Option<Vec<NetworkConfig>>,
    network_reset_busy: bool,
    network_action_busy: BTreeSet<String>,
    network_action_errors: BTreeMap<String, SharedString>,
    expanded_networks: BTreeSet<String>,
    pending_network_removal: Option<NetworkConfig>,
    network_proposal_error: Option<SharedString>,
    policy_json_input: Option<Entity<InputState>>,
    policy_editor: Option<PolicyEditor>,
    policy_chain_input: Option<Entity<InputState>>,
    policy_chain_label_input: Option<Entity<InputState>>,
    policy_chain_max_calls_input: Option<Entity<InputState>>,
    policy_chain_native_values_input: Option<Entity<InputState>>,
    policy_chain_original_key: Option<String>,
    policy_chain_native_value_mode: GuidedNativeValueMode,
    policy_chain_errors: GuidedPolicyChainErrors,
    policy_rule_chain_key: Option<String>,
    policy_rule_original_index: Option<usize>,
    policy_rule_effect: GuidedRuleEffect,
    policy_rule_target_mode: GuidedLiteralMode,
    policy_rule_sender_mode: GuidedLiteralMode,
    policy_rule_value_mode: GuidedLiteralMode,
    policy_rule_calldata_mode: GuidedCalldataMode,
    policy_rule_label_input: Option<Entity<InputState>>,
    policy_rule_targets_input: Option<Entity<InputState>>,
    policy_rule_senders_input: Option<Entity<InputState>>,
    policy_rule_values_input: Option<Entity<InputState>>,
    policy_rule_abi_input: Option<Entity<InputState>>,
    policy_rule_args_input: Option<Entity<InputState>>,
    policy_rule_errors: GuidedPolicyRuleErrors,
    policy_installing: bool,
    policy_action_error: Option<SharedString>,
    token_proposal_busy: bool,
    network_proposal_busy: bool,
    release_state: ReleaseDisplayState,
}

#[derive(Clone)]
struct DesktopSnapshot {
    reviews: std::result::Result<OwnerReviewQueues, SharedString>,
    activity: std::result::Result<Arc<[OwnerActivityRecord]>, SharedString>,
    clients: std::result::Result<Vec<McpClient>, SharedString>,
    accounts: std::result::Result<Vec<WalletMetadata>, SharedString>,
    policies: BTreeMap<String, std::result::Result<Option<StoredPolicy>, SharedString>>,
    legal_status: std::result::Result<LegalStatus, SharedString>,
    networks: std::result::Result<Vec<NetworkConfig>, SharedString>,
    message_documents: BTreeMap<uuid::Uuid, std::result::Result<ReviewDocument, SharedString>>,
    typed_data_documents: BTreeMap<uuid::Uuid, std::result::Result<ReviewDocument, SharedString>>,
}

impl DesktopSnapshot {
    fn capture(owner: &OwnerApi) -> Self {
        let reviews = cache_result(owner.reviews(None));
        let activity =
            cache_result(owner.activity(None, 200)).map(Arc::<[OwnerActivityRecord]>::from);
        let clients = cache_result(owner.clients());
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
            clients,
            accounts,
            policies,
            legal_status,
            networks,
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
    Ready(ReleaseCheck),
    Failed(SharedString),
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

enum WalletConnectScanState {
    Idle,
    Scanning,
    Choices {
        choices: QrChoices,
        previews: Vec<Arc<RenderImage>>,
    },
}

fn render_qr_preview(mut preview: QrPreview) -> Result<Arc<RenderImage>> {
    let expected = usize::try_from(preview.width)?
        .checked_mul(usize::try_from(preview.height)?)
        .and_then(|pixels| pixels.checked_mul(4))
        .context("QR preview dimensions overflow")?;
    ensure!(
        preview.rgba.len() == expected,
        "QR preview has inconsistent dimensions"
    );
    for pixel in preview.rgba.chunks_exact_mut(4) {
        pixel.swap(0, 2);
    }
    let pixels = std::mem::take(&mut preview.rgba);
    let buffer = image::RgbaImage::from_raw(preview.width, preview.height, pixels)
        .context("QR preview has inconsistent dimensions")?;
    Ok(Arc::new(RenderImage::new([image::Frame::new(buffer)])))
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
}

struct AccountExport {
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
    proposal: Option<PolicyProposal>,
    validation: Option<std::result::Result<PolicyDraftReview, SharedString>>,
    mode: PolicyEditorMode,
    guided_policy: std::result::Result<WalletPolicy, SharedString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyEditorMode {
    Guided,
    Advanced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuidedNativeValueMode {
    None,
    Any,
    Exact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuidedRuleEffect {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuidedLiteralMode {
    Any,
    Exact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuidedCalldataMode {
    Any,
    Empty,
    Selector,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct GuidedPolicyChainErrors {
    chain: Option<String>,
    label: Option<String>,
    max_calls: Option<String>,
    native_values: Option<String>,
    form: Option<String>,
}

struct GuidedPolicyChainDraft {
    chain: String,
    label: String,
    max_calls: String,
    native_value_mode: GuidedNativeValueMode,
    native_values: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct GuidedPolicyRuleErrors {
    chain: Option<String>,
    label: Option<String>,
    targets: Option<String>,
    senders: Option<String>,
    values: Option<String>,
    abi: Option<String>,
    args: Option<String>,
    form: Option<String>,
}

#[derive(Clone)]
struct GuidedPolicyRuleDraft {
    effect: GuidedRuleEffect,
    label: String,
    target_mode: GuidedLiteralMode,
    targets: String,
    sender_mode: GuidedLiteralMode,
    senders: String,
    value_mode: GuidedLiteralMode,
    values: String,
    calldata_mode: GuidedCalldataMode,
    abi: String,
    args: String,
}

struct PendingAgentInstall {
    display_name: String,
    preview: ConfigPreview,
}

#[allow(clippy::struct_excessive_bools)]
struct ActiveReview {
    state: ReviewState,
    simulation: Option<ekubo_wallet_core::simulation::SimulationResult>,
    completion: Option<ActiveReviewCompletion>,
    awaiting_refresh: bool,
    scroll_handle: ScrollHandle,
    scroll_check_scheduled: bool,
    scroll_layout_ready: bool,
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
        selected_account: usize,
        response: oneshot::Sender<ProposalCommand>,
    },
    AccountRemoval {
        wallet_id: String,
    },
}

enum QueuedReview {
    Transaction(Box<GuiReviewPrompt>),
    WalletConnect(ProposalPrompt),
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

    fn next(&mut self, active: bool) -> Option<T> {
        (!active).then(|| self.pending.pop_front()).flatten()
    }

    fn len(&self) -> usize {
        self.pending.len()
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

struct RouteListDelegate {
    routes: Vec<Route>,
    selected: Option<IndexPath>,
}

struct TokenListDelegate {
    owner: OwnerApi,
    editor: WeakEntity<WalletWindow>,
    all_tokens: Vec<StoredToken>,
    visible_tokens: Vec<StoredToken>,
    query: String,
    loading: bool,
    error: Option<SharedString>,
    action_errors: BTreeMap<(u64, alloy::primitives::Address), SharedString>,
    selected: Option<IndexPath>,
    pending_removal: Option<StoredToken>,
    removing: BTreeSet<(u64, alloy::primitives::Address)>,
    network_names: BTreeMap<u64, SharedString>,
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
    max_gas_limit: Option<String>,
    max_fee_per_gas: Option<String>,
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
    max_gas_limit: String,
    max_fee_per_gas: String,
    native_currency_name: String,
    native_currency_symbol: String,
    native_currency_decimals: String,
    block_explorer_url: String,
    documentation_url: String,
}

#[derive(Clone)]
struct ActivityFeedback {
    message: SharedString,
    error: bool,
}

fn render_activity_row(
    record: &OwnerActivityRecord,
    selected: bool,
    busy: bool,
    feedback: Option<ActivityFeedback>,
    editor: WeakEntity<WalletWindow>,
    cx: &mut App,
) -> gpui::Div {
    let request_id = record.request_id();
    let base = div().h(px(152.0)).pb_2();
    let card = match record {
        OwnerActivityRecord::Transaction(item) => {
            let status = item.status;
            let actions = transaction_actions(item.status);
            let inspect_editor = editor.clone();
            let refresh_editor = editor.clone();
            let send_editor = editor.clone();
            let cancel_editor = editor.clone();
            let discard_editor = editor;
            h_flex()
                .w_full()
                .flex_wrap()
                .justify_between()
                .gap_4()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .child(format!(
                            "{:?} · transaction · {} · {}",
                            item.status, item.wallet_id, item.network_name
                        ))
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .font_family(MONO_FONT_FAMILY)
                                .truncate()
                                .child(request_id.to_string()),
                        ),
                )
                .child(
                    h_flex()
                        .flex_wrap()
                        .gap_2()
                        .child(
                            Button::new(SharedString::from(format!(
                                "inspect-transaction-{request_id}"
                            )))
                            .label("Inspect")
                            .on_click(move |_, _, cx| {
                                let _ = inspect_editor.update(cx, |view, cx| {
                                    view.selected_record = Some(request_id);
                                    cx.notify();
                                });
                            }),
                        )
                        .when(actions.refresh, |buttons| {
                            buttons.child(
                                Button::new(SharedString::from(format!(
                                    "refresh-transaction-{request_id}"
                                )))
                                .label(if busy { "Working…" } else { "Refresh" })
                                .disabled(busy)
                                .on_click(move |_, _, cx| {
                                    let _ = refresh_editor.update(cx, |view, cx| {
                                        view.refresh_transaction(request_id, cx);
                                    });
                                }),
                            )
                        })
                        .when(actions.send, |buttons| {
                            buttons.child(
                                Button::new(SharedString::from(format!(
                                    "rebroadcast-transaction-{request_id}"
                                )))
                                .label(if status == PendingStatus::Signed {
                                    "Send signed bytes"
                                } else {
                                    "Rebroadcast"
                                })
                                .disabled(busy)
                                .on_click(move |_, _, cx| {
                                    let _ = send_editor.update(cx, |view, cx| {
                                        view.rebroadcast_transaction(request_id, cx);
                                    });
                                }),
                            )
                        })
                        .when(actions.cancel, |buttons| {
                            buttons.child(
                                Button::new(SharedString::from(format!(
                                    "cancel-transaction-{request_id}"
                                )))
                                .label(if status == PendingStatus::Cancelling {
                                    "Retry cancellation"
                                } else {
                                    "Cancel transaction"
                                })
                                .danger()
                                .disabled(busy)
                                .on_click(
                                    move |_, window, cx| {
                                        let _ = cancel_editor.update(cx, |view, cx| {
                                            view.confirm_transaction_cancellation(
                                                request_id, window, cx,
                                            );
                                        });
                                    },
                                ),
                            )
                        })
                        .when(actions.discard, |buttons| {
                            buttons.child(
                                Button::new(SharedString::from(format!("discard-{request_id}")))
                                    .label("Discard unsent signature")
                                    .danger()
                                    .disabled(busy)
                                    .on_click(move |_, _, cx| {
                                        let _ = discard_editor.update(cx, |view, cx| {
                                            view.discard_unsent_transaction(request_id, cx);
                                        });
                                    }),
                            )
                        }),
                )
                .into_any_element()
        }
        OwnerActivityRecord::Message(item) => {
            let inspect_editor = editor.clone();
            let review_editor = editor;
            h_flex()
                .w_full()
                .flex_wrap()
                .justify_between()
                .gap_4()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .child(format!(
                            "{:?} · message signature · {}",
                            item.status, item.wallet_id
                        ))
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .font_family(MONO_FONT_FAMILY)
                                .truncate()
                                .child(request_id.to_string()),
                        ),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new(SharedString::from(format!(
                                "inspect-message-{request_id}"
                            )))
                            .label("Inspect")
                            .on_click(move |_, _, cx| {
                                let _ = inspect_editor.update(cx, |view, cx| {
                                    view.selected_record = Some(request_id);
                                    cx.notify();
                                });
                            }),
                        )
                        .when(item.status == MessageStatus::AwaitingApproval, |buttons| {
                            buttons.child(
                                Button::new(SharedString::from(format!(
                                    "review-message-activity-{request_id}"
                                )))
                                .label("Review")
                                .on_click(move |_, _, cx| {
                                    let _ = review_editor.update(cx, |view, cx| {
                                        view.begin_message_review(request_id, cx);
                                    });
                                }),
                            )
                        }),
                )
                .into_any_element()
        }
        OwnerActivityRecord::TypedData(item) => {
            let inspect_editor = editor.clone();
            let review_editor = editor;
            h_flex()
                .w_full()
                .flex_wrap()
                .justify_between()
                .gap_4()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .child(format!(
                            "{:?} · typed-data signature · {} · chain {}",
                            item.status, item.wallet_id, item.chain_id
                        ))
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .font_family(MONO_FONT_FAMILY)
                                .truncate()
                                .child(request_id.to_string()),
                        ),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new(SharedString::from(format!(
                                "inspect-typed-data-{request_id}"
                            )))
                            .label("Inspect")
                            .on_click(move |_, _, cx| {
                                let _ = inspect_editor.update(cx, |view, cx| {
                                    view.selected_record = Some(request_id);
                                    cx.notify();
                                });
                            }),
                        )
                        .when(
                            item.status == TypedDataStatus::AwaitingApproval,
                            |buttons| {
                                buttons.child(
                                    Button::new(SharedString::from(format!(
                                        "review-typed-data-activity-{request_id}"
                                    )))
                                    .label("Review")
                                    .on_click(
                                        move |_, _, cx| {
                                            let _ = review_editor.update(cx, |view, cx| {
                                                view.begin_typed_data_review(request_id, cx);
                                            });
                                        },
                                    ),
                                )
                            },
                        ),
                )
                .into_any_element()
        }
    };
    base.map(|outer| {
        let mut card_container = div()
            .size_full()
            .p_3()
            .rounded_lg()
            .border_1()
            .border_color(if selected {
                cx.theme().primary
            } else {
                cx.theme().border
            })
            .flex()
            .flex_col()
            .justify_center()
            .gap_2()
            .child(card);
        if let Some(feedback) = feedback {
            card_container = card_container.child(
                div()
                    .text_sm()
                    .truncate()
                    .text_color(if feedback.error {
                        cx.theme().danger
                    } else {
                        cx.theme().muted_foreground
                    })
                    .child(feedback.message),
            );
        }
        outer.child(card_container)
    })
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
    fn new(owner: OwnerApi, editor: WeakEntity<WalletWindow>) -> Self {
        Self {
            owner,
            editor,
            all_tokens: Vec::new(),
            visible_tokens: Vec::new(),
            query: String::new(),
            loading: true,
            error: None,
            action_errors: BTreeMap::new(),
            selected: None,
            pending_removal: None,
            removing: BTreeSet::new(),
            network_names: BTreeMap::new(),
        }
    }

    fn replace_tokens(&mut self, result: Result<Vec<StoredToken>>) {
        self.loading = false;
        match result {
            Ok(tokens) => {
                if self
                    .pending_removal
                    .as_ref()
                    .is_some_and(|reviewed| !tokens.contains(reviewed))
                {
                    self.pending_removal = None;
                }
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
            .filter(|token| token_matches_search(token, &self.query))
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

    fn replace_networks(&mut self, networks: &[NetworkConfig]) {
        self.network_names = token_network_names(networks);
    }
}

fn token_network_names(networks: &[NetworkConfig]) -> BTreeMap<u64, SharedString> {
    networks
        .iter()
        .map(|network| {
            (
                network.chain_id,
                network
                    .display_name
                    .clone()
                    .unwrap_or_else(|| network.name.clone())
                    .into(),
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
                text: line.into(),
                kind,
            });
            line = continuation_prefix.to_owned();
            line_len = line.chars().count();
            prefix_len = line_len;
        }
        for character in word.chars() {
            if line_len == LEGAL_WRAP_COLUMNS {
                rows.push(LegalDisplayRow {
                    text: line.into(),
                    kind,
                });
                line = continuation_prefix.to_owned();
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

fn network_can_be_removed(network: &NetworkConfig) -> bool {
    network.disabled
}

fn restored_network_configuration(
    reviewed: &NetworkConfig,
    mut preset: NetworkConfig,
) -> NetworkConfig {
    preset.disabled = reviewed.disabled;
    preset.rpc_urls.truncate(1);
    preset
}

fn networks_for_display(networks: &[NetworkConfig]) -> Vec<&NetworkConfig> {
    let mut networks = networks.iter().collect::<Vec<_>>();
    networks.sort_by_key(|network| (network.chain_id, network.name.as_str()));
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
    let mut url = base.clone();
    let root = url.path().trim_end_matches('/');
    url.set_path(&format!("{root}/tx/{transaction_hash}"));
    Some(url.into())
}

fn network_preset_match_rank(profile: &NetworkProfile, query: &str) -> Option<(usize, usize)> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return Some((usize::from(!profile.is_default), 0));
    }
    let chain_id = profile.config.chain_id.to_string();
    let display_name = profile
        .config
        .display_name
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    let name = profile.config.name.to_lowercase();
    let aliases = profile
        .config
        .aliases
        .iter()
        .map(|alias| alias.to_lowercase())
        .collect::<Vec<_>>();
    std::iter::once(chain_id.as_str())
        .chain(std::iter::once(name.as_str()))
        .chain(std::iter::once(display_name.as_str()))
        .chain(aliases.iter().map(String::as_str))
        .filter_map(|value| {
            let position = value.find(&query)?;
            let kind = if value.len() == query.len() {
                0
            } else if position == 0 {
                1
            } else {
                2
            };
            Some((kind, position))
        })
        .min()
}

fn network_presets_for_display<'a>(
    presets: &'a [NetworkProfile],
    configured: &[NetworkConfig],
    query: &str,
    limit: usize,
) -> Vec<&'a NetworkProfile> {
    let configured_chains = configured
        .iter()
        .map(|network| network.chain_id)
        .collect::<BTreeSet<_>>();
    let mut matches = presets
        .iter()
        .filter_map(|profile| network_preset_match_rank(profile, query).map(|rank| (rank, profile)))
        .collect::<Vec<_>>();
    matches.sort_by_key(|(rank, profile)| {
        (
            *rank,
            profile.is_testnet,
            configured_chains.contains(&profile.config.chain_id),
            profile.config.chain_id,
        )
    });
    matches
        .into_iter()
        .take(limit)
        .map(|(_, profile)| profile)
        .collect()
}

fn networks_discarded_by_default_reset(
    configured: &[NetworkConfig],
    defaults: &[NetworkConfig],
) -> Vec<String> {
    let mut discarded = configured
        .iter()
        .filter(|network| !defaults.contains(network))
        .map(|network| network.name.clone())
        .collect::<Vec<_>>();
    discarded.sort();
    discarded
}

fn parse_network_editor_draft(
    draft: &NetworkEditorDraft,
    disabled: bool,
    rpc_strategy: RpcStrategy,
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

    let max_gas_limit = draft.max_gas_limit.trim();
    let max_gas_limit = if max_gas_limit.is_empty() {
        None
    } else if max_gas_limit.starts_with('0')
        || !max_gas_limit.bytes().all(|byte| byte.is_ascii_digit())
        || max_gas_limit.parse::<u64>().is_err()
        || max_gas_limit
            .parse::<u64>()
            .is_ok_and(|value| value < ekubo_wallet_core::config::INTRINSIC_GAS)
    {
        errors.max_gas_limit = Some(format!(
            "Enter a canonical integer of at least {} gas.",
            ekubo_wallet_core::config::INTRINSIC_GAS
        ));
        None
    } else {
        Some(max_gas_limit.to_owned())
    };
    let max_fee_per_gas = draft.max_fee_per_gas.trim();
    let max_fee_per_gas = if max_fee_per_gas.is_empty() {
        None
    } else if max_fee_per_gas.starts_with('0')
        || !max_fee_per_gas.bytes().all(|byte| byte.is_ascii_digit())
        || max_fee_per_gas.parse::<u128>().is_err()
    {
        errors.max_fee_per_gas =
            Some("Enter a canonical positive decimal wei amount that fits uint128.".into());
        None
    } else {
        Some(max_fee_per_gas.to_owned())
    };

    let native_values = [
        draft.native_currency_name.trim(),
        draft.native_currency_symbol.trim(),
        draft.native_currency_decimals.trim(),
    ];
    let native_currency = if native_values.iter().all(|value| value.is_empty()) {
        None
    } else if native_values.iter().any(|value| value.is_empty()) {
        errors.native_currency = Some(
            "Enter the native currency name, symbol, and decimals together, or leave all three blank."
                .into(),
        );
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
    let documentation_url =
        parse_optional_base_url(&draft.documentation_url).unwrap_or_else(|()| {
            errors.documentation_url =
                Some("Enter an http:// or https:// URL with no query string or fragment.".into());
            None
        });

    if errors != NetworkEditorErrors::default() {
        return (None, errors);
    }
    let network = NetworkConfig {
        name: name.to_owned(),
        disabled,
        display_name: (!display_name.is_empty()).then(|| display_name.to_owned()),
        aliases,
        chain_id: chain_id.expect("validated above"),
        rpc_urls,
        rpc_strategy,
        max_gas_limit,
        max_fee_per_gas,
        native_currency,
        block_explorer_url,
        documentation_url,
    };
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

fn rpc_urls_for_editor(urls: &[url::Url]) -> String {
    urls.iter()
        .map(url::Url::as_str)
        .collect::<Vec<_>>()
        .join(",\n")
}

fn token_removal_is_confirmed(pending: Option<&StoredToken>, row: &StoredToken) -> bool {
    pending == Some(row)
}

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

fn review_queue_decision_count(queues: &OwnerReviewQueues) -> usize {
    let token_sources = queues
        .token_proposals
        .iter()
        .map(|proposal| proposal.source.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    queues.transactions.len()
        + queues.typed_data.len()
        + queues.messages.len()
        + queues.policy_proposals.len()
        + queues.network_proposals.len()
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
        let editor = self.editor.clone();
        let edit_token = token.clone();
        let removal_token = token.clone();
        let begin_removal_token = token.clone();
        let removing = chain_id
            .zip(address)
            .is_some_and(|identity| self.removing.contains(&identity));
        let pending_removal = token_removal_is_confirmed(self.pending_removal.as_ref(), &token);
        let action_error = chain_id
            .zip(address)
            .and_then(|identity| self.action_errors.get(&identity).cloned());
        let row_id = format!("token-{}-{}", token.chain_id, token.address);
        let mut actions = div().flex().flex_col().flex_none().gap_1();
        if pending_removal {
            let confirm_state = state.clone();
            let owner = self.owner.clone();
            actions = actions
                .child(
                    Button::new(("confirm-remove-token", index.row))
                        .label(if removing {
                            "Authenticating…"
                        } else {
                            "Authenticate & remove"
                        })
                        .danger()
                        .disabled(removing)
                        .on_click(move |_, _, cx| {
                            let Some((chain_id, address)) = chain_id.zip(address) else {
                                return;
                            };
                            let reviewed = confirm_state
                                .update(cx, |list, cx| {
                                    let delegate = list.delegate_mut();
                                    if !token_removal_is_confirmed(
                                        delegate.pending_removal.as_ref(),
                                        &removal_token,
                                    ) {
                                        return None;
                                    }
                                    delegate.action_errors.remove(&(chain_id, address));
                                    delegate.removing.insert((chain_id, address));
                                    cx.notify();
                                    Some(removal_token.clone())
                                })
                                .ok()
                                .flatten();
                            let Some(reviewed) = reviewed else {
                                return;
                            };
                            let owner = owner.clone();
                            let state = confirm_state.clone();
                            let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                                owner.remove_token(&reviewed).await
                            });
                            cx.spawn(async move |cx| {
                                let result = task.await;
                                let _ = state.update(cx, |list, cx| {
                                    let delegate = list.delegate_mut();
                                    delegate.removing.remove(&(chain_id, address));
                                    match result {
                                        Ok(_) => {
                                            delegate.pending_removal = None;
                                            delegate.action_errors.remove(&(chain_id, address));
                                            delegate.all_tokens.retain(|item| {
                                                !(item.chain_id.parse::<u64>().ok()
                                                    == Some(chain_id)
                                                    && item
                                                        .address
                                                        .parse::<alloy::primitives::Address>()
                                                        .ok()
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
                        }),
                )
                .child(
                    Button::new(("cancel-remove-token", index.row))
                        .label("Cancel")
                        .disabled(removing)
                        .on_click({
                            let state = state.clone();
                            move |_, _, cx| {
                                let _ = state.update(cx, |list, cx| {
                                    list.delegate_mut().pending_removal = None;
                                    cx.notify();
                                });
                            }
                        }),
                );
        } else {
            actions = actions
                .child(
                    Button::new(("edit-token", index.row))
                        .icon(IconName::Settings2)
                        .ghost()
                        .tooltip("Edit token")
                        .accessibility_id("Edit token")
                        .disabled(chain_id.zip(address).is_none() || removing)
                        .on_click(move |_, window, cx| {
                            let _ = editor.update(cx, |view, cx| {
                                view.edit_token(&edit_token, window, cx);
                            });
                        }),
                )
                .child(
                    Button::new(("remove-token", index.row))
                        .icon(IconName::Delete)
                        .ghost()
                        .tooltip("Delete token")
                        .accessibility_id("Delete token")
                        .danger()
                        .disabled(chain_id.zip(address).is_none() || removing)
                        .on_click(move |_, _, cx| {
                            let Some(identity) = chain_id.zip(address) else {
                                return;
                            };
                            let removal_token = begin_removal_token.clone();
                            let _ = state.update(cx, |list, cx| {
                                let delegate = list.delegate_mut();
                                delegate.action_errors.remove(&identity);
                                delegate.pending_removal = Some(removal_token.clone());
                                cx.notify();
                            });
                        }),
                );
        }
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
                                            h_flex()
                                                .w_full()
                                                .gap_3()
                                                .child(
                                                    div().flex_1().min_w_0().truncate().child(
                                                        token
                                                            .symbol
                                                            .as_deref()
                                                            .unwrap_or("Unnamed token")
                                                            .to_owned(),
                                                    ),
                                                )
                                                .child(
                                                    div()
                                                        .flex_none()
                                                        .text_sm()
                                                        .text_color(cx.theme().muted_foreground)
                                                        .child(network_name),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .font_family(MONO_FONT_FAMILY)
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .truncate()
                                                .child(token.address.clone()),
                                        )
                                        .child(
                                            div()
                                                .min_w_0()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .truncate()
                                                .child(format!(
                                                    "{} · {} decimals · {}",
                                                    token.name.as_deref().unwrap_or("No full name"),
                                                    token.decimals.map_or_else(
                                                        || "unknown".to_owned(),
                                                        |value| value.to_string()
                                                    ),
                                                    token.source
                                                )),
                                        ),
                                )
                                .child(actions),
                        )
                        .when_some(action_error, |row, error| {
                            row.child(div().text_sm().text_color(cx.theme().danger).child(error))
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
            .child(
                self.error
                    .clone()
                    .unwrap_or_else(|| "No tokens match these filters.".into()),
            )
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
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .truncate()
                                        .child(token.symbol.clone()),
                                )
                                .child(
                                    div()
                                        .flex_none()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(network_name),
                                ),
                        )
                        .child(
                            div()
                                .font_family(MONO_FONT_FAMILY)
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .truncate()
                                .child(token.address.to_checksum(None)),
                        )
                        .child(
                            div()
                                .min_w_0()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .truncate()
                                .child(format!(
                                    "{} · {} decimals",
                                    token.name.as_deref().unwrap_or("No full name"),
                                    token.decimals
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

fn allow_anything_policy_document() -> Result<(String, WalletPolicy)> {
    let policy = WalletPolicy::allow_all_with_approval();
    let document = serde_json::to_string_pretty(&policy)?;
    Ok((document, policy))
}

fn update_guided_policy_chain(
    document: &str,
    original_key: Option<&str>,
    draft: &GuidedPolicyChainDraft,
) -> std::result::Result<(String, WalletPolicy), GuidedPolicyChainErrors> {
    let mut errors = GuidedPolicyChainErrors::default();
    let chain = draft.chain.trim();
    let canonical_chain = if chain == "*" {
        Some("*".to_owned())
    } else {
        match chain.parse::<u64>() {
            Ok(value) if value > 0 && value.to_string() == chain => Some(chain.to_owned()),
            _ => {
                errors.chain =
                    Some("Enter * or a positive decimal chain ID with no leading zeroes.".into());
                None
            }
        }
    };
    let label = draft.label.trim();
    if !label.is_empty()
        && (label.chars().count() > 160
            || ekubo_wallet_core::sanitize::stripped_capped(label, 160) != label)
    {
        errors.label = Some(
            "Use at most 160 visible characters with no control or bidirectional characters."
                .into(),
        );
    }
    let max_calls = if let Ok(value @ 1..=4096) = draft.max_calls.trim().parse::<u32>() {
        Some(value)
    } else {
        errors.max_calls = Some("Enter a whole number from 1 through 4096.".into());
        None
    };
    let native_value = match draft.native_value_mode {
        GuidedNativeValueMode::None => Some(serde_json::json!({ "eq": "0" })),
        GuidedNativeValueMode::Any => Some(serde_json::Value::String("any_value".into())),
        GuidedNativeValueMode::Exact => {
            let values = draft
                .native_values
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<BTreeSet<_>>();
            if values.is_empty()
                || values
                    .iter()
                    .any(|value| !value.bytes().all(|byte| byte.is_ascii_digit()))
            {
                errors.native_values = Some(
                    "Enter one or more non-negative decimal wei values, separated by commas."
                        .into(),
                );
                None
            } else {
                let values = values.into_iter().map(str::to_owned).collect::<Vec<_>>();
                Some(if values.len() == 1 {
                    serde_json::json!({ "eq": values[0] })
                } else {
                    serde_json::json!({ "in": values })
                })
            }
        }
    };
    if errors != GuidedPolicyChainErrors::default() {
        return Err(errors);
    }

    let mut value: serde_json::Value = match serde_json::from_str(document) {
        Ok(value) => value,
        Err(error) => {
            errors.form = Some(format!(
                "The advanced document is not valid JSON. Fix it before using the guided editor: {error}"
            ));
            return Err(errors);
        }
    };
    let Some(chains) = value
        .as_object_mut()
        .and_then(|root| root.get_mut("chains"))
        .and_then(serde_json::Value::as_object_mut)
    else {
        errors.form = Some("The policy document has no `chains` object.".into());
        return Err(errors);
    };
    let chain_key = canonical_chain.expect("validated above");
    if original_key != Some(chain_key.as_str()) && chains.contains_key(&chain_key) {
        errors.chain =
            Some("That chain already has a policy entry. Edit the existing entry.".into());
        return Err(errors);
    }
    let mut chain_value = match original_key {
        Some(key) => {
            if let Some(value) = chains.remove(key) {
                value
            } else {
                errors.form = Some("The chain entry changed while it was being edited.".into());
                return Err(errors);
            }
        }
        None => serde_json::json!({ "rules": [] }),
    };
    let Some(chain_object) = chain_value.as_object_mut() else {
        errors.form = Some("The selected chain entry is not an object.".into());
        return Err(errors);
    };
    if label.is_empty() {
        chain_object.remove("label");
    } else {
        chain_object.insert("label".into(), serde_json::Value::String(label.to_owned()));
    }
    chain_object.insert(
        "max_calls_per_batch".into(),
        serde_json::Value::Number(max_calls.expect("validated above").into()),
    );
    chain_object.insert(
        "native_value".into(),
        native_value.expect("validated above"),
    );
    chain_object
        .entry("rules")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    chains.insert(chain_key, chain_value);

    match WalletPolicy::parse(value) {
        Ok(policy) => match serde_json::to_string_pretty(&policy) {
            Ok(document) => Ok((document, policy)),
            Err(error) => {
                errors.form = Some(format!("Could not serialize the policy: {error:#}"));
                Err(errors)
            }
        },
        Err(error) => {
            errors.form = Some(format!("The resulting policy is invalid: {error:#}"));
            Err(errors)
        }
    }
}

fn remove_guided_policy_chain(document: &str, chain: &str) -> Result<(String, WalletPolicy)> {
    let mut value: serde_json::Value =
        serde_json::from_str(document).context("policy document is not valid JSON")?;
    let chains = value
        .as_object_mut()
        .and_then(|root| root.get_mut("chains"))
        .and_then(serde_json::Value::as_object_mut)
        .context("policy document has no `chains` object")?;
    ensure!(
        chains.remove(chain).is_some(),
        "the selected chain entry no longer exists"
    );
    let policy = WalletPolicy::parse(value)?;
    let document = serde_json::to_string_pretty(&policy)?;
    Ok((document, policy))
}

fn guided_literal_predicate(
    mode: GuidedLiteralMode,
    input: &str,
    address: bool,
) -> std::result::Result<Option<serde_json::Value>, String> {
    if mode == GuidedLiteralMode::Any {
        return Ok(None);
    }
    let values = input
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    if values.is_empty() {
        return Err(if address {
            "Enter one or more 0x-prefixed addresses, separated by commas.".into()
        } else {
            "Enter one or more non-negative decimal wei values, separated by commas.".into()
        });
    }
    let valid = if address {
        values.iter().all(|value| {
            *value == "$self"
                || (value.len() == 42
                    && value.starts_with("0x")
                    && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()))
        })
    } else {
        values
            .iter()
            .all(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
    };
    if !valid {
        return Err(if address {
            "Use complete 0x-prefixed addresses or $self, separated by commas.".into()
        } else {
            "Use non-negative decimal wei values, separated by commas.".into()
        });
    }
    let values = values.into_iter().map(str::to_owned).collect::<Vec<_>>();
    Ok(Some(if values.len() == 1 {
        serde_json::json!({ "eq": values[0] })
    } else {
        serde_json::json!({ "in": values })
    }))
}

fn update_guided_policy_rule(
    document: &str,
    chain_key: &str,
    original_index: Option<usize>,
    draft: &GuidedPolicyRuleDraft,
) -> std::result::Result<(String, WalletPolicy), Box<GuidedPolicyRuleErrors>> {
    let mut errors = GuidedPolicyRuleErrors::default();
    let label = draft.label.trim();
    if !label.is_empty()
        && (label.chars().count() > 160
            || ekubo_wallet_core::sanitize::stripped_capped(label, 160) != label)
    {
        errors.label = Some(
            "Use at most 160 visible characters with no control or bidirectional characters."
                .into(),
        );
    }
    let target = guided_literal_predicate(draft.target_mode, &draft.targets, true)
        .map_err(|error| errors.targets = Some(error))
        .ok()
        .flatten();
    let sender = guided_literal_predicate(draft.sender_mode, &draft.senders, true)
        .map_err(|error| errors.senders = Some(error))
        .ok()
        .flatten();
    let native_value = guided_literal_predicate(draft.value_mode, &draft.values, false)
        .map_err(|error| errors.values = Some(error))
        .ok()
        .flatten();
    let calldata = match draft.calldata_mode {
        GuidedCalldataMode::Any => None,
        GuidedCalldataMode::Empty => Some(serde_json::json!({ "eq": "0x" })),
        GuidedCalldataMode::Selector => {
            let abi = draft.abi.trim();
            if abi.is_empty() {
                errors.abi = Some("Enter the complete canonical function signature.".into());
            }
            let args = match serde_json::from_str::<serde_json::Value>(draft.args.trim()) {
                Ok(serde_json::Value::Object(args)) => Some(args),
                Ok(_) => {
                    errors.args = Some("Argument constraints must be a JSON object.".into());
                    None
                }
                Err(error) => {
                    errors.args = Some(format!("Argument constraints are not valid JSON: {error}"));
                    None
                }
            };
            args.filter(|_| !abi.is_empty()).map(|args| {
                if args.is_empty() {
                    serde_json::json!({ "selector": { "abi": abi } })
                } else {
                    serde_json::json!({ "selector": { "abi": abi, "args": args } })
                }
            })
        }
    };
    if errors != GuidedPolicyRuleErrors::default() {
        return Err(Box::new(errors));
    }

    let mut rule = serde_json::Map::new();
    rule.insert(
        "effect".into(),
        serde_json::Value::String(
            match draft.effect {
                GuidedRuleEffect::Allow => "allow",
                GuidedRuleEffect::Deny => "deny",
            }
            .into(),
        ),
    );
    if !label.is_empty() {
        rule.insert("label".into(), serde_json::Value::String(label.into()));
    }
    for (slot, predicate) in [
        ("to", target),
        ("from", sender),
        ("value", native_value),
        ("calldata", calldata),
    ] {
        if let Some(predicate) = predicate {
            rule.insert(slot.into(), predicate);
        }
    }

    let mut value: serde_json::Value = match serde_json::from_str(document) {
        Ok(value) => value,
        Err(error) => {
            errors.form = Some(format!(
                "The advanced document is not valid JSON. Fix it before using the guided editor: {error}"
            ));
            return Err(Box::new(errors));
        }
    };
    let rules = value
        .as_object_mut()
        .and_then(|root| root.get_mut("chains"))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|chains| chains.get_mut(chain_key))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|chain| chain.get_mut("rules"))
        .and_then(serde_json::Value::as_array_mut);
    let Some(rules) = rules else {
        errors.chain = Some("The selected chain entry no longer exists.".into());
        return Err(Box::new(errors));
    };
    let rule = serde_json::Value::Object(rule);
    if let Some(index) = original_index {
        let Some(existing) = rules.get_mut(index) else {
            errors.form = Some("The selected rule changed while it was being edited.".into());
            return Err(Box::new(errors));
        };
        *existing = rule;
    } else {
        rules.push(rule);
    }
    match WalletPolicy::parse(value) {
        Ok(policy) => match serde_json::to_string_pretty(&policy) {
            Ok(document) => Ok((document, policy)),
            Err(error) => {
                errors.form = Some(format!("Could not serialize the policy: {error:#}"));
                Err(Box::new(errors))
            }
        },
        Err(error) => {
            if draft.calldata_mode == GuidedCalldataMode::Selector {
                errors.abi = Some(format!(
                    "The selector or its predicates are invalid: {error:#}"
                ));
            } else {
                errors.form = Some(format!("The resulting rule is invalid: {error:#}"));
            }
            Err(Box::new(errors))
        }
    }
}

fn remove_guided_policy_rule(
    document: &str,
    chain_key: &str,
    index: usize,
) -> Result<(String, WalletPolicy)> {
    let mut value: serde_json::Value =
        serde_json::from_str(document).context("policy document is not valid JSON")?;
    let rules = value
        .as_object_mut()
        .and_then(|root| root.get_mut("chains"))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|chains| chains.get_mut(chain_key))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|chain| chain.get_mut("rules"))
        .and_then(serde_json::Value::as_array_mut)
        .context("the selected chain has no rule list")?;
    ensure!(index < rules.len(), "the selected rule no longer exists");
    rules.remove(index);
    let policy = WalletPolicy::parse(value)?;
    let document = serde_json::to_string_pretty(&policy)?;
    Ok((document, policy))
}

fn guided_predicate_values(
    predicate: Option<&ekubo_wallet_core::core::predicate::Predicate>,
) -> Result<(GuidedLiteralMode, String)> {
    let Some(predicate) = predicate else {
        return Ok((GuidedLiteralMode::Any, String::new()));
    };
    let value = serde_json::to_value(predicate)?;
    match value {
        serde_json::Value::String(value) if value == "any_value" => {
            Ok((GuidedLiteralMode::Any, String::new()))
        }
        serde_json::Value::Object(object) if object.len() == 1 => {
            if let Some(serde_json::Value::String(value)) = object.get("eq") {
                Ok((GuidedLiteralMode::Exact, value.clone()))
            } else if let Some(serde_json::Value::Array(values)) = object.get("in") {
                let values = values
                    .iter()
                    .map(serde_json::Value::as_str)
                    .collect::<Option<Vec<_>>>()
                    .context("the literal set contains a non-string value")?;
                Ok((GuidedLiteralMode::Exact, values.join(", ")))
            } else {
                anyhow::bail!("this predicate requires Advanced JSON")
            }
        }
        _ => anyhow::bail!("this predicate requires Advanced JSON"),
    }
}

fn guided_rule_draft(rule: &Rule) -> Result<GuidedPolicyRuleDraft> {
    let (target_mode, targets) = guided_predicate_values(rule.to.as_ref())?;
    let (sender_mode, senders) = guided_predicate_values(rule.from.as_ref())?;
    let (value_mode, values) = guided_predicate_values(rule.value.as_ref())?;
    let (calldata_mode, abi, args) = match rule.calldata.as_ref() {
        None => (GuidedCalldataMode::Any, String::new(), "{}".into()),
        Some(predicate) => {
            let value = serde_json::to_value(predicate)?;
            match value {
                serde_json::Value::String(value) if value == "any_value" => {
                    (GuidedCalldataMode::Any, String::new(), "{}".into())
                }
                serde_json::Value::Object(object)
                    if object.len() == 1
                        && object.get("eq") == Some(&serde_json::Value::String("0x".into())) =>
                {
                    (GuidedCalldataMode::Empty, String::new(), "{}".into())
                }
                serde_json::Value::Object(object) if object.len() == 1 => {
                    let selector = object
                        .get("selector")
                        .and_then(serde_json::Value::as_object)
                        .context("this calldata predicate requires Advanced JSON")?;
                    let abi = selector
                        .get("abi")
                        .and_then(serde_json::Value::as_str)
                        .context("this selector has no ABI signature")?
                        .to_owned();
                    let args = selector
                        .get("args")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));
                    let args = serde_json::to_string_pretty(&args)?;
                    (GuidedCalldataMode::Selector, abi, args)
                }
                _ => anyhow::bail!("this calldata predicate requires Advanced JSON"),
            }
        }
    };
    Ok(GuidedPolicyRuleDraft {
        effect: match rule.effect {
            Effect::Allow => GuidedRuleEffect::Allow,
            Effect::Deny => GuidedRuleEffect::Deny,
        },
        label: rule.label.clone().unwrap_or_default(),
        target_mode,
        targets,
        sender_mode,
        senders,
        value_mode,
        values,
        calldata_mode,
        abi,
        args,
    })
}

impl WalletWindow {
    fn new(
        owner: OwnerApi,
        review_presenter: GuiReviewPresenter,
        walletconnect: Arc<Mutex<WalletConnectManager>>,
        walletconnect_presenter: ProposalPresenter,
        detailed_notification_previews: Arc<AtomicBool>,
        tray: Rc<RefCell<Option<PlatformTray>>>,
        cx: &mut Context<Self>,
    ) -> Self {
        let appearance_preference = owner.appearance_preference().unwrap_or_default();
        let network_presets = Arc::from(owner.network_presets());
        let route_scroll_handle = ScrollHandle::new();
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
            route: Route::Overview,
            command_palette: false,
            command_palette_list: None,
            command_palette_subscription: None,
            token_list: None,
            token_proposal_list: None,
            token_list_url_input: None,
            token_chain_id_input: None,
            token_address_input: None,
            token_symbol_input: None,
            token_name_input: None,
            token_decimals_input: None,
            token_editor_open: false,
            token_editor_original: None,
            token_editor_errors: TokenEditorErrors::default(),
            token_editor_busy: false,
            token_import_state: TokenImportState::Idle,
            token_import_error: None,
            token_import_status: None,
            token_proposal_error: None,
            token_list_generation: 0,
            mcp_status: "MCP starting…".into(),
            selected_record: None,
            activity_busy: BTreeSet::new(),
            activity_feedback: BTreeMap::new(),
            active_review: None,
            queued_reviews: SerialQueue::default(),
            review_flow: ReviewFlowState::Ready,
            pending_agent_install: None,
            agent_reinstall: AgentReinstallState::Idle,
            detected_agents: AgentDetectionState::Loading,
            detected_agents_generation: 0,
            hidden_agent_sessions: BTreeSet::new(),
            account_id_input: None,
            private_key_input: None,
            account_id_error: None,
            private_key_error: None,
            account_action_errors: BTreeMap::new(),
            account_export: None,
            legal_review: None,
            legal_gate: false,
            route_errors: BTreeMap::new(),
            detailed_notification_previews,
            appearance_preference,
            notification_preference_busy: false,
            portfolio: PortfolioState::Idle,
            portfolio_generation: 0,
            portfolio_chain_id: None,
            network_editor_anchor: ScrollAnchor::for_handle(route_scroll_handle.clone()),
            token_editor_anchor: ScrollAnchor::for_handle(route_scroll_handle.clone()),
            policy_editor_anchor: ScrollAnchor::for_handle(route_scroll_handle.clone()),
            route_scroll_handle,
            modal_focus: cx.focus_handle(),
            walletconnect,
            walletconnect_sessions: Vec::new(),
            walletconnect_presenter,
            walletconnect_uri_input: None,
            walletconnect_scan: WalletConnectScanState::Idle,
            walletconnect_scan_generation: 0,
            network_json_input: None,
            network_json_error: None,
            network_editor_open: false,
            network_editor_original: None,
            network_editor_disabled: false,
            network_editor_rpc_strategy: RpcStrategy::Ordered,
            network_editor_advanced: false,
            network_editor_busy: false,
            network_editor_errors: NetworkEditorErrors::default(),
            network_name_input: None,
            network_display_name_input: None,
            network_aliases_input: None,
            network_chain_id_input: None,
            network_rpc_urls_input: None,
            network_max_gas_limit_input: None,
            network_max_fee_per_gas_input: None,
            network_native_name_input: None,
            network_native_symbol_input: None,
            network_native_decimals_input: None,
            network_explorer_url_input: None,
            network_documentation_url_input: None,
            network_presets,
            network_preset_search_input: None,
            network_preset_search_subscription: None,
            network_preset_busy: None,
            network_preset_error: None,
            network_reset_error: None,
            pending_network_reset: None,
            network_reset_busy: false,
            network_action_busy: BTreeSet::new(),
            network_action_errors: BTreeMap::new(),
            expanded_networks: BTreeSet::new(),
            pending_network_removal: None,
            network_proposal_error: None,
            policy_json_input: None,
            policy_editor: None,
            policy_chain_input: None,
            policy_chain_label_input: None,
            policy_chain_max_calls_input: None,
            policy_chain_native_values_input: None,
            policy_chain_original_key: None,
            policy_chain_native_value_mode: GuidedNativeValueMode::None,
            policy_chain_errors: GuidedPolicyChainErrors::default(),
            policy_rule_chain_key: None,
            policy_rule_original_index: None,
            policy_rule_effect: GuidedRuleEffect::Allow,
            policy_rule_target_mode: GuidedLiteralMode::Any,
            policy_rule_sender_mode: GuidedLiteralMode::Any,
            policy_rule_value_mode: GuidedLiteralMode::Any,
            policy_rule_calldata_mode: GuidedCalldataMode::Any,
            policy_rule_label_input: None,
            policy_rule_targets_input: None,
            policy_rule_senders_input: None,
            policy_rule_values_input: None,
            policy_rule_abi_input: None,
            policy_rule_args_input: None,
            policy_rule_errors: GuidedPolicyRuleErrors::default(),
            policy_installing: false,
            policy_action_error: None,
            token_proposal_busy: false,
            network_proposal_busy: false,
            release_state: ReleaseDisplayState::Idle,
        };
        window.open_next_required_legal(cx);
        window.reload_detected_agents(cx);
        window.reload_desktop_snapshot(cx);
        window
    }

    fn attach_window(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mut token_lists_created = false;
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
            let editor = cx.entity().downgrade();
            self.token_list = Some(cx.new(|cx| {
                ListState::new(TokenListDelegate::new(owner, editor), window, cx)
                    .searchable(true)
                    .selectable(false)
            }));
            token_lists_created = true;
            self.reload_tokens(cx);
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
                    list.delegate_mut().replace_networks(networks);
                    cx.notify();
                });
            }
            if let Some(list) = self.token_proposal_list.as_ref() {
                list.update(cx, |list, cx| {
                    list.delegate_mut().replace_networks(networks);
                    cx.notify();
                });
            }
        }
        if self.token_list_url_input.is_none() {
            self.token_list_url_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("https://tokens.example.org/tokens.json")
            }));
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
            self.token_decimals_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("18")));
        }
        if self.account_id_input.is_none() {
            self.account_id_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Account name, for example primary")
            }));
        }
        if self.private_key_input.is_none() {
            self.private_key_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("0x-prefixed 32-byte private key")
                    .masked(true)
            }));
        }
        if self.walletconnect_uri_input.is_none() {
            self.walletconnect_uri_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("wc: pairing URI")));
        }
        if self.network_json_input.is_none() {
            self.network_json_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .code_editor("json")
                    .rows(12)
                    .placeholder("Paste a complete network JSON object")
            }));
        }
        if self.network_name_input.is_none() {
            self.network_name_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Internal name, for example ethereum")
            }));
        }
        if self.network_display_name_input.is_none() {
            self.network_display_name_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Display name, for example Ethereum")
            }));
        }
        if self.network_aliases_input.is_none() {
            self.network_aliases_input =
                Some(cx.new(|cx| {
                    InputState::new(window, cx).placeholder("Aliases separated by commas")
                }));
        }
        if self.network_chain_id_input.is_none() {
            self.network_chain_id_input =
                Some(cx.new(|cx| {
                    InputState::new(window, cx).placeholder("Positive decimal chain ID")
                }));
        }
        if self.network_rpc_urls_input.is_none() {
            self.network_rpc_urls_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .rows(5)
                    .placeholder("https://primary.example,\nhttps://fallback.example")
            }));
        }
        if self.network_max_gas_limit_input.is_none() {
            self.network_max_gas_limit_input =
                Some(cx.new(|cx| {
                    InputState::new(window, cx).placeholder("Optional maximum gas limit")
                }));
        }
        if self.network_max_fee_per_gas_input.is_none() {
            self.network_max_fee_per_gas_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Optional maximum fee per gas in wei")
            }));
        }
        if self.network_native_name_input.is_none() {
            self.network_native_name_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Currency name, for example Ether")
            }));
        }
        if self.network_native_symbol_input.is_none() {
            self.network_native_symbol_input = Some(
                cx.new(|cx| InputState::new(window, cx).placeholder("Symbol, for example ETH")),
            );
        }
        if self.network_native_decimals_input.is_none() {
            self.network_native_decimals_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("Decimals, usually 18")));
        }
        if self.network_explorer_url_input.is_none() {
            self.network_explorer_url_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Optional block explorer base URL")
            }));
        }
        if self.network_documentation_url_input.is_none() {
            self.network_documentation_url_input =
                Some(cx.new(|cx| {
                    InputState::new(window, cx).placeholder("Optional documentation URL")
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
        if self.policy_chain_input.is_none() {
            self.policy_chain_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Chain ID, or * for every chain")
            }));
        }
        if self.policy_chain_label_input.is_none() {
            self.policy_chain_label_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("What this chain policy is for")
            }));
        }
        if self.policy_chain_max_calls_input.is_none() {
            self.policy_chain_max_calls_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Maximum calls per batch")
                    .default_value("1")
            }));
        }
        if self.policy_chain_native_values_input.is_none() {
            self.policy_chain_native_values_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder(
                    "Comma-separated exact wei values, for example 0, 1000000000000000000",
                )
            }));
        }
        if self.policy_rule_label_input.is_none() {
            self.policy_rule_label_input =
                Some(cx.new(|cx| {
                    InputState::new(window, cx).placeholder("What this permission is for")
                }));
        }
        if self.policy_rule_targets_input.is_none() {
            self.policy_rule_targets_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("0x-prefixed target addresses, separated by commas")
            }));
        }
        if self.policy_rule_senders_input.is_none() {
            self.policy_rule_senders_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("0x-prefixed sender addresses or $self")
            }));
        }
        if self.policy_rule_values_input.is_none() {
            self.policy_rule_values_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Exact wei values, separated by commas")
            }));
        }
        if self.policy_rule_abi_input.is_none() {
            self.policy_rule_abi_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("transfer(address to, uint256 amount)")
            }));
        }
        if self.policy_rule_args_input.is_none() {
            self.policy_rule_args_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .code_editor("json")
                    .rows(6)
                    .default_value("{}")
                    .placeholder("Typed argument predicate object")
            }));
        }
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
        self.detected_agents = AgentDetectionState::Loading;
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
                        if let Ok(clients) = &snapshot.clients {
                            view.hidden_agent_sessions.retain(|client_id| {
                                clients.iter().any(|client| {
                                    client.id == *client_id && client.revoked_at.is_some()
                                })
                            });
                        }
                        if let Ok(networks) = &snapshot.networks {
                            if view
                                .pending_network_removal
                                .as_ref()
                                .is_some_and(|reviewed| !networks.contains(reviewed))
                            {
                                view.pending_network_removal = None;
                            }
                            if let Some(list) = view.token_list.as_ref() {
                                list.update(cx, |list, cx| {
                                    list.delegate_mut().replace_networks(networks);
                                    cx.notify();
                                });
                            }
                            if let Some(list) = view.token_proposal_list.as_ref() {
                                list.update(cx, |list, cx| {
                                    list.delegate_mut().replace_networks(networks);
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

    fn cached_clients(&self) -> Result<&[McpClient]> {
        self.snapshot()?
            .clients
            .as_deref()
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
        let Some(chain_id) = self.token_chain_id_input.as_ref() else {
            return;
        };
        let Some(address) = self.token_address_input.as_ref() else {
            return;
        };
        let Some(symbol) = self.token_symbol_input.as_ref() else {
            return;
        };
        let Some(name) = self.token_name_input.as_ref() else {
            return;
        };
        let Some(decimals) = self.token_decimals_input.as_ref() else {
            return;
        };
        for input in [chain_id, address, symbol, name, decimals] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.token_editor_open = true;
        self.token_editor_original = None;
        self.token_editor_errors = TokenEditorErrors::default();
        chain_id.update(cx, |input, cx| input.focus(window, cx));
        self.token_editor_anchor.scroll_to(window, cx);
        cx.notify();
    }

    fn edit_token(&mut self, token: &StoredToken, window: &mut Window, cx: &mut Context<Self>) {
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
        let Ok(chain_id) = token.chain_id.parse::<u64>() else {
            self.token_editor_errors.form =
                Some("This stored token has an invalid chain ID.".to_owned());
            self.token_editor_open = true;
            cx.notify();
            return;
        };
        let Ok(address) = token.address.parse::<alloy::primitives::Address>() else {
            self.token_editor_errors.form =
                Some("This stored token has an invalid address.".to_owned());
            self.token_editor_open = true;
            cx.notify();
            return;
        };
        chain_id_input.update(cx, |input, cx| {
            input.set_value(chain_id.to_string(), window, cx);
        });
        address_input.update(cx, |input, cx| {
            input.set_value(address.to_checksum(None), window, cx);
        });
        symbol_input.update(cx, |input, cx| {
            input.set_value(token.symbol.clone().unwrap_or_default(), window, cx);
            input.set_selected_range(0..input.value().len(), cx);
            input.focus(window, cx);
        });
        name_input.update(cx, |input, cx| {
            input.set_value(token.name.clone().unwrap_or_default(), window, cx);
        });
        decimals_input.update(cx, |input, cx| {
            input.set_value(
                token
                    .decimals
                    .map_or_else(String::new, |value| value.to_string()),
                window,
                cx,
            );
        });
        self.token_editor_open = true;
        self.token_editor_original = Some(token.clone());
        self.token_editor_errors = TokenEditorErrors::default();
        self.token_editor_anchor.scroll_to(window, cx);
        cx.notify();
    }

    fn close_token_editor(&mut self, cx: &mut Context<Self>) {
        if self.token_editor_busy {
            return;
        }
        self.token_editor_open = false;
        self.token_editor_original = None;
        self.token_editor_errors = TokenEditorErrors::default();
        cx.notify();
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
        if let Some(original) = self.token_editor_original.as_ref()
            && let (Ok(original_chain_id), Ok(original_address)) = (
                original.chain_id.parse::<u64>(),
                original.address.parse::<alloy::primitives::Address>(),
            )
            && (original_chain_id, original_address) != (token.chain_id, token.address)
        {
            errors.chain_id = Some("Chain ID cannot change while editing a token.".to_owned());
            errors.address = Some("Address cannot change while editing a token.".to_owned());
            self.token_editor_errors = errors;
            cx.notify();
            return;
        }
        match self.cached_networks() {
            Ok(networks)
                if networks
                    .iter()
                    .any(|network| network.chain_id == token.chain_id) => {}
            Ok(_) => {
                errors.chain_id = Some("Choose a chain ID that exists in Networks.".to_owned());
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
        let original = self.token_editor_original.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            match original {
                Some(original) => owner.replace_token(&original, token).await,
                None => owner.add_token(token).await,
            }
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.token_editor_busy = false;
                match result {
                    Ok(_) => {
                        view.token_editor_open = false;
                        view.token_editor_original = None;
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

    fn scan_walletconnect_screen(&mut self, cx: &mut Context<Self>) {
        if matches!(self.walletconnect_scan, WalletConnectScanState::Scanning) {
            return;
        }
        match self.cached_accounts() {
            Ok([]) => {
                self.set_route_error(
                    Route::WalletConnect,
                    "Create an account before scanning a WalletConnect pairing.",
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
        if !SystemScreenPicker::supported() {
            self.set_route_error(
                Route::WalletConnect,
                "Screen scanning is not available on this platform.",
            );
            cx.notify();
            return;
        }
        self.walletconnect_scan_generation = self.walletconnect_scan_generation.wrapping_add(1);
        let generation = self.walletconnect_scan_generation;
        self.walletconnect_scan = WalletConnectScanState::Scanning;
        self.clear_route_error(Route::WalletConnect);
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(|| scan_screen(&SystemScreenPicker))
                .await
                .context("screen scanning task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update_in(cx, |view, window, cx| {
                if view.walletconnect_scan_generation != generation
                    || view.route != Route::WalletConnect
                {
                    return;
                }
                match result {
                    Ok(None) => view.walletconnect_scan = WalletConnectScanState::Idle,
                    Ok(Some(choices)) if choices.is_empty() => {
                        view.walletconnect_scan = WalletConnectScanState::Idle;
                        view.set_route_error(
                            Route::WalletConnect,
                            "No valid, unexpired WalletConnect QR code was found.",
                        );
                    }
                    Ok(Some(choices)) if choices.len() == 1 => {
                        let uri = choices.take(0);
                        view.walletconnect_scan = WalletConnectScanState::Idle;
                        match uri {
                            Ok(uri) => {
                                if let Some(input) = view.walletconnect_uri_input.as_ref() {
                                    input.update(cx, |input, cx| {
                                        input.set_value(uri.as_str(), window, cx);
                                        input.focus(window, cx);
                                    });
                                }
                                view.clear_route_error(Route::WalletConnect);
                            }
                            Err(error) => view.set_route_error(
                                Route::WalletConnect,
                                format!("Could not read the QR code: {error:#}"),
                            ),
                        }
                    }
                    Ok(Some(mut choices)) => {
                        let previews = choices
                            .take_previews()
                            .into_iter()
                            .map(render_qr_preview)
                            .collect::<Result<Vec<_>>>();
                        match previews {
                            Ok(previews) => {
                                view.walletconnect_scan =
                                    WalletConnectScanState::Choices { choices, previews };
                            }
                            Err(error) => {
                                view.walletconnect_scan = WalletConnectScanState::Idle;
                                view.set_route_error(
                                    Route::WalletConnect,
                                    format!("Could not display QR choices: {error:#}"),
                                );
                            }
                        }
                    }
                    Err(error) => {
                        view.walletconnect_scan = WalletConnectScanState::Idle;
                        view.set_route_error(
                            Route::WalletConnect,
                            format!("Could not scan screen: {error:#}"),
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn choose_walletconnect_qr(
        &mut self,
        index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.walletconnect_scan_generation = self.walletconnect_scan_generation.wrapping_add(1);
        let state = std::mem::replace(&mut self.walletconnect_scan, WalletConnectScanState::Idle);
        let WalletConnectScanState::Choices { choices, .. } = state else {
            return;
        };
        match choices.take(index) {
            Ok(uri) => {
                if let Some(input) = self.walletconnect_uri_input.as_ref() {
                    input.update(cx, |input, cx| {
                        input.set_value(uri.as_str(), window, cx);
                        input.focus(window, cx);
                    });
                }
                self.clear_route_error(Route::WalletConnect);
            }
            Err(error) => self.set_route_error(
                Route::WalletConnect,
                format!("Could not read the QR code: {error:#}"),
            ),
        }
        cx.notify();
    }

    fn cancel_walletconnect_scan(&mut self, cx: &mut Context<Self>) {
        self.walletconnect_scan_generation = self.walletconnect_scan_generation.wrapping_add(1);
        self.walletconnect_scan = WalletConnectScanState::Idle;
        cx.notify();
    }

    fn disconnect_walletconnect(&mut self, session_id: uuid::Uuid, cx: &mut Context<Self>) {
        let result = self
            .walletconnect
            .lock()
            .map_err(|_| anyhow::anyhow!("WalletConnect session state is unavailable"))
            .and_then(|mut manager| manager.disconnect(session_id).map(|_| ()));
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
        let Some(QueuedReview::WalletConnect(prompt)) = self.queued_reviews.receive(
            self.active_review.is_some() || self.review_flow.is_in_progress(),
            QueuedReview::WalletConnect(prompt),
        ) else {
            return;
        };
        self.activate_walletconnect_prompt(prompt);
    }

    fn activate_walletconnect_prompt(&mut self, prompt: ProposalPrompt) {
        let document = prompt.choices[0].document.clone();
        self.active_review = Some(ActiveReview {
            state: ReviewState::new(document),
            simulation: None,
            completion: Some(ActiveReviewCompletion::WalletConnect {
                choices: prompt.choices,
                selected_account: 0,
                response: prompt.response,
            }),
            awaiting_refresh: false,
            scroll_handle: ScrollHandle::new(),
            scroll_check_scheduled: false,
            scroll_layout_ready: false,
        });
    }

    fn activate_next_queued_review(&mut self) {
        if self.active_review.is_some() || self.review_flow.is_in_progress() {
            return;
        }
        match self.queued_reviews.next(self.active_review.is_some()) {
            Some(QueuedReview::Transaction(prompt)) => self.activate_transaction_prompt(*prompt),
            Some(QueuedReview::WalletConnect(prompt)) => {
                self.activate_walletconnect_prompt(prompt);
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
            Route::Reviews
        }
    }

    fn finish_review_flow(&mut self) {
        self.review_flow = ReviewFlowState::Ready;
        self.activate_next_queued_review();
        if self.active_review.is_some() {
            let route = self.active_review_route();
            self.set_route(route);
        }
    }

    fn select_walletconnect_account(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(active) = self.active_review.as_mut() else {
            return;
        };
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
        *selected_account = index;
        active.state = ReviewState::new(choice.document.clone());
        cx.notify();
    }

    fn create_account(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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
        match self
            .owner
            .create_account(&wallet_id, &WalletPolicy::require_approval_for_everything())
        {
            Ok(account) => {
                input.update(cx, |input, cx| input.set_value("", window, cx));
                self.account_action_errors.remove(&account.id);
            }
            Err(error) => {
                self.account_id_error = Some(format!("Could not create account: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn import_account(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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
        key_input.update(cx, |input, cx| input.set_value("", window, cx));
        let key = match PrivateKeyMaterial::from_hex(&secret) {
            Ok(key) => key,
            Err(error) => {
                self.private_key_error = Some(format!("{error:#}").into());
                cx.notify();
                return;
            }
        };
        match self.owner.import_account(&wallet_id, key) {
            Ok(account) => {
                id_input.update(cx, |input, cx| input.set_value("", window, cx));
                self.account_action_errors.remove(&account.id);
            }
            Err(error) => {
                self.account_id_error = Some(format!("Could not import account: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn begin_account_export(&mut self, wallet_id: String, cx: &mut Context<Self>) {
        self.account_export = Some(AccountExport {
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
                            && export.wallet_id == wallet_id
                        {
                            export.authenticating = false;
                            export.lease = Some(lease);
                            export.copied = false;
                            export.error = None;
                        }
                    }
                    Err(error) => {
                        if let Some(export) = view.account_export.as_mut()
                            && export.wallet_id == wallet_id
                        {
                            export.authenticating = false;
                            export.error =
                                Some(format!("Private-key export cancelled: {error:#}").into());
                        }
                    }
                }
                cx.notify();
            });
            cx.background_executor()
                .timer(PRIVATE_KEY_REVEAL_DURATION)
                .await;
            let _ = view.update(cx, |_, cx| cx.notify());
        })
        .detach();
        cx.notify();
    }

    fn copy_account_export(&mut self, cx: &mut Context<Self>) {
        let Some(export) = self.account_export.as_mut() else {
            return;
        };
        let Some(value) = export.lease.as_ref().and_then(ExportLease::visible_value) else {
            export.error = Some("The private-key reveal has expired.".into());
            cx.notify();
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        export.copied = true;
        export.error = None;
        cx.spawn(async move |_, cx| {
            cx.background_executor()
                .timer(PRIVATE_KEY_REVEAL_DURATION)
                .await;
            cx.update(|cx| {
                if cx
                    .read_from_clipboard()
                    .and_then(|item| item.text())
                    .as_deref()
                    == Some(value.as_str())
                {
                    cx.write_to_clipboard(ClipboardItem::new_string(String::new()));
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn open_policy_editor(&mut self, wallet_id: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(input) = self.policy_json_input.as_ref() else {
            return;
        };
        match self.owner.policy(wallet_id) {
            Ok(stored) => {
                let source_revision = stored.as_ref().map(|policy| policy.revision);
                let current_policy = stored.map(|policy| policy.policy);
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
                            guided_policy: Ok(current_policy
                                .clone()
                                .unwrap_or_else(WalletPolicy::require_approval_for_everything)),
                            current_policy,
                            proposal: None,
                            validation: None,
                            mode: PolicyEditorMode::Guided,
                        });
                        self.reset_guided_policy_chain_form(window, cx);
                        self.reset_guided_policy_rule_form(window, cx);
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
        match self.owner.policy(&proposal.wallet_id) {
            Ok(current) => {
                let current_policy = current.as_ref().map(|policy| policy.policy.clone());
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
                            proposal: Some(proposal),
                            guided_policy: Ok(review.policy.clone()),
                            validation: Some(Ok(review)),
                            mode: PolicyEditorMode::Advanced,
                        });
                        self.reset_guided_policy_chain_form(window, cx);
                        self.reset_guided_policy_rule_form(window, cx);
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

    fn set_policy_editor_mode(&mut self, mode: PolicyEditorMode, cx: &mut Context<Self>) {
        let Some(editor) = self.policy_editor.as_mut() else {
            return;
        };
        if mode == PolicyEditorMode::Guided
            && let Some(input) = self.policy_json_input.as_ref()
        {
            editor.guided_policy = serde_json::from_str(input.read(cx).value().as_ref())
                .context("policy document is not valid JSON")
                .and_then(WalletPolicy::parse)
                .map_err(|error| format!("Guided editor unavailable: {error:#}").into());
        }
        editor.mode = mode;
        cx.notify();
    }

    fn reset_guided_policy_chain_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for input in [
            self.policy_chain_input.as_ref(),
            self.policy_chain_label_input.as_ref(),
            self.policy_chain_native_values_input.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        if let Some(input) = self.policy_chain_max_calls_input.as_ref() {
            input.update(cx, |input, cx| input.set_value("1", window, cx));
        }
        self.policy_chain_original_key = None;
        self.policy_chain_native_value_mode = GuidedNativeValueMode::None;
        self.policy_chain_errors = GuidedPolicyChainErrors::default();
        cx.notify();
    }

    fn edit_guided_policy_chain(
        &mut self,
        chain_key: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(Ok(policy)) = self
            .policy_editor
            .as_ref()
            .map(|editor| &editor.guided_policy)
        else {
            return;
        };
        let Some(chain) = policy.chains.get(chain_key) else {
            self.policy_chain_errors.form =
                Some("The selected chain entry no longer exists.".into());
            cx.notify();
            return;
        };
        let native = serde_json::to_value(&chain.native_value);
        let (native_mode, native_values) = match native {
            Ok(serde_json::Value::String(value)) if value == "any_value" => {
                (GuidedNativeValueMode::Any, String::new())
            }
            Ok(serde_json::Value::Object(object)) if object.len() == 1 => {
                if let Some(serde_json::Value::String(value)) = object.get("eq")
                    && value == "0"
                {
                    (GuidedNativeValueMode::None, String::new())
                } else if let Some(serde_json::Value::String(value)) = object.get("eq") {
                    (GuidedNativeValueMode::Exact, value.clone())
                } else if let Some(serde_json::Value::Array(values)) = object.get("in") {
                    let values = values
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Option<Vec<_>>>();
                    let Some(values) = values else {
                        self.policy_chain_errors.form = Some(
                            "This native-value predicate needs the Advanced JSON editor.".into(),
                        );
                        cx.notify();
                        return;
                    };
                    (GuidedNativeValueMode::Exact, values.join(", "))
                } else {
                    self.policy_chain_errors.form =
                        Some("This native-value predicate needs the Advanced JSON editor.".into());
                    cx.notify();
                    return;
                }
            }
            Ok(_) | Err(_) => {
                self.policy_chain_errors.form =
                    Some("This native-value predicate needs the Advanced JSON editor.".into());
                cx.notify();
                return;
            }
        };
        let values = [
            (self.policy_chain_input.as_ref(), chain_key.to_owned()),
            (
                self.policy_chain_label_input.as_ref(),
                chain.label.clone().unwrap_or_default(),
            ),
            (
                self.policy_chain_max_calls_input.as_ref(),
                chain.max_calls_per_batch.to_string(),
            ),
            (
                self.policy_chain_native_values_input.as_ref(),
                native_values,
            ),
        ];
        for (input, value) in values {
            if let Some(input) = input {
                input.update(cx, |input, cx| input.set_value(value, window, cx));
            }
        }
        self.policy_chain_original_key = Some(chain_key.to_owned());
        self.policy_chain_native_value_mode = native_mode;
        self.policy_chain_errors = GuidedPolicyChainErrors::default();
        if let Some(input) = self.policy_chain_input.as_ref() {
            input.update(cx, |input, cx| {
                input.set_selected_range(0..input.value().len(), cx);
                input.focus(window, cx);
            });
        }
        self.policy_editor_anchor.scroll_to(window, cx);
        cx.notify();
    }

    fn save_guided_policy_chain(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let inputs = (
            self.policy_chain_input.as_ref(),
            self.policy_chain_label_input.as_ref(),
            self.policy_chain_max_calls_input.as_ref(),
            self.policy_chain_native_values_input.as_ref(),
            self.policy_json_input.as_ref(),
        );
        let (Some(chain), Some(label), Some(max_calls), Some(native_values), Some(document_input)) =
            inputs
        else {
            return;
        };
        let draft = GuidedPolicyChainDraft {
            chain: chain.read(cx).value().to_string(),
            label: label.read(cx).value().to_string(),
            max_calls: max_calls.read(cx).value().to_string(),
            native_value_mode: self.policy_chain_native_value_mode,
            native_values: native_values.read(cx).value().to_string(),
        };
        let result = update_guided_policy_chain(
            document_input.read(cx).value().as_ref(),
            self.policy_chain_original_key.as_deref(),
            &draft,
        );
        match result {
            Ok((document, policy)) => {
                document_input.update(cx, |input, cx| input.set_value(document, window, cx));
                if let Some(editor) = self.policy_editor.as_mut() {
                    editor.guided_policy = Ok(policy);
                    editor.validation = None;
                }
                self.policy_action_error = None;
                self.reset_guided_policy_rule_form(window, cx);
                self.reset_guided_policy_chain_form(window, cx);
            }
            Err(errors) => self.policy_chain_errors = errors,
        }
        cx.notify();
    }

    fn remove_guided_policy_chain(
        &mut self,
        chain_key: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(input) = self.policy_json_input.as_ref() else {
            return;
        };
        match remove_guided_policy_chain(input.read(cx).value().as_ref(), chain_key) {
            Ok((document, policy)) => {
                input.update(cx, |input, cx| input.set_value(document, window, cx));
                if let Some(editor) = self.policy_editor.as_mut() {
                    editor.guided_policy = Ok(policy);
                    editor.validation = None;
                }
                self.policy_action_error = None;
                if self.policy_chain_original_key.as_deref() == Some(chain_key) {
                    self.reset_guided_policy_chain_form(window, cx);
                }
                if self.policy_rule_chain_key.as_deref() == Some(chain_key) {
                    self.reset_guided_policy_rule_form(window, cx);
                }
            }
            Err(error) => {
                self.policy_action_error =
                    Some(format!("Could not remove chain from draft: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn reset_guided_policy_rule_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for input in [
            self.policy_rule_label_input.as_ref(),
            self.policy_rule_targets_input.as_ref(),
            self.policy_rule_senders_input.as_ref(),
            self.policy_rule_values_input.as_ref(),
            self.policy_rule_abi_input.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        if let Some(input) = self.policy_rule_args_input.as_ref() {
            input.update(cx, |input, cx| input.set_value("{}", window, cx));
        }
        self.policy_rule_chain_key = None;
        self.policy_rule_original_index = None;
        self.policy_rule_effect = GuidedRuleEffect::Allow;
        self.policy_rule_target_mode = GuidedLiteralMode::Any;
        self.policy_rule_sender_mode = GuidedLiteralMode::Any;
        self.policy_rule_value_mode = GuidedLiteralMode::Any;
        self.policy_rule_calldata_mode = GuidedCalldataMode::Any;
        self.policy_rule_errors = GuidedPolicyRuleErrors::default();
        cx.notify();
    }

    fn begin_guided_policy_rule(
        &mut self,
        chain_key: &str,
        index: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.reset_guided_policy_rule_form(window, cx);
        if let Some(index) = index {
            let Some(Ok(policy)) = self
                .policy_editor
                .as_ref()
                .map(|editor| &editor.guided_policy)
            else {
                return;
            };
            let Some(rule) = policy
                .chains
                .get(chain_key)
                .and_then(|chain| chain.rules.get(index))
            else {
                self.policy_rule_errors.form = Some("The selected rule no longer exists.".into());
                cx.notify();
                return;
            };
            let draft = match guided_rule_draft(rule) {
                Ok(draft) => draft,
                Err(error) => {
                    self.policy_rule_errors.form = Some(format!(
                        "This rule uses predicates that need the Advanced JSON editor: {error:#}"
                    ));
                    cx.notify();
                    return;
                }
            };
            let values = [
                (self.policy_rule_label_input.as_ref(), draft.label),
                (self.policy_rule_targets_input.as_ref(), draft.targets),
                (self.policy_rule_senders_input.as_ref(), draft.senders),
                (self.policy_rule_values_input.as_ref(), draft.values),
                (self.policy_rule_abi_input.as_ref(), draft.abi),
                (self.policy_rule_args_input.as_ref(), draft.args),
            ];
            for (input, value) in values {
                if let Some(input) = input {
                    input.update(cx, |input, cx| input.set_value(value, window, cx));
                }
            }
            self.policy_rule_effect = draft.effect;
            self.policy_rule_target_mode = draft.target_mode;
            self.policy_rule_sender_mode = draft.sender_mode;
            self.policy_rule_value_mode = draft.value_mode;
            self.policy_rule_calldata_mode = draft.calldata_mode;
            self.policy_rule_original_index = Some(index);
        }
        self.policy_rule_chain_key = Some(chain_key.to_owned());
        if let Some(input) = self.policy_rule_label_input.as_ref() {
            input.update(cx, |input, cx| input.focus(window, cx));
        }
        self.policy_editor_anchor.scroll_to(window, cx);
        cx.notify();
    }

    fn save_guided_policy_rule(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let inputs = (
            self.policy_rule_label_input.as_ref(),
            self.policy_rule_targets_input.as_ref(),
            self.policy_rule_senders_input.as_ref(),
            self.policy_rule_values_input.as_ref(),
            self.policy_rule_abi_input.as_ref(),
            self.policy_rule_args_input.as_ref(),
            self.policy_json_input.as_ref(),
        );
        let (
            Some(label),
            Some(targets),
            Some(senders),
            Some(values),
            Some(abi),
            Some(args),
            Some(document_input),
        ) = inputs
        else {
            return;
        };
        let Some(chain_key) = self.policy_rule_chain_key.as_deref() else {
            return;
        };
        let draft = GuidedPolicyRuleDraft {
            effect: self.policy_rule_effect,
            label: label.read(cx).value().to_string(),
            target_mode: self.policy_rule_target_mode,
            targets: targets.read(cx).value().to_string(),
            sender_mode: self.policy_rule_sender_mode,
            senders: senders.read(cx).value().to_string(),
            value_mode: self.policy_rule_value_mode,
            values: values.read(cx).value().to_string(),
            calldata_mode: self.policy_rule_calldata_mode,
            abi: abi.read(cx).value().to_string(),
            args: args.read(cx).value().to_string(),
        };
        match update_guided_policy_rule(
            document_input.read(cx).value().as_ref(),
            chain_key,
            self.policy_rule_original_index,
            &draft,
        ) {
            Ok((document, policy)) => {
                document_input.update(cx, |input, cx| input.set_value(document, window, cx));
                if let Some(editor) = self.policy_editor.as_mut() {
                    editor.guided_policy = Ok(policy);
                    editor.validation = None;
                }
                self.policy_action_error = None;
                self.reset_guided_policy_rule_form(window, cx);
            }
            Err(errors) => self.policy_rule_errors = *errors,
        }
        cx.notify();
    }

    fn remove_guided_policy_rule(
        &mut self,
        chain_key: &str,
        index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(input) = self.policy_json_input.as_ref() else {
            return;
        };
        match remove_guided_policy_rule(input.read(cx).value().as_ref(), chain_key, index) {
            Ok((document, policy)) => {
                input.update(cx, |input, cx| input.set_value(document, window, cx));
                if let Some(editor) = self.policy_editor.as_mut() {
                    editor.guided_policy = Ok(policy);
                    editor.validation = None;
                }
                if self.policy_rule_chain_key.as_deref() == Some(chain_key) {
                    self.reset_guided_policy_rule_form(window, cx);
                }
                self.policy_action_error = None;
            }
            Err(error) => {
                self.policy_action_error =
                    Some(format!("Could not remove rule from draft: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn apply_allow_anything_policy(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (Some(editor), Some(input)) =
            (self.policy_editor.as_mut(), self.policy_json_input.as_ref())
        else {
            return;
        };
        match allow_anything_policy_document() {
            Ok((document, policy)) => {
                input.update(cx, |input, cx| input.set_value(document, window, cx));
                editor.validation = None;
                editor.guided_policy = Ok(policy);
                self.policy_action_error = Some(
                    "Danger: this draft automatically signs every call on every chain, including arbitrary calldata and native value. Validate the diff carefully before installing it."
                        .into(),
                );
                self.reset_guided_policy_chain_form(window, cx);
                self.reset_guided_policy_rule_form(window, cx);
            }
            Err(error) => {
                self.policy_action_error =
                    Some(format!("Could not prepare the allow-anything policy: {error:#}").into());
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
                editor.guided_policy = Ok(WalletPolicy::require_approval_for_everything());
                self.policy_action_error = None;
                self.reset_guided_policy_chain_form(window, cx);
                self.reset_guided_policy_rule_form(window, cx);
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
                editor.guided_policy = Ok(review.policy.clone());
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
                            editor.current_policy = Some(installed.policy);
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
            Ok(document) => {
                self.account_action_errors.remove(&wallet_id);
                self.active_review = Some(ActiveReview {
                    state: ReviewState::new(document),
                    simulation: None,
                    completion: Some(ActiveReviewCompletion::AccountRemoval { wallet_id }),
                    awaiting_refresh: false,
                    scroll_handle: ScrollHandle::new(),
                    scroll_check_scheduled: false,
                    scroll_layout_ready: false,
                });
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
    }

    fn reinstall_detected_agents(&mut self, cx: &mut Context<Self>) {
        if self.agent_reinstall == AgentReinstallState::Running {
            self.set_route_error(
                Route::Settings,
                "Agent configuration repair is already running.",
            );
            cx.notify();
            return;
        }
        self.clear_route_error(Route::Settings);
        self.agent_reinstall = AgentReinstallState::Running;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(upsert_detected_agents)
                .await
                .context("agent configuration repair task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.agent_reinstall = AgentReinstallState::Idle;
                if let Err(error) = result {
                    view.set_route_error(
                        Route::Settings,
                        format!("Could not reinstall MCP server: {error:#}"),
                    );
                }
                view.reload_detected_agents(cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn reinstall_detected_agents_from_menu(&mut self, cx: &mut Context<Self>) {
        self.reinstall_detected_agents(cx);
    }

    fn refresh_portfolio(&mut self, cx: &mut Context<Self>) {
        if self.legal_gate || matches!(self.portfolio, PortfolioState::Loading) {
            return;
        }
        let Some(chain_id) = self.portfolio_chain_id else {
            return;
        };
        self.portfolio_generation = self.portfolio_generation.wrapping_add(1);
        let generation = self.portfolio_generation;
        self.portfolio = PortfolioState::Loading;
        let owner = self.owner.clone();
        let task =
            gpui_tokio::Tokio::spawn_result(cx, async move { owner.portfolio(chain_id).await });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                if view.portfolio_generation != generation {
                    return;
                }
                view.portfolio = match result {
                    Ok(snapshot) => PortfolioState::Ready(snapshot),
                    Err(error) => PortfolioState::Failed(
                        format!("Could not load portfolio: {error:#}").into(),
                    ),
                };
                cx.notify();
            });
        })
        .detach();
    }

    fn invalidate_portfolio(&mut self) {
        self.portfolio_generation = self.portfolio_generation.wrapping_add(1);
        self.portfolio = PortfolioState::Idle;
    }

    fn select_portfolio_network(&mut self, chain_id: u64, cx: &mut Context<Self>) {
        if self.portfolio_chain_id == Some(chain_id) {
            return;
        }
        self.portfolio_chain_id = Some(chain_id);
        self.invalidate_portfolio();
        self.refresh_portfolio(cx);
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
            max_gas_limit: self
                .network_max_gas_limit_input
                .as_ref()?
                .read(cx)
                .value()
                .to_string(),
            max_fee_per_gas: self
                .network_max_fee_per_gas_input
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
        for input in [
            self.network_name_input.as_ref(),
            self.network_display_name_input.as_ref(),
            self.network_aliases_input.as_ref(),
            self.network_chain_id_input.as_ref(),
            self.network_rpc_urls_input.as_ref(),
            self.network_max_gas_limit_input.as_ref(),
            self.network_max_fee_per_gas_input.as_ref(),
            self.network_native_name_input.as_ref(),
            self.network_native_symbol_input.as_ref(),
            self.network_native_decimals_input.as_ref(),
            self.network_explorer_url_input.as_ref(),
            self.network_documentation_url_input.as_ref(),
        ] {
            replace_input_value(input, "", window, cx);
        }
        replace_input_value(self.network_json_input.as_ref(), "", window, cx);
        self.network_editor_open = true;
        self.network_editor_original = None;
        self.network_editor_disabled = false;
        self.network_editor_rpc_strategy = RpcStrategy::Ordered;
        self.network_editor_advanced = false;
        self.network_editor_errors = NetworkEditorErrors::default();
        self.network_json_error = None;
        if let Some(input) = self.network_name_input.as_ref() {
            input.update(cx, |input, cx| input.focus(window, cx));
        }
        let anchor = self.network_editor_anchor.clone();
        cx.on_next_frame(window, move |_, window, cx| {
            anchor.scroll_to(window, cx);
        });
        cx.notify();
    }

    fn close_network_editor(&mut self, cx: &mut Context<Self>) {
        if self.network_editor_busy {
            return;
        }
        self.network_editor_open = false;
        self.network_editor_original = None;
        self.network_editor_errors = NetworkEditorErrors::default();
        self.network_json_error = None;
        cx.notify();
    }

    fn set_network_editor_strategy(&mut self, strategy: RpcStrategy, cx: &mut Context<Self>) {
        self.network_editor_rpc_strategy = strategy;
        cx.notify();
    }

    fn toggle_network_advanced_editor(&mut self, cx: &mut Context<Self>) {
        self.network_editor_advanced = !self.network_editor_advanced;
        cx.notify();
    }

    fn edit_network(
        &mut self,
        network: &NetworkConfig,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
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
            self.network_max_gas_limit_input.as_ref(),
            network.max_gas_limit.clone().unwrap_or_default(),
            window,
            cx,
        );
        replace_input_value(
            self.network_max_fee_per_gas_input.as_ref(),
            network.max_fee_per_gas.clone().unwrap_or_default(),
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
        match serde_json::to_string_pretty(network) {
            Ok(document) => {
                replace_input_value(self.network_json_input.as_ref(), document, window, cx);
            }
            Err(error) => {
                self.network_json_error =
                    Some(format!("Could not serialize network: {error:#}").into());
            }
        }
        self.network_editor_open = true;
        self.network_editor_original = Some(network.clone());
        self.network_editor_disabled = network.disabled;
        self.network_editor_rpc_strategy = network.rpc_strategy;
        self.network_editor_advanced = false;
        self.network_editor_errors = NetworkEditorErrors::default();
        if let Some(input) = self.network_display_name_input.as_ref() {
            input.update(cx, |input, cx| {
                input.set_selected_range(0..input.value().len(), cx);
                input.focus(window, cx);
            });
        }
        let anchor = self.network_editor_anchor.clone();
        cx.on_next_frame(window, move |_, window, cx| {
            anchor.scroll_to(window, cx);
        });
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
            self.network_editor_rpc_strategy,
        );
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
            let _ = view.update(cx, |view, cx| {
                view.network_editor_busy = false;
                match result {
                    Ok(()) => {
                        view.network_editor_open = false;
                        view.network_editor_original = None;
                        view.network_editor_errors = NetworkEditorErrors::default();
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

    fn install_network_from_editor(&mut self, cx: &mut Context<Self>) {
        if self.network_editor_busy {
            return;
        }
        let Some(input) = self.network_json_input.as_ref() else {
            return;
        };
        let network = match serde_json::from_str::<NetworkConfig>(&input.read(cx).value()) {
            Ok(network) => network,
            Err(error) => {
                self.network_json_error = Some(format!("Invalid network JSON: {error:#}").into());
                cx.notify();
                return;
            }
        };
        if let Err(error) = ekubo_wallet_core::config::validate_network(&network) {
            self.network_json_error = Some(format!("Invalid network settings: {error:#}").into());
            cx.notify();
            return;
        }
        self.network_json_error = None;
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
            let _ = view.update(cx, |view, cx| {
                view.network_editor_busy = false;
                match result {
                    Ok(()) => {
                        view.network_json_error = None;
                        view.network_editor_open = false;
                        view.network_editor_original = None;
                    }
                    Err(error) => {
                        view.network_json_error =
                            Some(format!("Network was not saved: {error:#}").into());
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn install_network_preset(&mut self, chain_id: u64, cx: &mut Context<Self>) {
        if self.network_preset_busy.is_some() || self.network_reset_busy {
            return;
        }
        self.network_preset_busy = Some(chain_id);
        self.network_preset_error = None;
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.install_network_preset(chain_id).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                if view.network_preset_busy != Some(chain_id) {
                    return;
                }
                view.network_preset_busy = None;
                match result {
                    Ok(_) => view.network_preset_error = None,
                    Err(error) => {
                        view.network_preset_error =
                            Some(format!("Could not install the network preset: {error:#}").into());
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn restore_network_preset(&mut self, reviewed: NetworkConfig, cx: &mut Context<Self>) {
        let name = reviewed.name.clone();
        if self.network_action_busy.contains(&name) {
            return;
        }
        let Some(preset) = self
            .network_presets
            .iter()
            .find(|profile| profile.config.chain_id == reviewed.chain_id)
            .map(|profile| profile.config.clone())
        else {
            self.network_action_errors
                .insert(name, "This network has no built-in defaults.".into());
            cx.notify();
            return;
        };
        // Restoring trusted metadata must not silently change whether the
        // owner allows the network to be used.
        let preset = restored_network_configuration(&reviewed, preset);
        self.network_action_busy.insert(name.clone());
        self.network_action_errors.remove(&name);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.replace_network(&reviewed, preset).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.network_action_busy.remove(&name);
                match result {
                    Ok(()) => {
                        view.network_action_errors.remove(&name);
                        view.invalidate_portfolio();
                    }
                    Err(error) => {
                        view.network_action_errors.insert(
                            name,
                            format!(
                                "Defaults were not restored; review the current row and try again: {error:#}"
                            )
                            .into(),
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn begin_network_reset(&mut self, cx: &mut Context<Self>) {
        if self.network_preset_busy.is_some() || self.network_reset_busy {
            return;
        }
        match self.cached_networks() {
            Ok(networks) => {
                self.pending_network_reset = Some(networks.to_vec());
                self.network_reset_error = None;
            }
            Err(error) => {
                self.network_reset_error =
                    Some(format!("Could not prepare the network reset: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn cancel_network_reset(&mut self, cx: &mut Context<Self>) {
        if self.network_reset_busy {
            return;
        }
        self.pending_network_reset = None;
        cx.notify();
    }

    fn confirm_network_reset(&mut self, cx: &mut Context<Self>) {
        let Some(reviewed_networks) = self.pending_network_reset.clone() else {
            return;
        };
        if self.network_reset_busy || self.network_preset_busy.is_some() {
            return;
        }
        self.network_reset_busy = true;
        self.network_reset_error = None;
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.reset_networks_to_defaults(&reviewed_networks).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.network_reset_busy = false;
                match result {
                    Ok(_) => {
                        view.pending_network_reset = None;
                        view.network_reset_error = None;
                        view.portfolio_chain_id = None;
                        view.invalidate_portfolio();
                    }
                    Err(error) => {
                        view.pending_network_reset = None;
                        view.network_reset_error = Some(
                            format!(
                                "Networks were not reset; review the current configuration and try again: {error:#}"
                            )
                            .into(),
                        );
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
        let selected_network = self.portfolio_chain_id == Some(reviewed.chain_id);
        let name = reviewed.name.clone();
        if !self.network_action_busy.insert(name.clone()) {
            return;
        }
        self.network_action_errors.remove(&name);
        if !disabled && self.pending_network_removal.as_ref() == Some(&reviewed) {
            self.pending_network_removal = None;
        }
        let owner = self.owner.clone();
        let action_name = name.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.set_network_disabled(&reviewed, disabled).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.network_action_busy.remove(&action_name);
                let changed = result.is_ok();
                if let Err(error) = result {
                    view.network_action_errors.insert(
                        action_name,
                        format!("Could not update network: {error:#}").into(),
                    );
                }
                if changed && disabled && selected_network {
                    view.portfolio_chain_id = None;
                    view.invalidate_portfolio();
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn begin_network_removal(&mut self, reviewed: NetworkConfig, cx: &mut Context<Self>) {
        self.network_action_errors.remove(&reviewed.name);
        self.pending_network_removal = Some(reviewed);
        cx.notify();
    }

    fn cancel_network_removal(&mut self, cx: &mut Context<Self>) {
        self.pending_network_removal = None;
        cx.notify();
    }

    fn confirm_network_removal(&mut self, reviewed: NetworkConfig, cx: &mut Context<Self>) {
        if self.pending_network_removal.as_ref() != Some(&reviewed) {
            return;
        }
        let owner = self.owner.clone();
        let name = reviewed.name.clone();
        if !self.network_action_busy.insert(name.clone()) {
            return;
        }
        self.network_action_errors.remove(&name);
        let action_name = name.clone();
        let task =
            gpui_tokio::Tokio::spawn_result(
                cx,
                async move { owner.remove_network(&reviewed).await },
            );
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.network_action_busy.remove(&action_name);
                match result {
                    Ok(_) => view.pending_network_removal = None,
                    Err(error) => {
                        view.network_action_errors.insert(
                            action_name,
                            format!("Could not delete network: {error:#}").into(),
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
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
        let requested_chains = Vec::new();
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
            Ok(_) => ActivityFeedback {
                message: "Discarded signed bytes that were never submitted.".into(),
                error: false,
            },
            Err(error) => ActivityFeedback {
                message: format!("Could not discard transaction: {error:#}").into(),
                error: true,
            },
        };
        self.activity_feedback.insert(request_id, feedback);
        self.selected_record = Some(request_id);
        cx.notify();
    }

    fn refresh_transaction(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if !self.activity_busy.insert(request_id) {
            return;
        }
        self.activity_feedback.remove(&request_id);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.refresh_transaction(request_id).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.activity_busy.remove(&request_id);
                view.activity_feedback.insert(
                    request_id,
                    match result {
                        Ok(record) => ActivityFeedback {
                            message: format!("Refreshed chain status: {:?}.", record.status).into(),
                            error: false,
                        },
                        Err(error) => ActivityFeedback {
                            message: format!("Could not refresh transaction: {error:#}").into(),
                            error: true,
                        },
                    },
                );
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
                let feedback = match result {
                    Ok(action) => match action
                        .broadcast
                        .as_ref()
                        .and_then(|broadcast| broadcast.broadcast_error.as_deref())
                    {
                        Some(error) => ActivityFeedback {
                            message: format!(
                                "No endpoint accepted the exact signed bytes: {error}"
                            )
                            .into(),
                            error: true,
                        },
                        None => ActivityFeedback {
                            message: format!(
                                "Exact signed bytes reconciled with status {:?}.",
                                action.record.status
                            )
                            .into(),
                            error: false,
                        },
                    },
                    Err(error) => ActivityFeedback {
                        message: format!("Could not send exact signed bytes: {error:#}").into(),
                        error: true,
                    },
                };
                view.activity_feedback.insert(request_id, feedback);
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
                let feedback = match result {
                    Ok(action) => match action
                        .broadcast
                        .as_ref()
                        .and_then(|broadcast| broadcast.broadcast_error.as_deref())
                    {
                        Some(error) => ActivityFeedback {
                            message: format!("Cancellation broadcast was not accepted: {error}")
                                .into(),
                            error: true,
                        },
                        None => ActivityFeedback {
                            message: format!(
                                "Cancellation reconciled with status {:?}.",
                                action.record.status
                            )
                            .into(),
                            error: false,
                        },
                    },
                    Err(error) => ActivityFeedback {
                        message: format!("Could not cancel transaction: {error:#}").into(),
                        error: true,
                    },
                };
                view.activity_feedback.insert(request_id, feedback);
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
        let data_dir = match crate::config::ConfigStore::production() {
            Ok(config) => config.data_dir().to_path_buf(),
            Err(error) => {
                self.release_state = ReleaseDisplayState::Failed(
                    format!("Could not locate release-check storage: {error:#}").into(),
                );
                cx.notify();
                return;
            }
        };
        self.release_state = ReleaseDisplayState::Checking;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            Ok::<_, anyhow::Error>(crate::release_check::check(&data_dir).await)
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.release_state = match result {
                    Ok(check) => ReleaseDisplayState::Ready(check),
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

    fn revoke_agent(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.clear_route_error(Route::Settings);
        match self.owner.revoke_client(client_id) {
            Ok(()) => {
                self.hidden_agent_sessions.insert(client_id);
                self.reload_desktop_snapshot(cx);
            }
            Err(error) => self.set_route_error(
                Route::Settings,
                format!("Could not revoke agent: {error:#}"),
            ),
        }
        cx.notify();
    }

    fn prepare_detected_agent_install(&mut self, kind: AgentKind, cx: &mut Context<Self>) {
        if self.pending_agent_install.is_some()
            || self.agent_reinstall == AgentReinstallState::Running
        {
            self.set_route_error(Route::Settings, "Finish the current agent change first.");
            cx.notify();
            return;
        }
        self.agent_reinstall = AgentReinstallState::Running;
        self.clear_route_error(Route::Settings);
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || {
                let adapter = AgentAdapter::supported()?
                    .into_iter()
                    .find(|adapter| adapter.kind == kind)
                    .context("the selected agent has no managed configuration adapter")?;
                ensure!(
                    adapter.detected(),
                    "the selected agent is no longer detected"
                );
                let preview = adapter.preview_install(true)?;
                Ok::<_, anyhow::Error>(PendingAgentInstall {
                    display_name: format!("Install {}", adapter.display_name),
                    preview,
                })
            })
            .await
            .context("agent installation preview task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.agent_reinstall = AgentReinstallState::Idle;
                match result {
                    Ok(pending) => view.pending_agent_install = Some(pending),
                    Err(error) => view.set_route_error(
                        Route::Settings,
                        format!("Could not prepare agent installation: {error:#}"),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn cancel_agent_install(&mut self, cx: &mut Context<Self>) {
        if self.pending_agent_install.take().is_some() {
            self.clear_route_error(Route::Settings);
        }
        cx.notify();
    }

    fn confirm_agent_install(&mut self, cx: &mut Context<Self>) {
        let Some(pending) = self.pending_agent_install.take() else {
            return;
        };
        let display_name = pending.display_name.clone();
        let preview = pending.preview;
        self.agent_reinstall = AgentReinstallState::Running;
        self.clear_route_error(Route::Settings);
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || preview.install())
                .await
                .context("agent configuration installation task failed")??;
            Ok::<_, anyhow::Error>(())
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.agent_reinstall = AgentReinstallState::Idle;
                match result {
                    Ok(()) => view.clear_route_error(Route::Settings),
                    Err(error) => view.set_route_error(
                        Route::Settings,
                        format!("Could not install {display_name}: {error:#}"),
                    ),
                }
                view.reload_detected_agents(cx);
                cx.notify();
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
            let identity_changed = active.state.document().identity != prompt.document.identity;
            active.state.refresh(prompt.document);
            if identity_changed {
                active.scroll_handle = ScrollHandle::new();
                active.scroll_check_scheduled = false;
                active.scroll_layout_ready = false;
            }
            active.simulation = Some(prompt.simulation);
            active.completion = Some(ActiveReviewCompletion::Transaction(prompt.response));
            active.awaiting_refresh = false;
            return;
        }
        if self.active_review.is_none() && self.review_flow.activate_transaction_prompt() {
            self.activate_transaction_prompt(prompt);
            return;
        }
        let Some(QueuedReview::Transaction(prompt)) = self.queued_reviews.receive(
            self.active_review.is_some() || self.review_flow.is_in_progress(),
            QueuedReview::Transaction(Box::new(prompt)),
        ) else {
            return;
        };
        self.activate_transaction_prompt(*prompt);
    }

    fn activate_transaction_prompt(&mut self, prompt: GuiReviewPrompt) {
        self.review_flow = ReviewFlowState::Busy;
        self.active_review = Some(ActiveReview {
            state: ReviewState::new(prompt.document),
            simulation: Some(prompt.simulation),
            completion: Some(ActiveReviewCompletion::Transaction(prompt.response)),
            awaiting_refresh: false,
            scroll_handle: ScrollHandle::new(),
            scroll_check_scheduled: false,
            scroll_layout_ready: false,
        });
    }

    fn begin_message_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.active_review.is_some() || self.review_flow.is_in_progress() {
            self.set_route_error(Route::Reviews, "Finish or close the current review first.");
            cx.notify();
            return;
        }
        match self.owner.message_review_document(request_id) {
            Ok(document) => {
                let digest = document.request.digest.clone().unwrap_or_default();
                self.active_review = Some(ActiveReview {
                    state: ReviewState::new(document),
                    simulation: None,
                    completion: Some(ActiveReviewCompletion::Message { request_id, digest }),
                    awaiting_refresh: false,
                    scroll_handle: ScrollHandle::new(),
                    scroll_check_scheduled: false,
                    scroll_layout_ready: false,
                });
                self.clear_route_error(Route::Reviews);
            }
            Err(error) => {
                self.set_route_error(
                    Route::Reviews,
                    format!("Could not open message review: {error:#}"),
                );
            }
        }
        cx.notify();
    }

    fn begin_typed_data_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.active_review.is_some() || self.review_flow.is_in_progress() {
            self.set_route_error(Route::Reviews, "Finish or close the current review first.");
            cx.notify();
            return;
        }
        match self.owner.typed_data_review_document(request_id) {
            Ok(document) => {
                let digest = document.request.digest.clone().unwrap_or_default();
                self.active_review = Some(ActiveReview {
                    state: ReviewState::new(document),
                    simulation: None,
                    completion: Some(ActiveReviewCompletion::TypedData { request_id, digest }),
                    awaiting_refresh: false,
                    scroll_handle: ScrollHandle::new(),
                    scroll_check_scheduled: false,
                    scroll_layout_ready: false,
                });
                self.clear_route_error(Route::Reviews);
            }
            Err(error) => {
                self.set_route_error(
                    Route::Reviews,
                    format!("Could not open typed-data review: {error:#}"),
                );
            }
        }
        cx.notify();
    }

    fn begin_transaction_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.active_review.is_some() || !self.review_flow.begin_transaction() {
            self.set_route_error(Route::Reviews, "Finish or close the current review first.");
            cx.notify();
            return;
        }
        self.clear_route_error(Route::Reviews);
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
                    view.finish_review_flow();
                    match result {
                        Ok(_) => view.clear_route_error(Route::Reviews),
                        Err(error) if error.to_string().contains("closed without a decision") => {
                            view.clear_route_error(Route::Reviews);
                        }
                        Err(error) => view
                            .set_route_error(Route::Reviews, format!("Review failed: {error:#}")),
                    }
                    cx.notify();
                });
        })
        .detach();
        cx.notify();
    }

    fn update_review_scroll_state(&mut self, cx: &mut Context<Self>) {
        let Some(review) = self.active_review.as_mut() else {
            return;
        };
        if review.scroll_layout_ready
            && !review.state.approve_enabled()
            && scroll_reached_end(
                review.scroll_handle.offset().y,
                review.scroll_handle.max_offset().y,
            )
        {
            let generation = review.state.generation();
            if review.state.mark_viewed_to_end(generation) {
                cx.notify();
            }
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
                active.state.selected() == ReviewDecision::Approve && active.state.approve_enabled()
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
                    self.set_route_error(Route::Reviews, "The review request is no longer active.");
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
                    self.set_route_error(Route::Reviews, "The review request is no longer active.");
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
                self.clear_route_error(Route::Reviews);
            }
            (
                GuiReviewCommand::Close | GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::AccountRemoval { wallet_id }),
            ) => {
                self.active_review = None;
                self.account_action_errors.remove(&wallet_id);
            }
            (
                GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::Message { request_id, .. }),
            ) => {
                self.active_review = None;
                match owner.reject_message(request_id) {
                    Ok(_) => self.clear_route_error(Route::Reviews),
                    Err(error) => self.set_route_error(
                        Route::Reviews,
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
                    Ok(_) => self.clear_route_error(Route::Reviews),
                    Err(error) => self.set_route_error(
                        Route::Reviews,
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
                        view.finish_review_flow();
                        match result {
                            Ok(_) => view.clear_route_error(Route::Reviews),
                            Err(error) => view.set_route_error(
                                Route::Reviews,
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
                        view.finish_review_flow();
                        match result {
                            Ok(_) => view.clear_route_error(Route::Reviews),
                            Err(error) => view.set_route_error(
                                Route::Reviews,
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
                Some(ActiveReviewCompletion::AccountRemoval { wallet_id }),
            ) => {
                wait_for_flow = true;
                self.active_review = None;
                let task_wallet_id = wallet_id.clone();
                let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                    owner.remove_account(&task_wallet_id).await
                });
                cx.spawn(async move |view, cx| {
                    let result = task.await;
                    let _ = view.update(cx, |view, cx| {
                        view.finish_review_flow();
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
                    selected_account,
                    response,
                    ..
                }),
            ) => {
                self.active_review = None;
                if response
                    .send(ProposalCommand::Approve(selected_account))
                    .is_err()
                {
                    self.set_route_error(
                        Route::WalletConnect,
                        "The connection proposal is no longer active.",
                    );
                } else {
                    self.clear_route_error(Route::WalletConnect);
                }
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
                    Route::Reviews,
                    "Only transaction reviews can be re-simulated.",
                );
            }
            (_, None) => {
                self.set_route_error(Route::Reviews, "The review request is no longer active.");
                self.active_review = None;
            }
        }
        if wait_for_flow {
            self.review_flow = ReviewFlowState::Busy;
        }
        self.activate_next_queued_review();
        if self.active_review.is_some() {
            let route = self.active_review_route();
            self.set_route(route);
        }
        cx.notify();
    }

    fn toggle_palette(
        &mut self,
        _: &OpenCommandPalette,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.legal_gate {
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
        reset_route_scroll_if_changed(self.route, route, &self.route_scroll_handle);
        if route != Route::WalletConnect {
            self.walletconnect_scan_generation = self.walletconnect_scan_generation.wrapping_add(1);
            self.walletconnect_scan = WalletConnectScanState::Idle;
        }
        self.route = route;
    }

    fn navigate_route(&mut self, route: Route, cx: &mut Context<Self>) {
        if self.legal_gate {
            return;
        }
        self.set_route(route);
        if route == Route::Settings && matches!(self.release_state, ReleaseDisplayState::Idle) {
            self.check_latest_release(cx);
        }
        self.command_palette = false;
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

    fn toggle_network_details(&mut self, name: &str, cx: &mut Context<Self>) {
        if !self.expanded_networks.remove(name) {
            self.expanded_networks.insert(name.to_owned());
        }
        cx.notify();
    }

    fn set_detailed_notification_previews(&mut self, enabled: bool, cx: &mut Context<Self>) {
        if self.notification_preference_busy {
            return;
        }
        self.notification_preference_busy = true;
        self.clear_route_error(Route::Settings);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.set_detailed_notification_previews(enabled).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.notification_preference_busy = false;
                match result {
                    Ok(()) => {
                        view.detailed_notification_previews
                            .store(enabled, Ordering::Relaxed);
                        view.clear_route_error(Route::Settings);
                    }
                    Err(error) => {
                        view.set_route_error(
                            Route::Settings,
                            format!("Could not save notification preference: {error:#}"),
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
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

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let pending_reviews = self
            .cached_reviews()
            .map(review_queue_decision_count)
            .unwrap_or_default();
        let mut menu = div()
            .id("wallet-sidebar")
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
            .gap_2();
        for route in Route::ALL {
            let button = Button::new(SharedString::from(format!(
                "sidebar-route-{}",
                route.label()
            )))
            .with_size(NAVIGATION_BUTTON_SIZE)
            .w(NAVIGATION_BUTTON_SIZE)
            .h(NAVIGATION_BUTTON_SIZE)
            .ghost()
            .selected(route == self.route)
            .disabled(self.legal_gate)
            .accessibility_id(route.label())
            .tooltip(format!("{}  {}", route.label(), route.shortcut()))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.navigate_route(route, cx);
            }))
            .when(
                route == Route::Reviews && route == self.route,
                ButtonVariants::primary,
            );
            let button = if route == Route::Reviews {
                let logo = if cx.theme().is_dark() {
                    self.sidebar_logo_dark.clone()
                } else {
                    self.sidebar_logo_light.clone()
                };
                button.child(img(logo).w(px(49.0)).h(px(49.0)))
            } else {
                button.child(Icon::new(route.icon()).size(px(30.0)))
            };
            if route == Route::Reviews {
                let count = if pending_reviews > 99 {
                    "99+".to_owned()
                } else {
                    pending_reviews.to_string()
                };
                menu = menu.child(div().relative().child(button).when(
                    pending_reviews > 0,
                    |badge| {
                        badge.child(
                            div()
                                .absolute()
                                .top(px(-4.0))
                                .right(px(-8.0))
                                .w(px(30.0))
                                .h(px(24.0))
                                .flex()
                                .items_center()
                                .justify_center()
                                .rounded_full()
                                .bg(cx.theme().red)
                                .text_color(gpui_component::white())
                                .text_sm()
                                .font_semibold()
                                .child(count),
                        )
                    },
                ));
            } else {
                menu = menu.child(button);
            }
        }
        menu
    }

    fn render_reviews(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div().flex().flex_col().gap_3();
        match self.cached_reviews() {
            Ok(queues) => {
                let total = review_queue_decision_count(queues);
                if total > 0 {
                    content = content.child(format!("{total} request(s) need your attention."));
                }
                for request in &queues.transactions {
                    let request_id = request.request_id;
                    content =
                        content.child(
                            div()
                                .w_full()
                                .min_w_0()
                                .max_w_full()
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
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
                                        .child(format!(
                                            "Transaction · {} · {}",
                                            request.wallet_id, request.network_name
                                        ))
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(format!(
                                                    "{} · {}",
                                                    request_id, request.created_at
                                                )),
                                        ),
                                )
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "review-transaction-{request_id}"
                                    )))
                                    .label("Review")
                                    .primary()
                                    .disabled(self.review_flow.is_in_progress())
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.begin_transaction_review(request_id, cx);
                                    })),
                                ),
                        );
                }
                for request in &queues.typed_data {
                    let request_id = request.request_id;
                    content =
                        content.child(
                            div()
                                .w_full()
                                .min_w_0()
                                .max_w_full()
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .justify_between()
                                .gap_3()
                                .child(div().min_w_0().flex_1().whitespace_normal().child(format!(
                                    "Typed data · {} · {} · {}",
                                    request.wallet_id, request.chain_id, request_id
                                )))
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "review-typed-data-{request_id}"
                                    )))
                                    .label("Review")
                                    .primary()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.begin_typed_data_review(request_id, cx);
                                    })),
                                ),
                        );
                }
                for request in &queues.messages {
                    let request_id = request.request_id;
                    content =
                        content.child(
                            div()
                                .w_full()
                                .min_w_0()
                                .max_w_full()
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .justify_between()
                                .gap_3()
                                .child(div().min_w_0().flex_1().whitespace_normal().child(format!(
                                    "Message · {} · {}",
                                    request.wallet_id, request_id
                                )))
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "review-message-{request_id}"
                                    )))
                                    .label("Review")
                                    .primary()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.begin_message_review(request_id, cx);
                                    })),
                                ),
                        );
                }
                for proposal in &queues.policy_proposals {
                    let wallet_id = proposal.wallet_id.clone();
                    content =
                        content.child(
                            div()
                                .w_full()
                                .min_w_0()
                                .max_w_full()
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .justify_between()
                                .gap_3()
                                .child(div().min_w_0().flex_1().whitespace_normal().child(format!(
                                    "Policy proposal · {wallet_id} · revision {}",
                                    proposal.source_revision
                                )))
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "open-policy-proposal-{wallet_id}"
                                    )))
                                    .label("Open Policies")
                                    .primary()
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.set_route(Route::Policies);
                                        cx.notify();
                                    })),
                                ),
                        );
                }
                for proposal in &queues.network_proposals {
                    let chain_id = proposal.chain_id;
                    content =
                        content.child(
                            div()
                                .w_full()
                                .min_w_0()
                                .max_w_full()
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .justify_between()
                                .gap_3()
                                .child(div().min_w_0().flex_1().whitespace_normal().child(format!(
                                    "Network proposal · {} · chain {chain_id}",
                                    proposal.name
                                )))
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "open-network-proposal-{chain_id}"
                                    )))
                                    .label("Open Networks")
                                    .primary()
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.set_route(Route::Networks);
                                        cx.notify();
                                    })),
                                ),
                        );
                }
                let mut token_groups = std::collections::BTreeMap::<String, usize>::new();
                for proposal in &queues.token_proposals {
                    *token_groups.entry(proposal.source.clone()).or_default() += 1;
                }
                for (index, (source, count)) in token_groups.into_iter().enumerate() {
                    content =
                        content.child(
                            div()
                                .w_full()
                                .min_w_0()
                                .max_w_full()
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .justify_between()
                                .gap_3()
                                .child(
                                    div().min_w_0().flex_1().whitespace_normal().child(format!(
                                        "Token proposal · {source} · {count} name(s)"
                                    )),
                                )
                                .child(
                                    Button::new(("open-token-proposal", index))
                                        .label("Open Tokens")
                                        .primary()
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            view.set_route(Route::Tokens);
                                            cx.notify();
                                        })),
                                ),
                        );
                }
                if total == 0 {
                    content = content.child(
                        div()
                            .p_5()
                            .rounded_lg()
                            .border_1()
                            .border_color(cx.theme().border)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(div().font_semibold().child("No requests waiting"))
                            .child(
                                div()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("Transactions, messages, typed data, WalletConnect requests, and proposed policy, network, or token changes that need your decision will appear here."),
                            ),
                    );
                }
            }
            Err(error) => {
                content = content.child(format!("Reviews unavailable: {error:#}"));
            }
        }
        content
    }

    fn render_activity_detail(
        &self,
        record: &OwnerActivityRecord,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let request_id = record.request_id();
        let header = |title: &'static str, status: String| {
            h_flex()
                .w_full()
                .justify_between()
                .gap_4()
                .child(
                    div()
                        .font_semibold()
                        .child(format!("{title} · {status} · {request_id}")),
                )
                .child(
                    Button::new(SharedString::from(format!(
                        "close-activity-detail-{request_id}"
                    )))
                    .label("Close")
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.selected_record = None;
                        cx.notify();
                    })),
                )
        };
        match record {
            OwnerActivityRecord::Transaction(item) => {
                let exact_plan = serde_json::to_string_pretty(&item.execution_plan)
                    .unwrap_or_else(|_| "Exact execution plan could not be rendered.".into());
                let mut detail = GroupBox::new()
                    .id(SharedString::from(format!("activity-detail-{request_id}")))
                    .outline()
                    .title("Transaction details")
                    .child(header("Transaction", format!("{:?}", item.status)))
                    .child(format!("Account: {}", item.wallet_id))
                    .child(format!(
                        "Network: {} · chain {}",
                        item.network_name, item.chain_id
                    ))
                    .child(format!(
                        "Created: {} · updated: {}",
                        item.created_at, item.updated_at
                    ))
                    .child(format!("Policy revision: {}", item.policy_revision))
                    .child(
                        div().child("Plan digest").child(
                            div()
                                .font_family(MONO_FONT_FAMILY)
                                .child(item.digest.clone()),
                        ),
                    );
                if let Some(source) = item.plan_source.as_ref() {
                    detail = detail.child(format!("Plan source: {source}"));
                }
                if let Some(review_digest) = item.review_digest.as_ref() {
                    detail = detail.child(
                        div().child("Review digest").child(
                            div()
                                .font_family(MONO_FONT_FAMILY)
                                .child(review_digest.clone()),
                        ),
                    );
                }
                for (label, value) in [
                    ("Signed hash", item.signed_transaction_hash.as_ref()),
                    ("Broadcast hash", item.broadcast_transaction_hash.as_ref()),
                    ("Block", item.block_number.as_ref()),
                ] {
                    if let Some(value) = value {
                        detail = detail.child(
                            div()
                                .child(label)
                                .child(div().font_family(MONO_FONT_FAMILY).child(value.clone())),
                        );
                    }
                }
                if let Some(hash) = item
                    .broadcast_transaction_hash
                    .as_ref()
                    .or(item.signed_transaction_hash.as_ref())
                    && let Ok(chain_id) = item.chain_id.parse::<u64>()
                    && let Ok(networks) = self.cached_networks()
                    && let Some(explorer_url) =
                        block_explorer_transaction_url(networks, chain_id, hash)
                {
                    detail = detail.child(
                        Button::new(SharedString::from(format!(
                            "open-transaction-explorer-{request_id}"
                        )))
                        .label("View transaction in block explorer")
                        .on_click(move |_, _, cx| cx.open_url(&explorer_url)),
                    );
                }
                if let Some(fee) = item.mined_fee.as_ref() {
                    detail = detail.child(format!(
                        "Mined fee: {} wei · {} gas at {} wei/gas",
                        fee.transaction_fee_wei, fee.gas_used, fee.effective_gas_price
                    ));
                }
                if !item.cancel_transaction_hashes.is_empty() {
                    detail =
                        detail
                            .child(div().font_semibold().child("Cancellation attempts"))
                            .children(item.cancel_transaction_hashes.iter().cloned().map(|hash| {
                                div().font_family(MONO_FONT_FAMILY).text_sm().child(hash)
                            }));
                }
                detail
                    .child(
                        div().child("Exact execution plan").child(
                            div()
                                .max_h(px(360.0))
                                .overflow_y_scrollbar()
                                .p_3()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().border)
                                .font_family(MONO_FONT_FAMILY)
                                .text_sm()
                                .whitespace_normal()
                                .child(exact_plan),
                        ),
                    )
                    .into_any_element()
            }
            OwnerActivityRecord::Message(item) => {
                let document = self.cached_message_document(request_id);
                let mut detail = GroupBox::new()
                    .id(SharedString::from(format!("activity-detail-{request_id}")))
                    .outline()
                    .title("Message signature details")
                    .child(header("Message signature", format!("{:?}", item.status)))
                    .child(format!("Account: {}", item.wallet_id))
                    .child(format!(
                        "Chain context: {}",
                        item.chain_id.as_deref().unwrap_or("Not specified")
                    ))
                    .child(format!(
                        "Requester: {}",
                        item.requester.as_deref().unwrap_or("Unknown requester")
                    ))
                    .child(format!(
                        "Created: {} · updated: {}",
                        item.created_at, item.updated_at
                    ))
                    .child(
                        div().child("Digest").child(
                            div()
                                .font_family(MONO_FONT_FAMILY)
                                .child(item.digest.clone()),
                        ),
                    );
                if let Some(decided_at) = item.approved_at.or(item.rejected_at) {
                    detail = detail.child(format!("Decision recorded: {decided_at}"));
                }
                if let Some(signature) = item.signature.as_ref() {
                    detail = detail.child(
                        div()
                            .child("Signature")
                            .child(div().font_family(MONO_FONT_FAMILY).child(signature.clone())),
                    );
                }
                match document {
                    Ok(document) => {
                        detail = detail.children(document.exact_payloads.iter().cloned().map(
                            |payload| {
                                div()
                                    .max_h(px(360.0))
                                    .overflow_y_scrollbar()
                                    .p_3()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(cx.theme().border)
                                    .font_family(MONO_FONT_FAMILY)
                                    .text_sm()
                                    .whitespace_normal()
                                    .child(payload)
                            },
                        ));
                    }
                    Err(error) => {
                        detail = detail.child(
                            div()
                                .text_color(cx.theme().danger)
                                .child(format!("Exact payload unavailable: {error:#}")),
                        );
                    }
                }
                detail.into_any_element()
            }
            OwnerActivityRecord::TypedData(item) => {
                let document = self.cached_typed_data_document(request_id);
                let mut detail = GroupBox::new()
                    .id(SharedString::from(format!("activity-detail-{request_id}")))
                    .outline()
                    .title("Typed-data signature details")
                    .child(header("Typed-data signature", format!("{:?}", item.status)))
                    .child(format!("Account: {}", item.wallet_id))
                    .child(format!("Chain: {}", item.chain_id))
                    .child(format!(
                        "Requester: {}",
                        item.requester.as_deref().unwrap_or("Unknown requester")
                    ))
                    .child(format!(
                        "Created: {} · updated: {}",
                        item.created_at, item.updated_at
                    ))
                    .child(
                        div().child("Digest").child(
                            div()
                                .font_family(MONO_FONT_FAMILY)
                                .child(item.digest.clone()),
                        ),
                    );
                if let Some(decided_at) = item.approved_at.or(item.rejected_at) {
                    detail = detail.child(format!("Decision recorded: {decided_at}"));
                }
                if let Some(signature) = item.signature.as_ref() {
                    detail = detail.child(
                        div()
                            .child("Signature")
                            .child(div().font_family(MONO_FONT_FAMILY).child(signature.clone())),
                    );
                }
                match document {
                    Ok(document) => {
                        detail = detail.children(document.exact_payloads.iter().cloned().map(
                            |payload| {
                                div()
                                    .max_h(px(360.0))
                                    .overflow_y_scrollbar()
                                    .p_3()
                                    .rounded_lg()
                                    .border_1()
                                    .border_color(cx.theme().border)
                                    .font_family(MONO_FONT_FAMILY)
                                    .text_sm()
                                    .whitespace_normal()
                                    .child(payload)
                            },
                        ));
                    }
                    Err(error) => {
                        detail = detail.child(
                            div()
                                .text_color(cx.theme().danger)
                                .child(format!("Exact payload unavailable: {error:#}")),
                        );
                    }
                }
                detail.into_any_element()
            }
        }
    }

    fn render_activity(&self, cx: &mut Context<Self>) -> gpui::Div {
        let panel = div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_3();
        let records = match self.cached_activity_records() {
            Ok(records) => records,
            Err(error) => return panel.child(format!("Activity unavailable: {error:#}")),
        };
        let items = records.as_ref();
        let selected = self
            .selected_record
            .and_then(|request_id| items.iter().find(|item| item.request_id() == request_id));
        let mut panel = panel;
        if let Some(item) = selected {
            panel = panel.child(self.render_activity_detail(item, cx));
        }
        if items.is_empty() {
            return panel.child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("No wallet activity yet."),
            );
        }
        let selected_record = self.selected_record;
        let busy = Arc::new(self.activity_busy.clone());
        let feedback = Arc::new(self.activity_feedback.clone());
        let editor = cx.entity().downgrade();
        panel.child(
            uniform_list("activity-records", records.len(), move |range, _, cx| {
                range
                    .map(|index| {
                        let record = &records[index];
                        let request_id = record.request_id();
                        render_activity_row(
                            record,
                            selected_record == Some(request_id),
                            busy.contains(&request_id),
                            feedback.get(&request_id).cloned(),
                            editor.clone(),
                            cx,
                        )
                    })
                    .collect()
            })
            .w_full()
            .h(px(580.0)),
        )
    }

    fn render_settings(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut agents = div().flex().flex_col().gap_1();
        let clients = self.cached_clients().unwrap_or_default();
        let visible_sessions = visible_agent_sessions(clients, &self.hidden_agent_sessions);
        let mut managed_agents = div().flex().flex_col().gap_1();
        for item in &visible_sessions {
            let client_id = item.id;
            let (expiration, expired) =
                agent_session_expiry_label(item.session_expires_at, chrono::Utc::now());
            let last_used = item.last_used_at.map_or_else(
                || "Not used yet".into(),
                |last_used| format!("Last used {}", last_used.format("%b %d, %Y at %H:%M UTC")),
            );
            managed_agents = managed_agents.child(
                ListItem::new(SharedString::from(format!("managed-agent-{client_id}"))).child(
                    div()
                        .w_full()
                        .px_3()
                        .py_3()
                        .flex()
                        .flex_col()
                        .gap_2()
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
                                        .child(div().font_semibold().truncate().child(format!(
                                            "{} · {:?}",
                                            item.display_name, item.agent_kind
                                        )))
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(last_used),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex_none()
                                        .flex()
                                        .flex_col()
                                        .items_end()
                                        .gap_1()
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(if expired {
                                                    cx.theme().danger
                                                } else {
                                                    cx.theme().success
                                                })
                                                .child(expiration),
                                        )
                                        .when(!expired, |actions| {
                                            actions.child(
                                                Button::new(SharedString::from(format!(
                                                    "revoke-agent-{client_id}"
                                                )))
                                                .label("Revoke")
                                                .small()
                                                .danger()
                                                .on_click(cx.listener(move |view, _, _, cx| {
                                                    view.revoke_agent(client_id, cx);
                                                })),
                                            )
                                        }),
                                ),
                        ),
                ),
            );
        }
        if visible_sessions.is_empty() {
            managed_agents = managed_agents.child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("No authorized agent sessions."),
            );
        }
        match &self.detected_agents {
            AgentDetectionState::Loading => {
                agents = agents.child(h_flex().gap_2().child(Spinner::new()).child("Detecting…"));
            }
            AgentDetectionState::Failed(error) => {
                agents = agents.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(format!("Agent detection unavailable: {error}")),
                );
            }
            AgentDetectionState::Ready(detected) if detected.is_empty() => {
                agents = agents.child(
                    div()
                        .text_color(cx.theme().muted_foreground)
                        .child("No supported agent installation was detected."),
                );
            }
            AgentDetectionState::Ready(detected) => {
                for (index, agent) in detected.iter().enumerate() {
                    let installed = agent.installed.as_ref().copied().unwrap_or(false);
                    let config_error = agent.installed.as_ref().err().cloned();
                    let kind = agent.kind;
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
                                        .flex_wrap()
                                        .justify_between()
                                        .gap_4()
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .child(agent.display_name)
                                                .child(
                                                    div()
                                                        .text_sm()
                                                        .text_color(cx.theme().muted_foreground)
                                                        .truncate()
                                                        .child(agent.config_path.clone()),
                                                ),
                                        )
                                        .child(
                                            h_flex()
                                                .gap_3()
                                                .child(
                                                    div()
                                                        .text_sm()
                                                        .text_color(cx.theme().muted_foreground)
                                                        .child(if installed {
                                                            "Automatically managed"
                                                        } else if config_error.is_some() {
                                                            "Configuration needs attention"
                                                        } else {
                                                            "Not installed"
                                                        }),
                                                )
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "install-detected-agent-{index}"
                                                    )))
                                                    .label(if installed {
                                                        "Reinstall"
                                                    } else if config_error.is_some() {
                                                        "Repair"
                                                    } else {
                                                        "Install"
                                                    })
                                                    .disabled(
                                                        self.agent_reinstall
                                                            == AgentReinstallState::Running,
                                                    )
                                                    .when(!installed, ButtonVariants::primary)
                                                    .on_click(cx.listener(move |view, _, _, cx| {
                                                        view.prepare_detected_agent_install(
                                                            kind, cx,
                                                        );
                                                    })),
                                                ),
                                        ),
                                )
                                .when_some(config_error, |row, error| {
                                    row.child(
                                        div().text_sm().text_color(cx.theme().danger).child(error),
                                    )
                                }),
                        ),
                    );
                }
            }
        }

        let detailed = self.detailed_notification_previews.load(Ordering::Relaxed);
        div()
            .flex()
            .flex_col()
            .gap_4()
            .child(settings_section(
                "Appearance",
                GroupBox::new()
                    .id("appearance-settings")
                    .outline()
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("System follows your operating-system appearance and updates while the wallet is running."),
                    )
                    .child(
                        h_flex()
                            .flex_wrap()
                            .gap_2()
                            .child(
                                Button::new("appearance-system")
                                    .label("System")
                                    .selected(
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
                                Button::new("appearance-light")
                                    .label("Light")
                                    .selected(
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
                                Button::new("appearance-dark")
                                    .label("Dark")
                                    .selected(
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
            .child(settings_section(
                "Notifications",
                GroupBox::new()
                    .id("notification-settings")
                    .outline()
                    .child(
                        h_flex()
                            .w_full()
                            .flex_wrap()
                            .justify_between()
                            .gap_4()
                            .child(
                                div()
                                    .flex_1()
                                    .child("Show detailed previews")
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(cx.theme().muted_foreground)
                                            .child("Off by default so lock-screen notifications do not expose transaction identifiers."),
                                    ),
                            )
                            .child(
                                Switch::new("detailed-notification-previews")
                                    .checked(detailed)
                                    .disabled(self.notification_preference_busy)
                                    .tooltip("Include request identifiers in lifecycle notifications")
                                    .on_click(cx.listener(|view, checked, _, cx| {
                                        view.set_detailed_notification_previews(*checked, cx);
                                    })),
                            ),
                    ),
            ))
            .child(settings_section(
                "Detected agents",
                GroupBox::new()
                    .id("detected-agent-settings")
                    .outline()
                    .child(
                        Button::new("reinstall-all-detected-agents")
                            .label(if self.agent_reinstall == AgentReinstallState::Running {
                                "Reinstalling…"
                            } else {
                                "Reinstall MCP server"
                            })
                            .primary()
                            .disabled(
                                self.legal_gate
                                    || self.agent_reinstall == AgentReinstallState::Running,
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.reinstall_detected_agents_from_menu(cx);
                            })),
                    )
                    .child(agents),
            ))
            .child(settings_section(
                "Agent sessions",
                GroupBox::new()
                    .id("agent-session-settings")
                    .outline()
                    .child(managed_agents),
            ))
            .child(self.render_updates(cx))
            .child(self.render_legal(cx))
    }

    fn render_accounts(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut panel = div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_2()
            .child(div().font_semibold().child("Create or import account"))
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("New and imported accounts start with a policy that requires review for every transaction."),
            );
        if let Some(input) = &self.account_id_input {
            panel = panel
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(
                            div()
                                .min_w(px(180.0))
                                .flex_1()
                                .flex_basis(px(320.0))
                                .child(Input::new(input)),
                        )
                        .child(
                            Button::new("create-account")
                                .label("Create")
                                .primary()
                                .on_click(cx.listener(|view, _, window, cx| {
                                    view.create_account(window, cx);
                                })),
                        ),
                )
                .when_some(self.account_id_error.clone(), |panel, error| {
                    panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
                });
        }
        if let Some(input) = &self.private_key_input {
            panel = panel
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_2()
                        .child(
                            div()
                                .min_w(px(180.0))
                                .flex_1()
                                .flex_basis(px(320.0))
                                .child(Input::new(input).mask_toggle()),
                        )
                        .child(
                            Button::new("import-account")
                                .label("Import private key")
                                .on_click(cx.listener(|view, _, window, cx| {
                                    view.import_account(window, cx);
                                })),
                        ),
                )
                .when_some(self.private_key_error.clone(), |panel, error| {
                    panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
                });
        }
        panel = panel.child(
            div()
                .mt_3()
                .font_semibold()
                .child("Accounts on this device"),
        );
        match self.cached_accounts() {
            Ok([]) => panel.child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("No accounts yet."),
            ),
            Ok(items) => {
                let item_count = items.len();
                panel.children(items.iter().enumerate().map(|(index, item)| {
                    let export_id = item.id.clone();
                    let removal_id = item.id.clone();
                    let action_error = self.account_action_errors.get(&item.id).cloned();
                    div()
                        .py_2()
                        .when(index + 1 < item_count, |row| {
                            row.border_b_1().border_color(cx.theme().border)
                        })
                        .flex()
                        .flex_col()
                        .gap_1()
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
                                        .child(
                                            div().font_semibold().truncate().child(item.id.clone()),
                                        )
                                        .child(
                                            div()
                                                .max_w_full()
                                                .truncate()
                                                .font_family(MONO_FONT_FAMILY)
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(format!("{:#x}", item.address)),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex_none()
                                        .flex()
                                        .flex_wrap()
                                        .gap_2()
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "export-account-{export_id}"
                                            )))
                                            .label("Export")
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.begin_account_export(export_id.clone(), cx);
                                            })),
                                        )
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "remove-account-{removal_id}"
                                            )))
                                            .label("Remove")
                                            .danger()
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.begin_account_removal(removal_id.clone(), cx);
                                            })),
                                        ),
                                ),
                        )
                        .when_some(action_error, |row, error| {
                            row.child(div().text_sm().text_color(cx.theme().danger).child(error))
                        })
                }))
            }
            Err(error) => panel.child(
                div()
                    .text_sm()
                    .text_color(cx.theme().danger)
                    .child(format!("Accounts unavailable: {error:#}")),
            ),
        }
    }

    fn render_guided_policy_chain_form(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut form = div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .font_semibold()
                    .child(if self.policy_chain_original_key.is_some() {
                        "Edit chain policy"
                    } else {
                        "Add chain policy"
                    }),
            );
        if let Some(input) = self.policy_chain_input.as_ref() {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child("Chain")
                    .child(Input::new(input))
                    .when_some(self.policy_chain_errors.chain.clone(), |field, error| {
                        field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            );
        }
        if let Some(input) = self.policy_chain_label_input.as_ref() {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child("Description (optional)")
                    .child(Input::new(input))
                    .when_some(self.policy_chain_errors.label.clone(), |field, error| {
                        field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            );
        }
        if let Some(input) = self.policy_chain_max_calls_input.as_ref() {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child("Maximum calls in one atomic batch")
                    .child(Input::new(input))
                    .when_some(
                        self.policy_chain_errors.max_calls.clone(),
                        |field, error| {
                            field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                        },
                    ),
            );
        }
        form = form
            .child("Native value guard")
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        Button::new("policy-native-none")
                            .label("No native value")
                            .when(
                                self.policy_chain_native_value_mode
                                    == GuidedNativeValueMode::None,
                                ButtonVariants::primary,
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.policy_chain_native_value_mode =
                                    GuidedNativeValueMode::None;
                                view.policy_chain_errors.native_values = None;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("policy-native-any")
                            .label("Any native value")
                            .when(
                                self.policy_chain_native_value_mode
                                    == GuidedNativeValueMode::Any,
                                ButtonVariants::primary,
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.policy_chain_native_value_mode = GuidedNativeValueMode::Any;
                                view.policy_chain_errors.native_values = None;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("policy-native-exact")
                            .label("Exact wei values")
                            .when(
                                self.policy_chain_native_value_mode
                                    == GuidedNativeValueMode::Exact,
                                ButtonVariants::primary,
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.policy_chain_native_value_mode =
                                    GuidedNativeValueMode::Exact;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("This is a guard, not a grant: a rule must still allow the call before it can sign automatically."),
            );
        if self.policy_chain_native_value_mode == GuidedNativeValueMode::Exact
            && let Some(input) = self.policy_chain_native_values_input.as_ref()
        {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child("Allowed values in wei")
                    .child(Input::new(input))
                    .when_some(
                        self.policy_chain_errors.native_values.clone(),
                        |field, error| {
                            field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                        },
                    ),
            );
        }
        form = form
            .when_some(self.policy_chain_errors.form.clone(), |form, error| {
                form.child(div().text_sm().text_color(cx.theme().danger).child(error))
            })
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        Button::new("save-guided-policy-chain")
                            .label(if self.policy_chain_original_key.is_some() {
                                "Save chain draft"
                            } else {
                                "Add chain draft"
                            })
                            .primary()
                            .disabled(self.policy_installing)
                            .on_click(cx.listener(|view, _, window, cx| {
                                view.save_guided_policy_chain(window, cx);
                            })),
                    )
                    .when(self.policy_chain_original_key.is_some(), |actions| {
                        actions.child(
                            Button::new("cancel-guided-policy-chain")
                                .label("Cancel edit")
                                .on_click(cx.listener(|view, _, window, cx| {
                                    view.reset_guided_policy_chain_form(window, cx);
                                })),
                        )
                    }),
            );
        form
    }

    fn render_guided_policy_rule_form(&self, cx: &mut Context<Self>) -> gpui::Div {
        let Some(chain_key) = self.policy_rule_chain_key.as_ref() else {
            return div();
        };
        let mut form = div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_3()
            .child(div().font_semibold().child(format!(
                "{} rule for chain {chain_key}",
                if self.policy_rule_original_index.is_some() {
                    "Edit"
                } else {
                    "Add"
                }
            )))
            .child("Effect")
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        Button::new("policy-rule-allow")
                            .label("Allow automatically")
                            .when(
                                self.policy_rule_effect == GuidedRuleEffect::Allow,
                                ButtonVariants::primary,
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.policy_rule_effect = GuidedRuleEffect::Allow;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("policy-rule-deny")
                            .label("Deny without review")
                            .danger()
                            .when(
                                self.policy_rule_effect == GuidedRuleEffect::Deny,
                                ButtonVariants::primary,
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.policy_rule_effect = GuidedRuleEffect::Deny;
                                cx.notify();
                            })),
                    ),
            );
        if let Some(input) = self.policy_rule_label_input.as_ref() {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child("Description (optional)")
                    .child(Input::new(input))
                    .when_some(self.policy_rule_errors.label.clone(), |field, error| {
                        field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            );
        }
        form = form.child("Called contract or recipient").child(
            h_flex()
                .gap_2()
                .child(
                    Button::new("policy-rule-target-any")
                        .label("Any target")
                        .when(
                            self.policy_rule_target_mode == GuidedLiteralMode::Any,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_target_mode = GuidedLiteralMode::Any;
                            view.policy_rule_errors.targets = None;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("policy-rule-target-exact")
                        .label("Named targets")
                        .when(
                            self.policy_rule_target_mode == GuidedLiteralMode::Exact,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_target_mode = GuidedLiteralMode::Exact;
                            cx.notify();
                        })),
                ),
        );
        if self.policy_rule_target_mode == GuidedLiteralMode::Exact
            && let Some(input) = self.policy_rule_targets_input.as_ref()
        {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(Input::new(input))
                    .when_some(self.policy_rule_errors.targets.clone(), |field, error| {
                        field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            );
        }
        form = form.child("Sending account").child(
            h_flex()
                .gap_2()
                .child(
                    Button::new("policy-rule-sender-any")
                        .label("Selected wallet")
                        .when(
                            self.policy_rule_sender_mode == GuidedLiteralMode::Any,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_sender_mode = GuidedLiteralMode::Any;
                            view.policy_rule_errors.senders = None;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("policy-rule-sender-exact")
                        .label("Named senders")
                        .when(
                            self.policy_rule_sender_mode == GuidedLiteralMode::Exact,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_sender_mode = GuidedLiteralMode::Exact;
                            cx.notify();
                        })),
                ),
        );
        if self.policy_rule_sender_mode == GuidedLiteralMode::Exact
            && let Some(input) = self.policy_rule_senders_input.as_ref()
        {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(Input::new(input))
                    .when_some(self.policy_rule_errors.senders.clone(), |field, error| {
                        field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            );
        }
        form = form.child("Native value on the call").child(
            h_flex()
                .gap_2()
                .child(
                    Button::new("policy-rule-value-any")
                        .label("Any value")
                        .when(
                            self.policy_rule_value_mode == GuidedLiteralMode::Any,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_value_mode = GuidedLiteralMode::Any;
                            view.policy_rule_errors.values = None;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("policy-rule-value-exact")
                        .label("Exact wei values")
                        .when(
                            self.policy_rule_value_mode == GuidedLiteralMode::Exact,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_value_mode = GuidedLiteralMode::Exact;
                            cx.notify();
                        })),
                ),
        );
        if self.policy_rule_value_mode == GuidedLiteralMode::Exact
            && let Some(input) = self.policy_rule_values_input.as_ref()
        {
            form = form.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(Input::new(input))
                    .when_some(self.policy_rule_errors.values.clone(), |field, error| {
                        field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            );
        }
        form = form.child("Calldata").child(
            div()
                .flex()
                .flex_wrap()
                .gap_2()
                .child(
                    Button::new("policy-rule-calldata-any")
                        .label("Any calldata")
                        .when(
                            self.policy_rule_calldata_mode == GuidedCalldataMode::Any,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_calldata_mode = GuidedCalldataMode::Any;
                            view.policy_rule_errors.abi = None;
                            view.policy_rule_errors.args = None;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("policy-rule-calldata-empty")
                        .label("Empty calldata")
                        .when(
                            self.policy_rule_calldata_mode == GuidedCalldataMode::Empty,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_calldata_mode = GuidedCalldataMode::Empty;
                            view.policy_rule_errors.abi = None;
                            view.policy_rule_errors.args = None;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("policy-rule-calldata-selector")
                        .label("ABI function")
                        .when(
                            self.policy_rule_calldata_mode == GuidedCalldataMode::Selector,
                            ButtonVariants::primary,
                        )
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.policy_rule_calldata_mode = GuidedCalldataMode::Selector;
                            cx.notify();
                        })),
                ),
        );
        if self.policy_rule_calldata_mode == GuidedCalldataMode::Selector {
            if let Some(input) = self.policy_rule_abi_input.as_ref() {
                form = form.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child("Canonical function signature")
                        .child(Input::new(input))
                        .when_some(self.policy_rule_errors.abi.clone(), |field, error| {
                            field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                        }),
                );
            }
            if let Some(input) = self.policy_rule_args_input.as_ref() {
                form = form.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child("Typed argument predicates (JSON object)")
                        .child(Input::new(input).w_full())
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child("Use eq/in predicates, or compose any, all, not, each, selector, and length predicates. The signature type-checks every constraint."),
                        )
                        .when_some(self.policy_rule_errors.args.clone(), |field, error| {
                            field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                        }),
                );
            }
        }
        form.when_some(self.policy_rule_errors.chain.clone(), |form, error| {
            form.child(div().text_sm().text_color(cx.theme().danger).child(error))
        })
        .when_some(self.policy_rule_errors.form.clone(), |form, error| {
            form.child(div().text_sm().text_color(cx.theme().danger).child(error))
        })
        .child(
            h_flex()
                .gap_2()
                .child(
                    Button::new("save-guided-policy-rule")
                        .label(if self.policy_rule_original_index.is_some() {
                            "Save rule draft"
                        } else {
                            "Add rule draft"
                        })
                        .primary()
                        .disabled(self.policy_installing)
                        .on_click(cx.listener(|view, _, window, cx| {
                            view.save_guided_policy_rule(window, cx);
                        })),
                )
                .child(
                    Button::new("cancel-guided-policy-rule")
                        .label("Cancel")
                        .on_click(cx.listener(|view, _, window, cx| {
                            view.reset_guided_policy_rule_form(window, cx);
                        })),
                ),
        )
    }

    fn render_policies(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div()
            .h_full()
            .min_h(px(520.0))
            .flex()
            .flex_col()
            .gap_4()
            .when_some(self.policy_action_error.clone(), |content, error| {
                content.child(div().text_sm().text_color(cx.theme().danger).child(error))
            });
        let accounts = match self.cached_accounts() {
            Ok(accounts) => accounts,
            Err(error) => {
                return content.child(Alert::error(
                    "policy-account-error",
                    format!("Accounts unavailable: {error:#}"),
                ));
            }
        };
        match self
            .cached_reviews()
            .map(|reviews| reviews.policy_proposals.as_slice())
        {
            Ok(proposals) if !proposals.is_empty() => {
                let mut proposal_list = div().flex().flex_col().gap_3();
                for proposal in proposals {
                    let current_result = self.cached_policy(&proposal.wallet_id);
                    let current_error = current_result
                        .as_ref()
                        .err()
                        .map(|error| format!("Could not read active policy: {error:#}"));
                    let current = current_result.ok().flatten();
                    let current_revision = current.as_ref().map(|policy| policy.revision);
                    let current_policy = current
                        .as_ref()
                        .map_or_else(WalletPolicy::require_approval_for_everything, |policy| {
                            policy.policy.clone()
                        });
                    let applicable = current_revision == Some(proposal.source_revision);
                    let mut changes = div().flex().flex_col().gap_1();
                    for line in diff_policies(&current_policy, &proposal.policy) {
                        changes = changes
                            .child(div().font_family(MONO_FONT_FAMILY).text_sm().child(line));
                    }
                    let review_proposal = proposal.clone();
                    let reject_proposal = proposal.clone();
                    proposal_list =
                        proposal_list.child(
                            div()
                                .p_3()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(
                                    div()
                                        .flex()
                                        .flex_wrap()
                                        .items_center()
                                        .justify_between()
                                        .gap_2()
                                        .child(div().font_semibold().child(format!(
                                            "{} · based on revision {}",
                                            proposal.wallet_id, proposal.source_revision
                                        )))
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(if applicable {
                                                    cx.theme().primary
                                                } else {
                                                    cx.theme().danger
                                                })
                                                .child(if applicable {
                                                    "Ready for review"
                                                } else {
                                                    "Superseded by a policy change"
                                                }),
                                        ),
                                )
                                .child(div().text_sm().child(
                                    ekubo_wallet_core::sanitize::terminal_safe_multiline(
                                        &proposal.rationale,
                                    ),
                                ))
                                .when_some(current_error, |card, error| {
                                    card.child(
                                        div().text_sm().text_color(cx.theme().danger).child(error),
                                    )
                                })
                                .child(changes)
                                .child(
                                    div()
                                        .flex()
                                        .flex_wrap()
                                        .gap_2()
                                        .child(
                                            Button::new(SharedString::from(format!(
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
                                            Button::new(SharedString::from(format!(
                                                "reject-policy-proposal-{}",
                                                proposal.wallet_id
                                            )))
                                            .label("Reject proposal")
                                            .danger()
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.reject_policy_proposal(&reject_proposal, cx);
                                            })),
                                        ),
                                ),
                        );
                }
                content = content.child(
                    GroupBox::new()
                        .id("policy-proposals")
                        .outline()
                        .title("Agent proposals")
                        .child(proposal_list),
                );
            }
            Ok(_) => {}
            Err(error) => {
                content = content.child(Alert::error(
                    "policy-proposal-error",
                    format!("Policy proposals unavailable: {error:#}"),
                ));
            }
        }
        if accounts.is_empty() {
            return content.child(
                GroupBox::new()
                    .id("policy-empty")
                    .outline()
                    .title("Signing policies")
                    .child("Create an account before configuring signing permissions.")
                    .child(
                        Button::new("policy-go-to-accounts")
                            .label("Go to Accounts")
                            .primary()
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_route(Route::Accounts);
                                cx.notify();
                            })),
                    ),
            );
        }

        let selected_wallet = self
            .policy_editor
            .as_ref()
            .map(|editor| editor.wallet_id.as_str());
        let mut account_picker = div().flex().flex_wrap().gap_2();
        for account in accounts {
            let wallet_id = account.id.clone();
            let selected = selected_wallet == Some(wallet_id.as_str());
            account_picker = account_picker.child(
                Button::new(SharedString::from(format!("policy-wallet-{wallet_id}")))
                    .label(wallet_id.clone())
                    .when(selected, ButtonVariants::primary)
                    .on_click(cx.listener(move |view, _, window, cx| {
                        view.open_policy_editor(&wallet_id, window, cx);
                    })),
            );
        }
        content = content.child(
            GroupBox::new()
                .id("policy-account-picker")
                .outline()
                .title("Account")
                .child(account_picker),
        );

        let (Some(editor), Some(input)) =
            (self.policy_editor.as_ref(), self.policy_json_input.as_ref())
        else {
            return content.child(
                div()
                    .p_5()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .text_color(cx.theme().muted_foreground)
                    .child("Select an account to inspect its exact policy document."),
            );
        };

        let current_document = input.read(cx).value();
        let validated = editor
            .validation
            .as_ref()
            .and_then(|result| result.as_ref().ok());
        let reviewed_exact_document =
            validated.is_some_and(|review| current_document.as_ref() == review.document.as_str());
        let revision = editor.source_revision.map_or_else(
            || "No installed policy · signing disabled".to_owned(),
            |revision| format!("Installed revision {revision}"),
        );
        let mut editor_panel = div()
            .id("policy-json-editor")
            .anchor_scroll(Some(self.policy_editor_anchor.clone()))
            .flex_1()
            .min_h(px(420.0))
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .font_semibold()
                    .child(format!("{} policy", editor.wallet_id)),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(revision),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        Button::new("policy-guided-mode")
                            .label("Guided")
                            .when(
                                editor.mode == PolicyEditorMode::Guided,
                                ButtonVariants::primary,
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_policy_editor_mode(PolicyEditorMode::Guided, cx);
                            })),
                    )
                    .child(
                        Button::new("policy-advanced-mode")
                            .label("Advanced JSON")
                            .when(
                                editor.mode == PolicyEditorMode::Advanced,
                                ButtonVariants::primary,
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_policy_editor_mode(PolicyEditorMode::Advanced, cx);
                            })),
                    ),
            )
            .when_some(
                editor
                    .validation
                    .as_ref()
                    .and_then(|validation| validation.as_ref().err().cloned()),
                |panel, error| {
                    panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
                },
            );
        match editor.mode {
            PolicyEditorMode::Advanced => {
                editor_panel = editor_panel.child(
                    div()
                        .id("policy-json-editor-input")
                        .flex_1()
                        .min_h(px(320.0))
                        .child(Input::new(input).w_full().h_full()),
                );
            }
            PolicyEditorMode::Guided => match &editor.guided_policy {
                Err(error) => {
                    editor_panel = editor_panel.child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().danger)
                            .child(error.clone()),
                    );
                }
                Ok(policy) => {
                    if policy == &WalletPolicy::allow_all_with_approval() {
                        editor_panel = editor_panel.child(
                            div()
                                .p_3()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().danger)
                                .text_color(cx.theme().danger)
                                .child("Danger: this policy automatically signs every call on every chain, including arbitrary calldata and native value."),
                        );
                    }
                    let mut chain_cards = div().flex().flex_col().gap_3();
                    for (chain_key, chain) in &policy.chains {
                        let edit_key = chain_key.clone();
                        let remove_key = chain_key.clone();
                        let mut rules = div().flex().flex_col().gap_1();
                        if chain.rules.is_empty() {
                            rules = rules.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("No automatic allow or hard-deny rules; calls queue for review."),
                            );
                        } else {
                            for (rule_index, rule) in chain.rules.iter().enumerate() {
                                let edit_rule_chain = chain_key.clone();
                                let remove_rule_chain = chain_key.clone();
                                rules = rules.child(
                                    div()
                                        .py_2()
                                        .flex()
                                        .items_center()
                                        .justify_between()
                                        .gap_2()
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .font_family(MONO_FONT_FAMILY)
                                                .text_sm()
                                                .child(rule.describe()),
                                        )
                                        .child(
                                            h_flex()
                                                .gap_2()
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "edit-policy-rule-{chain_key}-{rule_index}"
                                                    )))
                                                    .label("Edit")
                                                    .on_click(cx.listener(
                                                        move |view, _, window, cx| {
                                                            view.begin_guided_policy_rule(
                                                                &edit_rule_chain,
                                                                Some(rule_index),
                                                                window,
                                                                cx,
                                                            );
                                                        },
                                                    )),
                                                )
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "remove-policy-rule-{chain_key}-{rule_index}"
                                                    )))
                                                    .label("Remove")
                                                    .danger()
                                                    .on_click(cx.listener(
                                                        move |view, _, window, cx| {
                                                            view.remove_guided_policy_rule(
                                                                &remove_rule_chain,
                                                                rule_index,
                                                                window,
                                                                cx,
                                                            );
                                                        },
                                                    )),
                                                ),
                                        ),
                                );
                            }
                        }
                        let add_rule_chain = chain_key.clone();
                        chain_cards = chain_cards.child(
                            div()
                                .p_3()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(
                                    h_flex()
                                        .w_full()
                                        .justify_between()
                                        .gap_3()
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .child(div().font_semibold().child(
                                                    if chain_key == "*" {
                                                        "Every otherwise-unconfigured chain"
                                                            .to_owned()
                                                    } else {
                                                        format!("Chain {chain_key}")
                                                    },
                                                ))
                                                .when_some(chain.label.clone(), |column, label| {
                                                    column.child(
                                                        div()
                                                            .text_sm()
                                                            .text_color(cx.theme().muted_foreground)
                                                            .child(label),
                                                    )
                                                }),
                                        )
                                        .child(
                                            h_flex()
                                                .gap_2()
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "edit-policy-chain-{chain_key}"
                                                    )))
                                                    .label("Edit")
                                                    .on_click(cx.listener(
                                                        move |view, _, window, cx| {
                                                            view.edit_guided_policy_chain(
                                                                &edit_key, window, cx,
                                                            );
                                                        },
                                                    )),
                                                )
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "remove-policy-chain-{chain_key}"
                                                    )))
                                                    .label("Remove")
                                                    .danger()
                                                    .on_click(cx.listener(
                                                        move |view, _, window, cx| {
                                                            view.remove_guided_policy_chain(
                                                                &remove_key,
                                                                window,
                                                                cx,
                                                            );
                                                        },
                                                    )),
                                                ),
                                        ),
                                )
                                .child(format!(
                                    "Maximum {} call(s) per batch · native value {}",
                                    chain.max_calls_per_batch,
                                    chain.native_value.describe()
                                ))
                                .child(rules)
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "add-policy-rule-{chain_key}"
                                    )))
                                    .label("Add rule")
                                    .on_click(cx.listener(move |view, _, window, cx| {
                                        view.begin_guided_policy_rule(
                                            &add_rule_chain,
                                            None,
                                            window,
                                            cx,
                                        );
                                    })),
                                ),
                        );
                    }
                    if policy.chains.is_empty() {
                        chain_cards = chain_cards.child(
                            div()
                                .text_color(cx.theme().muted_foreground)
                                .child("No chains are configured; every request requires review."),
                        );
                    }
                    editor_panel = editor_panel
                        .child(self.render_guided_policy_chain_form(cx))
                        .child(self.render_guided_policy_rule_form(cx))
                        .child(
                            GroupBox::new()
                                .id("guided-policy-chains")
                                .outline()
                                .title("Chain policies")
                                .child(chain_cards),
                        );
                }
            },
        }
        editor_panel = editor_panel.child(
            div()
                .flex()
                .flex_wrap()
                .gap_2()
                .child(
                    Button::new("reset-policy-draft")
                        .label("Reset to review everything")
                        .disabled(self.policy_installing)
                        .on_click(cx.listener(|view, _, window, cx| {
                            view.reset_policy_editor(window, cx);
                        })),
                )
                .child(
                    Button::new("allow-anything-policy-draft")
                        .icon(IconName::TriangleAlert)
                        .label("Allow anything")
                        .danger()
                        .disabled(self.policy_installing)
                        .on_click(cx.listener(|view, _, window, cx| {
                            view.apply_allow_anything_policy(window, cx);
                        })),
                )
                .child(
                    Button::new("validate-policy-draft")
                        .label("Validate and preview diff")
                        .disabled(self.policy_installing)
                        .on_click(cx.listener(|view, _, window, cx| {
                            view.validate_policy_editor(window, cx);
                        })),
                )
                .child(
                    Button::new("install-policy-draft")
                        .label(if self.policy_installing {
                            "Authenticating…"
                        } else {
                            "Install policy"
                        })
                        .primary()
                        .disabled(self.policy_installing || !reviewed_exact_document)
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.install_policy_editor(cx);
                        })),
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
                            .child(line.clone()),
                    );
                }
                content.child(
                    GroupBox::new()
                        .id("policy-permission-diff")
                        .outline()
                        .title("Permission changes")
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child("Installing requires operating-system authentication and rechecks the policy revision immediately before the write."),
                        )
                        .child(changes),
                )
            }
            Some(Ok(_)) => content.child(Alert::warning(
                "policy-diff-stale",
                "The document changed after validation. Validate it again to refresh the permission diff.",
            )),
            Some(Err(_)) | None => content,
        }
    }

    fn render_legal(&self, cx: &mut Context<Self>) -> gpui::Div {
        let license_url = application_license_url();
        let panel = GroupBox::new()
            .id("legal-and-version")
            .outline()
            .child(format!("Version {BUILD_VERSION}"))
            .child("Copyright © 2026 Ekubo, Inc.")
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .child("Licensed under FSL-1.1-MIT")
                    .child(
                        Button::new("review-license")
                            .label("View")
                            .tooltip("View the license for this exact source revision on GitHub")
                            .on_click(cx.listener(move |_, _, _, cx| {
                                cx.open_url(&license_url);
                            })),
                    ),
            );
        let panel =
            match self.cached_legal_status() {
                Ok(status) => panel
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(format!(
                                "Terms of Service · {}",
                                legal_acceptance_label(&status.terms_of_service)
                            ))
                            .child(Button::new("review-terms").label("View").on_click(
                                cx.listener(|view, _, _, cx| {
                                    view.open_legal_review(LegalDocument::TermsOfService, cx);
                                }),
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(format!(
                                "Privacy Policy · {}",
                                legal_acceptance_label(&status.privacy_policy)
                            ))
                            .child(Button::new("review-privacy").label("View").on_click(
                                cx.listener(|view, _, _, cx| {
                                    view.open_legal_review(LegalDocument::PrivacyPolicy, cx);
                                }),
                            )),
                    )
                    .child(
                        h_flex()
                            .w_full()
                            .justify_between()
                            .child("Third-Party Licenses")
                            .child(Button::new("review-licenses").label("View").on_click(
                                cx.listener(|view, _, _, cx| {
                                    view.open_legal_review(LegalDocument::ThirdPartyLicenses, cx);
                                }),
                            )),
                    ),
                Err(error) => panel.child(format!("Legal status unavailable: {error:#}")),
            };
        settings_section("About Ekubo Wallet", panel)
    }

    fn render_walletconnect(&self, cx: &mut Context<Self>) -> gpui::Div {
        let account_error = match self.cached_accounts() {
            Ok([]) => Some("Create an account before starting a pairing.".into()),
            Err(error) => Some(format!("Signing accounts unavailable: {error:#}")),
            Ok(_) => None,
        };
        let account_unavailable = account_error.is_some();
        let scan_running = matches!(self.walletconnect_scan, WalletConnectScanState::Scanning);
        let mut panel = div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_3()
            .child("Pairings are in memory only and disconnect when you explicitly Quit.");
        if let Some(input) = self.walletconnect_uri_input.as_ref() {
            panel = panel.child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(Input::new(input).flex_1())
                    .child(
                        Button::new("connect-walletconnect")
                            .label("Connect")
                            .primary()
                            .disabled(account_unavailable)
                            .on_click(cx.listener(|view, _, window, cx| {
                                view.connect_walletconnect(window, cx);
                            })),
                    )
                    .when(SystemScreenPicker::supported(), |row| {
                        row.child(
                            Button::new("scan-walletconnect")
                                .label(if scan_running {
                                    "Waiting for selection…"
                                } else {
                                    "Scan Screen"
                                })
                                .disabled(account_unavailable || scan_running)
                                .on_click(cx.listener(|view, _, _, cx| {
                                    view.scan_walletconnect_screen(cx);
                                })),
                        )
                    }),
            );
            if let Some(error) = account_error {
                panel = panel.child(div().text_sm().text_color(cx.theme().danger).child(error));
            }
        }
        match &self.walletconnect_scan {
            WalletConnectScanState::Idle => {}
            WalletConnectScanState::Scanning => {
                panel = panel.child(
                    h_flex()
                        .gap_2()
                        .child(Spinner::new())
                        .child("Choose a screen area or window in the macOS picker."),
                );
            }
            WalletConnectScanState::Choices { previews, .. } => {
                let mut choices = div()
                    .p_3()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child("Several WalletConnect codes were found. Choose one to connect.")
                    .child(
                        Button::new("cancel-walletconnect-scan")
                            .label("Cancel")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.cancel_walletconnect_scan(cx);
                            })),
                    );
                let mut previews_row = div().flex().flex_wrap().gap_3();
                for (index, preview) in previews.iter().enumerate() {
                    previews_row =
                        previews_row.child(
                            div()
                                .p_2()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(
                                    img(preview.clone())
                                        .w(px(160.0))
                                        .h(px(160.0))
                                        .object_fit(ObjectFit::Contain),
                                )
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "choose-walletconnect-qr-{index}"
                                    )))
                                    .label(format!("Use QR {}", index + 1))
                                    .primary()
                                    .on_click(cx.listener(move |view, _, window, cx| {
                                        view.choose_walletconnect_qr(index, window, cx);
                                    })),
                                ),
                        );
                }
                choices = choices.child(previews_row);
                panel = panel.child(choices);
            }
        }
        if self.walletconnect_sessions.is_empty() {
            return panel.child("No active WalletConnect sessions.");
        }
        panel.children(self.walletconnect_sessions.iter().cloned().map(|session| {
            let session_id = session.id;
            div()
                .p_3()
                .rounded_lg()
                .border_1()
                .border_color(cx.theme().border)
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .child(format!(
                            "{} · {:?}",
                            session.dapp_name.as_deref().unwrap_or("Pairing"),
                            session.status
                        ))
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(format!(
                                    "{} active request(s) · topic {}",
                                    session.active_requests, session.pairing_topic
                                )),
                        )
                        .when_some(session.last_error, |column, error| {
                            column.child(format!("Connection error: {error}"))
                        }),
                )
                .child(
                    Button::new(SharedString::from(format!("disconnect-wc-{session_id}")))
                        .label("Disconnect")
                        .danger()
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.disconnect_walletconnect(session_id, cx);
                        })),
                )
        }))
    }

    fn render_network_editor(&self, cx: &mut Context<Self>) -> gpui::Div {
        if !self.network_editor_open {
            return div().child(
                Button::new("open-custom-network-editor")
                    .label("Add custom network")
                    .primary()
                    .icon(IconName::Plus)
                    .on_click(cx.listener(|view, _, window, cx| {
                        view.open_new_network_editor(window, cx);
                    })),
            );
        }
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
        let Some(max_gas_limit) = self.network_max_gas_limit_input.as_ref() else {
            return div();
        };
        let Some(max_fee_per_gas) = self.network_max_fee_per_gas_input.as_ref() else {
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
        let field = |label: &'static str,
                     input: &Entity<InputState>,
                     error: Option<String>,
                     disabled: bool| {
            div()
                .min_w(px(180.0))
                .flex_1()
                .flex()
                .flex_col()
                .gap_1()
                .child(div().text_sm().child(label))
                .child(Input::new(input).disabled(disabled || busy))
                .when_some(error, |field, error| {
                    field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                })
        };
        let mut panel = GroupBox::new()
            .id("guided-network-editor")
            .outline()
            .title(if editing {
                "Edit network"
            } else {
                "Add custom network"
            })
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("RPC endpoints provide balances and transaction simulations. The wallet validates every field, verifies the live chain ID, then requires owner authentication before saving to the encrypted database."),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(field(
                        "Internal name",
                        name,
                        self.network_editor_errors.name.clone(),
                        false,
                    ))
                    .child(field(
                        "Display name (optional)",
                        display_name,
                        self.network_editor_errors.display_name.clone(),
                        false,
                    ))
                    .child(field(
                        "Chain ID",
                        chain_id,
                        self.network_editor_errors.chain_id.clone(),
                        false,
                    )),
            )
            .child(field(
                "Aliases (optional, comma-separated)",
                aliases,
                self.network_editor_errors.aliases.clone(),
                false,
            ))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .child("RPC URLs (one per line, comma-separated)"),
                    )
                    .child(Input::new(rpc_urls).disabled(busy).h(px(132.0)))
                    .when_some(self.network_editor_errors.rpc_urls.clone(), |field, error| {
                        field.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .child(div().text_sm().child("Endpoint order"))
                    .child(
                        Button::new("network-strategy-ordered")
                            .label("Configured order")
                            .selected(self.network_editor_rpc_strategy == RpcStrategy::Ordered)
                            .disabled(busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_network_editor_strategy(RpcStrategy::Ordered, cx);
                            })),
                    )
                    .child(
                        Button::new("network-strategy-random")
                            .label("Random each request")
                            .selected(self.network_editor_rpc_strategy == RpcStrategy::Random)
                            .disabled(busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_network_editor_strategy(RpcStrategy::Random, cx);
                            })),
                    ),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(match self.network_editor_rpc_strategy {
                        RpcStrategy::Ordered => {
                            "Endpoints are tried from top to bottom; failures continue to the next URL."
                        }
                        RpcStrategy::Random => {
                            "Endpoints are shuffled for each request; failures continue through that shuffled list."
                        }
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(field(
                        "Maximum gas limit (optional)",
                        max_gas_limit,
                        self.network_editor_errors.max_gas_limit.clone(),
                        false,
                    ))
                    .child(field(
                        "Maximum fee per gas, wei (optional)",
                        max_fee_per_gas,
                        self.network_editor_errors.max_fee_per_gas.clone(),
                        false,
                    )),
            )
            .child(div().font_semibold().child("Native currency (optional)"))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(field("Name", native_name, None, false))
                    .child(field("Symbol", native_symbol, None, false))
                    .child(field("Decimals", native_decimals, None, false)),
            )
            .when_some(self.network_editor_errors.native_currency.clone(), |panel, error| {
                panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_3()
                    .child(field(
                        "Block explorer URL (optional)",
                        explorer,
                        self.network_editor_errors.block_explorer_url.clone(),
                        false,
                    ))
                    .child(field(
                        "Documentation URL (optional)",
                        documentation,
                        self.network_editor_errors.documentation_url.clone(),
                        false,
                    )),
            )
            .when_some(self.network_editor_errors.form.clone(), |panel, error| {
                panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        Button::new("save-guided-network")
                            .label(if busy {
                                "Verifying & authenticating…"
                            } else {
                                "Verify, authenticate & save"
                            })
                            .primary()
                            .disabled(busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.save_network_editor(cx);
                            })),
                    )
                    .child(
                        Button::new("cancel-guided-network")
                            .label("Cancel")
                            .disabled(busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.close_network_editor(cx);
                            })),
                    )
                    .child(
                        Button::new("toggle-advanced-network-json")
                            .label(if self.network_editor_advanced {
                                "Hide advanced JSON"
                            } else {
                                "Advanced JSON"
                            })
                            .disabled(busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.toggle_network_advanced_editor(cx);
                            })),
                    ),
            );
        if self.network_editor_advanced
            && let Some(input) = self.network_json_input.as_ref()
        {
            panel = panel.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(if editing {
                                "Advanced mode replaces the exact network row you opened with this complete object. If that row changed elsewhere, saving stops and asks you to review it again."
                            } else {
                                "Advanced mode creates this complete object. It will not overwrite an existing chain or conflicting identifier."
                            }),
                    )
                    .child(Input::new(input).h(px(320.0)).disabled(busy))
                    .when_some(self.network_json_error.clone(), |panel, error| {
                        panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    })
                    .child(
                        Button::new("install-network-json")
                            .label(if busy {
                                "Verifying & authenticating…"
                            } else {
                                "Verify, authenticate & install JSON"
                            })
                            .disabled(busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.install_network_from_editor(cx);
                            })),
                    ),
            );
        }
        div().child(
            div()
                .id("network-editor-anchor")
                .anchor_scroll(Some(self.network_editor_anchor.clone()))
                .child(panel),
        )
    }

    #[allow(dead_code)]
    fn render_network_registry(
        &self,
        configured: &[NetworkConfig],
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let mut registry = div().flex().flex_col().gap_4();
        if let Some(search) = self.network_preset_search_input.as_ref() {
            let query = search.read(cx).value().to_string();
            let matches =
                network_presets_for_display(self.network_presets.as_ref(), configured, &query, 10);
            let mut rows = div().flex().flex_col().gap_2();
            if matches.is_empty() {
                rows = rows.child(
                    div()
                        .py_3()
                        .text_color(cx.theme().muted_foreground)
                        .child("No built-in network preset matches this search."),
                );
            }
            for profile in matches {
                let chain_id = profile.config.chain_id;
                let configured_network = configured
                    .iter()
                    .find(|network| network.chain_id == chain_id);
                let exact = configured_network == Some(&profile.config);
                let installing = self.network_preset_busy == Some(chain_id);
                let any_action_busy = self.network_preset_busy.is_some() || self.network_reset_busy;
                let title = profile
                    .config
                    .display_name
                    .as_deref()
                    .unwrap_or(&profile.config.name)
                    .to_owned();
                let mut rpc_urls = div().flex().flex_col().gap_1();
                for (index, url) in profile.config.rpc_urls.iter().enumerate() {
                    rpc_urls = rpc_urls.child(
                        div()
                            .id(SharedString::from(format!(
                                "network-preset-{chain_id}-rpc-{index}"
                            )))
                            .max_w_full()
                            .overflow_x_scroll()
                            .font_family(MONO_FONT_FAMILY)
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(url.to_string()),
                    );
                }
                rows = rows.child(
                    div()
                        .p_3()
                        .rounded_lg()
                        .border_1()
                        .border_color(cx.theme().border)
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(
                            div()
                                .w_full()
                                .flex()
                                .flex_wrap()
                                .items_start()
                                .justify_between()
                                .gap_3()
                                .child(
                                    div()
                                        .min_w_0()
                                        .flex_1()
                                        .flex_basis(px(220.0))
                                        .child(div().font_semibold().child(title))
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(format!(
                                                    "{} · chain {}{}",
                                                    profile.config.name,
                                                    chain_id,
                                                    if profile.is_testnet {
                                                        " · testnet"
                                                    } else {
                                                        ""
                                                    }
                                                )),
                                        ),
                                )
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "install-network-preset-{chain_id}"
                                    )))
                                    .label(if installing {
                                        "Authenticating…"
                                    } else if exact {
                                        "Current preset"
                                    } else if configured_network.is_some() {
                                        "Restore preset"
                                    } else {
                                        "Install preset"
                                    })
                                    .primary()
                                    .disabled(any_action_busy || exact)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.install_network_preset(chain_id, cx);
                                    })),
                                ),
                        )
                        .child(
                            div()
                                .text_sm()
                                .text_color(if profile.simulate_endpoints == 0 {
                                    cx.theme().warning
                                } else {
                                    cx.theme().muted_foreground
                                })
                                .child(if profile.simulate_endpoints == 0 {
                                    "No bundled endpoint currently supports the simulation method required for signing. Install only for read access, then configure a compatible RPC."
                                        .to_owned()
                                } else {
                                    format!(
                                        "{} measured simulation endpoint(s) · {} fork-capable endpoint(s)",
                                        profile.simulate_endpoints, profile.fork_endpoints
                                    )
                                }),
                        )
                        .child(rpc_urls),
                );
            }
            registry = registry.child(
                GroupBox::new()
                    .id("network-preset-registry")
                    .outline()
                    .title("Built-in network presets")
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("Search the bundled registry instead of finding RPC URLs yourself. The wallet verifies the chain ID before asking you to authenticate the change. RPC URLs are shown in full because they supply security-sensitive simulation results."),
                    )
                    .child(Input::new(search).cleanable(true))
                    .when_some(self.network_preset_error.clone(), |panel, error| {
                        panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    })
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("Showing up to 10 matches."),
                    )
                    .child(rows),
            );
        }

        let defaults = ekubo_wallet_core::config::default_networks();
        let pending = self.pending_network_reset.as_deref();
        let discarded = pending
            .map(|reviewed| networks_discarded_by_default_reset(reviewed, &defaults))
            .unwrap_or_default();
        let reset_panel = GroupBox::new()
            .id("network-default-reset")
            .outline()
            .title("Reset network configuration")
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(format!(
                        "Replace every configured network with fresh copies of the {} built-in defaults. Accounts, policies, tokens, and activity are untouched.",
                        defaults.len()
                    )),
            )
            .when_some(self.network_reset_error.clone(), |panel, error| {
                panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
            })
            .when(pending.is_none(), |panel| {
                panel.child(
                    Button::new("prepare-network-reset")
                        .label("Review reset")
                        .danger()
                        .disabled(self.network_preset_busy.is_some() || self.network_reset_busy)
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.begin_network_reset(cx);
                        })),
                )
            })
            .when_some(pending, |panel, _| {
                panel
                    .child(
                        div()
                            .p_3()
                            .rounded_lg()
                            .border_1()
                            .border_color(cx.theme().danger)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(div().font_semibold().child("Confirm complete network reset"))
                            .child(if discarded.is_empty() {
                                "The configured rows already match the shipped defaults. Resetting will still restore their shipped enabled/disabled state and exact RPC lists."
                                    .to_owned()
                            } else {
                                format!(
                                    "Custom or modified configuration will be discarded for: {}.",
                                    discarded.join(", ")
                                )
                            })
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap_2()
                                    .child(
                                        Button::new("confirm-network-reset")
                                            .label(if self.network_reset_busy {
                                                "Authenticating…"
                                            } else {
                                                "Authenticate & reset"
                                            })
                                            .danger()
                                            .disabled(self.network_reset_busy)
                                            .on_click(cx.listener(|view, _, _, cx| {
                                                view.confirm_network_reset(cx);
                                            })),
                                    )
                                    .child(
                                        Button::new("cancel-network-reset")
                                            .label("Cancel")
                                            .disabled(self.network_reset_busy)
                                            .on_click(cx.listener(|view, _, _, cx| {
                                                view.cancel_network_reset(cx);
                                            })),
                                    ),
                            ),
                    )
            });
        registry.child(reset_panel)
    }

    fn render_networks(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div().flex().flex_col().gap_4();
        match self
            .cached_reviews()
            .map(|reviews| reviews.network_proposals.as_slice())
        {
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
                            .rounded_lg()
                            .border_1()
                            .border_color(cx.theme().border)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                h_flex()
                                    .w_full()
                                    .justify_between()
                                    .gap_3()
                                    .child(div().font_semibold().child(format!(
                                        "{} · chain {}",
                                        proposal.name, proposal.chain_id
                                    )))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .gap_2()
                                            .child(
                                                Button::new(SharedString::from(format!(
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
                                                Button::new(SharedString::from(format!(
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
                                    .child(exact),
                            ),
                    );
                }
                content = content.child(
                    GroupBox::new()
                        .id("network-proposals")
                        .outline()
                        .title("Agent proposals")
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child("The wallet contacts the proposed RPC and verifies its chain ID before authentication or installation."),
                        )
                        .when_some(self.network_proposal_error.clone(), |group, error| {
                            group.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().danger)
                                    .child(error),
                            )
                        })
                        .child(rows),
                );
            }
            Ok(_) => {}
            Err(error) => {
                content = content.child(Alert::error(
                    "network-proposals-error",
                    format!("Network proposals unavailable: {error:#}"),
                ));
            }
        }
        content = content.child(self.render_network_editor(cx));
        match self.cached_networks() {
            Ok(networks) => {
                content.children(networks_for_display(networks).into_iter().map(|network| {
                    let name = network.name.clone();
                    let edit = network.clone();
                    let details_name = name.clone();
                    let toggle_network = network.clone();
                    let remove_network = network.clone();
                    let confirm_remove_network = network.clone();
                    let disabled = network.disabled;
                    let expanded = self.expanded_networks.contains(&name);
                    let busy = self.network_action_busy.contains(&name);
                    let restore = self
                        .network_presets
                        .iter()
                        .find(|profile| profile.config.chain_id == network.chain_id)
                        .filter(|profile| profile.config != *network)
                        .map(|_| network.clone());
                    let confirming_removal = self.pending_network_removal.as_ref() == Some(network);
                    let action_error = self.network_action_errors.get(&name).cloned();
                    let exact = serde_json::to_string_pretty(&network)
                        .unwrap_or_else(|error| format!("Could not serialize network: {error:#}"));
                    div()
                        .p_4()
                        .rounded_lg()
                        .border_1()
                        .border_color(cx.theme().border)
                        .flex()
                        .flex_col()
                        .gap_3()
                        .child(
                            h_flex()
                                .flex_wrap()
                                .items_start()
                                .w_full()
                                .justify_between()
                                .gap_3()
                                .child(
                                    div()
                                        .min_w_0()
                                        .flex_1()
                                        .flex()
                                        .flex_col()
                                        .gap_2()
                                        .child(
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
                                                        .child(
                                                            network
                                                                .display_name
                                                                .clone()
                                                                .unwrap_or_else(|| name.clone()),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .text_sm()
                                                        .text_color(cx.theme().muted_foreground)
                                                        .child(format!(
                                                            "{} · chain {}",
                                                            name, network.chain_id,
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
                                                            cx.theme().success
                                                        })
                                                        .text_xs()
                                                        .text_color(if disabled {
                                                            cx.theme().muted_foreground
                                                        } else {
                                                            cx.theme().success
                                                        })
                                                        .child(if disabled {
                                                            "Disabled"
                                                        } else {
                                                            "Enabled"
                                                        }),
                                                ),
                                        )
                                        .child(
                                            h_flex()
                                                .flex_wrap()
                                                .gap_2()
                                                .child(
                                                    Button::new(SharedString::from(format!(
                                                        "inspect-network-{name}"
                                                    )))
                                                    .label(if expanded {
                                                        "Hide configuration"
                                                    } else {
                                                        "Show configuration"
                                                    })
                                                    .on_click(cx.listener(
                                                        move |view, _, _, cx| {
                                                            view.toggle_network_details(
                                                                &details_name,
                                                                cx,
                                                            );
                                                        },
                                                    )),
                                                )
                                                .child(
                                                    Button::new(SharedString::from(format!(
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
                                                    .on_click(cx.listener(
                                                        move |view, _, _, cx| {
                                                            view.set_network_disabled(
                                                                toggle_network.clone(),
                                                                !disabled,
                                                                cx,
                                                            );
                                                        },
                                                    )),
                                                )
                                                .when_some(restore, |actions, reviewed| {
                                                    actions.child(
                                                        Button::new(SharedString::from(format!(
                                                            "restore-network-{name}"
                                                        )))
                                                        .label("Restore defaults")
                                                        .tooltip("Restore this network's bundled configuration")
                                                        .disabled(busy)
                                                        .on_click(cx.listener(
                                                            move |view, _, _, cx| {
                                                                view.restore_network_preset(
                                                                    reviewed.clone(),
                                                                    cx,
                                                                );
                                                            },
                                                        )),
                                                    )
                                                }),
                                        ),
                                )
                                .child(
                                    h_flex()
                                        .flex_none()
                                        .gap_2()
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "edit-network-{name}"
                                            )))
                                            .icon(IconName::Settings2)
                                            .ghost()
                                            .tooltip("Edit network")
                                            .accessibility_id("Edit network")
                                            .disabled(busy)
                                            .on_click(cx.listener(move |view, _, window, cx| {
                                                view.edit_network(&edit, window, cx);
                                            })),
                                        )
                                        .when(network_can_be_removed(network), |buttons| {
                                            buttons.child(
                                                Button::new(SharedString::from(format!(
                                                    "delete-network-{name}"
                                                )))
                                                .icon(IconName::Delete)
                                                .ghost()
                                                .tooltip("Delete disabled network")
                                                .accessibility_id("Delete disabled network")
                                                .danger()
                                                .disabled(busy || confirming_removal)
                                                .on_click(cx.listener(move |view, _, _, cx| {
                                                    view.begin_network_removal(
                                                        remove_network.clone(),
                                                        cx,
                                                    );
                                                })),
                                            )
                                        }),
                                ),
                        )
                        .when(expanded, |card| {
                            card.child(
                                div()
                                    .max_w_full()
                                    .overflow_x_hidden()
                                    .p_3()
                                    .rounded(cx.theme().radius)
                                    .bg(cx.theme().secondary)
                                    .font_family(MONO_FONT_FAMILY)
                                    .text_sm()
                                    .child(exact),
                            )
                        })
                        .when(confirming_removal, |card| {
                            card.child(
                                div()
                                    .p_3()
                                    .rounded(cx.theme().radius)
                                    .border_1()
                                    .border_color(cx.theme().danger)
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(
                                        div()
                                            .text_color(cx.theme().danger)
                                            .child(format!(
                                                "Delete {name}? Its trusted RPC configuration will be removed from the encrypted wallet database."
                                            )),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .flex_wrap()
                                            .gap_2()
                                            .child(
                                                Button::new(SharedString::from(format!(
                                                    "confirm-delete-network-{name}"
                                                )))
                                                .label(if busy {
                                                    "Authenticating…"
                                                } else {
                                                    "Authenticate & delete"
                                                })
                                                .danger()
                                                .disabled(busy)
                                                .on_click(cx.listener(
                                                    move |view, _, _, cx| {
                                                        view.confirm_network_removal(
                                                            confirm_remove_network.clone(),
                                                            cx,
                                                        );
                                                    },
                                                )),
                                            )
                                            .child(
                                                Button::new(SharedString::from(format!(
                                                    "cancel-delete-network-{name}"
                                                )))
                                                .label("Cancel")
                                                .disabled(busy)
                                                .on_click(cx.listener(|view, _, _, cx| {
                                                    view.cancel_network_removal(cx);
                                                })),
                                            ),
                                    ),
                            )
                        })
                        .when_some(action_error, |card, error| {
                            card.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().danger)
                                    .child(error),
                            )
                        })
                }))
            }
            Err(error) => content.child(Alert::error(
                "network-list-error",
                format!("Networks unavailable: {error:#}"),
            )),
        }
    }

    fn render_portfolio(&self, cx: &mut Context<Self>) -> gpui::Div {
        // Rendering and scrolling must never open SQLCipher or consult the OS
        // credential store. The background snapshot already owns the exact
        // configured rows needed by this picker.
        let enabled_networks = self
            .cached_networks()
            .unwrap_or_default()
            .iter()
            .filter(|network| !network.disabled)
            .collect::<Vec<_>>();
        let mut network_picker = div().flex().flex_wrap().gap_2();
        for network in &enabled_networks {
            let chain_id = network.chain_id;
            network_picker = network_picker.child(
                Button::new(SharedString::from(format!("portfolio-network-{chain_id}")))
                    .label(
                        network
                            .display_name
                            .as_deref()
                            .unwrap_or(&network.name)
                            .to_owned(),
                    )
                    .when(
                        self.portfolio_chain_id == Some(chain_id),
                        ButtonVariants::primary,
                    )
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.select_portfolio_network(chain_id, cx);
                    })),
            );
        }
        let mut content = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                GroupBox::new()
                    .id("portfolio-network-picker")
                    .outline()
                    .title("Network")
                    .child(network_picker),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("Only non-zero balances on the selected network are shown"),
                    )
                    .child(
                        Button::new("refresh-portfolio")
                            .label(if matches!(self.portfolio, PortfolioState::Loading) {
                                "Refreshing…"
                            } else {
                                "Refresh"
                            })
                            .disabled(
                                self.portfolio_chain_id.is_none()
                                    || matches!(self.portfolio, PortfolioState::Loading),
                            )
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.refresh_portfolio(cx);
                            })),
                    ),
            );
        if self.portfolio_chain_id.is_none() {
            return content.child(
                div()
                    .p_5()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .text_color(cx.theme().muted_foreground)
                    .child("Select an enabled network to load balances."),
            );
        }
        match &self.portfolio {
            PortfolioState::Idle | PortfolioState::Loading => content.child(
                div()
                    .p_5()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(
                        h_flex()
                            .gap_2()
                            .child(Spinner::new())
                            .child("Loading account balances…"),
                    ),
            ),
            PortfolioState::Failed(error) => content.child(
                Alert::error("portfolio-error", error.clone()).title("Portfolio unavailable"),
            ),
            PortfolioState::Ready(snapshot) if snapshot.accounts.is_empty() => content.child(
                div()
                    .p_5()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(div().font_semibold().child("Create your first account"))
                    .child("A wallet account is required before there are balances to show.")
                    .child(
                        Button::new("portfolio-create-account")
                            .label("Go to Accounts")
                            .primary()
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_route(Route::Accounts);
                                cx.notify();
                            })),
                    ),
            ),
            PortfolioState::Ready(snapshot) => {
                let mut shown_accounts = 0_usize;
                for account in &snapshot.accounts {
                    let mut networks = div().flex().flex_wrap().gap_3();
                    let mut shown = false;
                    for item in &account.networks {
                        if item.result.as_ref().is_ok_and(|portfolio| {
                            portfolio.native_balance == "0" && portfolio.tokens.is_empty()
                        }) {
                            continue;
                        }
                        shown = true;
                        let network_name = item
                            .network
                            .display_name
                            .as_deref()
                            .unwrap_or(&item.network.name);
                        let mut card = div()
                            .min_w(px(230.0))
                            .flex_1()
                            .p_3()
                            .rounded_lg()
                            .border_1()
                            .border_color(cx.theme().border)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(div().font_semibold().child(network_name.to_owned()))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(format!("Chain {}", item.network.chain_id)),
                            );
                        card = match &item.result {
                            Ok(portfolio) => {
                                let native = item.network.native_currency.as_ref();
                                let native_balance = format_asset_balance(
                                    &portfolio.native_balance,
                                    native.map(|currency| currency.decimals),
                                    native.map(|currency| currency.symbol.as_str()),
                                    "wei",
                                );
                                let has_native = portfolio.native_balance != "0";
                                let asset_count = portfolio.tokens.len() + usize::from(has_native);
                                let mut asset_index = 0_usize;
                                let mut balances = div().flex().flex_col().gap_2();
                                if has_native {
                                    let row_index = asset_index;
                                    asset_index += 1;
                                    balances = balances.child(
                                        div()
                                            .py_2()
                                            .when(row_index + 1 < asset_count, |row| {
                                                row.border_b_1().border_color(cx.theme().border)
                                            })
                                            .flex()
                                            .justify_between()
                                            .gap_3()
                                            .child("Native")
                                            .child(
                                                div()
                                                    .font_family(MONO_FONT_FAMILY)
                                                    .text_sm()
                                                    .child(native_balance),
                                            ),
                                    );
                                }
                                for token in &portfolio.tokens {
                                    let row_index = asset_index;
                                    asset_index += 1;
                                    let label = token
                                        .symbol
                                        .as_deref()
                                        .unwrap_or(token.address.as_str())
                                        .to_owned();
                                    let balance = format_asset_balance(
                                        &token.balance,
                                        token.decimals,
                                        token.symbol.as_deref(),
                                        "base units",
                                    );
                                    balances = balances.child(
                                        div()
                                            .py_2()
                                            .when(row_index + 1 < asset_count, |row| {
                                                row.border_b_1().border_color(cx.theme().border)
                                            })
                                            .flex()
                                            .justify_between()
                                            .gap_3()
                                            .child(
                                                div().min_w_0().child(label).child(
                                                    div()
                                                        .text_xs()
                                                        .font_family(MONO_FONT_FAMILY)
                                                        .text_color(cx.theme().muted_foreground)
                                                        .child(token.address.clone()),
                                                ),
                                            )
                                            .child(
                                                div()
                                                    .font_family(MONO_FONT_FAMILY)
                                                    .text_sm()
                                                    .child(balance),
                                            ),
                                    );
                                }
                                card.child(balances)
                            }
                            Err(error) => card.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().danger)
                                    .child(error.clone()),
                            ),
                        };
                        networks = networks.child(card);
                    }
                    if shown {
                        shown_accounts += 1;
                        content = content.child(
                            div()
                                .p_4()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().border)
                                .flex()
                                .flex_col()
                                .gap_3()
                                .child(
                                    div()
                                        .child(
                                            div().font_semibold().child(account.wallet.id.clone()),
                                        )
                                        .child(
                                            div()
                                                .font_family(MONO_FONT_FAMILY)
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(account.wallet.address.to_checksum(None)),
                                        ),
                                )
                                .child(networks),
                        );
                    }
                }
                if shown_accounts == 0 {
                    content = content.child(
                        div()
                            .p_5()
                            .rounded_lg()
                            .border_1()
                            .border_color(cx.theme().border)
                            .text_color(cx.theme().muted_foreground)
                            .child("No non-zero balances were found on this network."),
                    );
                }
                content
            }
        }
    }

    fn render_tokens(&self, cx: &mut Context<Self>) -> gpui::Div {
        let Some(list) = self.token_list.as_ref() else {
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
            .min_h(px(320.0))
            .gap_3()
            .when_some(self.token_proposal_error.clone(), |content, error| {
                content.child(div().text_sm().text_color(cx.theme().danger).child(error))
            });
        if self.token_editor_open {
            if let (Some(chain_id), Some(address), Some(symbol), Some(name), Some(decimals)) = (
                self.token_chain_id_input.as_ref(),
                self.token_address_input.as_ref(),
                self.token_symbol_input.as_ref(),
                self.token_name_input.as_ref(),
                self.token_decimals_input.as_ref(),
            ) {
                let editing = self.token_editor_original.is_some();
                let busy = self.token_editor_busy;
                content = content.child(
                    div()
                        .id("token-editor-anchor")
                        .anchor_scroll(Some(self.token_editor_anchor.clone()))
                        .child(
                            GroupBox::new()
                                .id("token-editor")
                                .outline()
                                .title(if editing { "Edit token" } else { "Add token" })
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(if editing {
                                            "Correct the owner-authored name, symbol, or decimals. Chain ID and address identify the row and cannot be changed."
                                        } else {
                                            "Add display metadata for an address on a configured network. Saving requires operating-system authentication."
                                        }),
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
                                                    Input::new(chain_id)
                                                        .disabled(editing || busy),
                                                )
                                                .when_some(
                                                    self.token_editor_errors.chain_id.clone(),
                                                    |field, error| {
                                                        field.child(
                                                            div()
                                                                .text_sm()
                                                                .text_color(cx.theme().danger)
                                                                .child(error),
                                                        )
                                                    },
                                                ),
                                        )
                                        .child(
                                            div()
                                                .flex()
                                                .flex_col()
                                                .gap_1()
                                                .flex_1()
                                                .min_w(px(150.0))
                                                .child(div().text_sm().child("Symbol"))
                                                .child(Input::new(symbol).disabled(busy))
                                                .when_some(
                                                    self.token_editor_errors.symbol.clone(),
                                                    |field, error| {
                                                        field.child(
                                                            div()
                                                                .text_sm()
                                                                .text_color(cx.theme().danger)
                                                                .child(error),
                                                        )
                                                    },
                                                ),
                                        )
                                        .child(
                                            div()
                                                .flex()
                                                .flex_col()
                                                .gap_1()
                                                .flex_1()
                                                .min_w(px(150.0))
                                                .child(div().text_sm().child("Decimals"))
                                                .child(Input::new(decimals).disabled(busy))
                                                .when_some(
                                                    self.token_editor_errors.decimals.clone(),
                                                    |field, error| {
                                                        field.child(
                                                            div()
                                                                .text_sm()
                                                                .text_color(cx.theme().danger)
                                                                .child(error),
                                                        )
                                                    },
                                                ),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(div().text_sm().child("Token address"))
                                        .child(Input::new(address).disabled(editing || busy))
                                        .when_some(
                                            self.token_editor_errors.address.clone(),
                                            |field, error| {
                                                field.child(
                                                    div()
                                                        .text_sm()
                                                        .text_color(cx.theme().danger)
                                                        .child(error),
                                                )
                                            },
                                        ),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(div().text_sm().child("Full name (optional)"))
                                        .child(Input::new(name).disabled(busy))
                                        .when_some(
                                            self.token_editor_errors.name.clone(),
                                            |field, error| {
                                                field.child(
                                                    div()
                                                        .text_sm()
                                                        .text_color(cx.theme().danger)
                                                        .child(error),
                                                )
                                            },
                                        ),
                                )
                                .when_some(
                                    self.token_editor_errors.form.clone(),
                                    |panel, error| {
                                        panel.child(
                                            div()
                                                .text_sm()
                                                .text_color(cx.theme().danger)
                                                .child(error),
                                        )
                                    },
                                )
                                .child(
                                    h_flex()
                                        .gap_2()
                                        .child(
                                            Button::new("save-token-editor")
                                                .label(if busy {
                                                    "Authenticating…"
                                                } else if editing {
                                                    "Authenticate & save"
                                                } else {
                                                    "Authenticate & add"
                                                })
                                                .primary()
                                                .disabled(busy)
                                                .on_click(cx.listener(|view, _, _, cx| {
                                                    view.save_token_editor(cx);
                                                })),
                                        )
                                        .child(
                                            Button::new("close-token-editor")
                                                .label("Cancel")
                                                .disabled(busy)
                                                .on_click(cx.listener(|view, _, _, cx| {
                                                    view.close_token_editor(cx);
                                                })),
                                        ),
                                ),
                        ),
                );
            }
        } else {
            content = content.child(
                Button::new("open-token-editor")
                    .label("Add token")
                    .primary()
                    .on_click(cx.listener(|view, _, window, cx| {
                        view.open_new_token_editor(window, cx);
                    })),
            );
        }
        if let Some(input) = self.token_list_url_input.as_ref() {
            content = content.child(
                GroupBox::new()
                    .id("owner-token-list-import")
                    .outline()
                    .title("Import published token list")
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("Fetch a public HTTPS token-list JSON for all enabled networks. Nothing is trusted until you inspect and accept the exact resulting list below."),
                    )
                    .child(
                        h_flex()
                            .w_full()
                            .gap_2()
                            .child(div().flex_1().min_w_0().child(Input::new(input)))
                            .child(
                                Button::new("import-owner-token-list")
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
                    .when_some(self.token_import_error.clone(), |group, error| {
                        group.child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().danger)
                                .child(error),
                        )
                    })
                    .when_some(self.token_import_status.clone(), |group, status| {
                        group.child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(status),
                        )
                    }),
            );
        }
        match self
            .cached_reviews()
            .map(|reviews| reviews.token_proposals.as_slice())
        {
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
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(
                                div().flex_1().min_w_0().child(source).child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(format!("{count} token name(s) awaiting review")),
                                ),
                            )
                            .child(
                                Button::new(("review-token-proposal-group", index))
                                    .label(if selected { "Reviewing" } else { "Review" })
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
                        .outline()
                        .title("Agent proposals")
                        .child(groups),
                );
            }
            Ok(_) => {}
            Err(error) => {
                content = content.child(Alert::error(
                    "token-proposals-error",
                    format!("Token proposals unavailable: {error:#}"),
                ));
            }
        }

        if let Some(source) = selected_source {
            content = content.child(
                GroupBox::new()
                    .id("token-proposal-review")
                    .outline()
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
                                Button::new("accept-token-proposal-group")
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
                                Button::new("reject-token-proposal-group")
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

        content
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(format!("Showing {visible} of {total} token(s)")),
            )
            .child(
                List::new(list)
                    .search_placeholder("Search token name, symbol, chain ID, or address")
                    .flex_1()
                    .min_h(px(260.0))
                    .w_full()
                    .border_1()
                    .border_color(cx.theme().border)
                    .rounded(cx.theme().radius),
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
                    .child("Ekubo Wallet does not download or install updates. Open the latest release in your browser and install it through your operating system."),
            )
            .child(
                Button::new("open-latest-release")
                    .label("View latest release")
                    .primary()
                    .on_click(|_, _, cx| cx.open_url(LATEST_RELEASE_URL)),
            );
        panel = match &self.release_state {
            ReleaseDisplayState::Idle => panel.child(
                Button::new("check-latest-release")
                    .label("Check latest version")
                    .on_click(cx.listener(|view, _, _, cx| view.check_latest_release(cx))),
            ),
            ReleaseDisplayState::Checking => panel.child(
                h_flex()
                    .gap_2()
                    .child(Spinner::new())
                    .child("Checking the latest published version…"),
            ),
            ReleaseDisplayState::Ready(check) => panel
                .child(
                    div()
                        .font_semibold()
                        .child(check.latest_version.as_ref().map_or_else(
                            || "Latest version unavailable".to_owned(),
                            |version| format!("Latest published version: {version}"),
                        )),
                )
                .when(check.update_available, |panel| {
                    panel.child("A newer release is available.")
                })
                .child(
                    Button::new("recheck-latest-release")
                        .label("Check again")
                        .on_click(cx.listener(|view, _, _, cx| view.check_latest_release(cx))),
                ),
            ReleaseDisplayState::Failed(error) => panel
                .child(div().text_color(cx.theme().danger).child(error.clone()))
                .child(
                    Button::new("retry-latest-release")
                        .label("Try again")
                        .on_click(cx.listener(|view, _, _, cx| view.check_latest_release(cx))),
                ),
        };
        settings_section(
            "Updates",
            GroupBox::new()
                .id("software-updates")
                .outline()
                .child(panel),
        )
    }

    fn route_panel(&self, cx: &mut Context<Self>) -> gpui::Div {
        match self.route {
            Route::Overview => self.render_portfolio(cx),
            Route::Activity => self.render_activity(cx),
            Route::Accounts => self.render_accounts(cx),
            Route::Policies => self.render_policies(cx),
            Route::Networks => self.render_networks(cx),
            Route::Tokens => self.render_tokens(cx),
            Route::WalletConnect => self.render_walletconnect(cx),
            Route::Settings => self.render_settings(cx),
            Route::Reviews => self.render_reviews(cx),
        }
    }

    fn render_review_fact(
        fact: &ApprovalFact,
        section_kind: ApprovalSectionKind,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        if section_kind == ApprovalSectionKind::Effects {
            if fact.label.is_empty() {
                return div()
                    .pl_3()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(fact.value.clone());
            }
            let amount_color = if fact.value.trim_start().starts_with('-') {
                cx.theme().danger
            } else if fact.value.trim_start().starts_with('+') {
                cx.theme().success
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
                                div()
                                    .min_w_0()
                                    .max_w_full()
                                    .truncate()
                                    .font_family(MONO_FONT_FAMILY)
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(exact),
                            )
                        }),
                )
                .child(
                    div()
                        .min_w_0()
                        .flex_1()
                        .flex_basis(px(240.0))
                        .text_lg()
                        .font_semibold()
                        .text_color(amount_color)
                        .whitespace_normal()
                        .child(fact.value.clone()),
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
                .child(div().text_lg().font_semibold().child(fact.value.clone()));
        }

        let exact_value = matches!(fact.label.as_str(), "Address" | "Sender" | "Target");
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
                div()
                    .min_w_0()
                    .flex_1()
                    .text_sm()
                    .when(exact_value, |value| value.font_family(MONO_FONT_FAMILY))
                    .child(fact.value.clone()),
            )
    }

    fn render_review_section(section: &ApprovalSection, cx: &mut Context<Self>) -> gpui::Div {
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
            .rounded_lg()
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
            .children(
                section
                    .facts
                    .iter()
                    .map(|fact| Self::render_review_fact(fact, section.kind, cx)),
            )
    }

    fn render_review_simulation(
        simulation: &ekubo_wallet_core::simulation::SimulationResult,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let (icon, color, title) = if simulation.simulation.success {
            (
                IconName::CircleCheck,
                cx.theme().success,
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
            .rounded_lg()
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
        let document = active.state.document();
        let exact_data_required = !document.exact_payloads.is_empty();
        let approve_enabled = active.state.approve_enabled() && !active.awaiting_refresh;
        let can_refresh = matches!(
            active.completion,
            Some(ActiveReviewCompletion::Transaction(_))
        );
        let walletconnect_connection = matches!(
            active.completion,
            Some(ActiveReviewCompletion::WalletConnect { .. })
        );
        let mut review_body = div()
            .w_full()
            .max_w(px(920.0))
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .text_2xl()
                    .font_semibold()
                    .child(document.request.title.clone()),
            )
            .child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child(document.request.summary.clone()),
            );

        if let Some(simulation) = &active.simulation {
            review_body = review_body.child(Self::render_review_simulation(simulation, cx));
        }

        for section in review_sections_for_display(document)
            .into_iter()
            .filter(|section| section.kind == ApprovalSectionKind::Effects)
        {
            review_body = review_body.child(Self::render_review_section(section, cx));
        }

        if !document.request.warnings.is_empty() {
            review_body = review_body.child(
                div()
                    .w_full()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        h_flex()
                            .gap_2()
                            .text_color(cx.theme().warning)
                            .child(Icon::new(IconName::TriangleAlert).small())
                            .child(div().font_semibold().child("Important warnings")),
                    )
                    .children(document.request.warnings.iter().enumerate().map(
                        |(index, warning)| {
                            div()
                                .id(SharedString::from(format!(
                                    "review-warning-{generation}-{index}"
                                )))
                                .p_3()
                                .rounded_lg()
                                .border_1()
                                .border_color(cx.theme().warning)
                                .child(warning.clone())
                        },
                    )),
            );
        }

        if let Some(ActiveReviewCompletion::WalletConnect {
            choices,
            selected_account,
            ..
        }) = active.completion.as_ref()
        {
            review_body = review_body
                .child(div().mt_2().font_semibold().child("Account to expose"))
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .children(choices.iter().enumerate().map(|(index, choice)| {
                            Button::new(SharedString::from(format!("wc-account-{index}")))
                                .label(choice.account.id.clone())
                                .when(index == *selected_account, ButtonVariants::primary)
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    view.select_walletconnect_account(index, cx);
                                }))
                        })),
                );
        }

        for section in review_sections_for_display(document)
            .into_iter()
            .filter(|section| section.kind != ApprovalSectionKind::Effects)
        {
            review_body = review_body.child(Self::render_review_section(section, cx));
        }

        if !document.request.facts.is_empty() {
            let context = ApprovalSection {
                kind: ApprovalSectionKind::Details,
                heading: "Request details".to_owned(),
                facts: document.request.facts.clone(),
            };
            review_body = review_body.child(Self::render_review_section(&context, cx));
        }

        if exact_data_required {
            review_body = review_body
                .child(
                    div()
                        .w_full()
                        .p_4()
                        .rounded_lg()
                        .border_1()
                        .border_color(cx.theme().border)
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
                                        .child(
                                            "The complete bytes are always part of this review.",
                                        ),
                                ),
                        ),
                )
                .children(
                    document
                        .exact_payloads
                        .iter()
                        .enumerate()
                        .map(|(index, payload)| {
                            div()
                                .w_full()
                                .min_w_0()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(div().font_semibold().child(if index == 0 {
                                    "Execution plan JSON".to_owned()
                                } else {
                                    format!("Action {index} exact calldata")
                                }))
                                .child(
                                    div()
                                        .id(SharedString::from(format!(
                                            "review-exact-payload-{generation}-{index}"
                                        )))
                                        .w_full()
                                        .min_w_0()
                                        .overflow_x_scroll()
                                        .p_3()
                                        .rounded_lg()
                                        .border_1()
                                        .border_color(cx.theme().border)
                                        .bg(cx.theme().secondary)
                                        .font_family(MONO_FONT_FAMILY)
                                        .text_sm()
                                        .whitespace_normal()
                                        .child(payload.clone()),
                                )
                        }),
                );
        }
        div()
            .absolute()
            .inset_0()
            .min_h_0()
            .on_mouse_down(MouseButton::Left, |_, _, _| {})
            .p_4()
            .rounded_lg()
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
                                    "{} additional review(s) waiting",
                                    self.queued_reviews.len()
                                )),
                        )
                    },
                ),
            ))
            .child(
                div()
                    .id(("review-scroll", generation))
                    .flex_1()
                    .min_h_0()
                    .track_scroll(&active.scroll_handle)
                    .overflow_y_scrollbar()
                    .on_scroll_wheel(cx.listener(|_view, _, window, cx| {
                        cx.defer_in(window, |view, _, cx| {
                            view.update_review_scroll_state(cx);
                        });
                    }))
                    .pr_2()
                    .child(div().w_full().flex().justify_center().child(review_body)),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .justify_between()
                    .items_center()
                    .child(
                        Button::new(("review-refresh", generation))
                            .label("Re-simulate")
                            .loading(active.awaiting_refresh)
                            .disabled(active.awaiting_refresh || !can_refresh)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.send_review_command(generation, GuiReviewCommand::Refresh, cx);
                            })),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .when(!approve_enabled, |buttons| {
                                buttons.child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child("Scroll to the end to enable approval"),
                                )
                            })
                            .child(
                                Button::new(("review-select-reject", generation))
                                    .label(if walletconnect_connection {
                                        "Decline connection"
                                    } else {
                                        "Reject request"
                                    })
                                    .danger()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.decide_review(generation, ReviewDecision::Reject, cx);
                                    })),
                            )
                            .child(
                                Button::new(("review-select-approve", generation))
                                    .label(if walletconnect_connection {
                                        "Authenticate & connect"
                                    } else {
                                        "Authenticate & approve"
                                    })
                                    .primary()
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

    fn render_agent_install_overlay(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(pending) = &self.pending_agent_install else {
            return div().into_any_element();
        };
        div()
            .absolute()
            .inset_0()
            .on_mouse_down(MouseButton::Left, |_, _, _| {})
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .shadow_lg()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .font_semibold()
                    .child(format!("Review {}", pending.display_name)),
            )
            .child("Review the exact configuration change. A timestamped backup is created before installation.")
            .child(
                div()
                    .id("agent-configuration-diff-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .p_3()
                    .border_1()
                    .border_color(cx.theme().border)
                    .font_family(MONO_FONT_FAMILY)
                    .child(pending.preview.managed_diff().to_owned()),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("cancel-agent-install")
                            .label("Cancel")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.cancel_agent_install(cx);
                            })),
                    )
                    .child(
                        Button::new("confirm-agent-install")
                            .label("Apply")
                            .primary()
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.confirm_agent_install(cx);
                            })),
                    ),
            )
            .focus_trap("agent-install-focus", &self.modal_focus)
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
                            .child(row.text.clone());
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
            .on_mouse_down(MouseButton::Left, |_, _, _| {})
            .p_4()
            .rounded_lg()
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
                    .id("legal-document-scroll")
                    .flex_1()
                    .min_h_0()
                    .p_3()
                    .border_1()
                    .border_color(cx.theme().border)
                    .vertical_scrollbar(&review.scroll_handle)
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
            .when_some(review.error.clone(), |panel, error| {
                panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
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
                            Button::new("accept-legal")
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
                    Button::new("close-legal-review")
                        .label("Close")
                        .large()
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
        div()
            .absolute()
            .inset_4()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().background)
            .shadow_lg()
            .flex()
            .flex_col()
            .gap_3()
            .child(div().text_xl().font_semibold().child("Export private key"))
            .child(format!("Account: {}", export.wallet_id))
            .child("Anyone with this key has full control of the account. Never paste it into a website, chat, issue, log, or agent prompt.")
            .when_some(visible.as_ref(), |panel, value| {
                panel.child(
                    div()
                        .p_3()
                        .border_1()
                        .border_color(cx.theme().border)
                        .font_family(MONO_FONT_FAMILY)
                        .child(value.to_string()),
                )
            })
            .when(export.lease.is_some() && visible.is_none(), |panel| {
                panel.child("The 30-second reveal expired and the key is concealed.")
            })
            .when(export.copied, |panel| {
                panel.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child("Copied explicitly. After 30 seconds, the wallet clears the clipboard only if it still contains this exact key."),
                )
            })
            .when_some(export.error.clone(), |panel, error| {
                panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
            })
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(
                        Button::new("close-account-export")
                            .label("Close")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.account_export = None;
                                cx.notify();
                            })),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .when(export.lease.is_none(), |buttons| {
                                buttons.child(
                                    Button::new("authenticate-account-export")
                                        .label(if export.authenticating {
                                            "Authenticating…"
                                        } else {
                                            "Authenticate & reveal"
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
                                    Button::new("copy-account-export")
                                        .label(if export.copied { "Copied" } else { "Copy" })
                                        .disabled(export.copied)
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            view.copy_account_export(cx);
                                        })),
                                )
                            }),
                    ),
            )
            .focus_trap("account-security-focus", &self.modal_focus)
            .into_any_element()
    }

    fn render_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let route_panel = if self.desktop_snapshot.is_none() {
            div()
                .flex()
                .items_center()
                .gap_2()
                .text_color(cx.theme().muted_foreground)
                .child(Spinner::new())
                .child("Loading wallet data…")
        } else {
            self.route_panel(cx)
        };
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
                    .items_center()
                    .gap_2()
                    .child(div().text_2xl().font_semibold().child(self.route.label()))
                    .when(self.desktop_snapshot_loading, |header| {
                        header.child(Spinner::new().small())
                    }),
            )
            .child(
                div()
                    .id("route-content-scroll")
                    .flex_1()
                    .min_h_0()
                    .track_scroll(&self.route_scroll_handle)
                    .overflow_y_scrollbar()
                    .px_5()
                    .pb_5()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .when_some(self.desktop_snapshot_error.clone(), |content, error| {
                        content.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    })
                    .when_some(
                        self.route_errors.get(&self.route).cloned(),
                        |content, error| {
                            content
                                .child(div().text_sm().text_color(cx.theme().danger).child(error))
                        },
                    )
                    .child(route_panel),
            )
    }

    fn render_palette(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .absolute()
            .top(px(54.0))
            .left(px(58.0))
            .w(px(420.0))
            .max_h(px(460.0))
            .p_3()
            .rounded_lg()
            .shadow_lg()
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().popover)
            .child(div().font_semibold().mb_2().child("Go to…"))
            .when_some(self.command_palette_list.as_ref(), |palette, list| {
                palette.child(
                    List::new(list)
                        .h(px(390.0))
                        .w_full()
                        .border_1()
                        .border_color(cx.theme().border)
                        .rounded(cx.theme().radius),
                )
            })
    }
}

impl Render for WalletWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.attach_window(window, cx);
        if let Some(review) = self.active_review.as_mut() {
            if review.scroll_layout_ready {
                self.update_review_scroll_state(cx);
            } else if !review.scroll_check_scheduled {
                review.scroll_check_scheduled = true;
                cx.on_next_frame(window, move |view, _, cx| {
                    if let Some(review) = view.active_review.as_mut() {
                        review.scroll_layout_ready = true;
                    }
                    view.update_review_scroll_state(cx);
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
        let modal_open = self.active_review.is_some()
            || self.pending_agent_install.is_some()
            || self.legal_review.is_some()
            || self.account_export.is_some();
        if modal_open && !self.modal_focus.contains_focused(window, cx) {
            self.modal_focus.focus(window, cx);
        }
        if self.route == Route::Overview
            && !self.legal_gate
            && self.portfolio_chain_id.is_some()
            && matches!(self.portfolio, PortfolioState::Idle)
        {
            self.refresh_portfolio(cx);
        }
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
            .child(self.render_content(cx))
            .when(self.command_palette, |view| {
                view.child(self.render_palette(cx))
            })
            .when(self.active_review.is_some(), |view| {
                view.child(self.render_review_overlay(cx))
            })
            .when(self.pending_agent_install.is_some(), |view| {
                view.child(self.render_agent_install_overlay(cx))
            })
            .when(self.legal_review.is_some(), |view| {
                view.child(self.render_legal_overlay(cx))
            })
            .when(self.account_export.is_some(), |view| {
                view.child(self.render_account_security_overlay(cx))
            })
    }
}

type WalletWindowSlot = Rc<RefCell<Option<WindowHandle<Root>>>>;

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
}

#[allow(clippy::unreadable_literal)] // Six-digit literals are RGB colors from the interface palette.
const fn interface_interaction_palette(dark: bool) -> InterfaceInteractionPalette {
    InterfaceInteractionPalette {
        button: if dark { 0x1d1d1d } else { 0xf6f6f9 },
        button_hover: if dark { 0x373737 } else { 0xe5e4e4 },
        button_active: if dark { 0x261b34 } else { 0xf3e7fe },
        button_foreground: if dark { 0xffffff } else { 0x101010 },
        // Keep off-purple for accents. Small white labels need the darker
        // Ekubo purple to meet AA contrast in every interaction state.
        primary: 0x661cc4,
        primary_hover: 0x752ccf,
        primary_active: 0x4c1396,
        primary_foreground: 0xffffff,
        danger: 0xc0165b,
        danger_hover: 0xd11868,
        danger_active: 0x981047,
        danger_foreground: 0xffffff,
    }
}

#[allow(clippy::unreadable_literal)] // Six-digit literals match the interface repository's RGB palette.
fn apply_interface_palette(cx: &mut App) {
    let dark = Theme::global(cx).is_dark();
    let color = |hex: u32| -> gpui::Hsla { gpui::rgb(hex).into() };
    let interaction = interface_interaction_palette(dark);
    let (background, surface, hover, border, muted, foreground, muted_foreground) = if dark {
        (
            color(0x101010),
            color(0x1d1d1d),
            color(0x373737),
            color(0x373737),
            color(0x272727),
            color(0xffffff),
            color(0x878787),
        )
    } else {
        (
            color(0xffffff),
            color(0xf6f6f9),
            color(0xe5e4e4),
            color(0xe5e4e4),
            color(0xf6f6f9),
            color(0x101010),
            color(0x666666),
        )
    };
    let accent = color(0x9d5af2);
    let primary = color(interaction.primary);
    let primary_active = color(interaction.primary_active);
    let danger = color(interaction.danger);
    let success = color(0x26e8ad);
    let warning = color(0xdf7b32);
    let theme = Theme::global_mut(cx);
    let colors = &mut theme.colors;
    colors.background = background;
    colors.foreground = foreground;
    colors.border = border;
    colors.accent = hover;
    colors.accent_foreground = foreground;
    colors.accordion = surface;
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
    colors.button_danger = danger;
    colors.button_danger_active = color(interaction.danger_active);
    colors.button_danger_foreground = color(interaction.danger_foreground);
    colors.button_danger_hover = color(interaction.danger_hover);
    colors.button_success = success;
    colors.button_success_active = success.mix_oklab(background, 0.25);
    colors.button_success_foreground = color(0x101010);
    colors.button_success_hover = success.mix_oklab(background, 0.12);
    colors.button_warning = warning;
    colors.button_warning_active = warning.mix_oklab(background, 0.25);
    colors.button_warning_foreground = color(0x101010);
    colors.button_warning_hover = warning.mix_oklab(background, 0.12);
    colors.group_box = surface;
    colors.group_box_foreground = foreground;
    colors.input = border;
    colors.list = surface;
    colors.list_active = color(interaction.button_active);
    colors.list_active_border = accent;
    colors.list_even = surface;
    colors.list_head = muted;
    colors.list_hover = hover;
    colors.muted = muted;
    colors.muted_foreground = muted_foreground;
    colors.popover = surface;
    colors.popover_foreground = foreground;
    colors.primary = primary;
    colors.primary_active = primary_active;
    colors.primary_foreground = color(interaction.primary_foreground);
    colors.primary_hover = color(interaction.primary_hover);
    colors.ring = accent;
    colors.secondary = surface;
    colors.secondary_active = color(interaction.button_active);
    colors.secondary_foreground = foreground;
    colors.secondary_hover = hover;
    colors.sidebar = surface;
    colors.sidebar_accent = color(interaction.button_active);
    colors.sidebar_accent_foreground = foreground;
    colors.sidebar_border = border;
    colors.sidebar_foreground = foreground;
    colors.sidebar_primary = primary;
    colors.sidebar_primary_foreground = color(interaction.primary_foreground);
    colors.danger = danger;
    colors.danger_foreground = color(0xffffff);
    colors.success = success;
    colors.success_foreground = color(0x101010);
    colors.warning = warning;
    colors.warning_foreground = color(0x101010);
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

    wallet_view.update(cx, |view, cx| {
        view.command_palette = false;
        view.command_palette_list = None;
        view.command_palette_subscription = None;
        view.appearance_subscription = None;
        view.token_list = None;
        view.token_proposal_list = None;
        view.token_list_url_input = None;
        view.token_chain_id_input = None;
        view.token_address_input = None;
        view.token_symbol_input = None;
        view.token_name_input = None;
        view.token_decimals_input = None;
        view.token_editor_open = false;
        view.token_editor_original = None;
        view.token_list_generation = view.token_list_generation.wrapping_add(1);
        view.account_id_input = None;
        view.private_key_input = None;
        view.walletconnect_uri_input = None;
        view.network_json_input = None;
        view.network_name_input = None;
        view.network_display_name_input = None;
        view.network_aliases_input = None;
        view.network_chain_id_input = None;
        view.network_rpc_urls_input = None;
        view.network_max_gas_limit_input = None;
        view.network_max_fee_per_gas_input = None;
        view.network_native_name_input = None;
        view.network_native_symbol_input = None;
        view.network_native_decimals_input = None;
        view.network_explorer_url_input = None;
        view.network_documentation_url_input = None;
        view.network_preset_search_input = None;
        view.network_preset_search_subscription = None;
        view.network_editor_open = false;
        view.network_editor_original = None;
        view.policy_json_input = None;
        view.policy_editor = None;
        view.policy_chain_input = None;
        view.policy_chain_label_input = None;
        view.policy_chain_max_calls_input = None;
        view.policy_chain_native_values_input = None;
        view.policy_rule_label_input = None;
        view.policy_rule_targets_input = None;
        view.policy_rule_senders_input = None;
        view.policy_rule_values_input = None;
        view.policy_rule_abi_input = None;
        view.policy_rule_args_input = None;
        view.policy_installing = false;
        view.token_proposal_busy = false;
        view.network_proposal_busy = false;
        cx.notify();
    });
    let root_view = wallet_view.clone();
    let window_handle = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(960.0), px(650.0)), cx)),
            window_min_size: Some(size(px(660.0), px(500.0))),
            ..Default::default()
        },
        |window, cx| {
            window.set_window_title(&format!("Ekubo Wallet {BUILD_VERSION}"));
            cx.new(|cx| Root::new(root_view, window, cx))
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

fn run_desktop_with_visibility(hidden_startup: bool) -> Result<()> {
    initialize_platform_notifications();
    let config = crate::config::ConfigStore::production()?;
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
    let instance_slot = Arc::new(Mutex::new(Some(instance)));
    let walletconnect = Arc::new(Mutex::new(
        crate::walletconnect::WalletConnectManager::default(),
    ));
    let (review_presenter, mut review_prompts) = GuiReviewPresenter::channel();
    let (walletconnect_presenter, mut walletconnect_prompts) = ProposalPresenter::channel();

    gpui_platform::application()
        .with_assets(gpui_component_assets::Assets)
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
            let initial_agents = owner.clients().map_or(0, |clients| clients.len());
            let initial_pending_reviews = owner
                .reviews(None)
                .map_or(0, |queues| review_queue_decision_count(&queues));
            let detailed_notification_previews = Arc::new(AtomicBool::new(
                owner.detailed_notification_previews().unwrap_or(false),
            ));
            if let Some(tray) = tray.borrow_mut().as_mut() {
                tray.update(&TraySnapshot {
                    pending_reviews: initial_pending_reviews,
                    mcp_online: false,
                    connected_agents: initial_agents,
                    walletconnect_sessions: 0,
                });
            }
            cx.set_global(DesktopRuntime {
                _instance: instance_slot.clone(),
                _server: server_slot.clone(),
                _walletconnect: walletconnect.clone(),
                _tray: tray.clone(),
            });
            let mut key_bindings = vec![
                KeyBinding::new("cmd-k", OpenCommandPalette, None),
                KeyBinding::new("ctrl-k", OpenCommandPalette, None),
                KeyBinding::new("escape", CloseOverlay, Some("Wallet")),
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

            let wallet_view = cx.new(|cx| {
                WalletWindow::new(
                    owner.clone(),
                    review_presenter.clone(),
                    walletconnect.clone(),
                    walletconnect_presenter.clone(),
                    detailed_notification_previews.clone(),
                    tray.clone(),
                    cx,
                )
            });
            let shortcut_view = wallet_view.clone();
            cx.on_action(move |action: &NavigateRoute, cx| {
                shortcut_view.update(cx, |view, cx| {
                    view.navigate_route(action.route, cx);
                });
            });
            let window_slot: WalletWindowSlot = Rc::new(RefCell::new(None));
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
            let event_window = window_slot.clone();
            let event_tokio = gpui_tokio::Tokio::handle(cx);
            cx.spawn(async move |cx| {
                let mut mcp_online = false;
                loop {
                    let changed = match view_events.recv().await {
                        Ok(event) => {
                            let agent_connection_changed = matches!(
                                &event.kind,
                                crate::events::DomainEventKind::AgentConnectionChanged { .. }
                            );
                            if matches!(
                                &event.kind,
                                crate::events::DomainEventKind::OAuthAuthorizationRequested { .. }
                            ) {
                                event_view.update(cx, |view, cx| {
                                    view.set_route(Route::Settings);
                                    cx.notify();
                                });
                                let _ = cx.update(|cx| {
                                    show_wallet_window(cx, &event_view, &event_window)
                                });
                            }
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
                                    | crate::events::DomainEventKind::AgentConnectionChanged { .. }
                                    | crate::events::DomainEventKind::ReviewChanged { .. }
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
                                });
                            }
                            if agent_connection_changed {
                                let owner = event_owner.clone();
                                let login_result = event_tokio
                                    .spawn_blocking(move || {
                                        if owner.clients()?.iter().any(|client| {
                                            client.authorized_at.is_some()
                                                && client.revoked_at.is_none()
                                        }) {
                                            crate::launch_at_login::enable()?;
                                        }
                                        Ok::<_, anyhow::Error>(())
                                    })
                                    .await;
                                if let Err(error) = login_result
                                    .context("launch-at-login task failed")
                                    .and_then(|result| result)
                                {
                                    event_view.update(cx, |view, cx| {
                                        view.set_route_error(
                                            Route::Settings,
                                            format!("Could not enable launch at login: {error:#}"),
                                        );
                                        cx.notify();
                                    });
                                }
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
                                (
                                    owner
                                        .reviews(None)
                                        .map_or(0, |queues| review_queue_decision_count(&queues)),
                                    owner.clients().map_or(0, |clients| clients.len()),
                                    sessions,
                                )
                            })
                            .await
                            .unwrap_or_default();
                        if let Some(tray) = event_tray.borrow_mut().as_mut() {
                            tray.update(&TraySnapshot {
                                pending_reviews: counts.0,
                                mcp_online,
                                connected_agents: counts.1,
                                walletconnect_sessions: counts.2.len(),
                            });
                        }
                        event_view.update(cx, |view, cx| {
                            view.walletconnect_sessions = counts.2;
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
            std::thread::Builder::new()
                .name("ekubo-tray-events".into())
                .spawn(move || {
                    while let Some(command) = PlatformTray::recv_command() {
                        if tray_commands.send(command).is_err() {
                            break;
                        }
                    }
                })
                .expect("failed to start native tray event thread");
            cx.spawn(async move |cx| {
                while let Some(command) = tray_command_rx.recv().await {
                    match command {
                        TrayCommand::OpenWallet => {
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::OpenRoute(route) => {
                            tray_view.update(cx, |view, cx| {
                                view.set_route(route);
                                cx.notify();
                            });
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::ConnectDapp => {
                            tray_view.update(cx, |view, cx| {
                                view.set_route(Route::WalletConnect);
                                cx.notify();
                            });
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::ReinstallAgents => {
                            tray_view.update(cx, |view, cx| {
                                view.set_route(Route::Settings);
                                view.reinstall_detected_agents_from_menu(cx);
                            });
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::CheckForUpdates => {
                            tray_view.update(cx, |view, cx| {
                                view.set_route(Route::Settings);
                                view.check_latest_release(cx);
                                cx.notify();
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
            let notification_previews = detailed_notification_previews.clone();
            gpui_tokio::Tokio::spawn(cx, async move {
                loop {
                    match domain_events.recv().await {
                        Ok(event) => {
                            let preferences = NotificationPreferences {
                                detailed_previews: notification_previews.load(Ordering::Relaxed),
                            };
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

            let notification_window = window_slot.clone();
            let notification_view = wallet_view.clone();
            cx.spawn(async move |cx| {
                while let Some(route) = clicked_notifications.recv().await {
                    notification_view.update(cx, |view, cx| {
                        match route {
                            NotificationRoute::Review(request_id) => {
                                view.set_route(Route::Reviews);
                                view.selected_record = Some(request_id);
                            }
                            NotificationRoute::Activity(request_id) => {
                                view.set_route(Route::Activity);
                                view.selected_record = Some(request_id);
                            }
                        }
                        cx.notify();
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

            wallet_view.update(cx, WalletWindow::reinstall_detected_agents);

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

#[cfg(test)]
#[path = "desktop_test.rs"]
mod tests;
