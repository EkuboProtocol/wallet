use crate::{
    BUILD_VERSION,
    agent_config::{AgentAdapter, ConfigBatchInstall, ConfigPreview},
    authority::{
        ApplicationAuthority, ExportLease, OwnerActivityRecord, OwnerApi, OwnerPortfolioSnapshot,
        OwnerReviewQueues, PRIVATE_KEY_REVEAL_DURATION,
    },
    gui_review::{GuiReviewCommand, GuiReviewPresenter, GuiReviewPrompt},
    http_server::{MCP_REQUEST_LIMIT_BYTES, McpHttpServer},
    notifications::{
        NotificationPreferences, NotificationRoute, NotificationService as _,
        PlatformNotificationService, notification_for,
    },
    review::ReviewState,
    single_instance::{InstanceOutcome, SingleInstance},
    tray::{PlatformTray, TrayCommand, TrayService, TraySnapshot},
    updater::{UpdateSummary, VerifiedUpdate},
    walletconnect::{
        ProposalCommand, ProposalPresenter, ProposalPrompt, QrChoices, QrPreview, SessionSummary,
        SystemScreenPicker, WalletConnectManager, run_session, scan_screen,
    },
};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::approval::{ReviewDecision, ReviewDocument};
use ekubo_wallet_core::config::{NetworkConfig, WalletMetadata};
use ekubo_wallet_core::core::policy::{WalletPolicy, diff_policies};
use ekubo_wallet_core::custody::PrivateKeyMaterial;
use ekubo_wallet_core::desktop_store::{AgentKind, McpClient};
use ekubo_wallet_core::legal::{LegalDocument, LegalStatus};
use ekubo_wallet_core::message::MessageStatus;
use ekubo_wallet_core::pending::PendingStatus;
use ekubo_wallet_core::policy_store::{PolicyProposal, StoredPolicy};
use ekubo_wallet_core::token_store::{ListedToken, StoredToken, TokenProposal};
use ekubo_wallet_core::typed_data::TypedDataStatus;
use gpui::{
    App, ClipboardItem, Context, Entity, FocusHandle, KeyBinding, MouseButton, ObjectFit, QuitMode,
    Render, RenderImage, ScrollAnchor, ScrollHandle, SharedString, Subscription, Task, WeakEntity,
    Window, WindowAppearance, WindowBounds, WindowHandle, WindowOptions, actions, div, img,
    prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme, Disableable, FocusTrapElement, Icon, IconName, IndexPath, Root, Sizable,
    StyledExt, WindowExt as _,
    alert::Alert,
    button::{Button, ButtonVariant, ButtonVariants},
    dialog::DialogButtonProps,
    group_box::{GroupBox, GroupBoxVariants as _},
    h_flex,
    input::{Input, InputState},
    list::{List, ListDelegate, ListEvent, ListItem, ListState},
    scroll::ScrollableElement,
    sidebar::{Sidebar, SidebarMenu, SidebarMenuItem},
    spinner::Spinner,
    switch::Switch,
    text::TextView,
};
use std::{
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

actions!(ekubo_wallet, [OpenCommandPalette, Quit]);

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
    _pending_software_update: Arc<Mutex<Option<PendingSoftwareUpdate>>>,
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

fn legal_review_requires_acceptance(document: LegalDocument, status: &LegalStatus) -> bool {
    legal_requires_acceptance(document)
        && match document {
            LegalDocument::TermsOfService => !status.terms_of_service.accepted,
            LegalDocument::PrivacyPolicy => !status.privacy_policy.accepted,
            LegalDocument::ThirdPartyLicenses => false,
        }
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
    Updates,
}

impl Route {
    const ALL: [Self; 10] = [
        Self::Overview,
        Self::Reviews,
        Self::Activity,
        Self::Accounts,
        Self::Policies,
        Self::Networks,
        Self::Tokens,
        Self::WalletConnect,
        Self::Updates,
        Self::Settings,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Portfolio",
            Self::Reviews => "Reviews",
            Self::Activity => "Activity",
            Self::Accounts => "Accounts",
            Self::Policies => "Policies",
            Self::Networks => "Networks",
            Self::Tokens => "Tokens",
            Self::WalletConnect => "WalletConnect",
            Self::Settings => "Settings",
            Self::Updates => "Updates",
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
            Self::Updates => IconName::ArrowDown,
        }
    }

    #[cfg(target_os = "macos")]
    const fn shortcut(self) -> &'static str {
        match self {
            Self::Overview => "⌘1",
            Self::Reviews => "⌘2",
            Self::Activity => "⌘3",
            Self::Accounts => "⌘4",
            Self::Policies => "⌘5",
            Self::Networks => "⌘6",
            Self::Tokens => "⌘7",
            Self::WalletConnect => "⌘8",
            Self::Updates => "⌘9",
            Self::Settings => "⌘,",
        }
    }

    #[cfg(not(target_os = "macos"))]
    const fn shortcut(self) -> &'static str {
        match self {
            Self::Overview => "Ctrl+1",
            Self::Reviews => "Ctrl+2",
            Self::Activity => "Ctrl+3",
            Self::Accounts => "Ctrl+4",
            Self::Policies => "Ctrl+5",
            Self::Networks => "Ctrl+6",
            Self::Tokens => "Ctrl+7",
            Self::WalletConnect => "Ctrl+8",
            Self::Updates => "Ctrl+9",
            Self::Settings => "Ctrl+,",
        }
    }

    #[cfg(target_os = "macos")]
    const fn key_binding(self) -> &'static str {
        match self {
            Self::Overview => "cmd-1",
            Self::Reviews => "cmd-2",
            Self::Activity => "cmd-3",
            Self::Accounts => "cmd-4",
            Self::Policies => "cmd-5",
            Self::Networks => "cmd-6",
            Self::Tokens => "cmd-7",
            Self::WalletConnect => "cmd-8",
            Self::Updates => "cmd-9",
            Self::Settings => "cmd-,",
        }
    }

    #[cfg(not(target_os = "macos"))]
    const fn key_binding(self) -> &'static str {
        match self {
            Self::Overview => "ctrl-1",
            Self::Reviews => "ctrl-2",
            Self::Activity => "ctrl-3",
            Self::Accounts => "ctrl-4",
            Self::Policies => "ctrl-5",
            Self::Networks => "ctrl-6",
            Self::Tokens => "ctrl-7",
            Self::WalletConnect => "ctrl-8",
            Self::Updates => "ctrl-9",
            Self::Settings => "ctrl-,",
        }
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
    token_editor_identity: Option<(u64, alloy::primitives::Address)>,
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
    automatic_update_checks: bool,
    notification_preference_busy: bool,
    update_preference_busy: bool,
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
    network_action_busy: BTreeSet<String>,
    network_action_errors: BTreeMap<String, SharedString>,
    expanded_networks: BTreeSet<String>,
    pending_network_removal: Option<String>,
    network_proposal_error: Option<SharedString>,
    policy_json_input: Option<Entity<InputState>>,
    policy_editor: Option<PolicyEditor>,
    policy_installing: bool,
    policy_action_error: Option<SharedString>,
    token_proposal_busy: bool,
    network_proposal_busy: bool,
    update_state: SoftwareUpdateState,
    pending_software_update: Arc<Mutex<Option<PendingSoftwareUpdate>>>,
}

#[derive(Clone)]
struct DesktopSnapshot {
    reviews: std::result::Result<OwnerReviewQueues, SharedString>,
    activity: std::result::Result<Vec<OwnerActivityRecord>, SharedString>,
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
        let activity = cache_result(owner.activity(None, 200));
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
            for record in activity {
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

struct PendingSoftwareUpdate {
    update: VerifiedUpdate,
    bytes: Vec<u8>,
}

enum SoftwareUpdateState {
    Idle,
    Checking,
    Current,
    Available {
        update: VerifiedUpdate,
        summary: UpdateSummary,
    },
    Downloading {
        summary: UpdateSummary,
        received: u64,
        total: Option<u64>,
    },
    Ready {
        update: VerifiedUpdate,
        summary: UpdateSummary,
        bytes: Vec<u8>,
    },
    Authorizing,
    Installing,
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
    Busy,
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

// The persistent list state keeps long legal documents virtualized between
// frames; only the digest is retained for the eventual acceptance write.
struct LegalReview {
    document: LegalDocument,
    digest: String,
    sections: Arc<[SharedString]>,
    list_state: gpui::ListState,
    acceptance_required: bool,
    scroll_check_scheduled: bool,
    viewed_to_end: bool,
    error: Option<SharedString>,
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
}

struct PendingAgentInstall {
    display_name: String,
    preview: Option<ConfigPreview>,
    remove_client_id: Option<uuid::Uuid>,
}

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
    pending_removal: Option<(u64, alloy::primitives::Address)>,
    removing: BTreeSet<(u64, alloy::primitives::Address)>,
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

#[derive(Clone)]
struct ActivityFeedback {
    message: SharedString,
    error: bool,
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
}

impl TokenProposalListDelegate {
    fn new() -> Self {
        Self {
            source: None,
            proposals: Vec::new(),
            selected: None,
            viewed_to_end: false,
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
            .filter(|token| token_matches_search(token, &self.query))
            .cloned()
            .collect();
        self.selected = None;
    }
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

const LEGAL_SECTION_TARGET_BYTES: usize = 8 * 1024;

fn legal_markdown_sections(text: &str) -> Arc<[SharedString]> {
    let mut sections = Vec::new();
    let mut section = String::new();
    let mut fence = None;

    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let heading = fence.is_none()
            && trimmed
                .strip_prefix('#')
                .is_some_and(|rest| rest.starts_with('#') || rest.starts_with(' '));
        if heading && !section.trim().is_empty() {
            sections.push(SharedString::from(std::mem::take(&mut section)));
        }

        section.push_str(line);
        let marker = if trimmed.starts_with("```") {
            Some('`')
        } else if trimmed.starts_with("~~~") {
            Some('~')
        } else {
            None
        };
        if let Some(marker) = marker {
            fence = if fence == Some(marker) {
                None
            } else if fence.is_none() {
                Some(marker)
            } else {
                fence
            };
        }

        if fence.is_none() && section.len() >= LEGAL_SECTION_TARGET_BYTES && line.trim().is_empty()
        {
            sections.push(SharedString::from(std::mem::take(&mut section)));
        }
    }
    if !section.is_empty() || sections.is_empty() {
        sections.push(SharedString::from(section));
    }
    sections.into()
}

fn legal_list_reached_end(state: &gpui::ListState) -> bool {
    let Some(last_index) = state.item_count().checked_sub(1) else {
        return true;
    };
    let Some(item) = state.bounds_for_item(last_index) else {
        return false;
    };
    item.bottom() <= state.viewport_bounds().bottom() + px(1.0)
}

fn network_can_be_removed(network: &NetworkConfig) -> bool {
    network.disabled
}

fn networks_for_display(networks: &[NetworkConfig]) -> Vec<&NetworkConfig> {
    let mut networks = networks.iter().collect::<Vec<_>>();
    networks.sort_by_key(|network| (network.disabled, network.chain_id, network.name.as_str()));
    networks
}

fn token_removal_is_confirmed(
    pending: Option<(u64, alloy::primitives::Address)>,
    identity: (u64, alloy::primitives::Address),
) -> bool {
    pending == Some(identity)
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
        let state = cx.entity().downgrade();
        let editor = self.editor.clone();
        let edit_token = token.clone();
        let removing = chain_id
            .zip(address)
            .is_some_and(|identity| self.removing.contains(&identity));
        let pending_removal = chain_id
            .zip(address)
            .is_some_and(|identity| self.pending_removal == Some(identity));
        let action_error = chain_id
            .zip(address)
            .and_then(|identity| self.action_errors.get(&identity).cloned());
        let row_id = format!("token-{}-{}", token.chain_id, token.address);
        let mut actions = h_flex().gap_2();
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
                            let should_remove = confirm_state
                                .update(cx, |list, cx| {
                                    let delegate = list.delegate_mut();
                                    if !token_removal_is_confirmed(
                                        delegate.pending_removal,
                                        (chain_id, address),
                                    ) {
                                        return false;
                                    }
                                    delegate.action_errors.remove(&(chain_id, address));
                                    delegate.removing.insert((chain_id, address));
                                    cx.notify();
                                    true
                                })
                                .unwrap_or(false);
                            if !should_remove {
                                return;
                            }
                            let owner = owner.clone();
                            let state = confirm_state.clone();
                            let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                                owner.remove_token(chain_id, address).await
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
                        .label("Edit")
                        .disabled(chain_id.zip(address).is_none() || removing)
                        .on_click(move |_, window, cx| {
                            let _ = editor.update(cx, |view, cx| {
                                view.edit_token(&edit_token, window, cx);
                            });
                        }),
                )
                .child(
                    Button::new(("remove-token", index.row))
                        .label("Remove")
                        .danger()
                        .disabled(chain_id.zip(address).is_none() || removing)
                        .on_click(move |_, _, cx| {
                            let Some(identity) = chain_id.zip(address) else {
                                return;
                            };
                            let _ = state.update(cx, |list, cx| {
                                let delegate = list.delegate_mut();
                                delegate.action_errors.remove(&identity);
                                delegate.pending_removal = Some(identity);
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
                                .justify_between()
                                .gap_4()
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .child(format!(
                                            "{} · chain {}",
                                            token.symbol.as_deref().unwrap_or("Unnamed token"),
                                            token.chain_id
                                        ))
                                        .child(
                                            div()
                                                .font_family("monospace")
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .truncate()
                                                .child(token.address.clone()),
                                        )
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
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
        Some(
            ListItem::new(("token-proposal", index.row))
                .selected(self.selected == Some(index))
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .gap_4()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(format!(
                                    "{} · {} decimals · chain {}",
                                    token.symbol, token.decimals, token.chain_id
                                ))
                                .child(
                                    div()
                                        .font_family("monospace")
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .truncate()
                                        .child(token.address.to_checksum(None)),
                                ),
                        )
                        .when_some(token.name.as_ref(), |row, name| {
                            row.child(div().text_sm().child(name.clone()))
                        }),
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

impl WalletWindow {
    fn new(
        owner: OwnerApi,
        review_presenter: GuiReviewPresenter,
        walletconnect: Arc<Mutex<WalletConnectManager>>,
        walletconnect_presenter: ProposalPresenter,
        detailed_notification_previews: Arc<AtomicBool>,
        pending_software_update: Arc<Mutex<Option<PendingSoftwareUpdate>>>,
        tray: Rc<RefCell<Option<PlatformTray>>>,
        cx: &mut Context<Self>,
    ) -> Self {
        let automatic_update_checks = owner.automatic_update_checks().unwrap_or(true);
        let route_scroll_handle = ScrollHandle::new();
        let mut window = Self {
            owner,
            desktop_snapshot: None,
            desktop_snapshot_generation: 0,
            desktop_snapshot_loading: false,
            desktop_snapshot_dirty: false,
            desktop_snapshot_error: None,
            tray,
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
            token_editor_identity: None,
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
            automatic_update_checks,
            notification_preference_busy: false,
            update_preference_busy: false,
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
            network_action_busy: BTreeSet::new(),
            network_action_errors: BTreeMap::new(),
            expanded_networks: BTreeSet::new(),
            pending_network_removal: None,
            network_proposal_error: None,
            policy_json_input: None,
            policy_editor: None,
            policy_installing: false,
            policy_action_error: None,
            token_proposal_busy: false,
            network_proposal_busy: false,
            update_state: SoftwareUpdateState::Idle,
            pending_software_update,
        };
        window.open_next_required_legal(cx);
        window.reload_detected_agents(cx);
        window.reload_desktop_snapshot(cx);
        if !window.legal_gate && window.automatic_update_checks {
            window.check_for_updates(cx);
        }
        window
    }

    fn attach_window(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.appearance_subscription.is_none() {
            let tray = self.tray.clone();
            self.appearance_subscription =
                Some(cx.observe_window_appearance(window, move |_, window, _| {
                    if let Some(tray) = tray.borrow_mut().as_mut() {
                        tray.set_dark_mode(dark_appearance(window.appearance()));
                    }
                }));
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
            self.reload_tokens(cx);
        }
        if self.token_proposal_list.is_none() {
            self.token_proposal_list = Some(cx.new(|cx| {
                ListState::new(TokenProposalListDelegate::new(), window, cx).selectable(false)
            }));
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
        if self.policy_json_input.is_none() {
            self.policy_json_input = Some(cx.new(|cx| {
                InputState::new(window, cx)
                    .code_editor("json")
                    .rows(20)
                    .placeholder("Select an account to inspect and edit its policy")
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

    fn cached_activity(&self) -> Result<&[OwnerActivityRecord]> {
        self.snapshot()?
            .activity
            .as_deref()
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
        self.token_editor_identity = None;
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
        self.token_editor_identity = Some((chain_id, address));
        self.token_editor_errors = TokenEditorErrors::default();
        self.token_editor_anchor.scroll_to(window, cx);
        cx.notify();
    }

    fn close_token_editor(&mut self, cx: &mut Context<Self>) {
        if self.token_editor_busy {
            return;
        }
        self.token_editor_open = false;
        self.token_editor_identity = None;
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
        if let Some(identity) = self.token_editor_identity
            && identity != (token.chain_id, token.address)
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
        let task =
            gpui_tokio::Tokio::spawn_result(cx, async move { owner.upsert_token(token).await });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.token_editor_busy = false;
                match result {
                    Ok(_) => {
                        view.token_editor_open = false;
                        view.token_editor_identity = None;
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
            let _ = view.update(cx, |view, cx| {
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
                        match uri.and_then(|uri| view.begin_walletconnect_uri(&uri, cx)) {
                            Ok(()) => view.clear_route_error(Route::WalletConnect),
                            Err(error) => view.set_route_error(
                                Route::WalletConnect,
                                format!("Could not connect: {error:#}"),
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

    fn choose_walletconnect_qr(&mut self, index: usize, cx: &mut Context<Self>) {
        self.walletconnect_scan_generation = self.walletconnect_scan_generation.wrapping_add(1);
        let state = std::mem::replace(&mut self.walletconnect_scan, WalletConnectScanState::Idle);
        let WalletConnectScanState::Choices { choices, .. } = state else {
            return;
        };
        match choices
            .take(index)
            .and_then(|uri| self.begin_walletconnect_uri(&uri, cx))
        {
            Ok(()) => self.clear_route_error(Route::WalletConnect),
            Err(error) => self.set_route_error(
                Route::WalletConnect,
                format!("Could not connect: {error:#}"),
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
            self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy,
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
        if self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy {
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
                            current_policy,
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
        if self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy {
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
        let acceptance_required = self
            .owner
            .legal_status()
            .is_ok_and(|status| legal_review_requires_acceptance(document, &status));
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
        cx: &mut Context<Self>,
    ) -> LegalReview {
        let sections = legal_markdown_sections(text);
        let list_state = gpui::ListState::new(sections.len(), gpui::ListAlignment::Top, px(600.0))
            .with_uniform_item_height(px(180.0));
        let view = cx.entity().downgrade();
        let review_digest = digest.clone();
        list_state.set_scroll_handler(move |event, _, cx| {
            if event.visible_range.end < event.count {
                return;
            }
            let view = view.clone();
            let review_digest = review_digest.clone();
            cx.defer(move |cx| {
                let _ = view.update(cx, |view, cx| {
                    view.update_legal_scroll_state(&review_digest, cx);
                });
            });
        });
        LegalReview {
            document,
            digest,
            sections,
            list_state,
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
        if review.acceptance_required
            && review.digest == digest
            && !review.viewed_to_end
            && legal_list_reached_end(&review.list_state)
        {
            review.viewed_to_end = true;
            cx.notify();
        }
    }

    fn accept_legal(&mut self, cx: &mut Context<Self>) {
        let Some(review) = self.legal_review.as_ref() else {
            return;
        };
        if !review.acceptance_required || !review.viewed_to_end {
            return;
        }
        match self.owner.accept_legal(review.document, &review.digest) {
            Ok(()) => {
                self.open_next_required_legal(cx);
                if !self.legal_gate && self.automatic_update_checks {
                    self.check_for_updates(cx);
                }
            }
            Err(error) => {
                if let Some(review) = self.legal_review.as_mut() {
                    review.error = Some(format!("Could not accept document: {error:#}").into());
                }
            }
        }
        cx.notify();
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

    fn edit_network(
        &mut self,
        network: &NetworkConfig,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(input) = self.network_json_input.as_ref() else {
            return;
        };
        match serde_json::to_string_pretty(&network) {
            Ok(document) => {
                input.update(cx, |input, cx| {
                    input.set_value(document, window, cx);
                    input.set_selected_range(0..input.value().len(), cx);
                    input.focus(window, cx);
                });
                self.network_json_error = None;
                self.network_editor_anchor.scroll_to(window, cx);
            }
            Err(error) => {
                self.network_json_error =
                    Some(format!("Could not serialize network: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn install_network_from_editor(&mut self, cx: &mut Context<Self>) {
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
        let owner = self.owner.clone();
        let task =
            gpui_tokio::Tokio::spawn_result(
                cx,
                async move { owner.install_network(network).await },
            );
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                match result {
                    Ok(()) => view.network_json_error = None,
                    Err(error) => {
                        view.network_json_error =
                            Some(format!("Network was not installed: {error:#}").into());
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn set_network_disabled(&mut self, name: &str, disabled: bool, cx: &mut Context<Self>) {
        let selected_network = self.portfolio_chain_id.is_some_and(|chain_id| {
            self.owner.networks().is_ok_and(|networks| {
                networks
                    .iter()
                    .any(|network| network.chain_id == chain_id && network.name == name)
            })
        });
        let name = name.to_owned();
        if !self.network_action_busy.insert(name.clone()) {
            return;
        }
        self.network_action_errors.remove(&name);
        if !disabled && self.pending_network_removal.as_deref() == Some(name.as_str()) {
            self.pending_network_removal = None;
        }
        let owner = self.owner.clone();
        let action_name = name.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.set_network_disabled(&name, disabled).await
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

    fn begin_network_removal(&mut self, name: &str, cx: &mut Context<Self>) {
        self.pending_network_removal = Some(name.to_owned());
        self.network_action_errors.remove(name);
        cx.notify();
    }

    fn cancel_network_removal(&mut self, cx: &mut Context<Self>) {
        self.pending_network_removal = None;
        cx.notify();
    }

    fn confirm_network_removal(&mut self, name: &str, cx: &mut Context<Self>) {
        if self.pending_network_removal.as_deref() != Some(name) {
            return;
        }
        let owner = self.owner.clone();
        let name = name.to_owned();
        if !self.network_action_busy.insert(name.clone()) {
            return;
        }
        self.network_action_errors.remove(&name);
        let action_name = name.clone();
        let task =
            gpui_tokio::Tokio::spawn_result(cx, async move { owner.remove_network(&name).await });
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
                view.selected_record = Some(request_id);
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

    fn check_for_updates(&mut self, cx: &mut Context<Self>) {
        if matches!(
            self.update_state,
            SoftwareUpdateState::Checking
                | SoftwareUpdateState::Downloading { .. }
                | SoftwareUpdateState::Authorizing
                | SoftwareUpdateState::Installing
        ) {
            return;
        }
        self.update_state = SoftwareUpdateState::Checking;
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(crate::updater::check_for_update)
                .await
                .context("software update check task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.update_state = match result {
                    Ok(Some(update)) => SoftwareUpdateState::Available {
                        summary: update.summary(),
                        update,
                    },
                    Ok(None) => SoftwareUpdateState::Current,
                    Err(error) => SoftwareUpdateState::Failed(
                        format!("Could not check for signed updates: {error:#}").into(),
                    ),
                };
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn download_update(&mut self, cx: &mut Context<Self>) {
        let state = std::mem::replace(&mut self.update_state, SoftwareUpdateState::Idle);
        let SoftwareUpdateState::Available { update, summary } = state else {
            self.update_state = state;
            return;
        };
        self.update_state = SoftwareUpdateState::Downloading {
            summary: summary.clone(),
            received: 0,
            total: None,
        };
        let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || {
                let bytes = update.download_verified_with_progress(|chunk, total| {
                    let _ = progress_tx.send((chunk as u64, total));
                })?;
                Ok::<_, anyhow::Error>((update, bytes))
            })
            .await
            .context("software update download task failed")?
        });
        cx.spawn(async move |view, cx| {
            let mut received = 0_u64;
            while let Some((chunk, total)) = progress_rx.recv().await {
                received = received.saturating_add(chunk);
                let _ = view.update(cx, |view, cx| {
                    if let SoftwareUpdateState::Downloading {
                        received: current,
                        total: expected,
                        ..
                    } = &mut view.update_state
                    {
                        *current = received;
                        *expected = total;
                        cx.notify();
                    }
                });
            }
        })
        .detach();
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.update_state = match result {
                    Ok((update, bytes)) => SoftwareUpdateState::Ready {
                        update,
                        summary,
                        bytes,
                    },
                    Err(error) => SoftwareUpdateState::Failed(
                        format!("Update download or signature verification failed: {error:#}")
                            .into(),
                    ),
                };
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn install_update(&mut self, cx: &mut Context<Self>) {
        let state = std::mem::replace(&mut self.update_state, SoftwareUpdateState::Idle);
        let SoftwareUpdateState::Ready {
            update,
            summary,
            bytes,
        } = state
        else {
            self.update_state = state;
            return;
        };
        self.update_state = SoftwareUpdateState::Authorizing;
        let owner = self.owner.clone();
        let pending = self.pending_software_update.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            let authorization = owner.authorize_software_update().await?;
            owner.confirm_software_update_install(&authorization)?;
            Ok::<_, anyhow::Error>(())
        });
        self.clear_route_error(Route::Updates);
        cx.spawn(async move |view, cx| match task.await {
            Ok(()) => {
                let staged = pending
                    .lock()
                    .map_err(|_| anyhow::anyhow!("software update slot was poisoned"))
                    .map(|mut pending| {
                        *pending = Some(PendingSoftwareUpdate { update, bytes });
                    });
                match staged {
                    Ok(()) => {
                        let _ = view.update(cx, |view, cx| {
                            view.update_state = SoftwareUpdateState::Installing;
                            cx.notify();
                        });
                        cx.update(|cx| cx.quit());
                    }
                    Err(error) => {
                        let _ = view.update(cx, |view, cx| {
                            view.update_state = SoftwareUpdateState::Failed(
                                format!("Could not stage verified update: {error:#}").into(),
                            );
                            cx.notify();
                        });
                    }
                }
            }
            Err(error) => {
                let _ = view.update(cx, |view, cx| {
                    view.update_state = SoftwareUpdateState::Ready {
                        update,
                        summary,
                        bytes,
                    };
                    view.set_route_error(
                        Route::Updates,
                        format!("Update installation was not authorized: {error:#}"),
                    );
                    cx.notify();
                });
            }
        })
        .detach();
        cx.notify();
    }

    fn revoke_agent(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.clear_route_error(Route::Settings);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            let authorization = owner.authorize_agent_access().await?;
            owner.revoke_client(client_id, &authorization)
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                match result {
                    Ok(()) => view.clear_route_error(Route::Settings),
                    Err(error) => view.set_route_error(
                        Route::Settings,
                        format!("Could not revoke agent: {error:#}"),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn prepare_agent_repair(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        let kind = self
            .cached_clients()
            .ok()
            .and_then(|clients| clients.iter().find(|client| client.id == client_id))
            .map(|client| client.agent_kind);
        if let Some(kind) = kind {
            self.prepare_detected_agent_install(kind, cx);
        }
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
                    preview: Some(preview),
                    remove_client_id: None,
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

    fn prepare_agent_removal(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.pending_agent_install.is_some() {
            self.set_route_error(Route::Settings, "Finish the current agent change first.");
            cx.notify();
            return;
        }
        let client_kind = match self.cached_clients().and_then(|clients| {
            clients
                .iter()
                .find(|client| client.id == client_id)
                .map(|client| client.agent_kind)
                .context("the selected agent registration no longer exists")
        }) {
            Ok(kind) => kind,
            Err(error) => {
                self.set_route_error(
                    Route::Settings,
                    format!("Could not prepare agent change: {error:#}"),
                );
                cx.notify();
                return;
            }
        };
        self.agent_reinstall = AgentReinstallState::Running;
        self.clear_route_error(Route::Settings);
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            tokio::task::spawn_blocking(move || {
                let adapter = AgentAdapter::supported()?
                    .into_iter()
                    .find(|adapter| adapter.kind == client_kind)
                    .context("the selected agent has no managed configuration adapter")?;
                Ok::<_, anyhow::Error>(PendingAgentInstall {
                    display_name: format!("Remove {}", adapter.display_name),
                    preview: Some(adapter.preview_remove(false)?),
                    remove_client_id: Some(client_id),
                })
            })
            .await
            .context("agent removal preview task failed")?
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.agent_reinstall = AgentReinstallState::Idle;
                match result {
                    Ok(pending) => view.pending_agent_install = Some(pending),
                    Err(error) => view.set_route_error(
                        Route::Settings,
                        format!("Could not prepare agent change: {error:#}"),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn prepare_agent_registration_removal(
        &mut self,
        client_id: uuid::Uuid,
        cx: &mut Context<Self>,
    ) {
        if self.pending_agent_install.is_some() {
            self.set_route_error(Route::Settings, "Finish the current agent change first.");
            cx.notify();
            return;
        }
        match self.cached_clients().and_then(|clients| {
            clients
                .iter()
                .find(|client| client.id == client_id && client.revoked_at.is_none())
                .cloned()
                .context("the selected agent registration is no longer active")
        }) {
            Ok(client) => {
                self.pending_agent_install = Some(PendingAgentInstall {
                    display_name: format!("Delete {}", client.display_name),
                    preview: None,
                    remove_client_id: Some(client_id),
                });
                self.clear_route_error(Route::Settings);
            }
            Err(error) => self.set_route_error(
                Route::Settings,
                format!("Could not prepare registration removal: {error:#}"),
            ),
        }
        cx.notify();
    }

    fn cancel_agent_install(&mut self, cx: &mut Context<Self>) {
        if self.pending_agent_install.take().is_some() {
            self.clear_route_error(Route::Settings);
        }
        cx.notify();
    }

    fn confirm_agent_install(&mut self, cx: &mut Context<Self>) {
        let Some(mut pending) = self.pending_agent_install.take() else {
            return;
        };
        let display_name = pending.display_name.clone();
        let preview = pending.preview.take();
        let Some(client_id) = pending.remove_client_id else {
            let preview = preview.expect("an installation always has its preview");
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
            return;
        };
        self.agent_reinstall = AgentReinstallState::Running;
        self.clear_route_error(Route::Settings);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            let batch = if let Some(preview) = preview {
                Some(
                    tokio::task::spawn_blocking(move || ConfigBatchInstall::install(vec![preview]))
                        .await
                        .context("agent configuration removal task failed")??,
                )
            } else {
                None
            };
            let authorization = owner.authorize_agent_access().await?;
            owner.remove_client(client_id, &authorization)?;
            if let Some(batch) = batch {
                batch.commit();
            }
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
                        format!("Could not complete {display_name}: {error:#}"),
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
        let Some(QueuedReview::Transaction(prompt)) = self.queued_reviews.receive(
            self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy,
            QueuedReview::Transaction(Box::new(prompt)),
        ) else {
            return;
        };
        self.activate_transaction_prompt(*prompt);
    }

    fn activate_transaction_prompt(&mut self, prompt: GuiReviewPrompt) {
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
        if self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy {
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
        if self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy {
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
        if self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy {
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
        self.route_scroll_handle
            .set_offset(gpui::point(px(0.0), px(0.0)));
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

    fn set_automatic_update_checks(&mut self, enabled: bool, cx: &mut Context<Self>) {
        if self.update_preference_busy {
            return;
        }
        self.update_preference_busy = true;
        self.clear_route_error(Route::Settings);
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.set_automatic_update_checks(enabled).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.update_preference_busy = false;
                match result {
                    Ok(()) => {
                        view.automatic_update_checks = enabled;
                        view.clear_route_error(Route::Settings);
                        if enabled && !view.legal_gate {
                            view.check_for_updates(cx);
                        }
                    }
                    Err(error) => view.set_route_error(
                        Route::Settings,
                        format!("Could not save update preference: {error:#}"),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let menu = SidebarMenu::new().children(Route::ALL.into_iter().map(|route| {
            SidebarMenuItem::new(format!("{}  {}", route.label(), route.shortcut()))
                .icon(route.icon())
                .active(route == self.route)
                .disable(self.legal_gate)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.route = route;
                    this.command_palette = false;
                    cx.notify();
                }))
        }));
        Sidebar::new("wallet-sidebar")
            .w(px(48.0))
            .collapsed(true)
            .child(menu)
    }

    fn render_reviews(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div().flex().flex_col().gap_3();
        match self.cached_reviews() {
            Ok(queues) => {
                let total = review_queue_decision_count(queues);
                content = content.child(format!("{total} request(s) awaiting an owner decision"));
                for request in &queues.transactions {
                    let request_id = request.request_id;
                    content =
                        content.child(
                            div()
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
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
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(format!(
                                    "Typed data · {} · {} · {}",
                                    request.wallet_id, request.chain_id, request_id
                                ))
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
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(format!("Message · {} · {}", request.wallet_id, request_id))
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
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .items_center()
                                .justify_between()
                                .gap_3()
                                .child(format!(
                                    "Policy proposal · {wallet_id} · revision {}",
                                    proposal.source_revision
                                ))
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
                                .p_3()
                                .border_1()
                                .rounded_lg()
                                .border_color(cx.theme().border)
                                .flex()
                                .items_center()
                                .justify_between()
                                .gap_3()
                                .child(format!(
                                    "Network proposal · {} · chain {chain_id}",
                                    proposal.name
                                ))
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
                    content = content.child(
                        div()
                            .p_3()
                            .border_1()
                            .rounded_lg()
                            .border_color(cx.theme().border)
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_3()
                            .child(format!("Token proposal · {source} · {count} name(s)"))
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
                            .text_color(cx.theme().muted_foreground)
                            .child("Nothing is waiting for review."),
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
                        div()
                            .child("Plan digest")
                            .child(div().font_family("monospace").child(item.digest.clone())),
                    );
                if let Some(source) = item.plan_source.as_ref() {
                    detail = detail.child(format!("Plan source: {source}"));
                }
                if let Some(review_digest) = item.review_digest.as_ref() {
                    detail = detail.child(
                        div()
                            .child("Review digest")
                            .child(div().font_family("monospace").child(review_digest.clone())),
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
                                .child(div().font_family("monospace").child(value.clone())),
                        );
                    }
                }
                if let Some(fee) = item.mined_fee.as_ref() {
                    detail = detail.child(format!(
                        "Mined fee: {} wei · {} gas at {} wei/gas",
                        fee.transaction_fee_wei, fee.gas_used, fee.effective_gas_price
                    ));
                }
                if !item.cancel_transaction_hashes.is_empty() {
                    detail = detail
                        .child(div().font_semibold().child("Cancellation attempts"))
                        .children(
                            item.cancel_transaction_hashes
                                .iter()
                                .cloned()
                                .map(|hash| div().font_family("monospace").text_sm().child(hash)),
                        );
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
                                .font_family("monospace")
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
                        div()
                            .child("Digest")
                            .child(div().font_family("monospace").child(item.digest.clone())),
                    );
                if let Some(decided_at) = item.approved_at.or(item.rejected_at) {
                    detail = detail.child(format!("Decision recorded: {decided_at}"));
                }
                if let Some(signature) = item.signature.as_ref() {
                    detail = detail.child(
                        div()
                            .child("Signature")
                            .child(div().font_family("monospace").child(signature.clone())),
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
                                    .font_family("monospace")
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
                        div()
                            .child("Digest")
                            .child(div().font_family("monospace").child(item.digest.clone())),
                    );
                if let Some(decided_at) = item.approved_at.or(item.rejected_at) {
                    detail = detail.child(format!("Decision recorded: {decided_at}"));
                }
                if let Some(signature) = item.signature.as_ref() {
                    detail = detail.child(
                        div()
                            .child("Signature")
                            .child(div().font_family("monospace").child(signature.clone())),
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
                                    .font_family("monospace")
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
        let items = match self.cached_activity() {
            Ok(items) => items,
            Err(error) => return panel.child(format!("Activity unavailable: {error:#}")),
        };
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
        panel.children(items.iter().map(|record| {
            let request_id = record.request_id();
            let selected = self.selected_record == Some(request_id);
            let base = div()
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
                .gap_2();
            match record {
                OwnerActivityRecord::Transaction(item) => {
                    let status = item.status;
                    let busy = self.activity_busy.contains(&request_id);
                    let actions = transaction_actions(item.status);
                    let feedback = self.activity_feedback.get(&request_id).cloned();
                    base.child(
                        h_flex()
                            .w_full()
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
                                            .font_family("monospace")
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
                                        .on_click(
                                            cx.listener(move |view, _, _, cx| {
                                                view.selected_record = Some(request_id);
                                                cx.notify();
                                            }),
                                        ),
                                    )
                                    .when(actions.refresh, |buttons| {
                                        buttons.child(
                                            Button::new(SharedString::from(format!(
                                                "refresh-transaction-{request_id}"
                                            )))
                                            .label(if busy { "Working…" } else { "Refresh" })
                                            .disabled(busy)
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.refresh_transaction(request_id, cx);
                                            })),
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
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.rebroadcast_transaction(request_id, cx);
                                            })),
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
                                            .on_click(cx.listener(move |view, _, window, cx| {
                                                view.confirm_transaction_cancellation(
                                                    request_id, window, cx,
                                                );
                                            })),
                                        )
                                    })
                                    .when(actions.discard, |buttons| {
                                        buttons.child(
                                            Button::new(SharedString::from(format!(
                                                "discard-{request_id}"
                                            )))
                                            .label("Discard unsent signature")
                                            .danger()
                                            .disabled(busy)
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.discard_unsent_transaction(request_id, cx);
                                            })),
                                        )
                                    }),
                            ),
                    )
                    .when_some(feedback, |row, feedback| {
                        row.child(
                            div()
                                .text_sm()
                                .text_color(if feedback.error {
                                    cx.theme().danger
                                } else {
                                    cx.theme().muted_foreground
                                })
                                .child(feedback.message),
                        )
                    })
                }
                OwnerActivityRecord::Message(item) => base.child(
                    h_flex()
                        .w_full()
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
                                        .font_family("monospace")
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
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.selected_record = Some(request_id);
                                        cx.notify();
                                    })),
                                )
                                .when(item.status == MessageStatus::AwaitingApproval, |buttons| {
                                    buttons.child(
                                        Button::new(SharedString::from(format!(
                                            "review-message-activity-{request_id}"
                                        )))
                                        .label("Review")
                                        .on_click(
                                            cx.listener(move |view, _, _, cx| {
                                                view.begin_message_review(request_id, cx);
                                            }),
                                        ),
                                    )
                                }),
                        ),
                ),
                OwnerActivityRecord::TypedData(item) => base.child(
                    h_flex()
                        .w_full()
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
                                        .font_family("monospace")
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
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.selected_record = Some(request_id);
                                        cx.notify();
                                    })),
                                )
                                .when(
                                    item.status == TypedDataStatus::AwaitingApproval,
                                    |buttons| {
                                        buttons.child(
                                            Button::new(SharedString::from(format!(
                                                "review-typed-data-activity-{request_id}"
                                            )))
                                            .label("Review")
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.begin_typed_data_review(request_id, cx);
                                            })),
                                        )
                                    },
                                ),
                        ),
                ),
            }
        }))
    }

    fn render_settings(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut agents = div().flex().flex_col().gap_1();
        let clients = self.cached_clients().unwrap_or_default();
        let mut managed_agents = div().flex().flex_col().gap_1();
        for item in clients.iter().filter(|client| client.revoked_at.is_none()) {
            let client_id = item.id;
            let active = item.revoked_at.is_none();
            let managed = item.agent_kind != AgentKind::Other;
            let status = if let Some(revoked) = item.revoked_at {
                format!("Revoked {revoked}")
            } else if let Some(last_used) = item.last_used_at {
                format!("Last used {last_used}")
            } else {
                item.authorized_at.map_or_else(
                    || "Authorized, not yet used".into(),
                    |authorized| format!("Authorized {authorized}; not yet used"),
                )
            };
            managed_agents =
                managed_agents.child(
                    ListItem::new(SharedString::from(format!("managed-agent-{client_id}"))).child(
                        div()
                            .w_full()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                h_flex()
                                    .w_full()
                                    .justify_between()
                                    .gap_4()
                                    .child(format!("{} · {:?}", item.display_name, item.agent_kind))
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(cx.theme().muted_foreground)
                                            .child(status),
                                    ),
                            )
                            .when(active && managed, |row| {
                                row.child(
                                    h_flex()
                                        .gap_2()
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "repair-agent-{client_id}"
                                            )))
                                            .label("Repair")
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.prepare_agent_repair(client_id, cx);
                                            })),
                                        )
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "remove-agent-{client_id}"
                                            )))
                                            .label("Remove")
                                            .danger()
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.prepare_agent_removal(client_id, cx);
                                            })),
                                        ),
                                )
                            })
                            .when(active && !managed, |row| {
                                row.child(
                                    Button::new(SharedString::from(format!(
                                        "delete-agent-registration-{client_id}"
                                    )))
                                    .label("Delete registration")
                                    .danger()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.prepare_agent_registration_removal(client_id, cx);
                                    })),
                                )
                            })
                            .when(active, |row| {
                                row.child(
                                    Button::new(SharedString::from(format!(
                                        "revoke-agent-{client_id}"
                                    )))
                                    .label("Revoke access")
                                    .danger()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.revoke_agent(client_id, cx);
                                    })),
                                )
                            }),
                    ),
                );
        }
        if clients.iter().all(|client| client.revoked_at.is_some()) {
            managed_agents = managed_agents.child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("No agent registrations have been created."),
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
            .child(
                GroupBox::new()
                    .id("mcp-settings")
                    .outline()
                    .title("MCP service")
                    .child(self.mcp_status.clone())
                    .child(format!(
                        "Request limit: {} MiB",
                        MCP_REQUEST_LIMIT_BYTES / 1024 / 1024
                    ))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("OAuth access tokens are issued only after you choose a one-day, one-week, or one-month session and complete wallet-mediated human presence. Agent configuration files contain no credential; Codex is forced to use the OS keyring, while other harnesses control their own credential storage. Access tokens last 10 minutes and refresh rotation cannot extend your selected absolute expiry. A stolen bearer token can exercise the same Agent API and policy as its harness, so use narrowly scoped policies—an allow-all policy intentionally grants full unattended signing authority. Plaintext loopback HTTP cannot protect against malicious code already running as your OS user."),
                    ),
            )
            .child(
                GroupBox::new()
                    .id("notification-settings")
                    .outline()
                    .title("Notifications")
                    .child(
                        h_flex()
                            .w_full()
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
            )
            .child(
                GroupBox::new()
                    .id("update-settings")
                    .outline()
                    .title("Updates")
                    .child(
                        h_flex()
                            .w_full()
                            .justify_between()
                            .gap_4()
                            .child(
                                div()
                                    .flex_1()
                                    .child("Check automatically at launch")
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(cx.theme().muted_foreground)
                                            .child("Checks signed metadata after legal acceptance. Updates are never downloaded or installed without explicit confirmation."),
                                    ),
                            )
                            .child(
                                Switch::new("automatic-update-checks")
                                    .checked(self.automatic_update_checks)
                                    .disabled(self.update_preference_busy)
                                    .tooltip("Check signed update metadata when the wallet starts")
                                    .on_click(cx.listener(|view, checked, _, cx| {
                                        view.set_automatic_update_checks(*checked, cx);
                                    })),
                            ),
                    ),
            )
            .child(
                GroupBox::new()
                    .id("detected-agent-settings")
                    .outline()
                    .title("Detected agents")
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
            )
            .child(
                GroupBox::new()
                    .id("managed-agent-settings")
                    .outline()
                    .title("Managed agent connections")
                    .child(managed_agents),
            )
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
                        .gap_2()
                        .child(div().flex_1().child(Input::new(input)))
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
                        .gap_2()
                        .child(Input::new(input).mask_toggle().flex_1())
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
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .child(format!("{} · {:#x}", item.id, item.address))
                                        .child(
                                            div()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(format!(
                                                    "{:?} · created {}",
                                                    item.source, item.created_at
                                                )),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex()
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
                        changes =
                            changes.child(div().font_family("monospace").text_sm().child(line));
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
        let editor_panel = div()
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
                div()
                    .id("policy-json-editor-input")
                    .flex_1()
                    .min_h(px(320.0))
                    .child(Input::new(input).w_full().h_full()),
            )
            .when_some(
                editor
                    .validation
                    .as_ref()
                    .and_then(|validation| validation.as_ref().err().cloned()),
                |panel, error| {
                    panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
                },
            )
            .child(
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
                            .font_family("monospace")
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
        let panel = div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_2()
            .child(div().font_semibold().child("Legal & Version"));
        match self.cached_legal_status() {
            Ok(status) => {
                panel
                    .child(format!("Signing enabled: {}", status.signing_allowed))
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
                        Button::new("review-licenses")
                            .label("Third-Party Licenses")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.open_legal_review(LegalDocument::ThirdPartyLicenses, cx);
                            })),
                    )
                    .child(format!("Version {BUILD_VERSION}"))
            }
            Err(error) => panel.child(format!("Legal status unavailable: {error:#}")),
        }
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
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.choose_walletconnect_qr(index, cx);
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
                                    .font_family("monospace")
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
        if let Some(input) = self.network_json_input.as_ref() {
            content = content.child(
                div()
                    .id("network-editor-anchor")
                    .anchor_scroll(Some(self.network_editor_anchor.clone()))
                    .child(
                        GroupBox::new()
                            .id("network-editor")
                            .outline()
                            .title("Add or update network")
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("Paste a complete network object, or choose Edit below. Existing chain IDs are updated in place."),
                            )
                            .child(Input::new(input).h(px(260.0)))
                            .when_some(self.network_json_error.clone(), |panel, error| {
                                panel.child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().danger)
                                        .child(error),
                                )
                            })
                            .child(
                                Button::new("install-network-json")
                                    .label("Authenticate & install")
                                    .primary()
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.install_network_from_editor(cx);
                                    })),
                            ),
                    ),
            );
        }
        match self.cached_networks() {
            Ok(networks) => {
                content.children(networks_for_display(networks).into_iter().map(|network| {
                    let name = network.name.clone();
                    let edit = network.clone();
                    let details_name = name.clone();
                    let toggle_name = name.clone();
                    let remove_name = name.clone();
                    let confirm_remove_name = name.clone();
                    let disabled = network.disabled;
                    let expanded = self.expanded_networks.contains(&name);
                    let busy = self.network_action_busy.contains(&name);
                    let confirming_removal =
                        self.pending_network_removal.as_deref() == Some(name.as_str());
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
                                .w_full()
                                .justify_between()
                                .gap_3()
                                .child(
                                    div()
                                        .child(
                                            h_flex()
                                                .gap_2()
                                                .child(
                                                    div().font_semibold().child(
                                                        network
                                                            .display_name
                                                            .clone()
                                                            .unwrap_or_else(|| name.clone()),
                                                    ),
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
                                            div()
                                                .text_sm()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(format!(
                                                    "{} · chain {}",
                                                    name, network.chain_id,
                                                )),
                                        ),
                                )
                                .child(
                                    h_flex()
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
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.toggle_network_details(&details_name, cx);
                                            })),
                                        )
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "edit-network-{name}"
                                            )))
                                            .label("Edit")
                                            .disabled(busy)
                                            .on_click(cx.listener(move |view, _, window, cx| {
                                                view.edit_network(&edit, window, cx);
                                            })),
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
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.set_network_disabled(
                                                    &toggle_name,
                                                    !disabled,
                                                    cx,
                                                );
                                            })),
                                        )
                                        .when(network_can_be_removed(network), |buttons| {
                                            buttons.child(
                                                Button::new(SharedString::from(format!(
                                                    "delete-network-{name}"
                                                )))
                                                .label(if confirming_removal {
                                                    "Awaiting confirmation"
                                                } else {
                                                    "Delete"
                                                })
                                                .danger()
                                                .disabled(busy || confirming_removal)
                                                .on_click(cx.listener(move |view, _, _, cx| {
                                                    view.begin_network_removal(&remove_name, cx);
                                                })),
                                            )
                                        }),
                                ),
                        )
                        .when(expanded, |card| {
                            card.child(
                                div()
                                    .p_3()
                                    .rounded(cx.theme().radius)
                                    .bg(cx.theme().secondary)
                                    .font_family("monospace")
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
                                        h_flex()
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
                                                            &confirm_remove_name,
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
        let enabled_networks = self
            .owner
            .networks()
            .unwrap_or_default()
            .into_iter()
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
                                                    .font_family("monospace")
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
                                                        .font_family("monospace")
                                                        .text_color(cx.theme().muted_foreground)
                                                        .child(token.address.clone()),
                                                ),
                                            )
                                            .child(
                                                div()
                                                    .font_family("monospace")
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
                                                .font_family("monospace")
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
                let editing = self.token_editor_identity.is_some();
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
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_4()
            .child(format!("Installed version: {BUILD_VERSION}"))
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("Updates are installed only after their embedded Minisign signature is verified and you explicitly confirm the exact version and release notes."),
            );
        match &self.update_state {
            SoftwareUpdateState::Idle => panel.child(
                Button::new("check-for-software-update")
                    .label("Check for updates")
                    .primary()
                    .on_click(cx.listener(|view, _, _, cx| view.check_for_updates(cx))),
            ),
            SoftwareUpdateState::Checking => panel.child(
                h_flex()
                    .gap_2()
                    .child(Spinner::new())
                    .child("Downloading and verifying signed update metadata…"),
            ),
            SoftwareUpdateState::Current => panel
                .child("This is the latest signed release for this platform.")
                .child(
                    Button::new("recheck-for-software-update")
                        .label("Check again")
                        .on_click(cx.listener(|view, _, _, cx| view.check_for_updates(cx))),
                ),
            SoftwareUpdateState::Available { summary, .. } => {
                panel = panel
                    .child(div().text_lg().font_semibold().child(format!(
                        "Ekubo Wallet {} is available",
                        summary.version
                    )))
                    .when_some(summary.notes.clone(), |panel, notes| {
                        panel.child(
                            GroupBox::new()
                                .id("software-update-release-notes")
                                .outline()
                                .title("Release notes")
                                .child(TextView::markdown("software-update-notes", notes)),
                        )
                    })
                    .when(summary.requires_package_handoff, |panel| {
                        panel.child("This package is managed by the operating system. After verification, the native package installer will complete the update.")
                    })
                    .child(
                        Button::new("download-software-update")
                            .label("Download and verify signature")
                            .primary()
                            .on_click(cx.listener(|view, _, _, cx| view.download_update(cx))),
                    );
                panel
            }
            SoftwareUpdateState::Downloading {
                summary,
                received,
                total,
            } => {
                let progress = total.map_or_else(
                    || format!("{} MiB received", received / 1024 / 1024),
                    |total| {
                        let percent = if total == 0 {
                            0
                        } else {
                            received.saturating_mul(100).saturating_div(total).min(100)
                        };
                        format!(
                            "{percent}% · {} of {} MiB",
                            received / 1024 / 1024,
                            total / 1024 / 1024
                        )
                    },
                );
                panel.child(
                    h_flex()
                        .gap_2()
                        .child(Spinner::new())
                        .child(format!(
                            "Downloading Ekubo Wallet {} and verifying its signature… {progress}",
                            summary.version
                        )),
                )
            }
            SoftwareUpdateState::Ready { summary, bytes, .. } => panel
                .child(
                    div()
                        .font_semibold()
                        .child(format!("Ekubo Wallet {} is verified", summary.version)),
                )
                .child(format!(
                    "The {} MiB package passed Minisign verification. Installation will gracefully disconnect WalletConnect sessions, stop the MCP server, replace the application, and relaunch.",
                    bytes.len() / 1024 / 1024
                ))
                .child(
                    Button::new("install-software-update")
                        .label("Authenticate, install, and restart")
                        .primary()
                        .on_click(cx.listener(|view, _, _, cx| view.install_update(cx))),
                ),
            SoftwareUpdateState::Authorizing => panel.child(
                h_flex()
                    .gap_2()
                    .child(Spinner::new())
                    .child("Waiting for operating-system authentication…"),
            ),
            SoftwareUpdateState::Installing => panel.child(
                h_flex()
                    .gap_2()
                    .child(Spinner::new())
                    .child("Stopping services and installing the verified update…"),
            ),
            SoftwareUpdateState::Failed(error) => panel
                .child(div().text_color(cx.theme().danger).child(error.clone()))
                .child(
                    Button::new("retry-software-update")
                        .label("Try again")
                        .on_click(cx.listener(|view, _, _, cx| view.check_for_updates(cx))),
                ),
        }
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
            Route::Updates => self.render_updates(cx),
            Route::Reviews => self.render_reviews(cx),
        }
    }

    fn render_review_overlay(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(active) = &self.active_review else {
            return div().into_any_element();
        };
        let generation = active.state.generation();
        let document = active.state.document();
        let approve_enabled = active.state.approve_enabled() && !active.awaiting_refresh;
        let can_refresh = matches!(
            active.completion,
            Some(ActiveReviewCompletion::Transaction(_))
        );
        let mut review_body = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .text_xl()
                    .font_semibold()
                    .child(document.request.title.clone()),
            )
            .child(document.request.summary.clone());
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
        for fact in &document.request.facts {
            review_body = review_body.child(
                div()
                    .flex()
                    .gap_3()
                    .child(div().w(px(150.0)).font_semibold().child(fact.label.clone()))
                    .child(div().flex_1().child(fact.value.clone())),
            );
        }
        for section in &document.request.sections {
            review_body =
                review_body.child(div().mt_3().font_semibold().child(section.heading.clone()));
            for fact in &section.facts {
                review_body = review_body.child(
                    div()
                        .flex()
                        .gap_3()
                        .child(div().w(px(150.0)).child(fact.label.clone()))
                        .child(div().flex_1().child(fact.value.clone())),
                );
            }
        }
        for warning in &document.request.warnings {
            review_body = review_body.child(
                div()
                    .p_3()
                    .rounded_lg()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(format!("Warning: {warning}")),
            );
        }
        if let Some(digest) = &document.request.digest {
            review_body = review_body.child(
                div()
                    .child("Digest")
                    .child(div().font_family("monospace").child(digest.clone())),
            );
        }
        for (index, payload) in document.exact_payloads.iter().enumerate() {
            review_body = review_body.child(
                div()
                    .mt_3()
                    .child(format!("Exact payload {}", index + 1))
                    .child(
                        div()
                            .mt_1()
                            .p_3()
                            .rounded_lg()
                            .border_1()
                            .border_color(cx.theme().border)
                            .font_family("monospace")
                            .whitespace_normal()
                            .child(payload.clone()),
                    ),
            );
        }
        if let Some(simulation) = &active.simulation {
            review_body = review_body
                .child(div().mt_3().font_semibold().child("Fresh simulation"))
                .child(format!(
                    "Block {} · success {} · policy {:?} · mode {:?}",
                    simulation.block_number,
                    simulation.simulation.success,
                    simulation.policy_outcome,
                    simulation.execution_mode
                ));
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
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(div().font_semibold().child("Security review").when(
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
                    ))
                    .child(
                        Button::new(("review-close", generation))
                            .label("Close")
                            .disabled(active.awaiting_refresh)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.send_review_command(generation, GuiReviewCommand::Close, cx);
                            })),
                    ),
            )
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
                    .child(review_body),
            )
            .child(
                div()
                    .flex()
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
                                    .label("Reject request")
                                    .danger()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.decide_review(generation, ReviewDecision::Reject, cx);
                                    })),
                            )
                            .child(
                                Button::new(("review-select-approve", generation))
                                    .label("Authenticate & approve")
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
            .when(pending.preview.is_some(), |panel| {
                panel.child("Review the exact configuration change. A timestamped backup is created before installation.")
            })
            .when(pending.remove_client_id.is_some(), |panel| {
                panel.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child("Removal also deletes this wallet registration and revokes all of its OAuth credentials after operating-system authentication. The configuration change is rolled back if authentication or database removal fails."),
                )
            })
            .when_some(pending.preview.as_ref(), |panel, preview| {
                panel.child(
                    div()
                        .id("agent-configuration-diff-scroll")
                        .flex_1()
                        .min_h_0()
                        .overflow_y_scrollbar()
                        .p_3()
                        .border_1()
                        .border_color(cx.theme().border)
                        .font_family("monospace")
                        .child(preview.exact_diff().to_owned()),
                )
            })
            .when(pending.preview.is_none(), |panel| {
                panel.child("No managed configuration file belongs to this registration. Only its encrypted wallet registration and OAuth credentials will be deleted.")
            })
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
                            .label(if pending.remove_client_id.is_some() {
                                "Authenticate & remove"
                            } else {
                                "Apply"
                            })
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
        let sections = review.sections.clone();
        let document_title = review.document.title();
        let document = gpui::list(review.list_state.clone(), move |index, _, _| {
            div()
                .w_full()
                .pr_3()
                .pb_3()
                .child(
                    TextView::markdown(
                        SharedString::from(format!("legal-markdown-{document_title}-{index}")),
                        sections[index].clone(),
                    )
                    .w_full()
                    .selectable(true),
                )
                .into_any_element()
        })
        .size_full();
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
                    .vertical_scrollbar(&review.list_state)
                    .child(document),
            )
            .when_some(review.error.clone(), |panel, error| {
                panel.child(div().text_sm().text_color(cx.theme().danger).child(error))
            })
            .child(
                div()
                    .flex()
                    .flex_shrink_0()
                    .flex_wrap()
                    .justify_between()
                    .child(
                        Button::new("close-legal-review")
                            .label("Close")
                            .disabled(self.legal_gate)
                            .on_click(cx.listener(|view, _, _, cx| {
                                if !view.legal_gate {
                                    view.legal_review = None;
                                    cx.notify();
                                }
                            })),
                    )
                    .child(div().flex().items_center().gap_2().when(
                        review.acceptance_required,
                        |buttons| {
                            buttons
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(if review.viewed_to_end {
                                            "Document read to end"
                                        } else {
                                            "Scroll to the end to accept"
                                        }),
                                )
                                .child(
                                    Button::new("accept-legal")
                                        .label("Accept")
                                        .primary()
                                        .disabled(!review.viewed_to_end)
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            view.accept_legal(cx);
                                        })),
                                )
                        },
                    )),
            )
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
                        .font_family("monospace")
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
        view.token_list_generation = view.token_list_generation.wrapping_add(1);
        view.account_id_input = None;
        view.private_key_input = None;
        view.walletconnect_uri_input = None;
        view.network_json_input = None;
        view.policy_json_input = None;
        view.policy_editor = None;
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
    let pending_software_update = Arc::new(Mutex::new(None::<PendingSoftwareUpdate>));
    let walletconnect = Arc::new(Mutex::new(
        crate::walletconnect::WalletConnectManager::default(),
    ));
    let (review_presenter, mut review_prompts) = GuiReviewPresenter::channel();
    let (walletconnect_presenter, mut walletconnect_prompts) = ProposalPresenter::channel();

    gpui_platform::application()
        .with_assets(gpui_component_assets::Assets)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
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
                _pending_software_update: pending_software_update.clone(),
            });
            let mut key_bindings = vec![
                KeyBinding::new("cmd-k", OpenCommandPalette, None),
                KeyBinding::new("ctrl-k", OpenCommandPalette, None),
                #[cfg(target_os = "macos")]
                KeyBinding::new("cmd-q", Quit, None),
                #[cfg(not(target_os = "macos"))]
                KeyBinding::new("ctrl-q", Quit, None),
            ];
            key_bindings.extend(Route::ALL.into_iter().map(|route| {
                KeyBinding::new(route.key_binding(), NavigateRoute { route }, None)
            }));
            cx.bind_keys(key_bindings);
            cx.on_action(|_: &Quit, cx| cx.quit());
            let shutdown_server = server_slot.clone();
            let shutdown_walletconnect = walletconnect.clone();
            let shutdown_update = pending_software_update.clone();
            let shutdown_instance = instance_slot.clone();
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
                let shutdown_update = shutdown_update.clone();
                let shutdown_instance = shutdown_instance.clone();
                async move {
                    if let Some(server) = server {
                        let _ = tokio.spawn(server.stop()).await;
                    }
                    let pending = shutdown_update
                        .lock()
                        .ok()
                        .and_then(|mut pending| pending.take());
                    if let Some(pending) = pending {
                        match tokio
                            .spawn_blocking(move || pending.update.install(pending.bytes))
                            .await
                        {
                            Ok(Ok(())) => {
                                let instance = shutdown_instance
                                    .lock()
                                    .ok()
                                    .and_then(|mut instance| instance.take());
                                drop(instance);
                                if let Err(error) = crate::updater::relaunch() {
                                    tracing::error!(%error, "verified update installed but relaunch failed");
                                }
                            }
                            Ok(Err(error)) => {
                                tracing::error!(%error, "verified software update installation failed");
                            }
                            Err(error) => {
                                tracing::error!(%error, "verified software update installation task failed");
                            }
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
                    detailed_notification_previews.clone(),
                    pending_software_update.clone(),
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
                                            format!(
                                                "Could not enable launch at login: {error:#}"
                                            ),
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
                                    owner.reviews(None).map_or(0, |queues| {
                                        review_queue_decision_count(&queues)
                                    }),
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
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                            }
                            TrayCommand::OpenRoute(route) => {
                                tray_view.update(cx, |view, cx| {
                                    view.set_route(route);
                                    cx.notify();
                                });
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                            }
                            TrayCommand::ConnectDapp => {
                                tray_view.update(cx, |view, cx| {
                                    view.set_route(Route::WalletConnect);
                                    cx.notify();
                                });
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                            }
                            TrayCommand::ReinstallAgents => {
                                tray_view.update(cx, |view, cx| {
                                    view.set_route(Route::Settings);
                                    view.reinstall_detected_agents_from_menu(cx);
                                });
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                            }
                            TrayCommand::CheckForUpdates => {
                                tray_view.update(cx, |view, cx| {
                                    view.set_route(Route::Updates);
                                    view.check_for_updates(cx);
                                    cx.notify();
                                });
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
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
