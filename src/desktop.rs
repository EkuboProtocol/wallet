use crate::{
    BUILD_VERSION,
    agent_config::{AgentAdapter, ConfigPreview},
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
    walletconnect::{
        ProposalCommand, ProposalPresenter, ProposalPrompt, WalletConnectManager, run_session,
    },
};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::approval::ReviewDecision;
use ekubo_wallet_core::config::NetworkConfig;
use ekubo_wallet_core::core::policy::{WalletPolicy, diff_policies};
use ekubo_wallet_core::custody::PrivateKeyMaterial;
use ekubo_wallet_core::desktop_store::AgentKind;
use ekubo_wallet_core::human_presence::OwnerAuthorization;
use ekubo_wallet_core::legal::{LegalDocument, LegalStatus};
use ekubo_wallet_core::message::MessageStatus;
use ekubo_wallet_core::pending::PendingStatus;
use ekubo_wallet_core::policy_store::PolicyProposal;
use ekubo_wallet_core::token_store::{StoredToken, TokenProposal};
use ekubo_wallet_core::typed_data::TypedDataStatus;
use gpui::{
    App, ClipboardItem, Context, Entity, FocusHandle, KeyBinding, MouseButton, QuitMode, Render,
    ScrollHandle, SharedString, Subscription, Task, Window, WindowAppearance, WindowBounds,
    WindowHandle, WindowOptions, actions, div, prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme, Disableable, FocusTrapElement, Icon, IconName, IndexPath, Root, StyledExt,
    WindowExt as _,
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
    time::Duration,
};
use tokio::sync::oneshot;

actions!(ekubo_wallet, [OpenCommandPalette, Quit]);

#[derive(Clone, PartialEq, gpui::Action)]
#[action(namespace = ekubo_wallet, no_json)]
struct NavigateRoute {
    route: Route,
}

struct DesktopRuntime {
    _instance: SingleInstance,
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

async fn upsert_detected_agents(owner: &OwnerApi, port: u16) -> Result<String> {
    let adapters = AgentAdapter::supported()?
        .into_iter()
        .filter(AgentAdapter::detected)
        .collect::<Vec<_>>();
    if adapters.is_empty() {
        return Ok("No supported agent installations were detected.".into());
    }
    let authorization = owner.authorize_agent_access().await?;
    let clients = owner.clients()?;
    let mut detected = 0_usize;
    let mut changed = 0_usize;
    let mut failures = Vec::new();
    for adapter in adapters {
        detected += 1;
        let existing = clients
            .iter()
            .rev()
            .find(|client| client.agent_kind == adapter.kind && client.revoked_at.is_none());
        let install_companion = existing
            .and_then(|client| client.registration.as_ref())
            .and_then(|registration| registration["install_companion"].as_bool())
            .unwrap_or(true);
        let mut created_client = None;
        let token = if let Some(client) = existing {
            owner.repair_client_token(client.id, &authorization)
        } else {
            let registration = serde_json::json!({
                "config_path": adapter.config_path,
                "install_companion": install_companion,
            });
            owner
                .register_client(
                    adapter.display_name,
                    adapter.kind,
                    Some(&registration),
                    &authorization,
                )
                .map(|registered| {
                    created_client = Some(registered.client.id);
                    registered.token
                })
        };
        let result = token.and_then(|token| {
            let token = zeroize::Zeroizing::new(token.expose_base64url());
            let preview = adapter.preview_install(port, &token, install_companion)?;
            if preview.has_changes() {
                preview.install()?;
                changed += 1;
            } else {
                preview.validate_current()?;
            }
            Ok(())
        });
        if let Err(error) = result {
            if let Some(client_id) = created_client {
                let _ = owner.remove_client(client_id, &authorization);
            }
            failures.push(format!("{}: {error:#}", adapter.display_name));
        }
    }
    ensure!(
        failures.is_empty(),
        "some detected agent configurations could not be updated: {}",
        failures.join("; ")
    );
    Ok(format!(
        "MCP server is installed for {detected} detected agent(s); {changed} configuration file(s) changed."
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        Self::Settings,
        Self::Updates,
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
            Self::Overview => "⌘P",
            Self::Reviews => "⌘R",
            Self::Activity => "⌘A",
            Self::Accounts => "⌘⇧A",
            Self::Policies => "⌘⇧P",
            Self::Networks => "⌘N",
            Self::Tokens => "⌘T",
            Self::WalletConnect => "⌘W",
            Self::Settings => "⌘,",
            Self::Updates => "⌘U",
        }
    }

    #[cfg(not(target_os = "macos"))]
    const fn shortcut(self) -> &'static str {
        match self {
            Self::Overview => "Ctrl+P",
            Self::Reviews => "Ctrl+R",
            Self::Activity => "Ctrl+A",
            Self::Accounts => "Ctrl+Shift+A",
            Self::Policies => "Ctrl+Shift+P",
            Self::Networks => "Ctrl+N",
            Self::Tokens => "Ctrl+T",
            Self::WalletConnect => "Ctrl+W",
            Self::Settings => "Ctrl+,",
            Self::Updates => "Ctrl+U",
        }
    }
}

// These flags describe independent controls and async operations. Combining
// them into one state machine would admit fewer valid combinations, not make
// the state safer.
#[allow(clippy::struct_excessive_bools)]
pub struct WalletWindow {
    owner: OwnerApi,
    review_presenter: GuiReviewPresenter,
    route: Route,
    command_palette: bool,
    command_palette_list: Option<Entity<ListState<RouteListDelegate>>>,
    command_palette_subscription: Option<Subscription>,
    token_list: Option<Entity<ListState<TokenListDelegate>>>,
    token_proposal_list: Option<Entity<ListState<TokenProposalListDelegate>>>,
    token_list_url_input: Option<Entity<InputState>>,
    token_import_state: TokenImportState,
    token_import_error: Option<SharedString>,
    token_import_status: Option<SharedString>,
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
    account_id_input: Option<Entity<InputState>>,
    private_key_input: Option<Entity<InputState>>,
    account_id_error: Option<SharedString>,
    private_key_error: Option<SharedString>,
    account_status: Option<SharedString>,
    account_export: Option<AccountExport>,
    legal_review: Option<LegalReview>,
    legal_gate: bool,
    operation_status: Option<SharedString>,
    detailed_notification_previews: Arc<AtomicBool>,
    portfolio: PortfolioState,
    portfolio_generation: u64,
    portfolio_chain_id: Option<u64>,
    modal_focus: FocusHandle,
    walletconnect: Arc<Mutex<WalletConnectManager>>,
    walletconnect_presenter: ProposalPresenter,
    walletconnect_uri_input: Option<Entity<InputState>>,
    network_json_input: Option<Entity<InputState>>,
    network_json_error: Option<SharedString>,
    policy_json_input: Option<Entity<InputState>>,
    policy_editor: Option<PolicyEditor>,
    policy_installing: bool,
    token_proposal_busy: bool,
    network_proposal_busy: bool,
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

// Document mode, layout readiness, deferred scroll measurement, and whether
// the end was reached are orthogonal facts during a review.
#[allow(clippy::struct_excessive_bools)]
struct LegalReview {
    document: LegalDocument,
    text: String,
    digest: String,
    acceptance_required: bool,
    scroll_handle: ScrollHandle,
    scroll_check_scheduled: bool,
    scroll_layout_ready: bool,
    viewed_to_end: bool,
}

struct AccountExport {
    wallet_id: String,
    lease: Option<ExportLease>,
    copied: bool,
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
    owner: OwnerApi,
    authorization: Arc<OwnerAuthorization>,
    completion: AgentConfigCompletion,
    committed: bool,
}

#[derive(Clone, Copy)]
enum AgentConfigCompletion {
    Install {
        client_id: uuid::Uuid,
    },
    Repair,
    Rotate {
        previous_client_id: uuid::Uuid,
        replacement_client_id: uuid::Uuid,
    },
    Remove {
        client_id: uuid::Uuid,
    },
}

impl Drop for PendingAgentInstall {
    fn drop(&mut self) {
        if !self.committed {
            match self.completion {
                AgentConfigCompletion::Install { client_id }
                | AgentConfigCompletion::Rotate {
                    replacement_client_id: client_id,
                    ..
                } => {
                    let _ = self.owner.remove_client(client_id, &self.authorization);
                }
                AgentConfigCompletion::Repair | AgentConfigCompletion::Remove { .. } => {}
            }
        }
    }
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
    all_tokens: Vec<StoredToken>,
    visible_tokens: Vec<StoredToken>,
    chain_filter: Option<u64>,
    query: String,
    loading: bool,
    error: Option<SharedString>,
    status: Option<TokenListStatus>,
    removing: BTreeSet<(u64, alloy::primitives::Address)>,
}

#[derive(Clone)]
enum TokenListStatus {
    Message(SharedString),
    Error(SharedString),
}

#[derive(Clone)]
struct ActivityFeedback {
    message: SharedString,
    error: bool,
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
    fn new(owner: OwnerApi) -> Self {
        Self {
            owner,
            all_tokens: Vec::new(),
            visible_tokens: Vec::new(),
            chain_filter: None,
            query: String::new(),
            loading: true,
            error: None,
            status: None,
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

    fn set_chain_filter(&mut self, chain_filter: Option<u64>) {
        self.chain_filter = chain_filter;
        self.apply_filters();
    }

    fn apply_filters(&mut self) {
        self.visible_tokens = self
            .all_tokens
            .iter()
            .filter(|token| token_matches_filter(token, self.chain_filter, &self.query))
            .cloned()
            .collect();
    }
}

fn token_matches_filter(token: &StoredToken, chain_filter: Option<u64>, query: &str) -> bool {
    if chain_filter.is_some_and(|chain| token.chain_id.parse::<u64>().ok() != Some(chain)) {
        return false;
    }
    let query = query.to_lowercase();
    query.is_empty()
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
        _: Option<IndexPath>,
        _: &mut Window,
        _: &mut Context<ListState<Self>>,
    ) {
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
        let owner = self.owner.clone();
        let state = cx.entity().downgrade();
        let removing = chain_id
            .zip(address)
            .is_some_and(|identity| self.removing.contains(&identity));
        let row_id = format!("token-{}-{}", token.chain_id, token.address);
        Some(
            ListItem::new(SharedString::from(row_id)).child(
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
                            ),
                    )
                    .child(
                        Button::new(("remove-token", index.row))
                            .label(if removing {
                                "Authenticating…"
                            } else {
                                "Remove"
                            })
                            .danger()
                            .disabled(chain_id.zip(address).is_none() || removing)
                            .on_click(move |_, _, cx| {
                                let Some((chain_id, address)) = chain_id.zip(address) else {
                                    return;
                                };
                                let _ = state.update(cx, |list, cx| {
                                    list.delegate_mut().removing.insert((chain_id, address));
                                    cx.notify();
                                });
                                let owner = owner.clone();
                                let state = state.clone();
                                let task = gpui_tokio::Tokio::spawn_result(cx, async move {
                                    owner.remove_token(chain_id, address).await
                                });
                                cx.spawn(async move |cx| {
                                    let result = task.await;
                                    let _ = state.update(cx, |list, cx| {
                                        let delegate = list.delegate_mut();
                                        delegate.removing.remove(&(chain_id, address));
                                        match result {
                                            Ok(removed) => {
                                                delegate.status =
                                                    Some(TokenListStatus::Message(if removed {
                                                        "Removed token metadata.".into()
                                                    } else {
                                                        "Token metadata was already absent.".into()
                                                    }));
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
                                                delegate.status = Some(TokenListStatus::Error(
                                                    format!("Could not remove token: {error:#}")
                                                        .into(),
                                                ));
                                            }
                                        }
                                        cx.notify();
                                    });
                                })
                                .detach();
                            }),
                    ),
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
        cx: &mut Context<Self>,
    ) -> Self {
        let mut window = Self {
            owner,
            review_presenter,
            route: Route::Overview,
            command_palette: false,
            command_palette_list: None,
            command_palette_subscription: None,
            token_list: None,
            token_proposal_list: None,
            token_list_url_input: None,
            token_import_state: TokenImportState::Idle,
            token_import_error: None,
            token_import_status: None,
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
            account_id_input: None,
            private_key_input: None,
            account_id_error: None,
            private_key_error: None,
            account_status: None,
            account_export: None,
            legal_review: None,
            legal_gate: false,
            operation_status: None,
            detailed_notification_previews,
            portfolio: PortfolioState::Idle,
            portfolio_generation: 0,
            portfolio_chain_id: None,
            modal_focus: cx.focus_handle(),
            walletconnect,
            walletconnect_presenter,
            walletconnect_uri_input: None,
            network_json_input: None,
            network_json_error: None,
            policy_json_input: None,
            policy_editor: None,
            policy_installing: false,
            token_proposal_busy: false,
            network_proposal_busy: false,
        };
        window.open_next_required_legal();
        window
    }

    fn attach_window(&mut self, window: &mut Window, cx: &mut Context<Self>) {
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
                            view.route = route;
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
                ListState::new(TokenListDelegate::new(owner), window, cx)
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

    fn connect_walletconnect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(input) = self.walletconnect_uri_input.as_ref() else {
            return;
        };
        let uri = input.read(cx).value().trim().to_owned();
        let start = match self
            .walletconnect
            .lock()
            .map_err(|_| anyhow::anyhow!("WalletConnect session state is unavailable"))
            .and_then(|mut manager| manager.begin_uri(&uri).map(|(start, _)| start))
        {
            Ok(start) => start,
            Err(error) => {
                self.operation_status = Some(format!("Could not connect: {error:#}").into());
                cx.notify();
                return;
            }
        };
        input.update(cx, |input, cx| input.set_value("", window, cx));
        self.owner
            .event_bus()
            .publish(crate::events::DomainEventKind::WalletConnectChanged {
                session_id: start.id.to_string(),
            });
        let owner = self.owner.clone();
        let presenter = self.walletconnect_presenter.clone();
        let manager = self.walletconnect.clone();
        let events = self.owner.event_bus();
        self.operation_status = Some("Connecting to the WalletConnect relay…".into());
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
                view.operation_status = Some(match result {
                    Ok(()) => "WalletConnect session ended.".into(),
                    Err(error) => format!("WalletConnect session failed: {error:#}").into(),
                });
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn disconnect_walletconnect(&mut self, session_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.operation_status = Some(match self.walletconnect.lock() {
            Ok(mut manager) => match manager.disconnect(session_id) {
                Ok(_) => "Disconnecting WalletConnect session…".into(),
                Err(error) => format!("Could not disconnect session: {error:#}").into(),
            },
            Err(_) => "WalletConnect session state is unavailable.".into(),
        });
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
            self.route = self.active_review_route();
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
        self.account_status = None;
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
                self.account_status = Some(
                    format!(
                        "Created account {} at {:#x}. Every transaction requires review.",
                        account.id, account.address
                    )
                    .into(),
                );
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
        self.account_status = None;
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
                self.account_status = Some(
                    format!("Imported account {} at {:#x}.", account.id, account.address).into(),
                );
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
        });
        cx.notify();
    }

    fn authenticate_account_export(&mut self, cx: &mut Context<Self>) {
        let Some(export) = self.account_export.as_ref() else {
            return;
        };
        let wallet_id = export.wallet_id.clone();
        let owner = self.owner.clone();
        self.operation_status = Some("Waiting for operating-system authentication…".into());
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
                            export.lease = Some(lease);
                            export.copied = false;
                            view.operation_status = Some(
                                "Private key revealed for 30 seconds. It has not been copied."
                                    .into(),
                            );
                        }
                    }
                    Err(error) => {
                        view.operation_status =
                            Some(format!("Private-key export cancelled: {error:#}").into());
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
            self.operation_status = Some("The private-key reveal has expired.".into());
            cx.notify();
            return;
        };
        cx.write_to_clipboard(ClipboardItem::new_string(value.to_string()));
        export.copied = true;
        self.operation_status = Some(
            "Copied explicitly. The clipboard will be conditionally cleared in 30 seconds.".into(),
        );
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
                        input.update(cx, |input, cx| input.set_value(document, window, cx));
                        self.policy_editor = Some(PolicyEditor {
                            wallet_id: wallet_id.to_owned(),
                            source_revision,
                            current_policy,
                            proposal: None,
                            validation: None,
                        });
                        self.operation_status = None;
                    }
                    Err(error) => {
                        self.operation_status =
                            Some(format!("Could not serialize policy: {error:#}").into());
                    }
                }
            }
            Err(error) => {
                self.operation_status = Some(format!("Could not read policy: {error:#}").into());
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
                        self.operation_status = Some(
                            "Opened the exact agent proposal. Review its rationale and permission diff before installing or rejecting it."
                                .into(),
                        );
                    }
                    Err(error) => {
                        self.operation_status =
                            Some(format!("Could not prepare proposal review: {error:#}").into());
                    }
                }
            }
            Err(error) => {
                self.operation_status =
                    Some(format!("Could not read the active policy: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn reject_policy_proposal(&mut self, proposal: &PolicyProposal, cx: &mut Context<Self>) {
        self.operation_status = Some(match self.owner.reject_policy_proposal(proposal) {
            Ok(true) => {
                if self
                    .policy_editor
                    .as_ref()
                    .and_then(|editor| editor.proposal.as_ref())
                    == Some(proposal)
                {
                    self.policy_editor = None;
                }
                format!("Rejected the policy proposal for {}.", proposal.wallet_id).into()
            }
            Ok(false) => "The proposal changed while it was open. Review the current one.".into(),
            Err(error) => format!("Could not reject proposal: {error:#}").into(),
        });
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
                self.operation_status = Some(
                    "Reset the draft to require explicit approval for every transaction. Validate the permission diff before installing."
                        .into(),
                );
            }
            Err(error) => {
                self.operation_status =
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
                self.operation_status = Some(
                    "Policy is valid and canonical. Review every permission change before installing."
                        .into(),
                );
                Ok(review)
            }
            Err(error) => {
                let message: SharedString = format!("Policy validation failed: {error:#}").into();
                self.operation_status = Some(message.clone());
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
            self.operation_status = Some("Validate the policy and review its diff first.".into());
            cx.notify();
            return;
        };
        if input.read(cx).value().as_ref() != review.document {
            self.operation_status = Some(
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
        self.operation_status = Some("Waiting for operating-system authentication…".into());
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
                        view.operation_status = Some(match proposal_cleanup {
                            Ok(_) => format!(
                                "Installed policy revision {} for {}.",
                                installed.revision, review.wallet_id
                            )
                            .into(),
                            Err(error) => format!(
                                "Installed policy revision {} for {}, but could not clear the superseded proposal: {error:#}",
                                installed.revision, review.wallet_id
                            )
                            .into(),
                        });
                    }
                    Err(error) => {
                        view.operation_status =
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
            self.operation_status = Some("Finish or close the current review first.".into());
            cx.notify();
            return;
        }
        match self.owner.account_removal_document(&wallet_id) {
            Ok(document) => {
                self.active_review = Some(ActiveReview {
                    state: ReviewState::new(document),
                    simulation: None,
                    completion: Some(ActiveReviewCompletion::AccountRemoval { wallet_id }),
                    awaiting_refresh: false,
                    scroll_handle: ScrollHandle::new(),
                    scroll_check_scheduled: false,
                    scroll_layout_ready: false,
                });
                self.operation_status = None;
            }
            Err(error) => {
                self.operation_status =
                    Some(format!("Could not prepare account removal: {error:#}").into());
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
        self.legal_review = Some(LegalReview {
            document,
            text,
            digest,
            acceptance_required,
            scroll_handle: ScrollHandle::new(),
            scroll_check_scheduled: false,
            scroll_layout_ready: false,
            viewed_to_end: false,
        });
        cx.notify();
    }

    fn open_next_required_legal(&mut self) {
        let document = match self.owner.legal_status() {
            Ok(status) => next_required_legal(&status),
            Err(_) => Some(LegalDocument::TermsOfService),
        };
        self.legal_gate = document.is_some();
        self.legal_review = document.map(|document| {
            let (text, digest) = self.owner.legal_document(document);
            LegalReview {
                document,
                text,
                digest,
                acceptance_required: true,
                scroll_handle: ScrollHandle::new(),
                scroll_check_scheduled: false,
                scroll_layout_ready: false,
                viewed_to_end: false,
            }
        });
    }

    fn update_legal_scroll_state(&mut self, cx: &mut Context<Self>) {
        let Some(review) = self.legal_review.as_mut() else {
            return;
        };
        if review.acceptance_required
            && review.scroll_layout_ready
            && !review.viewed_to_end
            && scroll_reached_end(
                review.scroll_handle.offset().y,
                review.scroll_handle.max_offset().y,
            )
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
        self.operation_status = Some(
            match self.owner.accept_legal(review.document, &review.digest) {
                Ok(()) => format!("Accepted the current {}.", review.document.title()).into(),
                Err(error) => format!("Could not accept document: {error:#}").into(),
            },
        );
        self.open_next_required_legal();
        if !self.legal_gate
            && let Ok(Some(port)) = self.owner.mcp_port()
        {
            self.reinstall_detected_agents(port, cx);
        }
        cx.notify();
    }

    fn reinstall_detected_agents(&mut self, port: u16, cx: &mut Context<Self>) {
        if self.agent_reinstall == AgentReinstallState::Running {
            self.operation_status = Some("Agent configuration repair is already running.".into());
            cx.notify();
            return;
        }
        self.agent_reinstall = AgentReinstallState::Running;
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            upsert_detected_agents(&owner, port).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.agent_reinstall = AgentReinstallState::Idle;
                if let Err(error) = result {
                    view.operation_status =
                        Some(format!("Could not reinstall MCP server: {error:#}").into());
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn reinstall_detected_agents_from_menu(&mut self, cx: &mut Context<Self>) {
        if self.legal_gate {
            self.operation_status = Some(
                "Accept the current Terms and Privacy Policy before installing agents.".into(),
            );
            cx.notify();
            return;
        }
        match self.owner.mcp_port() {
            Ok(Some(port)) => self.reinstall_detected_agents(port, cx),
            Ok(None) => {
                self.operation_status = Some("MCP is still selecting its loopback port.".into());
                cx.notify();
            }
            Err(error) => {
                self.operation_status = Some(format!("Could not read MCP port: {error:#}").into());
                cx.notify();
            }
        }
    }

    fn refresh_portfolio(&mut self, cx: &mut Context<Self>) {
        if self.legal_gate || matches!(self.portfolio, PortfolioState::Loading) {
            return;
        }
        let Some(chain_id) = self.portfolio_chain_id else {
            self.operation_status = Some("Select a network before loading balances.".into());
            cx.notify();
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
                input.update(cx, |input, cx| input.set_value(document, window, cx));
                self.network_json_error = None;
                self.operation_status = Some(format!("Editing network {}.", network.name).into());
            }
            Err(error) => {
                self.operation_status =
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
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            let name = network.name.clone();
            owner.install_network(network).await.map(|()| name)
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.operation_status = Some(match result {
                    Ok(name) => format!("Installed network {name}.").into(),
                    Err(error) => {
                        view.network_json_error =
                            Some(format!("Network was not installed: {error:#}").into());
                        format!("Could not install network: {error:#}").into()
                    }
                });
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
        let owner = self.owner.clone();
        self.operation_status = Some("Waiting for operating-system authentication…".into());
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.set_network_disabled(&name, disabled).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                let changed = result.is_ok();
                view.operation_status = Some(match result {
                    Ok(network) if disabled => format!("Disabled network {}.", network.name).into(),
                    Ok(network) => format!("Enabled network {}.", network.name).into(),
                    Err(error) => format!("Could not update network: {error:#}").into(),
                });
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

    fn remove_network(&mut self, name: &str, cx: &mut Context<Self>) {
        let owner = self.owner.clone();
        let name = name.to_owned();
        self.operation_status = Some("Waiting for operating-system authentication…".into());
        let task =
            gpui_tokio::Tokio::spawn_result(cx, async move { owner.remove_network(&name).await });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.operation_status = Some(match result {
                    Ok(network) => format!("Deleted disabled network {}.", network.name).into(),
                    Err(error) => format!("Could not delete network: {error:#}").into(),
                });
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
        self.operation_status =
            Some("Verifying the proposed RPC chain ID before owner authentication…".into());
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
                view.operation_status = Some(match result {
                    Ok(proposal) => format!(
                        "Installed network {} after verifying chain {}.",
                        proposal.name, proposal.chain_id
                    )
                    .into(),
                    Err(error) => format!("Network proposal was not installed: {error:#}").into(),
                });
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn reject_network_proposal(&mut self, proposal: &NetworkConfig, cx: &mut Context<Self>) {
        self.operation_status = Some(match self.owner.reject_network_proposal(proposal) {
            Ok(true) => format!("Rejected network proposal {}.", proposal.name).into(),
            Ok(false) => "The network proposal changed. Review the current profile.".into(),
            Err(error) => format!("Could not reject network proposal: {error:#}").into(),
        });
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
        let requested_chains = self
            .token_list
            .as_ref()
            .and_then(|list| list.read(cx).delegate().chain_filter)
            .into_iter()
            .collect::<Vec<_>>();
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
        let Some(source) = source else {
            return;
        };
        if !viewed_to_end {
            self.operation_status =
                Some("Scroll through the complete token proposal before accepting it.".into());
            cx.notify();
            return;
        }
        let owner = self.owner.clone();
        self.token_proposal_busy = true;
        self.operation_status = Some("Waiting for operating-system authentication…".into());
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
                view.operation_status = Some(match result {
                    Ok(inserted) => {
                        format!("Accepted {inserted} new token name(s) from {source}.").into()
                    }
                    Err(error) => format!("Token proposals were not accepted: {error:#}").into(),
                });
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
        let Some(source) = source else {
            return;
        };
        let owner = self.owner.clone();
        self.token_proposal_busy = true;
        self.operation_status = Some("Rejecting the exact token proposal rows…".into());
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
                view.operation_status = Some(match result {
                    Ok(removed) => {
                        format!("Rejected {removed} token proposal(s) from {source}.").into()
                    }
                    Err(error) => format!("Could not reject token proposals: {error:#}").into(),
                });
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

    fn revoke_agent(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.operation_status = Some("Waiting for operating-system authentication…".into());
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            let authorization = owner.authorize_agent_access().await?;
            owner.revoke_client(client_id, &authorization)
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.operation_status = Some(match result {
                    Ok(()) => "Revoked the agent token immediately.".into(),
                    Err(error) => format!("Could not revoke agent: {error:#}").into(),
                });
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn prepare_agent_repair(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.prepare_existing_agent_change(client_id, false, false, cx);
    }

    fn prepare_detected_agent_install(&mut self, kind: AgentKind, cx: &mut Context<Self>) {
        if self.pending_agent_install.is_some()
            || self.agent_reinstall == AgentReinstallState::Running
        {
            self.operation_status = Some("Finish the current agent change first.".into());
            cx.notify();
            return;
        }
        self.agent_reinstall = AgentReinstallState::Running;
        self.operation_status = Some("Waiting for operating-system authentication…".into());
        let owner = self.owner.clone();
        let task =
            gpui_tokio::Tokio::spawn_result(
                cx,
                async move { owner.authorize_agent_access().await },
            );
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.agent_reinstall = AgentReinstallState::Idle;
                match result {
                    Ok(authorization) => view.prepare_detected_agent_install_authorized(
                        kind,
                        Arc::new(authorization),
                        cx,
                    ),
                    Err(error) => {
                        view.operation_status =
                            Some(format!("Agent change was not authorized: {error:#}").into());
                        cx.notify();
                    }
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn prepare_detected_agent_install_authorized(
        &mut self,
        kind: AgentKind,
        authorization: Arc<OwnerAuthorization>,
        cx: &mut Context<Self>,
    ) {
        let clients = match self.owner.clients() {
            Ok(clients) => clients,
            Err(error) => {
                self.operation_status =
                    Some(format!("Could not inspect agent registrations: {error:#}").into());
                cx.notify();
                return;
            }
        };
        if let Some(client) = clients
            .iter()
            .rev()
            .find(|client| client.agent_kind == kind && client.revoked_at.is_none())
        {
            self.prepare_existing_agent_change_authorized(
                client.id,
                false,
                false,
                authorization,
                cx,
            );
            return;
        }

        let result = (|| -> Result<PendingAgentInstall> {
            let adapter = AgentAdapter::supported()?
                .into_iter()
                .find(|adapter| adapter.kind == kind)
                .context("the selected agent has no managed configuration adapter")?;
            ensure!(
                adapter.detected(),
                "the selected agent is no longer detected"
            );
            let port = self
                .owner
                .mcp_port()?
                .context("the MCP server has not selected its loopback port yet")?;
            let registration = serde_json::json!({
                "config_path": adapter.config_path,
                "install_companion": true,
            });
            let registered = self.owner.register_client(
                adapter.display_name,
                adapter.kind,
                Some(&registration),
                &authorization,
            )?;
            let client_id = registered.client.id;
            let token = zeroize::Zeroizing::new(registered.token.expose_base64url());
            let mut preview = match adapter.preview_install(port, &token, true) {
                Ok(preview) => preview,
                Err(error) => {
                    let _ = self.owner.remove_client(client_id, &authorization);
                    return Err(error);
                }
            };
            preview.redact_diff_secret(&token);
            Ok(PendingAgentInstall {
                display_name: format!("Install {}", adapter.display_name),
                preview: Some(preview),
                owner: self.owner.clone(),
                authorization,
                completion: AgentConfigCompletion::Install { client_id },
                committed: false,
            })
        })();
        match result {
            Ok(pending) => {
                self.pending_agent_install = Some(pending);
                self.operation_status = None;
            }
            Err(error) => {
                self.operation_status =
                    Some(format!("Could not prepare agent installation: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn prepare_agent_rotation(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.prepare_existing_agent_change(client_id, true, false, cx);
    }

    fn prepare_agent_removal(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.prepare_existing_agent_change(client_id, false, true, cx);
    }

    fn prepare_existing_agent_change(
        &mut self,
        client_id: uuid::Uuid,
        rotate: bool,
        remove: bool,
        cx: &mut Context<Self>,
    ) {
        if self.pending_agent_install.is_some() {
            self.operation_status = Some("Finish the current agent change first.".into());
            cx.notify();
            return;
        }
        self.agent_reinstall = AgentReinstallState::Running;
        self.operation_status = Some("Waiting for operating-system authentication…".into());
        let owner = self.owner.clone();
        let task =
            gpui_tokio::Tokio::spawn_result(
                cx,
                async move { owner.authorize_agent_access().await },
            );
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.agent_reinstall = AgentReinstallState::Idle;
                match result {
                    Ok(authorization) => view.prepare_existing_agent_change_authorized(
                        client_id,
                        rotate,
                        remove,
                        Arc::new(authorization),
                        cx,
                    ),
                    Err(error) => {
                        view.operation_status =
                            Some(format!("Agent change was not authorized: {error:#}").into());
                        cx.notify();
                    }
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn prepare_existing_agent_change_authorized(
        &mut self,
        client_id: uuid::Uuid,
        rotate: bool,
        remove: bool,
        authorization: Arc<OwnerAuthorization>,
        cx: &mut Context<Self>,
    ) {
        let result = (|| -> Result<PendingAgentInstall> {
            let client = self
                .owner
                .clients()?
                .into_iter()
                .find(|client| client.id == client_id)
                .context("the selected agent registration no longer exists")?;
            ensure!(client.revoked_at.is_none(), "the selected agent is revoked");
            let install_companion = client
                .registration
                .as_ref()
                .and_then(|registration| registration["install_companion"].as_bool())
                .unwrap_or(true);
            let adapter = AgentAdapter::supported()?
                .into_iter()
                .find(|adapter| adapter.kind == client.agent_kind)
                .context("the selected agent has no managed configuration adapter")?;
            if remove {
                return Ok(PendingAgentInstall {
                    display_name: format!("Remove {}", adapter.display_name),
                    preview: Some(adapter.preview_remove(false)?),
                    owner: self.owner.clone(),
                    authorization,
                    completion: AgentConfigCompletion::Remove { client_id },
                    committed: false,
                });
            }
            let port = self
                .owner
                .mcp_port()?
                .context("the MCP server has not selected its loopback port yet")?;
            if rotate {
                let registration = serde_json::json!({
                    "config_path": adapter.config_path,
                    "install_companion": install_companion,
                });
                let replacement = self.owner.register_client(
                    adapter.display_name,
                    adapter.kind,
                    Some(&registration),
                    &authorization,
                )?;
                let replacement_id = replacement.client.id;
                let token = zeroize::Zeroizing::new(replacement.token.expose_base64url());
                let mut preview = match adapter.preview_install(port, &token, install_companion) {
                    Ok(preview) => preview,
                    Err(error) => {
                        let _ = self.owner.remove_client(replacement_id, &authorization);
                        return Err(error);
                    }
                };
                preview.redact_diff_secret(&token);
                return Ok(PendingAgentInstall {
                    display_name: format!("Rotate {} token", adapter.display_name),
                    preview: Some(preview),
                    owner: self.owner.clone(),
                    authorization,
                    completion: AgentConfigCompletion::Rotate {
                        previous_client_id: client_id,
                        replacement_client_id: replacement_id,
                    },
                    committed: false,
                });
            }
            let token = zeroize::Zeroizing::new(
                self.owner
                    .repair_client_token(client_id, &authorization)?
                    .expose_base64url(),
            );
            let mut preview = adapter.preview_install(port, &token, install_companion)?;
            preview.redact_diff_secret(&token);
            Ok(PendingAgentInstall {
                display_name: format!("Repair {}", adapter.display_name),
                preview: Some(preview),
                owner: self.owner.clone(),
                authorization,
                completion: AgentConfigCompletion::Repair,
                committed: false,
            })
        })();
        match result {
            Ok(pending) => {
                self.pending_agent_install = Some(pending);
                self.operation_status = None;
            }
            Err(error) => {
                self.operation_status =
                    Some(format!("Could not prepare agent change: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn cancel_agent_install(&mut self, cx: &mut Context<Self>) {
        if self.pending_agent_install.take().is_some() {
            self.operation_status = Some("Agent installation cancelled.".into());
        }
        cx.notify();
    }

    fn confirm_agent_install(&mut self, cx: &mut Context<Self>) {
        let Some(mut pending) = self.pending_agent_install.take() else {
            return;
        };
        let display_name = pending.display_name.clone();
        let result = pending
            .preview
            .take()
            .expect("a pending installation always has its preview")
            .install();
        self.operation_status = Some(match result {
            Ok(backup) => {
                pending.committed = true;
                let database_result = match pending.completion {
                    AgentConfigCompletion::Install { .. } | AgentConfigCompletion::Repair => Ok(()),
                    AgentConfigCompletion::Rotate {
                        previous_client_id, ..
                    }
                    | AgentConfigCompletion::Remove {
                        client_id: previous_client_id,
                    } => pending
                        .owner
                        .remove_client(previous_client_id, &pending.authorization),
                };
                match database_result {
                    Ok(()) if backup.as_os_str().is_empty() => {
                        format!("Completed {display_name} configuration change.").into()
                    }
                    Ok(()) => format!(
                        "Completed {display_name} configuration change. Backup: {}",
                        backup.display()
                    )
                    .into(),
                    Err(error) => {
                        format!("Configuration changed, but registration cleanup failed: {error:#}")
                            .into()
                    }
                }
            }
            Err(error) => format!("Could not install {display_name}: {error:#}").into(),
        });
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
            self.operation_status = Some("Finish or close the current review first.".into());
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
                self.operation_status = None;
            }
            Err(error) => {
                self.operation_status =
                    Some(format!("Could not open message review: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn begin_typed_data_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy {
            self.operation_status = Some("Finish or close the current review first.".into());
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
                self.operation_status = None;
            }
            Err(error) => {
                self.operation_status =
                    Some(format!("Could not open typed-data review: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn begin_transaction_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        if self.active_review.is_some() || self.review_flow == ReviewFlowState::Busy {
            self.operation_status = Some("Finish or close the current review first.".into());
            cx.notify();
            return;
        }
        self.operation_status = Some(format!("Opening review {request_id}…").into());
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
                    view.operation_status = Some(match result {
                        Ok(ekubo_wallet_core::orchestrator::ApprovalOutcome::Signed(_)) => {
                            "Review approved and transaction signed.".into()
                        }
                        Ok(ekubo_wallet_core::orchestrator::ApprovalOutcome::Rejected(_)) => {
                            "Review rejected. No signature was produced.".into()
                        }
                        Err(error) if error.to_string().contains("closed without a decision") => {
                            "Review closed. The request remains pending.".into()
                        }
                        Err(error) => format!("Review failed: {error:#}").into(),
                    });
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

    fn select_review(&mut self, generation: u64, decision: ReviewDecision, cx: &mut Context<Self>) {
        if self
            .active_review
            .as_mut()
            .is_some_and(|review| review.state.select(generation, decision))
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
                    self.operation_status = Some("The review request is no longer active.".into());
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
                    self.operation_status = Some("The review request is no longer active.".into());
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
                self.operation_status = Some("Review closed. The request remains pending.".into());
            }
            (
                GuiReviewCommand::Close | GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::AccountRemoval { .. }),
            ) => {
                self.active_review = None;
                self.operation_status = Some("Account removal cancelled.".into());
            }
            (
                GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::Message { request_id, .. }),
            ) => {
                self.active_review = None;
                self.operation_status = Some(match owner.reject_message(request_id) {
                    Ok(_) => "Message signature rejected.".into(),
                    Err(error) => format!("Could not reject message: {error:#}").into(),
                });
            }
            (
                GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::TypedData { request_id, .. }),
            ) => {
                self.active_review = None;
                self.operation_status = Some(match owner.reject_typed_data(request_id) {
                    Ok(_) => "Typed-data signature rejected.".into(),
                    Err(error) => format!("Could not reject typed data: {error:#}").into(),
                });
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
                        view.operation_status = Some(match result {
                            Ok(_) => "Message reviewed, authenticated, and signed.".into(),
                            Err(error) => format!("Message signing failed: {error:#}").into(),
                        });
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
                        view.operation_status = Some(match result {
                            Ok(_) => "Typed data reviewed, authenticated, and signed.".into(),
                            Err(error) => format!("Typed-data signing failed: {error:#}").into(),
                        });
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
                        view.operation_status = Some(match result {
                            Ok(_) => {
                                format!("Removed account {wallet_id} and its local policy.").into()
                            }
                            Err(error) => format!("Could not remove account: {error:#}").into(),
                        });
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
                    self.operation_status =
                        Some("The connection proposal is no longer active.".into());
                }
            }
            (
                GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::WalletConnect { response, .. }),
            ) => {
                self.active_review = None;
                let _ = response.send(ProposalCommand::Reject);
                self.operation_status = Some("WalletConnect proposal rejected.".into());
            }
            (
                GuiReviewCommand::Close,
                Some(ActiveReviewCompletion::WalletConnect { response, .. }),
            ) => {
                self.active_review = None;
                let _ = response.send(ProposalCommand::Close);
                self.operation_status = Some("WalletConnect proposal closed and declined.".into());
            }
            (GuiReviewCommand::Refresh, completion) => {
                active.completion = completion;
                self.operation_status =
                    Some("Only transaction reviews can be re-simulated.".into());
            }
            (_, None) => {
                self.operation_status = Some("The review request is no longer active.".into());
                self.active_review = None;
            }
        }
        if wait_for_flow {
            self.review_flow = ReviewFlowState::Busy;
        }
        self.activate_next_queued_review();
        if self.active_review.is_some() {
            self.route = self.active_review_route();
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

    fn navigate_route(&mut self, action: &NavigateRoute, _: &mut Window, cx: &mut Context<Self>) {
        if self.legal_gate {
            return;
        }
        self.route = action.route;
        self.command_palette = false;
        cx.notify();
    }

    fn set_detailed_notification_previews(&mut self, enabled: bool, cx: &mut Context<Self>) {
        self.operation_status = Some("Waiting for operating-system authentication…".into());
        let owner = self.owner.clone();
        let task = gpui_tokio::Tokio::spawn_result(cx, async move {
            owner.set_detailed_notification_previews(enabled).await
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                match result {
                    Ok(()) => {
                        view.detailed_notification_previews
                            .store(enabled, Ordering::Relaxed);
                        view.operation_status = Some(
                            if enabled {
                                "Notification previews may now include request identifiers."
                            } else {
                                "Notification previews are now lock-screen safe."
                            }
                            .into(),
                        );
                    }
                    Err(error) => {
                        view.operation_status = Some(
                            format!("Could not save notification preference: {error:#}").into(),
                        );
                    }
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
        match self.owner.reviews(None) {
            Ok(queues) => {
                let total = review_queue_decision_count(&queues);
                content = content.child(format!("{total} request(s) awaiting an owner decision"));
                for request in queues.transactions {
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
                for request in queues.typed_data {
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
                for request in queues.messages {
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
                for proposal in queues.policy_proposals {
                    let wallet_id = proposal.wallet_id;
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
                                        view.route = Route::Policies;
                                        cx.notify();
                                    })),
                                ),
                        );
                }
                for proposal in queues.network_proposals {
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
                                        view.route = Route::Networks;
                                        cx.notify();
                                    })),
                                ),
                        );
                }
                let mut token_groups = std::collections::BTreeMap::<String, usize>::new();
                for proposal in queues.token_proposals {
                    *token_groups.entry(proposal.source).or_default() += 1;
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
                                        view.route = Route::Tokens;
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
                let document = self.owner.message_review_document(request_id);
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
                        detail =
                            detail.children(document.exact_payloads.into_iter().map(|payload| {
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
                            }));
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
                let document = self.owner.typed_data_review_document(request_id);
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
                        detail =
                            detail.children(document.exact_payloads.into_iter().map(|payload| {
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
                            }));
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
        let items = match self.owner.activity(None, 200) {
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
        panel.children(items.into_iter().map(|record| {
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
        let clients = self.owner.clients().unwrap_or_default();
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
                "Registered, not yet used".into()
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
                                                "rotate-agent-{client_id}"
                                            )))
                                            .label("Rotate token")
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.prepare_agent_rotation(client_id, cx);
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
        let adapters = match AgentAdapter::supported() {
            Ok(adapters) => adapters,
            Err(error) => {
                return div().child(Alert::error(
                    "agent-detection-error",
                    format!("Agent detection unavailable: {error:#}"),
                ));
            }
        };
        let mut detected = 0;
        for adapter in adapters.into_iter().filter(AgentAdapter::detected) {
            detected += 1;
            let installed = clients
                .iter()
                .any(|client| client.agent_kind == adapter.kind && client.revoked_at.is_none());
            let display_name = adapter.display_name;
            let config_path = adapter.config_path.display().to_string();
            let kind = adapter.kind;
            agents = agents.child(
                ListItem::new(SharedString::from(format!("detected-agent-{detected}"))).child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .gap_4()
                        .child(
                            div().flex_1().min_w_0().child(display_name).child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .truncate()
                                    .child(config_path),
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
                                        } else {
                                            "Not installed"
                                        }),
                                )
                                .child(
                                    Button::new(SharedString::from(format!(
                                        "install-detected-agent-{detected}"
                                    )))
                                    .label(if installed { "Reinstall" } else { "Install" })
                                    .disabled(
                                        self.legal_gate
                                            || self.agent_reinstall == AgentReinstallState::Running,
                                    )
                                    .when(!installed, ButtonVariants::primary)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.prepare_detected_agent_install(kind, cx);
                                    })),
                                ),
                        ),
                ),
            );
        }
        if detected == 0 {
            agents = agents.child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("No supported agent installation was detected."),
            );
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
                            .child("Agent tokens protect this endpoint from accidental or unauthorized local clients. Plaintext loopback HTTP cannot protect against malicious code already running as your OS user."),
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
                                    .tooltip("Include request identifiers in lifecycle notifications")
                                    .on_click(cx.listener(|view, checked, _, cx| {
                                        view.set_detailed_notification_previews(*checked, cx);
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
            .child(div().font_semibold().child("Create account"));
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
        panel = panel.when_some(self.account_status.clone(), |panel, status| {
            panel.child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(status),
            )
        });
        panel = panel.child(
            div()
                .mt_3()
                .font_semibold()
                .child("Accounts on this device"),
        );
        match self.owner.accounts() {
            Ok(items) if items.is_empty() => panel.child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("No accounts yet."),
            ),
            Ok(items) => {
                panel.children(items.into_iter().map(|item| {
                    let export_id = item.id.clone();
                    let removal_id = item.id.clone();
                    div()
                        .py_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
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
                        )
                }))
            }
            Err(error) => panel.child(format!("Accounts unavailable: {error:#}")),
        }
    }

    fn render_policies(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div().h_full().min_h(px(520.0)).flex().flex_col().gap_4();
        let accounts = match self.owner.accounts() {
            Ok(accounts) => accounts,
            Err(error) => {
                return content.child(Alert::error(
                    "policy-account-error",
                    format!("Accounts unavailable: {error:#}"),
                ));
            }
        };
        match self.owner.policy_proposals() {
            Ok(proposals) if !proposals.is_empty() => {
                let mut proposal_list = div().flex().flex_col().gap_3();
                for proposal in proposals {
                    let current = self.owner.policy(&proposal.wallet_id).ok().flatten();
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
                                view.route = Route::Accounts;
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
        match self.owner.legal_status() {
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
                    .gap_2()
                    .child(Input::new(input).flex_1())
                    .child(
                        Button::new("connect-walletconnect")
                            .label("Connect")
                            .primary()
                            .on_click(cx.listener(|view, _, window, cx| {
                                view.connect_walletconnect(window, cx);
                            })),
                    ),
            );
        }
        let sessions = self
            .walletconnect
            .lock()
            .map(|manager| manager.sessions())
            .unwrap_or_default();
        if sessions.is_empty() {
            return panel.child("No active WalletConnect sessions.");
        }
        panel.children(sessions.into_iter().map(|session| {
            let session_id = session.id;
            div()
                .py_2()
                .border_t_1()
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
        match self.owner.network_proposals() {
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
            );
        }
        match self.owner.networks() {
            Ok(networks) => {
                content.children(networks.into_iter().map(|network| {
                    let name = network.name.clone();
                    let edit = network.clone();
                    let toggle_name = name.clone();
                    let remove_name = name.clone();
                    let disabled = network.disabled;
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
                                            div().font_semibold().child(
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
                                                    "{} · chain {} · {}",
                                                    name,
                                                    network.chain_id,
                                                    if disabled { "Disabled" } else { "Enabled" }
                                                )),
                                        ),
                                )
                                .child(
                                    h_flex()
                                        .gap_2()
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "edit-network-{name}"
                                            )))
                                            .label("Edit")
                                            .on_click(cx.listener(move |view, _, window, cx| {
                                                view.edit_network(&edit, window, cx);
                                            })),
                                        )
                                        .child(
                                            Button::new(SharedString::from(format!(
                                                "toggle-network-{name}"
                                            )))
                                            .label(if disabled { "Enable" } else { "Disable" })
                                            .on_click(cx.listener(move |view, _, _, cx| {
                                                view.set_network_disabled(
                                                    &toggle_name,
                                                    !disabled,
                                                    cx,
                                                );
                                            })),
                                        )
                                        .when(disabled, |buttons| {
                                            buttons.child(
                                                Button::new(SharedString::from(format!(
                                                    "delete-network-{name}"
                                                )))
                                                .label("Delete")
                                                .danger()
                                                .on_click(cx.listener(move |view, _, _, cx| {
                                                    view.remove_network(&remove_name, cx);
                                                })),
                                            )
                                        }),
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
                        )
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
                                view.route = Route::Accounts;
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
                                let mut balances = div().flex().flex_col().gap_2();
                                if portfolio.native_balance != "0" {
                                    balances = balances.child(
                                        div()
                                            .py_2()
                                            .border_b_1()
                                            .border_color(cx.theme().border)
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
                                            .border_b_1()
                                            .border_color(cx.theme().border)
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
        let active_chain = delegate.chain_filter;
        let visible = delegate.visible_tokens.len();
        let total = delegate.all_tokens.len();
        let token_status = delegate.status.clone();
        let networks = self.owner.networks().unwrap_or_default();
        let (selected_source, selected_count, viewed_to_end) = {
            let delegate = proposal_list.read(cx).delegate();
            (
                delegate.source.clone(),
                delegate.proposals.len(),
                delegate.viewed_to_end,
            )
        };

        let mut content = div().flex().flex_col().flex_1().min_h(px(320.0)).gap_3();
        if let Some(input) = self.token_list_url_input.as_ref() {
            let selection = active_chain.map_or_else(
                || "all enabled networks".to_owned(),
                |chain_id| format!("chain {chain_id}"),
            );
            content = content.child(
                GroupBox::new()
                    .id("owner-token-list-import")
                    .outline()
                    .title("Import published token list")
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "Fetch a public HTTPS token-list JSON for {selection}. Nothing is trusted until you inspect and accept the exact resulting list below."
                            )),
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
        match self.owner.token_proposals() {
            Ok(proposals) if !proposals.is_empty() => {
                let mut grouped = std::collections::BTreeMap::<String, Vec<TokenProposal>>::new();
                for proposal in proposals {
                    grouped
                        .entry(proposal.source.clone())
                        .or_default()
                        .push(proposal);
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
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        Button::new("token-network-all")
                            .label("All networks")
                            .when(active_chain.is_none(), ButtonVariants::primary)
                            .on_click({
                                let list = list.clone();
                                move |_, _, cx| {
                                    list.update(cx, |list, cx| {
                                        list.delegate_mut().set_chain_filter(None);
                                        cx.notify();
                                    });
                                }
                            }),
                    )
                    .children(networks.into_iter().map(|network| {
                        let chain_id = network.chain_id;
                        let list = list.clone();
                        Button::new(SharedString::from(format!("token-network-{chain_id}")))
                            .label(network.display_name.unwrap_or(network.name))
                            .when(active_chain == Some(chain_id), ButtonVariants::primary)
                            .on_click(move |_, _, cx| {
                                list.update(cx, |list, cx| {
                                    list.delegate_mut().set_chain_filter(Some(chain_id));
                                    cx.notify();
                                });
                            })
                    })),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(format!("Showing {visible} of {total} token(s)")),
            )
            .when_some(token_status, |content, status| match status {
                TokenListStatus::Message(message) => content.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(message),
                ),
                TokenListStatus::Error(error) => {
                    content.child(div().text_sm().text_color(cx.theme().danger).child(error))
                }
            })
            .child(
                List::new(list)
                    .search_placeholder("Search token name, symbol, or address")
                    .flex_1()
                    .min_h(px(260.0))
                    .w_full()
                    .border_1()
                    .border_color(cx.theme().border)
                    .rounded(cx.theme().radius),
            )
    }

    fn route_panel(&self, cx: &mut Context<Self>) -> gpui::Div {
        let panel = div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_2();
        match self.route {
            Route::Overview => self.render_portfolio(cx),
            Route::Activity => self.render_activity(cx),
            Route::Accounts => self.render_accounts(cx),
            Route::Policies => self.render_policies(cx),
            Route::Networks => self.render_networks(cx),
            Route::Tokens => self.render_tokens(cx),
            Route::WalletConnect => self.render_walletconnect(cx),
            Route::Settings => self.render_settings(cx),
            Route::Updates => panel
                .child(format!("Installed version: {BUILD_VERSION}"))
                .child("Updates are downloaded and signature-verified only after confirmation."),
            Route::Reviews => self.render_reviews(cx),
        }
    }

    fn render_review_overlay(&self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let Some(active) = &self.active_review else {
            return div().into_any_element();
        };
        let generation = active.state.generation();
        let document = active.state.document();
        let selected = active.state.selected();
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
                                    .label("Reject")
                                    .when(
                                        selected == ReviewDecision::Reject,
                                        ButtonVariants::primary,
                                    )
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.select_review(generation, ReviewDecision::Reject, cx);
                                    })),
                            )
                            .child(
                                Button::new(("review-select-approve", generation))
                                    .label("Approve")
                                    .disabled(!approve_enabled)
                                    .when(
                                        selected == ReviewDecision::Approve,
                                        ButtonVariants::primary,
                                    )
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.select_review(generation, ReviewDecision::Approve, cx);
                                    })),
                            )
                            .child(
                                Button::new(("review-confirm", generation))
                                    .label(if selected == ReviewDecision::Reject {
                                        "Reject request"
                                    } else {
                                        "Authenticate & approve"
                                    })
                                    .danger()
                                    .when(
                                        selected == ReviewDecision::Approve,
                                        ButtonVariants::primary,
                                    )
                                    .disabled(
                                        active.awaiting_refresh
                                            || (selected == ReviewDecision::Approve
                                                && !approve_enabled),
                                    )
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        let command = if selected == ReviewDecision::Reject {
                                            GuiReviewCommand::Reject
                                        } else {
                                            GuiReviewCommand::Approve
                                        };
                                        view.send_review_command(generation, command, cx);
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
                    .child(format!("{} MCP configuration", pending.display_name)),
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
                    .font_family("monospace")
                    .child(
                        pending
                            .preview
                            .as_ref()
                            .expect("a pending installation always has its preview")
                            .exact_diff()
                            .to_owned(),
                    ),
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
                    .track_scroll(&review.scroll_handle)
                    .overflow_y_scroll()
                    .on_scroll_wheel(cx.listener(|_view, _, window, cx| {
                        cx.defer_in(window, |view, _, cx| {
                            view.update_legal_scroll_state(cx);
                        });
                    }))
                    .p_3()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(
                        TextView::markdown("legal-markdown", review.text.clone())
                            .w_full()
                            .selectable(true),
                    ),
            )
            .child(
                div()
                    .font_family("monospace")
                    .text_sm()
                    .flex_shrink_0()
                    .child(format!("Document digest: {}", review.digest)),
            )
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
                                        .label("Authenticate & reveal")
                                        .danger()
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
                    .child(div().text_2xl().font_semibold().child(self.route.label())),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scrollbar()
                    .px_5()
                    .pb_5()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(self.route_panel(cx)),
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
                cx.on_next_frame(window, |view, _, cx| {
                    if let Some(review) = view.active_review.as_mut() {
                        review.scroll_layout_ready = true;
                    }
                    view.update_review_scroll_state(cx);
                });
            }
        }
        if let Some(review) = self.legal_review.as_mut() {
            if review.scroll_layout_ready {
                self.update_legal_scroll_state(cx);
            } else if !review.scroll_check_scheduled {
                review.scroll_check_scheduled = true;
                cx.on_next_frame(window, |view, _, cx| {
                    if let Some(review) = view.legal_review.as_mut() {
                        review.scroll_layout_ready = true;
                    }
                    view.update_legal_scroll_state(cx);
                });
            }
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
            .on_action(cx.listener(Self::navigate_route))
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
                _instance: instance,
                _server: server_slot.clone(),
                _walletconnect: walletconnect.clone(),
                _tray: tray.clone(),
            });
            let mut key_bindings = vec![
                KeyBinding::new("cmd-k", OpenCommandPalette, None),
                KeyBinding::new("ctrl-k", OpenCommandPalette, None),
                #[cfg(target_os = "macos")]
                KeyBinding::new("cmd-q", Quit, None),
                #[cfg(not(target_os = "macos"))]
                KeyBinding::new("ctrl-q", Quit, None),
            ];
            #[cfg(target_os = "macos")]
            key_bindings.extend([
                KeyBinding::new(
                    "cmd-p",
                    NavigateRoute {
                        route: Route::Overview,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-r",
                    NavigateRoute {
                        route: Route::Reviews,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-a",
                    NavigateRoute {
                        route: Route::Activity,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-shift-a",
                    NavigateRoute {
                        route: Route::Accounts,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-shift-p",
                    NavigateRoute {
                        route: Route::Policies,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-n",
                    NavigateRoute {
                        route: Route::Networks,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-t",
                    NavigateRoute {
                        route: Route::Tokens,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-w",
                    NavigateRoute {
                        route: Route::WalletConnect,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-,",
                    NavigateRoute {
                        route: Route::Settings,
                    },
                    None,
                ),
                KeyBinding::new(
                    "cmd-u",
                    NavigateRoute {
                        route: Route::Updates,
                    },
                    None,
                ),
            ]);
            #[cfg(not(target_os = "macos"))]
            key_bindings.extend([
                KeyBinding::new(
                    "ctrl-p",
                    NavigateRoute {
                        route: Route::Overview,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-r",
                    NavigateRoute {
                        route: Route::Reviews,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-a",
                    NavigateRoute {
                        route: Route::Activity,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-shift-a",
                    NavigateRoute {
                        route: Route::Accounts,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-shift-p",
                    NavigateRoute {
                        route: Route::Policies,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-n",
                    NavigateRoute {
                        route: Route::Networks,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-t",
                    NavigateRoute {
                        route: Route::Tokens,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-w",
                    NavigateRoute {
                        route: Route::WalletConnect,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-,",
                    NavigateRoute {
                        route: Route::Settings,
                    },
                    None,
                ),
                KeyBinding::new(
                    "ctrl-u",
                    NavigateRoute {
                        route: Route::Updates,
                    },
                    None,
                ),
            ]);
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
                    cx,
                )
            });
            let window_slot: WalletWindowSlot = Rc::new(RefCell::new(None));
            show_wallet_window(cx, &wallet_view, &window_slot)
                .expect("failed to open the wallet window");
            let review_view = wallet_view.clone();
            let review_window = window_slot.clone();
            cx.spawn(async move |cx| {
                while let Some(prompt) = review_prompts.recv().await {
                    review_view.update(cx, |view, cx| {
                        view.receive_transaction_prompt(prompt);
                        view.route = view.active_review_route();
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
                        view.route = view.active_review_route();
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
            cx.spawn(async move |cx| {
                let mut mcp_online = false;
                loop {
                    let changed = match view_events.recv().await {
                        Ok(event) => {
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
                            if portfolio_changed || configuration_changed {
                                event_view.update(cx, |view, cx| {
                                    if portfolio_changed {
                                        view.invalidate_portfolio();
                                    }
                                    if configuration_changed {
                                        view.reload_tokens(cx);
                                    }
                                });
                            }
                            true
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => false,
                    };
                    if changed {
                        let pending_reviews = event_owner
                            .reviews(None)
                            .map_or(0, |queues| review_queue_decision_count(&queues));
                        let connected_agents =
                            event_owner.clients().map_or(0, |clients| clients.len());
                        let walletconnect_sessions = event_walletconnect
                            .lock()
                            .map_or(0, |sessions| sessions.sessions().len());
                        if let Some(tray) = event_tray.borrow_mut().as_mut() {
                            tray.update(&TraySnapshot {
                                pending_reviews,
                                mcp_online,
                                connected_agents,
                                walletconnect_sessions,
                            });
                        }
                        event_view.update(cx, |_, cx| cx.notify());
                    } else {
                        break;
                    }
                }
            })
            .detach();
            let tray_events = tray.clone();
            let tray_window = window_slot.clone();
            let tray_view = wallet_view.clone();
            cx.spawn(async move |cx| {
                loop {
                    cx.background_executor()
                        .timer(Duration::from_millis(100))
                        .await;
                    let dark_mode = cx.update(|cx| dark_appearance(cx.window_appearance()));
                    if let Some(tray) = tray_events.borrow_mut().as_mut() {
                        tray.set_dark_mode(dark_mode);
                    }
                    let commands = tray_events
                        .borrow_mut()
                        .as_mut()
                        .map_or_else(Vec::new, TrayService::drain_commands);
                    for command in commands {
                        match command {
                            TrayCommand::OpenWallet => {
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                            }
                            TrayCommand::OpenRoute(route) => {
                                tray_view.update(cx, |view, cx| {
                                    view.route = route;
                                    cx.notify();
                                });
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                            }
                            TrayCommand::ConnectDapp => {
                                tray_view.update(cx, |view, cx| {
                                    view.route = Route::WalletConnect;
                                    cx.notify();
                                });
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                            }
                            TrayCommand::ReinstallAgents => {
                                tray_view.update(cx, |view, cx| {
                                    view.route = Route::Settings;
                                    view.reinstall_detected_agents_from_menu(cx);
                                });
                                let _ = cx
                                    .update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                            }
                            TrayCommand::CheckForUpdates => {
                                tray_view.update(cx, |view, cx| {
                                    view.route = Route::Updates;
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
                        if !view.legal_gate {
                            view.reinstall_detected_agents(address.port(), cx);
                        }
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
