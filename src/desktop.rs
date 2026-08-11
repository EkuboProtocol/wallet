use crate::{
    BUILD_VERSION,
    agent_config::{AgentAdapter, ConfigPreview},
    authority::{ApplicationAuthority, OwnerApi},
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
use ekubo_wallet_core::core::policy::WalletPolicy;
use ekubo_wallet_core::desktop_store::AgentKind;
use ekubo_wallet_core::legal::LegalDocument;
use ekubo_wallet_core::pending::PendingStatus;
use gpui::{
    App, Context, Entity, KeyBinding, QuitMode, Render, SharedString, Window, WindowAppearance,
    WindowBounds, WindowHandle, WindowOptions, actions, div, prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme, Disableable, Root, StyledExt,
    button::{Button, ButtonVariants},
    input::{Input, InputState},
    scroll::ScrollableElement,
};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;

actions!(ekubo_wallet, [OpenCommandPalette, Quit]);

struct DesktopRuntime {
    _instance: SingleInstance,
    _server: Arc<Mutex<Option<McpHttpServer>>>,
    _walletconnect: Arc<Mutex<crate::walletconnect::WalletConnectManager>>,
    _tray: Rc<RefCell<Option<PlatformTray>>>,
}

impl gpui::Global for DesktopRuntime {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Overview,
    Reviews,
    Activity,
    Accounts,
    Policies,
    Networks,
    Tokens,
    AddressBook,
    Agents,
    WalletConnect,
    Settings,
    Legal,
    Updates,
}

impl Route {
    const ALL: [Self; 13] = [
        Self::Overview,
        Self::Reviews,
        Self::Activity,
        Self::Accounts,
        Self::Policies,
        Self::Networks,
        Self::Tokens,
        Self::AddressBook,
        Self::Agents,
        Self::WalletConnect,
        Self::Settings,
        Self::Legal,
        Self::Updates,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Reviews => "Reviews",
            Self::Activity => "Activity",
            Self::Accounts => "Accounts",
            Self::Policies => "Policies",
            Self::Networks => "Networks",
            Self::Tokens => "Tokens",
            Self::AddressBook => "Address Book",
            Self::Agents => "Agents",
            Self::WalletConnect => "WalletConnect",
            Self::Settings => "Settings",
            Self::Legal => "Legal & Version",
            Self::Updates => "Updates",
        }
    }
}

pub struct WalletWindow {
    owner: OwnerApi,
    review_presenter: GuiReviewPresenter,
    route: Route,
    command_palette: bool,
    mcp_status: SharedString,
    selected_record: Option<uuid::Uuid>,
    active_review: Option<ActiveReview>,
    pending_agent_install: Option<PendingAgentInstall>,
    account_id_input: Option<Entity<InputState>>,
    legal_review: Option<LegalReview>,
    operation_status: Option<SharedString>,
    walletconnect: Arc<Mutex<WalletConnectManager>>,
    walletconnect_presenter: ProposalPresenter,
    walletconnect_uri_input: Option<Entity<InputState>>,
}

struct LegalReview {
    document: LegalDocument,
    text: String,
    digest: String,
    viewed: bool,
}

struct PendingAgentInstall {
    display_name: String,
    client_id: uuid::Uuid,
    preview: Option<ConfigPreview>,
    owner: OwnerApi,
    committed: bool,
}

impl Drop for PendingAgentInstall {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.owner.remove_client(self.client_id);
        }
    }
}

struct ActiveReview {
    state: ReviewState,
    simulation: Option<ekubo_wallet_core::simulation::SimulationResult>,
    completion: Option<ActiveReviewCompletion>,
    awaiting_refresh: bool,
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
}

impl WalletWindow {
    fn new(
        owner: OwnerApi,
        review_presenter: GuiReviewPresenter,
        walletconnect: Arc<Mutex<WalletConnectManager>>,
        walletconnect_presenter: ProposalPresenter,
    ) -> Self {
        Self {
            owner,
            review_presenter,
            route: Route::Overview,
            command_palette: false,
            mcp_status: "MCP starting…".into(),
            selected_record: None,
            active_review: None,
            pending_agent_install: None,
            account_id_input: None,
            legal_review: None,
            operation_status: None,
            walletconnect,
            walletconnect_presenter,
            walletconnect_uri_input: None,
        }
    }

    fn attach_window(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.account_id_input.is_none() {
            self.account_id_input = Some(cx.new(|cx| {
                InputState::new(window, cx).placeholder("Account name, for example primary")
            }));
        }
        if self.walletconnect_uri_input.is_none() {
            self.walletconnect_uri_input =
                Some(cx.new(|cx| InputState::new(window, cx).placeholder("wc: pairing URI")));
        }
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
        cx.spawn(async move |view, cx| {
            let result = run_session(start, owner, presenter, manager, events).await;
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

    fn install_walletconnect_prompt(&mut self, prompt: ProposalPrompt) {
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
        });
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
        match self
            .owner
            .create_account(&wallet_id, &WalletPolicy::require_approval_for_everything())
        {
            Ok(account) => {
                input.update(cx, |input, cx| input.set_value("", window, cx));
                self.operation_status = Some(
                    format!(
                        "Created account {} at {:#x}. Every transaction requires review.",
                        account.id, account.address
                    )
                    .into(),
                );
            }
            Err(error) => {
                self.operation_status = Some(format!("Could not create account: {error:#}").into());
            }
        }
        cx.notify();
    }

    fn open_legal_review(&mut self, document: LegalDocument, cx: &mut Context<Self>) {
        let (text, digest) = self.owner.legal_document(document);
        self.legal_review = Some(LegalReview {
            document,
            text,
            digest,
            viewed: false,
        });
        cx.notify();
    }

    fn mark_legal_viewed(&mut self, cx: &mut Context<Self>) {
        if let Some(review) = self.legal_review.as_mut() {
            review.viewed = true;
        }
        cx.notify();
    }

    fn accept_legal(&mut self, cx: &mut Context<Self>) {
        let Some(review) = self.legal_review.as_ref() else {
            return;
        };
        if !review.viewed {
            return;
        }
        self.operation_status = Some(
            match self.owner.accept_legal(review.document, &review.digest) {
                Ok(()) => format!("Accepted the current {}.", review.document.title()).into(),
                Err(error) => format!("Could not accept document: {error:#}").into(),
            },
        );
        self.legal_review = None;
        cx.notify();
    }

    fn discard_unsent_transaction(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.operation_status = Some(match self.owner.discard_unsent_transaction(request_id) {
            Ok(_) => "Discarded signed bytes that were never submitted.".into(),
            Err(error) => format!("Could not discard transaction: {error:#}").into(),
        });
        cx.notify();
    }

    fn revoke_agent(&mut self, client_id: uuid::Uuid, cx: &mut Context<Self>) {
        self.operation_status = Some(match self.owner.revoke_client(client_id) {
            Ok(()) => "Revoked the agent token immediately.".into(),
            Err(error) => format!("Could not revoke agent: {error:#}").into(),
        });
        cx.notify();
    }

    fn prepare_agent_install(&mut self, kind: AgentKind, cx: &mut Context<Self>) {
        if self.pending_agent_install.is_some() {
            self.operation_status = Some("Finish the current agent installation first.".into());
            cx.notify();
            return;
        }
        let result = (|| -> Result<PendingAgentInstall> {
            let adapter = AgentAdapter::supported()?
                .into_iter()
                .find(|adapter| adapter.kind == kind)
                .context("the selected agent is not supported")?;
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
            )?;
            let client_id = registered.client.id;
            let token = registered.token.expose_base64url();
            let preview = match adapter.preview_install(port, &token, true) {
                Ok(preview) => preview,
                Err(error) => {
                    let _ = self.owner.remove_client(client_id);
                    return Err(error);
                }
            };
            Ok(PendingAgentInstall {
                display_name: adapter.display_name.to_owned(),
                client_id,
                preview: Some(preview),
                owner: self.owner.clone(),
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
            Ok(backup) if backup.as_os_str().is_empty() => {
                pending.committed = true;
                format!("Installed {display_name} MCP configuration.").into()
            }
            Ok(backup) => {
                pending.committed = true;
                format!(
                    "Installed {display_name} MCP configuration. Backup: {}",
                    backup.display()
                )
                .into()
            }
            Err(error) => format!("Could not install {display_name}: {error:#}").into(),
        });
        cx.notify();
    }

    fn install_review_prompt(&mut self, prompt: GuiReviewPrompt) {
        if let Some(active) = self.active_review.as_mut() {
            active.state.refresh(prompt.document);
            active.simulation = Some(prompt.simulation);
            active.completion = Some(ActiveReviewCompletion::Transaction(prompt.response));
            active.awaiting_refresh = false;
        } else {
            self.active_review = Some(ActiveReview {
                state: ReviewState::new(prompt.document),
                simulation: Some(prompt.simulation),
                completion: Some(ActiveReviewCompletion::Transaction(prompt.response)),
                awaiting_refresh: false,
            });
        }
    }

    fn begin_message_review(&mut self, request_id: uuid::Uuid, cx: &mut Context<Self>) {
        match self.owner.message_review_document(request_id) {
            Ok(document) => {
                let digest = document.request.digest.clone().unwrap_or_default();
                self.active_review = Some(ActiveReview {
                    state: ReviewState::new(document),
                    simulation: None,
                    completion: Some(ActiveReviewCompletion::Message { request_id, digest }),
                    awaiting_refresh: false,
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
        match self.owner.typed_data_review_document(request_id) {
            Ok(document) => {
                let digest = document.request.digest.clone().unwrap_or_default();
                self.active_review = Some(ActiveReview {
                    state: ReviewState::new(document),
                    simulation: None,
                    completion: Some(ActiveReviewCompletion::TypedData { request_id, digest }),
                    awaiting_refresh: false,
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
        if self.active_review.is_some() {
            self.operation_status = Some("Finish or close the current review first.".into());
            cx.notify();
            return;
        }
        self.operation_status = Some(format!("Opening review {request_id}…").into());
        let owner = self.owner.clone();
        let presenter = self.review_presenter.clone();
        cx.spawn(async move |view, cx| {
            let result = owner.review_transaction(request_id, &presenter).await;
            let _ = view.update(cx, |view, cx| {
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

    fn mark_review_viewed(&mut self, generation: u64, cx: &mut Context<Self>) {
        if self
            .active_review
            .as_mut()
            .is_some_and(|review| review.state.mark_viewed_to_end(generation))
        {
            cx.notify();
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
        match (command, completion) {
            (GuiReviewCommand::Refresh, Some(ActiveReviewCompletion::Transaction(response))) => {
                active.awaiting_refresh = true;
                if response.send(command).is_err() {
                    self.operation_status = Some("The review request is no longer active.".into());
                    self.active_review = None;
                }
            }
            (GuiReviewCommand::Close, Some(ActiveReviewCompletion::Transaction(response))) => {
                let _ = response.send(command);
                self.active_review = None;
            }
            (
                GuiReviewCommand::Approve | GuiReviewCommand::Reject,
                Some(ActiveReviewCompletion::Transaction(response)),
            ) => {
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
                self.active_review = None;
                cx.spawn(async move |view, cx| {
                    let result = owner.sign_message(request_id, &digest).await;
                    let _ = view.update(cx, |view, cx| {
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
                self.active_review = None;
                cx.spawn(async move |view, cx| {
                    let result = owner.sign_typed_data(request_id, &digest).await;
                    let _ = view.update(cx, |view, cx| {
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
        cx.notify();
    }

    fn toggle_palette(&mut self, _: &OpenCommandPalette, _: &mut Window, cx: &mut Context<Self>) {
        self.command_palette = !self.command_palette;
        cx.notify();
    }

    fn render_sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut sidebar = div()
            .w(px(184.0))
            .h_full()
            .flex()
            .flex_col()
            .gap_1()
            .p_3()
            .border_r_1()
            .border_color(cx.theme().border)
            .child(div().text_lg().font_semibold().mb_3().child("Ekubo Wallet"));
        for route in Route::ALL {
            let selected = route == self.route;
            sidebar = sidebar.child(
                Button::new(SharedString::from(format!("route-{route:?}")))
                    .label(route.label())
                    .when(selected, ButtonVariants::primary)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.route = route;
                        this.command_palette = false;
                        cx.notify();
                    })),
            );
        }
        sidebar
    }

    fn render_reviews(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut content = div().flex().flex_col().gap_3();
        match self.owner.reviews(None) {
            Ok(queues) => {
                let total =
                    queues.transactions.len() + queues.typed_data.len() + queues.messages.len();
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

    fn render_settings(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut panel = div()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().border)
            .flex()
            .flex_col()
            .gap_2()
            .child(self.mcp_status.clone())
            .child(format!(
                "Request limit: {} MiB",
                MCP_REQUEST_LIMIT_BYTES / 1024 / 1024
            ))
            .child("Notifications hide transaction details by default.")
            .child(div().mt_3().font_semibold().child("Detected agents"));
        let clients = self.owner.clients().unwrap_or_default();
        let adapters = match AgentAdapter::supported() {
            Ok(adapters) => adapters,
            Err(error) => return panel.child(format!("Agent detection unavailable: {error:#}")),
        };
        let mut detected = 0;
        for adapter in adapters.into_iter().filter(AgentAdapter::detected) {
            detected += 1;
            let kind = adapter.kind;
            let installed = clients
                .iter()
                .any(|client| client.agent_kind == kind && client.revoked_at.is_none());
            panel = panel.child(
                div()
                    .py_2()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div().child(adapter.display_name).child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(adapter.config_path.display().to_string()),
                        ),
                    )
                    .child(
                        Button::new(SharedString::from(format!("install-agent-{kind:?}")))
                            .label(if installed { "Installed" } else { "Install" })
                            .disabled(installed || self.pending_agent_install.is_some())
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.prepare_agent_install(kind, cx);
                            })),
                    ),
            );
        }
        if detected == 0 {
            panel = panel.child(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("No supported agent installation was detected."),
            );
        }
        panel
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
            panel = panel.child(
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
            );
        }
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
            Ok(items) => panel.children(items.into_iter().map(|item| {
                div()
                    .py_2()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(format!("{} · {:#x}", item.id, item.address))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("{:?} · created {}", item.source, item.created_at)),
                    )
            })),
            Err(error) => panel.child(format!("Accounts unavailable: {error:#}")),
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
            .gap_2();
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
                                if status.terms_of_service.accepted {
                                    "Accepted"
                                } else {
                                    "Review required"
                                }
                            ))
                            .child(Button::new("review-terms").label("Review").on_click(
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
                                if status.privacy_policy.accepted {
                                    "Accepted"
                                } else {
                                    "Review required"
                                }
                            ))
                            .child(Button::new("review-privacy").label("Review").on_click(
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
            Route::Overview => {
                let accounts = self.owner.accounts().map_or(0, |items| items.len());
                let agents = self.owner.clients().map_or(0, |items| items.len());
                let reviews = self.owner.reviews(None).map_or(0, |queues| {
                    queues.transactions.len() + queues.typed_data.len() + queues.messages.len()
                });
                panel
                    .child(format!("{accounts} account(s)"))
                    .child(format!("{agents} registered agent(s)"))
                    .child(format!("{reviews} pending review(s)"))
                    .child(self.mcp_status.clone())
            }
            Route::Activity => match self.owner.transactions(None, 200) {
                Ok(items) => panel.children(items.into_iter().map(|item| {
                    let request_id = item.request_id;
                    let can_discard = item.status == PendingStatus::Signed;
                    div()
                        .py_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .child(format!(
                            "{:?} · {} · {} · {}",
                            item.status, item.wallet_id, item.network_name, item.request_id
                        ))
                        .when(can_discard, |row| {
                            row.child(
                                Button::new(SharedString::from(format!("discard-{request_id}")))
                                    .label("Discard unsent signature")
                                    .danger()
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.discard_unsent_transaction(request_id, cx);
                                    })),
                            )
                        })
                })),
                Err(error) => panel.child(format!("Activity unavailable: {error:#}")),
            },
            Route::Accounts => self.render_accounts(cx),
            Route::Policies => match self.owner.accounts() {
                Ok(accounts) => {
                    let mut content = panel;
                    for account in accounts {
                        content = content.child(match self.owner.policy(&account.id) {
                            Ok(Some(policy)) => div()
                                .py_2()
                                .border_b_1()
                                .border_color(cx.theme().border)
                                .child(format!(
                                    "{} · revision {} · updated {}",
                                    policy.wallet_id, policy.revision, policy.updated_at
                                )),
                            Ok(None) => {
                                div().child(format!("{} · signing disabled: no policy", account.id))
                            }
                            Err(error) => div()
                                .child(format!("{} · policy unavailable: {error:#}", account.id)),
                        });
                    }
                    content
                }
                Err(error) => panel.child(format!("Policies unavailable: {error:#}")),
            },
            Route::Networks => match self.owner.networks() {
                Ok(items) => panel.children(items.into_iter().map(|item| {
                    div()
                        .py_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .child(format!(
                            "{} · chain {}",
                            item.display_name.as_deref().unwrap_or(&item.name),
                            item.chain_id
                        ))
                        .child(
                            div()
                                .text_sm()
                                .text_color(cx.theme().muted_foreground)
                                .child(format!("{} RPC endpoint(s)", item.rpc_urls.len())),
                        )
                })),
                Err(error) => panel.child(format!("Networks unavailable: {error:#}")),
            },
            Route::Tokens => match self.owner.tokens(None, 500, 0) {
                Ok(items) => panel.children(items.into_iter().map(|item| {
                    div()
                        .py_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .child(format!(
                            "{} · chain {} · {}",
                            item.symbol.as_deref().unwrap_or("Unnamed token"),
                            item.chain_id,
                            item.address
                        ))
                })),
                Err(error) => panel.child(format!("Tokens unavailable: {error:#}")),
            },
            Route::AddressBook => match self.owner.address_book(None, 500, 0) {
                Ok(items) => panel.children(items.into_iter().map(|item| {
                    div()
                        .py_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .child(format!(
                            "{} · chain {} · {}",
                            item.alias, item.chain_id, item.address
                        ))
                        .when_some(item.note, |row, note| {
                            row.child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(note),
                            )
                        })
                })),
                Err(error) => panel.child(format!("Address book unavailable: {error:#}")),
            },
            Route::Agents => {
                match self.owner.clients() {
                    Ok(items) => panel.children(items.into_iter().map(|item| {
                        let client_id = item.id;
                        let active = item.revoked_at.is_none();
                        div()
                            .py_2()
                            .border_b_1()
                            .border_color(cx.theme().border)
                            .child(format!("{} · {:?}", item.display_name, item.agent_kind))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(if let Some(revoked) = item.revoked_at {
                                        format!("Revoked {revoked}")
                                    } else if let Some(last_used) = item.last_used_at {
                                        format!("Last used {last_used}")
                                    } else {
                                        "Registered, not yet used".into()
                                    }),
                            )
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
                            })
                    })),
                    Err(error) => panel.child(format!("Agents unavailable: {error:#}")),
                }
            }
            Route::WalletConnect => self.render_walletconnect(cx),
            Route::Settings => self.render_settings(cx),
            Route::Legal => self.render_legal(cx),
            Route::Updates => panel
                .child(format!("Installed version: {BUILD_VERSION}"))
                .child("Updates are downloaded and signature-verified only after confirmation."),
            Route::Reviews => self.render_reviews(cx),
        }
    }

    fn render_review_overlay(&self, cx: &mut Context<Self>) -> gpui::Div {
        let Some(active) = &self.active_review else {
            return div();
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
        review_body = review_body.child(
            Button::new(("review-viewed", generation))
                .label(if active.state.approve_enabled() {
                    "Complete review viewed"
                } else {
                    "Mark complete review as viewed"
                })
                .disabled(active.state.approve_enabled())
                .on_click(cx.listener(move |view, _, _, cx| {
                    view.mark_review_viewed(generation, cx);
                })),
        );

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
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(div().font_semibold().child("Security review"))
                    .child(
                        Button::new(("review-close", generation))
                            .label("Close")
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.send_review_command(generation, GuiReviewCommand::Close, cx);
                            })),
                    ),
            )
            .child(
                div()
                    .id(("review-scroll", generation))
                    .flex_1()
                    .overflow_y_scrollbar()
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
                            .gap_2()
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
    }

    fn render_agent_install_overlay(&self, cx: &mut Context<Self>) -> gpui::Div {
        let Some(pending) = &self.pending_agent_install else {
            return div();
        };
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
            .child(
                div()
                    .font_semibold()
                    .child(format!("Install {} MCP configuration", pending.display_name)),
            )
            .child("Review the exact configuration change. A timestamped backup is created before installation.")
            .child(
                div()
                    .flex_1()
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
                            .label("Install")
                            .primary()
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.confirm_agent_install(cx);
                            })),
                    ),
            )
    }

    fn render_legal_overlay(&self, cx: &mut Context<Self>) -> gpui::Div {
        let Some(review) = &self.legal_review else {
            return div();
        };
        let informational = review.document == LegalDocument::ThirdPartyLicenses;
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
            .child(div().font_semibold().child(review.document.title()))
            .child(
                div()
                    .flex_1()
                    .overflow_y_scrollbar()
                    .p_3()
                    .border_1()
                    .border_color(cx.theme().border)
                    .child(review.text.clone()),
            )
            .child(
                div()
                    .font_family("monospace")
                    .text_sm()
                    .child(format!("Document digest: {}", review.digest)),
            )
            .child(
                div()
                    .flex()
                    .justify_between()
                    .child(
                        Button::new("close-legal-review")
                            .label("Close")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.legal_review = None;
                                cx.notify();
                            })),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                Button::new("legal-viewed")
                                    .label(if review.viewed {
                                        "Complete document viewed"
                                    } else {
                                        "Mark complete document as viewed"
                                    })
                                    .disabled(review.viewed)
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.mark_legal_viewed(cx);
                                    })),
                            )
                            .when(!informational, |buttons| {
                                buttons.child(
                                    Button::new("accept-legal")
                                        .label("Accept")
                                        .primary()
                                        .disabled(!review.viewed)
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            view.accept_legal(cx);
                                        })),
                                )
                            }),
                    ),
            )
    }

    fn render_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex_1()
            .h_full()
            .p_5()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .child(div().text_2xl().font_semibold().child(self.route.label())),
            )
            .child(self.route_panel(cx))
            .when_some(self.operation_status.clone(), |view, status| {
                view.child(
                    div()
                        .p_2()
                        .rounded_lg()
                        .border_1()
                        .border_color(cx.theme().border)
                        .child(status),
                )
            })
            .child(div().text_sm().text_color(cx.theme().muted_foreground).child(
                "Agent tokens protect this endpoint from accidental or unauthorized local clients. Plaintext loopback HTTP cannot protect against malicious code already running as your OS user.",
            ))
    }

    fn render_palette(cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .absolute()
            .top(px(54.0))
            .left(px(220.0))
            .w(px(360.0))
            .p_3()
            .rounded_lg()
            .shadow_lg()
            .border_1()
            .border_color(cx.theme().border)
            .bg(cx.theme().popover)
            .child(div().font_semibold().mb_2().child("Go to…"))
            .children(Route::ALL.into_iter().map(|route| {
                Button::new(SharedString::from(format!("palette-{route:?}")))
                    .label(route.label())
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.route = route;
                        this.command_palette = false;
                        cx.notify();
                    }))
            }))
    }
}

impl Render for WalletWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.attach_window(window, cx);
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
                view.child(Self::render_palette(cx))
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
        view.account_id_input = None;
        view.walletconnect_uri_input = None;
        cx.notify();
    });
    let root_view = wallet_view.clone();
    let window_handle = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(960.0), px(650.0)), cx)),
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

    gpui_platform::application().run(move |cx: &mut App| {
        gpui_component::init(cx);
        gpui_tokio::init(cx);
        cx.set_quit_mode(QuitMode::Explicit);
        let tray = Rc::new(RefCell::new(
            PlatformTray::new(dark_appearance(cx.window_appearance())).ok(),
        ));
        let initial_agents = owner.clients().map_or(0, |clients| clients.len());
        if let Some(tray) = tray.borrow_mut().as_mut() {
            tray.update(&TraySnapshot {
                pending_reviews: 0,
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
        cx.bind_keys([
            KeyBinding::new("cmd-k", OpenCommandPalette, Some("Wallet")),
            KeyBinding::new("ctrl-k", OpenCommandPalette, Some("Wallet")),
            #[cfg(target_os = "macos")]
            KeyBinding::new("cmd-q", Quit, None),
            #[cfg(not(target_os = "macos"))]
            KeyBinding::new("ctrl-q", Quit, None),
        ]);
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

        let wallet_view = cx.new(|_| {
            WalletWindow::new(
                owner.clone(),
                review_presenter.clone(),
                walletconnect.clone(),
                walletconnect_presenter.clone(),
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
                    view.install_review_prompt(prompt);
                    view.route = Route::Reviews;
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
                    view.install_walletconnect_prompt(prompt);
                    view.route = Route::WalletConnect;
                    cx.notify();
                });
                let _ = cx.update(|cx| {
                    show_wallet_window(cx, &walletconnect_review_view, &walletconnect_review_window)
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
                            event.kind
                        {
                            mcp_online = online;
                        }
                        true
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => false,
                };
                if changed {
                    let pending_reviews = event_owner.reviews(None).map_or(0, |queues| {
                        queues.transactions.len() + queues.typed_data.len() + queues.messages.len()
                    });
                    let connected_agents = event_owner.clients().map_or(0, |clients| clients.len());
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
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::OpenRoute(route) => {
                            tray_view.update(cx, |view, cx| {
                                view.route = route;
                                cx.notify();
                            });
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::ConnectDapp => {
                            tray_view.update(cx, |view, cx| {
                                view.route = Route::WalletConnect;
                                cx.notify();
                            });
                            let _ =
                                cx.update(|cx| show_wallet_window(cx, &tray_view, &tray_window));
                        }
                        TrayCommand::CheckForUpdates => {
                            tray_view.update(cx, |view, cx| {
                                view.route = Route::Updates;
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
            }
        })
        .detach();

        let detailed_previews = clients
            .lock()
            .ok()
            .and_then(|store| store.setting::<bool>("notification_detailed_previews").ok())
            .flatten()
            .unwrap_or(false);
        let preferences = NotificationPreferences { detailed_previews };
        let (notification_clicks, mut clicked_notifications) =
            tokio::sync::mpsc::unbounded_channel();
        let notification_service = PlatformNotificationService::new(notification_clicks);
        let mut domain_events = events.subscribe();
        gpui_tokio::Tokio::spawn(cx, async move {
            loop {
                match domain_events.recv().await {
                    Ok(event) => {
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
                let _ = cx
                    .update(|cx| show_wallet_window(cx, &notification_view, &notification_window));
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
                let _ =
                    cx.update(|cx| show_wallet_window(cx, &activation_view, &activation_window));
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
