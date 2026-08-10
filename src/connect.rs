//! `ekubo-wallet connect`: pair with a dapp from a pasted `WalletConnect` link
//! and serve what it proposes on this terminal.
//!
//! What a dapp may ask for and what it is refused lives in [`crate::dapp`],
//! shared with the MCP server's sessions so that a fix lands once. This module
//! is the terminal half of that split, and it owns exactly two things:
//!
//! * the **connection review** — the full-screen document a person approves,
//!   the account list they choose from, and the warnings about a dapp's
//!   unattested account of itself; and
//! * the **decision surface** — how a request that needs a person gets to one.
//!   Here that is a review drawn on this terminal:
//!   `orchestrator::approve_transaction` for a queued transaction, and
//!   [`crate::signing_review`] for a message or a typed-data payload. Same
//!   document, same guard ladder, same owner authentication as
//!   `ekubo-wallet review`.
//!
//! The session's approved scope is enforced in
//! [`crate::walletconnect::session`] before a request reaches either.

use crate::{
    approval::{ApprovalDecision, ApprovalKind, ApprovalRequest},
    config::{ConfigStore, WalletMetadata},
    connect_screen::{IdleView, SessionState},
    dapp::{DappSession, DappSurface, PlanVerdict},
    legal,
    message::{MessageStore, PendingMessage},
    pending::PendingTransaction,
    policy_store::PolicyStore,
    sanitize::terminal_safe_line,
    signing_review::{
        MessageDecision, SigningAccount, TypedDataDecision, decide_message, decide_typed_data,
    },
    token_store::TokenStore,
    typed_data::{PendingTypedData, TypedDataStore},
    walletconnect::{
        crypto::ClientIdentity,
        identity::DappIdentity,
        protocol::error_code,
        relay::{DEFAULT_RELAY_URL, RelayConnection},
        session::{
            ApprovedScope, DappRequest, ProposalDecision, ProposalSummary, RequestOutcome, Session,
            SessionEvent, SessionHandler,
        },
        uri::PairingUri,
    },
};
use anyhow::{Context, Result, ensure};
use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use url::Url;

pub use crate::dapp::{MAX_BATCH_CALLS, SUPPORTED_METHODS};

/// What `ekubo-wallet connect` was asked to do.
pub struct ConnectOptions {
    /// The pasted `wc:` URI. Prompted for when absent.
    pub uri: Option<String>,
    /// Which account to expose. Inferred when the wallet holds exactly one.
    pub account: Option<String>,
    /// An alternative relay, for a self-hosted deployment.
    pub relay_url: Option<Url>,
}

/// Pair, settle, and serve until the dapp disconnects or Ctrl-C.
pub async fn run(config: &ConfigStore, options: ConnectOptions) -> Result<()> {
    // Every request this session can produce ends at a review on this
    // terminal, so a session opened without one could only ever refuse
    // everything. Better to say so before a dapp thinks it is connected.
    ensure!(
        crate::tui::interactive(),
        "`connect` needs an interactive terminal: every request a dapp sends is reviewed here, \
         and there would be nowhere to show the review."
    );
    legal::require_current_acceptance(config.data_dir())?;

    let (accounts, selected) = resolve_accounts(config, options.account.as_deref())?;
    let relay_url = match options.relay_url {
        Some(url) => url,
        None => Url::parse(DEFAULT_RELAY_URL).expect("the default relay URL is valid"),
    };

    // Full-screen, like everything after it. A command that opens full-screen
    // surfaces opens them from its first question.
    let uri = if let Some(uri) = options.uri {
        uri
    } else {
        let Some(uri) = crate::connect_screen::prompt_for_uri(
            &accounts[selected].id,
            &accounts[selected].address.to_checksum(None),
            relay_url.as_str(),
        )
        .await?
        else {
            crate::tui::outro_cancel("No link given; nothing was connected.");
            return Ok(());
        };
        uri
    };
    let pairing = PairingUri::parse(&uri, chrono::Utc::now())?;

    let relay_display = relay_url.to_string();
    let identity = ClientIdentity::generate()?;
    let relay = RelayConnection::connect(&relay_url, &identity).await?;

    let state = Arc::new(Mutex::new(SessionState {
        title: "Connecting…".to_owned(),
        header: vec![
            crate::connect_screen::fact("Account", &accounts[selected].id),
            crate::connect_screen::fact("Address", &accounts[selected].address.to_checksum(None)),
            crate::connect_screen::fact("Relay", &relay_display),
        ],
        log: Vec::new(),
        status: "Pairing".to_owned(),
    }));
    let surface = TerminalSurface {
        config,
        data_dir: config.data_dir().to_path_buf(),
        state: Arc::clone(&state),
        idle: RefCell::new(None),
        quit: Arc::new(AtomicBool::new(false)),
    };
    let handler = TerminalDapp {
        session: DappSession::new(config, accounts, selected, surface),
    };
    let session = Session::new(relay, pairing, &handler);
    let outcome = session
        .run(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    // The surface is released before anything is printed, so the closing
    // line lands in the ordinary scrollback rather than behind an alternate
    // screen nobody will see again.
    handler.session.surface().suspend_idle().await;
    match outcome {
        Ok(()) => {
            crate::tui::outro("Session closed.");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Every account this session could expose, and which one starts selected.
///
/// A session exposes exactly one account, but *which* one is a question best
/// asked on the review screen, where the consequences of the answer are
/// already on display — so this returns all of them rather than making the
/// caller choose blind. `--account` preselects; it does not narrow the list,
/// because the review names the selected account in its own document and
/// changing it takes a deliberate keystroke.
fn resolve_accounts(
    config: &ConfigStore,
    requested: Option<&str>,
) -> Result<(Vec<WalletMetadata>, usize)> {
    let accounts = config.load()?.wallets;
    ensure!(
        !accounts.is_empty(),
        "this wallet holds no accounts. Run `ekubo-wallet account create` first."
    );
    let Some(requested) = requested else {
        return Ok((accounts, 0));
    };
    // Resolved through the config store rather than by scanning the list, so
    // an unknown id fails with the store's own message.
    let wanted = config.wallet(requested)?;
    let selected = accounts
        .iter()
        .position(|account| account.id == wanted.id)
        .context("the named account is not in this wallet's account list")?;
    Ok((accounts, selected))
}

/// The terminal's answer to everything a dapp session has to ask a person.
struct TerminalSurface<'a> {
    config: &'a ConfigStore,
    data_dir: PathBuf,
    /// What the idle surface draws. Shared with the loop drawing it.
    state: Arc<Mutex<SessionState>>,
    /// The running idle surface, when it holds the terminal.
    ///
    /// `None` means something else does — a review, or owner authentication.
    /// Exactly one of them ever reads a keystroke, and the handover is the
    /// `suspend_idle`/`enter_idle` pair rather than anything implicit.
    idle: RefCell<Option<IdleView>>,
    /// Whether the person asked to disconnect, held by the session rather than
    /// by whichever idle view happened to be on screen when they said so.
    ///
    /// The flag used to belong to the view. A view is stopped and replaced
    /// around every review, and the session loop selects between relay
    /// delivery and this answer -- so a `q`, Escape, or Ctrl-C that lands
    /// while a request wins that race set a flag on a view that `suspend_idle`
    /// then dropped, and `enter_idle` built a replacement that started out
    /// saying no. The disconnect was not delayed; it was gone, and the dapp
    /// stayed connected with a person who believed they had left.
    quit: Arc<AtomicBool>,
}

impl TerminalSurface<'_> {
    /// Take the terminal back from the idle surface and wait until it is
    /// really free.
    ///
    /// Called before anything that draws: a review, a paste, an owner
    /// authentication prompt. Awaiting matters — returning while the idle loop
    /// was still restoring the terminal would let two surfaces fight over it.
    async fn suspend_idle(&self) {
        let running = self.idle.borrow_mut().take();
        if let Some(view) = running {
            view.stop().await;
        }
    }

    fn set_status(&self, status: impl Into<String>) {
        if let Ok(mut state) = self.state.lock() {
            state.status = status.into();
        }
    }

    /// Add a line to the session screen's log, in the tone that says what kind
    /// of thing happened. The `DappSurface` seam carries no tone — see its
    /// `log` — so the choice is made here, where the screen is.
    fn note(&self, tone: crate::tui::Tone, text: impl Into<String>) {
        if let Ok(mut state) = self.state.lock() {
            state.push(crate::connect_screen::event(tone, text.into()));
        }
    }
}

#[async_trait::async_trait(?Send)]
impl DappSurface for TerminalSurface<'_> {
    fn closing(&self) -> bool {
        self.quit.load(Ordering::Relaxed)
    }

    fn log(&self, text: &str) {
        self.note(crate::tui::Tone::Info, text);
    }

    /// A terminal session proceeds. The gate exists for a surface whose
    /// operator is not present while the dapp is talking; here they are, they
    /// read this dapp's identity and cautions on the connection review before
    /// approving it, and they will see the full review for anything the policy
    /// does not already cover. Adding a second question they would answer from
    /// the same screen buys nothing.
    ///
    /// What that leaves standing is the pre-existing shape of `connect`: under
    /// a policy that signs everything automatically, a dapp the person chose to
    /// connect can act without another prompt. That is what approving the
    /// connection meant before this seam existed and it is not changed here.
    async fn approve_plan(
        &self,
        _plan: &crate::core::execution_plan::ExecutionPlan,
        _simulation: &crate::simulation::SimulationResult,
        _dapp: &crate::walletconnect::protocol::AppMetadata,
    ) -> Result<PlanVerdict> {
        Ok(PlanVerdict::Proceed)
    }

    /// Put a queued transaction through the same review `ekubo-wallet review`
    /// runs. `None` means the reviewer rejected it.
    async fn resolve_queued(
        &self,
        queued: PendingTransaction,
    ) -> Result<Option<PendingTransaction>> {
        // The review draws, and owner authentication below it may put a polkit
        // text agent on this same terminal, so the idle surface hands it over
        // before either — and the session loop takes it back afterwards.
        self.suspend_idle().await;
        let data_dir = self.data_dir.clone();
        let wallet_id = queued.wallet_id.clone();
        let read_policy = move || -> Result<crate::policy_store::StoredPolicy> {
            PolicyStore::production(&data_dir)?
                .get(&wallet_id)?
                .with_context(|| format!("wallet {wallet_id} has no local policy"))
        };
        let outcome = crate::orchestrator::approve_transaction(
            self.config,
            crate::pending::PendingStore::production(&self.data_dir)?,
            &TokenStore::production(&self.data_dir)?,
            &read_policy,
            queued,
            crate::approval::InteractiveProof::from_terminal()?,
            &FullScreenPresenter,
            &crate::human_presence::PlatformHumanPresence,
            &crate::custody::OsKeyStore,
        )
        .await?;
        Ok(match outcome {
            crate::orchestrator::ApprovalOutcome::Rejected(_) => None,
            crate::orchestrator::ApprovalOutcome::Signed(record) => Some(record),
        })
    }

    async fn resolve_message(
        &self,
        record: PendingMessage,
        account: &WalletMetadata,
    ) -> Result<Option<PendingMessage>> {
        let store = MessageStore::production(&self.data_dir)?;
        let policies = PolicyStore::production(&self.data_dir)?;
        // Every message is reviewed by a person, so this one always draws.
        self.suspend_idle().await;
        Ok(
            match decide_message(
                self.config,
                &policies,
                store,
                record,
                &SigningAccount::Settled(account),
            )
            .await?
            {
                MessageDecision::Rejected(_) => None,
                MessageDecision::Signed(record) => Some(record),
            },
        )
    }

    async fn resolve_typed_data(
        &self,
        record: PendingTypedData,
        account: &WalletMetadata,
    ) -> Result<Option<PendingTypedData>> {
        let store = TypedDataStore::production(&self.data_dir)?;
        let policies = PolicyStore::production(&self.data_dir)?;
        // Every typed-data payload is reviewed by a person, so this one always
        // draws.
        self.suspend_idle().await;
        Ok(
            match decide_typed_data(
                self.config,
                &policies,
                store,
                record,
                &SigningAccount::Settled(account),
            )
            .await?
            {
                TypedDataDecision::Rejected(_) => None,
                TypedDataDecision::Signed(record) => Some(record),
            },
        )
    }
}

/// One dapp session on this terminal.
struct TerminalDapp<'a> {
    session: DappSession<'a, TerminalSurface<'a>>,
}

#[async_trait::async_trait(?Send)]
impl SessionHandler for TerminalDapp<'_> {
    async fn enter_idle(&self) {
        let surface = self.session.surface();
        if surface.idle.borrow().is_some() {
            return;
        }
        let view = IdleView::start(Arc::clone(&surface.state), Arc::clone(&surface.quit));
        *surface.idle.borrow_mut() = Some(view);
    }

    async fn quit_requested(&self) {
        // Polled rather than signalled: the alternative is a channel whose
        // receiver has to survive the surface being stopped and restarted
        // around every review, and this future is dropped and rebuilt on every
        // turn of the session loop anyway.
        loop {
            if self.session.surface().closing() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn review_proposal(&self, proposal: &ProposalSummary) -> Result<ProposalDecision> {
        // Everything below draws, so the idle surface hands the terminal over
        // first and does not take it back until the session loop waits again.
        self.session.surface().suspend_idle().await;
        // The narrowing — configured chains, implemented methods — is shared
        // with every other session this wallet serves. What is decided here is
        // only whether to expose it, and as which account.
        let (chains, methods) = match self.session.negotiate(proposal, None) {
            Ok(negotiated) => negotiated,
            Err(refusal) => return Ok(refusal),
        };

        // One complete review per account, authored before the screen opens,
        // so switching between them is instant and the reviewer always sees
        // the consequences of the account actually selected — the address
        // exposed, and which chains it will be exposed on.
        let scopes: Vec<ApprovedScope> = self
            .session
            .accounts()
            .iter()
            .map(|account| {
                DappSession::<TerminalSurface<'_>>::scope_for(
                    account,
                    chains.clone(),
                    methods.clone(),
                )
            })
            .collect();
        let choices: Vec<crate::approve_tui::ReviewChoice> = self
            .session
            .accounts()
            .iter()
            .zip(&scopes)
            .map(|(account, scope)| crate::approve_tui::ReviewChoice {
                request: self.proposal_document(proposal, account, scope),
                label: account.id.clone(),
            })
            .collect();

        let (decision, chosen) =
            crate::approve_tui::review_fullscreen_choosing(choices, self.session.selected())
                .await?;
        if decision != ApprovalDecision::Approved {
            return Ok(ProposalDecision::Reject {
                code: error_code::USER_REJECTED,
                message: "The wallet owner declined this connection.".to_owned(),
            });
        }
        // Recorded before the scope is handed back, so every request served
        // afterwards signs for the account whose review was approved.
        self.session.set_selected(chosen);
        Ok(ProposalDecision::Approve(
            scopes
                .into_iter()
                .nth(chosen)
                .context("the review returned an account that was never offered")?,
        ))
    }

    async fn handle_request(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        // Deliberately no `suspend_idle` here. Handing the terminal over for
        // every request meant leaving the alternate screen and re-entering it
        // on the next turn of the session loop, so the session screen blinked
        // out and back on every answer — including for `eth_chainId`, which
        // draws nothing, and for a transaction the policy signs automatically.
        //
        // The surface is released by the paths that actually draw (the three
        // `resolve_*` methods above) and taken back by the session loop
        // afterwards. Everything else answers underneath it, and its log line
        // appears in place.
        Ok(self.session.answer(request).await)
    }

    fn notify(&self, event: &SessionEvent<'_>) {
        use crate::tui::Tone;

        let surface = self.session.surface();
        match event {
            SessionEvent::Pairing => {
                surface.set_status("Waiting for the dapp");
                surface.note(
                    Tone::Muted,
                    "Paired. Waiting for the connection proposal…".to_owned(),
                );
            }
            SessionEvent::ProposalReceived => {
                surface.note(Tone::Info, "A connection proposal arrived.".to_owned());
            }
            SessionEvent::Settled { scope, metadata } => {
                let dapp = DappIdentity::of(metadata);
                // The identity block is pinned above the log rather than
                // scrolling with it: who this session is with is the context
                // every line below it has to be read against, and a busy dapp
                // would otherwise push it off the top within seconds.
                //
                // Chains are named rather than listed as CAIP-2 ids, and each
                // fact gets its own line, because on a small terminal a
                // paragraph of comma-joined identifiers is a paragraph nobody
                // reads.
                let chains = scope
                    .chains
                    .iter()
                    .map(|chain| {
                        self.session
                            .network_for(chain)
                            .map_or_else(|| chain.clone(), |network| network.name)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                if let Ok(mut state) = surface.state.lock() {
                    state.title = format!("Connected to {}", dapp.host_or_unknown());
                    state.header = vec![
                        crate::connect_screen::fact("Site", &dapp.host_or_unknown()),
                        crate::connect_screen::fact(
                            "Name",
                            dapp.name.as_deref().unwrap_or("not stated"),
                        ),
                        crate::connect_screen::fact("Account", &self.session.wallet().id),
                        crate::connect_screen::fact("Address", &scope.address),
                        crate::connect_screen::fact("Chains", &chains),
                        Vec::new(),
                    ];
                    "Connected".clone_into(&mut state.status);
                }
                surface.note(Tone::Success, "Connected. Waiting for requests…".to_owned());
            }
            SessionEvent::RequestReceived {
                method,
                caip2_chain_id,
            } => {
                surface.set_status(format!("Serving {}", terminal_safe_line(method)));
                surface.note(
                    Tone::Info,
                    format!(
                        "{} on {}",
                        terminal_safe_line(method),
                        terminal_safe_line(caip2_chain_id)
                    ),
                );
            }
            SessionEvent::RequestAnswered { method, outcome } => {
                surface.set_status("Connected");
                match outcome {
                    RequestOutcome::Result(_) => surface.note(
                        Tone::Success,
                        format!("{} — answered.", terminal_safe_line(method)),
                    ),
                    RequestOutcome::Error { message, .. } => surface.note(
                        Tone::Danger,
                        format!(
                            "{} — refused: {}",
                            terminal_safe_line(method),
                            terminal_safe_line(message)
                        ),
                    ),
                }
            }
            SessionEvent::RequestRefused { method, reason } => {
                surface.set_status("Connected");
                surface.note(
                    Tone::Danger,
                    format!(
                        "{} — outside this session's scope: {}",
                        terminal_safe_line(method),
                        terminal_safe_line(reason)
                    ),
                );
            }
            SessionEvent::Ping => {}
            SessionEvent::DappDisconnected { code, message } => {
                surface.set_status("Disconnected");
                surface.note(
                    Tone::Info,
                    format!(
                        "The dapp closed the session ({code}): {}",
                        terminal_safe_line(message)
                    ),
                );
            }
            SessionEvent::RelayReconnected => {
                surface.note(Tone::Info, "Reconnected to the relay.".to_owned());
            }
        }
    }
}

impl TerminalDapp<'_> {
    /// The review a person decides the connection on.
    ///
    /// Ordered for a small terminal: the four facts the decision actually
    /// turns on — which site, which account, which chains, which powers — are
    /// the first thing drawn, so they are legible without scrolling on a
    /// short screen. Everything a reviewer might want but rarely needs comes
    /// after, and the warnings come last because the decision pane refuses
    /// Approve until the end of the document has been on screen, which makes
    /// last the one position they can never be scrolled away from.
    ///
    /// Labels are kept short for the same reason: they occupy a fixed column
    /// on every line, and a narrow terminal spends what is left on the value.
    ///
    /// Every dapp-authored string here goes through [`DappIdentity`], which
    /// sanitizes it. A name is the thing a person actually reads, and it is
    /// chosen entirely by the dapp — including, if it likes, a name with a
    /// right-to-left override in it that rewrites the line it sits on.
    fn proposal_document(
        &self,
        proposal: &ProposalSummary,
        account: &WalletMetadata,
        scope: &ApprovedScope,
    ) -> ApprovalRequest {
        let dapp = DappIdentity::of(&proposal.metadata);
        let accounts = self.session.accounts();
        let mut approval = ApprovalRequest::new(
            ApprovalKind::PolicyException,
            "Approve a dapp connection",
            "Let this dapp propose transactions and signatures from this account. It cannot sign \
             anything by itself: each request it sends is checked against this wallet's policy \
             and, unless the policy already allows it outright, shown to you before anything is \
             signed.",
        )
        // The host leads. It is the only field on this screen with a shape
        // that can be wrong, and the only one a person can check against the
        // address bar of the page they opened.
        .fact("Site", dapp.host_or_unknown())
        .fact(
            "Name",
            dapp.name.clone().unwrap_or_else(|| "not stated".to_owned()),
        );
        if let Some(description) = &dapp.description {
            approval = approval.fact("About", description);
        }
        approval = approval
            .fact("Account", &account.id)
            .fact("Address", &scope.address);
        // Every account, not just the selected one, with the cursor on the
        // one this document is about. A list you can see is what makes Tab
        // discoverable; a single "press Tab to change" line asks the reviewer
        // to take on faith both that there is something else and that it is
        // the account they wanted.
        if accounts.len() > 1 {
            approval = approval.section("Connect as");
            for other in accounts {
                let selected = other.id == account.id;
                approval = approval.fact(
                    format!("{} {}", if selected { "▸" } else { " " }, other.id),
                    other.address.to_checksum(None),
                );
            }
            approval = approval.fact("", "Tab moves between them; ← and → choose reject/approve.");
        }

        approval = approval.section("What this session will allow");
        for chain in &scope.chains {
            let name = self.session.network_for(chain).map_or_else(
                || "not configured".to_owned(),
                |network| network.name.clone(),
            );
            approval = approval.fact("Chain", format!("{name} ({chain})"));
        }
        // One method per line rather than one long comma-joined value: on a
        // narrow terminal the joined form wraps into a paragraph of names
        // nobody reads, and this is the list that says what the dapp may do.
        for method in &scope.methods {
            approval = approval.fact("Can call", method);
        }

        // Required and optional get a heading each rather than four labels
        // that all begin with the same word: on a narrow screen the label
        // column is the scarcest thing on the line, and "Needs chains" spends
        // it repeating what a heading can say once.
        approval = approval
            .section("What the dapp cannot work without")
            .fact("Chains", join_or_none(&proposal.required_chains))
            .fact("Methods", join_or_none(&proposal.required_methods))
            .section("What it would also like")
            .fact("Chains", join_or_none(&proposal.optional_chains))
            .fact("Methods", join_or_none(&proposal.optional_methods));

        approval = approval.section("About this connection");
        approval = approval.fact(
            "URL",
            dapp.url.clone().unwrap_or_else(|| "not stated".to_owned()),
        );
        if !dapp.icon_hosts.is_empty() {
            approval = approval.fact("Icons", dapp.icon_hosts.join(", "));
        }
        approval = approval.fact("Pairing", &proposal.pairing_topic);

        // What a reviewer cannot see from the screen itself, and what decides
        // whether the name above means anything at all.
        approval = approval.warning(
            "The site, name, and description above are supplied by the dapp and verified by \
             nobody. A site impersonating another one will claim the other one's name here. Trust \
             this only if you started the connection yourself, just now, from the page you meant.",
        );
        for caution in dapp.cautions {
            approval = approval.warning(caution);
        }
        // `wallet_sendCalls` is the same privilege as `eth_sendTransaction`
        // and then some — one approval covering several calls — so a session
        // carrying either gets the warning.
        let sends: Vec<&str> = ["eth_sendTransaction", "wallet_sendCalls"]
            .into_iter()
            .filter(|method| {
                proposal
                    .required_methods
                    .iter()
                    .chain(&proposal.optional_methods)
                    .any(|requested| requested == method)
            })
            .collect();
        if sends.is_empty() {
            return approval;
        }
        approval.warning(format!(
            "This session includes {}. Transactions your policy already permits will be signed \
             and broadcast without asking again; everything else stops here for your review{}",
            sends.join(" and "),
            if sends.contains(&"wallet_sendCalls") {
                ", and a batch is reviewed and approved as one — every call in it or none."
            } else {
                "."
            }
        ))
    }
}

/// The transaction review, full screen, with the refresh the queued path
/// needs — a transaction is queued here precisely when its simulation failed
/// or its policy asked a question, and the first of those is often about the
/// moment rather than the plan.
struct FullScreenPresenter;

#[async_trait::async_trait]
impl crate::approval::ReviewPresenter for FullScreenPresenter {
    async fn review_transaction(
        &self,
        request: &ApprovalRequest,
        _simulation: &crate::simulation::SimulationResult,
        refresh: &dyn crate::approval::ReviewRefresh,
    ) -> Result<ApprovalDecision> {
        crate::approve_tui::review_fullscreen_refreshable(request, Vec::new(), Some(refresh)).await
    }
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
#[path = "connect_test.rs"]
mod tests;
