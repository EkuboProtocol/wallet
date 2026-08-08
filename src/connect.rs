//! `ekubo-wallet connect`: pair with a dapp from a pasted `WalletConnect` link
//! and serve what it proposes.
//!
//! This is the wiring, and the whole point of it is that there is nothing new
//! underneath. A dapp is a proposer, exactly as an MCP agent is, so it gets the
//! proposer's privileges and no others:
//!
//! * `eth_sendTransaction` becomes the same signer-neutral execution plan an
//!   agent would have produced. It is simulated, put to the same policy, and
//!   either signed automatically because the policy already allows it or queued
//!   and reviewed through `orchestrator::approve_transaction` — the same
//!   document, the same guard ladder, the same owner authentication.
//! * `personal_sign` and `eth_signTypedData*` go to
//!   [`crate::signing_review`], which is what `ekubo-wallet review` uses.
//!   Every one of them is reviewed by a person, because no policy can evaluate
//!   what a signature authorizes.
//! * Everything else is either answered from local state or refused.
//!
//! What this module adds on top is two checks a dapp needs and an agent does
//! not. The session's approved scope is enforced in [`crate::walletconnect::session`]
//! before a request reaches here. And every request is checked to be *about
//! this wallet*: a `from`, a signer address, or a typed-data domain naming
//! anything other than the connected account is refused before a record is
//! created, because such a signature is useless to the address it names and can
//! only be a mistake or a trick.

use crate::{
    approval::{ApprovalDecision, ApprovalKind, ApprovalRequest},
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    connect_screen::{IdleView, SessionState},
    core::execution_plan::{
        DecimalU256, ExecutionPlan, ExecutionStep, ExecutionStepKind, PlannedTransaction,
    },
    custody::OsKeyStore,
    human_presence::PlatformHumanPresence,
    legal,
    message::{MessageEncoding, MessageStore, parse_siwe},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    sanitize::terminal_safe_line,
    signing_review::{MessageDecision, TypedDataDecision, decide_message, decide_typed_data},
    simulation::simulate_execution,
    token_store::TokenStore,
    typed_data::{TypedDataStore, parse_typed_data},
    walletconnect::{
        crypto::ClientIdentity,
        identity::DappIdentity,
        protocol::{AppMetadata, error_code},
        relay::{DEFAULT_RELAY_URL, RelayConnection},
        request as dapp_request,
        session::{
            ApprovedScope, DappRequest, ProposalDecision, ProposalSummary, RequestOutcome,
            SUPPORTED_EVENTS, Session, SessionEvent, SessionHandler,
        },
        uri::PairingUri,
    },
};
use alloy::primitives::Address;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use url::Url;

/// The dapp-facing methods this wallet implements.
///
/// Two absences are deliberate rather than unfinished:
///
/// * `eth_sign` signs a bare 32-byte digest with no context whatsoever, so a
///   reviewer cannot be shown what they are authorizing. It is refused
///   everywhere else in this wallet and is refused here.
/// * `eth_signTransaction` hands a signed transaction back to the dapp instead
///   of broadcasting it. This wallet's record of what it has signed is what
///   makes nonce reconciliation and cancellation work, and a signed envelope
///   loose in a dapp's memory breaks both.
pub const SUPPORTED_METHODS: &[&str] = &[
    "eth_accounts",
    "eth_chainId",
    "eth_sendTransaction",
    "eth_signTypedData",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
    "personal_sign",
    "wallet_getCallsStatus",
    "wallet_getCapabilities",
    "wallet_sendCalls",
    "wallet_switchEthereumChain",
];

/// The most calls this wallet will take in one EIP-5792 batch.
///
/// A plan can hold far more, and the chain would carry them, but a batch is
/// approved as one document by a person reading it: past a couple of dozen
/// calls nobody is reading, and "approve all of this" stops meaning anything.
/// A dapp told the batch is too large can send smaller ones.
pub const MAX_BATCH_CALLS: usize = 24;

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
    let handler = DappSession {
        config,
        accounts,
        selected: std::cell::Cell::new(selected),
        data_dir: config.data_dir().to_path_buf(),
        state: Arc::clone(&state),
        idle: RefCell::new(None),
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
    handler.suspend_idle().await;
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

/// One dapp session, bound to one account.
struct DappSession<'a> {
    config: &'a ConfigStore,
    /// Every account the connection review may be pointed at.
    accounts: Vec<WalletMetadata>,
    /// Which one the reviewer settled on. Written once, when the connection
    /// review returns, and read by every request afterwards.
    ///
    /// A `Cell` because [`SessionHandler`] takes `&self` — the session owns the
    /// handler for the whole run — and because the alternative, threading the
    /// choice back out through the trait, would put a session-lifetime decision
    /// into a per-request signature. Nothing here is shared across threads: the
    /// handler's futures are `?Send` and run on the thread that owns the
    /// terminal.
    selected: std::cell::Cell<usize>,
    data_dir: PathBuf,
    /// What the idle surface draws. Shared with the loop drawing it.
    state: Arc<Mutex<SessionState>>,
    /// The running idle surface, when it holds the terminal.
    ///
    /// `None` means something else does — a review, or owner authentication.
    /// Exactly one of them ever reads a keystroke, and the handover is the
    /// `suspend_idle`/`enter_idle` pair rather than anything implicit.
    idle: RefCell<Option<IdleView>>,
}

impl DappSession<'_> {
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

    /// Record something that happened, for the idle surface's log.
    fn log(&self, tone: crate::tui::Tone, text: impl AsRef<str>) {
        if let Ok(mut state) = self.state.lock() {
            state.push(crate::connect_screen::event(tone, text));
        }
    }

    fn set_status(&self, status: impl Into<String>) {
        if let Ok(mut state) = self.state.lock() {
            state.status = status.into();
        }
    }
}

#[async_trait::async_trait(?Send)]
impl SessionHandler for DappSession<'_> {
    async fn enter_idle(&self) {
        if self.idle.borrow().is_some() {
            return;
        }
        let view = IdleView::start(Arc::clone(&self.state));
        *self.idle.borrow_mut() = Some(view);
    }

    async fn quit_requested(&self) {
        // Polled rather than signalled: the alternative is a channel whose
        // receiver has to survive the surface being stopped and restarted
        // around every review, and this future is dropped and rebuilt on every
        // turn of the session loop anyway.
        loop {
            if self
                .idle
                .borrow()
                .as_ref()
                .is_some_and(IdleView::wants_quit)
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn review_proposal(&self, proposal: &ProposalSummary) -> Result<ProposalDecision> {
        // Everything below draws, so the idle surface hands the terminal over
        // first and does not take it back until the session loop waits again.
        self.suspend_idle().await;
        // Anything the dapp cannot work without has to be satisfiable before a
        // person is asked, because approving a session that cannot serve the
        // dapp's required scope produces a connection that fails on its first
        // request with no explanation.
        let mut unconfigured = Vec::new();
        for chain in &proposal.required_chains {
            if self.network_for(chain).is_none() {
                unconfigured.push(chain.clone());
            }
        }
        if !unconfigured.is_empty() {
            return Ok(ProposalDecision::Reject {
                code: error_code::UNSUPPORTED_CHAINS,
                message: format!(
                    "This wallet has no configuration for {}. Add the network with \
                     `ekubo-wallet network add` and reconnect.",
                    unconfigured.join(", ")
                ),
            });
        }
        let unsupported: Vec<&String> = proposal
            .required_methods
            .iter()
            .filter(|method| !SUPPORTED_METHODS.contains(&method.as_str()))
            .collect();
        if !unsupported.is_empty() {
            return Ok(ProposalDecision::Reject {
                code: error_code::UNSUPPORTED_METHODS,
                message: format!(
                    "This wallet does not implement {}.",
                    unsupported
                        .iter()
                        .map(|method| method.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        // Optional chains are exposed only when this wallet already has a
        // configuration for them; an optional chain is not a reason to ask the
        // person to configure anything.
        let mut chains = proposal.required_chains.clone();
        for chain in &proposal.optional_chains {
            if self.network_for(chain).is_some() && !chains.contains(chain) {
                chains.push(chain.clone());
            }
        }
        if chains.is_empty() {
            return Ok(ProposalDecision::Reject {
                code: error_code::UNSUPPORTED_CHAINS,
                message: "None of the chains this dapp asked for are configured in this wallet."
                    .to_owned(),
            });
        }
        let methods: Vec<String> = SUPPORTED_METHODS
            .iter()
            .filter(|method| {
                proposal.required_methods.iter().any(|m| m == *method)
                    || proposal.optional_methods.iter().any(|m| m == *method)
            })
            .map(|method| (*method).to_owned())
            .collect();

        // One complete review per account, authored before the screen opens,
        // so switching between them is instant and the reviewer always sees
        // the consequences of the account actually selected — the address
        // exposed, and which chains it will be exposed on.
        let scopes: Vec<ApprovedScope> = self
            .accounts
            .iter()
            .map(|account| Self::scope_for(account, chains.clone(), methods.clone()))
            .collect();
        let choices: Vec<crate::approve_tui::ReviewChoice> = self
            .accounts
            .iter()
            .zip(&scopes)
            .map(|(account, scope)| crate::approve_tui::ReviewChoice {
                request: self.proposal_document(proposal, account, scope),
                label: account.id.clone(),
            })
            .collect();

        let (decision, chosen) =
            crate::approve_tui::review_fullscreen_choosing(choices, self.selected.get()).await?;
        if decision != ApprovalDecision::Approved {
            return Ok(ProposalDecision::Reject {
                code: error_code::USER_REJECTED,
                message: "The wallet owner declined this connection.".to_owned(),
            });
        }
        // Recorded before the scope is handed back, so every request served
        // afterwards signs for the account whose review was approved.
        self.selected.set(chosen);
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
        // The surface is released by the paths that actually draw
        // ([`Self::review_queued`] and the two signing reviews) and taken back
        // by the session loop afterwards. Everything else answers underneath
        // it, and its log line appears in place.
        //
        // A failure carrying out one request answers that request and leaves
        // the session up. Ending the whole session because one call could not
        // be served would disconnect the dapp mid-flow over, say, one RPC
        // timeout, and the person would have to re-pair to find out.
        Ok(match self.dispatch(request).await {
            Ok(outcome) => outcome,
            Err(error) => RequestOutcome::failed(format!("{error:#}")),
        })
    }

    fn notify(&self, event: &SessionEvent<'_>) {
        use crate::tui::Tone;
        match event {
            SessionEvent::Pairing => {
                self.set_status("Waiting for the dapp");
                self.log(Tone::Muted, "Paired. Waiting for the connection proposal…");
            }
            SessionEvent::ProposalReceived => {
                self.log(Tone::Info, "A connection proposal arrived.");
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
                        self.network_for(chain)
                            .map_or_else(|| chain.clone(), |network| network.name)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                if let Ok(mut state) = self.state.lock() {
                    state.title = format!("Connected to {}", dapp.host_or_unknown());
                    state.header = vec![
                        crate::connect_screen::fact("Site", &dapp.host_or_unknown()),
                        crate::connect_screen::fact(
                            "Name",
                            dapp.name.as_deref().unwrap_or("not stated"),
                        ),
                        crate::connect_screen::fact("Account", &self.wallet().id),
                        crate::connect_screen::fact("Address", &scope.address),
                        crate::connect_screen::fact("Chains", &chains),
                        Vec::new(),
                    ];
                    "Connected".clone_into(&mut state.status);
                }
                self.log(Tone::Success, "Connected. Waiting for requests…");
            }
            SessionEvent::RequestReceived {
                method,
                caip2_chain_id,
            } => {
                self.set_status(format!("Serving {}", terminal_safe_line(method)));
                self.log(
                    Tone::Info,
                    format!(
                        "{} on {}",
                        terminal_safe_line(method),
                        terminal_safe_line(caip2_chain_id)
                    ),
                );
            }
            SessionEvent::RequestAnswered { method, outcome } => {
                self.set_status("Connected");
                match outcome {
                    RequestOutcome::Result(_) => self.log(
                        Tone::Success,
                        format!("{} — answered.", terminal_safe_line(method)),
                    ),
                    RequestOutcome::Error { message, .. } => self.log(
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
                self.set_status("Connected");
                self.log(
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
                self.set_status("Disconnected");
                self.log(
                    Tone::Info,
                    format!(
                        "The dapp closed the session ({code}): {}",
                        terminal_safe_line(message)
                    ),
                );
            }
            SessionEvent::RelayReconnected => {
                self.log(Tone::Info, "Reconnected to the relay.");
            }
        }
    }
}

impl DappSession<'_> {
    /// The account this session signs for.
    fn wallet(&self) -> &WalletMetadata {
        &self.accounts[self.selected.get().min(self.accounts.len() - 1)]
    }

    /// The scope a session would expose if it settled on `account`.
    fn scope_for(
        account: &WalletMetadata,
        chains: Vec<String>,
        methods: Vec<String>,
    ) -> ApprovedScope {
        ApprovedScope {
            address: account.address.to_checksum(None),
            chains,
            methods,
            events: SUPPORTED_EVENTS
                .iter()
                .map(|event| (*event).to_owned())
                .collect(),
        }
    }

    /// The network configured for a CAIP-2 chain, if any.
    fn network_for(&self, caip2: &str) -> Option<NetworkConfig> {
        let chain_id = crate::walletconnect::session::numeric_chain_id(caip2)?;
        self.config.network_by_chain_id(&chain_id.to_string()).ok()
    }

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
        if self.accounts.len() > 1 {
            approval = approval.section("Connect as");
            for other in &self.accounts {
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
            let name = self.network_for(chain).map_or_else(
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

    async fn dispatch(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        match request.method.as_str() {
            "eth_accounts" => Ok(RequestOutcome::Result(json!([self
                .wallet()
                .address
                .to_checksum(None)]))),
            "eth_chainId" => Ok(RequestOutcome::Result(json!(format!(
                "0x{:x}",
                request.chain_id
            )))),
            // The session's chains were fixed when it settled, so this can only
            // ever confirm one of them. EIP-3326 answers null on success, and
            // 4902 for a chain the wallet does not have.
            "wallet_switchEthereumChain" => {
                let requested = dapp_request::parse_switch_chain(&request.params)?;
                // Any chain the session approved is a legitimate destination,
                // not only the one this request happened to arrive on.
                if request
                    .scope
                    .chains
                    .iter()
                    .any(|chain| chain == &format!("eip155:{requested}"))
                {
                    Ok(RequestOutcome::Result(Value::Null))
                } else {
                    Ok(RequestOutcome::Error {
                        code: error_code::CHAIN_NOT_ADDED,
                        message: format!(
                            "This session covers only {}. Disconnect and reconnect to include \
                             chain {requested}.",
                            request.scope.chains.join(", ")
                        ),
                    })
                }
            }
            "personal_sign" => self.personal_sign(request).await,
            "eth_signTypedData" | "eth_signTypedData_v3" | "eth_signTypedData_v4" => {
                self.sign_typed_data(request).await
            }
            "eth_sendTransaction" => self.send_transaction(request).await,
            "wallet_getCapabilities" => self.capabilities(request),
            "wallet_sendCalls" => self.send_calls(request).await,
            "wallet_getCallsStatus" => self.calls_status(request).await,
            other => Ok(RequestOutcome::Error {
                code: error_code::UNSUPPORTED_METHODS,
                message: format!(
                    "This wallet does not implement `{}`.",
                    terminal_safe_line(other)
                ),
            }),
        }
    }

    async fn personal_sign(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let (message, signer, was_hex) = dapp_request::parse_personal_sign(&request.params)?;
        if let Some(refusal) = self.refuse_foreign_signer(signer) {
            return Ok(refusal);
        }
        // The same check the MCP path makes: a login naming a different account
        // is useless to the address it names, so it is refused before a record
        // exists rather than shown to a person as a decision.
        if let Some(siwe) = std::str::from_utf8(&message).ok().and_then(parse_siwe)
            && siwe.address != self.wallet().address.to_checksum(None)
        {
            return Ok(RequestOutcome::failed(format!(
                "this sign-in message names account {}, but this session is {}",
                siwe.address,
                self.wallet().address.to_checksum(None)
            )));
        }

        let requester = DappIdentity::of(request.dapp).headline();
        let encoding = if was_hex {
            MessageEncoding::Hex
        } else {
            MessageEncoding::Text
        };
        let record = MessageStore::production(&self.data_dir)?.create(
            &self.wallet().id,
            Some(&request.chain_id.to_string()),
            &message,
            encoding,
        )?;
        let store = MessageStore::production(&self.data_dir)?;
        // Every message is reviewed by a person, so this one always draws.
        self.suspend_idle().await;
        match decide_message(self.config, store, record, Some(&requester), false).await? {
            MessageDecision::Rejected(_) => Ok(RequestOutcome::rejected(
                "The wallet owner declined to sign this message.",
            )),
            MessageDecision::Signed(record) => Ok(RequestOutcome::Result(json!(
                record
                    .signature
                    .context("the approved message carries no signature")?
            ))),
        }
    }

    async fn sign_typed_data(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let (signer, payload) = dapp_request::parse_sign_typed_data(&request.params)?;
        if let Some(refusal) = self.refuse_foreign_signer(signer) {
            return Ok(refusal);
        }
        let requester = DappIdentity::of(request.dapp).headline();
        let (_, chain_id, digest) = parse_typed_data(&payload)?;
        // The domain's own chain has to be the chain the request came in on.
        // Without this, a session approved on a testnet could collect a
        // signature whose domain binds it to mainnet, and the signature would
        // be perfectly valid there.
        if chain_id != request.chain_id {
            return Ok(RequestOutcome::failed(format!(
                "this payload's EIP-712 domain binds chain {chain_id}, but the request arrived on \
                 chain {}",
                request.chain_id
            )));
        }
        self.config.network_by_chain_id(&chain_id.to_string())?;

        let record = TypedDataStore::production(&self.data_dir)?.create(
            &self.wallet().id,
            chain_id,
            &payload,
            digest,
        )?;
        let store = TypedDataStore::production(&self.data_dir)?;
        // Every typed-data payload is reviewed by a person, so this one always
        // draws.
        self.suspend_idle().await;
        match decide_typed_data(self.config, store, record, Some(&requester), false).await? {
            TypedDataDecision::Rejected(_) => Ok(RequestOutcome::rejected(
                "The wallet owner declined to sign this payload.",
            )),
            TypedDataDecision::Signed(record) => Ok(RequestOutcome::Result(json!(
                record
                    .signature
                    .context("the approved payload carries no signature")?
            ))),
        }
    }

    async fn send_transaction(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let proposed = dapp_request::parse_send_transaction(&request.params)?;
        if let Some(refusal) = self.refuse_foreign_signer(proposed.from) {
            return Ok(refusal);
        }
        let plan = self.build_plan(
            request.chain_id,
            &[dapp_request::ProposedCall {
                to: proposed.to,
                data: proposed.data.clone(),
                value: proposed.value,
            }],
        )?;
        self.log(
            crate::tui::Tone::Info,
            describe_dapp_request(request.dapp, &proposed),
        );
        match self
            .execute_plan(request.chain_id, &plan, &describe_plan_source(request.dapp))
            .await?
        {
            Ok(record) => Ok(RequestOutcome::Result(json!(
                record
                    .broadcast_transaction_hash
                    .context("the broadcast record carries no transaction hash")?
            ))),
            Err(refusal) => Ok(refusal),
        }
    }

    /// EIP-5792 `wallet_getCapabilities`.
    ///
    /// Atomicity is reported as `supported` because it is: two or more calls
    /// become one `revertOnFailure` Calibur batch, so either all of them
    /// happen or none does. It is reported per chain the session approved,
    /// because that is where this wallet can act at all.
    fn capabilities(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let (address, requested) = dapp_request::parse_get_capabilities(&request.params)?;
        if let Some(refusal) = self.refuse_foreign_signer(address) {
            return Ok(refusal);
        }
        let mut capabilities = serde_json::Map::new();
        for chain in &request.scope.chains {
            let Some(chain_id) = chain
                .strip_prefix("eip155:")
                .and_then(|id| id.parse::<u64>().ok())
            else {
                continue;
            };
            // An empty list is the dapp asking about everything, which is what
            // the spec says to answer when it does not narrow the question.
            if !requested.is_empty() && !requested.contains(&chain_id) {
                continue;
            }
            capabilities.insert(
                format!("0x{chain_id:x}"),
                json!({ "atomic": { "status": "supported" } }),
            );
        }
        Ok(RequestOutcome::Result(Value::Object(capabilities)))
    }

    /// EIP-5792 `wallet_sendCalls`.
    ///
    /// One batch is one execution plan, so it takes exactly the path a single
    /// transaction takes: simulated once as a whole, put to the same policy,
    /// and either signed automatically or reviewed as one document showing
    /// every call. The id handed back is the pending record's, which is what
    /// `wallet_getCallsStatus` reads and what `ekubo-wallet transaction show`
    /// takes.
    async fn send_calls(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let batch = dapp_request::parse_send_calls(&request.params)?;
        if let Some(from) = batch.from
            && let Some(refusal) = self.refuse_foreign_signer(from)
        {
            return Ok(refusal);
        }
        if let Some(unsupported) = batch.required_capabilities.first() {
            return Ok(RequestOutcome::Error {
                code: error_code::UNSUPPORTED_CAPABILITY,
                message: format!(
                    "This wallet does not implement the `{}` capability, and this batch did not \
                     mark it optional.",
                    terminal_safe_line(unsupported)
                ),
            });
        }
        // The chain the batch names, not the one the request arrived on: a
        // dapp may hold one session across several chains, and the batch says
        // which of them it means.
        if !request
            .scope
            .chains
            .iter()
            .any(|chain| chain == &format!("eip155:{}", batch.chain_id))
        {
            return Ok(RequestOutcome::Error {
                code: error_code::UNSUPPORTED_CHAIN_ID,
                message: format!(
                    "This session covers only {}, not chain {}.",
                    request.scope.chains.join(", "),
                    batch.chain_id
                ),
            });
        }
        if batch.calls.len() > MAX_BATCH_CALLS {
            return Ok(RequestOutcome::Error {
                code: error_code::BUNDLE_TOO_LARGE,
                message: format!(
                    "This batch holds {} calls, and this wallet reviews at most {MAX_BATCH_CALLS} \
                     in one request.",
                    batch.calls.len()
                ),
            });
        }

        let plan = self.build_plan(batch.chain_id, &batch.calls)?;
        self.log(
            crate::tui::Tone::Info,
            terminal_safe_line(&format!(
                "{} proposed a batch of {} calls, to execute atomically",
                DappIdentity::of(request.dapp).headline(),
                batch.calls.len()
            )),
        );
        match self
            .execute_plan(batch.chain_id, &plan, &describe_plan_source(request.dapp))
            .await?
        {
            Ok(record) => Ok(RequestOutcome::Result(
                json!({ "id": batch_id(record.request_id) }),
            )),
            Err(refusal) => Ok(refusal),
        }
    }

    /// EIP-5792 `wallet_getCallsStatus`.
    ///
    /// Answers only for records this session's own account owns. A batch id is
    /// a record id, and a dapp that guessed one belonging to another wallet on
    /// this machine would otherwise read its history.
    async fn calls_status(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let id = dapp_request::parse_get_calls_status(&request.params)?;
        let unknown = || RequestOutcome::Error {
            code: error_code::UNKNOWN_BUNDLE_ID,
            message: "This wallet has no batch under that id.".to_owned(),
        };
        let Some(request_id) = parse_batch_id(&id) else {
            return Ok(unknown());
        };
        let store = PendingStore::production(&self.data_dir)?;
        let Ok(record) = store.get(request_id) else {
            return Ok(unknown());
        };
        drop(store);
        if record.wallet_id != self.wallet().id {
            return Ok(unknown());
        }

        let receipts = match record.broadcast_transaction_hash.as_deref() {
            Some(hash)
                if matches!(
                    record.status,
                    PendingStatus::Confirmed | PendingStatus::Reverted
                ) =>
            {
                let network = self.config.network(&record.network_name)?;
                crate::rpc::transaction_receipt_details(&network, hash)
                    .await
                    .ok()
                    .flatten()
                    .map(|receipt| json!([receipt_json(hash, &receipt)]))
            }
            _ => None,
        };
        let mut status = serde_json::Map::from_iter([
            (
                "version".to_owned(),
                json!(dapp_request::SEND_CALLS_VERSION),
            ),
            ("id".to_owned(), json!(batch_id(record.request_id))),
            (
                "chainId".to_owned(),
                json!(format!(
                    "0x{:x}",
                    record.chain_id.parse::<u64>().unwrap_or_default()
                )),
            ),
            // Every batch this wallet executes is all-or-nothing, so there is
            // no partial-failure case to report.
            ("atomic".to_owned(), json!(true)),
            ("status".to_owned(), json!(calls_status_code(record.status))),
        ]);
        if let Some(receipts) = receipts {
            status.insert("receipts".to_owned(), receipts);
        }
        Ok(RequestOutcome::Result(Value::Object(status)))
    }

    /// A dapp's calls as one execution plan, in the order it gave them.
    ///
    /// The dapp's own opinions about nonce, fees, and chain are not carried
    /// over — the wallet decides those, and `overridden` on a single
    /// transaction records what was set so the review can say so rather than
    /// silently disagreeing.
    ///
    /// A plan of two or more steps is what makes an EIP-5792 batch atomic:
    /// [`crate::execution`] turns it into one `revertOnFailure` Calibur batch,
    /// so either every call happens or none does.
    fn build_plan(
        &self,
        chain_id: u64,
        calls: &[dapp_request::ProposedCall],
    ) -> Result<ExecutionPlan> {
        let chain = DecimalU256::new(chain_id.to_string())?;
        let mut ordered_steps = Vec::with_capacity(calls.len());
        for (index, call) in calls.iter().enumerate() {
            ordered_steps.push(ExecutionStep {
                step: u32::try_from(index + 1)
                    .context("that is more calls than a plan can hold")?,
                kind: ExecutionStepKind::Execution,
                transaction: PlannedTransaction {
                    chain_id: chain.clone(),
                    from: self.wallet().address,
                    to: call.to,
                    data: call.data.clone(),
                    value: DecimalU256::new(call.value.to_string())?,
                    // Deliberately absent. A gas limit the dapp suggested is
                    // not a fact about the transaction, and the simulation
                    // produces one that is.
                    gas: None,
                },
                revert_decode: None,
            });
        }
        let plan = ExecutionPlan {
            schema_version: "1".to_owned(),
            chain_id: chain,
            caip2_chain_id: format!("eip155:{chain_id}"),
            sender: self.wallet().address,
            ordered_steps,
            required_capabilities: Vec::new(),
            extensions: serde_json::Map::new(),
            simulation_failure_policy: None,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Simulate, policy-check, review if the policy says so, sign, and
    /// broadcast one plan.
    ///
    /// Shared by `eth_sendTransaction` and `wallet_sendCalls` so that a batch
    /// is not a second, quieter path to a signature: same simulation, same
    /// policy, same guard ladder, same review document.
    async fn execute_plan(
        &self,
        chain_id: u64,
        plan: &ExecutionPlan,
        plan_source: &str,
    ) -> Result<std::result::Result<PendingTransaction, RequestOutcome>> {
        let network = self.config.network_by_chain_id(&chain_id.to_string())?;

        let policies = PolicyStore::production(&self.data_dir)?;
        let stored_policy = policies
            .get(&self.wallet().id)?
            .with_context(|| format!("wallet {} has no local policy", self.wallet().id))?;
        drop(policies);

        let policy_context = crate::core::predicate::PolicyContext {
            wallet: self.wallet().address,
        };
        let simulation = simulate_execution(
            self.wallet(),
            &network,
            plan,
            &stored_policy,
            &policy_context,
            None,
        )
        .await?;

        let pending = Mutex::new(PendingStore::production(&self.data_dir)?);
        let disposition = crate::orchestrator::execute_automatic(
            self.config,
            &pending,
            &OsKeyStore,
            self.wallet(),
            &network,
            &stored_policy,
            plan,
            Some(plan_source),
            &simulation,
        )
        .await?;
        drop(pending);

        let signed = match disposition {
            crate::orchestrator::SendDisposition::Signed(record) => record,
            crate::orchestrator::SendDisposition::Queued(queued) => {
                match self.review_queued(queued).await? {
                    Some(record) => record,
                    None => {
                        return Ok(Err(RequestOutcome::rejected(
                            "The wallet owner declined this transaction.",
                        )));
                    }
                }
            }
        };
        let request_id = signed.request_id;
        self.broadcast(&network, signed).await?;
        // Re-read rather than returning the pre-broadcast record: the hash and
        // status a caller reports onward are written by the submission.
        Ok(Ok(
            PendingStore::production(&self.data_dir)?.get(request_id)?
        ))
    }

    /// Put a queued transaction through the same review `ekubo-wallet review`
    /// runs. `None` means the reviewer rejected it.
    async fn review_queued(
        &self,
        queued: PendingTransaction,
    ) -> Result<Option<PendingTransaction>> {
        // The review draws, and owner authentication below it may put a polkit
        // text agent on this same terminal, so the idle surface hands it over
        // before either — and the session loop takes it back afterwards.
        self.suspend_idle().await;
        let data_dir = self.data_dir.clone();
        let wallet_id = self.wallet().id.clone();
        let read_policy = move || -> Result<crate::policy_store::StoredPolicy> {
            PolicyStore::production(&data_dir)?
                .get(&wallet_id)?
                .with_context(|| format!("wallet {wallet_id} has no local policy"))
        };
        let outcome = crate::orchestrator::approve_transaction(
            self.config,
            PendingStore::production(&self.data_dir)?,
            &TokenStore::production(&self.data_dir)?,
            &read_policy,
            queued,
            crate::approval::InteractiveProof::from_terminal()?,
            &FullScreenPresenter,
            &PlatformHumanPresence,
            &OsKeyStore,
        )
        .await?;
        Ok(match outcome {
            crate::orchestrator::ApprovalOutcome::Rejected(_) => None,
            crate::orchestrator::ApprovalOutcome::Signed(record) => Some(record),
        })
    }

    /// Broadcast the signed envelope and return the hash the dapp is waiting
    /// for.
    async fn broadcast(
        &self,
        network: &NetworkConfig,
        record: PendingTransaction,
    ) -> Result<String> {
        let request_id = record.request_id;
        let pending = Mutex::new(PendingStore::production(&self.data_dir)?);
        let claimed = {
            let mut store = pending
                .lock()
                .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?;
            store.claim_for_submission(request_id)?
        };
        let (record, broadcast) =
            crate::reconcile::submit_claimed(&pending, self.wallet(), network, claimed).await?;
        if let Some(error) = broadcast.broadcast_error {
            bail!("the transaction was signed but the node refused it: {error}");
        }
        record
            .signed_transaction_hash
            .context("the broadcast transaction has no hash")
    }

    /// Refuse a request that names an address this session does not control.
    fn refuse_foreign_signer(&self, address: Address) -> Option<RequestOutcome> {
        if address == self.wallet().address {
            return None;
        }
        Some(RequestOutcome::Error {
            code: error_code::UNSUPPORTED_ACCOUNTS,
            message: format!(
                "This session signs for {} only; the request names {}.",
                self.wallet().address.to_checksum(None),
                address.to_checksum(None)
            ),
        })
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

/// What the approval document says this plan came from.
///
/// The dapp's own account of itself behind
/// [`crate::pending::DAPP_PLAN_SOURCE_PREFIX`], which is what marks it as
/// claimed rather than proved: the same field holds a TLS-verified host for a
/// fetched plan, and the two must not read alike. The host rides along with
/// the name because it is the part a person can compare against the address
/// bar they opened the site from.
///
/// Capped to what the store accepts. A dapp's claimed name is up to 120
/// characters and characters are up to four bytes, so a long enough name in a
/// wide enough script would otherwise be refused at exactly the moment the
/// owner is trying to sign.
fn describe_plan_source(dapp: &AppMetadata) -> String {
    let mut source = format!(
        "{}{}",
        crate::pending::DAPP_PLAN_SOURCE_PREFIX,
        DappIdentity::of(dapp).headline()
    );
    while source.len() > crate::pending::MAX_PLAN_SOURCE_BYTES {
        source.pop();
    }
    terminal_safe_line(&source)
}

/// What this session says about a request, for the log on the session screen.
///
/// The log is a running account of who asked for what, so it names the dapp
/// and states what was discarded: a dapp that set a nonce or a gas price asked
/// for something specific and did not get it. That detail belongs here rather
/// than in the plan source, which answers who produced the bytes and nothing
/// else.
fn describe_dapp_request(
    dapp: &AppMetadata,
    proposed: &dapp_request::TransactionRequest,
) -> String {
    use std::fmt::Write as _;

    let mut line = format!(
        "{} proposed a transaction",
        DappIdentity::of(dapp).headline()
    );
    if let Some(gas) = proposed.suggested_gas {
        let _ = write!(line, "; it suggested a gas limit of {gas}");
    }
    if !proposed.overridden.is_empty() {
        let _ = write!(
            line,
            "; it also set {}, which this wallet determines itself and ignored",
            proposed.overridden.join(", ")
        );
    }
    terminal_safe_line(&line)
}

/// A pending record's id as an EIP-5792 batch id.
///
/// The record's own UUID, hex-encoded. Using the id the rest of the wallet
/// already uses means a batch a dapp is asking about is the same thing
/// `ekubo-wallet transaction show` prints and `transaction cancel` acts on,
/// rather than a second identifier that has to be kept in step with the first.
fn batch_id(request_id: uuid::Uuid) -> String {
    format!("0x{}", hex::encode(request_id.as_bytes()))
}

/// The record id inside a batch id, or `None` for anything this wallet did not
/// mint.
fn parse_batch_id(id: &str) -> Option<uuid::Uuid> {
    let bytes = hex::decode(id.strip_prefix("0x").unwrap_or(id)).ok()?;
    uuid::Uuid::from_slice(&bytes).ok()
}

/// EIP-5792's status code for what the chain has done with a batch so far.
///
/// The spec's 600 — partially reverted — is unreachable here and deliberately
/// so: a multi-call plan executes as one `revertOnFailure` batch, so the only
/// outcomes are all of it, none of it, or not yet.
const fn calls_status_code(status: PendingStatus) -> u16 {
    match status {
        PendingStatus::AwaitingApproval
        | PendingStatus::Signed
        | PendingStatus::Submitting
        | PendingStatus::Broadcast
        | PendingStatus::Cancelling => 100,
        PendingStatus::Confirmed => 200,
        // Onchain, and every call reverted together.
        PendingStatus::Reverted => 500,
        // Never made it onchain and never will: declined, cancelled, or its
        // nonce taken by something else.
        PendingStatus::Rejected | PendingStatus::Cancelled | PendingStatus::Replaced => 400,
    }
}

/// One mined receipt in the shape EIP-5792 asks for.
fn receipt_json(transaction_hash: &str, receipt: &crate::rpc::ReceiptDetails) -> Value {
    json!({
        "logs": receipt
            .logs
            .iter()
            .map(|log| json!({
                "address": format!("{:#x}", log.address),
                "topics": log.topics.iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>(),
                "data": format!("0x{}", hex::encode(&log.data)),
            }))
            .collect::<Vec<_>>(),
        "status": if receipt.succeeded { "0x1" } else { "0x0" },
        "blockHash": format!("{:#x}", receipt.block_hash),
        "blockNumber": format!("0x{:x}", receipt.block_number),
        "gasUsed": format!("0x{:x}", receipt.gas_used),
        "transactionHash": transaction_hash,
    })
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
