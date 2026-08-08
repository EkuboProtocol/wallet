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
    core::execution_plan::{
        DecimalU256, ExecutionPlan, ExecutionStep, ExecutionStepKind, PlannedTransaction,
    },
    custody::OsKeyStore,
    human_presence::PlatformHumanPresence,
    legal,
    message::{MessageEncoding, MessageStore, parse_siwe},
    pending::{PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    sanitize::terminal_safe_line,
    signing_review::{MessageDecision, TypedDataDecision, decide_message, decide_typed_data},
    simulation::simulate_execution,
    token_store::TokenStore,
    typed_data::{TypedDataStore, parse_typed_data},
    walletconnect::{
        crypto::ClientIdentity,
        protocol::{AppMetadata, error_code},
        relay::{DEFAULT_RELAY_URL, RelayConfig, RelayConnection},
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
use std::{path::PathBuf, sync::Mutex};
use url::Url;

/// Environment variable holding the relay project id, so it need not be typed
/// on every invocation.
pub const PROJECT_ID_ENV: &str = "EKUBO_WALLET_WALLETCONNECT_PROJECT_ID";

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
    "wallet_switchEthereumChain",
];

/// What `ekubo-wallet connect` was asked to do.
pub struct ConnectOptions {
    /// The pasted `wc:` URI. Prompted for when absent.
    pub uri: Option<String>,
    /// Which account to expose. Inferred when the wallet holds exactly one.
    pub account: Option<String>,
    /// The relay project id, or `None` to read [`PROJECT_ID_ENV`].
    pub project_id: Option<String>,
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
    let project_id = resolve_project_id(options.project_id)?;
    let relay_url = match options.relay_url {
        Some(url) => url,
        None => Url::parse(DEFAULT_RELAY_URL).expect("the default relay URL is valid"),
    };

    let uri = match options.uri {
        Some(uri) => uri,
        None => prompt_for_uri()?,
    };
    let pairing = PairingUri::parse(&uri, chrono::Utc::now())?;

    crate::tui::info(format!(
        "Connecting as {} ({}) through {}.",
        accounts[selected].id,
        accounts[selected].address.to_checksum(None),
        relay_url.as_str()
    ));
    if accounts.len() > 1 {
        crate::tui::info(format!(
            "{} accounts available; press `a` on the connection review to change which one the \
             dapp gets.",
            accounts.len()
        ));
    }

    let identity = ClientIdentity::generate()?;
    let relay = RelayConnection::connect(
        &RelayConfig {
            url: relay_url,
            project_id,
        },
        &identity,
    )
    .await?;

    let handler = DappSession {
        config,
        accounts,
        selected: std::cell::Cell::new(selected),
        data_dir: config.data_dir().to_path_buf(),
    };
    let session = Session::new(relay, pairing, &handler);
    let outcome = session
        .run(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
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

/// The relay project id, from the flag or the environment.
///
/// There is no default and no anonymous fallback: the public relay refuses a
/// connection without one, and a wallet that silently borrowed somebody else's
/// id would be rate-limited on their quota.
fn resolve_project_id(requested: Option<String>) -> Result<String> {
    let project_id = match requested {
        Some(project_id) => project_id,
        None => std::env::var(PROJECT_ID_ENV).unwrap_or_default(),
    };
    let project_id = project_id.trim().to_owned();
    ensure!(
        !project_id.is_empty(),
        "a WalletConnect relay project id is required. Create one — it is free — at \
         https://dashboard.reown.com, then pass `--project-id` or set {PROJECT_ID_ENV}. It \
         identifies the application to the relay operator, not you, and it is not a secret."
    );
    ensure!(
        project_id.len() <= 128
            && project_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "that does not look like a relay project id: they are short alphanumeric strings"
    );
    Ok(project_id)
}

/// Ask for the link.
///
/// Inline, and before anything full-screen opens, which is the same shape
/// `account create` uses for its one starting question. Nothing after this
/// point prompts inline.
fn prompt_for_uri() -> Result<String> {
    crate::tui::text("Paste the WalletConnect link from the dapp")
        .placeholder("wc:…@2?relay-protocol=irn&symKey=…")
        .help(
            "In the dapp, choose WalletConnect and use its \"copy link\" button rather than \
             scanning the QR code.",
        )
        .validate(|value| {
            if crate::walletconnect::uri::looks_like_pairing_uri(value) {
                Ok(())
            } else {
                Err("a WalletConnect link starts with `wc:`".to_owned())
            }
        })
        .prompt_required()
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
}

#[async_trait::async_trait(?Send)]
impl SessionHandler for DappSession<'_> {
    async fn review_proposal(&self, proposal: &ProposalSummary) -> Result<ProposalDecision> {
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
        match event {
            SessionEvent::Pairing => {
                crate::tui::info("Paired. Waiting for the dapp's connection proposal…");
            }
            SessionEvent::ProposalReceived => {
                crate::tui::info("A connection proposal arrived; opening the review.");
            }
            SessionEvent::Settled { scope, metadata } => {
                crate::tui::note(
                    format!("Connected to {}", describe_dapp(metadata)),
                    format!(
                        "Account {}\nChains  {}\nMethods {}\n\nRequests will appear here as the \
                         dapp sends them. Press Ctrl-C to disconnect.",
                        scope.address,
                        scope.chains.join(", "),
                        scope.methods.join(", "),
                    ),
                );
            }
            SessionEvent::RequestReceived {
                method,
                caip2_chain_id,
            } => {
                crate::tui::info(format!(
                    "{} on {}",
                    terminal_safe_line(method),
                    terminal_safe_line(caip2_chain_id)
                ));
            }
            SessionEvent::RequestAnswered { method, outcome } => match outcome {
                RequestOutcome::Result(_) => {
                    crate::tui::info(format!("{} — answered.", terminal_safe_line(method)));
                }
                RequestOutcome::Error { message, .. } => {
                    crate::tui::warning(format!(
                        "{} — refused: {}",
                        terminal_safe_line(method),
                        terminal_safe_line(message)
                    ));
                }
            },
            SessionEvent::RequestRefused { method, reason } => {
                crate::tui::warning(format!(
                    "{} — outside this session's scope: {}",
                    terminal_safe_line(method),
                    terminal_safe_line(reason)
                ));
            }
            SessionEvent::Ping => {}
            SessionEvent::DappDisconnected { code, message } => {
                crate::tui::info(format!(
                    "The dapp closed the session ({code}): {}",
                    terminal_safe_line(message)
                ));
            }
            SessionEvent::RelayReconnected => {
                crate::tui::info("Reconnected to the relay.");
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
    /// Every dapp-authored string on this screen goes through the sanitizer.
    /// A name is the one thing a person actually reads here, and it is chosen
    /// entirely by the dapp — including, if it likes, a name with a
    /// right-to-left override in it that rewrites the line it sits on.
    fn proposal_document(
        &self,
        proposal: &ProposalSummary,
        account: &WalletMetadata,
        scope: &ApprovedScope,
    ) -> ApprovalRequest {
        let mut approval = ApprovalRequest::new(
            ApprovalKind::PolicyException,
            "Approve a dapp connection",
            "Let this dapp propose transactions and signatures from this account. It cannot sign \
             anything by itself: each request it sends is checked against this wallet's policy \
             and, unless the policy already allows it outright, shown to you before anything is \
             signed.",
        )
        .fact("Dapp name", sanitized(&proposal.metadata.name))
        .fact("Dapp URL", sanitized(&proposal.metadata.url))
        .fact("Description", sanitized(&proposal.metadata.description))
        .fact("Pairing topic", &proposal.pairing_topic)
        .fact(
            "Account exposed",
            format!("{} — {}", account.id, scope.address),
        );
        if self.accounts.len() > 1 {
            approval = approval.fact(
                "Other accounts",
                format!(
                    "press `a` to connect a different one ({})",
                    self.accounts
                        .iter()
                        .filter(|other| other.id != account.id)
                        .map(|other| other.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
        }

        approval = approval.section("What this session will allow");
        for chain in &scope.chains {
            let name = self.network_for(chain).map_or_else(
                || "not configured".to_owned(),
                |network| network.name.clone(),
            );
            approval = approval.fact("Chain", format!("{chain} ({name})"));
        }
        approval = approval.fact("Methods", scope.methods.join(", "));

        approval = approval.section("What the dapp asked for");
        approval = approval.fact("Required chains", join_or_none(&proposal.required_chains));
        approval = approval.fact("Required methods", join_or_none(&proposal.required_methods));
        approval = approval.fact("Optional chains", join_or_none(&proposal.optional_chains));
        approval = approval.fact("Optional methods", join_or_none(&proposal.optional_methods));

        // Two facts about this screen that a person cannot see from the screen
        // itself, and that decide whether the name above means anything.
        approval = approval.warning(
            "The name, URL, and description above are supplied by the dapp and verified by \
             nobody. A site impersonating another one will claim the other one's name here. Trust \
             this only if you started the connection yourself, just now, from the site you meant.",
        );
        if !proposal
            .required_methods
            .iter()
            .chain(&proposal.optional_methods)
            .any(|method| method == "eth_sendTransaction")
        {
            return approval;
        }
        approval.warning(
            "This session includes eth_sendTransaction. Transactions your policy already permits \
             will be signed and broadcast without asking again; everything else stops here for \
             your review.",
        )
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
        match decide_message(self.config, store, record, false).await? {
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
        match decide_typed_data(self.config, store, record, false).await? {
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
        let network = self
            .config
            .network_by_chain_id(&request.chain_id.to_string())?;
        let plan = self.build_plan(request.chain_id, &proposed)?;

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
            &plan,
            &stored_policy,
            &policy_context,
            None,
        )
        .await?;

        let plan_source = describe_plan_source(request.dapp, &proposed);
        let pending = Mutex::new(PendingStore::production(&self.data_dir)?);
        let disposition = crate::orchestrator::execute_automatic(
            self.config,
            &pending,
            &OsKeyStore,
            self.wallet(),
            &network,
            &stored_policy,
            &plan,
            Some(&plan_source),
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
                        return Ok(RequestOutcome::rejected(
                            "The wallet owner declined this transaction.",
                        ));
                    }
                }
            }
        };
        let hash = self.broadcast(&network, signed).await?;
        Ok(RequestOutcome::Result(json!(hash)))
    }

    /// One dapp transaction as a one-step execution plan.
    ///
    /// The dapp's own opinions about nonce, fees, and chain are not carried
    /// over — the wallet decides those, and `proposed.overridden` records what
    /// was set so the review can say so rather than silently disagreeing.
    fn build_plan(
        &self,
        chain_id: u64,
        proposed: &dapp_request::TransactionRequest,
    ) -> Result<ExecutionPlan> {
        let chain = DecimalU256::new(chain_id.to_string())?;
        let plan = ExecutionPlan {
            schema_version: "1".to_owned(),
            chain_id: chain.clone(),
            caip2_chain_id: format!("eip155:{chain_id}"),
            sender: self.wallet().address,
            ordered_steps: vec![ExecutionStep {
                step: 1,
                kind: ExecutionStepKind::Execution,
                transaction: PlannedTransaction {
                    chain_id: chain,
                    from: self.wallet().address,
                    to: proposed.to,
                    data: proposed.data.clone(),
                    value: DecimalU256::new(proposed.value.to_string())?,
                    // Deliberately absent. A gas limit the dapp suggested is
                    // not a fact about the transaction, and the simulation
                    // produces one that is.
                    gas: None,
                },
                revert_decode: None,
            }],
            required_capabilities: Vec::new(),
            extensions: serde_json::Map::new(),
            simulation_failure_policy: None,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Put a queued transaction through the same review `ekubo-wallet review`
    /// runs. `None` means the reviewer rejected it.
    async fn review_queued(
        &self,
        queued: PendingTransaction,
    ) -> Result<Option<PendingTransaction>> {
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
/// Names the dapp, because "a dapp" is not enough to decide on: the reviewer is
/// being asked about a specific transaction and the first question is which
/// site sent it. The name is sanitized — it is dapp-authored text landing in a
/// review document — and the connection review this session already passed said
/// plainly that nobody verifies it.
///
/// Also explicit about what was discarded: a dapp that set a nonce or a gas
/// price asked for something specific and did not get it.
fn describe_plan_source(dapp: &AppMetadata, proposed: &dapp_request::TransactionRequest) -> String {
    use std::fmt::Write as _;

    let mut source = format!("{}, connected over WalletConnect", describe_dapp(dapp));
    if let Some(gas) = proposed.suggested_gas {
        let _ = write!(source, "; it suggested a gas limit of {gas}");
    }
    if !proposed.overridden.is_empty() {
        let _ = write!(
            source,
            "; it also set {}, which this wallet determines itself and ignored",
            proposed.overridden.join(", ")
        );
    }
    terminal_safe_line(&source)
}

/// A dapp's name and URL, for a status line.
fn describe_dapp(metadata: &AppMetadata) -> String {
    match (
        sanitized_optional(&metadata.name),
        sanitized_optional(&metadata.url),
    ) {
        (Some(name), Some(url)) => format!("{name} ({url})"),
        (Some(text), None) | (None, Some(text)) => text,
        (None, None) => "an unnamed dapp".to_owned(),
    }
}

/// Dapp-authored text, made safe to draw and kept to one line, or `None` when
/// what is left after sanitizing says nothing.
///
/// The `None` case is not just the empty string: a name of one zero-width
/// space survives `trim` and disappears in the sanitizer, and a caller that
/// tested the input for emptiness would still print an empty field.
fn sanitized_optional(value: &str) -> Option<String> {
    const MAX_CHARACTERS: usize = 120;
    let safe = crate::sanitize::stripped_capped(value.trim(), MAX_CHARACTERS);
    (!safe.trim().is_empty()).then_some(safe)
}

/// The same, for a review fact, where a field is always drawn and so needs
/// something to say when the dapp left it blank.
fn sanitized(value: &str) -> String {
    sanitized_optional(value).unwrap_or_else(|| "not stated".to_owned())
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
