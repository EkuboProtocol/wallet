//! What a dapp session does, independent of who answers its questions.
//!
//! A dapp reached over `WalletConnect` is a proposer, exactly as an MCP agent
//! is, so it gets the proposer's privileges and no others: every transaction it
//! proposes becomes the same signer-neutral execution plan an agent would have
//! produced, is simulated, is put to the same policy, and is either signed
//! automatically because the policy already allows it or held until a person
//! approves it. Every signature request is held for a person unconditionally,
//! because no policy can evaluate what a signature authorizes.
//!
//! Two surfaces reach this module and they differ in exactly one respect —
//! *how* a request that needs a person is put to one:
//!
//! * `ekubo-wallet connect` owns a terminal, so it draws the review there and
//!   waits for the keystroke.
//! * The MCP server owns no terminal, so it leaves the queued record for
//!   `ekubo-wallet review` and waits for the row to change.
//!
//! That difference is [`DappSurface`] and nothing else is. Everything a dapp
//! can ask for, everything it is refused, and every check between the two is
//! here, so a fix lands once for both. The alternative — a second copy for the
//! MCP path — is precisely the shape of this feature's existing bug history:
//! the batch-ownership check and the replay-eviction order were both wrong in
//! one place and right in another before they were wrong in both.
//!
//! Nothing in this module can widen a policy, and nothing in it decides whether
//! a person is asked. Where the policy says a person must be asked, this module
//! creates the record and hands it to the surface.

use crate::{
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    core::execution_plan::{
        DecimalU256, ExecutionPlan, ExecutionStep, ExecutionStepKind, PlannedTransaction,
    },
    custody::OsKeyStore,
    legal,
    message::{MessageEncoding, MessageStore, PendingMessage, parse_siwe},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    sanitize::terminal_safe_line,
    simulation::simulate_execution,
    typed_data::{PendingTypedData, TypedDataStore, parse_typed_data},
    walletconnect::{
        identity::DappIdentity,
        protocol::{AppMetadata, error_code},
        request as dapp_request,
        session::{
            ApprovedScope, DappRequest, ProposalDecision, ProposalSummary, RequestOutcome,
            SUPPORTED_EVENTS,
        },
    },
};
use alloy::primitives::Address;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{cell::RefCell, path::PathBuf, sync::Mutex};

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

/// How a session puts a request to the person who has to decide it, and how it
/// reports what is happening.
///
/// The three `resolve_*` methods are the whole of the difference between a
/// session on a terminal and a session under the MCP server. Each is handed a
/// record that already exists in the encrypted store, and each returns the
/// decided record or `None` for a refusal. Neither implementation may sign by
/// itself: the terminal one goes through the orchestrator's review, and the
/// headless one waits for `ekubo-wallet review` to do exactly that.
#[async_trait::async_trait(?Send)]
pub trait DappSurface {
    /// Whether a disconnect has already been asked for.
    ///
    /// Checked before every request rather than only between them: the session
    /// loop selects between relay delivery and the disconnect, so delivery can
    /// win the race and arrive with the answer already given.
    fn closing(&self) -> bool {
        false
    }

    /// Record something that happened, for whatever surface is showing it.
    ///
    /// Deliberately a bare string. A tone would be the one presentation
    /// concept crossing this seam, and it would put `crate::tui` in the
    /// import list of a module the audit boundary reads for the absence of
    /// exactly that. A surface that draws picks its own tone.
    fn log(&self, text: &str);

    /// Settle a transaction the policy declined to sign automatically.
    ///
    /// `None` means it was refused — by a person, or by the request outliving
    /// what the surface can wait for.
    async fn resolve_queued(
        &self,
        queued: PendingTransaction,
    ) -> Result<Option<PendingTransaction>>;

    /// Settle a message signature. Always reaches a person: no policy
    /// authorizes a signature.
    async fn resolve_message(
        &self,
        record: PendingMessage,
        account: &WalletMetadata,
    ) -> Result<Option<PendingMessage>>;

    /// Settle a typed-data signature, for the same reason.
    async fn resolve_typed_data(
        &self,
        record: PendingTypedData,
        account: &WalletMetadata,
    ) -> Result<Option<PendingTypedData>>;
}

/// One dapp session's wallet-side state and every request it can serve.
pub struct DappSession<'a, S: DappSurface> {
    config: &'a ConfigStore,
    /// Every account this session could expose.
    accounts: Vec<WalletMetadata>,
    /// Which one it settled on. Written once, when the connection is decided,
    /// and read by every request afterwards.
    ///
    /// A `Cell` because the session owns the handler for its whole run and
    /// hands out `&self`; threading a session-lifetime decision back through a
    /// per-request signature would be worse. Nothing here is shared across
    /// threads: these futures are `?Send` and run on one thread.
    selected: std::cell::Cell<usize>,
    data_dir: PathBuf,
    /// Batch ids this session minted, so `wallet_getCallsStatus` answers about
    /// the dapp's own batches and nothing else.
    ///
    /// A batch id is a pending record's UUID, and the wallet hands one out in
    /// an in-flight conflict diagnostic, so a same-wallet id is not a secret.
    /// Ownership by wallet was therefore the whole of the check, and any
    /// record the account owns — a CLI transfer, another dapp's batch, a plain
    /// `eth_sendTransaction` — answered as this dapp's batch, complete with
    /// its receipt and an `atomic: true` that was not true of it.
    ///
    /// Session-scoped rather than durable on purpose: EIP-5792 status is about
    /// a batch this connection submitted, and a connection does not outlive the
    /// session that made it.
    submitted_batches: RefCell<std::collections::BTreeSet<uuid::Uuid>>,
    surface: S,
}

impl<'a, S: DappSurface> DappSession<'a, S> {
    pub fn new(
        config: &'a ConfigStore,
        accounts: Vec<WalletMetadata>,
        selected: usize,
        surface: S,
    ) -> Self {
        Self {
            config,
            accounts,
            selected: std::cell::Cell::new(selected),
            data_dir: config.data_dir().to_path_buf(),
            submitted_batches: RefCell::new(std::collections::BTreeSet::new()),
            surface,
        }
    }

    pub fn surface(&self) -> &S {
        &self.surface
    }

    pub fn accounts(&self) -> &[WalletMetadata] {
        &self.accounts
    }

    pub fn selected(&self) -> usize {
        self.selected.get()
    }

    /// Record which account the connection settled on. Called once, before the
    /// scope is handed back to the protocol, so every request afterwards signs
    /// for the account the decision was about.
    pub fn set_selected(&self, index: usize) {
        self.selected.set(index);
    }

    /// The account this session signs for.
    pub fn wallet(&self) -> &WalletMetadata {
        &self.accounts[self.selected.get().min(self.accounts.len() - 1)]
    }

    /// The scope a session would expose if it settled on `account`.
    #[must_use]
    pub fn scope_for(
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
    pub fn network_for(&self, caip2: &str) -> Option<NetworkConfig> {
        let chain_id = crate::walletconnect::session::numeric_chain_id(caip2)?;
        self.config.network_by_chain_id(&chain_id.to_string()).ok()
    }

    /// Reduce a proposal to the chains and methods a session could expose, or
    /// the refusal to send instead.
    ///
    /// This is the narrowing, and it is the same narrowing whether or not a
    /// person is asked afterwards. Anything the dapp cannot work without has to
    /// be satisfiable before anyone decides, because settling a session that
    /// cannot serve the dapp's required scope produces a connection that fails
    /// on its first request with no explanation. Optional chains are included
    /// only when this wallet already has a configuration for them; an optional
    /// chain is not a reason to ask anybody to configure anything.
    ///
    /// `limit_to` narrows further, to the CAIP-2 chains a caller named. It can
    /// only ever remove: a chain the dapp did not ask for is not added by
    /// naming it here.
    pub fn negotiate(
        &self,
        proposal: &ProposalSummary,
        limit_to: Option<&[String]>,
    ) -> std::result::Result<(Vec<String>, Vec<String>), ProposalDecision> {
        let permitted = |chain: &String| limit_to.is_none_or(|allowed| allowed.contains(chain));

        let mut unconfigured = Vec::new();
        for chain in &proposal.required_chains {
            if self.network_for(chain).is_none() {
                unconfigured.push(chain.clone());
            }
        }
        if !unconfigured.is_empty() {
            return Err(ProposalDecision::Reject {
                code: error_code::UNSUPPORTED_CHAINS,
                message: format!(
                    "This wallet has no configuration for {}. Add the network with \
                     `ekubo-wallet network add` and reconnect.",
                    unconfigured.join(", ")
                ),
            });
        }
        // A caller-supplied narrowing is checked against the *required* chains
        // before anything is settled, for the same reason an unconfigured one
        // is: a session that omits a chain the dapp cannot work without is a
        // session that fails on its first request.
        let excluded: Vec<&String> = proposal
            .required_chains
            .iter()
            .filter(|chain| !permitted(chain))
            .collect();
        if !excluded.is_empty() {
            return Err(ProposalDecision::Reject {
                code: error_code::UNSUPPORTED_CHAINS,
                message: format!(
                    "This connection was limited to chains that do not include {}, which this \
                     dapp cannot work without.",
                    excluded
                        .iter()
                        .map(|chain| chain.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        let unsupported: Vec<&String> = proposal
            .required_methods
            .iter()
            .filter(|method| !SUPPORTED_METHODS.contains(&method.as_str()))
            .collect();
        if !unsupported.is_empty() {
            return Err(ProposalDecision::Reject {
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

        let mut chains = proposal.required_chains.clone();
        for chain in &proposal.optional_chains {
            if self.network_for(chain).is_some() && permitted(chain) && !chains.contains(chain) {
                chains.push(chain.clone());
            }
        }
        if chains.is_empty() {
            return Err(ProposalDecision::Reject {
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
        Ok((chains, methods))
    }

    /// Carry out one in-scope request.
    ///
    /// A failure carrying out one request answers that request and leaves the
    /// session up. Ending the whole session because one call could not be
    /// served would disconnect the dapp mid-flow over, say, one RPC timeout,
    /// and the person would have to re-pair to find out.
    pub async fn answer(&self, request: &DappRequest<'_>) -> RequestOutcome {
        match self.dispatch(request).await {
            Ok(outcome) => outcome,
            Err(error) => RequestOutcome::failed(format!("{error:#}")),
        }
    }

    async fn dispatch(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        // A disconnect already asked for is not undone by a request arriving.
        // The session loop selects between the relay and the quit future, so
        // delivery can win the race and reach here with the answer already
        // given; the loop honours it on its next turn, and until then this is
        // what keeps the interval from being one more signature.
        if self.surface.closing() {
            return Ok(RequestOutcome::Error {
                code: error_code::UNSUPPORTED_METHODS,
                message: "The wallet owner disconnected this session.".into(),
            });
        }
        // Acceptance is live state, not a fact established at startup. A
        // session lasts as long as the dapp keeps it, and `legal accept`
        // records a digest: publishing new terms makes an existing acceptance
        // stale without anything here noticing. A session is the only surface
        // with a window that long, since every CLI command re-checks on entry
        // and the MCP dispatch re-checks per tool call.
        //
        // So it is checked here, where the MCP server checks it: once per
        // request, before the method is even looked at, so a method added
        // later is covered by having been dispatched rather than by having
        // remembered.
        if let Err(error) = legal::require_current_acceptance(self.config.data_dir()) {
            return Ok(RequestOutcome::Error {
                code: error_code::UNSUPPORTED_METHODS,
                message: format!("{error:#}"),
            });
        }
        if let Some(refusal) = self.refuse_replaced_account() {
            return Ok(refusal);
        }
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
        let (message, signer, was_hex) =
            dapp_request::parse_personal_sign(&request.params, self.wallet().address)?;
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
            Some(&requester),
        )?;
        // Every message reaches a person. No policy authorizes a signature: a
        // per-transaction limit cannot bound something its holder redeems
        // whenever it likes.
        match self.surface.resolve_message(record, self.wallet()).await? {
            None => Ok(RequestOutcome::rejected(
                "The wallet owner did not approve this message.",
            )),
            Some(record) => Ok(RequestOutcome::Result(json!(
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
            Some(&requester),
        )?;
        match self
            .surface
            .resolve_typed_data(record, self.wallet())
            .await?
        {
            None => Ok(RequestOutcome::rejected(
                "The wallet owner did not approve this payload.",
            )),
            Some(record) => Ok(RequestOutcome::Result(json!(
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
        self.surface
            .log(&describe_dapp_request(request.dapp, &proposed));
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
        self.surface.log(&terminal_safe_line(&format!(
            "{} proposed a batch of {} calls, to execute atomically",
            DappIdentity::of(request.dapp).headline(),
            batch.calls.len()
        )));
        match self
            .execute_plan(batch.chain_id, &plan, &describe_plan_source(request.dapp))
            .await?
        {
            Ok(record) => {
                self.submitted_batches
                    .borrow_mut()
                    .insert(record.request_id);
                Ok(RequestOutcome::Result(
                    json!({ "id": batch_id(record.request_id) }),
                ))
            }
            Err(refusal) => Ok(refusal),
        }
    }

    /// EIP-5792 `wallet_getCallsStatus`.
    ///
    /// Answers only for batches this session itself submitted. A batch id is a
    /// record id and the wallet prints one in an in-flight conflict
    /// diagnostic, so "a record this account owns" was not a boundary: any
    /// record — a CLI transfer, another dapp's batch — read back as this
    /// dapp's, with its receipt and an `atomic: true` that described a
    /// different thing.
    async fn calls_status(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let id = dapp_request::parse_get_calls_status(&request.params)?;
        let unknown = || RequestOutcome::Error {
            code: error_code::UNKNOWN_BUNDLE_ID,
            message: "This wallet has no batch under that id.".to_owned(),
        };
        let Some(request_id) = parse_batch_id(&id) else {
            return Ok(unknown());
        };
        if !self.submitted_batches.borrow().contains(&request_id) {
            return Ok(unknown());
        }
        let store = PendingStore::production(&self.data_dir)?;
        let Ok(record) = store.get(request_id) else {
            return Ok(unknown());
        };
        drop(store);
        // Kept as well as the check above: the account a session signs for can
        // stop being the account that wallet id names, and a batch this
        // session submitted before that happened is not this session's to
        // report on afterwards.
        if record.wallet_id != self.wallet().id {
            return Ok(unknown());
        }

        // Read the chain before answering. A broadcast record is written as
        // `Broadcast` and stays that way until something reconciles it against
        // the chain — so answering from storage alone reports 100, "not
        // completed", for a batch that mined minutes ago, and goes on doing so
        // for as long as the dapp polls. This is the same reconciliation
        // `wallet_get_execution_status` performs, and the reason that tool
        // exists.
        //
        // `false` for the stale-submission lease: recovering one belongs to
        // the owner's own tooling, not to a dapp asking how its batch went.
        let network = self.config.network(&record.network_name)?;
        let record = {
            let pending = Mutex::new(PendingStore::production(&self.data_dir)?);
            crate::reconcile::reconcile_record(&pending, &network, record, false).await?
        };

        let receipts = match record.broadcast_transaction_hash.as_deref() {
            Some(hash)
                if matches!(
                    record.status,
                    PendingStatus::Confirmed | PendingStatus::Reverted
                ) =>
            {
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

    /// Simulate, policy-check, put to a person if the policy says so, sign, and
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
                match self.surface.resolve_queued(queued).await? {
                    Some(record) => record,
                    None => {
                        return Ok(Err(RequestOutcome::rejected(
                            "The wallet owner did not approve this transaction.",
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

    /// Refuse everything if the account this session settled on is no longer
    /// the account that wallet id names.
    ///
    /// The session holds the `WalletMetadata` chosen when the connection was
    /// decided, and its address is what the dapp was told and what
    /// `refuse_foreign_signer` measures every request against. Storing and
    /// signing, though, go by wallet id: the request row keeps `wallet_id`,
    /// and the signer is whatever key the credential store holds under it
    /// today. A wallet id is reusable — `account remove` then `account create`
    /// under the same name gives it a different key and a different address —
    /// so those two bindings can come apart while the session is up.
    ///
    /// When they do, the session's checks all measure the old address and the
    /// signing measures the new one. A typed-data payload could name the old
    /// address as its RPC signer, pass this session's scope, and carry a
    /// permit whose owner is the *new* address, which is the key that would
    /// then sign it. A session approved for one account would have produced an
    /// asset-authorizing signature from another.
    ///
    /// So the session ends its usefulness where its account ended. Refusing
    /// rather than following the id is the only answer that keeps the address
    /// the dapp was told and the key that signs as the same thing.
    fn refuse_replaced_account(&self) -> Option<RequestOutcome> {
        let settled = self.wallet();
        if self
            .config
            .wallet(&settled.id)
            .is_ok_and(|current| current == *settled)
        {
            return None;
        }
        Some(RequestOutcome::Error {
            code: error_code::UNSUPPORTED_ACCOUNTS,
            message: format!(
                "The account this session connected with ({}) is no longer configured under {}. \
                 Disconnect and reconnect to use the account that is.",
                settled.address.to_checksum(None),
                settled.id
            ),
        })
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
#[must_use]
pub fn describe_plan_source(dapp: &AppMetadata) -> String {
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

/// What this session says about a request, for whatever log is showing it.
///
/// The log is a running account of who asked for what, so it names the dapp
/// and states what was discarded: a dapp that set a nonce or a gas price asked
/// for something specific and did not get it. That detail belongs here rather
/// than in the plan source, which answers who produced the bytes and nothing
/// else.
#[must_use]
pub fn describe_dapp_request(
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
#[must_use]
pub fn batch_id(request_id: uuid::Uuid) -> String {
    format!("0x{}", hex::encode(request_id.as_bytes()))
}

/// The record id inside a batch id, or `None` for anything this wallet did not
/// mint.
#[must_use]
pub fn parse_batch_id(id: &str) -> Option<uuid::Uuid> {
    let bytes = hex::decode(id.strip_prefix("0x").unwrap_or(id)).ok()?;
    uuid::Uuid::from_slice(&bytes).ok()
}

/// EIP-5792's status code for what the chain has done with a batch so far.
///
/// The spec's 600 — partially reverted — is unreachable here and deliberately
/// so: a multi-call plan executes as one `revertOnFailure` batch, so the only
/// outcomes are all of it, none of it, or not yet.
#[must_use]
pub const fn calls_status_code(status: PendingStatus) -> u16 {
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
#[must_use]
pub fn receipt_json(transaction_hash: &str, receipt: &crate::rpc::ReceiptDetails) -> Value {
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

#[cfg(test)]
#[path = "dapp_test.rs"]
mod tests;
