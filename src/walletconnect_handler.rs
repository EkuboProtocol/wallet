//! Live `WalletConnect` session wiring for the desktop authority.

use crate::{
    BUILD_VERSION,
    authority::OwnerApi,
    dapp_identity::DappIdentity,
    events::{DomainEventKind, EventBus},
    walletconnect::{
        ProposalChoice, ProposalCommand, ProposalPresenter, SessionStart, SessionStatus,
        WalletConnectManager,
    },
};
use alloy::primitives::Address;
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use ekubo_wallet_core::{
    approval::{ApprovalKind, ApprovalRequest, ReviewDocument},
    core::execution_plan::{
        DecimalU256, ExecutionPlan, ExecutionStep, ExecutionStepKind, PlannedTransaction,
    },
    custody::OsKeyStore,
    legal,
    message::{MessageEncoding, MessageStatus, MessageStore, parse_siwe},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    sanitize::terminal_safe_line,
    simulation::simulate_external_execution,
    typed_data::{TypedDataStatus, TypedDataStore},
};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
use url::Url;
use walletconnect_session::{
    AppMetadata, ApprovedScope, DappRequest, ProposalDecision, ProposalSummary, RelayConfig,
    RequestOutcome, SUPPORTED_EVENTS, Session, SessionEvent, SessionHandler, protocol::error_code,
    request as dapp_request,
};

const WALLETCONNECT_PROJECT_ID: &str = "1b68f6037b9d5d9558dc5aa3f67c2dc3";
const PUBLIC_REQUEST_FAILURE: &str =
    "The wallet could not complete this request. Review the wallet activity for details.";

fn internal_request_failure() -> RequestOutcome {
    RequestOutcome::failed(PUBLIC_REQUEST_FAILURE)
}

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

pub const MAX_BATCH_CALLS: usize = 24;

fn wallet_metadata() -> AppMetadata {
    AppMetadata {
        name: "Ekubo Wallet".to_owned(),
        description: "Policy-enforced local EVM wallet".to_owned(),
        url: "https://github.com/EkuboProtocol/wallet".to_owned(),
        icons: Vec::new(),
    }
}

/// Cancels a session's farewell token however its task leaves.
///
/// The application shutdown waits on that token to let the goodbye reach the
/// relay, so every exit has to reach it — including the early ones that never
/// opened a connection at all, and a panic. A guard is the only construction
/// that covers all of them; a cancel at the end of `run` would leave the
/// shutdown waiting out its whole budget for a session that failed on its
/// first line.
struct Farewell(tokio_util::sync::CancellationToken);

impl Drop for Farewell {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub async fn run(
    start: SessionStart,
    owner: OwnerApi,
    presenter: ProposalPresenter,
    manager: Arc<Mutex<WalletConnectManager>>,
    events: EventBus,
) -> Result<()> {
    let _farewell = Farewell(start.farewell.clone());
    legal::require_current_acceptance(owner.config_store().data_dir())?;
    let accounts = owner.accounts()?;
    ensure!(
        !accounts.is_empty(),
        "create an account before connecting a dapp"
    );
    let relay = RelayConfig::new(
        Url::parse(walletconnect_session::DEFAULT_RELAY_URL)
            .expect("the WalletConnect relay URL is valid"),
        WALLETCONNECT_PROJECT_ID,
        format!("wc-2/rust-ekubo-wallet-{BUILD_VERSION}/desktop"),
    );
    let handler = DesktopSession {
        id: start.id,
        owner,
        accounts,
        selected: Cell::new(0),
        presenter,
        manager: manager.clone(),
        events: events.clone(),
        shutdown: start.shutdown.clone(),
        submitted_batches: Mutex::new(BTreeSet::new()),
        settled: Cell::new(false),
    };
    let session = Session::connect(&relay, start.pairing, wallet_metadata(), &handler).await?;
    let result = session.run(start.shutdown.cancelled()).await;
    if let Ok(mut manager) = manager.lock() {
        if let Err(error) = &result {
            manager.fail(start.id, terminal_safe_line(&format!("{error:#}")));
        } else {
            manager.finish(start.id);
        }
    }
    events.publish(DomainEventKind::WalletConnectChanged {
        session_id: start.id.to_string(),
    });
    result
}

struct DesktopSession {
    id: uuid::Uuid,
    owner: OwnerApi,
    accounts: Vec<ekubo_wallet_core::config::WalletMetadata>,
    selected: Cell<usize>,
    presenter: ProposalPresenter,
    manager: Arc<Mutex<WalletConnectManager>>,
    events: EventBus,
    shutdown: tokio_util::sync::CancellationToken,
    submitted_batches: Mutex<BTreeSet<uuid::Uuid>>,
    /// Whether the session settled, so a reconnect can put the row back into
    /// the state it left rather than announcing a connection that was never
    /// approved.
    settled: Cell<bool>,
}

impl DesktopSession {
    fn wallet(&self) -> &ekubo_wallet_core::config::WalletMetadata {
        &self.accounts[self.selected.get().min(self.accounts.len() - 1)]
    }

    fn network_for(&self, caip2: &str) -> Option<ekubo_wallet_core::config::NetworkConfig> {
        let chain_id = walletconnect_session::session::numeric_chain_id(caip2)?;
        self.owner.network_by_chain_id(chain_id).ok()
    }

    fn update(
        &self,
        status: SessionStatus,
        dapp_name: Option<String>,
        active_requests: usize,
        expires_at: Option<i64>,
    ) {
        if let Ok(mut manager) = self.manager.lock() {
            manager.update(self.id, status, dapp_name, active_requests, expires_at);
        }
        self.events.publish(DomainEventKind::WalletConnectChanged {
            session_id: self.id.to_string(),
        });
    }

    fn scope_for(
        account: &ekubo_wallet_core::config::WalletMetadata,
        chains: Vec<String>,
        methods: Vec<String>,
        requested_grants: &[walletconnect_session::ScopeGrant],
    ) -> ApprovedScope {
        let grants = requested_grants
            .iter()
            .map(|requested| walletconnect_session::ScopeGrant {
                chains: requested
                    .chains
                    .iter()
                    .filter(|chain| chains.contains(chain))
                    .cloned()
                    .collect(),
                methods: requested
                    .methods
                    .iter()
                    .filter(|method| methods.contains(method))
                    .cloned()
                    .collect(),
            })
            .filter(|grant| !grant.chains.is_empty() && !grant.methods.is_empty())
            .collect();
        ApprovedScope {
            address: account.address.to_checksum(None),
            chains,
            methods,
            grants,
            events: SUPPORTED_EVENTS
                .iter()
                .map(|event| (*event).to_owned())
                .collect(),
        }
    }

    /// The review a dapp connection is decided from.
    ///
    /// `account` is `None` for the state the window opens in, before the owner
    /// has picked one. Everything else in the document — the dapp, the chains,
    /// the methods, the grants — is the same whichever account is chosen, so
    /// the blank form is the real review with one answer missing rather than a
    /// different screen. Only the identity of a document naming an account is
    /// ever authorized against; the blank one is drawn and nothing else.
    fn proposal_document(
        review_id: uuid::Uuid,
        proposal: &ProposalSummary,
        account: Option<&ekubo_wallet_core::config::WalletMetadata>,
        scope: &ApprovedScope,
    ) -> ReviewDocument {
        let dapp = DappIdentity::of(&proposal.metadata);
        let mut request = ApprovalRequest::new(
            ApprovalKind::PolicyException,
            "Approve a dapp connection",
            "Expose one of your accounts to the dapp. Signing requests still pass through wallet policy and owner review.",
        )
        .fact("Site", dapp.host_or_unknown())
        .fact("Claimed name", dapp.name.clone().unwrap_or_else(|| "not stated".into()))
        .fact("Account", account.map_or("not chosen yet", |account| account.id.as_str()))
        .fact(
            "Address",
            account.map_or_else(
                || "not chosen yet".to_owned(),
                |account| account.address.to_checksum(None),
            ),
        )
        .section("Granted chains and methods");
        for chain in &scope.chains {
            request = request.fact("Chain", chain);
        }
        for method in &scope.methods {
            request = request.fact("Method", method);
        }
        for grant in &scope.grants {
            request = request.fact(
                "Chain-method grant",
                format!(
                    "{} → {}",
                    join_or_none(&grant.chains),
                    join_or_none(&grant.methods)
                ),
            );
        }
        request = request
            .section("Proposal details")
            .fact("Required chains", join_or_none(&proposal.required_chains))
            .fact("Optional chains", join_or_none(&proposal.optional_chains))
            .fact("Required methods", join_or_none(&proposal.required_methods))
            .fact("Optional methods", join_or_none(&proposal.optional_methods))
            .fact("Claimed URL", dapp.url.clone().unwrap_or_else(|| "not stated".into()))
            .warning("Dapp identity metadata is self-asserted and unverified. Approve only a connection you initiated from the intended site.");
        for caution in dapp.cautions {
            request = request.warning(caution);
        }
        request.id = review_id;
        ReviewDocument::from_request(request, Vec::new())
    }

    fn refuse_foreign_signer(&self, address: Address) -> Option<RequestOutcome> {
        (address != self.wallet().address).then(|| RequestOutcome::Error {
            code: error_code::UNSUPPORTED_ACCOUNTS,
            message: format!(
                "This session signs for {} only; the request names {}.",
                self.wallet().address.to_checksum(None),
                address.to_checksum(None)
            ),
        })
    }

    fn refuse_replaced_account(&self) -> Option<RequestOutcome> {
        let settled = self.wallet();
        if self
            .owner
            .account(&settled.id)
            .is_ok_and(|current| current == *settled)
        {
            return None;
        }
        Some(RequestOutcome::Error {
            code: error_code::UNSUPPORTED_ACCOUNTS,
            message: "The connected account changed. Disconnect and reconnect.".into(),
        })
    }

    async fn dispatch(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        legal::require_current_acceptance(self.owner.config_store().data_dir())?;
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
            "wallet_switchEthereumChain" => {
                let requested = dapp_request::parse_switch_chain(&request.params)?;
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
                        message: format!("Chain {requested} was not approved for this session."),
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
        if let Some(siwe) = std::str::from_utf8(&message).ok().and_then(parse_siwe)
            && siwe.address != self.wallet().address.to_checksum(None)
        {
            return Ok(RequestOutcome::failed(
                "The sign-in message names another account.",
            ));
        }
        let requester = DappIdentity::of(request.dapp).headline();
        let queued = self.owner.queue_message(
            &self.wallet().id,
            request.chain_id,
            &message,
            if was_hex {
                MessageEncoding::Hex
            } else {
                MessageEncoding::Text
            },
            &requester,
        )?;
        self.wait_for_message(queued.request_id).await
    }

    async fn wait_for_message(&self, request_id: uuid::Uuid) -> Result<RequestOutcome> {
        let mut events = self.owner.event_bus().subscribe();
        loop {
            let record =
                MessageStore::production(self.owner.config_store().data_dir())?.get(request_id)?;
            match record.status {
                MessageStatus::Signed => {
                    return Ok(RequestOutcome::Result(json!(
                        record
                            .signature
                            .context("signed message has no signature")?
                    )));
                }
                MessageStatus::Rejected => {
                    return Ok(RequestOutcome::rejected(
                        "The wallet owner declined this message.",
                    ));
                }
                MessageStatus::AwaitingApproval => {}
            }
            tokio::select! {
                () = self.shutdown.cancelled() => return Ok(RequestOutcome::rejected("The WalletConnect session was disconnected.")),
                _ = events.recv() => {}
            }
        }
    }

    async fn sign_typed_data(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let (signer, payload) = dapp_request::parse_sign_typed_data(&request.params)?;
        if let Some(refusal) = self.refuse_foreign_signer(signer) {
            return Ok(refusal);
        }
        let requester = DappIdentity::of(request.dapp).headline();
        let queued = self.owner.queue_typed_data(
            &self.wallet().id,
            request.chain_id,
            &payload,
            &requester,
        )?;
        let mut events = self.owner.event_bus().subscribe();
        loop {
            let record = TypedDataStore::production(self.owner.config_store().data_dir())?
                .get(queued.request_id)?;
            match record.status {
                TypedDataStatus::Signed => {
                    return Ok(RequestOutcome::Result(json!(
                        record
                            .signature
                            .context("signed typed data has no signature")?
                    )));
                }
                TypedDataStatus::Rejected => {
                    return Ok(RequestOutcome::rejected(
                        "The wallet owner declined this typed data.",
                    ));
                }
                TypedDataStatus::AwaitingApproval => {}
            }
            tokio::select! {
                () = self.shutdown.cancelled() => return Ok(RequestOutcome::rejected("The WalletConnect session was disconnected.")),
                _ = events.recv() => {}
            }
        }
    }

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
            if requested.is_empty() || requested.contains(&chain_id) {
                capabilities.insert(
                    format!("0x{chain_id:x}"),
                    json!({"atomic": {"status": "supported"}}),
                );
            }
        }
        Ok(RequestOutcome::Result(Value::Object(capabilities)))
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
                data: proposed.data,
                value: proposed.value,
            }],
        )?;
        match self
            .execute_plan(request.chain_id, &plan, &describe_plan_source(request.dapp))
            .await?
        {
            Ok(record) => Ok(RequestOutcome::Result(json!(
                record
                    .broadcast_transaction_hash
                    .context("broadcast record has no transaction hash")?
            ))),
            Err(refusal) => Ok(refusal),
        }
    }

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
                    "This wallet does not implement the `{}` capability.",
                    terminal_safe_line(unsupported)
                ),
            });
        }
        // The session boundary already requires these selectors to match.
        // Repeat the equality here as defense in depth: membership in the
        // flattened chain list is insufficient because grants are relational.
        if batch.chain_id != request.chain_id {
            return Ok(RequestOutcome::Error {
                code: error_code::UNSUPPORTED_CHAIN_ID,
                message: format!(
                    "The batch names chain {}, but this request was authorized for chain {}.",
                    batch.chain_id, request.chain_id
                ),
            });
        }
        if batch.calls.len() > MAX_BATCH_CALLS {
            return Ok(RequestOutcome::Error {
                code: error_code::BUNDLE_TOO_LARGE,
                message: format!(
                    "This batch holds {} calls; at most {MAX_BATCH_CALLS} can be reviewed at once.",
                    batch.calls.len()
                ),
            });
        }
        let plan = self.build_plan(batch.chain_id, &batch.calls)?;
        match self
            .execute_plan(batch.chain_id, &plan, &describe_plan_source(request.dapp))
            .await?
        {
            Ok(record) => {
                self.submitted_batches
                    .lock()
                    .map_err(|_| anyhow::anyhow!("batch state lock was poisoned"))?
                    .insert(record.request_id);
                Ok(RequestOutcome::Result(
                    json!({ "id": batch_id(record.request_id) }),
                ))
            }
            Err(refusal) => Ok(refusal),
        }
    }

    async fn calls_status(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        let id = dapp_request::parse_get_calls_status(&request.params)?;
        let unknown = || RequestOutcome::Error {
            code: error_code::UNKNOWN_BUNDLE_ID,
            message: "This wallet has no batch under that id.".into(),
        };
        let Some(request_id) = parse_batch_id(&id) else {
            return Ok(unknown());
        };
        if !self
            .submitted_batches
            .lock()
            .map_err(|_| anyhow::anyhow!("batch state lock was poisoned"))?
            .contains(&request_id)
        {
            return Ok(unknown());
        }
        let Ok(record) =
            PendingStore::production(self.owner.config_store().data_dir())?.get(request_id)
        else {
            return Ok(unknown());
        };
        if record.wallet_id != self.wallet().id {
            return Ok(unknown());
        }
        let network = self.owner.config_store().network(&record.network_name)?;
        let record = {
            let pending = Mutex::new(PendingStore::production(
                self.owner.config_store().data_dir(),
            )?);
            ekubo_wallet_core::reconcile::reconcile_record(&pending, &network, record, false)
                .await?
        };
        let receipts = match record.broadcast_transaction_hash.as_deref() {
            Some(hash)
                if matches!(
                    record.status,
                    PendingStatus::Confirmed | PendingStatus::Reverted
                ) =>
            {
                ekubo_wallet_core::rpc::transaction_receipt_details(&network, hash)
                    .await
                    .ok()
                    .flatten()
                    .map(|receipt| json!([receipt_json(hash, &receipt)]))
            }
            _ => None,
        };
        let mut status = serde_json::Map::from_iter([
            ("version".into(), json!(dapp_request::SEND_CALLS_VERSION)),
            ("id".into(), json!(batch_id(record.request_id))),
            (
                "chainId".into(),
                json!(format!(
                    "0x{:x}",
                    record.chain_id.parse::<u64>().unwrap_or_default()
                )),
            ),
            ("atomic".into(), json!(true)),
            (
                "status".into(),
                json!(if record.settlement_transaction_hash.is_some()
                    && record.finalized_at.is_none()
                {
                    100
                } else {
                    calls_status_code(record.status)
                }),
            ),
        ]);
        if let Some(receipts) = receipts {
            status.insert("receipts".into(), receipts);
        }
        Ok(RequestOutcome::Result(Value::Object(status)))
    }

    fn build_plan(
        &self,
        chain_id: u64,
        calls: &[dapp_request::ProposedCall],
    ) -> Result<ExecutionPlan> {
        let chain = DecimalU256::new(chain_id.to_string())?;
        let mut ordered_steps = Vec::with_capacity(calls.len());
        for (index, call) in calls.iter().enumerate() {
            ordered_steps.push(ExecutionStep {
                step: u32::try_from(index + 1)?,
                kind: ExecutionStepKind::Execution,
                transaction: PlannedTransaction {
                    chain_id: chain.clone(),
                    from: self.wallet().address,
                    to: call.to,
                    data: call.data.clone(),
                    value: DecimalU256::new(call.value.to_string())?,
                    gas: None,
                },
                revert_decode: None,
            });
        }
        let plan = ExecutionPlan {
            schema_version: "1".into(),
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

    async fn execute_plan(
        &self,
        chain_id: u64,
        plan: &ExecutionPlan,
        plan_source: &str,
    ) -> Result<std::result::Result<PendingTransaction, RequestOutcome>> {
        let config = self.owner.config_store();
        let network = config.network_by_chain_id(&chain_id.to_string())?;
        let policies = Mutex::new(PolicyStore::production(config.data_dir())?);
        let stored_policy = policies
            .lock()
            .map_err(|_| anyhow::anyhow!("policy database lock was poisoned"))?
            .get_for_wallet(
                &self.wallet().id,
                self.wallet().instance_id,
                self.wallet().address,
            )?
            .with_context(|| format!("wallet {} has no local policy", self.wallet().id))?;
        let policy_context = ekubo_wallet_core::core::predicate::PolicyContext {
            wallet: self.wallet().address,
        };
        let simulation = simulate_external_execution(
            self.wallet(),
            &network,
            plan,
            &stored_policy,
            &policy_context,
            None,
        )
        .await?;
        if self.shutdown.is_cancelled() {
            return Ok(Err(RequestOutcome::rejected(
                "The WalletConnect session was disconnected.",
            )));
        }
        let pending = Mutex::new(PendingStore::production(config.data_dir())?);
        let disposition = ekubo_wallet_core::orchestrator::execute_automatic(
            config,
            &pending,
            &policies,
            &OsKeyStore,
            self.wallet(),
            &network,
            plan,
            Some(plan_source),
            &simulation,
            // A dapp is not the wallet's agent and gets no say in how closely
            // the owner looks at what it asked for. Only the policy decides
            // here, exactly as it did before the ask existed.
            ekubo_wallet_core::core::policy::ReviewRequest::PolicyDecides,
        )
        .await?;
        drop(pending);
        let signed = match disposition {
            ekubo_wallet_core::orchestrator::SendDisposition::Signed(record) => {
                self.events.publish(DomainEventKind::Transaction {
                    request_id: record.request_id,
                    stage: crate::events::TransactionStage::Signed,
                });
                record
            }
            ekubo_wallet_core::orchestrator::SendDisposition::Queued(queued) => {
                self.events.publish(DomainEventKind::Transaction {
                    request_id: queued.request_id,
                    stage: crate::events::TransactionStage::Proposed,
                });
                self.events.publish(DomainEventKind::ReviewChanged {
                    request_id: queued.request_id,
                });
                match self.wait_for_transaction(queued.request_id).await? {
                    ReviewedRequest::Signed(record) => record,
                    // The review window sends what it approves, so by the time
                    // this session sees the decision the bytes are usually
                    // already on the wire. Nothing is left to do but report the
                    // row the owner's approval produced.
                    ReviewedRequest::AlreadySent(record) => return Ok(Ok(record)),
                    ReviewedRequest::Declined => {
                        return Ok(Err(RequestOutcome::rejected(
                            "The wallet owner declined this transaction.",
                        )));
                    }
                }
            }
        };
        if self.shutdown.is_cancelled() {
            return Ok(Err(RequestOutcome::rejected(
                "The WalletConnect session was disconnected.",
            )));
        }
        let request_id = signed.request_id;
        self.broadcast(&network, signed).await?;
        Ok(Ok(
            PendingStore::production(config.data_dir())?.get(request_id)?
        ))
    }

    /// Wait for the owner's decision on a queued request.
    ///
    /// A decision is not only `signed` or `rejected`: approving in the review
    /// window submits the signed bytes, and the owner can press "Send now" on
    /// the activity row, so this session can arrive to find the transaction
    /// already claimed, broadcast, or even mined. Every one of those is the
    /// approval this session was waiting for, and treating them as an
    /// unexpected state failed the dapp's request over a transaction that had
    /// actually been sent.
    async fn wait_for_transaction(&self, request_id: uuid::Uuid) -> Result<ReviewedRequest> {
        let mut events = self.owner.event_bus().subscribe();
        loop {
            let record =
                PendingStore::production(self.owner.config_store().data_dir())?.get(request_id)?;
            match classify_reviewed_status(record.status) {
                ReviewedStatus::Signed => return Ok(ReviewedRequest::Signed(record)),
                ReviewedStatus::AlreadySent => return Ok(ReviewedRequest::AlreadySent(record)),
                ReviewedStatus::Declined => return Ok(ReviewedRequest::Declined),
                ReviewedStatus::Undecided => {}
            }
            tokio::select! {
                () = self.shutdown.cancelled() => return Ok(ReviewedRequest::Declined),
                _ = events.recv() => {}
                // Every local sender publishes, but the row is the authority
                // and this waits on the row: a tick costs one encrypted read
                // and removes "somebody wrote the database quietly" as a way
                // to strand a dapp request.
                () = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
            }
        }
    }

    async fn broadcast(
        &self,
        network: &ekubo_wallet_core::config::NetworkConfig,
        record: PendingTransaction,
    ) -> Result<()> {
        let request_id = record.request_id;
        let pending = Mutex::new(PendingStore::production(
            self.owner.config_store().data_dir(),
        )?);
        let claim = pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .claim_for_submission(request_id);
        let claimed = match claim {
            Ok(claimed) => claimed,
            // The desktop, the MCP server, and this session share the database
            // but not a lock, and the lease is what decides between them.
            // Losing it to whoever sent these exact bytes first is success.
            Err(error) => {
                let current = pending
                    .lock()
                    .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                    .get(request_id)?;
                if current.broadcast_transaction_hash.is_some() {
                    return Ok(());
                }
                return Err(error);
            }
        };
        let (record, broadcast) =
            ekubo_wallet_core::reconcile::submit_claimed(&pending, self.wallet(), network, claimed)
                .await?;
        if let Some(error) = broadcast.broadcast_error {
            bail!("the transaction was signed but the node refused it: {error}");
        }
        let _ = record
            .signed_transaction_hash
            .context("broadcast transaction has no hash")?;
        self.events.publish(DomainEventKind::Transaction {
            request_id,
            stage: crate::events::TransactionStage::Broadcast,
        });
        Ok(())
    }
}

/// What the owner's review left behind for a session that was waiting on it.
enum ReviewedRequest {
    /// Approved and signed, and nothing has claimed the submission yet.
    Signed(PendingTransaction),
    /// Approved and already handed to the network by whoever got there first.
    AlreadySent(PendingTransaction),
    /// Rejected, or the session went away before a decision arrived.
    Declined,
}

/// The same reading of a lifecycle status, without the row, so the rule this
/// session waits on can be stated once and checked directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReviewedStatus {
    Undecided,
    Signed,
    AlreadySent,
    Declined,
}

/// Every status spelled out rather than caught by a wildcard: a new lifecycle
/// state has to be classified deliberately, because guessing here either hangs
/// a dapp on a decision that already happened or reports a sent transaction as
/// a failure.
///
/// `submitting` is deliberately not an answer. It is the common state to
/// observe — the review window publishes `signed` and then claims the
/// submission, so this session usually wakes inside that window — and it is
/// the one state where the row has no broadcast hash to answer
/// `eth_sendTransaction` with. Waiting through it costs one RPC round trip and
/// ends at `broadcast` with a hash, or back at `signed` if no endpoint took
/// the bytes, which is this session's cue to send them itself.
const fn classify_reviewed_status(status: PendingStatus) -> ReviewedStatus {
    match status {
        PendingStatus::AwaitingApproval | PendingStatus::Submitting => ReviewedStatus::Undecided,
        PendingStatus::Signed => ReviewedStatus::Signed,
        PendingStatus::Rejected => ReviewedStatus::Declined,
        PendingStatus::Broadcast
        | PendingStatus::Confirmed
        | PendingStatus::Reverted
        | PendingStatus::Cancelling
        | PendingStatus::Cancelled
        | PendingStatus::Replaced => ReviewedStatus::AlreadySent,
    }
}

#[async_trait(?Send)]
impl SessionHandler for DesktopSession {
    async fn review_proposal(&self, proposal: &ProposalSummary) -> Result<ProposalDecision> {
        if self.shutdown.is_cancelled() {
            return Ok(ProposalDecision::Reject {
                code: error_code::USER_REJECTED,
                message: "The WalletConnect pairing was disconnected.".into(),
            });
        }
        let unavailable: Vec<String> = proposal
            .required_chains
            .iter()
            .filter(|chain| self.network_for(chain).is_none())
            .cloned()
            .collect();
        if !unavailable.is_empty() {
            return Ok(ProposalDecision::Reject {
                code: error_code::UNSUPPORTED_CHAINS,
                message: format!(
                    "These required chains are not configured: {}",
                    unavailable.join(", ")
                ),
            });
        }
        let unsupported: Vec<&str> = proposal
            .required_methods
            .iter()
            .map(String::as_str)
            .filter(|method| !SUPPORTED_METHODS.contains(method))
            .collect();
        if !unsupported.is_empty() {
            return Ok(ProposalDecision::Reject {
                code: error_code::UNSUPPORTED_METHODS,
                message: format!(
                    "These required methods are unsupported: {}",
                    unsupported.join(", ")
                ),
            });
        }
        let mut chains = proposal.required_chains.clone();
        for chain in &proposal.optional_chains {
            if self.network_for(chain).is_some() && !chains.contains(chain) {
                chains.push(chain.clone());
            }
        }
        if chains.is_empty() {
            return Ok(ProposalDecision::Reject {
                code: error_code::UNSUPPORTED_CHAINS,
                message: "No requested chain is configured.".into(),
            });
        }
        let methods: Vec<String> = SUPPORTED_METHODS
            .iter()
            .filter(|method| {
                proposal
                    .required_methods
                    .iter()
                    .chain(&proposal.optional_methods)
                    .any(|requested| requested == **method)
            })
            .map(|method| (*method).to_owned())
            .collect();
        let choices: Vec<ProposalChoice> = self
            .accounts
            .iter()
            .map(|account| {
                let scope = Self::scope_for(
                    account,
                    chains.clone(),
                    methods.clone(),
                    &proposal.requested_grants,
                );
                ProposalChoice {
                    account: account.clone(),
                    document: Self::proposal_document(self.id, proposal, Some(account), &scope),
                    scope,
                }
            })
            .collect();
        // Any choice's scope will do for the blank form: the chains, methods
        // and grants are identical across accounts, and the one field that is
        // not — the address — is the one the blank form leaves unanswered.
        let unselected_document = choices
            .first()
            .map(|choice| Self::proposal_document(self.id, proposal, None, &choice.scope))
            .context("this wallet has no account to expose")?;
        // Raising the window is not the same as telling the owner. A pairing
        // arrives while they are looking at whatever asked them to scan the
        // code, and every other decision this wallet puts in front of a person
        // announces itself. `headline` is already sanitized dapp-authored
        // text, which is the only form of it allowed into a banner.
        self.events.publish(DomainEventKind::WalletConnectProposed {
            session_id: self.id.to_string(),
            dapp: DappIdentity::of(&proposal.metadata).headline(),
        });
        let command = tokio::select! {
            () = self.shutdown.cancelled() => {
                return Ok(ProposalDecision::Reject {
                    code: error_code::USER_REJECTED,
                    message: "The WalletConnect pairing was disconnected.".into(),
                });
            }
            result = self.presenter.review(self.id, unselected_document, choices) => result?,
        };
        if self.shutdown.is_cancelled() {
            return Ok(ProposalDecision::Reject {
                code: error_code::USER_REJECTED,
                message: "The WalletConnect pairing was disconnected.".into(),
            });
        }
        match command {
            ProposalCommand::Approve {
                index,
                authorization,
            } => {
                ensure!(
                    index < self.accounts.len(),
                    "review selected an unknown account"
                );
                let expected = &self.accounts[index];
                let account = self.owner.account(&expected.id)?;
                ensure!(
                    account == *expected,
                    "the selected account changed after owner authentication"
                );
                let unavailable: Vec<String> = proposal
                    .required_chains
                    .iter()
                    .filter(|chain| self.network_for(chain).is_none())
                    .cloned()
                    .collect();
                ensure!(
                    unavailable.is_empty(),
                    "required network state changed after owner authentication"
                );
                let mut fresh_chains = proposal.required_chains.clone();
                for chain in &proposal.optional_chains {
                    if self.network_for(chain).is_some() && !fresh_chains.contains(chain) {
                        fresh_chains.push(chain.clone());
                    }
                }
                let fresh_scope =
                    Self::scope_for(&account, fresh_chains, methods, &proposal.requested_grants);
                let fresh_document =
                    Self::proposal_document(self.id, proposal, Some(&account), &fresh_scope);
                authorization.verify(&fresh_document.identity, &account.id)?;
                self.selected.set(index);
                Ok(ProposalDecision::Approve(fresh_scope))
            }
            ProposalCommand::Reject | ProposalCommand::Close => Ok(ProposalDecision::Reject {
                code: error_code::USER_REJECTED,
                message: "The wallet owner declined this connection.".into(),
            }),
        }
    }

    async fn handle_request(&self, request: &DappRequest<'_>) -> Result<RequestOutcome> {
        self.update(SessionStatus::Connected, None, 1, None);
        let result = tokio::select! {
            () = self.shutdown.cancelled() => Ok(RequestOutcome::rejected(
                "The WalletConnect session was disconnected.",
            )),
            result = self.dispatch(request) => result,
        };
        self.update(SessionStatus::Connected, None, 0, None);
        Ok(match result {
            Ok(outcome) => outcome,
            Err(_) => internal_request_failure(),
        })
    }

    fn notify(&self, event: &SessionEvent<'_>) {
        match event {
            SessionEvent::Pairing | SessionEvent::ProposalReceived => {
                self.update(SessionStatus::AwaitingProposal, None, 0, None);
            }
            SessionEvent::Settled {
                metadata, expiry, ..
            } => {
                self.settled.set(true);
                self.update(
                    SessionStatus::Connected,
                    Some(DappIdentity::of(metadata).headline()),
                    0,
                    Some(*expiry),
                );
            }
            SessionEvent::RequestReceived { .. } => {
                self.update(SessionStatus::Connected, None, 1, None);
            }
            SessionEvent::RequestAnswered { .. } | SessionEvent::RequestRefused { .. } => {
                self.update(SessionStatus::Connected, None, 0, None);
            }
            SessionEvent::DappDisconnected { .. } => {
                self.update(SessionStatus::Disconnecting, None, 0, None);
            }
            SessionEvent::RelayDisconnected => {
                self.update(SessionStatus::Reconnecting, None, 0, None);
            }
            // Back to whatever the session was doing before the socket went
            // away. A settled session is connected again; one that had not
            // settled is still waiting on the dapp it never met.
            SessionEvent::RelayReconnected => {
                let status = if self.settled.get() {
                    SessionStatus::Connected
                } else {
                    SessionStatus::AwaitingProposal
                };
                self.update(status, None, 0, None);
            }
            SessionEvent::Ping => {}
        }
    }
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.join(", ")
    }
}

fn describe_plan_source(dapp: &AppMetadata) -> String {
    let mut source = format!(
        "{}{}",
        ekubo_wallet_core::pending::DAPP_PLAN_SOURCE_PREFIX,
        DappIdentity::of(dapp).headline()
    );
    while source.len() > ekubo_wallet_core::pending::MAX_PLAN_SOURCE_BYTES {
        source.pop();
    }
    terminal_safe_line(&source)
}

fn batch_id(request_id: uuid::Uuid) -> String {
    format!("0x{}", hex::encode(request_id.as_bytes()))
}

fn parse_batch_id(id: &str) -> Option<uuid::Uuid> {
    let bytes = hex::decode(id.strip_prefix("0x").unwrap_or(id)).ok()?;
    uuid::Uuid::from_slice(&bytes).ok()
}

const fn calls_status_code(status: PendingStatus) -> u16 {
    match status {
        PendingStatus::AwaitingApproval
        | PendingStatus::Signed
        | PendingStatus::Submitting
        | PendingStatus::Broadcast
        | PendingStatus::Cancelling => 100,
        PendingStatus::Confirmed => 200,
        PendingStatus::Reverted => 500,
        PendingStatus::Rejected | PendingStatus::Cancelled | PendingStatus::Replaced => 400,
    }
}

fn receipt_json(transaction_hash: &str, receipt: &ekubo_wallet_core::rpc::ReceiptDetails) -> Value {
    json!({
        "logs": receipt.logs.iter().map(|log| json!({
            "address": format!("{:#x}", log.address),
            "topics": log.topics.iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>(),
            "data": format!("0x{}", hex::encode(&log.data)),
        })).collect::<Vec<_>>(),
        "status": if receipt.succeeded { "0x1" } else { "0x0" },
        "blockHash": format!("{:#x}", receipt.block_hash),
        "blockNumber": format!("0x{:x}", receipt.block_number),
        "gasUsed": format!("0x{:x}", receipt.gas_used),
        "transactionHash": transaction_hash,
    })
}

#[cfg(test)]
#[path = "walletconnect_handler_test.rs"]
mod tests;
