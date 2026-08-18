use crate::events::{DomainEventKind, EventBus, SignatureKind, SignatureStage, TransactionStage};
use crate::{
    abi_decoder::{AbiDecodePlan, AbiDecodeResult, decode_abi_result},
    agent_authority::AgentExecutionAuthority,
    automation::{AutomationDefinition, CronSchedule, PollFailure},
    automation_store::AutomationStore,
    batch_read::{BatchEthCallInput, BatchEthCallOutput, batch_eth_call, resolve_read_input},
    config::{ConfigStore, NativeCurrency, NetworkConfig, WalletMetadata, WalletSource},
    core::{execution_plan::ExecutionPlan, policy::WalletPolicy},
    custody::KeyStore,
    execution::ReceiptStatus,
    fork::{ForkSession, ForkStore, MAX_FORKS, MAX_PLANS_PER_FORK, pin_parent_block},
    input_validation::{parse_chain_id, validate_timeout_seconds},
    legal::{self, LegalDocument, LegalStatus, LegalStore},
    message::{
        MessageDisplay, MessageStatus, MessageStore, PendingMessage, SiweMessage, describe_message,
        parse_message_input, parse_siwe, siwe_warnings,
    },
    pending::{PendingStatus, PendingStore, PendingTransaction},
    plan_fetch::{ArtifactReference, FetchPolicy, resolve_execution_plan_reference},
    policy_store::PolicyStore,
    release_check::{self, ReleaseCheck},
    rpc::{WalletStatus, transaction_known, wallet_status},
    simulation::{SimulationResult, simulate_external_execution},
    simulation_store::{MAX_RECORDED_SIMULATIONS, RecordedSimulation, SimulationStore},
    token_store::{StoredToken, TokenStore},
    typed_data::{
        PendingTypedData, PermitApproval, TypedDataStatus, TypedDataStore,
        interpret_permit_approvals, parse_typed_data,
    },
};
use alloy::primitives::Address;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use ekubo_wallet_core::desktop_store::{AgentKind, DesktopStore};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::wrapper::{Json, Parameters},
    model::{
        Implementation, ListResourcesResult, PaginatedRequestParams, ReadResourceRequestParams,
        ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

/// How many caller-proposed RPC endpoints this process probes at once.
///
/// `wallet_propose_network` is the only tool that sends a request to a URL its
/// caller named, and each probe holds a task for up to the RPC timeout. One at
/// a time costs an honest operator nothing — a person adds a network once, and
/// waits for it — while denying a caller the parallelism that would turn a
/// chain-ID check into a sweep of the host's network.
const MAX_CONCURRENT_NETWORK_PROBES: usize = 1;

static NETWORK_PROBE_SLOTS: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_NETWORK_PROBES));

/// Approval waits this process polls at once.
///
/// A wait is a 250 ms poll of a database row whose payload is re-parsed and,
/// for typed data, whose EIP-712 digest is re-derived on every read — at up to
/// `MAX_TYPED_DATA_BYTES` a time, roughly two hundred times over a full wait.
/// One agent needs at most one wait per queued request, and the queues
/// themselves are capped at 64 per wallet, so sixteen is far more than any
/// real sequence holds open and far below the point where polling costs more
/// than the approval it is waiting for.
const MAX_CONCURRENT_WAITS: usize = 16;

static WAIT_SLOTS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_WAITS));

#[derive(Default)]
pub(crate) struct GlobalAgentQuota {
    forks: HashMap<(uuid::Uuid, uuid::Uuid), DateTime<Utc>>,
    simulations: HashMap<(uuid::Uuid, uuid::Uuid), DateTime<Utc>>,
}

impl GlobalAgentQuota {
    fn prune(&mut self, now: DateTime<Utc>) {
        self.forks.retain(|_, expiry| *expiry > now);
        self.simulations.retain(|_, expiry| *expiry > now);
    }

    fn ensure_fork_capacity(&mut self, now: DateTime<Utc>) -> Result<()> {
        self.prune(now);
        ensure!(
            self.forks.len() < MAX_FORKS,
            "all authenticated clients already hold the global maximum of {MAX_FORKS} simulation forks"
        );
        Ok(())
    }

    fn register_fork(&mut self, client: uuid::Uuid, session: &ForkSession) -> Result<()> {
        self.ensure_fork_capacity(Utc::now())?;
        self.forks
            .insert((client, session.fork_id), session.expires_at);
        Ok(())
    }

    fn register_simulation(&mut self, client: uuid::Uuid, simulation: &RecordedSimulation) -> bool {
        self.prune(Utc::now());
        if self.simulations.len() >= MAX_RECORDED_SIMULATIONS {
            return false;
        }
        self.simulations
            .insert((client, simulation.simulation_id), simulation.expires_at);
        true
    }

    fn release_fork(&mut self, client: uuid::Uuid, fork: uuid::Uuid) {
        self.forks.remove(&(client, fork));
    }

    fn release_simulation(&mut self, client: uuid::Uuid, simulation: uuid::Uuid) {
        self.simulations.remove(&(client, simulation));
    }
}

/// How far past its own deadline a wait may run while one reconciliation
/// finishes.
///
/// A reconciliation is up to four sequential RPC lookups at `RPC_TIMEOUT`
/// each, and the loop only tests its deadline between passes — so an
/// unresponsive endpoint turned a one-second wait into a minute of silence,
/// against a tool that advertises at most 55. Five seconds covers a healthy
/// endpoint's round trips and keeps the caller's own timeout meaningful.
const WAIT_RECONCILE_GRACE: Duration = Duration::from_secs(5);
use url::Url;

#[derive(Clone)]
pub(crate) struct WalletMcpServer {
    config: ConfigStore,
    policies: Arc<Mutex<PolicyStore>>,
    pending: Arc<Mutex<PendingStore>>,
    typed_data: Arc<Mutex<TypedDataStore>>,
    messages: Arc<Mutex<MessageStore>>,
    legal: Arc<Mutex<LegalStore>>,
    tokens: Arc<Mutex<TokenStore>>,
    automations: Arc<Mutex<AutomationStore>>,
    /// Temporary simulation forks. Deliberately in-process only: fork state
    /// is never persisted, never shown at approval time, and never survives a
    /// restart.
    forks: Arc<Mutex<ForkStore>>,
    /// Simulation results a send may consume instead of simulating again.
    /// In-process only for the same reasons, and short-lived besides.
    simulations: Arc<Mutex<SimulationStore>>,
    client_namespace: uuid::Uuid,
    global_quota: Arc<Mutex<GlobalAgentQuota>>,
    events: EventBus,
    /// The only signing capability exposed to this hostile-input adapter.
    /// It has no raw-key or arbitrary-signature operation.
    execution_authority: AgentExecutionAuthority,
    requesting_client: Option<(AgentKind, Arc<Mutex<DesktopStore>>)>,
}

impl WalletMcpServer {
    fn enabled_chain_ids(&self) -> Result<Vec<u64>> {
        let mut chains = self
            .config
            .load()?
            .networks
            .into_iter()
            .filter(|network| !network.disabled)
            .map(|network| network.chain_id)
            .collect::<Vec<_>>();
        chains.sort_unstable();
        Ok(chains)
    }

    pub(crate) fn production(
        config: ConfigStore,
        client_id: uuid::Uuid,
        harness: AgentKind,
        desktop: Arc<Mutex<DesktopStore>>,
        global_quota: Arc<Mutex<GlobalAgentQuota>>,
        events: EventBus,
    ) -> Result<Self> {
        // Loading first initializes the encrypted wallet configuration in the
        // same database that the stores below open. No plaintext configuration
        // file participates in startup or request handling.
        config.load()?;
        let policies = PolicyStore::production(config.data_dir())?;
        let pending = PendingStore::production(config.data_dir())?;
        let typed_data = TypedDataStore::production(config.data_dir())?;
        let messages = MessageStore::production(config.data_dir())?;
        let legal = LegalStore::production(config.data_dir())?;
        let tokens = TokenStore::production(config.data_dir())?;
        let automations = AutomationStore::production(config.data_dir())?;
        let mut server = Self::new(
            config,
            policies,
            pending,
            typed_data,
            messages,
            legal,
            tokens,
            automations,
            Arc::new(ekubo_wallet_core::custody::OsKeyStore),
        )?;
        server.requesting_client = Some((harness, desktop));
        server.client_namespace = client_id;
        server.global_quota = global_quota;
        server.events = events;
        Ok(server)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        config: ConfigStore,
        policies: PolicyStore,
        pending: PendingStore,
        typed_data: TypedDataStore,
        messages: MessageStore,
        legal: LegalStore,
        tokens: TokenStore,
        automations: AutomationStore,
        keys: Arc<dyn KeyStore>,
    ) -> Result<Self> {
        for wallet in config.load()?.wallets {
            ensure!(
                policies
                    .get_for_wallet(&wallet.id, wallet.instance_id, wallet.address)?
                    .is_some(),
                "wallet {} has no policy in the encrypted database",
                wallet.id
            );
        }
        let policies = Arc::new(Mutex::new(policies));
        let execution_authority = AgentExecutionAuthority::over(keys, Arc::clone(&policies));
        Ok(Self {
            config,
            policies,
            pending: Arc::new(Mutex::new(pending)),
            typed_data: Arc::new(Mutex::new(typed_data)),
            messages: Arc::new(Mutex::new(messages)),
            legal: Arc::new(Mutex::new(legal)),
            tokens: Arc::new(Mutex::new(tokens)),
            automations: Arc::new(Mutex::new(automations)),
            forks: Arc::new(Mutex::new(ForkStore::new())),
            simulations: Arc::new(Mutex::new(SimulationStore::new())),
            client_namespace: uuid::Uuid::nil(),
            global_quota: Arc::new(Mutex::new(GlobalAgentQuota::default())),
            events: EventBus::default(),
            execution_authority,
            requesting_client: None,
        })
    }

    fn with_attribution(
        &self,
        apply: impl FnOnce(&mut DesktopStore, AgentKind) -> Result<()>,
    ) -> Result<()> {
        let Some((harness, desktop)) = &self.requesting_client else {
            return Ok(());
        };
        let mut desktop = desktop
            .lock()
            .map_err(|_| anyhow::anyhow!("desktop database lock was poisoned"))?;
        apply(&mut desktop, *harness)
    }

    fn ensure_global_fork_capacity(&self) -> std::result::Result<(), ErrorData> {
        self.global_quota
            .lock()
            .map_err(|_| ErrorData::internal_error("global quota lock was poisoned", None))?
            .ensure_fork_capacity(Utc::now())
            .map_err(|error| tool_error(&error))
    }

    fn register_global_fork(&self, session: &ForkSession) -> std::result::Result<(), ErrorData> {
        self.global_quota
            .lock()
            .map_err(|_| ErrorData::internal_error("global quota lock was poisoned", None))?
            .register_fork(self.client_namespace, session)
            .map_err(|error| tool_error(&error))
    }

    fn release_global_fork(&self, fork_id: uuid::Uuid) {
        if let Ok(mut quota) = self.global_quota.lock() {
            quota.release_fork(self.client_namespace, fork_id);
        }
    }

    fn register_global_simulation(&self, simulation: &RecordedSimulation) -> bool {
        self.global_quota
            .lock()
            .is_ok_and(|mut quota| quota.register_simulation(self.client_namespace, simulation))
    }

    fn release_global_simulation(&self, simulation_id: uuid::Uuid) {
        if let Ok(mut quota) = self.global_quota.lock() {
            quota.release_simulation(self.client_namespace, simulation_id);
        }
    }

    fn publish_execution_status(&self, output: &ExecutionStatusOutput) {
        let stage = match output.status {
            ExecutionStatus::ApprovalRequired => Some(TransactionStage::Proposed),
            ExecutionStatus::Approved => Some(TransactionStage::Signed),
            ExecutionStatus::SubmissionPending | ExecutionStatus::CancellationPending => {
                Some(TransactionStage::Broadcast)
            }
            ExecutionStatus::Submitted => Some(TransactionStage::Confirmed),
            ExecutionStatus::Reverted => Some(TransactionStage::Reverted),
            ExecutionStatus::Cancelled => Some(TransactionStage::Cancelled),
            ExecutionStatus::Replaced => Some(TransactionStage::Replaced),
            ExecutionStatus::TimedOut | ExecutionStatus::Rejected => None,
        };
        if let Some(stage) = stage {
            self.events.publish(DomainEventKind::Transaction {
                request_id: output.request_id,
                stage,
            });
        }
    }

    /// Announce a signature request an agent has just queued.
    ///
    /// Everything the owner sees — the inbox, the tray count, the banner — is
    /// driven off this bus. The two signing tools used to write straight to
    /// their stores and return, so the request reached the database and
    /// nothing else: no notification, and an inbox that only caught up the
    /// next time some unrelated event happened to redraw it. A request nobody
    /// is told about is a request that waits forever, since these two are the
    /// one thing in the wallet that no policy can ever approve on its own.
    fn publish_queued_signature(&self, request_id: uuid::Uuid, kind: SignatureKind) {
        self.events.publish(DomainEventKind::Signature {
            request_id,
            kind,
            stage: SignatureStage::Queued,
        });
        self.events
            .publish(DomainEventKind::ReviewChanged { request_id });
    }
}

#[derive(Debug, Serialize, JsonSchema)]
struct PublicWallet {
    id: String,
    address: String,
    source: WalletSource,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct PublicNetwork {
    name: String,
    chain_id: String,
    testnet: bool,
    /// Every endpoint configured for this network, in the order the wallet
    /// tries them. Each label contains only scheme, host, and port; paths and
    /// query strings may carry provider credentials and never reach an agent.
    rpc_urls: Vec<String>,
    /// Whether endpoints are tried in configured or fresh random order.
    rpc_strategy: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct WalletInventory {
    wallets: Vec<PublicWallet>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct NetworkInventory {
    networks: Vec<PublicNetwork>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WalletInput {
    wallet_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct PolicyOutput {
    wallet_id: String,
    revision: u64,
    updated_at: DateTime<Utc>,
    policy: WalletPolicy,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Public MCP field names intentionally match the protocol.
struct WalletNetworkInput {
    wallet_id: String,
    chain_id: String,
    /// Report this temporary simulation fork's hypothetical state instead of
    /// real chain state.
    #[serde(default)]
    fork_id: Option<uuid::Uuid>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SimulateInput {
    wallet_id: String,
    chain_id: String,
    /// The producer's `artifact_reference` envelope, passed as a JSON object
    /// through VERBATIM, never as a JSON-encoded string: never rename, edit,
    /// restate, or reconstruct any of its fields. The
    /// wallet fetches the plan body itself and verifies the envelope's
    /// integrity digest and byte count over what it actually fetched, so what
    /// the agent saw prepared is what gets simulated. An inline plan travels
    /// as an envelope whose url is a `data:application/json[;base64],…` URI
    /// of its exact bytes (integrity optional there). Public HTTPS artifacts
    /// must include their integrity digest and exact byte count. Local
    /// filesystem references are not accepted.
    #[schemars(schema_with = "ekubo_wallet_core::plan_fetch::artifact_reference_object_schema")]
    reference: ArtifactReference,
    /// Simulate on top of everything already applied to this temporary fork
    /// and, if execution succeeds, append this plan to it. Omit to simulate
    /// against real chain state.
    #[serde(default)]
    fork_id: Option<uuid::Uuid>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SendExecutionPlanInput {
    wallet_id: String,
    chain_id: String,
    /// The producer's `artifact_reference` envelope for the plan to simulate
    /// and send, passed as a JSON object through VERBATIM, never as a
    /// JSON-encoded string. Provide exactly one of `reference`,
    /// `simulation_id`, or `request_id`.
    #[serde(default)]
    #[schemars(schema_with = "ekubo_wallet_core::plan_fetch::artifact_reference_object_schema")]
    reference: Option<ArtifactReference>,
    /// The `simulation_id` of a plan previously simulated against real chain
    /// state by `wallet_simulate_execution_plan`. This is a one-use,
    /// short-lived plan handle only. Send repeats simulation, exact envelope
    /// preparation, and current-policy evaluation; the preview grants no
    /// signing authority.
    #[serde(default)]
    simulation_id: Option<uuid::Uuid>,
    /// The `request_id` of a request the user already approved and signed,
    /// whose exact signed bytes are submitted as they stand. A request whose
    /// broadcast the chain never saw is re-broadcast; one already known to
    /// the chain is left alone and reported. Nothing is re-signed, so this
    /// can never become a different transaction.
    #[serde(default)]
    request_id: Option<uuid::Uuid>,
    /// What to do when the plan's simulation fails. It says nothing about
    /// policy: a plan no rule covers always queues for human approval, and a
    /// plan a `deny` rule matched always fails outright.
    #[serde(default)]
    on_simulation_failure: OnSimulationFailure,
}

/// What a caller wants done when simulation says the plan will not execute.
///
/// Distinct from `SimulationFailureAction`, which is the action a failure
/// recommends; this is the one the caller chose in advance.
///
/// A failed simulation and a plan no policy rule covers are different problems
/// with the same old answer: queue for a human. But only the uncovered plan is
/// a question a human can answer — a plan that reverts needs new calldata from
/// whoever produced it, and sending the user to a review prompt for it costs
/// them an interruption to approve something that will fail anyway. Callers
/// that can act on the failure themselves say so here.
///
/// A plan a `deny` rule matched is neither: it never queues whatever this
/// says, because no approval prompt can override the owner's own rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OnSimulationFailure {
    /// Create a pending request so the user can override the failure. The
    /// long-standing behavior, and still the default.
    #[default]
    RequestApproval,
    /// Return the failure to the caller. Nothing is queued, nothing is
    /// signed, and the user is not interrupted.
    Fail,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DecodeAbiInput {
    /// The bytes to decode, `0x`-prefixed and a whole number of bytes, up to
    /// 1048576 of them. Bytes already in hand: this tool reads nothing.
    return_data: String,
    /// How to read those bytes. A plan that does not fit them fails the
    /// decode and reports why rather than guessing.
    decode: AbiDecodePlan,
    /// Echo `return_data` back beside the decoded value. Default true.
    #[serde(default = "default_true")]
    include_raw: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AddNetworkInput {
    /// The identifier the owner types: 1-64 letters, numbers, underscores, or
    /// hyphens.
    name: String,
    /// How the network is written out for a human, 1-128 characters.
    display_name: String,
    /// Up to 8 further identifiers for the same network, each in the same
    /// character set as `name`. Omit for none.
    #[serde(default)]
    aliases: Vec<String>,
    /// Canonical decimal chain ID, positive and without leading zeros.
    chain_id: String,
    /// Whether this is a test network. Testnet data stays out of owner-facing
    /// surfaces until the owner enables testnet mode.
    testnet: bool,
    /// One to eight distinct http/https RPC endpoints, tried in the order
    /// given. Several is better than one: the wallet moves to the next when
    /// an endpoint fails, and a network with a single endpoint stops working
    /// when that endpoint does.
    #[schemars(with = "Vec<String>")]
    rpc_urls: Vec<Url>,
    /// How endpoints are ordered: `ordered` takes the first answer and
    /// `random` varies which endpoint is asked first. Omit for `ordered`.
    /// Proposing this still queues for the owner, who sees the strategy on the
    /// review screen before anything is written.
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    rpc_strategy: Option<String>,
    /// Confirmations required before a receipt releases the wallet's signing
    /// slot. Omit for the default of 3, and raise it for a chain that reorgs
    /// deeper than that.
    #[serde(default = "default_network_finality_confirmations")]
    finality_confirmations: u16,
    native_currency: NativeCurrency,
    #[schemars(with = "String")]
    block_explorer_url: Url,
    #[schemars(with = "String")]
    documentation_url: Url,
}

/// What a queued network suggestion tells the agent.
///
/// Deliberately thin. Echoing the profile back would read as confirmation that
/// it is in effect, and it is not: nothing about this network resolves until
/// the owner accepts it. `replaces` names the network this would edit, so an
/// agent can tell the owner whether it is proposing a new chain or changing
/// the endpoint of one they already use — which is the part worth saying out
/// loud before a person decides.
#[derive(Debug, Serialize, JsonSchema)]
struct ProposedNetworkOutput {
    chain_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    replaces: Option<String>,
    pending_review: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Public MCP field names intentionally match the protocol.
struct RequestInput {
    wallet_id: String,
    chain_id: String,
    request_id: uuid::Uuid,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WaitInput {
    wallet_id: String,
    chain_id: String,
    request_id: uuid::Uuid,
    /// How long this call blocks before returning what it last saw, in
    /// seconds: 1 to 55, default 55. A wait that times out has decided
    /// nothing; call it again with the same `request_id` to keep waiting.
    #[serde(default = "default_wait_seconds")]
    #[schemars(range(min = 1, max = 55))]
    timeout_seconds: u8,
    /// How many confirmations the mined receipt must have before the wait
    /// resolves: 1 means included in any block. Default 1, maximum 1000.
    #[serde(default = "default_confirmations")]
    #[schemars(range(min = 1, max = 1000))]
    confirmations: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ApprovalWaitInput {
    request_id: uuid::Uuid,
    /// How long this call blocks before returning what it last saw, in
    /// seconds: 1 to 55, default 55. A wait that times out has decided
    /// nothing; call it again with the same `request_id` to keep waiting.
    #[serde(default = "default_wait_seconds")]
    #[schemars(range(min = 1, max = 55))]
    timeout_seconds: u8,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListTokensInput {
    /// Decimal chain ID filter; omitted lists every chain.
    #[serde(default)]
    chain_id: Option<crate::token_store::ChainIdInput>,
    /// Rows to return, default 200. Values above 1000 are silently capped at
    /// 1000; page through the rest with `offset`.
    #[serde(default = "default_token_limit")]
    limit: usize,
    /// Rows to skip before the page begins, default 0.
    #[serde(default)]
    offset: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
struct TokenListOutput {
    /// Total stored tokens matching the filter, ignoring paging.
    total: u64,
    tokens: Vec<StoredToken>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SearchTokensInput {
    /// A symbol, part of a name, or a full token address.
    query: String,
    #[serde(default)]
    chain_id: Option<crate::token_store::ChainIdInput>,
    /// Matches to return, default 50. Values above 1000 are silently capped
    /// at 1000.
    #[serde(default = "default_search_limit")]
    limit: usize,
}

const fn default_search_limit() -> usize {
    50
}

#[derive(Debug, Serialize, JsonSchema)]
struct TokenSearchOutput {
    matches: u64,
    tokens: Vec<StoredToken>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ProposeTokenItem {
    /// Accepts a canonical decimal string or the bare number used by
    /// standard token-list files.
    #[serde(alias = "chainId")]
    chain_id: crate::token_store::ChainIdInput,
    address: String,
    /// The list's symbol for this address. If the owner accepts it, this is
    /// the name they will read whenever a transaction moves the token, so it
    /// must be the list's symbol and not the contract's.
    symbol: String,
    #[serde(default)]
    name: Option<String>,
    /// The list's decimals. This scales every amount the owner is ever shown
    /// for the token, and the contract is never consulted about it, so take it
    /// from the same list as the symbol rather than reading `decimals()`.
    decimals: u8,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ProposeTokensInput {
    /// Where these entries came from — the token list's own name, for
    /// instance. The owner reviews suggestions grouped under it and usually
    /// decides a whole list at once, so name the real source rather than
    /// something generic. Required with inline `tokens`; with a `reference`
    /// it overrides whatever name the referenced list declares.
    #[serde(default)]
    list_name: Option<String>,
    /// Entries written out one by one, at most 10000 of them. Provide exactly
    /// one of `tokens` and `reference`; prefer `reference` for anything
    /// beyond a handful, since restating a list here costs an output token
    /// per field.
    #[serde(default)]
    tokens: Vec<ProposeTokenItem>,
    /// A producer's `artifact_reference` envelope of `artifact_type`
    /// `token_list`, passed as a JSON object through VERBATIM, never as a
    /// JSON-encoded string: never rename, edit, restate, or reconstruct any of
    /// its fields. The wallet fetches the list itself and
    /// verifies the envelope's integrity digest and byte count over what it
    /// actually fetched. This changes only who carries the bytes — the
    /// entries still reach the owner as suggestions and are still named
    /// nothing until they accept them in the desktop Tokens review screen. The
    /// same 10000-entry cap applies: a longer list is refused rather than
    /// truncated.
    #[serde(default)]
    #[schemars(schema_with = "ekubo_wallet_core::plan_fetch::artifact_reference_object_schema")]
    reference: Option<ArtifactReference>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ProposeTokensOutput {
    #[serde(flatten)]
    summary: crate::token_store::ProposalSummary,
    /// Every suggestion now waiting for the owner, this call's included.
    awaiting_review: u64,
    /// Entries a referenced list carried that this wallet cannot act on,
    /// because their address is not 20 bytes — the Starknet rows in a
    /// multi-ecosystem list, typically. Dropped rather than proposed, and
    /// reported so a shorter proposal than expected explains itself.
    skipped_non_evm: usize,
    next_step: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImportTokenListInput {
    /// The `https` URL the list is published at, such as
    /// `https://tokens.uniswap.org`. Must be the token-list JSON itself, not
    /// the tokenlists.org page describing it. No credentials, no fragment, no
    /// port, and redirects are not followed, so give the URL the curator
    /// publishes rather than a shortener or a mirror.
    url: String,
    /// Which chains to take entries for, as decimal chain IDs. Omit this to
    /// take the chains this wallet has networks configured for, which is
    /// usually what you want: a published list spans chains the owner does
    /// not use, and names for those are suggestions they would have to read
    /// past. Pass an explicit set to narrow it further. Entries on every
    /// other chain are skipped and counted, never imported silently.
    #[serde(default)]
    chain_ids: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ImportTokenListOutput {
    #[serde(flatten)]
    summary: crate::token_store::ProposalSummary,
    /// What the owner will see these suggestions grouped under. Built from
    /// the host that served the list and the name the list gives itself, in
    /// that order; it is not something the caller can set.
    list_name: String,
    /// The host that actually served the bytes, as TLS proved it.
    host: String,
    /// The list's own `version`, when it declares one. Compare it across
    /// imports to tell a list that changed from one that did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    declared_version: Option<String>,
    /// The list's own `timestamp`, verbatim, when it declares one.
    #[serde(skip_serializing_if = "Option::is_none")]
    declared_timestamp: Option<String>,
    /// Every suggestion now waiting for the owner, this call's included.
    awaiting_review: u64,
    /// The chains entries were taken for, decimal, in the order applied.
    /// Echoed because omitting `chain_ids` lets the wallet choose them.
    chains_selected: Vec<String>,
    /// Entries the list carried that this wallet cannot act on, because their
    /// address is not 20 bytes — the Starknet rows in a multi-ecosystem list,
    /// typically. Dropped rather than proposed, and reported so a shorter
    /// import than expected explains itself.
    skipped_non_evm: usize,
    /// Entries dropped for naming a chain outside `chains_selected`. Large on
    /// a multi-chain list, and reported so taking 396 rows from a 1685-row
    /// list reads as a selection rather than a half-empty list.
    skipped_other_chain: usize,
    next_step: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PortfolioInput {
    chain_id: String,
    /// A configured wallet. Provide exactly one of `wallet_id` or `address`.
    #[serde(default)]
    wallet_id: Option<String>,
    /// Any EVM address. Provide exactly one of `wallet_id` or `address`.
    #[serde(default)]
    address: Option<String>,
    /// Read this temporary simulation fork's hypothetical balances instead of
    /// real chain state.
    #[serde(default)]
    fork_id: Option<uuid::Uuid>,
}

const fn default_token_limit() -> usize {
    200
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct GetBalancesInput {
    chain_id: String,
    /// A configured wallet. Provide exactly one of `wallet_id` or `address`.
    #[serde(default)]
    wallet_id: Option<String>,
    /// Any EVM address. Provide exactly one of `wallet_id` or `address`.
    #[serde(default)]
    address: Option<String>,
    /// 1-1000 token contract addresses. Include
    /// 0x0000000000000000000000000000000000000000 to read the native balance.
    /// Provide exactly one of `tokens` and `reference`.
    #[serde(default)]
    tokens: Vec<String>,
    /// A producer's `artifact_reference` envelope of `artifact_type`
    /// `token_list`, passed as a JSON object through VERBATIM, never as a
    /// JSON-encoded string, whose entries supply the addresses to read. Use
    /// this instead of restating a long list of addresses. Only the addresses
    /// are used: this reads balances and never
    /// consults or records what the list calls anything. Entries on other
    /// chains are ignored, so one canonical multi-chain list can be pointed
    /// at any chain. Two different caps apply: the referenced list itself is
    /// refused outright above 10000 entries across every chain it names, and
    /// what survives the chain filter must still be at most 1000 addresses,
    /// which is what one balance request will carry.
    #[serde(default)]
    #[schemars(schema_with = "ekubo_wallet_core::plan_fetch::artifact_reference_object_schema")]
    reference: Option<ArtifactReference>,
    /// Read this temporary simulation fork's hypothetical balances instead of
    /// real chain state.
    #[serde(default)]
    fork_id: Option<uuid::Uuid>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct LegalInput {
    /// Include the complete text of this document in the response.
    #[serde(default)]
    document: Option<LegalDocument>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct LegalDocumentOutput {
    document: LegalDocument,
    title: String,
    digest: String,
    text: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct LegalOutput {
    status: LegalStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    document: Option<LegalDocumentOutput>,
    instruction: String,
}

fn deserialize_policy_object<'de, D>(deserializer: D) -> Result<serde_json::Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "policy must be a JSON object, not JSON encoded as a string",
        ))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct InstallAutomationInput {
    wallet_id: String,
    chain_id: String,
    /// Your own identifier for this automation, unique per wallet. Installing
    /// again with the same key replaces that automation instead of adding a
    /// second one, which is what makes retrying this call safe. Reuse the key
    /// to update bytecode, config, or schedule; choose a new one for a
    /// genuinely different job.
    automation_key: String,
    /// Short label the user sees in the Automations tab.
    name: String,
    /// Deployed runtime bytecode as hex — solc's `deployedBytecode`, not
    /// `bytecode`. Test it with `wallet_dry_run_automation` first.
    bytecode: String,
    /// The `config` bytes `automate(bytes config)` receives, as hex. Omitted
    /// means empty.
    #[serde(default)]
    config: Option<String>,
    /// Six-field cron expression, seconds first, in UTC. `*/12 * * * * *` is
    /// roughly per block on a twelve-second chain.
    cron: String,
    /// The policy revision this automation was written for, from
    /// `wallet_get_policy`. Must be the active revision: an automation is bound
    /// to it, and a later policy change moves the automation to
    /// `awaiting_relink` rather than letting it run under authority the user
    /// granted for something else.
    policy_revision: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
struct InstallAutomationOutput {
    automation_id: uuid::Uuid,
    automation_key: String,
    wallet_id: String,
    chain_id: String,
    name: String,
    bytecode_hash: String,
    cron: String,
    policy_revision: u64,
    state: ekubo_wallet_core::automation::AutomationState,
    /// True when this call replaced an automation that already held the key,
    /// which is also what a safe retry of the same call reports.
    replaced_existing: bool,
    /// The next few times it will fire, in UTC.
    upcoming: Vec<DateTime<Utc>>,
    instruction: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListAutomationsInput {
    wallet_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ListAutomationsOutput {
    automations: Vec<AutomationSummary>,
    instruction: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct AutomationSummary {
    automation_id: uuid::Uuid,
    automation_key: String,
    name: String,
    chain_id: u64,
    cron: String,
    bytecode_hash: String,
    policy_revision: u64,
    state: ekubo_wallet_core::automation::AutomationState,
    /// Why it stopped, when it is not enabled. This is the whole account of
    /// what went wrong; read it before reinstalling anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    stopped_reason: Option<String>,
    consecutive_failures: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_tick_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_request_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_fire_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DisableAutomationInput {
    wallet_id: String,
    automation_key: String,
    /// Why, recorded and shown to the user in the Automations tab.
    reason: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DryRunAutomationInput {
    wallet_id: String,
    chain_id: String,
    /// The automation's deployed runtime bytecode as hex — solc's
    /// `deployedBytecode`, not `bytecode`. The wallet never runs a
    /// constructor, so a creation-code artifact will not behave.
    bytecode: String,
    /// The opaque `config` bytes `automate(bytes config)` receives, as hex.
    /// Omitted means empty.
    #[serde(default)]
    config: Option<String>,
    /// A six-field cron expression, seconds first, validated and previewed but
    /// not installed. Supplying it here is how to learn that `*/12 * * * *`
    /// has five fields before proposing it.
    #[serde(default)]
    cron: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct DryRunAutomationOutput {
    wallet_id: String,
    chain_id: String,
    /// keccak256 of the bytecode, which is what the owner's review displays.
    bytecode_hash: String,
    bytecode_bytes: usize,
    /// The block the poll observed, when it got that far.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_number: Option<u64>,
    /// Gas the poll itself used. Not the batch's gas: that is in `simulation`.
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_gas_used: Option<u64>,
    /// The calls the blob asked for. Empty means it had nothing to do, which
    /// is a healthy tick rather than a failure.
    calls: Vec<DryRunCall>,
    /// The full simulation of the batch those calls become, including the
    /// policy findings that decide whether it could send automatically.
    /// Absent when the blob returned no calls or the poll failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    simulation: Option<SimulationResult>,
    /// Present exactly when the poll failed, and verbose on purpose: an agent
    /// iterating on bytecode needs the bytes, not a category.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<DryRunFailure>,
    /// The next few moments the supplied schedule would fire, in UTC.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    upcoming: Vec<DateTime<Utc>>,
    instruction: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct DryRunCall {
    to: String,
    value: String,
    data: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct DryRunFailure {
    kind: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revert_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revert_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_data: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ProposePolicyInput {
    wallet_id: String,
    /// The policy revision this proposal was written against, from
    /// `wallet_get_policy`. Must be the active revision.
    source_revision: u64,
    /// The complete proposed replacement policy document as a JSON object,
    /// never as a JSON-encoded string. Read `wallet://docs/policy-authoring`
    /// and `wallet://schemas/policy` first. Selector ABI parameters must be
    /// named; tuple arguments use exact-arity positional `tuple` arrays where
    /// `null` leaves one position unconstrained.
    #[serde(deserialize_with = "deserialize_policy_object")]
    #[schemars(schema_with = "ekubo_wallet_core::core::policy::policy_object_schema")]
    policy: serde_json::Value,
    /// Why this change is needed, shown verbatim to the human reviewer.
    /// Explain what the user asked for and which permissions enable it.
    rationale: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ProposePolicyOutput {
    wallet_id: String,
    source_revision: u64,
    created_at: DateTime<Utc>,
    /// The minimized permission diff the reviewer will see, one change per
    /// line, prefixed +/-/~.
    diff: Vec<String>,
    rationale: String,
    /// True when this proposal replaced a previous pending proposal.
    replaced_previous_proposal: bool,
    instruction: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SignTypedDataInput {
    wallet_id: String,
    /// Complete EIP-712 payload: `types`, `primaryType`, `domain`, `message`.
    /// The domain must include a `chainId` matching a configured network.
    #[schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")]
    typed_data: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct TypedDataWaitInput {
    request_id: uuid::Uuid,
    /// How long this call blocks before returning what it last saw, in
    /// seconds: 1 to 55, default 55. A wait that times out has decided
    /// nothing; call it again with the same `request_id` to keep waiting.
    #[serde(default = "default_wait_seconds")]
    #[schemars(range(min = 1, max = 55))]
    timeout_seconds: u8,
}

#[derive(Debug, Serialize, JsonSchema)]
struct TypedDataOutput {
    request_id: uuid::Uuid,
    wallet_id: String,
    chain_id: String,
    /// The EIP-712 signing hash of the exact payload.
    digest: String,
    status: TypedDataStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_at: Option<DateTime<Utc>>,
    /// The 65-byte r||s||v signature, present only once signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    /// Token approvals this payload grants, when it is a recognized permit.
    /// Review information: it never shortens the approval path.
    #[serde(skip_serializing_if = "Option::is_none")]
    permit_approvals: Option<Vec<PermitApproval>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SignMessageInput {
    wallet_id: String,
    /// The exact message to sign, as text. Pass exactly one of `message_text`
    /// and `message_hex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message_text: Option<String>,
    /// The exact message to sign, as `0x`-prefixed bytes, for messages that
    /// are not valid UTF-8. A bare 32-byte value is refused: that is the
    /// legacy `eth_sign` shape and no approval screen can describe it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message_hex: Option<String>,
    /// Optional context the requester is declaring. EIP-191 signatures bind no
    /// chain, so this is shown to the user as a claim, never as a guarantee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct MessageWaitInput {
    request_id: uuid::Uuid,
    /// How long this call blocks before returning what it last saw, in
    /// seconds: 1 to 55, default 55. A wait that times out has decided
    /// nothing; call it again with the same `request_id` to keep waiting.
    #[serde(default = "default_wait_seconds")]
    #[schemars(range(min = 1, max = 55))]
    timeout_seconds: u8,
}

#[derive(Debug, Serialize, JsonSchema)]
struct MessageOutput {
    request_id: uuid::Uuid,
    wallet_id: String,
    /// Context the requester declared, if any. Never a property of the
    /// signature itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_id: Option<String>,
    /// The exact bytes that are hashed.
    message_hex: String,
    /// The EIP-191 version `0x45` signing hash of those bytes.
    digest: String,
    status: MessageStatus,
    /// How the message reads, and everything about it that can mislead a
    /// human reading it in a native review.
    display: MessageDisplay,
    /// The parsed login, when the message is a recognized ERC-4361 payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    siwe: Option<SiweMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_at: Option<DateTime<Utc>>,
    /// The 65-byte r||s||v signature, present only once signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CreateForkInput {
    wallet_id: String,
    chain_id: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ForkOutput {
    fork_id: uuid::Uuid,
    wallet_id: String,
    chain_id: String,
    /// The real block this fork's state is pinned to.
    parent_block_number: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    applied_plans: u32,
    max_plans: u32,
    instruction: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DiscardForkInput {
    fork_id: uuid::Uuid,
}

#[derive(Debug, Serialize, JsonSchema)]
struct DiscardForkOutput {
    fork_id: uuid::Uuid,
    /// False when the fork had already expired or been discarded.
    discarded: bool,
    instruction: String,
}

#[derive(Clone, Copy, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ExecutionStatus {
    ApprovalRequired,
    TimedOut,
    Rejected,
    Approved,
    SubmissionPending,
    Submitted,
    Reverted,
    Cancelled,
    /// The envelope's nonce was consumed by a different mined transaction, so
    /// the exact signed bytes can never mine.
    Replaced,
    /// An owner-requested cancellation is racing the broadcast envelope at
    /// its own nonce; the chain has not yet settled which one mines.
    CancellationPending,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ExecutionStatusOutput {
    request_id: uuid::Uuid,
    wallet_id: String,
    chain_id: String,
    digest: String,
    status: ExecutionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<String>,
    /// False while the receipt is still being revalidated and retains the
    /// wallet/chain signing slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    finalized: Option<bool>,
    /// What this transaction actually cost, read from its receipt: gas burned,
    /// the price the chain charged, and their product in wei. Present once the
    /// record settles.
    ///
    /// This is the wallet's own record of a real price paid, so prefer it when
    /// judging whether gas is currently cheap. Reading a base fee onchain
    /// instead is a trap: a `wallet_batch_eth_call` to Multicall3's
    /// `getBasefee()` returns 0 at both `latest` and `pending` through some
    /// configured RPCs — a wrong answer rather than a failure. Treat this as
    /// backward-looking either way: it prices the last transaction, not the
    /// next one.
    #[serde(skip_serializing_if = "Option::is_none")]
    mined_fee: Option<crate::rpc::MinedFee>,
    /// How many blocks deep the mined receipt is (1 = head), when measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_status: Option<ReceiptStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcast_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    simulation: Option<SimulationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct SimulateOutput {
    #[serde(flatten)]
    result: SimulationResult,
    /// What the caller holding this result should do next; present only when
    /// the path forward is commonly misread.
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction: Option<String>,
}

#[tool_router]
impl WalletMcpServer {
    #[tool(
        name = "wallet_list",
        description = "Discover all local wallets: ID, address, source, and creation time. Never returns private keys. Use list_networks separately to discover configured chains and redacted RPC endpoint hosts.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn wallet_list(&self) -> Result<Json<WalletInventory>, ErrorData> {
        let state = self.config.load().map_err(|error| tool_error(&error))?;
        Ok(Json(WalletInventory {
            wallets: state
                .wallets
                .into_iter()
                .map(|wallet| PublicWallet {
                    id: wallet.id,
                    address: format!("{:#x}", wallet.address),
                    source: wallet.source,
                    created_at: wallet.created_at,
                })
                .collect(),
        }))
    }

    #[tool(
        name = "list_networks",
        description = "List every enabled globally configured network: name, decimal chain ID, each RPC endpoint's scheme/host/port, and endpoint selection strategy. URL paths, queries, userinfo, and disabled profiles are owner-only and are not disclosed. This contains no wallet or private-key information.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn list_networks(&self) -> Result<Json<NetworkInventory>, ErrorData> {
        let state = self.config.load().map_err(|error| tool_error(&error))?;
        Ok(Json(NetworkInventory {
            networks: state
                .networks
                .into_iter()
                .filter(|network| !network.disabled)
                .map(|network| PublicNetwork {
                    name: network.name,
                    chain_id: network.chain_id.to_string(),
                    testnet: network.testnet,
                    rpc_urls: network
                        .rpc_urls
                        .iter()
                        .map(ekubo_wallet_core::rpc::rpc_endpoint_label)
                        .collect(),
                    rpc_strategy: network.rpc_strategy.to_string(),
                })
                .collect(),
        }))
    }

    // Read-only in the strongest sense available: installation remains an
    // explicit owner operation in the signed desktop updater.
    #[tool(
        name = "wallet_check_for_updates",
        description = "Report whether a newer signed Ekubo Wallet desktop release has been published. Reads a release listing and nothing else: no wallet, key, address, policy, or transaction is involved, and this tool never installs, downloads, or modifies anything. When an update is available, direct the user to the wallet application's Updates screen; never download or install it on their behalf. Follow the returned instruction. An answer with update_available false, whether because this build is current or because the release listing could not be reached, is never a reason to suggest upgrading or to call this again.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn wallet_check_for_updates(&self) -> Result<Json<ReleaseCheck>, ErrorData> {
        // Deliberately not gated on legal acceptance, unlike every tool that
        // touches a wallet: "you are running a stale build" is exactly the
        // kind of thing someone still setting the wallet up should hear.
        Ok(Json(release_check::check().await))
    }

    #[tool(
        name = "wallet_get_policy",
        description = "Read the active SQLCipher-backed stateless signing policy and its monotonically increasing revision.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn wallet_get_policy(
        &self,
        Parameters(WalletInput { wallet_id }): Parameters<WalletInput>,
    ) -> Result<Json<PolicyOutput>, ErrorData> {
        let wallet = self
            .config
            .wallet(&wallet_id)
            .map_err(|error| tool_error(&error))?;
        let stored = self
            .policies
            .lock()
            .map_err(|_| ErrorData::internal_error("policy database lock was poisoned", None))?
            .get_for_wallet(&wallet_id, wallet.instance_id, wallet.address)
            .map_err(|error| tool_error(&error))?
            .ok_or_else(|| {
                ErrorData::invalid_params(format!("wallet {wallet_id} has no local policy"), None)
            })?;
        Ok(Json(PolicyOutput {
            wallet_id: stored.wallet_id,
            revision: stored.revision,
            updated_at: stored.updated_at,
            policy: stored.policy,
        }))
    }

    #[tool(
        name = "wallet_get_status",
        description = "Read native balance, transaction count, and EIP-7702 delegation status from the configured RPC for a canonical decimal chain ID.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn wallet_get_status(
        &self,
        Parameters(WalletNetworkInput {
            wallet_id,
            chain_id,
            fork_id,
        }): Parameters<WalletNetworkInput>,
    ) -> Result<Json<WalletStatus>, ErrorData> {
        let wallet = self
            .config
            .wallet(&wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&chain_id)
            .map_err(|error| tool_error(&error))?;
        let session = self.fork_session(fork_id, &chain_id, Some(&wallet_id))?;
        let preface = session.as_ref().map(ForkSession::preface);
        let mut status = wallet_status(&wallet, &network, preface.as_ref())
            .await
            .map_err(|error| tool_error(&error))?;
        status.fork = session.map(|session| session.read_context());
        Ok(Json(status))
    }

    // Not annotated read-only, though it signs nothing and broadcasts
    // nothing. A simulation against real chain state is recorded and returns
    // a `simulation_id` that `wallet_send_execution_plan` will later accept
    // as a short-lived plan handle, and a simulation on a fork appends the
    // plan to that fork, changing what every later call on it sees. Both are
    // modifications of this server's state, and `wallet_create_fork` is
    // already annotated for creating the same kind of state. Nothing here is
    // destructive: the only writes are additions, to registries that are
    // in-process, short-lived, and invisible at approval time.
    #[tool(
        name = "wallet_simulate_execution_plan",
        description = "Resolve an exact execution plan from a producer's artifact_reference envelope passed through VERBATIM as reference (the wallet fetches the body over vetted public HTTPS or decodes a bounded data:application/json URI and verifies the envelope's integrity digest and byte count), validate and policy-check it, then execute its direct call or atomic EIP-7702 Calibur batch with eth_simulateV1 against a pinned parent block. Never rename, restate, or reconstruct the envelope or the plan body. The wallet verifies response linkage and locally derives policy findings from returned results and transfer logs; there is no local fork or eth_getProof path. Policy findings describe what the user will be asked to approve, not a reason to stop: an allowed=false result with policy_outcome \"requires_approval\" still goes to wallet_send_execution_plan, which queues it for human approval. The one exception is policy_outcome \"rejected\", meaning a deny rule in the user's own policy matched: that never queues and sending it only fails. Follow the returned instruction.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_simulate_execution_plan(
        &self,
        Parameters(input): Parameters<SimulateInput>,
    ) -> Result<Json<SimulateOutput>, ErrorData> {
        // Local lookups settle first so an invalid wallet or chain never
        // becomes an outbound request to a caller-chosen URL.
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let (execution_plan, plan_source) =
            resolve_execution_plan_reference(&input.reference, FetchPolicy::production())
                .await
                .map_err(|error| tool_error(&error))?;
        let stored_policy = self
            .policies
            .lock()
            .map_err(|_| ErrorData::internal_error("policy database lock was poisoned", None))?
            .get_for_wallet(&input.wallet_id, wallet.instance_id, wallet.address)
            .map_err(|error| tool_error(&error))?
            .ok_or_else(|| {
                ErrorData::invalid_params(
                    format!("wallet {} has no local policy", input.wallet_id),
                    None,
                )
            })?;
        let session = self.fork_session(input.fork_id, &input.chain_id, Some(&input.wallet_id))?;
        // Refuse before spending a simulation rather than after.
        if let Some(session) = &session {
            ensure_tool(
                session.has_capacity(),
                &format!(
                    "fork {} already holds the maximum of {MAX_PLANS_PER_FORK} plans; open a new fork",
                    session.fork_id
                ),
            )?;
        }
        let preface = session.as_ref().map(ForkSession::preface);
        let policy_context = Self::policy_context(&wallet);
        let mut result = simulate_external_execution(
            &wallet,
            &network,
            &execution_plan,
            &stored_policy,
            &policy_context,
            preface.as_ref(),
        )
        .await
        .map_err(|error| tool_error(&error))?;
        // A result against real chain state is recorded under an identifier
        // the caller can hand back as an exact plan handle. Sending still
        // repeats real-chain simulation, preparation, and policy evaluation.
        // A fork result is never recorded: it describes a world that does not
        // exist.
        if session.is_none() {
            let mut simulations = self.simulations.lock().map_err(|_| {
                ErrorData::internal_error("simulation registry lock was poisoned", None)
            })?;
            let recorded = simulations.record_for_instance(
                &wallet.id,
                wallet.instance_id,
                &input.chain_id,
                execution_plan.clone(),
                Some(plan_source.to_string()),
                result.clone(),
                Utc::now(),
            );
            if self.register_global_simulation(&recorded) {
                result.simulation_id = Some(recorded.simulation_id);
            } else {
                simulations.discard(recorded.simulation_id);
            }
        }
        if let Some(session) = session {
            // Only a plan that actually executed becomes part of the fork's
            // history. Policy findings never gate the append: on a fork they
            // are advisory, so an agent can learn a sequence would be blocked
            // and still see the rest of it.
            result.fork = Some(if result.simulation.success {
                self.forks
                    .lock()
                    .map_err(|_| {
                        ErrorData::internal_error("fork registry lock was poisoned", None)
                    })?
                    .append(
                        session.fork_id,
                        execution_plan,
                        session.plans.len(),
                        Utc::now(),
                    )
                    .map_err(|error| tool_error(&error))?
                    .applied_context()
            } else {
                session.read_context()
            });
        }
        // The instruction rides on the result an agent is actually holding
        // when it first sees allowed=false, because that is the moment the
        // findings get misread as a dead end. A fork result carries no such
        // instruction: its findings are advisory and nothing about it can be
        // sent.
        let instruction = match result.simulation_id {
            Some(simulation_id) if !result.allowed && result.simulation.success => Some(
                policy_denial_next_step(result.policy_outcome, simulation_id),
            ),
            _ => None,
        };
        Ok(Json(SimulateOutput {
            result,
            instruction,
        }))
    }

    #[tool(
        name = "wallet_create_fork",
        description = "Open a temporary simulation fork so a chain of dependent actions can be simulated end to end before the user is asked to approve the first step. The fork pins the current block and starts empty. Pass its fork_id to wallet_simulate_execution_plan to run a plan on top of everything already applied to that fork and, on success, append it; pass it to wallet_batch_eth_call, wallet_get_balances, wallet_get_portfolio, and wallet_get_status to read the world as it would be after those plans, so preparation tools can build step N+1 against step N's state. Everything a fork produces is hypothetical: it never creates a pending request, never signs, never approves, never satisfies a policy rule, and never appears at approval time. Submission always re-simulates and re-policy-checks against real chain state, so passing on a fork is not a substitute. Forks cannot advance blocks or time, though eth_simulateV1 advances the block number by one per applied plan. They expire, are capped per wallet, hold a small number of plans, and are lost when this server restarts.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_create_fork(
        &self,
        Parameters(CreateForkInput {
            wallet_id,
            chain_id,
        }): Parameters<CreateForkInput>,
    ) -> Result<Json<ForkOutput>, ErrorData> {
        let wallet = self
            .config
            .wallet(&wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&chain_id)
            .map_err(|error| tool_error(&error))?;
        // Refuse before spending the round trip, not after. `create` checks
        // the same limits and stays the authority; this keeps a caller at its
        // fork limit from buying two RPC calls per attempt to be told no.
        self.forks
            .lock()
            .map_err(|_| ErrorData::internal_error("fork registry lock was poisoned", None))?
            .ensure_capacity(&wallet_id, wallet.instance_id, Utc::now())
            .map_err(|error| tool_error(&error))?;
        self.ensure_global_fork_capacity()?;
        let parent = pin_parent_block(&network)
            .await
            .map_err(|error| tool_error(&error))?;
        let session = self
            .forks
            .lock()
            .map_err(|_| ErrorData::internal_error("fork registry lock was poisoned", None))?
            .create(
                &wallet_id,
                wallet.instance_id,
                wallet.address,
                network.chain_id,
                parent,
                Utc::now(),
            )
            .map_err(|error| tool_error(&error))?;
        if let Err(error) = self.register_global_fork(&session) {
            if let Ok(mut forks) = self.forks.lock() {
                forks.discard(session.fork_id);
            }
            return Err(error);
        }
        Ok(Json(ForkOutput {
            fork_id: session.fork_id,
            wallet_id: session.wallet_id.clone(),
            chain_id: session.chain_id.to_string(),
            parent_block_number: session.parent.number.to_string(),
            created_at: session.created_at,
            expires_at: session.expires_at,
            applied_plans: 0,
            max_plans: u32::try_from(MAX_PLANS_PER_FORK).unwrap_or(u32::MAX),
            instruction: format!(
                "Simulate each step of the sequence with wallet_simulate_execution_plan and this fork_id, in order; a step that executes successfully is appended and the next one sees its state. Read through the fork with the same fork_id so preparation tools build later steps against the right world. Show the user the net effect of the whole sequence, then submit the real plans one at a time through the normal approval path without any fork_id. This fork expires at {} and is discarded with wallet_discard_fork.",
                session.expires_at.to_rfc3339()
            ),
        }))
    }

    #[tool(
        name = "wallet_discard_fork",
        description = "Discard a temporary simulation fork and every plan applied to it. Forks also expire on their own; discarding early frees one of the wallet's fork slots. Nothing on chain is affected, because a fork never held anything real.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn wallet_discard_fork(
        &self,
        Parameters(DiscardForkInput { fork_id }): Parameters<DiscardForkInput>,
    ) -> Result<Json<DiscardForkOutput>, ErrorData> {
        let discarded = self
            .forks
            .lock()
            .map_err(|_| ErrorData::internal_error("fork registry lock was poisoned", None))?
            .discard(fork_id);
        if discarded {
            self.release_global_fork(fork_id);
        }
        Ok(Json(DiscardForkOutput {
            fork_id,
            discarded,
            instruction: if discarded {
                "The fork and everything applied to it are gone. Nothing on chain changed."
            } else {
                "No such live fork; it had already expired or been discarded. Nothing on chain changed."
            }
            .into(),
        }))
    }

    #[tool(
        name = "wallet_decode_abi_result",
        description = "Decode previously obtained EVM return bytes entirely inside this process. Enforces canonical ABI encoding, bounded recursive plans, deterministic JSON values, and an exact local semantic-codec allowlist. Performs no RPC or transaction work.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    #[allow(clippy::unused_self)]
    fn wallet_decode_abi_result(
        &self,
        Parameters(input): Parameters<DecodeAbiInput>,
    ) -> Json<AbiDecodeResult> {
        Json(decode_abi_result(
            &input.return_data,
            &input.decode,
            input.include_raw,
        ))
    }

    #[tool(
        name = "wallet_batch_eth_call",
        description = "Execute 1-4096 read-only eth_call requests against one exact resolved block. Count is only one bound: calldata, response size, timeout, RPC gas, and decoder-work limits still apply. Accepts inline calls, or a producer read_calls_reference envelope passed through VERBATIM as reference — the wallet fetches, decompresses when HTTP content encoding is used, and integrity-verifies the bounded HTTPS or data:application/json call bundle itself instead of having it restated. Uses Multicall3 when caller semantics permit, otherwise bounded parallel individual calls, and can apply the same deterministic local ABI decoder inline.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn wallet_batch_eth_call(
        &self,
        Parameters(input): Parameters<BatchEthCallInput>,
    ) -> Result<Json<BatchEthCallOutput>, ErrorData> {
        // The local network lookup settles first so an invalid chain never
        // becomes an outbound request to a caller-chosen URL.
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let input = resolve_read_input(input, FetchPolicy::production())
            .await
            .map_err(|error| tool_input_error(&error))?;
        crate::batch_read::validate_input(&input).map_err(|error| tool_input_error(&error))?;
        let session = self.fork_session(input.fork_id, &input.chain_id, None)?;
        let preface = session.as_ref().map(ForkSession::preface);
        let mut output = batch_eth_call(&network, &input, preface.as_ref())
            .await
            .map_err(|error| tool_error(&error))?;
        output.fork = session.map(|session| session.read_context());
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_list_tokens",
        description = "List tokens the owner has confirmed in the local token database, optionally filtered by decimal chain ID, with limit/offset paging. These are the only tokens the wallet will name when the owner reviews a transaction; anything absent is shown by address alone. Tokens merely proposed and not yet confirmed are not listed. Token metadata is public display data and never affects signing decisions.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn wallet_list_tokens(
        &self,
        Parameters(input): Parameters<ListTokensInput>,
    ) -> Result<Json<TokenListOutput>, ErrorData> {
        let chain_id = input
            .chain_id
            .as_ref()
            .map(crate::token_store::ChainIdInput::value)
            .transpose()
            .map_err(|error| tool_error(&error))?;
        let enabled_chains = self
            .enabled_chain_ids()
            .map_err(|error| tool_error(&error))?;
        if let Some(chain_id) = chain_id {
            ensure_tool(
                enabled_chains.binary_search(&chain_id).is_ok(),
                "no enabled network has that chain ID",
            )?;
        }
        let store = self
            .tokens
            .lock()
            .map_err(|_| ErrorData::internal_error("token database lock was poisoned", None))?;
        let limit = input.limit.min(1_000);
        let (total, tokens) = if let Some(chain_id) = chain_id {
            let tokens = store
                .list(Some(chain_id), limit, input.offset)
                .map_err(|error| tool_error(&error))?;
            let total = store
                .count(Some(chain_id))
                .map_err(|error| tool_error(&error))?;
            (total, tokens)
        } else {
            let mut total = 0_u64;
            let mut remaining_offset = input.offset as u64;
            let mut tokens = Vec::new();
            for chain_id in enabled_chains {
                let chain_total = store
                    .count(Some(chain_id))
                    .map_err(|error| tool_error(&error))?;
                total = total.saturating_add(chain_total);
                if remaining_offset >= chain_total {
                    remaining_offset -= chain_total;
                    continue;
                }
                if tokens.len() < limit {
                    let page = store
                        .list(
                            Some(chain_id),
                            limit - tokens.len(),
                            usize::try_from(remaining_offset).unwrap_or(usize::MAX),
                        )
                        .map_err(|error| tool_error(&error))?;
                    tokens.extend(page);
                }
                remaining_offset = 0;
            }
            (total, tokens)
        };
        Ok(Json(TokenListOutput { total, tokens }))
    }

    #[tool(
        name = "wallet_search_tokens",
        description = "Search the tokens the owner has confirmed, by symbol, name, or address, optionally within one decimal chain ID. Use this to resolve a symbol a user typed into the exact address to act on, and to check whether the wallet can name a token before proposing it. Symbol and name match case-insensitively on substring; an address matches exactly, because a partial address match would answer a question about one token with a different one. Exact symbol matches are returned first. Only confirmed tokens are searched: a token still awaiting the owner's review is not one the wallet will name. An empty result means the wallet has no confirmed name for it, not that the token does not exist.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn wallet_search_tokens(
        &self,
        Parameters(input): Parameters<SearchTokensInput>,
    ) -> Result<Json<TokenSearchOutput>, ErrorData> {
        let chain_id = input
            .chain_id
            .as_ref()
            .map(crate::token_store::ChainIdInput::value)
            .transpose()
            .map_err(|error| tool_error(&error))?;
        let enabled_chains = self
            .enabled_chain_ids()
            .map_err(|error| tool_error(&error))?;
        if let Some(chain_id) = chain_id {
            ensure_tool(
                enabled_chains.binary_search(&chain_id).is_ok(),
                "no enabled network has that chain ID",
            )?;
        }
        let store = self
            .tokens
            .lock()
            .map_err(|_| ErrorData::internal_error("token database lock was poisoned", None))?;
        let mut tokens = if let Some(chain_id) = chain_id {
            store
                .search(&input.query, Some(chain_id), input.limit)
                .map_err(|error| tool_error(&error))?
        } else {
            let mut matches = Vec::new();
            for chain_id in enabled_chains {
                matches.extend(
                    store
                        .search(&input.query, Some(chain_id), input.limit)
                        .map_err(|error| tool_error(&error))?,
                );
            }
            matches
        };
        let query = input.query.trim().to_lowercase();
        tokens.sort_by_key(|token| {
            (
                token
                    .symbol
                    .as_deref()
                    .is_none_or(|symbol| symbol.to_lowercase() != query),
                token.symbol.as_ref().map_or(usize::MAX, String::len),
                token.chain_id.parse::<u64>().unwrap_or(u64::MAX),
                token.address.clone(),
            )
        });
        tokens.truncate(input.limit.min(1_000));
        Ok(Json(TokenSearchOutput {
            matches: tokens.len() as u64,
            tokens,
        }))
    }

    #[tool(
        name = "wallet_propose_tokens",
        description = "Suggest tokens for the owner to add to the local token database, from a token list you name. Provide the entries one of two ways: inline in tokens, or — for anything beyond a handful — as a producer's token_list artifact_reference envelope passed through VERBATIM as reference, which the wallet fetches and integrity-verifies itself instead of having the list restated a field at a time. Prefer the reference: a thousand-token list costs about fifty thousand output tokens to write out and a few hundred to reference, and the two paths are otherwise identical. This never adds anything: suggestions wait until the owner reviews them in the Tokens review screen, where they accept or reject them by list. The owner sees your list_name marked as a name you gave rather than one anything verified, so it can never be mistaken for a group wallet_import_token_list built from a publisher's own TLS host. Symbols matter because the wallet shows them when the owner reviews a transaction that moves the token, and a name the owner trusts is worth forging — which is why they come from a curated list you cite rather than from each contract's own symbol(), a string any address can answer with anything, and why only the owner can turn a suggestion into a name. Pass the list's own symbol, name, and decimals for each entry; decimals scales every amount the owner is shown for the token and the contract is never consulted about it either. Tokens already confirmed are reported and not re-proposed; proposing the same address again replaces the earlier suggestion. Accepting reaches no chain at all: a contract cannot tell the owner whether the curator you cited is trustworthy, which is the only question a listing raises, so their approval is the check and an address with nothing behind it just yields a row that names nothing.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            // The `reference` path fetches a body from a URL the caller
            // named, over the same admission policy a plan reference uses.
            // Nothing about the proposal reaches a chain, but the call does
            // leave this machine, so it is not a closed-world tool.
            open_world_hint = true
        )
    )]
    async fn wallet_propose_tokens(
        &self,
        Parameters(input): Parameters<ProposeTokensInput>,
    ) -> Result<Json<ProposeTokensOutput>, ErrorData> {
        ensure_tool(
            input.tokens.is_empty() != input.reference.is_none(),
            "provide exactly one of tokens and reference",
        )?;
        let (list_name, listed, skipped_non_evm) = if let Some(reference) = &input.reference {
            let (parsed, _source) = crate::plan_fetch::resolve_token_list_reference(
                reference,
                FetchPolicy::production(),
            )
            .await
            .map_err(|error| tool_error(&error))?;
            let list_name = input
                .list_name
                .clone()
                .or(parsed.declared_name)
                .ok_or_else(|| {
                    ErrorData::invalid_params(
                        "the referenced list declares no name; pass list_name so the owner \
                         sees where these suggestions came from"
                            .to_owned(),
                        None,
                    )
                })?;
            (list_name, parsed.tokens, parsed.skipped_non_evm)
        } else {
            let list_name = input.list_name.clone().ok_or_else(|| {
                ErrorData::invalid_params(
                    "list_name is required with inline tokens".to_owned(),
                    None,
                )
            })?;
            ensure_tool(
                input.tokens.len() <= crate::token_store::MAX_IMPORT_TOKENS,
                "proposal exceeds the per-call maximum",
            )?;
            let mut listed = Vec::with_capacity(input.tokens.len());
            for item in &input.tokens {
                let chain_id = item.chain_id.value().map_err(|error| tool_error(&error))?;
                let address = Address::from_str(&item.address).map_err(|_| {
                    ErrorData::invalid_params(
                        format!(
                            "token address {} is not a 20-byte EVM address",
                            item.address
                        ),
                        None,
                    )
                })?;
                listed.push(crate::token_store::ListedToken {
                    chain_id,
                    address,
                    symbol: item.symbol.clone(),
                    name: item.name.clone(),
                    decimals: item.decimals,
                });
            }
            (list_name, listed, 0)
        };
        ensure_tool(
            !listed.is_empty(),
            "a proposal must contain at least one token",
        )?;
        let enabled_chains = self
            .enabled_chain_ids()
            .map_err(|error| tool_error(&error))?;
        ensure_tool(
            listed
                .iter()
                .all(|token| enabled_chains.binary_search(&token.chain_id).is_ok()),
            "token proposal includes a chain without an enabled network",
        )?;
        let mut store = self
            .tokens
            .lock()
            .map_err(|_| ErrorData::internal_error("token database lock was poisoned", None))?;
        let summary = store
            .propose(
                &listed,
                &crate::token_store::ProposalSource::Claimed(&list_name),
            )
            .map_err(|error| tool_error(&error))?;
        drop(store);
        let attributed = listed
            .iter()
            .map(|token| (token.chain_id, token.address.into_array()))
            .collect::<Vec<_>>();
        self.with_attribution(|desktop, client_id| {
            desktop.attribute_token_proposals(&attributed, client_id)
        })
        .map_err(|error| tool_error(&error))?;
        let store = self
            .tokens
            .lock()
            .map_err(|_| ErrorData::internal_error("token database lock was poisoned", None))?;
        let awaiting_review = store
            .count_proposals()
            .map_err(|error| tool_error(&error))?;
        Ok(Json(ProposeTokensOutput {
            summary,
            awaiting_review,
            skipped_non_evm,
            next_step: "The owner reviews these in the desktop Tokens review screen. \
                        Until they accept one, the wallet keeps showing that token by \
                        address alone."
                .into(),
        }))
    }

    #[tool(
        name = "wallet_import_token_list",
        description = "Import a published token list by URL, so the owner can set up the lists they want by naming one rather than having it restated entry by entry. Takes the https URL a list is published at — https://tokens.uniswap.org, and the other lists catalogued at tokenlists.org — and reads the standard Uniswap token-list schema: a tokens array whose entries carry chainId, address, symbol, name, and decimals, with the list's own name, version, and timestamp reported back so the owner can see which revision they are accepting. Published lists span many chains, so entries are taken only for the chains this wallet has networks configured for; pass chain_ids to narrow that further. Everything else is skipped and counted rather than imported silently, including entries whose address is not a 20-byte EVM address, such as a list's Starknet or Solana rows. At most 10000 entries after that selection, which fits the published lists people actually name, and an overflowing selection is refused rather than truncated — narrow the chains, or point at a more specific list. This adds nothing to the token database: every entry becomes a suggestion the owner accepts or rejects as a group in the Tokens review screen, and until they do the wallet keeps showing those tokens by address alone. Unlike the reference path on wallet_propose_tokens there is no integrity digest here, because a list at a well-known URL is whatever its curator published today — which is why the owner is shown the host that served it rather than a name you chose, and why you cannot label the import: the suggestions are grouped under that host and the list's own declared name. Symbols and decimals come from the list and are never read from the contract, since any address can answer symbol() with anything, and decimals scales every amount the owner is ever shown for the token. Use wallet_propose_tokens instead when you hold entries inline or a producer handed you a token_list reference.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            // Re-importing the same list re-files the same suggestions rather
            // than stacking them: a repeated proposal for an address replaces
            // the earlier one.
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn wallet_import_token_list(
        &self,
        Parameters(input): Parameters<ImportTokenListInput>,
    ) -> Result<Json<ImportTokenListOutput>, ErrorData> {
        // An omitted selection means the chains this wallet is set up for.
        // A published list spans chains the owner does not use, and every row
        // for one of those is a decision added to a review screen that only
        // works while it is short enough to read.
        let chain_ids = if input.chain_ids.is_empty() {
            self.config
                .load()
                .map_err(|error| tool_error(&error))?
                .networks
                .iter()
                .filter(|network| !network.disabled)
                .map(|network| network.chain_id)
                .collect::<Vec<_>>()
        } else {
            input
                .chain_ids
                .iter()
                .map(|chain_id| {
                    self.config
                        .network_by_chain_id(chain_id)
                        .map(|network| network.chain_id)
                        .map_err(|error| tool_error(&error))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let (parsed, host) = crate::plan_fetch::fetch_token_list_url(
            &input.url,
            &chain_ids,
            FetchPolicy::production(),
        )
        .await
        .map_err(|error| tool_error(&error))?;
        // The host leads because it is the one part of this the caller could
        // not choose: TLS proved it, while the declared name is a string the
        // same bytes carried. An owner deciding whether to trust a list is
        // deciding about a publisher, so the publisher is what they read
        // first, and a list that names itself something it is not cannot push
        // that off the label.
        let source = crate::token_store::ProposalSource::Served {
            host: &host,
            declared: parsed.declared_name.as_deref(),
        };
        let list_name = source.label();
        let mut store = self
            .tokens
            .lock()
            .map_err(|_| ErrorData::internal_error("token database lock was poisoned", None))?;
        let summary = store
            .propose(&parsed.tokens, &source)
            .map_err(|error| tool_error(&error))?;
        let awaiting_review = store
            .count_proposals()
            .map_err(|error| tool_error(&error))?;
        Ok(Json(ImportTokenListOutput {
            summary,
            list_name,
            host,
            declared_version: parsed.declared_version,
            declared_timestamp: parsed.declared_timestamp,
            chains_selected: chain_ids.iter().map(u64::to_string).collect(),
            awaiting_review,
            skipped_non_evm: parsed.skipped_non_evm,
            skipped_other_chain: parsed.skipped_other_chain,
            next_step: "The owner reviews these in the desktop Tokens review screen, where they \
                        accept or reject the whole list at once. Until they accept one, the \
                        wallet keeps showing that token by address alone."
                .into(),
        }))
    }

    #[tool(
        name = "wallet_get_portfolio",
        description = "Read the native balance and every token-database balance for one address on one chain, pinned to a reported block, through the same path as wallet_get_balances: the Ekubo TokenDataFetcher lens where deployed, otherwise Multicall3 balanceOf reads. Accepts a wallet_id or any EVM address. Only nonzero token balances are returned. At most 8000 known tokens are checked; a database holding more reports the remainder as tokens_skipped rather than reading them.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn wallet_get_portfolio(
        &self,
        Parameters(input): Parameters<PortfolioInput>,
    ) -> Result<Json<crate::token_store::Portfolio>, ErrorData> {
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let address =
            self.resolve_read_address(input.wallet_id.as_deref(), input.address.as_deref())?;
        let known = {
            let store = self
                .tokens
                .lock()
                .map_err(|_| ErrorData::internal_error("token database lock was poisoned", None))?;
            store
                .list(
                    Some(network.chain_id),
                    crate::token_store::MAX_PORTFOLIO_TOKENS + 1,
                    0,
                )
                .map_err(|error| tool_error(&error))?
        };
        let session = self.fork_session(input.fork_id, &input.chain_id, None)?;
        let preface = session.as_ref().map(ForkSession::preface);
        let mut portfolio =
            crate::token_store::read_portfolio(&network, address, &known, preface.as_ref())
                .await
                .map_err(|error| tool_error(&error))?;
        portfolio.fork = session.map(|session| session.read_context());
        Ok(Json(portfolio))
    }

    #[tool(
        name = "wallet_get_balances",
        description = "Read balances for up to 1000 token addresses for one address on one chain, pinned to a reported block. Give the addresses inline in tokens, or as a producer's token_list artifact_reference envelope passed through VERBATIM as reference — the wallet fetches and integrity-verifies the list itself and reads only its entries on the selected chain, so one canonical multi-chain list serves every chain without being restated. Uses the Ekubo TokenDataFetcher lens where deployed (all default networks) and falls back to individual Multicall3 balanceOf reads elsewhere; failed, nonexistent, or misbehaving tokens read as zero instead of aborting the batch, and only nonzero balances are returned with their token addresses. Address 0x0000000000000000000000000000000000000000 reads the native balance. Accepts a wallet_id or any EVM address.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn wallet_get_balances(
        &self,
        Parameters(input): Parameters<GetBalancesInput>,
    ) -> Result<Json<crate::token_store::TokenBalances>, ErrorData> {
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let owner =
            self.resolve_read_address(input.wallet_id.as_deref(), input.address.as_deref())?;
        ensure_tool(
            input.tokens.is_empty() != input.reference.is_none(),
            "provide exactly one of tokens and reference",
        )?;
        let tokens = if let Some(reference) = &input.reference {
            let (parsed, _source) = crate::plan_fetch::resolve_token_list_reference(
                reference,
                FetchPolicy::production(),
            )
            .await
            .map_err(|error| tool_error(&error))?;
            // A canonical list spans chains; reading the whole thing against
            // one chain would spend the request on addresses that cannot hold
            // a balance there. Filtering here is what lets one reference serve
            // every chain the caller asks about.
            let addresses: Vec<Address> = parsed
                .tokens
                .iter()
                .filter(|token| token.chain_id == network.chain_id)
                .map(|token| token.address)
                .collect();
            ensure_tool(
                !addresses.is_empty(),
                "the referenced list holds no tokens on this chain",
            )?;
            addresses
        } else {
            input
                .tokens
                .iter()
                .map(|token| {
                    Address::from_str(token).map_err(|_| {
                        ErrorData::invalid_params(
                            format!("token address {token} is not a 20-byte EVM address"),
                            None,
                        )
                    })
                })
                .collect::<Result<Vec<_>, ErrorData>>()?
        };
        ensure_tool(
            tokens.len() <= crate::token_store::MAX_BALANCE_TOKENS,
            "tokens exceeds the per-request maximum of 1000 addresses",
        )?;
        let session = self.fork_session(input.fork_id, &input.chain_id, None)?;
        let preface = session.as_ref().map(ForkSession::preface);
        let mut balances =
            crate::token_store::read_token_balances(&network, owner, &tokens, preface.as_ref())
                .await
                .map_err(|error| tool_error(&error))?;
        balances.fork = session.map(|session| session.read_context());
        Ok(Json(balances))
    }

    #[tool(
        name = "wallet_send_execution_plan",
        description = "Freshly simulate, prepare the exact transaction envelope, evaluate the current policy, then locally sign, persist, and broadcast an execution plan resolved from a producer's bounded HTTPS or data:application/json artifact_reference envelope passed through VERBATIM as reference; consume a prior simulation_id as a short-lived handle to that exact plan while repeating the same fresh pipeline; or submit the exact signed bytes for a separately approved request_id. Provide exactly one of reference, simulation_id, or request_id. A simulation_id is not approval, policy authority, or a reusable prepared envelope. Set on_simulation_failure to \"fail\" to be told about a failed simulation instead of queuing it for the user; a plan with an unmatched call or review effect queues for approval, and a plan with any deny result fails without queuing whatever you set. This tool cannot approve a request or create a replacement transaction on retry.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_send_execution_plan(
        &self,
        Parameters(input): Parameters<SendExecutionPlanInput>,
    ) -> Result<Json<ExecutionStatusOutput>, ErrorData> {
        let selected = usize::from(input.reference.is_some())
            + usize::from(input.simulation_id.is_some())
            + usize::from(input.request_id.is_some());
        if selected != 1 {
            return Err(ErrorData::invalid_params(
                "provide exactly one of reference, simulation_id, or request_id",
                None,
            ));
        }
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let output = match (input.reference, input.simulation_id, input.request_id) {
            (Some(reference), None, None) => {
                let (plan, plan_source) =
                    resolve_execution_plan_reference(&reference, FetchPolicy::production())
                        .await
                        .map_err(|error| tool_error(&error))?;
                Box::pin(self.send_new_plan(
                    wallet,
                    network,
                    plan,
                    Some(plan_source.to_string()),
                    input.on_simulation_failure,
                ))
                .await
            }
            (None, Some(simulation_id), None) => {
                Box::pin(self.send_recorded_simulation(
                    wallet,
                    network,
                    simulation_id,
                    input.on_simulation_failure,
                ))
                .await
            }
            (None, None, Some(request_id)) => {
                self.send_existing_request(wallet, network, request_id)
                    .await
            }
            _ => unreachable!("exclusive input was checked"),
        }
        .map_err(|error| tool_error(&error))?;
        self.publish_execution_status(&output);
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_attempt_cancel",
        description = "Attempt to cancel a broadcast but unmined transaction by outbidding it with a 0-value self-send at its own nonce. Reconciles against the chain first and fails if the transaction already mined, was already cancelled, or was already replaced. The cancellation derives every field from the stored envelope and the chain, cannot expand what was authorized, and therefore needs no policy check or approval; the original may still win the race, so reconcile afterwards with wallet_get_execution_status or wallet_wait_for_execution. Call again to outbid a cancellation that is itself stuck.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_attempt_cancel(
        &self,
        Parameters(input): Parameters<RequestInput>,
    ) -> Result<Json<ExecutionStatusOutput>, ErrorData> {
        // Cancellation signs, so it repeats the legal gate like every other
        // signing path, as defense in depth.
        self.require_legal_acceptance()
            .map_err(|error| tool_error(&error))?;
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let record = self
            .pending_record(&input.wallet_id, &input.chain_id, input.request_id)
            .map_err(|error| tool_error(&error))?;
        let (record, broadcast) = self
            .execution_authority
            .cancel(&self.pending, &self.config, &wallet, &network, record)
            .await
            .map_err(|error| tool_error(&error))?;
        let mut output = execution_status_output(record);
        output.broadcast_error = broadcast.broadcast_error;
        self.publish_execution_status(&output);
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_propose_network",
        description = "Suggest one complete server-wide EVM network for the owner to review in the native wallet application. Adds nothing: a proposal naming a chain ID that is already configured is an edit of that network, one naming a chain ID that is not is an addition, and neither takes effect until the owner accepts it. The RPC endpoint is admitted (public https, no credentials, no private address) when proposed and its chain ID is verified when accepted.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn wallet_propose_network(
        &self,
        Parameters(input): Parameters<AddNetworkInput>,
    ) -> Result<Json<ProposedNetworkOutput>, ErrorData> {
        let chain_id = parse_chain_id(&input.chain_id).map_err(|error| tool_error(&error))?;
        let testnet = ekubo_wallet_core::networks::known_network(chain_id)
            .map_or(input.testnet, |profile| profile.config.testnet);
        let candidate = NetworkConfig {
            name: input.name,
            disabled: false,
            testnet,
            display_name: Some(input.display_name),
            aliases: input.aliases,
            chain_id,
            rpc_urls: input.rpc_urls,
            rpc_strategy: input
                .rpc_strategy
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|error: anyhow::Error| tool_error(&error))?
                .unwrap_or_default(),
            finality_confirmations: input.finality_confirmations,
            native_currency: Some(input.native_currency),
            block_explorer_url: Some(input.block_explorer_url),
            documentation_url: Some(input.documentation_url),
        };
        // A proposal for a chain already configured is an edit of it; for one
        // that is not, an addition. Both are refused the same way if the
        // profile is malformed, so the agent hears about a bad field now
        // rather than the owner hearing about it at review.
        let configured = self.config.load().map_err(|error| tool_error(&error))?;
        let replaces = configured
            .networks
            .iter()
            .find(|network| !network.disabled && network.chain_id == candidate.chain_id)
            .map(|network| network.name.clone());
        // A name or alias belonging to a *different* chain is a conflict no
        // confirmation can resolve, so it fails here rather than becoming a
        // decision the owner cannot act on.
        for network in configured
            .networks
            .iter()
            .filter(|network| !network.disabled)
        {
            if network.chain_id == candidate.chain_id {
                continue;
            }
            let taken = std::iter::once(&network.name).chain(network.aliases.iter());
            let proposed: std::collections::BTreeSet<&String> = std::iter::once(&candidate.name)
                .chain(candidate.aliases.iter())
                .collect();
            for identifier in taken {
                ensure_tool(
                    !proposed.contains(identifier),
                    &format!(
                        "{identifier} already names chain {}, so it cannot also name chain {}",
                        network.chain_id, candidate.chain_id
                    ),
                )?;
            }
        }
        // Taken before the admission check, because that check resolves a
        // hostname the caller chose and DNS to an arbitrary name is outbound
        // work. Refused rather than queued: waiting would let a caller build a
        // backlog, which is the thing being prevented.
        let _probe = NETWORK_PROBE_SLOTS.try_acquire().map_err(|_| {
            tool_error(&"another network proposal is already being checked; retry once it finishes")
        })?;
        // `validate_network` admits http and loopback so an owner can point
        // their own wallet at a devnet. This caller is not the owner, so the
        // endpoint passes the same admission a referenced plan URL does.
        //
        // The chain ID is deliberately NOT probed here. Verifying it now would
        // prove something about an endpoint at proposal time and store the
        // result for the owner to read later, which is the weaker claim; the
        // check that matters happens in `network review`, immediately before
        // the profile is written. Not probing also keeps an unconfirmed agent
        // action from producing a JSON-RPC request.
        // Every endpoint, not just the first. A proposal whose second entry
        // is a loopback address is exactly the proposal this check exists to
        // refuse, and failover would reach it.
        for endpoint in &candidate.rpc_urls {
            ekubo_wallet_core::plan_fetch::ensure_public_endpoint(endpoint, "RPC URL")
                .await
                .map_err(|error| tool_error(&error))?;
        }
        self.policies
            .lock()
            .map_err(|_| ErrorData::internal_error("policy store lock was poisoned", None))?
            .put_network_proposal(&candidate)
            .map_err(|error| tool_error(&error))?;
        self.with_attribution(|desktop, client_id| {
            desktop.attribute_network_proposal(candidate.chain_id, client_id)
        })
        .map_err(|error| tool_error(&error))?;
        Ok(Json(ProposedNetworkOutput {
            chain_id: candidate.chain_id.to_string(),
            replaces,
            pending_review: true,
        }))
    }

    #[tool(
        name = "wallet_wait_for_approval",
        description = "Wait for a pending transaction to be approved and signed or rejected through the native wallet review window. This tool cannot approve, reject, sign, or submit it.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn wallet_wait_for_approval(
        &self,
        Parameters(input): Parameters<ApprovalWaitInput>,
    ) -> Result<Json<ExecutionStatusOutput>, ErrorData> {
        let (record, timed_out) = wait_for_decision(
            input.timeout_seconds,
            || {
                self.pending_record_by_id(input.request_id)
                    .map_err(|error| tool_error(&error))
            },
            |record| record.status == PendingStatus::AwaitingApproval,
        )
        .await?;
        let mut output = execution_status_output(record);
        if timed_out {
            output.status = ExecutionStatus::TimedOut;
            output.instruction = Some(still_awaiting_instruction(
                "wallet_wait_for_approval",
                output.request_id,
            ));
        }
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_get_execution_status",
        description = "Read and reconcile one encrypted pending transaction lifecycle record. This tool never approves, signs, or submits a transaction.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn wallet_get_execution_status(
        &self,
        Parameters(input): Parameters<RequestInput>,
    ) -> Result<Json<ExecutionStatusOutput>, ErrorData> {
        Ok(Json(
            self.reconcile_pending(&input)
                .await
                .map_err(|error| tool_error(&error))?,
        ))
    }

    #[tool(
        name = "wallet_wait_for_execution",
        description = "Wait for an execution plan to be executed: poll a previously broadcast transaction for up to 55 seconds, reconcile its receipt, and optionally keep waiting until the receipt has a requested number of confirmations. Repeat the call after each timeout to continue waiting. This tool never approves, signs, or submits.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn wallet_wait_for_execution(
        &self,
        Parameters(input): Parameters<WaitInput>,
    ) -> Result<Json<ExecutionStatusOutput>, ErrorData> {
        validate_timeout_seconds(input.timeout_seconds).map_err(|error| tool_error(&error))?;
        ensure_tool(
            (1..=1_000).contains(&input.confirmations),
            "confirmations must be between 1 and 1000",
        )?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let request = RequestInput {
            wallet_id: input.wallet_id,
            chain_id: input.chain_id,
            request_id: input.request_id,
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(u64::from(input.timeout_seconds));
        loop {
            // The deadline bounds the loop; without this it bounded only the
            // decision to iterate again, and one pass could outlast it by four
            // RPC timeouts. A pass that runs out of grace returns the stored
            // record, which is what this endpoint is documented to be — the
            // last observation, not a live read.
            let Ok(status) = tokio::time::timeout_at(
                deadline + WAIT_RECONCILE_GRACE,
                self.reconcile_pending(&request),
            )
            .await
            else {
                return self
                    .pending_record(
                        request.wallet_id.as_str(),
                        request.chain_id.as_str(),
                        request.request_id,
                    )
                    .map(|record| Json(execution_status_output(record)))
                    .map_err(|error| tool_error(&error));
            };
            let mut status = status.map_err(|error| tool_error(&error))?;
            let mined = matches!(
                status.status,
                ExecutionStatus::Submitted | ExecutionStatus::Reverted
            );
            if mined {
                let receipt_block = status
                    .block_number
                    .as_deref()
                    .and_then(|block| block.parse::<u64>().ok());
                let Some(receipt_block) = receipt_block else {
                    return Ok(Json(status));
                };
                let Ok(latest) = tokio::time::timeout_at(
                    deadline + WAIT_RECONCILE_GRACE,
                    crate::rpc::latest_block_number(&network),
                )
                .await
                else {
                    return Ok(Json(status));
                };
                let latest = latest.map_err(|error| tool_error(&error))?;
                // A lagging RPC can briefly report a head below the receipt
                // block; the mined receipt still counts as one confirmation.
                let observed = latest.saturating_sub(receipt_block).saturating_add(1);
                status.confirmations = Some(observed);
                if observed >= u64::from(input.confirmations) {
                    return Ok(Json(status));
                }
                if tokio::time::Instant::now() >= deadline {
                    status.instruction = Some(format!(
                        "The transaction is mined with {observed} of {} requested confirmations. Call wallet_wait_for_execution again with the same request_id and confirmations to continue waiting.",
                        input.confirmations
                    ));
                    return Ok(Json(status));
                }
            } else if status.status != ExecutionStatus::SubmissionPending
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(Json(status));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[tool(
        name = "wallet_get_legal",
        description = "Read the legal acceptance status, and optionally the complete text of the Terms of Service, Privacy Policy, or Third-Party Licenses. Acceptance is an owner-only operation in the native wallet application; every other wallet tool fails until the user has accepted the current terms and privacy policy there.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn wallet_get_legal(
        &self,
        Parameters(input): Parameters<LegalInput>,
    ) -> Result<Json<LegalOutput>, ErrorData> {
        let status = self
            .legal
            .lock()
            .map_err(|_| ErrorData::internal_error("legal state lock was poisoned", None))?
            .status()
            .map_err(|error| tool_error(&error))?;
        let instruction = if status.signing_allowed {
            "The current Terms of Service and Privacy Policy are accepted; the wallet tools are available.".into()
        } else {
            "Every wallet tool except this one is disabled until the user accepts the current Terms of Service and separately acknowledges the Privacy Policy. Offer to display each document (this tool returns their text), then tell the user to open Settings → Legal & Version and accept both documents. Never run that command for them and never claim acceptance on their behalf.".to_string()
        };
        Ok(Json(LegalOutput {
            status,
            document: input.document.map(|document| LegalDocumentOutput {
                document,
                title: document.title().into(),
                digest: document.digest(),
                text: document.text(),
            }),
            instruction,
        }))
    }

    #[tool(
        name = "wallet_install_automation",
        description = "Install EVM bytecode the wallet polls on a cron schedule, whose returned calls go through the ordinary signing policy. No user approval is needed to install one: an automation only suggests transactions, and the policy decides whether any of them may send. IMPORTANT: unless the active policy already allows every call the bytecode emits to send automatically, the automation stops on its first tick and reports why — so dry-run it with wallet_dry_run_automation first, and propose a policy with wallet_propose_policy if the batch is not allowed. Read wallet://skills/write-ekubo-automation/SKILL.md before writing bytecode. Installing with an automation_key that already exists replaces that automation, so retrying this call is safe.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn wallet_install_automation(
        &self,
        Parameters(input): Parameters<InstallAutomationInput>,
    ) -> Result<Json<InstallAutomationOutput>, ErrorData> {
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let bytecode = parse_hex_bytes(&input.bytecode, "bytecode")?;
        let config_bytes = match &input.config {
            None => alloy::primitives::Bytes::new(),
            Some(value) => parse_hex_bytes(value, "config")?,
        };
        let schedule = CronSchedule::parse(&input.cron)
            .map_err(|error| ErrorData::invalid_params(format!("{error:#}"), None))?;
        let definition = AutomationDefinition::new(
            &input.name,
            bytecode,
            config_bytes,
            schedule.clone(),
            network.chain_id,
        )
        .map_err(|error| ErrorData::invalid_params(format!("{error:#}"), None))?;

        // The caller states the revision it wrote this for, and it has to be
        // the live one. Binding to whatever happens to be current instead would
        // silently attach the automation to a policy the caller never read.
        let active = self
            .policies
            .lock()
            .map_err(|_| ErrorData::internal_error("policy database lock was poisoned", None))?
            .get_for_wallet(&wallet.id, wallet.instance_id, wallet.address)
            .map_err(|error| tool_error(&error))?
            .ok_or_else(|| {
                ErrorData::invalid_params(format!("wallet {} has no local policy", wallet.id), None)
            })?;
        if active.revision != input.policy_revision {
            return Err(ErrorData::invalid_params(
                format!(
                    "this automation names policy revision {} but the active revision is {}. Read                      wallet_get_policy again, confirm the policy still allows the calls this                      automation emits, and install it naming {}.",
                    input.policy_revision, active.revision, active.revision
                ),
                None,
            ));
        }

        let installed = self
            .automations
            .lock()
            .map_err(|_| ErrorData::internal_error("automation database lock was poisoned", None))?
            .install(&wallet, &input.automation_key, &definition, active.revision)
            .map_err(|error| tool_error(&error))?;
        self.events.publish(DomainEventKind::AutomationsChanged {
            wallet_id: wallet.id.clone(),
        });
        let automation = installed.automation;
        Ok(Json(InstallAutomationOutput {
            automation_id: automation.id,
            automation_key: automation.key.clone(),
            wallet_id: wallet.id.clone(),
            chain_id: input.chain_id.clone(),
            name: automation.name.clone(),
            bytecode_hash: format!("{:#x}", automation.bytecode_hash()),
            cron: automation.schedule.expression().to_owned(),
            policy_revision: automation.policy_revision,
            state: automation.state,
            replaced_existing: installed.replaced.is_some(),
            upcoming: schedule.preview(chrono::Utc::now(), 3),
            instruction: format!(
                "The automation is installed and will run on its schedule while the wallet is unlocked. It stops on its own if policy revision {} stops allowing its calls, if a batch reverts on chain, or after repeated failures; check wallet_list_automations for `stopped_reason` before assuming it is still running. Tell the user it exists and what it does.",
                automation.policy_revision
            ),
        }))
    }

    #[tool(
        name = "wallet_list_automations",
        description = "List this wallet's installed automations with their schedules, bound policy revision, state, and — for any that stopped — exactly why. Read this before reinstalling or debugging one: `stopped_reason` is the whole account of what went wrong, and an automation in `awaiting_relink` stopped because the signing policy changed rather than because anything is broken.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn wallet_list_automations(
        &self,
        Parameters(input): Parameters<ListAutomationsInput>,
    ) -> Result<Json<ListAutomationsOutput>, ErrorData> {
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let installed = self
            .automations
            .lock()
            .map_err(|_| ErrorData::internal_error("automation database lock was poisoned", None))?
            .list_for_wallet(wallet.instance_id)
            .map_err(|error| tool_error(&error))?;
        let now = chrono::Utc::now();
        let stopped = installed
            .iter()
            .filter(|automation| {
                automation.state != ekubo_wallet_core::automation::AutomationState::Enabled
            })
            .count();
        let automations = installed
            .into_iter()
            .map(|automation| AutomationSummary {
                next_fire_at: automation
                    .schedule
                    .next_after(automation.last_tick_at.unwrap_or(now)),
                automation_id: automation.id,
                automation_key: automation.key,
                name: automation.name,
                chain_id: automation.chain_id,
                cron: automation.schedule.expression().to_owned(),
                bytecode_hash: format!("{:#x}", alloy::primitives::keccak256(&automation.bytecode)),
                policy_revision: automation.policy_revision,
                state: automation.state,
                stopped_reason: automation.stopped_reason,
                consecutive_failures: automation.consecutive_failures,
                last_tick_at: automation.last_tick_at,
                last_outcome: automation.last_outcome,
                last_request_id: automation.last_request_id,
            })
            .collect::<Vec<_>>();
        Ok(Json(ListAutomationsOutput {
            instruction: if stopped == 0 {
                "Every automation on this wallet is running.".into()
            } else {
                format!(
                    "{stopped} automation(s) have stopped. Read each `stopped_reason`: one in `awaiting_relink` needs the user to review it again in the Automations tab because the signing policy changed, and one in `disabled` failed — fix the bytecode or the policy and install again under the same automation_key."
                )
            },
            automations,
        }))
    }

    #[tool(
        name = "wallet_disable_automation",
        description = "Stop one of this wallet's automations and record why. Reducing what the wallet does automatically, so no approval is needed; re-enabling is not something this tool can do, and reinstalling with wallet_install_automation under the same automation_key is how an automation starts again.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn wallet_disable_automation(
        &self,
        Parameters(input): Parameters<DisableAutomationInput>,
    ) -> Result<Json<AutomationSummary>, ErrorData> {
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let mut automations = self.automations.lock().map_err(|_| {
            ErrorData::internal_error("automation database lock was poisoned", None)
        })?;
        let existing = automations
            .by_key(wallet.instance_id, input.automation_key.trim())
            .map_err(|error| tool_error(&error))?
            .ok_or_else(|| {
                ErrorData::invalid_params(
                    format!(
                        "wallet {} has no automation with key {:?}",
                        wallet.id, input.automation_key
                    ),
                    None,
                )
            })?;
        let stopped = automations
            .disable(existing.id, &input.reason)
            .map_err(|error| tool_error(&error))?;
        drop(automations);
        self.events.publish(DomainEventKind::AutomationsChanged {
            wallet_id: wallet.id.clone(),
        });
        Ok(Json(AutomationSummary {
            next_fire_at: None,
            automation_id: stopped.id,
            automation_key: stopped.key,
            name: stopped.name,
            chain_id: stopped.chain_id,
            cron: stopped.schedule.expression().to_owned(),
            bytecode_hash: format!("{:#x}", alloy::primitives::keccak256(&stopped.bytecode)),
            policy_revision: stopped.policy_revision,
            state: stopped.state,
            stopped_reason: stopped.stopped_reason,
            consecutive_failures: stopped.consecutive_failures,
            last_tick_at: stopped.last_tick_at,
            last_outcome: stopped.last_outcome,
            last_request_id: stopped.last_request_id,
        }))
    }

    #[tool(
        name = "wallet_dry_run_automation",
        description = "Run automation bytecode once against live chain state without installing, scheduling, signing, or storing anything, and report exactly what it would do: the calls it returned, the full simulation of the batch those calls become, the policy findings that decide whether that batch could send automatically, and — on failure — the revert selector, decoded Error/Panic, and raw bytes. This is the compile-test-fix loop for writing an automation; read wallet://skills/write-ekubo-automation/SKILL.md first for the interface, the storage and delegation rules, and worked examples. Supply `cron` to validate a schedule and see when it would fire.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_dry_run_automation(
        &self,
        Parameters(input): Parameters<DryRunAutomationInput>,
    ) -> Result<Json<DryRunAutomationOutput>, ErrorData> {
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let bytecode = parse_hex_bytes(&input.bytecode, "bytecode")?;
        let config_bytes = match &input.config {
            None => alloy::primitives::Bytes::new(),
            Some(value) => parse_hex_bytes(value, "config")?,
        };
        // Validated through the same constructor an install uses, so a dry run
        // cannot succeed on bytecode the install would refuse.
        let schedule = match &input.cron {
            None => CronSchedule::parse("0 0 * * * *").map_err(|error| tool_error(&error))?,
            Some(expression) => CronSchedule::parse(expression)
                .map_err(|error| ErrorData::invalid_params(format!("{error:#}"), None))?,
        };
        let definition = AutomationDefinition::new(
            "dry run",
            bytecode.clone(),
            config_bytes.clone(),
            schedule.clone(),
            network.chain_id,
        )
        .map_err(|error| ErrorData::invalid_params(format!("{error:#}"), None))?;
        let upcoming = input
            .cron
            .as_ref()
            .map(|_| schedule.preview(chrono::Utc::now(), 3))
            .unwrap_or_default();

        // Failover across endpoints, exactly as a scheduled tick does. Without
        // it one flaky endpoint reports to the agent as "your bytecode failed",
        // and the compile-test-fix loop this tool exists for starts chasing a
        // bug that is not in the bytecode. Only an RPC failure moves on: a
        // revert or an undecodable return is a fact about the blob, and the
        // next endpoint returns it again more slowly.
        let clients = ekubo_wallet_core::rpc::clients_for(&network)
            .await
            .map_err(|error| tool_error(&error))?;
        let mut last = None;
        let mut remaining = clients.len();
        for client in clients {
            remaining -= 1;
            let attempt = ekubo_wallet_core::automation::poll(
                client.as_ref(),
                wallet.address,
                definition.bytecode(),
                definition.config(),
            )
            .await
            .map_err(|error| tool_error(&error))?;
            let retryable = matches!(attempt, Err(PollFailure::Rpc(_))) && remaining > 0;
            last = Some(attempt);
            if !retryable {
                break;
            }
        }
        let outcome =
            last.ok_or_else(|| tool_error(&anyhow::anyhow!("network has no RPC endpoints")))?;

        let mut output = DryRunAutomationOutput {
            wallet_id: wallet.id.clone(),
            chain_id: input.chain_id.clone(),
            bytecode_hash: format!("{:#x}", definition.bytecode_hash()),
            bytecode_bytes: bytecode.len(),
            block_number: None,
            poll_gas_used: None,
            calls: Vec::new(),
            simulation: None,
            failure: None,
            upcoming,
            instruction: String::new(),
        };

        let polled = match outcome {
            Err(failure) => {
                output.failure = Some(describe_poll_failure(&failure));
                output.instruction = "The automation did not produce calls. Fix the bytecode and dry-run it again; nothing was installed or signed.".into();
                return Ok(Json(output));
            }
            Ok(polled) => polled,
        };
        output.block_number = Some(polled.block_number);
        output.poll_gas_used = Some(polled.gas_used);
        output.calls = polled
            .calls
            .iter()
            .map(|call| DryRunCall {
                to: format!("{:#x}", call.to),
                value: call.value.to_string(),
                data: format!("0x{}", hex::encode(&call.data)),
            })
            .collect();
        if polled.calls.is_empty() {
            output.instruction = "The automation ran and asked for nothing, which is a healthy idle tick. Change the chain state it reads, or its config, to exercise the branch that emits calls.".into();
            return Ok(Json(output));
        }

        let plan = ekubo_wallet_core::automation::synthesize_plan(
            wallet.address,
            network.chain_id,
            &polled.calls,
        )
        .map_err(|error| tool_error(&error))?;
        let stored_policy = self
            .policies
            .lock()
            .map_err(|_| ErrorData::internal_error("policy database lock was poisoned", None))?
            .get_for_wallet(&wallet.id, wallet.instance_id, wallet.address)
            .map_err(|error| tool_error(&error))?
            .ok_or_else(|| {
                ErrorData::invalid_params(format!("wallet {} has no local policy", wallet.id), None)
            })?;
        let policy_context = Self::policy_context(&wallet);
        let simulation = simulate_external_execution(
            &wallet,
            &network,
            &plan,
            &stored_policy,
            &policy_context,
            None,
        )
        .await
        .map_err(|error| tool_error(&error))?;
        output.instruction = if simulation.allowed {
            format!(
                "This batch of {} call(s) would send automatically under policy revision {}. Propose the automation for the user to install; nothing here was installed or signed.",
                polled.calls.len(),
                stored_policy.revision
            )
        } else {
            format!(
                "Policy revision {} would NOT allow this batch, so an installed automation emitting it would stop on its first tick. Read policy_findings to see which call, then either change the bytecode or propose a policy that permits it.",
                stored_policy.revision
            )
        };
        output.simulation = Some(simulation);
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_propose_policy",
        description = "Propose a complete replacement signing policy for human review — the way to adapt permissions to planned actions (automatic token spends to certain recipients, approvals to certain spenders, native value limits). Read wallet://docs/policy-authoring and wallet://schemas/policy first, and base the proposal on the exact document from wallet_get_policy: source_revision must be the active revision. One proposal exists per wallet; a newer proposal replaces it. The user reviews a minimized permission diff plus your rationale in the native wallet application and applies it there; this tool can never change the active policy.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    fn wallet_propose_policy(
        &self,
        Parameters(input): Parameters<ProposePolicyInput>,
    ) -> Result<Json<ProposePolicyOutput>, ErrorData> {
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let proposed = WalletPolicy::parse(input.policy).map_err(|error| {
            ErrorData::invalid_params(
                format!(
                    "the proposed document is not a valid policy: {error:#}. Read \
                         wallet://schemas/policy and wallet://docs/policy-authoring, then propose \
                         again."
                ),
                None,
            )
        })?;
        let mut policies = self
            .policies
            .lock()
            .map_err(|_| ErrorData::internal_error("policy database lock was poisoned", None))?;
        let current = policies
            .get_for_wallet(&wallet.id, wallet.instance_id, wallet.address)
            .map_err(|error| tool_error(&error))?
            .ok_or_else(|| {
                ErrorData::invalid_params(format!("wallet {} has no local policy", wallet.id), None)
            })?;
        let replaced_previous_proposal = policies
            .proposal_for_instance(wallet.instance_id)
            .map_err(|error| tool_error(&error))?
            .is_some();
        let proposal = policies
            .put_proposal_for_wallet(
                &wallet.id,
                wallet.instance_id,
                wallet.address,
                input.source_revision,
                &proposed,
                &input.rationale,
            )
            .map_err(|error| tool_error(&error))?;
        drop(policies);
        self.with_attribution(|desktop, client_id| {
            desktop.attribute_policy_proposal(&wallet.id, client_id)
        })
        .map_err(|error| tool_error(&error))?;
        self.events.publish(DomainEventKind::PolicyProposalChanged {
            wallet_id: wallet.id.clone(),
        });
        let diff = crate::core::policy::diff_policies(&current.policy, &proposal.policy);
        Ok(Json(ProposePolicyOutput {
            wallet_id: proposal.wallet_id.clone(),
            source_revision: proposal.source_revision,
            created_at: proposal.created_at,
            diff,
            rationale: proposal.rationale,
            replaced_previous_proposal,
            instruction: format!(
                "The proposal is stored. Tell the user to open policy proposal {} in the Policies screen to see the permission diff and your rationale, then approve or reject it there (never run that command for them and never claim it was applied). Confirm the outcome by reading wallet_get_policy: the revision advances past {} when the user applies the proposal. Any policy change by the user invalidates this proposal.",
                proposal.wallet_id, proposal.source_revision
            ),
        }))
    }

    #[tool(
        name = "wallet_sign_typed_data",
        description = "Queue an exact EIP-712 typed-data payload for explicit human approval through the native wallet application, which is the only way it can be signed: no policy is consulted, and there is no automatic path for any payload, including recognized permits. The domain must pin a configured chainId. Recognized permits (ERC-2612 Permit and canonical Permit2) are decoded into the token approvals they grant and shown to the user and returned to you, as review information only. Wait on the queued request with wallet_wait_for_typed_data.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    fn wallet_sign_typed_data(
        &self,
        Parameters(input): Parameters<SignTypedDataInput>,
    ) -> Result<Json<TypedDataOutput>, ErrorData> {
        self.require_legal_acceptance()
            .map_err(|error| tool_error(&error))?;
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        self.require_provisioned_wallet(&wallet.id)
            .map_err(|error| tool_error(&error))?;
        let (typed, chain_id, digest) =
            parse_typed_data(&input.typed_data).map_err(|error| tool_error(&error))?;
        self.config
            .network_by_chain_id(&chain_id.to_string())
            .map_err(|error| tool_error(&error))?;
        // Decoded for the human reviewing the request and for the caller's own
        // reporting. No policy is consulted: a policy that authorizes a permit
        // authorizes every permit shaped like it, and a spender holding one
        // signature below a limit can collect an unbounded number of them.
        // Only a person can see that pattern, so a person sees every payload.
        let permit_approvals = interpret_permit_approvals(&typed, wallet.address)
            .map_err(|error| tool_error(&error))?;

        let record = self
            .typed_data
            .lock()
            .map_err(|_| ErrorData::internal_error("typed-data database lock was poisoned", None))?
            .create_for_wallet(&wallet, chain_id, &input.typed_data, digest, None)
            .map_err(|error| tool_error(&error))?;
        self.with_attribution(|desktop, client_id| {
            desktop.attribute_typed_data(record.request_id, client_id)
        })
        .map_err(|error| tool_error(&error))?;
        self.publish_queued_signature(record.request_id, SignatureKind::TypedData);
        let mut output = typed_data_output(record);
        output.permit_approvals = permit_approvals;
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_wait_for_typed_data",
        description = "Wait for a pending typed-data request to be approved and signed or rejected through the native wallet review window, and read the signature once signed. This tool cannot approve, reject, or sign.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn wallet_wait_for_typed_data(
        &self,
        Parameters(input): Parameters<TypedDataWaitInput>,
    ) -> Result<Json<TypedDataOutput>, ErrorData> {
        let (record, timed_out) = wait_for_decision(
            input.timeout_seconds,
            || {
                self.typed_data
                    .lock()
                    .map_err(|_| {
                        ErrorData::internal_error("typed-data database lock was poisoned", None)
                    })?
                    .get(input.request_id)
                    .map_err(|error| tool_error(&error))
            },
            |record| record.status == TypedDataStatus::AwaitingApproval,
        )
        .await?;
        let mut output = typed_data_output(record);
        if timed_out {
            output.instruction = Some(still_awaiting_instruction(
                "wallet_wait_for_typed_data",
                output.request_id,
            ));
        }
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_sign_message",
        description = "Sign an exact EIP-191 `personal_sign` message — dapp logins (ERC-4361 Sign-In with Ethereum), address-ownership proofs, and off-chain attestations. Every message queues for explicit human approval through the native wallet application: no policy can evaluate what a message signature authorizes, so there is no automatic path. Pass exactly one of message_text and message_hex. Legacy raw eth_sign over a bare 32-byte digest is refused; use wallet_sign_typed_data for EIP-712. Wait on the queued request with wallet_wait_for_message.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    fn wallet_sign_message(
        &self,
        Parameters(input): Parameters<SignMessageInput>,
    ) -> Result<Json<MessageOutput>, ErrorData> {
        self.require_legal_acceptance()
            .map_err(|error| tool_error(&error))?;
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        self.require_provisioned_wallet(&wallet.id)
            .map_err(|error| tool_error(&error))?;
        let (message, encoding) =
            parse_message_input(input.message_text.as_deref(), input.message_hex.as_deref())
                .map_err(|error| tool_error(&error))?;
        if let Some(chain_id) = &input.chain_id {
            self.config
                .network_by_chain_id(chain_id)
                .map_err(|error| tool_error(&error))?;
        }

        // A login naming a different account is refused before a request ever
        // exists, exactly as a permit whose owner is not the signing wallet
        // is: that signature is useless to the address it names and can only
        // be a mistake or a trick.
        if let Some(siwe) = std::str::from_utf8(&message).ok().and_then(parse_siwe)
            && siwe.address != wallet.address.to_checksum(None)
        {
            return Err(tool_error(&anyhow::anyhow!(
                "this sign-in message names account {}, but wallet {} is {}",
                siwe.address,
                wallet.id,
                wallet.address.to_checksum(None)
            )));
        }

        let record = self
            .messages
            .lock()
            .map_err(|_| ErrorData::internal_error("message database lock was poisoned", None))?
            .create_for_wallet(&wallet, input.chain_id.as_deref(), &message, encoding, None)
            .map_err(|error| tool_error(&error))?;
        self.with_attribution(|desktop, client_id| {
            desktop.attribute_message(record.request_id, client_id)
        })
        .map_err(|error| tool_error(&error))?;
        // After attribution, so the row the owner is sent to already names the
        // agent that asked rather than filling that in a moment later.
        self.publish_queued_signature(record.request_id, SignatureKind::Message);
        Ok(Json(
            message_output(record, &self.config).map_err(|error| tool_error(&error))?,
        ))
    }

    #[tool(
        name = "wallet_wait_for_message",
        description = "Wait for a pending EIP-191 message request to be approved and signed or rejected through the native wallet review window, and read the signature once signed. This tool cannot approve, reject, or sign.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn wallet_wait_for_message(
        &self,
        Parameters(input): Parameters<MessageWaitInput>,
    ) -> Result<Json<MessageOutput>, ErrorData> {
        let (record, timed_out) = wait_for_decision(
            input.timeout_seconds,
            || {
                self.messages
                    .lock()
                    .map_err(|_| {
                        ErrorData::internal_error("message database lock was poisoned", None)
                    })?
                    .get(input.request_id)
                    .map_err(|error| tool_error(&error))
            },
            |record| record.status == MessageStatus::AwaitingApproval,
        )
        .await?;
        let mut output =
            message_output(record, &self.config).map_err(|error| tool_error(&error))?;
        if timed_out {
            output.instruction = Some(still_awaiting_instruction(
                "wallet_wait_for_message",
                output.request_id,
            ));
        }
        Ok(Json(output))
    }
}

impl WalletMcpServer {
    /// Resolve a live fork for a read or a simulation.
    ///
    /// A fork is bound to the wallet and chain it was opened for, so it can
    /// never be used to answer a question about a different one. Expiry is
    /// enforced by the store, so an expired fork reads as unknown.
    fn fork_session(
        &self,
        fork_id: Option<uuid::Uuid>,
        chain_id: &str,
        wallet_id: Option<&str>,
    ) -> Result<Option<ForkSession>, ErrorData> {
        let Some(fork_id) = fork_id else {
            return Ok(None);
        };
        let session = self
            .forks
            .lock()
            .map_err(|_| ErrorData::internal_error("fork registry lock was poisoned", None))?
            .session(fork_id, Utc::now());
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                self.release_global_fork(fork_id);
                return Err(tool_error(&error));
            }
        };
        ensure_tool(
            session.chain_id.to_string() == chain_id,
            "fork was opened for a different chain",
        )?;
        if let Some(wallet_id) = wallet_id {
            let wallet = self
                .config
                .wallet(wallet_id)
                .map_err(|error| tool_error(&error))?;
            ensure_tool(
                session.wallet_instance_id == wallet.instance_id
                    && session.wallet_id == wallet_id
                    && session.wallet_address == wallet.address,
                "fork was opened for a different wallet",
            )?;
        }
        Ok(Some(session))
    }

    /// Resolve the exactly-one-of `wallet_id`/`address` pair used by read tools.
    fn resolve_read_address(
        &self,
        wallet_id: Option<&str>,
        address: Option<&str>,
    ) -> Result<Address, ErrorData> {
        match (wallet_id, address) {
            (Some(wallet_id), None) => Ok(self
                .config
                .wallet(wallet_id)
                .map_err(|error| tool_error(&error))?
                .address),
            (None, Some(address)) => Address::from_str(address).map_err(|_| {
                ErrorData::invalid_params("address must be a 20-byte EVM address", None)
            }),
            _ => Err(ErrorData::invalid_params(
                "provide exactly one of wallet_id or address",
                None,
            )),
        }
    }

    fn active_policy(
        &self,
        wallet: &crate::config::WalletMetadata,
    ) -> Result<crate::policy_store::StoredPolicy> {
        self.policies
            .lock()
            .map_err(|_| anyhow::anyhow!("policy database lock was poisoned"))?
            .get_for_wallet(&wallet.id, wallet.instance_id, wallet.address)?
            .with_context(|| format!("wallet {} has no local policy", wallet.id))
    }

    /// Everything a policy may consult beyond the plan itself: the wallet the
    /// plan is being signed for, and nothing else. Token names are display
    /// metadata for a person and never decide whether a plan may be signed.
    fn policy_context(
        wallet: &crate::config::WalletMetadata,
    ) -> crate::core::predicate::PolicyContext {
        crate::core::predicate::PolicyContext {
            wallet: wallet.address,
        }
    }

    fn pending_record_by_id(&self, request_id: uuid::Uuid) -> Result<PendingTransaction> {
        let record = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .get(request_id)?;
        let wallet = self.config.wallet(&record.wallet_id)?;
        self.config
            .network_for_record(&record.chain_id, &record.network_name)?;
        ensure!(
            record.wallet_instance_id == wallet.instance_id
                && record.execution_plan.sender == wallet.address,
            "pending request sender no longer matches the configured wallet"
        );
        Ok(record)
    }

    fn pending_record(
        &self,
        wallet_id: &str,
        chain_id: &str,
        request_id: uuid::Uuid,
    ) -> Result<PendingTransaction> {
        let wallet = self.config.wallet(wallet_id)?;
        let record = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .get(request_id)?;
        self.config
            .network_for_record(chain_id, &record.network_name)?;
        ensure!(
            record.wallet_id == wallet_id && record.wallet_instance_id == wallet.instance_id,
            "pending request wallet mismatch"
        );
        ensure!(
            record.chain_id == chain_id,
            "pending request chain mismatch"
        );
        ensure!(
            record.execution_plan.sender == wallet.address,
            "pending request sender no longer matches the configured wallet"
        );
        Ok(record)
    }

    async fn send_new_plan(
        &self,
        wallet: WalletMetadata,
        network: NetworkConfig,
        plan: ExecutionPlan,
        plan_source: Option<String>,
        on_simulation_failure: OnSimulationFailure,
    ) -> Result<ExecutionStatusOutput> {
        self.require_legal_acceptance()?;
        let stored_policy = self.active_policy(&wallet)?;
        // Only what has to hold before the RPC is asked to execute anything.
        // The sender, chain, and digest are checked against this wallet and
        // network below, on the path both kinds of send share.
        plan.validate()?;
        let policy_context = Self::policy_context(&wallet);
        let simulation = simulate_external_execution(
            &wallet,
            &network,
            &plan,
            &stored_policy,
            &policy_context,
            None,
        )
        .await?;
        Box::pin(self.send_simulated_plan(
            wallet,
            network,
            plan,
            plan_source,
            simulation,
            on_simulation_failure,
        ))
        .await
    }

    /// Consume a recorded preview as a handle to its exact plan, then run the
    /// complete simulation, preparation, and policy pipeline again. Preview
    /// results are display state, never signing authority.
    async fn send_recorded_simulation(
        &self,
        wallet: WalletMetadata,
        network: NetworkConfig,
        simulation_id: uuid::Uuid,
        on_simulation_failure: OnSimulationFailure,
    ) -> Result<ExecutionStatusOutput> {
        self.require_legal_acceptance()?;
        let recorded = self
            .simulations
            .lock()
            .map_err(|_| anyhow::anyhow!("simulation registry lock was poisoned"))?
            .take(simulation_id, Utc::now())?;
        self.release_global_simulation(simulation_id);
        ensure!(
            recorded.wallet_instance_id == wallet.instance_id && recorded.wallet_id == wallet.id,
            "simulation {simulation_id} was recorded for wallet {}, not {}",
            recorded.wallet_id,
            wallet.id
        );
        ensure!(
            recorded.chain_id == network.chain_id.to_string(),
            "simulation {simulation_id} was recorded on chain {}, not {}",
            recorded.chain_id,
            network.chain_id
        );
        Box::pin(self.send_new_plan(
            wallet,
            network,
            recorded.plan,
            recorded.plan_source,
            on_simulation_failure,
        ))
        .await
    }

    /// Finish a freshly simulated send. Core re-reads the active policy before
    /// any key use; this result supplies preview and prepared-envelope state,
    /// not authority.
    #[allow(clippy::too_many_arguments)]
    async fn send_simulated_plan(
        &self,
        wallet: WalletMetadata,
        network: NetworkConfig,
        plan: ExecutionPlan,
        plan_source: Option<String>,
        mut simulation: SimulationResult,
        on_simulation_failure: OnSimulationFailure,
    ) -> Result<ExecutionStatusOutput> {
        crate::orchestrator::validate_send(&wallet, &network, &plan, &simulation)?;
        // Whatever identifier this result carried is spent now.
        simulation.simulation_id = None;

        // A caller that asked to hear about a failed simulation hears about
        // it, and nothing is written: no pending row, no expiry to wait out,
        // no review prompt for a plan that does not execute. A plan no policy
        // rule covers is deliberately not covered here — whether to allow it
        // once is exactly the decision only the user can make, so it still
        // queues below. A plan a `deny` rule matched never gets that far: it
        // fails outright in `execute_automatic`, whatever was passed here.
        if !simulation.simulation.success && on_simulation_failure == OnSimulationFailure::Fail {
            // Attributed, because this sentence was written by whoever produced
            // the plan and travels outside the plan digest. It is advice about
            // that producer's own protocol, not a finding of this wallet's, and
            // an agent reading it should weigh it accordingly. It grants
            // nothing either way: every action it might suggest still passes
            // policy and, where required, human approval.
            let guidance = simulation.simulation.failure.as_ref().map_or_else(
                || {
                    "Simulation failed; obtain guidance from the plan producer before continuing."
                        .to_owned()
                },
                |failure| format!("The plan producer's guidance: {}", failure.instruction),
            );
            bail!(
                "simulation failed and on_simulation_failure is \"fail\", so nothing was queued or \
                 signed. {guidance} Call wallet_simulate_execution_plan with this plan for the \
                 full failure detail, or resend with on_simulation_failure \"request_approval\" to \
                 let the user override it."
            );
        }

        let disposition = self
            .execution_authority
            .execute(
                &self.config,
                &self.pending,
                &wallet,
                &network,
                &plan,
                plan_source.as_deref(),
                &simulation,
            )
            .await?;
        if let crate::orchestrator::SendDisposition::Queued(request) = disposition {
            self.with_attribution(|desktop, client_id| {
                desktop.attribute_transaction(request.request_id, client_id)
            })?;
            let mut output = execution_status_output(request);
            output.instruction = Some(if simulation.simulation.success {
                format!(
                    "The plan needs explicit human approval before it can sign. Tell the user to open review {} in the wallet application (never attempt to approve it on their behalf), then immediately call wallet_wait_for_approval with this request_id and keep calling it after each timeout until the request is approved, rejected, or expired. On approved, submit with wallet_send_execution_plan and this request_id. Do not ask the user to report the approval in chat.",
                    output.request_id
                )
            } else {
                // Attributed for the same reason as above: producer-authored
                // text, outside the digest, advisory only.
                let guidance = simulation.simulation.failure.as_ref().map_or_else(
                    || {
                        "Simulation failed; obtain guidance from the plan producer before \
                        continuing."
                            .to_owned()
                    },
                    |failure| format!("The plan producer's guidance: {}", failure.instruction),
                );
                format!(
                    "{guidance} If the user instead explicitly chooses to override the failed simulation, they can open review {} in the wallet application (never attempt to approve it on their behalf); in that case call wallet_wait_for_approval with this request_id until it resolves.",
                    output.request_id
                )
            });
            output.simulation = Some(simulation);
            return Ok(output);
        }
        let crate::orchestrator::SendDisposition::Signed(record) = disposition else {
            unreachable!("queued disposition returned above");
        };
        self.with_attribution(|desktop, client_id| {
            desktop.attribute_transaction(record.request_id, client_id)
        })?;
        self.submit_signed_record(&wallet, &network, record, Some(simulation))
            .await
    }

    async fn send_existing_request(
        &self,
        wallet: WalletMetadata,
        network: NetworkConfig,
        request_id: uuid::Uuid,
    ) -> Result<ExecutionStatusOutput> {
        let record = self.pending_record(&wallet.id, &network.chain_id.to_string(), request_id)?;
        let record = self.reconcile_record(&network, record, true).await?;
        match record.status {
            PendingStatus::Signed => {
                self.submit_signed_record(&wallet, &network, record, None)
                    .await
            }
            PendingStatus::Broadcast => {
                let hash = record
                    .signed_transaction_hash
                    .as_deref()
                    .context("broadcast transaction is missing its signed hash")?;
                if transaction_known(&network, hash).await? {
                    return Ok(execution_status_output(record));
                }
                let claimed = self
                    .pending
                    .lock()
                    .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                    .claim_broadcast_retry(request_id)?;
                self.broadcast_claimed(&wallet, &network, claimed, None)
                    .await
            }
            _ => Ok(execution_status_output(record)),
        }
    }

    async fn submit_signed_record(
        &self,
        wallet: &WalletMetadata,
        network: &NetworkConfig,
        record: PendingTransaction,
        simulation: Option<SimulationResult>,
    ) -> Result<ExecutionStatusOutput> {
        ensure!(
            record.status == PendingStatus::Signed,
            "pending transaction is not ready for submission"
        );
        let request_id = record.request_id;
        let claim_result = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?;
            pending.claim_for_submission(request_id)
        };
        let claimed = match claim_result {
            Ok(claimed) => claimed,
            Err(error) => {
                let current = self
                    .pending
                    .lock()
                    .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                    .get(request_id)?;
                if current.status == PendingStatus::Cancelled {
                    return Ok(execution_status_output(current));
                }
                return Err(error);
            }
        };
        self.broadcast_claimed(wallet, network, claimed, simulation)
            .await
    }

    async fn broadcast_claimed(
        &self,
        wallet: &WalletMetadata,
        network: &NetworkConfig,
        claimed: PendingTransaction,
        simulation: Option<SimulationResult>,
    ) -> Result<ExecutionStatusOutput> {
        let (record, broadcast) =
            crate::reconcile::submit_claimed(&self.pending, wallet, network, claimed).await?;
        // The persisted record deliberately excludes transient RPC error text;
        // it retains only exact bytes, hashes, and lifecycle state.
        let mut output = execution_status_output(record);
        output.receipt_status = Some(broadcast.receipt_status);
        output.broadcast_error = broadcast.broadcast_error;
        output.simulation = simulation;
        Ok(output)
    }

    async fn reconcile_pending(&self, input: &RequestInput) -> Result<ExecutionStatusOutput> {
        let record = self.pending_record(
            input.wallet_id.as_str(),
            input.chain_id.as_str(),
            input.request_id,
        )?;
        let network = self.config.network_by_chain_id(&input.chain_id)?;
        Ok(execution_status_output(
            self.reconcile_record(&network, record, true).await?,
        ))
    }

    async fn reconcile_record(
        &self,
        network: &NetworkConfig,
        record: PendingTransaction,
        recover_stale_submission: bool,
    ) -> Result<PendingTransaction> {
        crate::reconcile::reconcile_record(&self.pending, network, record, recover_stale_submission)
            .await
    }
}

const SECURITY_RESOURCE_URI: &str = "wallet://docs/security-model";
const POLICY_AUTHORING_RESOURCE_URI: &str = "wallet://docs/policy-authoring";
const POLICY_SCHEMA_RESOURCE_URI: &str = "wallet://schemas/policy";
const SKILL_RESOURCE_URI: &str = "wallet://skills/use-ekubo-wallet/SKILL.md";
const AUTOMATION_SKILL_RESOURCE_URI: &str = "wallet://skills/write-ekubo-automation/SKILL.md";
const TERMS_RESOURCE_URI: &str = "wallet://legal/terms-of-service";
const PRIVACY_RESOURCE_URI: &str = "wallet://legal/privacy-policy";
const LICENSES_RESOURCE_URI: &str = "wallet://legal/third-party-licenses";
// This server is a general-purpose local EVM wallet. It is deliberately not
// bound to any particular protocol, dapp, or companion MCP server: it accepts a
// signer-neutral execution plan from whatever produced it and applies the same
// validation, simulation, and policy rules to all of them.
//
// The instructions do point at one plan producer, because the wallet cannot
// build calldata and an agent asked to swap, provide liquidity, or chase yield
// with no such tool connected is otherwise stuck. That pointer is a
// capability hint, not a trust statement, and the wording says so explicitly:
// a plan from there is validated, simulated, and policy-checked exactly like a
// plan from anywhere else, and no code path anywhere in this process treats
// its origin as special.
const SERVER_INSTRUCTIONS: &str = include_str!("../docs/mcp-server-instructions.md");
const SECURITY_MODEL: &str = include_str!("../docs/mcp-security-model.md");
const EKUBO_WALLET_SKILL: &str = include_str!("../docs/skills/use-ekubo-wallet/SKILL.md");
const WRITE_AUTOMATION_SKILL: &str = include_str!("../docs/skills/write-ekubo-automation/SKILL.md");

const POLICY_AUTHORING_GUIDE: &str = include_str!("../docs/policy-authoring.md");

/// Hex in, bytes out, with an error that names the field rather than the codec.
fn parse_hex_bytes(value: &str, field: &str) -> Result<alloy::primitives::Bytes, ErrorData> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed)
        .map(alloy::primitives::Bytes::from)
        .map_err(|error| ErrorData::invalid_params(format!("{field} is not hex: {error}"), None))
}

/// Every byte a failed poll produced, in the shape an author debugs from.
///
/// Nothing here is summarized away. A terse category is what makes an agent
/// guess, and guessing at bytecode is what the dry run exists to replace.
fn describe_poll_failure(failure: &PollFailure) -> DryRunFailure {
    match failure {
        PollFailure::Rpc(message) => DryRunFailure {
            kind: "rpc_error".into(),
            message: message.clone(),
            revert_data: None,
            revert_selector: None,
            decoded_error: None,
            return_data: None,
        },
        PollFailure::Reverted {
            message,
            revert_data,
            revert_selector,
            decoded,
        } => DryRunFailure {
            kind: "reverted".into(),
            message: message.clone(),
            revert_data: Some(revert_data.clone()),
            revert_selector: revert_selector.clone(),
            decoded_error: decoded.clone(),
            return_data: None,
        },
        PollFailure::Undecodable {
            message,
            return_data,
        } => DryRunFailure {
            kind: "undecodable_return".into(),
            message: message.clone(),
            revert_data: None,
            revert_selector: None,
            decoded_error: None,
            return_data: Some(return_data.clone()),
        },
    }
}

fn wallet_resources() -> Vec<Resource> {
    vec![
        Resource::new(SKILL_RESOURCE_URI, "use-ekubo-wallet")
            .with_title("Use Ekubo Wallet")
            .with_description(
                "Reusable agent instructions for onchain work on enabled EVM networks and requests where ‘wallet’ may mean a crypto wallet.",
            )
            .with_mime_type("text/markdown"),
        Resource::new(AUTOMATION_SKILL_RESOURCE_URI, "write-ekubo-automation")
            .with_title("Write an Ekubo Automation")
            .with_description(
                "How to write, compile, and test the EVM bytecode the wallet polls on a cron schedule, with worked Solidity examples.",
            )
            .with_mime_type("text/markdown"),
        Resource::new(SECURITY_RESOURCE_URI, "security-model")
            .with_title("Wallet trust and security model")
            .with_description("The local signing, storage, approval, RPC, and retry boundary.")
            .with_mime_type("text/markdown"),
        Resource::new(POLICY_AUTHORING_RESOURCE_URI, "policy-authoring")
            .with_title("Authoring wallet policies")
            .with_description(
                "How policy documents work and how to propose minimal, reviewable changes.",
            )
            .with_mime_type("text/markdown"),
        Resource::new(POLICY_SCHEMA_RESOURCE_URI, "policy-schema")
            .with_title("Policy JSON Schema")
            .with_description("The exact schema wallet_propose_policy validates against.")
            .with_mime_type("application/json"),
        Resource::new(TERMS_RESOURCE_URI, "terms-of-service")
            .with_title("Terms of Service")
            .with_description(
                "Must be accepted via the native wallet review window before signing tools work.",
            )
            .with_mime_type("text/markdown"),
        Resource::new(PRIVACY_RESOURCE_URI, "privacy-policy")
            .with_title("Privacy Policy")
            .with_description(
                "Discloses the default RPC endpoints; must be acknowledged separately via the native wallet application.",
            )
            .with_mime_type("text/markdown"),
        Resource::new(LICENSES_RESOURCE_URI, "third-party-licenses")
            .with_title("Third-Party Licenses")
            .with_description("License attributions for every bundled dependency.")
            .with_mime_type("text/markdown"),
    ]
}

#[tool_handler(router = Self::sanitized_tool_router())]
impl ServerHandler for WalletMcpServer {
    /// Hand-written so every tool call passes the legal-acceptance gate. The
    /// privacy policy governs RPC requests and agent data exposure, so even
    /// read-only tools stay disabled until acceptance; only `wallet_get_legal`
    /// and `wallet_check_for_updates` are exempt.
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, ErrorData> {
        self.tool_gate(&request.name)?;
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        Self::sanitized_tool_router().call(tcc).await
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(
            Implementation::new("ekubo_wallet", crate::BUILD_VERSION)
                .with_title("Ekubo Wallet — Local EVM Execution"),
        )
        .with_instructions(SERVER_INSTRUCTIONS)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(wallet_resources()))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let contents = match request.uri.as_ref() {
            SKILL_RESOURCE_URI => EKUBO_WALLET_SKILL.to_string(),
            AUTOMATION_SKILL_RESOURCE_URI => WRITE_AUTOMATION_SKILL.to_string(),
            SECURITY_RESOURCE_URI => SECURITY_MODEL.to_string(),
            POLICY_AUTHORING_RESOURCE_URI => POLICY_AUTHORING_GUIDE.to_string(),
            POLICY_SCHEMA_RESOURCE_URI => {
                serde_json::to_string_pretty(&crate::core::policy::json_schema())
                    .map_err(|error| tool_error(&error))?
            }
            TERMS_RESOURCE_URI => LegalDocument::TermsOfService.text(),
            PRIVACY_RESOURCE_URI => LegalDocument::PrivacyPolicy.text(),
            LICENSES_RESOURCE_URI => LegalDocument::ThirdPartyLicenses.text(),
            _ => {
                return Err(ErrorData::resource_not_found(
                    "unknown wallet resource",
                    None,
                ));
            }
        };
        let mime_type = if request.uri == POLICY_SCHEMA_RESOURCE_URI {
            "application/json"
        } else {
            "text/markdown"
        };
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(contents, request.uri.clone()).with_mime_type(mime_type),
        ])
        .into())
    }
}

fn ensure_tool(condition: bool, message: &str) -> Result<(), ErrorData> {
    if condition {
        Ok(())
    } else {
        Err(ErrorData::invalid_params(message.to_string(), None))
    }
}

/// Polls one queued request until it leaves awaiting-approval or the timeout
/// lapses: the shared engine of the three wait tools. `fetch` reads the
/// record, `awaiting` says whether it is still queued. Returns the final
/// record and whether the wait timed out with the record still queued.
async fn wait_for_decision<R>(
    timeout_seconds: u8,
    mut fetch: impl FnMut() -> Result<R, ErrorData>,
    awaiting: impl Fn(&R) -> bool,
) -> Result<(R, bool), ErrorData> {
    validate_timeout_seconds(timeout_seconds).map_err(|error| tool_error(&error))?;
    // Refuse rather than queue: queueing more waits is the backlog this
    // prevents, and a caller told to retry has lost nothing — approval does
    // not expire, so the request it was waiting on is still there.
    let _slot = WAIT_SLOTS.try_acquire().map_err(|_| {
        ErrorData::invalid_request(
            format!(
                "this wallet is already polling {MAX_CONCURRENT_WAITS} approval waits; retry once one of them finishes"
            ),
            None,
        )
    })?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(u64::from(timeout_seconds));
    loop {
        let record = fetch()?;
        if !awaiting(&record) || tokio::time::Instant::now() >= deadline {
            let timed_out = awaiting(&record);
            return Ok((record, timed_out));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        // Tested here as well as above, so a wait whose sleep carried it past
        // the deadline does no further database work — one read per wait
        // re-parses a payload of up to MAX_TYPED_DATA_BYTES.
        if tokio::time::Instant::now() >= deadline {
            let record = fetch()?;
            let timed_out = awaiting(&record);
            return Ok((record, timed_out));
        }
    }
}

/// The instruction returned on a timed-out wait: approval never expires, so
/// the agent calls the same wait tool again rather than involving the chat.
fn still_awaiting_instruction(wait_tool: &str, request_id: impl std::fmt::Display) -> String {
    format!(
        "Still awaiting human approval, which does not expire. Call {wait_tool} again with \
         request_id {request_id}; do not ask the user to report approval in chat."
    )
}

/// The longest error this server hands back over MCP.
///
/// A tool error is read by a model and written into a transcript, and the text
/// it carries can be a whole RPC or plan-producer response body: alloy embeds
/// the complete body in its deserialization and HTTP error variants, and
/// nothing upstream caps it. Past a kilobyte there is no diagnosis left, only
/// an unbounded write into somebody else's context window.
const MAX_TOOL_ERROR_CHARS: usize = 1_024;

fn tool_error(error: &impl std::fmt::Display) -> ErrorData {
    // Stripped as well as capped: the text is untrusted — an RPC or a plan
    // producer chose it — and a transcript is something a person reads.
    //
    // The alternate flag, not `{error}`: an `anyhow::Error`'s plain `Display`
    // prints only the outermost `.context()`, dropping the underlying cause
    // (an `io::Error`'s "permission denied", say) that names what actually
    // went wrong. `{:#}` walks the whole chain, matching the convention
    // already used for user-facing errors elsewhere (tx_browser.rs,
    // connect.rs, cli.rs). Types that don't special-case the alternate flag —
    // `String`, the literals most tests pass here — render identically
    // either way.
    ErrorData::internal_error(
        crate::sanitize::stripped_capped(&format!("{error:#}"), MAX_TOOL_ERROR_CHARS),
        None,
    )
}

fn tool_input_error(error: &impl std::fmt::Display) -> ErrorData {
    ErrorData::invalid_params(
        crate::sanitize::stripped_capped(&format!("{error:#}"), MAX_TOOL_ERROR_CHARS),
        None,
    )
}

const fn default_true() -> bool {
    true
}

const fn default_wait_seconds() -> u8 {
    55
}

const fn default_confirmations() -> u16 {
    1
}

const fn default_network_finality_confirmations() -> u16 {
    ekubo_wallet_core::config::DEFAULT_FINALITY_CONFIRMATIONS
}

fn typed_data_output(record: PendingTypedData) -> TypedDataOutput {
    let instruction = match record.status {
        TypedDataStatus::AwaitingApproval => Some(format!(
            "Typed-data signing requires explicit human approval. Tell the user to open review {} in the wallet application (never attempt to approve it on their behalf), then call wallet_wait_for_typed_data with this request_id and keep calling it after each timeout until the request is signed, rejected, or expired. Do not ask the user to report the approval in chat.",
            record.request_id
        )),
        TypedDataStatus::Signed => Some(
            "The typed data is signed; signature holds the exact 65-byte r||s||v signature. Deliver it to whatever requested the signature.".into(),
        ),
        TypedDataStatus::Rejected => Some(
            "The user rejected this typed-data request. Do not recreate it unless they explicitly ask to sign again.".into(),
        ),
    };
    TypedDataOutput {
        request_id: record.request_id,
        wallet_id: record.wallet_id,
        chain_id: record.chain_id,
        digest: record.digest,
        status: record.status,
        approved_at: record.approved_at,
        rejected_at: record.rejected_at,
        signature: record.signature,
        permit_approvals: None,
        instruction,
    }
}

fn message_output(record: PendingMessage, config: &ConfigStore) -> Result<MessageOutput> {
    let instruction = match record.status {
        MessageStatus::AwaitingApproval => Some(format!(
            "Message signing requires explicit human approval. Tell the user to open review {} in the wallet application (never attempt to approve it on their behalf), then call wallet_wait_for_message with this request_id and keep calling it after each timeout until the request is signed, rejected, or expired. Do not ask the user to report the approval in chat.",
            record.request_id
        )),
        MessageStatus::Signed => Some(
            "The message is signed; signature holds the exact 65-byte r||s||v signature over the EIP-191 digest. Deliver it to whatever requested the signature.".into(),
        ),
        MessageStatus::Rejected => Some(
            "The user rejected this message request. Do not recreate it unless they explicitly ask to sign again.".into(),
        ),
    };
    let message = record.message_bytes()?;
    let mut display = describe_message(&message);
    let siwe = display.text.as_deref().and_then(parse_siwe);
    if let Some(siwe) = &siwe {
        display.warnings.extend(siwe_warnings(
            siwe,
            record.chain_id.as_deref(),
            config.network_by_chain_id(&siwe.chain_id).is_ok(),
            Utc::now(),
        ));
    } else {
        display.warnings.push(
            "This is not a recognized sign-in message. A message signature can authorize an \
             off-chain order, a delegation, or an account link; the user must read every byte."
                .into(),
        );
    }
    Ok(MessageOutput {
        request_id: record.request_id,
        wallet_id: record.wallet_id,
        chain_id: record.chain_id,
        message_hex: record.message_hex,
        digest: record.digest,
        status: record.status,
        display,
        siwe,
        approved_at: record.approved_at,
        rejected_at: record.rejected_at,
        signature: record.signature,
        instruction,
    })
}

/// What to do next when the policy did not allow a plan outright: the
/// instruction an agent gets alongside a sendable simulation with
/// `allowed=false`.
///
/// The two negative outcomes need opposite advice, which is why this takes the
/// outcome rather than assuming. Telling an agent to queue a plan the policy
/// rejects wastes the user's attention on a prompt that cannot help; telling it
/// to demand a policy change for a plan that merely matched no rule trains the
/// user to widen their policy for routine work. A deliberate review rule and
/// an unmatched call share the reviewable outcome.
fn policy_denial_next_step(
    outcome: crate::core::policy::PolicyOutcome,
    simulation_id: uuid::Uuid,
) -> String {
    match outcome {
        crate::core::policy::PolicyOutcome::Rejected => {
            "A deny rule in the active policy refuses this plan outright. There is no approval \
             that can override it: do not queue it, and do not call wallet_send_execution_plan. \
             Report the denial to the user and let them decide whether to change the policy, \
             which is a separate explicit owner action in the wallet application."
                .to_string()
        }
        _ => format!(
            "This plan requires human review because a review rule matched or no policy rule \
             covered a call; it is not a dead end. Call wallet_send_execution_plan with simulation_id {simulation_id}; \
             the wallet will freshly simulate, prepare, and evaluate policy before queuing the \
             resulting exact transaction, then follow the returned instruction \
             through wallet_wait_for_approval. Do not stop to report the findings as a blocker, \
             and do not ask the user to change their policy before this action can proceed."
        ),
    }
}

fn execution_status_output(record: PendingTransaction) -> ExecutionStatusOutput {
    let status = match record.status {
        PendingStatus::AwaitingApproval => ExecutionStatus::ApprovalRequired,
        PendingStatus::Rejected => ExecutionStatus::Rejected,
        PendingStatus::Signed => ExecutionStatus::Approved,
        PendingStatus::Submitting | PendingStatus::Broadcast => ExecutionStatus::SubmissionPending,
        PendingStatus::Confirmed => ExecutionStatus::Submitted,
        PendingStatus::Reverted => ExecutionStatus::Reverted,
        PendingStatus::Cancelled => ExecutionStatus::Cancelled,
        PendingStatus::Replaced => ExecutionStatus::Replaced,
        PendingStatus::Cancelling => ExecutionStatus::CancellationPending,
    };
    let receipt_status = match record.status {
        PendingStatus::Submitting | PendingStatus::Broadcast | PendingStatus::Cancelling => {
            Some(ReceiptStatus::Pending)
        }
        PendingStatus::Confirmed => Some(ReceiptStatus::Success),
        PendingStatus::Reverted => Some(ReceiptStatus::Reverted),
        _ => None,
    };
    let instruction = match status {
        ExecutionStatus::ApprovalRequired => Some(format!(
            "Awaiting human approval. Tell the user to open review {} in the wallet application (never attempt to approve it on their behalf), then call wallet_wait_for_approval with this request_id, repeating after each timeout, until it resolves. Approval is a step in the work, not the end of it: do not stop here holding an unresolved request, and do not ask the user to report their decision in chat.",
            record.request_id
        )),
        ExecutionStatus::TimedOut => Some(
            "Still awaiting separate human approval; wait again without asking the user to report approval in chat."
                .into(),
        ),
        ExecutionStatus::Approved => Some(format!(
            "The exact transaction is locally signed. Submit it by calling wallet_send_execution_plan with request_id {}, wallet_id {}, and chain_id {}.",
            record.request_id, record.wallet_id, record.chain_id
        )),
        ExecutionStatus::SubmissionPending => Some(
            "The exact signed transaction may be in flight. Reconcile with wallet_get_execution_status or wallet_wait_for_execution; retries use only the persisted signed bytes.".into(),
        ),
        ExecutionStatus::Rejected => Some(
            "The user rejected this request. Do not recreate it unless they explicitly request a new transaction.".into(),
        ),
        ExecutionStatus::Cancelled if record.settlement_transaction_hash.is_some()
            && record.finalized_at.is_none() => Some(
            "A cancellation receipt was observed but is not final yet. The wallet is revalidating it and will not sign another transaction for this wallet and chain until finality.".into(),
        ),
        ExecutionStatus::Cancelled => Some(if record.cancel_transaction_hashes.is_empty() {
            "The signed request was cancelled because its policy revision changed before initial submission.".into()
        } else {
            "This wallet's own cancellation transaction consumed the nonce on chain: the original plan will never execute. Prepare a fresh plan only if the user still wants the action.".into()
        }),
        ExecutionStatus::CancellationPending => Some(
            "A cancellation transaction is racing the original at the same nonce. Reconcile with wallet_get_execution_status or wallet_wait_for_execution until the chain settles which one mined.".into(),
        ),
        ExecutionStatus::Replaced => Some(
            "The signed transaction's nonce was consumed by a different mined transaction (for example one sent from the same key on another device), so these exact bytes can never mine and nothing was executed. Prepare a fresh plan only if the user still wants the action.".into(),
        ),
        ExecutionStatus::Submitted | ExecutionStatus::Reverted
            if record.finalized_at.is_none() => Some(
            "This receipt is provisional. The wallet is revalidating its block identity and retains the wallet/chain signing slot until the network finality depth is reached.".into(),
        ),
        ExecutionStatus::Submitted | ExecutionStatus::Reverted => None,
    };
    ExecutionStatusOutput {
        request_id: record.request_id,
        wallet_id: record.wallet_id,
        chain_id: record.chain_id,
        digest: record.digest,
        status,
        approved_at: record.approved_at,
        rejected_at: record.rejected_at,
        transaction_hash: record
            .broadcast_transaction_hash
            .or(record.signed_transaction_hash),
        block_number: record.block_number,
        block_hash: record.block_hash,
        finalized: record
            .settlement_transaction_hash
            .as_ref()
            .map(|_| record.finalized_at.is_some()),
        mined_fee: record.mined_fee,
        confirmations: None,
        receipt_status,
        broadcast_error: None,
        simulation: None,
        instruction,
    }
}

impl WalletMcpServer {
    /// The per-call legal gate: every tool except the two below requires
    /// current acceptance of the terms of service and privacy policy. Before
    /// either, every tool re-checks the database schema version, so a database
    /// replaced underneath this process refuses all requests with a restart
    /// instruction instead of being written through a stale understanding of
    /// its shape.
    ///
    /// `wallet_get_legal` is exempt because it is how the documents are read
    /// in order to be accepted. `wallet_check_for_updates` is exempt because
    /// it reads a release listing and touches no wallet, key, or policy, and
    /// because the moment it is most worth hearing from is exactly this one: a
    /// release that revises the documents un-accepts everyone, so gating it
    /// would tell a user their wallet is disabled without letting the agent
    /// mention that a newer build is what they are being asked to accept.
    fn tool_gate(&self, tool_name: &str) -> Result<(), ErrorData> {
        self.policies
            .lock()
            .map_err(|_| anyhow::anyhow!("policy store lock was poisoned"))
            .and_then(|store| store.assert_schema_current())
            .map_err(|error| tool_error(&error))?;
        if matches!(tool_name, "wallet_get_legal" | "wallet_check_for_updates") {
            return Ok(());
        }
        self.require_legal_acceptance()
            .map_err(|error| tool_error(&error))
    }

    /// Read acceptance from the encrypted database through the held store; a
    /// plain file can no longer forge it.
    fn require_legal_acceptance(&self) -> Result<()> {
        let status = self
            .legal
            .lock()
            .map_err(|_| anyhow::anyhow!("legal state lock was poisoned"))?
            .status()?;
        legal::require_status_allows_use(&status)
    }

    /// Refuse to enqueue anything for a wallet that has no policy.
    ///
    /// `new` walks the configured wallets once and refuses to start if any of
    /// them lacks one, which covers the wallets that existed at startup and no
    /// others. Wallets appear afterwards: `account create` and `account import`
    /// write encrypted account metadata before initializing the policy, and every request
    /// here resolves its wallet from encrypted storage as it stands now. So a wallet
    /// half-provisioned under a running server was a wallet the startup check
    /// had never seen.
    ///
    /// The signature itself is refused by the kernel regardless — see
    /// `orchestrator::require_provisioned_wallet`, which is where the invariant
    /// actually lives. This is the earlier, kinder half: say no when the
    /// request is made rather than after a person has read the payload and
    /// authenticated to sign it.
    fn require_provisioned_wallet(&self, wallet_id: &str) -> Result<()> {
        let wallet = self.config.wallet(wallet_id)?;
        let present = self
            .policies
            .lock()
            .map_err(|_| anyhow::anyhow!("policy database lock was poisoned"))?
            .get_for_wallet(wallet_id, wallet.instance_id, wallet.address)?
            .is_some();
        anyhow::ensure!(
            present,
            "wallet {wallet_id} has no policy, so nothing it holds can be signed. Tell the user to \
             open Accounts in Ekubo Wallet and install the require-approval preset or remove the account."
        );
        Ok(())
    }

    /// The generated router with schemars' nonstandard integer `format`
    /// annotations removed. Validators warn loudly on every `tools/list` for
    /// formats like `uint32`; the `minimum`/`maximum` bounds already carry
    /// the constraint.
    fn sanitized_tool_router() -> rmcp::handler::server::router::tool::ToolRouter<Self> {
        let mut router = Self::tool_router();
        for route in router.map.values_mut() {
            let mut input = serde_json::Value::Object((*route.attr.input_schema).clone());
            strip_nonstandard_formats(&mut input);
            if let serde_json::Value::Object(object) = input {
                route.attr.input_schema = std::sync::Arc::new(object);
            }
            if let Some(output) = route.attr.output_schema.take() {
                let mut output = serde_json::Value::Object((*output).clone());
                strip_nonstandard_formats(&mut output);
                if let serde_json::Value::Object(object) = output {
                    route.attr.output_schema = Some(std::sync::Arc::new(object));
                }
            }
        }
        router
    }
}

/// Remove `"format"` annotations that are not JSON Schema formats: the
/// integer-width and float families schemars emits for Rust numeric types.
fn strip_nonstandard_formats(value: &mut serde_json::Value) {
    fn is_nonstandard(format: &str) -> bool {
        let base = format
            .strip_prefix("uint")
            .or_else(|| format.strip_prefix("int"));
        matches!(base, Some(rest) if rest.is_empty() || rest.bytes().all(|byte| byte.is_ascii_digit()))
            || matches!(format, "float" | "double")
    }
    match value {
        serde_json::Value::Object(map) => {
            if map
                .get("format")
                .and_then(serde_json::Value::as_str)
                .is_some_and(is_nonstandard)
            {
                map.remove("format");
            }
            for child in map.values_mut() {
                strip_nonstandard_formats(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_nonstandard_formats(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[path = "pipeline_test.rs"]
mod pipeline_tests;

#[cfg(test)]
#[path = "mcp_test.rs"]
mod tests;
