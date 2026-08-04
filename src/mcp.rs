use crate::{
    abi_decoder::{AbiDecodePlan, AbiDecodeResult, decode_abi_result},
    address_book::{AddressBookEntry, AddressBookStore},
    batch_read::{BatchEthCallInput, BatchEthCallOutput, batch_eth_call},
    config::{
        ConfigStore, NativeCurrency, NetworkConfig, WalletMetadata, WalletSource,
        add_configured_network,
    },
    core::{
        execution_plan::{DecimalU256, ExecutionPlan},
        policy::WalletPolicy,
        transfers::{Erc20Transfer, NativeTransfer, erc20_transfer_plan, native_transfer_plan},
    },
    custody::{KeyStore, OsKeyStore},
    execution::{
        ReceiptStatus, SignedExecution, SigningOverrides, broadcast_signed_execution,
        sign_execution,
    },
    human_presence::{HumanPresence, PlatformHumanPresence, PresenceAction, PresenceRequest},
    legal::{self, LegalDocument, LegalStatus, LegalStore},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    rpc::{WalletStatus, transaction_known, transaction_receipt, verify_chain_id, wallet_status},
    simulation::{SimulationResult, simulate_execution},
    token_store::{StoredToken, TokenStore},
    typed_data::{
        PendingTypedData, PermitApproval, TypedDataStatus, TypedDataStore,
        interpret_permit_approvals, parse_typed_data,
    },
};
use alloy::{primitives::Address, signers::SignerSync};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{
        Implementation, ListResourcesResult, PaginatedRequestParams, ReadResourceRequestParams,
        ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

#[derive(Clone)]
struct WalletMcpServer {
    config: ConfigStore,
    policies: Arc<Mutex<PolicyStore>>,
    pending: Arc<Mutex<PendingStore>>,
    typed_data: Arc<Mutex<TypedDataStore>>,
    human_presence: Arc<dyn HumanPresence>,
}

impl WalletMcpServer {
    fn production(config: ConfigStore) -> Result<Self> {
        let configured = config.load()?;
        ensure!(
            configured.wallets.is_empty() || config.data_dir().join("policies.db").is_file(),
            "{} lists wallets but {} does not exist. If a wallet was created or imported while \
             policy initialization failed, repair it with `ekubo-wallet policy require-approval \
             <wallet-id>` or remove it with `ekubo-wallet wallet remove <wallet-id>`. If this \
             directory belongs to different wallet software, point EKUBO_WALLET_HOME elsewhere.",
            config.data_dir().join("config.json").display(),
            config.data_dir().join("policies.db").display(),
        );
        let policies = PolicyStore::production(config.data_dir())?;
        let pending = PendingStore::production(config.data_dir())?;
        let typed_data = TypedDataStore::production(config.data_dir())?;
        Self::new(config, policies, pending, typed_data)
    }

    fn new(
        config: ConfigStore,
        policies: PolicyStore,
        pending: PendingStore,
        typed_data: TypedDataStore,
    ) -> Result<Self> {
        Self::with_human_presence(
            config,
            policies,
            pending,
            typed_data,
            Arc::new(PlatformHumanPresence),
        )
    }

    fn with_human_presence(
        config: ConfigStore,
        policies: PolicyStore,
        pending: PendingStore,
        typed_data: TypedDataStore,
        human_presence: Arc<dyn HumanPresence>,
    ) -> Result<Self> {
        for wallet in config.load()?.wallets {
            ensure!(
                policies.get(&wallet.id)?.is_some(),
                "wallet {} has no policy in the encrypted database",
                wallet.id
            );
        }
        Ok(Self {
            config,
            policies: Arc::new(Mutex::new(policies)),
            pending: Arc::new(Mutex::new(pending)),
            typed_data: Arc::new(Mutex::new(typed_data)),
            human_presence,
        })
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
}

#[derive(Debug, Serialize, JsonSchema)]
struct WalletInventory {
    wallets: Vec<PublicWallet>,
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
struct WalletNetworkInput {
    wallet_id: String,
    chain_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SimulateInput {
    wallet_id: String,
    chain_id: String,
    execution_plan: ExecutionPlan,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct NativeTransfersInput {
    wallet_id: String,
    chain_id: String,
    transfers: Vec<NativeTransfer>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Erc20TransfersInput {
    wallet_id: String,
    chain_id: String,
    transfers: Vec<Erc20Transfer>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SendExecutionPlanInput {
    wallet_id: String,
    chain_id: String,
    #[serde(default)]
    execution_plan: Option<ExecutionPlan>,
    #[serde(default)]
    request_id: Option<uuid::Uuid>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DecodeAbiInput {
    return_data: String,
    decode: AbiDecodePlan,
    #[serde(default = "default_true")]
    include_raw: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AddNetworkInput {
    name: String,
    display_name: String,
    aliases: Vec<String>,
    chain_id: String,
    #[schemars(with = "String")]
    rpc_url: Url,
    max_gas_limit: String,
    native_currency: NativeCurrency,
    #[schemars(with = "String")]
    block_explorer_url: Url,
    #[schemars(with = "String")]
    documentation_url: Url,
}

#[derive(Debug, Serialize, JsonSchema)]
struct AddedNetworkOutput {
    name: String,
    display_name: String,
    aliases: Vec<String>,
    chain_id: String,
    max_gas_limit: String,
    native_currency: NativeCurrency,
    #[schemars(with = "String")]
    block_explorer_url: Url,
    #[schemars(with = "String")]
    documentation_url: Url,
    rpc_verified: bool,
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
    #[serde(default = "default_wait_seconds")]
    timeout_seconds: u8,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ApprovalWaitInput {
    request_id: uuid::Uuid,
    #[serde(default = "default_wait_seconds")]
    timeout_seconds: u8,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListTokensInput {
    /// Decimal chain ID filter; omitted lists every chain.
    #[serde(default)]
    chain_id: Option<crate::token_store::ChainIdInput>,
    #[serde(default = "default_token_limit")]
    limit: usize,
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
struct AddTokenInput {
    chain_id: crate::token_store::ChainIdInput,
    address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImportTokenItem {
    /// Accepts a canonical decimal string or the bare number used by
    /// standard token-list files.
    #[serde(alias = "chainId")]
    chain_id: crate::token_store::ChainIdInput,
    address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ImportTokenListInput {
    #[serde(default)]
    list_name: Option<String>,
    tokens: Vec<ImportTokenItem>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
struct ImportTokenListOutput {
    added: u64,
    /// Already present, in the database or repeated within the list.
    skipped_existing: u64,
    /// On chains this server has no configured network for.
    skipped_unconfigured_chain: u64,
    /// Contracts that answered neither `symbol()` nor `decimals()`.
    skipped_unverifiable: u64,
    /// Up to 32 chain:address identifiers of unverifiable entries.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unverifiable: Vec<String>,
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
}

const fn default_token_limit() -> usize {
    200
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

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AddressBookInput {
    /// Decimal chain ID filter; omitted lists every chain.
    #[serde(default)]
    chain_id: Option<crate::token_store::ChainIdInput>,
    /// Exact alias to look up. Requires `chain_id`.
    #[serde(default)]
    alias: Option<String>,
    #[serde(default = "default_token_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
struct AddressBookOutput {
    /// Total stored entries matching the chain filter, ignoring paging.
    total: u64,
    entries: Vec<AddressBookEntry>,
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
    #[serde(default = "default_wait_seconds")]
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
    /// False when a recognized permit was authorized by the active policy.
    approval_required: bool,
    expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_at: Option<DateTime<Utc>>,
    /// The 65-byte r||s||v signature, present only once signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    /// Token approvals this payload grants, when it is a recognized permit.
    #[serde(skip_serializing_if = "Option::is_none")]
    permit_approvals: Option<Vec<PermitApproval>>,
    /// Policy findings for recognized permits, evaluated like `approve()` calls.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_findings: Vec<crate::core::policy::PolicyFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction: Option<String>,
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
    Expired,
    Cancelled,
}

#[derive(Debug, Serialize, JsonSchema)]
struct ExecutionStatusOutput {
    request_id: uuid::Uuid,
    wallet_id: String,
    chain_id: String,
    digest: String,
    status: ExecutionStatus,
    expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transaction_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_status: Option<ReceiptStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcast_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    simulation: Option<SimulationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction: Option<String>,
}

const SUBMISSION_LEASE_SECONDS: i64 = 120;

#[tool_router]
impl WalletMcpServer {
    #[tool(
        name = "wallet_list",
        description = "Discover all local wallets and globally configured network names and decimal chain IDs. Never returns private keys or RPC URLs.",
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
            networks: state
                .networks
                .into_iter()
                .map(|network| PublicNetwork {
                    name: network.name,
                    chain_id: network.chain_id.to_string(),
                })
                .collect(),
        }))
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
        self.config
            .wallet(&wallet_id)
            .map_err(|error| tool_error(&error))?;
        let stored = self
            .policies
            .lock()
            .map_err(|_| ErrorData::internal_error("policy database lock was poisoned", None))?
            .get(&wallet_id)
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
        Ok(Json(
            wallet_status(&wallet, &network)
                .await
                .map_err(|error| tool_error(&error))?,
        ))
    }

    #[tool(
        name = "wallet_simulate_execution_plan",
        description = "Validate and policy-check an exact execution plan, then execute its direct call or atomic EIP-7702 Calibur batch with eth_simulateV1 against a pinned parent block. The wallet verifies response linkage and locally derives policy findings from returned results and transfer logs; there is no local fork or eth_getProof path.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn wallet_simulate_execution_plan(
        &self,
        Parameters(input): Parameters<SimulateInput>,
    ) -> Result<Json<SimulationResult>, ErrorData> {
        input
            .execution_plan
            .validate()
            .map_err(|error| tool_error(&error))?;
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let stored_policy = self
            .policies
            .lock()
            .map_err(|_| ErrorData::internal_error("policy database lock was poisoned", None))?
            .get(&input.wallet_id)
            .map_err(|error| tool_error(&error))?
            .ok_or_else(|| {
                ErrorData::invalid_params(
                    format!("wallet {} has no local policy", input.wallet_id),
                    None,
                )
            })?;
        Ok(Json(
            simulate_execution(&wallet, &network, &input.execution_plan, &stored_policy)
                .await
                .map_err(|error| tool_error(&error))?,
        ))
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
        description = "Execute 1-128 read-only eth_call requests against one exact resolved block. Uses Multicall3 when caller semantics permit, otherwise bounded parallel individual calls, and can apply the same deterministic local ABI decoder inline.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn wallet_batch_eth_call(
        &self,
        Parameters(input): Parameters<BatchEthCallInput>,
    ) -> Result<Json<BatchEthCallOutput>, ErrorData> {
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        Ok(Json(
            batch_eth_call(&network, &input)
                .await
                .map_err(|error| tool_error(&error))?,
        ))
    }

    #[tool(
        name = "wallet_list_tokens",
        description = "List tokens from the local token database, optionally filtered by decimal chain ID, with limit/offset paging. Token metadata is public display data verified on-chain at insert time; it never affects signing decisions.",
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
        let store =
            TokenStore::production(self.config.data_dir()).map_err(|error| tool_error(&error))?;
        let tokens = store
            .list(chain_id, input.limit.min(1_000), input.offset)
            .map_err(|error| tool_error(&error))?;
        let total = store.count(chain_id).map_err(|error| tool_error(&error))?;
        Ok(Json(TokenListOutput { total, tokens }))
    }

    #[tool(
        name = "wallet_add_token",
        description = "Verify one token on its configured chain through Multicall3 (symbol, name, decimals read from the contract itself) and add it to the local token database. Fails if the chain_id/address pair already exists; existing entries are never overwritten.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_add_token(
        &self,
        Parameters(input): Parameters<AddTokenInput>,
    ) -> Result<Json<StoredToken>, ErrorData> {
        let chain_id = input.chain_id.value().map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&chain_id.to_string())
            .map_err(|error| tool_error(&error))?;
        let address = Address::from_str(&input.address).map_err(|_| {
            ErrorData::invalid_params("address must be a 20-byte EVM address", None)
        })?;
        let metadata = crate::token_store::fetch_onchain_metadata(&network, &[address])
            .await
            .map_err(|error| tool_error(&error))?;
        let metadata = metadata.get(&address).cloned().unwrap_or_default();
        if metadata.decimals.is_none() && metadata.symbol.is_none() {
            return Err(tool_error(&anyhow::anyhow!(
                "contract {} on chain {chain_id} answered neither symbol() nor decimals(); refusing to store it as a token",
                address.to_checksum(None)
            )));
        }
        let mut store =
            TokenStore::production(self.config.data_dir()).map_err(|error| tool_error(&error))?;
        Ok(Json(
            store
                .add(chain_id, address, &metadata, "mcp:add")
                .map_err(|error| tool_error(&error))?,
        ))
    }

    #[tool(
        name = "wallet_import_token_list",
        description = "Import up to 1000 tokens into the local token database. Each new token's symbol, name, and decimals are read from its contract through Multicall3 on its configured chain rather than trusted from the list. Existing chain_id/address pairs are skipped, never overwritten; tokens on unconfigured chains are reported and skipped.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn wallet_import_token_list(
        &self,
        Parameters(input): Parameters<ImportTokenListInput>,
    ) -> Result<Json<ImportTokenListOutput>, ErrorData> {
        ensure_tool(
            !input.tokens.is_empty(),
            "token list must contain at least one token",
        )?;
        ensure_tool(
            input.tokens.len() <= crate::token_store::MAX_IMPORT_TOKENS,
            "token list exceeds the per-import maximum",
        )?;
        let source = format!(
            "mcp:import:{}",
            input.list_name.as_deref().unwrap_or("unnamed")
        );

        // Group by chain so each configured chain gets one verification pass.
        let mut by_chain: std::collections::BTreeMap<u64, Vec<Address>> =
            std::collections::BTreeMap::new();
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
            by_chain.entry(chain_id).or_default().push(address);
        }

        let mut output = ImportTokenListOutput::default();
        let mut store =
            TokenStore::production(self.config.data_dir()).map_err(|error| tool_error(&error))?;
        for (chain_id, addresses) in by_chain {
            let Ok(network) = self.config.network_by_chain_id(&chain_id.to_string()) else {
                output.skipped_unconfigured_chain += addresses.len() as u64;
                continue;
            };
            // Deduplicate within the list and against the database before the
            // RPC pass so only genuinely new tokens are verified on-chain.
            let mut new_tokens = Vec::new();
            for address in addresses {
                if new_tokens.contains(&address) {
                    output.skipped_existing += 1;
                    continue;
                }
                match store.get(chain_id, address) {
                    Ok(Some(_)) => output.skipped_existing += 1,
                    Ok(None) => new_tokens.push(address),
                    Err(error) => return Err(tool_error(&error)),
                }
            }
            if new_tokens.is_empty() {
                continue;
            }
            let metadata = crate::token_store::fetch_onchain_metadata(&network, &new_tokens)
                .await
                .map_err(|error| tool_error(&error))?;
            for address in new_tokens {
                let token_metadata = metadata.get(&address).cloned().unwrap_or_default();
                if token_metadata.decimals.is_none() && token_metadata.symbol.is_none() {
                    output.skipped_unverifiable += 1;
                    if output.unverifiable.len() < 32 {
                        output.unverifiable.push(format!(
                            "{}:{}",
                            chain_id,
                            address.to_checksum(None)
                        ));
                    }
                    continue;
                }
                match store.insert_if_absent(chain_id, address, &token_metadata, &source) {
                    Ok(true) => output.added += 1,
                    Ok(false) => output.skipped_existing += 1,
                    Err(error) => return Err(tool_error(&error)),
                }
            }
        }
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_get_portfolio",
        description = "Read the native balance and every token-database balance for one address on one chain through Multicall3, pinned to a reported block. Accepts a wallet_id or any EVM address. Only nonzero token balances are returned.",
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
        let address = match (&input.wallet_id, &input.address) {
            (Some(wallet_id), None) => {
                self.config
                    .wallet(wallet_id)
                    .map_err(|error| tool_error(&error))?
                    .address
            }
            (None, Some(address)) => Address::from_str(address).map_err(|_| {
                ErrorData::invalid_params("address must be a 20-byte EVM address", None)
            })?,
            _ => {
                return Err(ErrorData::invalid_params(
                    "provide exactly one of wallet_id or address",
                    None,
                ));
            }
        };
        let store =
            TokenStore::production(self.config.data_dir()).map_err(|error| tool_error(&error))?;
        let known = store
            .list(
                Some(network.chain_id),
                crate::token_store::MAX_PORTFOLIO_TOKENS + 1,
                0,
            )
            .map_err(|error| tool_error(&error))?;
        Ok(Json(
            crate::token_store::read_portfolio(&network, address, &known)
                .await
                .map_err(|error| tool_error(&error))?,
        ))
    }

    #[tool(
        name = "wallet_send_native_transfers",
        description = "Simulate, policy-check, locally sign, persist, and send a non-empty ordered list of native-token transfers. One transfer is direct; multiple transfers execute atomically through canonical Calibur.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_send_native_transfers(
        &self,
        Parameters(input): Parameters<NativeTransfersInput>,
    ) -> Result<Json<ExecutionStatusOutput>, ErrorData> {
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let chain_id = DecimalU256::new(input.chain_id).map_err(|error| tool_error(&error))?;
        let plan = native_transfer_plan(&chain_id, wallet.address, input.transfers)
            .map_err(|error| tool_error(&error))?;
        Ok(Json(
            self.send_new_plan(wallet, network, plan)
                .await
                .map_err(|error| tool_error(&error))?,
        ))
    }

    #[tool(
        name = "wallet_send_erc20_transfers",
        description = "Simulate, policy-check, locally sign, persist, and send a non-empty ordered list of ERC-20 transfer(address,uint256) calls. Amounts are raw smallest-unit quantities; multiple transfers execute atomically through canonical Calibur.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_send_erc20_transfers(
        &self,
        Parameters(input): Parameters<Erc20TransfersInput>,
    ) -> Result<Json<ExecutionStatusOutput>, ErrorData> {
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let network = self
            .config
            .network_by_chain_id(&input.chain_id)
            .map_err(|error| tool_error(&error))?;
        let chain_id = DecimalU256::new(input.chain_id).map_err(|error| tool_error(&error))?;
        let plan = erc20_transfer_plan(&chain_id, wallet.address, input.transfers)
            .map_err(|error| tool_error(&error))?;
        Ok(Json(
            self.send_new_plan(wallet, network, plan)
                .await
                .map_err(|error| tool_error(&error))?,
        ))
    }

    #[tool(
        name = "wallet_send_execution_plan",
        description = "Simulate, policy-check, locally sign, persist, and broadcast an exact execution plan, or submit the exact signed bytes for a separately approved request_id. Provide exactly one of execution_plan or request_id. This tool cannot approve a request or create a replacement transaction on retry.",
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
        if input.execution_plan.is_some() == input.request_id.is_some() {
            return Err(ErrorData::invalid_params(
                "provide exactly one of execution_plan or request_id",
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
        let output = match (input.execution_plan, input.request_id) {
            (Some(plan), None) => self.send_new_plan(wallet, network, plan).await,
            (None, Some(request_id)) => {
                self.send_existing_request(wallet, network, request_id)
                    .await
            }
            _ => unreachable!("exclusive input was checked"),
        }
        .map_err(|error| tool_error(&error))?;
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_add_network",
        description = "Verify and add one complete server-wide EVM network after OS owner authentication. Fails without writing if its chain ID, name, or alias is already configured. RPC URLs are stored locally and never returned by wallet_list.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn wallet_add_network(
        &self,
        Parameters(input): Parameters<AddNetworkInput>,
    ) -> Result<Json<AddedNetworkOutput>, ErrorData> {
        let chain_id = parse_chain_id(&input.chain_id).map_err(|error| tool_error(&error))?;
        let candidate = NetworkConfig {
            name: input.name,
            display_name: Some(input.display_name),
            aliases: input.aliases,
            chain_id,
            rpc_url: input.rpc_url,
            max_gas_limit: Some(input.max_gas_limit),
            native_currency: Some(input.native_currency),
            block_explorer_url: Some(input.block_explorer_url),
            documentation_url: Some(input.documentation_url),
        };
        // Validate every local field and conflict before owner authentication.
        // The new endpoint is not contacted until the owner authorizes its
        // complete configuration digest, preventing unauthenticated SSRF.
        let mut prospective = self
            .config
            .load()
            .map_err(|error| tool_error(&error))?
            .networks;
        add_configured_network(&mut prospective, candidate.clone())
            .map_err(|error| tool_error(&error))?;
        let digest = configuration_digest(&candidate).map_err(|error| tool_error(&error))?;
        self.human_presence
            .confirm(&PresenceRequest {
                action: PresenceAction::ChangeNetworkConfiguration,
                wallet_id: format!(
                    "network {} on chain {} via {}",
                    candidate.name,
                    candidate.chain_id,
                    rpc_origin(&candidate.rpc_url)
                ),
                operation_digest: Some(digest),
            })
            .await
            .map_err(|error| tool_error(&error))?;
        verify_chain_id(&candidate)
            .await
            .map_err(|error| tool_error(&error))?;
        self.config
            .update(|state| {
                add_configured_network(&mut state.networks, candidate.clone())?;
                Ok(())
            })
            .map_err(|error| tool_error(&error))?;
        Ok(Json(AddedNetworkOutput {
            name: candidate.name,
            display_name: candidate.display_name.expect("complete MCP network"),
            aliases: candidate.aliases,
            chain_id: candidate.chain_id.to_string(),
            max_gas_limit: candidate.max_gas_limit.expect("complete MCP network"),
            native_currency: candidate.native_currency.expect("complete MCP network"),
            block_explorer_url: candidate.block_explorer_url.expect("complete MCP network"),
            documentation_url: candidate.documentation_url.expect("complete MCP network"),
            rpc_verified: true,
        }))
    }

    #[tool(
        name = "wallet_wait_for_approval",
        description = "Wait for a pending transaction to be approved and signed or rejected through the separate human CLI. This tool cannot approve, reject, sign, or submit it.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn wallet_wait_for_approval(
        &self,
        Parameters(input): Parameters<ApprovalWaitInput>,
    ) -> Result<Json<ExecutionStatusOutput>, ErrorData> {
        validate_wait_seconds(input.timeout_seconds).map_err(|error| tool_error(&error))?;
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(u64::from(input.timeout_seconds));
        loop {
            let record = self
                .pending_record_by_id(input.request_id)
                .map_err(|error| tool_error(&error))?;
            if record.status != PendingStatus::AwaitingApproval
                || tokio::time::Instant::now() >= deadline
            {
                let timed_out = record.status == PendingStatus::AwaitingApproval;
                let mut output = execution_status_output(record);
                if timed_out {
                    output.status = ExecutionStatus::TimedOut;
                    output.instruction = Some(format!(
                        "Still awaiting human approval; the request expires at {}. Call wallet_wait_for_approval again with request_id {}; do not ask the user to report approval in chat.",
                        output.expires_at.to_rfc3339(),
                        output.request_id
                    ));
                }
                return Ok(Json(output));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
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
        description = "Poll a previously broadcast transaction for up to 55 seconds and reconcile its receipt. This tool never approves, signs, or submits.",
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
        validate_wait_seconds(input.timeout_seconds).map_err(|error| tool_error(&error))?;
        let request = RequestInput {
            wallet_id: input.wallet_id,
            chain_id: input.chain_id,
            request_id: input.request_id,
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(u64::from(input.timeout_seconds));
        loop {
            let status = self
                .reconcile_pending(&request)
                .await
                .map_err(|error| tool_error(&error))?;
            if status.status != ExecutionStatus::SubmissionPending
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(Json(status));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[tool(
        name = "wallet_get_legal",
        description = "Read the legal acceptance status, and optionally the complete text of the Terms of Service, Privacy Policy, or Third-Party Licenses. Acceptance itself is a separate human CLI operation; every other wallet tool fails until the user has accepted the current terms and privacy policy via `ekubo-wallet legal accept`.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn wallet_get_legal(
        &self,
        Parameters(input): Parameters<LegalInput>,
    ) -> Result<Json<LegalOutput>, ErrorData> {
        let status = LegalStore::new(self.config.data_dir())
            .status()
            .map_err(|error| tool_error(&error))?;
        let instruction = if status.signing_allowed {
            "The current Terms of Service and Privacy Policy are accepted; the wallet tools are available.".into()
        } else {
            "Every wallet tool except this one is disabled until the user accepts the current Terms of Service and separately acknowledges the Privacy Policy. Offer to display each document (this tool returns their text), then tell the user to run `ekubo-wallet legal accept` in their own terminal. Never run that command for them and never claim acceptance on their behalf.".to_string()
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
        name = "wallet_address_book",
        description = "Look up user-configured aliases for addresses on particular chains. Entries are lookup convenience data with no signing authority and never affect policy decisions; adding, changing, or removing entries is a separate human CLI operation with OS owner authentication. Provide alias with chain_id for an exact lookup, or list with optional chain filter.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    fn wallet_address_book(
        &self,
        Parameters(input): Parameters<AddressBookInput>,
    ) -> Result<Json<AddressBookOutput>, ErrorData> {
        let chain_id = input
            .chain_id
            .as_ref()
            .map(crate::token_store::ChainIdInput::value)
            .transpose()
            .map_err(|error| tool_error(&error))?;
        let store = AddressBookStore::production(self.config.data_dir())
            .map_err(|error| tool_error(&error))?;
        if let Some(alias) = &input.alias {
            let chain_id = chain_id
                .ok_or_else(|| ErrorData::invalid_params("alias lookup requires chain_id", None))?;
            let entries = store
                .get(chain_id, alias)
                .map_err(|error| tool_error(&error))?
                .into_iter()
                .collect::<Vec<_>>();
            return Ok(Json(AddressBookOutput {
                total: entries.len() as u64,
                entries,
            }));
        }
        let entries = store
            .list(chain_id, input.limit.min(1_000), input.offset)
            .map_err(|error| tool_error(&error))?;
        let total = store.count(chain_id).map_err(|error| tool_error(&error))?;
        Ok(Json(AddressBookOutput { total, entries }))
    }

    #[tool(
        name = "wallet_sign_typed_data",
        description = "Sign an exact EIP-712 typed-data payload. Recognized permits (ERC-2612 Permit and canonical Permit2) are policy-checked exactly like approve() calls: a permitted approval signs immediately, and anything else — over-limit permits and every unrecognized payload — queues for explicit human approval through the separate CLI. The domain must pin a configured chainId. When a request queues, wait on it with wallet_wait_for_typed_data.",
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
        legal::require_current_acceptance(self.config.data_dir())
            .map_err(|error| tool_error(&error))?;
        let wallet = self
            .config
            .wallet(&input.wallet_id)
            .map_err(|error| tool_error(&error))?;
        let (typed, chain_id, digest) =
            parse_typed_data(&input.typed_data).map_err(|error| tool_error(&error))?;
        self.config
            .network_by_chain_id(&chain_id.to_string())
            .map_err(|error| tool_error(&error))?;
        let permit_approvals = interpret_permit_approvals(&typed, wallet.address)
            .map_err(|error| tool_error(&error))?;

        // A recognized permit is an approval as far as policy goes: evaluate
        // it against the approval-spender rules, and sign immediately when
        // the active policy permits it.
        let mut policy_findings = Vec::new();
        if let Some(approvals) = &permit_approvals {
            let stored_policy = self
                .policies
                .lock()
                .map_err(|_| ErrorData::internal_error("policy database lock was poisoned", None))?
                .get(&wallet.id)
                .map_err(|error| tool_error(&error))?
                .ok_or_else(|| {
                    ErrorData::invalid_params(
                        format!("wallet {} has no local policy", wallet.id),
                        None,
                    )
                })?;
            let tuples = approvals
                .iter()
                .map(PermitApproval::tuple)
                .collect::<Result<Vec<_>>>()
                .map_err(|error| tool_error(&error))?;
            policy_findings = crate::core::policy::evaluate_permit_approvals(
                &stored_policy.policy,
                &chain_id.to_string(),
                &tuples,
            );
            if crate::core::policy::policy_allows(&policy_findings) {
                let record = self
                    .sign_permit_automatically(
                        &wallet,
                        chain_id,
                        &input.typed_data,
                        digest,
                        stored_policy.revision,
                    )
                    .map_err(|error| tool_error(&error))?;
                let mut output = typed_data_output(record);
                output.permit_approvals = permit_approvals;
                output.policy_findings = policy_findings;
                return Ok(Json(output));
            }
        }

        let record = self
            .typed_data
            .lock()
            .map_err(|_| ErrorData::internal_error("typed-data database lock was poisoned", None))?
            .create(&wallet.id, chain_id, &input.typed_data, digest)
            .map_err(|error| tool_error(&error))?;
        let mut output = typed_data_output(record);
        output.permit_approvals = permit_approvals;
        output.policy_findings = policy_findings;
        Ok(Json(output))
    }

    #[tool(
        name = "wallet_wait_for_typed_data",
        description = "Wait for a pending typed-data request to be approved and signed or rejected through the separate human CLI, and read the signature once signed. This tool cannot approve, reject, or sign.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn wallet_wait_for_typed_data(
        &self,
        Parameters(input): Parameters<TypedDataWaitInput>,
    ) -> Result<Json<TypedDataOutput>, ErrorData> {
        validate_wait_seconds(input.timeout_seconds).map_err(|error| tool_error(&error))?;
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(u64::from(input.timeout_seconds));
        loop {
            let record = self
                .typed_data
                .lock()
                .map_err(|_| {
                    ErrorData::internal_error("typed-data database lock was poisoned", None)
                })?
                .get(input.request_id)
                .map_err(|error| tool_error(&error))?;
            if record.status != TypedDataStatus::AwaitingApproval
                || tokio::time::Instant::now() >= deadline
            {
                let timed_out = record.status == TypedDataStatus::AwaitingApproval;
                let mut output = typed_data_output(record);
                if timed_out {
                    output.instruction = Some(format!(
                        "Still awaiting human approval; the request expires at {}. Call wallet_wait_for_typed_data again with request_id {}; do not ask the user to report approval in chat.",
                        output.expires_at.to_rfc3339(),
                        output.request_id
                    ));
                }
                return Ok(Json(output));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

impl WalletMcpServer {
    /// Sign a policy-authorized permit with the wallet key and persist the
    /// signature. The persistence step re-checks the policy revision, so a
    /// concurrent policy change discards the signature instead of storing it.
    fn sign_permit_automatically(
        &self,
        wallet: &WalletMetadata,
        chain_id: u64,
        typed_data: &serde_json::Value,
        digest: alloy::primitives::B256,
        policy_revision: u64,
    ) -> Result<PendingTypedData> {
        let material = OsKeyStore.load(&wallet.id)?;
        let signer = material.signer();
        ensure!(
            signer.address() == wallet.address,
            "credential-store private key does not match wallet metadata"
        );
        let signature = signer
            .sign_hash_sync(&digest)
            .context("failed to sign typed data")?;
        self.typed_data
            .lock()
            .map_err(|_| anyhow::anyhow!("typed-data database lock was poisoned"))?
            .record_automatic_signed(
                &wallet.id,
                chain_id,
                typed_data,
                digest,
                policy_revision,
                &format!("0x{}", hex::encode(signature.as_bytes())),
            )
    }

    fn pending_record_by_id(&self, request_id: uuid::Uuid) -> Result<PendingTransaction> {
        let record = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .get(request_id)?;
        let wallet = self.config.wallet(&record.wallet_id)?;
        let network = self.config.network_by_chain_id(&record.chain_id)?;
        ensure!(
            record.network_name == network.name,
            "pending request network mismatch"
        );
        ensure!(
            record.execution_plan.sender == wallet.address,
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
        let network = self.config.network_by_chain_id(chain_id)?;
        let record = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .get(request_id)?;
        ensure!(
            record.wallet_id == wallet_id,
            "pending request wallet mismatch"
        );
        ensure!(
            record.chain_id == chain_id,
            "pending request chain mismatch"
        );
        ensure!(
            record.network_name == network.name,
            "pending request network mismatch"
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
    ) -> Result<ExecutionStatusOutput> {
        legal::require_current_acceptance(self.config.data_dir())?;
        plan.validate()?;
        ensure!(
            plan.sender == wallet.address,
            "execution plan sender mismatch"
        );
        ensure!(
            plan.chain_id.as_str() == network.chain_id.to_string(),
            "execution plan chain mismatch"
        );
        let stored_policy = self
            .policies
            .lock()
            .map_err(|_| anyhow::anyhow!("policy database lock was poisoned"))?
            .get(&wallet.id)?
            .with_context(|| format!("wallet {} has no local policy", wallet.id))?;
        let simulation = simulate_execution(&wallet, &network, &plan, &stored_policy).await?;

        if !simulation.allowed || !simulation.simulation.success {
            let expiry = stored_policy
                .policy
                .approval_expiry_seconds(plan.chain_id.as_str());
            let request = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                .create(
                    &wallet.id,
                    &network.name,
                    &plan,
                    stored_policy.revision,
                    expiry,
                )?;
            let mut output = execution_status_output(request);
            output.instruction = Some(if simulation.simulation.success {
                format!(
                    "The plan needs explicit human approval before it can sign. Tell the user to run `ekubo-wallet approve {}` in their own terminal (never invoke that CLI for them), then immediately call wallet_wait_for_approval with this request_id and keep calling it after each timeout until the request is approved, rejected, or expired. On approved, submit with wallet_send_execution_plan and this request_id. Do not ask the user to report the approval in chat.",
                    output.request_id
                )
            } else {
                let guidance = simulation.simulation.failure.as_ref().map_or(
                    "Simulation failed; obtain guidance from the plan producer before continuing.",
                    |failure| failure.instruction.as_str(),
                );
                format!(
                    "{guidance} If the user instead explicitly chooses to override the failed simulation, they can run `ekubo-wallet approve {}` in their own terminal (never invoke that CLI for them); in that case call wallet_wait_for_approval with this request_id until it resolves.",
                    output.request_id
                )
            });
            output.simulation = Some(simulation);
            return Ok(output);
        }

        let signed = sign_execution(
            &wallet,
            &network,
            &plan,
            &simulation,
            &OsKeyStore,
            SigningOverrides::default(),
        )
        .await?;
        ensure!(
            self.config.wallet(&wallet.id)? == wallet,
            "wallet configuration changed while the transaction was being signed"
        );
        ensure!(
            self.config.network_by_chain_id(plan.chain_id.as_str())? == network,
            "network configuration changed while the transaction was being signed"
        );
        let record = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .record_automatic_signed(
                &wallet.id,
                &network.name,
                &plan,
                stored_policy.revision,
                &signed.serialized_transaction,
                &signed.transaction_hash,
            )?;
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
        ensure!(
            claimed.status == PendingStatus::Submitting,
            "pending transaction does not hold the submission lease"
        );
        let signed = signed_execution(&claimed)?;
        let broadcast =
            match broadcast_signed_execution(&signed, wallet, network, &claimed.execution_plan)
                .await
            {
                Ok(broadcast) => broadcast,
                Err(error) => {
                    self.pending
                        .lock()
                        .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                        .release_submission(claimed.request_id)
                        .context("failed to release transaction submission lease")?;
                    return Err(error);
                }
            };

        let record = {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?;
            let broadcast_record =
                pending.mark_broadcast(claimed.request_id, &broadcast.transaction_hash)?;
            match broadcast.receipt_status {
                ReceiptStatus::Success | ReceiptStatus::Reverted => pending.finalize(
                    broadcast_record.request_id,
                    broadcast.receipt_status == ReceiptStatus::Success,
                    broadcast
                        .block_number
                        .as_deref()
                        .context("confirmed transaction is missing a block number")?,
                )?,
                ReceiptStatus::Pending => broadcast_record,
            }
        };
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
        mut record: PendingTransaction,
        recover_stale_submission: bool,
    ) -> Result<PendingTransaction> {
        if matches!(
            record.status,
            PendingStatus::Broadcast | PendingStatus::Submitting
        ) {
            let transaction_hash = record
                .broadcast_transaction_hash
                .as_ref()
                .or(record.signed_transaction_hash.as_ref())
                .cloned()
                .context("submitted transaction is missing its hash")?;
            if let Some(receipt) = transaction_receipt(network, &transaction_hash).await? {
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?;
                if record.status == PendingStatus::Submitting {
                    record = pending.mark_broadcast(record.request_id, &transaction_hash)?;
                }
                return pending.finalize(
                    record.request_id,
                    receipt.succeeded,
                    &receipt.block_number.to_string(),
                );
            }

            if record.status == PendingStatus::Submitting
                && recover_stale_submission
                && Utc::now() - record.updated_at >= TimeDelta::seconds(SUBMISSION_LEASE_SECONDS)
            {
                let known = transaction_known(network, &transaction_hash).await?;
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?;
                record = if known {
                    pending.mark_broadcast(record.request_id, &transaction_hash)?
                } else {
                    pending.release_submission(record.request_id)?
                };
            }
        }
        Ok(record)
    }
}

const SECURITY_RESOURCE_URI: &str = "wallet://docs/security-model";
const TERMS_RESOURCE_URI: &str = "wallet://legal/terms-of-service";
const PRIVACY_RESOURCE_URI: &str = "wallet://legal/privacy-policy";
const LICENSES_RESOURCE_URI: &str = "wallet://legal/third-party-licenses";
// This server is a general-purpose local EVM wallet. It is deliberately not
// bound to any particular protocol, dapp, or companion MCP server: it accepts a
// signer-neutral execution plan from whatever produced it and applies the same
// validation, simulation, and policy rules to all of them. Naming a specific
// counterpart here would both mislead an agent about the wallet's scope and
// imply that plans from that source are more trusted, which they are not.
const SERVER_INSTRUCTIONS: &str = "A local EVM wallet that reads chain state, and simulates, policy-checks, signs, and broadcasts signer-neutral execution plans. Call wallet_list first for user-owned onchain actions; it returns the available wallets and configured chains. Any tool, protocol server, or dapp may produce an execution plan: pass it here unchanged, and this wallet validates, simulates, and policy-checks it identically regardless of origin. Never construct or edit calldata to satisfy a policy. MCP tools select networks only with canonical decimal chain_id strings; profile names are CLI and display metadata. Execution plans never choose transaction gas: the wallet doubles RPC-simulated gas and caps it at the configured network and simulated block limits. A one-call plan is signed directly; multiple calls execute atomically through canonical Calibur using EIP-7702, keeping an existing canonical delegation, creating a missing one, or replacing a different one. Simulation uses only eth_simulateV1 against a pinned parent block; there is no local fork or eth_getProof path. Private keys never enter MCP. Wallet creation, import/export, policy changes, network replacement/removal, and exceptional transaction approvals are separate human CLI operations. wallet_add_network is the only MCP configuration mutation and requires OS owner authentication. The token database is separate public display data: wallet_add_token and wallet_import_token_list verify symbol, name, and decimals against the token contracts through Multicall3 before storing, a chain_id/address pair can never be overwritten, and wallet_get_portfolio reads native plus known-token balances for any address through Multicall3. Nothing in the signing path reads the token database. Never invoke or automate the approval CLI for the user. Policies are stateless and contain no daily limits, spend counters, reservations, or spend-history endpoint. On simulation failure, follow simulation.failure.recommended_action and instruction: retry identical calldata only for retry_same_plan, which normally means a transient RPC failure, and obtain freshly prepared calldata from the plan's originator for reprepare_plan, including reverts and slippage. After approval_required, tell the user the exact `ekubo-wallet approve <request-id>` command, then immediately call wallet_wait_for_approval and keep calling it after each timeout until the request is approved, rejected, or expired; on approved, submit with wallet_send_execution_plan and the request_id. Never invoke the approval CLI yourself and never ask the user to report the approval in chat. Reconcile submitted requests with wallet_get_execution_status or wallet_wait_for_execution; retries rebroadcast only the persisted exact signed bytes. Every tool except wallet_get_legal is disabled until the user has accepted the current Terms of Service and separately acknowledged the Privacy Policy through the human CLI (`ekubo-wallet legal accept`), because the privacy policy governs even read-only RPC requests and agent data exposure; read acceptance state and document text with wallet_get_legal, and never run the acceptance command for the user or claim acceptance on their behalf. Third-party license attributions are available through wallet_get_legal and the wallet://legal resources. EIP-712 typed-data signing always queues for explicit human CLI approval via wallet_sign_typed_data, then wallet_wait_for_typed_data returns the signature once the user approves; policies cannot evaluate typed data, so there is no automatic typed-data path. The address book (wallet_address_book) is read-only lookup data mapping user-chosen aliases to addresses per chain: use it to resolve aliases the user mentions, but always present the resolved address in any transaction context; entries carry no signing authority and are managed only by the human CLI with OS owner authentication.";
const SECURITY_MODEL: &str = "# Security model\n\n- This is one local stdio MCP process. It parses, simulates, policy-checks, signs, validates, persists, and broadcasts structured execution plans.\n- Private keys are created or imported only by the separate human CLI and remain in the OS credential store. No MCP input or output carries a private key, mnemonic, password, arbitrary digest, or generic signing request.\n- Current policies and pending transaction lifecycle rows share one SQLCipher database. The database key is a distinct 256-bit OS-credential-store secret. There are no daily limits, spend counters, allowance reservations, or rollback-sensitive consumption records.\n- Simulation sends the exact target, value, calldata, and any EIP-7702 delegation override to eth_simulateV1 at a pinned parent block. There is no local fork, eth_getProof, or eth_call fallback for signing decisions. The configured RPC executes the EVM and remains a trust dependency for state accuracy.\n- Automatic transactions persist their exact signed envelope and hash before first submission. Approval and crash-recovery retries never re-sign or alter that transaction.\n- Policy exceptions require separate terminal review plus OS-backed owner authentication. Their review digest binds the exact plan, nonce, gas, fees, call, and delegation; signing performs no RPC lookup after authentication. The MCP server can wait for or observe that decision but cannot approve it.\n- wallet_add_network validates locally and requires OS owner authentication before contacting the proposed RPC, then verifies its chain before the atomic configuration write. Other policy, network, custody, and approval mutations remain CLI-only.\n- The token database (tokens.db) is unencrypted public display data used for listings and portfolio reads. MCP tools may add to it, entries are verified against the token contracts through Multicall3 at insert, a chain_id/address pair is never overwritten, and no signing or policy decision reads it.\n- The address book (address_book.db) is unencrypted lookup data mapping per-chain aliases to addresses. Only the human CLI can mutate it, after OS owner authentication. Nothing in the signing or policy path reads it, and an alias never substitutes for reviewing the actual address.\n- EIP-712 typed-data requests always queue in the encrypted database for separate human CLI review, which displays the complete payload, requires terminal approval plus OS owner authentication, and only then signs. The MCP server can create and observe typed-data requests but cannot approve or sign them.\n- No MCP tool other than wallet_get_legal is reachable until the user has accepted the current Terms of Service and Privacy Policy through the interactive CLI; the signing paths repeat the check as defense in depth. Acceptance binds the exact document digests; changed documents fail closed until re-accepted.\n";

#[tool_handler(router = Self::sanitized_tool_router())]
impl ServerHandler for WalletMcpServer {
    /// Hand-written so every tool call passes the legal-acceptance gate. The
    /// privacy policy governs RPC requests and agent data exposure, so even
    /// read-only tools stay disabled until acceptance; only `wallet_get_legal`
    /// is exempt so the documents and status remain readable.
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
            Implementation::new("ekubo-wallet", crate::VERSION)
                .with_title("Ekubo Wallet — Local EVM Execution"),
        )
        .with_instructions(SERVER_INSTRUCTIONS)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(SECURITY_RESOURCE_URI, "security-model")
                .with_title("Wallet trust and security model")
                .with_description("The local signing, storage, approval, RPC, and retry boundary.")
                .with_mime_type("text/markdown"),
            Resource::new(TERMS_RESOURCE_URI, "terms-of-service")
                .with_title("Terms of Service")
                .with_description(
                    "Must be accepted via the separate human CLI before signing tools work.",
                )
                .with_mime_type("text/markdown"),
            Resource::new(PRIVACY_RESOURCE_URI, "privacy-policy")
                .with_title("Privacy Policy")
                .with_description(
                    "Discloses the default RPC endpoints; must be acknowledged separately via the human CLI.",
                )
                .with_mime_type("text/markdown"),
            Resource::new(LICENSES_RESOURCE_URI, "third-party-licenses")
                .with_title("Third-Party Licenses")
                .with_description("License attributions for every bundled dependency.")
                .with_mime_type("text/markdown"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let contents = match request.uri.as_ref() {
            SECURITY_RESOURCE_URI => SECURITY_MODEL.to_string(),
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
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(contents, request.uri.clone()).with_mime_type("text/markdown"),
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

fn tool_error(error: &impl std::fmt::Display) -> ErrorData {
    ErrorData::internal_error(error.to_string(), None)
}

fn parse_chain_id(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty()
            && !value.starts_with('0')
            && value.bytes().all(|byte| byte.is_ascii_digit()),
        "chain ID must be a canonical positive decimal integer"
    );
    value.parse().context("chain ID must fit uint64")
}

fn configuration_digest(value: &impl Serialize) -> Result<String> {
    Ok(format!(
        "0x{}",
        hex::encode(Keccak256::digest(serde_json::to_vec(value)?))
    ))
}

/// The scheme, host, and port of an RPC URL, with any userinfo, path, and query
/// removed. Provider credentials commonly live in the path or query, so this is
/// the most that may be shown without disclosing them.
#[must_use]
pub fn rpc_origin(url: &Url) -> String {
    let host = url.host_str().unwrap_or("<invalid-host>");
    url.port().map_or_else(
        || format!("{}://{host}", url.scheme()),
        |port| format!("{}://{host}:{port}", url.scheme()),
    )
}

const fn default_true() -> bool {
    true
}

const fn default_wait_seconds() -> u8 {
    55
}

fn validate_wait_seconds(seconds: u8) -> Result<()> {
    ensure!(
        (1..=55).contains(&seconds),
        "timeout_seconds must be between 1 and 55"
    );
    Ok(())
}

fn signed_execution(record: &PendingTransaction) -> Result<SignedExecution> {
    Ok(SignedExecution {
        digest: record.digest.clone(),
        serialized_transaction: record
            .serialized_transaction
            .clone()
            .context("pending transaction has no signed bytes")?,
        transaction_hash: record
            .signed_transaction_hash
            .clone()
            .context("pending transaction has no signed hash")?,
    })
}

fn typed_data_output(record: PendingTypedData) -> TypedDataOutput {
    let instruction = match record.status {
        TypedDataStatus::AwaitingApproval => Some(format!(
            "Typed-data signing requires explicit human approval. Tell the user to run `ekubo-wallet approve {}` in their own terminal (never invoke that CLI for them), then call wallet_wait_for_typed_data with this request_id and keep calling it after each timeout until the request is signed, rejected, or expired. Do not ask the user to report the approval in chat.",
            record.request_id
        )),
        TypedDataStatus::Signed => Some(
            "The typed data is signed; signature holds the exact 65-byte r||s||v signature. Deliver it to whatever requested the signature.".into(),
        ),
        TypedDataStatus::Rejected => Some(
            "The user rejected this typed-data request. Do not recreate it unless they explicitly ask to sign again.".into(),
        ),
        TypedDataStatus::Expired => Some(
            "The typed-data approval request expired. Create a new request only if the user still wants to sign.".into(),
        ),
    };
    TypedDataOutput {
        request_id: record.request_id,
        wallet_id: record.wallet_id,
        chain_id: record.chain_id,
        digest: record.digest,
        status: record.status,
        approval_required: record.approval_required,
        expires_at: record.expires_at,
        approved_at: record.approved_at,
        rejected_at: record.rejected_at,
        signature: record.signature,
        permit_approvals: None,
        policy_findings: Vec::new(),
        instruction,
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
        PendingStatus::Expired => ExecutionStatus::Expired,
        PendingStatus::Cancelled => ExecutionStatus::Cancelled,
    };
    let receipt_status = match record.status {
        PendingStatus::Submitting | PendingStatus::Broadcast => Some(ReceiptStatus::Pending),
        PendingStatus::Confirmed => Some(ReceiptStatus::Success),
        PendingStatus::Reverted => Some(ReceiptStatus::Reverted),
        _ => None,
    };
    let instruction = match status {
        ExecutionStatus::ApprovalRequired => Some(format!(
            "Awaiting human approval. Tell the user to run `ekubo-wallet approve {}` in their own terminal (never invoke that CLI for them), then call wallet_wait_for_approval with this request_id, repeating after each timeout, until it resolves.",
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
        ExecutionStatus::Expired => Some(
            "The approval request expired. Create a new request only if the user still wants to proceed.".into(),
        ),
        ExecutionStatus::Cancelled => Some(
            "The signed request was cancelled because its policy revision changed before initial submission.".into(),
        ),
        ExecutionStatus::Submitted | ExecutionStatus::Reverted => None,
    };
    ExecutionStatusOutput {
        request_id: record.request_id,
        wallet_id: record.wallet_id,
        chain_id: record.chain_id,
        digest: record.digest,
        status,
        expires_at: record.expires_at,
        approved_at: record.approved_at,
        rejected_at: record.rejected_at,
        transaction_hash: record
            .broadcast_transaction_hash
            .or(record.signed_transaction_hash),
        block_number: record.block_number,
        receipt_status,
        broadcast_error: None,
        simulation: None,
        instruction,
    }
}

impl WalletMcpServer {
    /// The per-call legal gate: every tool except `wallet_get_legal` requires
    /// current acceptance of the terms of service and privacy policy.
    fn tool_gate(&self, tool_name: &str) -> Result<(), ErrorData> {
        if tool_name == "wallet_get_legal" {
            return Ok(());
        }
        legal::require_current_acceptance(self.config.data_dir())
            .map_err(|error| tool_error(&error))
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

pub async fn serve(config: ConfigStore) -> Result<()> {
    let server = WalletMcpServer::production(config)?;
    let running = server
        .serve(stdio())
        .await
        .context("failed to initialize MCP stdio server")?;
    running.waiting().await.context("MCP server task failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{CustodyStatus, WalletMetadata, WalletSource},
        human_presence::TestHumanPresence,
        policy_store::DatabaseKey,
    };
    use alloy::primitives::Address;
    use std::str::FromStr;

    fn server() -> (tempfile::TempDir, WalletMcpServer) {
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigStore::new(directory.path());
        let mut state = config.load().unwrap();
        state.wallets.push(WalletMetadata {
            id: "primary".into(),
            address: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
            created_at: Utc::now(),
            source: WalletSource::Created,
            custody: CustodyStatus::Sealed,
            exported_at: None,
        });
        config.save(&state).unwrap();
        let mut policies = PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([4; 32]),
        )
        .unwrap();
        policies
            .put("primary", &WalletPolicy::allow_all_with_approval(), None)
            .unwrap();
        let pending_database = PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([4; 32]),
        )
        .unwrap();
        let typed_data_database = PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([4; 32]),
        )
        .unwrap();
        let server = WalletMcpServer::new(
            config,
            policies,
            PendingStore::new(pending_database),
            TypedDataStore::new(typed_data_database),
        )
        .unwrap();
        (directory, server)
    }

    fn accept_legal(server: &WalletMcpServer) {
        let store = LegalStore::new(server.config.data_dir());
        store
            .record_acceptance(
                LegalDocument::TermsOfService,
                &LegalDocument::TermsOfService.digest(),
            )
            .unwrap();
        store
            .record_acceptance(
                LegalDocument::PrivacyPolicy,
                &LegalDocument::PrivacyPolicy.digest(),
            )
            .unwrap();
    }

    #[test]
    fn inventory_omits_rpc_urls_and_private_state() {
        let (_directory, server) = server();
        let Json(inventory) = server.wallet_list().unwrap();
        assert_eq!(inventory.wallets[0].id, "primary");
        assert!(
            inventory
                .networks
                .iter()
                .all(|network| !network.name.contains("http"))
        );
    }

    #[test]
    fn policy_tool_reads_encrypted_policy_revision() {
        let (_directory, server) = server();
        let Json(output) = server
            .wallet_get_policy(Parameters(WalletInput {
                wallet_id: "primary".into(),
            }))
            .unwrap();
        assert_eq!(output.revision, 1);
        assert_eq!(output.wallet_id, "primary");
    }

    #[test]
    fn advertised_version_matches_crate() {
        assert_eq!(crate::VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn tool_schemas_contain_no_boolean_schemas() {
        // Schemars renders serde_json::Value as the boolean schema `true`,
        // which Claude Code's MCP client rejects when it validates tools/list
        // ("Invalid input at tools.N.outputSchema..."). Every position that
        // holds a subschema must hold an object.
        fn assert_no_boolean_schemas(value: &serde_json::Value, path: &str) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        let child_path = format!("{path}.{key}");
                        // additionalProperties is exempt: boolean forms are
                        // universal there and clients accept them.
                        let schema_position = matches!(key.as_str(), "items" | "contains" | "not")
                            || path.ends_with(".properties")
                            || path.ends_with(".$defs")
                            || path.ends_with(".definitions");
                        if schema_position {
                            assert!(
                                child.is_object(),
                                "boolean or non-object schema at {child_path}: {child}"
                            );
                        }
                        assert_no_boolean_schemas(child, &child_path);
                    }
                }
                serde_json::Value::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        assert_no_boolean_schemas(item, &format!("{path}[{index}]"));
                    }
                }
                _ => {}
            }
        }

        fn assert_no_nonstandard_formats(value: &serde_json::Value, path: &str) {
            match value {
                serde_json::Value::Object(map) => {
                    if let Some(format) = map.get("format").and_then(serde_json::Value::as_str) {
                        assert!(
                            !(format.starts_with("uint")
                                || format.starts_with("int")
                                || format == "float"
                                || format == "double"),
                            "nonstandard format {format:?} at {path}"
                        );
                    }
                    for (key, child) in map {
                        assert_no_nonstandard_formats(child, &format!("{path}.{key}"));
                    }
                }
                serde_json::Value::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        assert_no_nonstandard_formats(item, &format!("{path}[{index}]"));
                    }
                }
                _ => {}
            }
        }

        for tool in WalletMcpServer::sanitized_tool_router().list_all() {
            let name = tool.name.clone();
            let input = serde_json::to_value(tool.input_schema.as_ref()).unwrap();
            assert_no_boolean_schemas(&input, &format!("{name}.inputSchema"));
            assert_no_nonstandard_formats(&input, &format!("{name}.inputSchema"));
            if let Some(output) = &tool.output_schema {
                let output = serde_json::to_value(output.as_ref()).unwrap();
                assert_no_boolean_schemas(&output, &format!("{name}.outputSchema"));
                assert_no_nonstandard_formats(&output, &format!("{name}.outputSchema"));
            }
        }
    }

    #[test]
    fn tool_inventory_exposes_implemented_parity_surface() {
        let names = WalletMcpServer::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            names,
            [
                "wallet_add_network",
                "wallet_add_token",
                "wallet_address_book",
                "wallet_batch_eth_call",
                "wallet_decode_abi_result",
                "wallet_get_legal",
                "wallet_get_policy",
                "wallet_get_portfolio",
                "wallet_get_status",
                "wallet_get_execution_status",
                "wallet_import_token_list",
                "wallet_list",
                "wallet_list_tokens",
                "wallet_send_erc20_transfers",
                "wallet_send_execution_plan",
                "wallet_send_native_transfers",
                "wallet_sign_typed_data",
                "wallet_simulate_execution_plan",
                "wallet_wait_for_approval",
                "wallet_wait_for_execution",
                "wallet_wait_for_typed_data",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
    }

    #[test]
    fn approval_wait_schema_uses_only_the_pending_request_id() {
        let router = WalletMcpServer::tool_router();
        let tool = router.get("wallet_wait_for_approval").unwrap();
        let properties = tool
            .input_schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .unwrap();
        assert!(properties.contains_key("request_id"));
        assert!(properties.contains_key("timeout_seconds"));
        assert!(!properties.contains_key("wallet_id"));
        assert!(!properties.contains_key("chain_id"));
        assert_eq!(
            tool.annotations.as_ref().unwrap().read_only_hint,
            Some(true)
        );
    }

    #[test]
    fn network_add_is_owner_authenticated_and_marked_destructive() {
        let router = WalletMcpServer::tool_router();
        let tool = router.get("wallet_add_network").unwrap();
        assert_eq!(
            tool.annotations.as_ref().unwrap().destructive_hint,
            Some(true)
        );
        assert!(tool.description.as_deref().unwrap().contains("OS owner"));
    }

    #[tokio::test]
    async fn network_add_authenticates_before_contacting_the_proposed_rpc() {
        let (_directory, mut server) = server();
        server.human_presence = Arc::new(TestHumanPresence { allow: false });
        let result = server
            .wallet_add_network(Parameters(AddNetworkInput {
                name: "untrusted-test".into(),
                display_name: "Untrusted Test".into(),
                aliases: vec!["untrusted-testnet".into()],
                chain_id: "999999".into(),
                rpc_url: "http://127.0.0.1:9".parse().unwrap(),
                max_gas_limit: "30000000".into(),
                native_currency: NativeCurrency {
                    name: "Test Ether".into(),
                    symbol: "TETH".into(),
                    decimals: 18,
                },
                block_explorer_url: "https://explorer.example.invalid".parse().unwrap(),
                documentation_url: "https://docs.example.invalid".parse().unwrap(),
            }))
            .await;
        let Err(error) = result else {
            panic!("denied owner authentication unexpectedly succeeded");
        };
        assert!(error.message.contains("owner did not authorize"));
    }

    #[test]
    fn startup_fails_closed_when_a_configured_wallet_has_no_policy() {
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigStore::new(directory.path());
        let mut state = config.load().unwrap();
        state.wallets.push(WalletMetadata {
            id: "orphan".into(),
            address: Address::repeat_byte(0x22),
            created_at: Utc::now(),
            source: WalletSource::Created,
            custody: CustodyStatus::Sealed,
            exported_at: None,
        });
        config.save(&state).unwrap();
        let policies = PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([5; 32]),
        )
        .unwrap();
        let pending_database = PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([5; 32]),
        )
        .unwrap();
        let typed_data_database = PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([5; 32]),
        )
        .unwrap();
        let result = WalletMcpServer::new(
            config,
            policies,
            PendingStore::new(pending_database),
            TypedDataStore::new(typed_data_database),
        );
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("has no policy"));
    }

    fn permit_payload() -> serde_json::Value {
        serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Permit": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "Test Token",
                "chainId": 1,
                "verifyingContract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            },
            "message": {
                "owner": "0x1111111111111111111111111111111111111111",
                "spender": "0x2222222222222222222222222222222222222222",
                "value": "1000000",
                "nonce": "0",
                "deadline": "1900000000"
            }
        })
    }

    #[test]
    fn every_tool_except_legal_is_gated_on_acceptance() {
        let (_directory, server) = server();
        for tool in WalletMcpServer::sanitized_tool_router().list_all() {
            let gated = server.tool_gate(&tool.name).is_err();
            assert_eq!(
                gated,
                tool.name != "wallet_get_legal",
                "unexpected gate state for {}",
                tool.name
            );
        }
        accept_legal(&server);
        for tool in WalletMcpServer::sanitized_tool_router().list_all() {
            assert!(server.tool_gate(&tool.name).is_ok());
        }
    }

    #[tokio::test]
    async fn signing_tools_fail_closed_until_legal_acceptance() {
        let (_directory, server) = server();
        let result = server
            .wallet_send_native_transfers(Parameters(NativeTransfersInput {
                wallet_id: "primary".into(),
                chain_id: "1".into(),
                transfers: vec![NativeTransfer {
                    to: Address::from_str("0x2222222222222222222222222222222222222222").unwrap(),
                    amount_wei: DecimalU256::new("1").unwrap(),
                }],
            }))
            .await;
        let Err(error) = result else {
            panic!("send unexpectedly bypassed the legal acceptance gate");
        };
        assert!(error.message.contains("legal accept"));

        let result = server.wallet_sign_typed_data(Parameters(SignTypedDataInput {
            wallet_id: "primary".into(),
            typed_data: permit_payload(),
        }));
        let Err(error) = result else {
            panic!("typed-data signing unexpectedly bypassed the legal acceptance gate");
        };
        assert!(error.message.contains("legal accept"));
    }

    fn order_payload() -> serde_json::Value {
        serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Order": [
                    {"name": "maker", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ]
            },
            "primaryType": "Order",
            "domain": {
                "name": "Test Exchange",
                "chainId": 1,
                "verifyingContract": "0x4444444444444444444444444444444444444444"
            },
            "message": {
                "maker": "0x1111111111111111111111111111111111111111",
                "amount": "5"
            }
        })
    }

    #[test]
    fn unrecognized_typed_data_queues_for_human_approval_and_never_signs_inline() {
        let (_directory, server) = server();
        accept_legal(&server);
        // The wallet policy is allow-all, but a payload that is not a
        // recognized permit cannot be policy-evaluated and must queue.
        let Json(output) = server
            .wallet_sign_typed_data(Parameters(SignTypedDataInput {
                wallet_id: "primary".into(),
                typed_data: order_payload(),
            }))
            .unwrap();
        assert_eq!(output.status, TypedDataStatus::AwaitingApproval);
        assert!(output.approval_required);
        assert_eq!(output.chain_id, "1");
        assert!(output.signature.is_none());
        assert!(output.permit_approvals.is_none());
        assert!(
            output
                .instruction
                .as_deref()
                .unwrap()
                .contains("ekubo-wallet approve")
        );

        // A duplicate payload reuses the pending request.
        let Json(duplicate) = server
            .wallet_sign_typed_data(Parameters(SignTypedDataInput {
                wallet_id: "primary".into(),
                typed_data: order_payload(),
            }))
            .unwrap();
        assert_eq!(duplicate.request_id, output.request_id);

        // A chain the server does not know is rejected outright.
        let mut foreign = order_payload();
        foreign["domain"]["chainId"] = serde_json::json!(999_999);
        assert!(
            server
                .wallet_sign_typed_data(Parameters(SignTypedDataInput {
                    wallet_id: "primary".into(),
                    typed_data: foreign,
                }))
                .is_err()
        );
    }

    #[test]
    fn policy_denied_permits_queue_with_findings_instead_of_signing() {
        let (_directory, server) = server();
        accept_legal(&server);
        {
            let mut policies = server.policies.lock().unwrap();
            let current = policies.get("primary").unwrap().unwrap();
            policies
                .put(
                    "primary",
                    &WalletPolicy::require_approval_for_everything(),
                    Some(current.revision),
                )
                .unwrap();
        }
        let Json(output) = server
            .wallet_sign_typed_data(Parameters(SignTypedDataInput {
                wallet_id: "primary".into(),
                typed_data: permit_payload(),
            }))
            .unwrap();
        // The permit is recognized and interpreted as an approval, but the
        // deny-all policy queues it for human review instead of signing.
        assert_eq!(output.status, TypedDataStatus::AwaitingApproval);
        assert!(output.approval_required);
        assert!(output.signature.is_none());
        let approvals = output.permit_approvals.as_deref().unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].kind, "erc2612_permit");
        assert!(
            output
                .policy_findings
                .iter()
                .any(|finding| finding.code == "approval_spender_not_allowed")
        );
    }

    #[test]
    fn legal_tool_reports_status_and_document_text() {
        let (_directory, server) = server();
        let Json(output) = server
            .wallet_get_legal(Parameters(LegalInput {
                document: Some(LegalDocument::PrivacyPolicy),
            }))
            .unwrap();
        assert!(!output.status.signing_allowed);
        assert!(output.instruction.contains("legal accept"));
        let document = output.document.unwrap();
        assert!(document.text.contains("RPC"));
        assert_eq!(document.digest, LegalDocument::PrivacyPolicy.digest());

        accept_legal(&server);
        let Json(output) = server
            .wallet_get_legal(Parameters(LegalInput { document: None }))
            .unwrap();
        assert!(output.status.signing_allowed);
        assert!(output.document.is_none());
    }

    #[test]
    fn address_book_tool_is_lookup_only() {
        let (_directory, server) = server();
        let Json(empty) = server
            .wallet_address_book(Parameters(AddressBookInput {
                chain_id: None,
                alias: None,
                limit: 10,
                offset: 0,
            }))
            .unwrap();
        assert_eq!(empty.total, 0);

        // Entries written by the CLI store are visible read-only.
        let mut store = AddressBookStore::production(server.config.data_dir()).unwrap();
        store
            .upsert(
                1,
                "alice",
                Address::from_str("0x3333333333333333333333333333333333333333").unwrap(),
                Some("payroll"),
            )
            .unwrap();
        let Json(found) = server
            .wallet_address_book(Parameters(AddressBookInput {
                chain_id: Some(crate::token_store::ChainIdInput::Number(1)),
                alias: Some("alice".into()),
                limit: 10,
                offset: 0,
            }))
            .unwrap();
        assert_eq!(found.total, 1);
        assert_eq!(found.entries[0].note.as_deref(), Some("payroll"));

        // Alias lookup without a chain is ambiguous and rejected.
        assert!(
            server
                .wallet_address_book(Parameters(AddressBookInput {
                    chain_id: None,
                    alias: Some("alice".into()),
                    limit: 10,
                    offset: 0,
                }))
                .is_err()
        );

        // The MCP router exposes no mutation tool for the address book.
        let router = WalletMcpServer::tool_router();
        let tool = router.get("wallet_address_book").unwrap();
        assert_eq!(
            tool.annotations.as_ref().unwrap().read_only_hint,
            Some(true)
        );
    }

    #[test]
    fn server_advertises_the_security_resource_and_rpc_simulation_boundary() {
        let (_directory, server) = server();
        let info = ServerHandler::get_info(&server);
        assert!(info.capabilities.resources.is_some());
        assert!(info.capabilities.tools.is_some());
        assert!(SECURITY_MODEL.contains("eth_simulateV1"));
        assert!(SECURITY_MODEL.contains("no local fork"));
        assert!(SECURITY_MODEL.contains("eth_getProof"));
    }
}
