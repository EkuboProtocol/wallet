//! Long-lived application authority and compile-time capability surfaces.

use crate::{
    events::{DomainEventKind, EventBus},
    mcp::{GlobalAgentQuota, WalletMcpServer},
};
use alloy::primitives::{Address, B256, U256, keccak256};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use ekubo_wallet_core::{
    approval::{
        ApprovalKind, ApprovalRequest, ApprovalSectionKind, ReviewDocument, ReviewPresenter,
    },
    approval_summary::{TokenMetadataMap, format_fixed_point, interpret_steps, plan_token_targets},
    config::{ConfigStore, NetworkConfig, WalletConfig, WalletMetadata},
    core::policy::WalletPolicy,
    custody::{CustodyService, OsKeyStore, PrivateKeyMaterial},
    desktop_store::{
        AgentKind, AppearancePreference, DesktopStore, McpClient, OAuthAuthorizationCode,
        OAuthSessionPreset, OAuthTokenPair,
    },
    execution::BroadcastResult,
    human_presence::{
        OwnerAuthorizationScope, PlatformHumanPresence, authorize_oauth_client, authorize_owner,
    },
    legal::{LegalDocument, LegalStatus, LegalStore, require_current_acceptance},
    message::{MessageStore, PendingMessage, describe_message},
    orchestrator::{
        ApprovalOutcome, approve_transaction, sign_reviewed_message, sign_reviewed_typed_data,
    },
    pending::{PendingStatus, PendingStore, PendingTransaction},
    plan_fetch::{FetchPolicy, fetch_token_list_url},
    policy_store::{PolicyProposal, PolicyStore, StoredPolicy},
    reconcile::{attempt_cancellation, reconcile_record, submit_claimed},
    rpc::{ReceiptDetails, transaction_known, transaction_receipt_details},
    token_store::{
        ListedToken, MAX_PORTFOLIO_TOKENS, Portfolio, ProposalSource, ProposalSummary, StoredToken,
        TokenProposal, TokenStore, read_portfolio,
    },
    typed_data::{PendingTypedData, TypedDataStore, parse_typed_data},
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

fn contains_configured_chain(config: &WalletConfig, chain_id: u64) -> bool {
    config
        .networks
        .iter()
        .any(|network| network.chain_id == chain_id)
}

/// One owner account's balances across every configured network.
#[derive(Clone, Debug)]
pub struct OwnerPortfolioAccount {
    pub wallet: WalletMetadata,
    pub networks: Vec<OwnerPortfolioNetwork>,
}

/// A network read is isolated so one unavailable public RPC does not hide the
/// rest of the portfolio.
#[derive(Clone, Debug)]
pub struct OwnerPortfolioNetwork {
    pub network: NetworkConfig,
    pub result: std::result::Result<Portfolio, String>,
}

#[derive(Clone, Debug)]
pub struct OwnerPortfolioSnapshot {
    pub accounts: Vec<OwnerPortfolioAccount>,
}

#[derive(Clone, Debug)]
pub struct OwnerTokenListImport {
    pub source: String,
    pub host: String,
    pub declared_version: Option<String>,
    pub declared_timestamp: Option<String>,
    pub chains_selected: Vec<u64>,
    pub skipped_non_evm: usize,
    pub skipped_other_chain: usize,
    pub summary: ProposalSummary,
    pub proposals: Vec<TokenProposal>,
}

#[derive(Clone, Debug)]
pub struct OwnerTransactionAction {
    pub record: PendingTransaction,
    pub broadcast: Option<BroadcastResult>,
}

/// A human-readable, read-only inspection of one transaction lifecycle row.
///
/// The document is authored from the encrypted execution plan, owner-confirmed
/// token metadata, and (when available) the mined receipt. Receipt lookup does
/// not mutate wallet state or grant any capability.
#[derive(Clone, Debug)]
pub struct OwnerTransactionInspection {
    pub document: ReviewDocument,
    pub receipt_loaded: bool,
    pub receipt_error: Option<String>,
}

const MAX_DISPLAYED_RECEIPT_EVENTS: usize = 32;

#[derive(Clone, Copy, Debug, Default)]
struct ReceiptTokenFlow {
    incoming: U256,
    outgoing: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiptEffect {
    label: String,
    amount: String,
    /// Present only when the net figure above hides something.
    ///
    /// `amount` is the net change, so when a token moved one way this would
    /// restate it — "+0.187585 USDC" over "0.187585 USDC in, 0 USDC out" is
    /// the same fact twice, and the reader learns to skip the second line.
    /// When the wallet both sent and received the same token the net *does*
    /// hide the gross movement, and only then is there something to add.
    detail: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ReceiptPresentation {
    effects: Vec<ReceiptEffect>,
    events: Vec<(String, String)>,
    decoded: usize,
}

fn topic_address(topic: B256) -> Address {
    Address::from_slice(&topic.as_slice()[12..])
}

fn trusted_token_label(address: Address, metadata: &TokenMetadataMap) -> String {
    metadata
        .get(&address)
        .and_then(|token| token.symbol.as_deref())
        .map_or_else(
            || format!("{address:#x} (unlisted token)"),
            |symbol| format!("{symbol} ({address:#x})"),
        )
}

fn token_amount(amount: U256, address: Address, metadata: &TokenMetadataMap) -> String {
    let display = metadata.get(&address).cloned().unwrap_or_default();
    display.decimals.map_or_else(
        || format!("{amount} base units"),
        |decimals| {
            let amount = format_fixed_point(&amount.to_string(), decimals);
            display
                .symbol
                .map_or(amount.clone(), |symbol| format!("{amount} {symbol}"))
        },
    )
}

fn signed_token_amount(
    incoming: U256,
    outgoing: U256,
    address: Address,
    metadata: &TokenMetadataMap,
) -> String {
    let (sign, magnitude) = if incoming >= outgoing {
        ("+", incoming - outgoing)
    } else {
        ("-", outgoing - incoming)
    };
    format!("{sign}{}", token_amount(magnitude, address, metadata))
}

fn native_amount(value: U256, network: &NetworkConfig) -> String {
    let Some(currency) = network.native_currency.as_ref() else {
        return format!("{value} wei");
    };
    format!(
        "{} {}",
        format_fixed_point(&value.to_string(), currency.decimals),
        currency.symbol
    )
}

fn calldata_summary(data: &[u8]) -> String {
    if data.is_empty() {
        "none".to_owned()
    } else {
        format!(
            "{} bytes; selector 0x{}",
            data.len(),
            hex::encode(&data[..data.len().min(4)])
        )
    }
}

/// Decode the small set of standard receipt events whose meaning is stable
/// across contracts. Token names and decimal scales still come only from the
/// owner-confirmed token database; the contract is never trusted to name
/// itself.
fn receipt_presentation(
    wallet: Address,
    receipt: &ReceiptDetails,
    metadata: &TokenMetadataMap,
) -> ReceiptPresentation {
    let transfer = keccak256("Transfer(address,address,uint256)");
    let approval = keccak256("Approval(address,address,uint256)");
    let approval_for_all = keccak256("ApprovalForAll(address,address,bool)");
    let transfer_single = keccak256("TransferSingle(address,address,address,uint256,uint256)");
    let mut flows = std::collections::BTreeMap::<Address, ReceiptTokenFlow>::new();
    let mut events = Vec::new();
    let mut decoded = 0usize;

    for log in &receipt.logs {
        let Some(signature) = log.topics.first().copied() else {
            continue;
        };
        if signature == transfer && log.topics.len() == 3 && log.data.len() == 32 {
            let from = topic_address(log.topics[1]);
            let to = topic_address(log.topics[2]);
            let amount = U256::from_be_slice(&log.data);
            decoded += 1;
            if from == wallet || to == wallet {
                let flow = flows.entry(log.address).or_default();
                if from == wallet {
                    flow.outgoing = flow.outgoing.saturating_add(amount);
                }
                if to == wallet {
                    flow.incoming = flow.incoming.saturating_add(amount);
                }
                events.push((
                    "Token transfer".to_owned(),
                    format!(
                        "{} from {from:#x} to {to:#x}",
                        token_amount(amount, log.address, metadata)
                    ),
                ));
            }
        } else if signature == transfer && log.topics.len() == 4 && log.data.is_empty() {
            let from = topic_address(log.topics[1]);
            let to = topic_address(log.topics[2]);
            let token_id = U256::from_be_slice(log.topics[3].as_slice());
            decoded += 1;
            if from == wallet || to == wallet {
                events.push((
                    "NFT transfer".to_owned(),
                    format!(
                        "{} token #{token_id} from {from:#x} to {to:#x}",
                        trusted_token_label(log.address, metadata)
                    ),
                ));
            }
        } else if signature == approval && log.topics.len() == 3 && log.data.len() == 32 {
            let owner = topic_address(log.topics[1]);
            let spender = topic_address(log.topics[2]);
            decoded += 1;
            if owner == wallet {
                events.push((
                    "Token approval".to_owned(),
                    format!(
                        "Allowed {spender:#x} to spend {}",
                        token_amount(U256::from_be_slice(&log.data), log.address, metadata)
                    ),
                ));
            }
        } else if signature == approval_for_all && log.topics.len() == 3 && log.data.len() == 32 {
            let owner = topic_address(log.topics[1]);
            let operator = topic_address(log.topics[2]);
            decoded += 1;
            if owner == wallet {
                let enabled = U256::from_be_slice(&log.data) != U256::ZERO;
                events.push((
                    "Collection approval".to_owned(),
                    format!(
                        "{} operator access for {operator:#x} on {}",
                        if enabled { "Enabled" } else { "Removed" },
                        trusted_token_label(log.address, metadata)
                    ),
                ));
            }
        } else if signature == transfer_single && log.topics.len() == 4 && log.data.len() == 64 {
            let from = topic_address(log.topics[2]);
            let to = topic_address(log.topics[3]);
            decoded += 1;
            if from == wallet || to == wallet {
                let token_id = U256::from_be_slice(&log.data[..32]);
                let amount = U256::from_be_slice(&log.data[32..]);
                events.push((
                    "Multi-token transfer".to_owned(),
                    format!(
                        "{amount} of token #{token_id} on {} from {from:#x} to {to:#x}",
                        trusted_token_label(log.address, metadata)
                    ),
                ));
            }
        }
    }

    let effects = flows
        .into_iter()
        .map(|(token, flow)| ReceiptEffect {
            label: trusted_token_label(token, metadata),
            amount: signed_token_amount(flow.incoming, flow.outgoing, token, metadata),
            detail: (!flow.incoming.is_zero() && !flow.outgoing.is_zero()).then(|| {
                format!(
                    "{} received and {} sent; the figure above is the difference",
                    token_amount(flow.incoming, token, metadata),
                    token_amount(flow.outgoing, token, metadata)
                )
            }),
        })
        .collect();
    ReceiptPresentation {
        effects,
        events,
        decoded,
    }
}

async fn transaction_inspection_document(
    pending: &PendingTransaction,
    wallet: Address,
    network: &NetworkConfig,
    metadata: &TokenMetadataMap,
    transaction_hash: Option<&str>,
    receipt: Option<&ReceiptDetails>,
    receipt_error: Option<&str>,
) -> Result<ReviewDocument> {
    // A record that never reached a chain has no receipt to be missing, so it
    // is not told it is waiting for one.
    let reachable = pending.status.can_reach_a_chain();
    let summary = match receipt {
        Some(receipt) if receipt.succeeded => {
            "This transaction was mined successfully. Receipt-derived asset movements and decoded events are shown before the original calls."
        }
        Some(_) => {
            "This transaction was mined but reverted. No state changes from its calls were committed; the network fee was still paid."
        }
        None if !reachable => {
            "Nothing was signed and nothing was sent, so there is no receipt and never will be. The calls that were asked for are decoded below."
        }
        None => {
            "This lifecycle record has no readable mined receipt yet. The original calls are decoded below so the request remains understandable."
        }
    };
    let mut request = ApprovalRequest::new(ApprovalKind::Transaction, "Transaction", summary)
        .fact("Status", pending.status.label())
        .fact("Account", &pending.wallet_id)
        .fact("Network", network.display_label())
        .fact("Chain ID", &pending.chain_id)
        .fact("Sender", format!("{wallet:#x}"))
        .fact(
            "Plan source",
            pending
                .plan_source
                .as_deref()
                .unwrap_or("constructed locally by this wallet"),
        )
        .fact("Created", pending.created_at.to_string())
        .fact("Last updated", pending.updated_at.to_string())
        .fact("Policy revision", pending.policy_revision.to_string())
        .fact("Plan digest", &pending.digest);
    request.id = pending.request_id;
    if let Some(hash) = transaction_hash {
        request = request.fact("Transaction hash", hash);
    }

    // No receipt section at all for a record that cannot have one. It held a
    // single row reading "Receipt — Not available", under a heading promising
    // receipt-derived changes, on a request the wallet refused to sign.
    if reachable {
        request = request.section_kind(
            ApprovalSectionKind::Effects,
            "Receipt-derived wallet changes",
        );
    }
    if let Some(receipt) = receipt {
        let presentation = receipt_presentation(wallet, receipt, metadata);
        if receipt.succeeded {
            if presentation.effects.is_empty() {
                request = request.fact(
                    "Result",
                    "No wallet-directed ERC-20 Transfer events were present in this receipt.",
                );
            } else {
                for effect in presentation.effects {
                    request = request.fact(effect.label, effect.amount);
                    if let Some(detail) = effect.detail {
                        request = request.fact("", detail);
                    }
                }
            }
        } else {
            request = request.fact(
                "Result",
                "Reverted — the calls committed no token or permission changes.",
            );
        }
        request = request.fact(
            "Network fee",
            format!(
                "-{}",
                native_amount(
                    U256::from(receipt.gas_used)
                        .saturating_mul(U256::from(receipt.effective_gas_price)),
                    network,
                )
            ),
        );

        request = request.section_kind(ApprovalSectionKind::Details, "Decoded receipt events");
        if presentation.events.is_empty() {
            request = request.fact(
                "Result",
                "No wallet-relevant standard transfer or approval events were decoded.",
            );
        } else {
            for (label, value) in presentation
                .events
                .into_iter()
                .take(MAX_DISPLAYED_RECEIPT_EVENTS)
            {
                request = request.fact(label, value);
            }
        }
        request = request.fact(
            "Coverage",
            if receipt.logs.len() > MAX_DISPLAYED_RECEIPT_EVENTS {
                format!(
                    "Decoded {} of {} receipt logs; showing up to {MAX_DISPLAYED_RECEIPT_EVENTS} wallet-relevant events.",
                    presentation.decoded,
                    receipt.logs.len()
                )
            } else {
                format!(
                    "Decoded {} of {} receipt logs.",
                    presentation.decoded,
                    receipt.logs.len()
                )
            },
        );
        if !receipt.logs.is_empty() {
            request = request.warning("Standard token events are decoded locally from the receipt. They are useful evidence, but unusual contracts can omit or emit misleading events, so this is not a complete archival state diff.");
        }
    } else if reachable {
        request = request.fact("Receipt", "Not available");
    }

    let interpretations = interpret_steps(&pending.execution_plan.ordered_steps, metadata).await;
    for (step, interpretation) in pending
        .execution_plan
        .ordered_steps
        .iter()
        .zip(interpretations)
    {
        request = request
            .section_kind(ApprovalSectionKind::Action, format!("Call {}", step.step))
            .fact(
                "What it does",
                interpretation.description.unwrap_or_else(|| {
                    "Unrecognized contract call — verify the target and exact calldata.".to_owned()
                }),
            )
            .fact("Target", format!("{:#x}", step.transaction.to))
            .fact(
                "Native value",
                native_amount(
                    step.transaction
                        .value
                        .as_str()
                        .parse::<U256>()
                        .unwrap_or_default(),
                    network,
                ),
            );
        // Only when the step is one the reader did not ask for; see
        // `ExecutionStepKind::reason`.
        if let Some(reason) = step.kind.reason() {
            request = request.fact("Why this call is here", reason);
        }
        for detail in interpretation.details {
            request = request.fact("·", detail);
        }
        request = request.fact("Calldata", calldata_summary(&step.transaction.data));
        for warning in interpretation.warnings {
            request = request.warning(warning);
        }
    }

    if let Some(receipt) = receipt {
        request = request
            .section_kind(ApprovalSectionKind::Fees, "Mined receipt")
            .fact(
                "Outcome",
                if receipt.succeeded {
                    "Succeeded"
                } else {
                    "Reverted"
                },
            )
            .fact("Block", receipt.block_number.to_string())
            .fact("Block hash", format!("{:#x}", receipt.block_hash))
            .fact("Gas used", receipt.gas_used.to_string())
            .fact(
                "Effective gas price",
                format!("{} wei", receipt.effective_gas_price),
            )
            .fact(
                "Actual network fee",
                native_amount(
                    U256::from(receipt.gas_used)
                        .saturating_mul(U256::from(receipt.effective_gas_price)),
                    network,
                ),
            );
    }
    if let Some(error) = receipt_error {
        request = request.warning(format!(
            "The latest receipt lookup failed: {error}. Retry inspection to query another configured RPC."
        ));
    }
    if let Some(review_digest) = pending.review_digest.as_deref() {
        request = request.fact("Review digest", review_digest);
    }

    let exact_plan = serde_json::to_string_pretty(&pending.execution_plan)
        .context("failed to render exact execution plan")?;
    Ok(ReviewDocument::from_request(request, vec![exact_plan]))
}

/// One durable owner-visible activity record. Signature requests remain in
/// the audit trail after approval or rejection just like transactions do.
#[derive(Clone, Debug)]
pub enum OwnerActivityRecord {
    Transaction(Box<PendingTransaction>),
    Message(PendingMessage),
    TypedData(PendingTypedData),
}

impl OwnerActivityRecord {
    #[must_use]
    pub const fn request_id(&self) -> Uuid {
        match self {
            Self::Transaction(record) => record.request_id,
            Self::Message(record) => record.request_id,
            Self::TypedData(record) => record.request_id,
        }
    }

    fn created_at(&self) -> DateTime<Utc> {
        match self {
            Self::Transaction(record) => record.created_at,
            Self::Message(record) => record.created_at,
            Self::TypedData(record) => record.created_at,
        }
    }
}

/// The restricted capability cloned into authenticated MCP sessions.
///
/// It intentionally exposes only server construction. Account custody,
/// approvals, policy installation, exports, and client registration are not
/// methods on this type and therefore cannot be reached from an MCP handler.
#[derive(Clone)]
pub struct AgentApi {
    config: ConfigStore,
    desktop: Arc<Mutex<DesktopStore>>,
    global_quota: Arc<Mutex<GlobalAgentQuota>>,
    events: EventBus,
}

impl AgentApi {
    pub(crate) fn server(&self, client_id: Uuid) -> Result<WalletMcpServer> {
        WalletMcpServer::production(
            self.config.clone(),
            client_id,
            self.desktop.clone(),
            self.global_quota.clone(),
            self.events.clone(),
        )
    }
}

/// Owner-only operations. Only the GPUI application receives this value.
#[derive(Clone)]
pub struct OwnerApi {
    config: ConfigStore,
    desktop: Arc<Mutex<DesktopStore>>,
    events: EventBus,
}

#[derive(Clone, Debug)]
pub struct OwnerReviewQueues {
    pub transactions: Vec<PendingTransaction>,
    pub typed_data: Vec<PendingTypedData>,
    pub messages: Vec<PendingMessage>,
    pub policy_proposals: Vec<PolicyProposal>,
    pub network_proposals: Vec<NetworkConfig>,
    pub token_proposals: Vec<TokenProposal>,
}

fn transaction_observation_changed(
    before: &PendingTransaction,
    after: &PendingTransaction,
) -> bool {
    before.status != after.status || (before.finalized_at.is_none() && after.finalized_at.is_some())
}

impl OwnerApi {
    /// An owner capability over a throwaway database, for tests only.
    ///
    /// `ApplicationAuthority::open` deliberately goes straight to
    /// `DesktopStore::production`, so the real authority can only ever be
    /// built on the keychain-backed database — which is also why nothing could
    /// lay out a `WalletWindow` in a test. This is the same `#[cfg(test)]`
    /// escape the core crate already uses for `plan_fetch::insecure_for_tests`
    /// and `clear_signing::stake_fixture`: it exists only in a test build of
    /// this crate, it takes an explicit key rather than reading one, and no
    /// release binary contains it.
    #[cfg(test)]
    pub(crate) fn for_test(data_dir: &std::path::Path) -> Result<Self> {
        use ekubo_wallet_core::policy_store::{DATABASE_FILE, DatabaseKey};

        let key = DatabaseKey::new([0x43; 32]);
        let desktop = DesktopStore::open(&data_dir.join(DATABASE_FILE), &key)?;
        Ok(Self {
            config: ConfigStore::new(data_dir),
            desktop: Arc::new(Mutex::new(desktop)),
            events: EventBus::default(),
        })
    }

    fn desktop(&self) -> Result<std::sync::MutexGuard<'_, DesktopStore>> {
        self.desktop
            .lock()
            .map_err(|_| anyhow::anyhow!("desktop database lock was poisoned"))
    }

    pub fn snapshot(&self) -> Result<WalletConfig> {
        self.config.load()
    }

    pub fn accounts(&self) -> Result<Vec<WalletMetadata>> {
        Ok(self.config.load()?.wallets)
    }

    pub fn account(&self, wallet_id: &str) -> Result<WalletMetadata> {
        self.config.wallet(wallet_id)
    }

    pub fn create_account(&self, wallet_id: &str, policy: &WalletPolicy) -> Result<WalletMetadata> {
        let custody = CustodyService::new(
            self.config.clone(),
            Arc::new(OsKeyStore),
            Arc::new(PlatformHumanPresence),
        );
        let wallet = custody.create_with_policy(wallet_id, policy)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(wallet)
    }

    pub fn import_account(
        &self,
        wallet_id: &str,
        key: PrivateKeyMaterial,
    ) -> Result<WalletMetadata> {
        let custody = CustodyService::new(
            self.config.clone(),
            Arc::new(OsKeyStore),
            Arc::new(PlatformHumanPresence),
        );
        let wallet = custody.import_with_policy(
            wallet_id,
            key,
            &WalletPolicy::require_approval_for_everything(),
        )?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(wallet)
    }

    async fn export_account(&self, wallet_id: &str) -> Result<zeroize::Zeroizing<String>> {
        let expected = self.config.wallet(wallet_id)?.address;
        CustodyService::new(
            self.config.clone(),
            Arc::new(OsKeyStore),
            Arc::new(PlatformHumanPresence),
        )
        .export(wallet_id, expected)
        .await
    }

    pub async fn begin_private_key_export(&self, wallet_id: &str) -> Result<ExportLease> {
        Ok(ExportLease::new(self.export_account(wallet_id).await?))
    }

    pub fn account_removal_document(&self, wallet_id: &str) -> Result<ReviewDocument> {
        let wallet = self.config.wallet(wallet_id)?;
        let in_flight =
            PolicyStore::production(self.config.data_dir())?.in_flight_transactions(wallet_id)?;
        let mut request = ApprovalRequest::new(
            ApprovalKind::RemoveWallet,
            "Remove account",
            "Delete this account's platform credential, local metadata, policy, and queued requests.",
        )
        .fact("Account", &wallet.id)
        .fact("Address", format!("{:#x}", wallet.address))
        .warning("This cannot be undone unless you have a separate private-key backup.");
        for transaction in in_flight {
            request = request.warning(format!(
                "A transaction on chain {} has not settled yet. It may still reach the chain, and removing this account deletes the only local copy of its signed bytes along with everything used to track it.",
                transaction.chain_id
            ));
        }
        Ok(ReviewDocument::from_request(request, Vec::new()))
    }

    pub async fn remove_account(&self, wallet_id: &str) -> Result<WalletMetadata> {
        let removed = CustodyService::new(
            self.config.clone(),
            Arc::new(OsKeyStore),
            Arc::new(PlatformHumanPresence),
        )
        .remove(wallet_id)
        .await?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(removed)
    }

    pub fn register_oauth_client(
        &self,
        name: &str,
        kind: AgentKind,
        redirect_uris: &[String],
        managed_registration: Option<&serde_json::Value>,
    ) -> Result<McpClient> {
        self.desktop()?
            .register_oauth_client(name, kind, redirect_uris, managed_registration)
    }

    pub async fn authorize_oauth_client(
        &self,
        client_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scope: &str,
        resource: &str,
        session_preset: OAuthSessionPreset,
    ) -> Result<OAuthAuthorizationCode> {
        let client = self.desktop()?.validate_oauth_authorization_request(
            client_id,
            redirect_uri,
            code_challenge,
            scope,
            resource,
        )?;
        self.events
            .publish(DomainEventKind::OAuthAuthorizationRequested { client_id });
        tokio::task::yield_now().await;
        require_current_acceptance(self.config.data_dir())?;
        let authorization = authorize_oauth_client(&client.display_name, redirect_uri).await?;
        let code = self.desktop()?.issue_authorization_code_with_session(
            client_id,
            redirect_uri,
            code_challenge,
            scope,
            resource,
            session_preset,
            &authorization,
        )?;
        if let Err(launch_error) = crate::launch_at_login::enable(&authorization) {
            // The authorization code has not left this process yet. Revoke
            // the just-created grant before reporting the persistence failure
            // so a caller cannot exchange the code after an incomplete grant.
            let rollback = self.desktop()?.revoke_client(client_id);
            self.events
                .publish(DomainEventKind::AgentConnectionChanged { client_id });
            if let Err(rollback) = rollback {
                return Err(launch_error).context(format!(
                    "launch-at-login setup failed and the new agent grant could not be revoked: \
                     {rollback:#}"
                ));
            }
            return Err(launch_error)
                .context("new agent grant was revoked because launch-at-login setup failed");
        }
        self.events
            .publish(DomainEventKind::AgentConnectionChanged { client_id });
        Ok(code)
    }

    pub fn validate_oauth_authorization_request(
        &self,
        client_id: Uuid,
        redirect_uri: &str,
        code_challenge: &str,
        scope: &str,
        resource: &str,
    ) -> Result<McpClient> {
        self.desktop()?.validate_oauth_authorization_request(
            client_id,
            redirect_uri,
            code_challenge,
            scope,
            resource,
        )
    }

    pub fn exchange_oauth_code(
        &self,
        code: &str,
        client_id: Uuid,
        redirect_uri: &str,
        code_verifier: &str,
        resource: &str,
    ) -> Result<OAuthTokenPair> {
        self.desktop()?.exchange_authorization_code(
            code,
            client_id,
            redirect_uri,
            code_verifier,
            resource,
        )
    }

    pub fn refresh_oauth_token(
        &self,
        refresh_token: &str,
        client_id: Uuid,
        resource: &str,
    ) -> Result<OAuthTokenPair> {
        self.desktop()?
            .refresh_access_token(refresh_token, client_id, resource)
    }

    pub fn revoke_client(&self, client_id: Uuid) -> Result<()> {
        let mut desktop = self.desktop()?;
        desktop.revoke_client(client_id)?;
        let any_active = desktop
            .clients()?
            .iter()
            .any(|client| client.authorized_at.is_some() && client.revoked_at.is_none());
        drop(desktop);
        self.events
            .publish(DomainEventKind::AgentConnectionChanged { client_id });
        if !any_active {
            crate::launch_at_login::disable().context(
                "agent access was revoked, but launch-at-login persistence could not be removed",
            )?;
        }
        Ok(())
    }

    pub fn remove_client(&self, client_id: Uuid) -> Result<()> {
        let mut desktop = self.desktop()?;
        desktop.remove_client(client_id)?;
        let any_active = desktop
            .clients()?
            .iter()
            .any(|client| client.authorized_at.is_some() && client.revoked_at.is_none());
        drop(desktop);
        self.events
            .publish(DomainEventKind::AgentConnectionChanged { client_id });
        if !any_active {
            crate::launch_at_login::disable().context(
                "agent registration was removed, but launch-at-login persistence could not be removed",
            )?;
        }
        Ok(())
    }

    pub fn clients(&self) -> Result<Vec<McpClient>> {
        self.desktop()?.clients()
    }

    pub fn detailed_notification_previews(&self) -> Result<bool> {
        self.desktop()?.detailed_notification_previews()
    }

    pub async fn set_detailed_notification_previews(&self, enabled: bool) -> Result<()> {
        let authorization = authorize_owner(OwnerAuthorizationScope::NotificationPrivacy).await?;
        self.desktop()?
            .set_detailed_notification_previews(enabled, &authorization)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    pub fn appearance_preference(&self) -> Result<AppearancePreference> {
        self.desktop()?.appearance_preference()
    }

    pub fn set_appearance_preference(&self, preference: AppearancePreference) -> Result<()> {
        self.desktop()?.set_appearance_preference(preference)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    pub fn testnet_mode(&self) -> Result<bool> {
        self.desktop()?.testnet_mode()
    }

    pub fn set_testnet_mode(&self, enabled: bool) -> Result<()> {
        self.desktop()?.set_testnet_mode(enabled)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    pub fn policy(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        let wallet = self.account(wallet_id)?;
        PolicyStore::production(self.config.data_dir())?.get_for_wallet(wallet_id, wallet.address)
    }

    pub async fn install_policy(
        &self,
        wallet_id: &str,
        policy: &WalletPolicy,
        reviewed_revision: Option<u64>,
    ) -> Result<StoredPolicy> {
        let wallet = self.account(wallet_id)?;
        let before = self.policy(wallet_id)?;
        ensure_optional_revision(
            reviewed_revision,
            before.as_ref().map(|policy| policy.revision),
        )?;
        let baseline = WalletPolicy::require_approval_for_everything();
        let current = before.as_ref().map_or(&baseline, |stored| &stored.policy);
        let authorization = if crate::core::policy::is_tightening(current, policy) {
            None
        } else {
            Some(authorize_owner(OwnerAuthorizationScope::PolicySettings).await?)
        };
        let mut store = PolicyStore::production(self.config.data_dir())?;
        let current = store.get_for_wallet(wallet_id, wallet.address)?;
        ensure_optional_revision(
            reviewed_revision,
            current.as_ref().map(|policy| policy.revision),
        )?;
        let installed = store.install_policy(
            wallet_id,
            wallet.address,
            policy,
            reviewed_revision,
            authorization.as_ref(),
        )?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(installed)
    }

    pub fn policy_proposals(&self) -> Result<Vec<PolicyProposal>> {
        PolicyStore::production(self.config.data_dir())?.list_proposals()
    }

    pub async fn apply_policy_proposal(&self, proposal: &PolicyProposal) -> Result<StoredPolicy> {
        let wallet = self.account(&proposal.wallet_id)?;
        ensure!(
            wallet.address == proposal.wallet_address,
            "the proposal belongs to a predecessor wallet identity"
        );
        let before = PolicyStore::production(self.config.data_dir())?
            .proposal(&proposal.wallet_id)?
            .context("the policy proposal no longer exists")?;
        ensure!(
            before == *proposal,
            "the policy proposal changed before authentication; review it again"
        );
        let current = self
            .policy(&proposal.wallet_id)?
            .context("the wallet has no active policy")?;
        let authorization = if crate::core::policy::is_tightening(&current.policy, &proposal.policy)
        {
            None
        } else {
            Some(authorize_owner(OwnerAuthorizationScope::PolicySettings).await?)
        };
        let mut store = PolicyStore::production(self.config.data_dir())?;
        let installed = store.apply_proposal(proposal, authorization.as_ref())?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(installed)
    }

    pub fn reject_policy_proposal(&self, proposal: &PolicyProposal) -> Result<bool> {
        let removed = PolicyStore::production(self.config.data_dir())?.delete_proposal(proposal)?;
        if removed {
            self.events.publish(DomainEventKind::ConfigurationChanged);
        }
        Ok(removed)
    }

    pub fn networks(&self) -> Result<Vec<NetworkConfig>> {
        Ok(self.config.load()?.networks)
    }

    pub fn network_by_chain_id(&self, chain_id: u64) -> Result<NetworkConfig> {
        self.config.network_by_chain_id(&chain_id.to_string())
    }

    /// Read accounts on all enabled configured networks with bounded
    /// concurrency. Each network is block-pinned by the same core path exposed
    /// to agents, and one read's failure does not hide the others.
    ///
    /// `wallet_id` restricts the read to a single account. The desktop viewer
    /// shows one account at a time, and reading the accounts nobody is looking
    /// at multiplies the RPC calls a refresh costs by the account count.
    pub async fn portfolio(&self, wallet_id: Option<&str>) -> Result<OwnerPortfolioSnapshot> {
        use futures::{StreamExt as _, stream};

        let mut snapshot = self.config.load()?;
        let testnet_mode = self.testnet_mode()?;
        snapshot
            .networks
            .retain(|network| !network.disabled && (testnet_mode || !network.testnet));
        ensure!(
            !snapshot.networks.is_empty(),
            "there are no enabled configured networks"
        );
        if let Some(wallet_id) = wallet_id {
            snapshot.wallets.retain(|wallet| wallet.id == wallet_id);
            ensure!(!snapshot.wallets.is_empty(), "unknown account {wallet_id}");
        }
        let token_store = TokenStore::production(self.config.data_dir())?;
        let mut known_by_chain = std::collections::BTreeMap::new();
        for network in &snapshot.networks {
            known_by_chain.insert(
                network.chain_id,
                token_store.list(
                    Some(network.chain_id),
                    MAX_PORTFOLIO_TOKENS.saturating_add(1),
                    0,
                )?,
            );
        }

        let mut accounts: Vec<OwnerPortfolioAccount> = snapshot
            .wallets
            .iter()
            .cloned()
            .map(|wallet| OwnerPortfolioAccount {
                wallet,
                networks: Vec::with_capacity(snapshot.networks.len()),
            })
            .collect();
        let mut jobs = Vec::with_capacity(
            snapshot
                .wallets
                .len()
                .saturating_mul(snapshot.networks.len()),
        );
        for (account_index, wallet) in snapshot.wallets.into_iter().enumerate() {
            for (network_index, network) in snapshot.networks.iter().cloned().enumerate() {
                let known = known_by_chain
                    .get(&network.chain_id)
                    .cloned()
                    .unwrap_or_default();
                jobs.push((account_index, network_index, wallet.address, network, known));
            }
        }
        let mut reads = stream::iter(jobs)
            .map(
                |(account_index, network_index, address, network, known)| async move {
                    let result = read_portfolio(&network, address, &known, None)
                        .await
                        .map_err(|error| {
                            ekubo_wallet_core::sanitize::stripped_capped(&format!("{error:#}"), 500)
                        });
                    (
                        account_index,
                        network_index,
                        OwnerPortfolioNetwork { network, result },
                    )
                },
            )
            .buffer_unordered(6)
            .collect::<Vec<_>>()
            .await;
        reads.sort_by_key(|(account_index, network_index, _)| (*account_index, *network_index));
        for (account_index, _, network) in reads {
            accounts[account_index].networks.push(network);
        }
        Ok(OwnerPortfolioSnapshot { accounts })
    }

    pub async fn install_network(&self, network: NetworkConfig) -> Result<()> {
        ekubo_wallet_core::config::validate_network(&network)?;
        ekubo_wallet_core::rpc::verify_chain_id(&network).await?;
        let authorization = authorize_owner(OwnerAuthorizationScope::NetworkSettings).await?;
        self.config.install_network(network, &authorization)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    /// Create a new network without allowing the form to overwrite a row that
    /// appeared while owner authentication was in progress.
    pub async fn add_network(&self, network: NetworkConfig) -> Result<()> {
        ekubo_wallet_core::config::validate_network(&network)?;
        ekubo_wallet_core::rpc::verify_chain_id(&network).await?;
        let authorization = authorize_owner(OwnerAuthorizationScope::NetworkSettings).await?;
        self.config.add_network(network, &authorization)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    /// Save an edit only if the encrypted network row is still byte-for-byte
    /// the row the owner opened.
    pub async fn replace_network(
        &self,
        reviewed: &NetworkConfig,
        replacement: NetworkConfig,
    ) -> Result<()> {
        ekubo_wallet_core::config::validate_network(&replacement)?;
        ekubo_wallet_core::rpc::verify_chain_id(&replacement).await?;
        let authorization = authorize_owner(OwnerAuthorizationScope::NetworkSettings).await?;
        self.config
            .replace_network(reviewed, replacement, &authorization)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    pub async fn reset_networks_to_defaults(
        &self,
        reviewed_networks: &[NetworkConfig],
    ) -> Result<Vec<NetworkConfig>> {
        let authorization = authorize_owner(OwnerAuthorizationScope::NetworkSettings).await?;
        let networks = self
            .config
            .reset_networks_to_defaults(reviewed_networks, &authorization)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(networks)
    }

    pub async fn set_network_disabled(
        &self,
        reviewed: &NetworkConfig,
        disabled: bool,
    ) -> Result<NetworkConfig> {
        let authorization = if disabled {
            None
        } else {
            Some(authorize_owner(OwnerAuthorizationScope::NetworkSettings).await?)
        };
        let updated =
            self.config
                .set_network_disabled(reviewed, disabled, authorization.as_ref())?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(updated)
    }

    pub fn network_proposals(&self) -> Result<Vec<NetworkConfig>> {
        PolicyStore::production(self.config.data_dir())?.network_proposals()
    }

    pub async fn accept_network_proposal(&self, proposal: &NetworkConfig) -> Result<()> {
        let before = PolicyStore::production(self.config.data_dir())?
            .network_proposal(proposal.chain_id)?
            .context("the network proposal no longer exists")?;
        ensure!(
            before == *proposal,
            "the network proposal changed; review the current profile"
        );
        ekubo_wallet_core::config::validate_network(proposal)?;
        ekubo_wallet_core::rpc::verify_chain_id(proposal).await?;
        let authorization = authorize_owner(OwnerAuthorizationScope::NetworkSettings).await?;
        let current = PolicyStore::production(self.config.data_dir())?
            .network_proposal(proposal.chain_id)?
            .context("the network proposal no longer exists")?;
        ensure!(
            current == *proposal,
            "the network proposal changed during confirmation; review it again"
        );
        self.config
            .install_network(proposal.clone(), &authorization)?;
        let removed =
            PolicyStore::production(self.config.data_dir())?.discard_network_proposal(proposal)?;
        ensure!(
            removed,
            "the installed network proposal could not be consumed"
        );
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    pub fn reject_network_proposal(&self, proposal: &NetworkConfig) -> Result<bool> {
        let removed =
            PolicyStore::production(self.config.data_dir())?.discard_network_proposal(proposal)?;
        if removed {
            self.events.publish(DomainEventKind::ConfigurationChanged);
        }
        Ok(removed)
    }

    pub fn transactions(
        &self,
        wallet_id: Option<&str>,
        limit: u16,
    ) -> Result<Vec<PendingTransaction>> {
        PendingStore::production(self.config.data_dir())?.list(wallet_id, limit)
    }

    /// Recent transactions and human-reviewed signatures, interleaved by the
    /// moment they were queued. Every source is read from the encrypted owner
    /// database and terminal signature decisions remain visible.
    pub fn activity(
        &self,
        wallet_id: Option<&str>,
        limit: u16,
    ) -> Result<Vec<OwnerActivityRecord>> {
        ensure!(
            (1..=1_000).contains(&limit),
            "limit must be between 1 and 1000"
        );
        let mut records = self
            .transactions(wallet_id, limit)?
            .into_iter()
            .map(Box::new)
            .map(OwnerActivityRecord::Transaction)
            .collect::<Vec<_>>();
        records.extend(
            MessageStore::production(self.config.data_dir())?
                .list(wallet_id, limit)?
                .into_iter()
                .map(OwnerActivityRecord::Message),
        );
        records.extend(
            TypedDataStore::production(self.config.data_dir())?
                .list(wallet_id, limit)?
                .into_iter()
                .map(OwnerActivityRecord::TypedData),
        );
        records.sort_by(|left, right| {
            right
                .created_at()
                .cmp(&left.created_at())
                .then_with(|| right.request_id().cmp(&left.request_id()))
        });
        records.truncate(usize::from(limit));
        Ok(records)
    }

    /// The agent that asked for each record, by request ID.
    ///
    /// Read for the owner's activity list and nowhere else. It is deliberately
    /// not folded into `PendingTransaction`: that type is an agent-facing
    /// schema, and who else is talking to this wallet is not something one
    /// agent gets to read off another's request.
    pub fn activity_sources(&self) -> Result<std::collections::BTreeMap<Uuid, String>> {
        self.desktop()?.request_attributions()
    }

    /// Forget every finished record in the activity list, for every wallet.
    ///
    /// Owner-only, and pointedly absent from `AgentApi`: this list is the
    /// account a person keeps of what their agents did, so an agent able to
    /// clear it could erase the evidence of its own behaviour.
    ///
    /// What survives is everything not yet finished — awaiting a decision,
    /// signed, in flight, cancelling — because those are live state rather
    /// than history, and one of them holds the only copy of an envelope the
    /// chain may still mine. Nothing on chain changes and no policy loosens;
    /// this forgets the local record and nothing else.
    pub fn clear_activity_history(&self) -> Result<usize> {
        let data_dir = self.config.data_dir();
        let mut removed = PendingStore::production(data_dir)?.clear_terminal_history(None)?;
        removed += MessageStore::production(data_dir)?.clear_history(None)?;
        removed += TypedDataStore::production(data_dir)?.clear_history(None)?;
        Ok(removed)
    }

    pub fn transaction(&self, request_id: Uuid) -> Result<PendingTransaction> {
        PendingStore::production(self.config.data_dir())?.get(request_id)
    }

    /// Build the owner-facing transaction view from the encrypted lifecycle
    /// row and, when the chain has one, its complete mined receipt.
    pub async fn transaction_inspection(
        &self,
        request_id: Uuid,
    ) -> Result<OwnerTransactionInspection> {
        // Opening the receipt view is itself an opportunity to settle a stale
        // lifecycle row. Keep inspection available when an RPC is temporarily
        // unreachable, but never keep presenting `Broadcast` after the same
        // lookup has already observed a mined receipt.
        let pending = match self.refresh_transaction(request_id).await {
            Ok(refreshed) => refreshed,
            Err(_) => self.transaction(request_id)?,
        };
        let chain_id = pending
            .chain_id
            .parse::<u64>()
            .context("stored transaction chain ID is invalid")?;
        let network = self.config.network_by_chain_id(&pending.chain_id)?;
        let wallet = self.config.wallet(&pending.wallet_id)?;

        let mut candidates = Vec::new();
        if pending.status == PendingStatus::Cancelled {
            candidates.extend(pending.cancel_transaction_hashes.iter().rev().cloned());
        }
        if let Some(hash) = pending
            .broadcast_transaction_hash
            .as_ref()
            .or(pending.signed_transaction_hash.as_ref())
        {
            candidates.push(hash.clone());
        }
        candidates.dedup();

        let mut receipt = None;
        let mut receipt_hash = None;
        let mut receipt_error = None;
        for hash in &candidates {
            match transaction_receipt_details(&network, hash).await {
                Ok(Some(details)) => {
                    receipt = Some(details);
                    receipt_hash = Some(hash.clone());
                    receipt_error = None;
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    receipt_error = Some(ekubo_wallet_core::sanitize::stripped_capped(
                        &format!("{error:#}"),
                        500,
                    ));
                }
            }
        }

        let mut token_targets = plan_token_targets(&pending.execution_plan.ordered_steps)
            .await
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        if let Some(receipt) = &receipt {
            token_targets.extend(receipt.logs.iter().map(|log| log.address));
        }
        let metadata = TokenStore::production(self.config.data_dir())?
            .display_metadata(chain_id, &token_targets.into_iter().collect::<Vec<_>>())?;
        let document = transaction_inspection_document(
            &pending,
            wallet.address,
            &network,
            &metadata,
            receipt_hash
                .as_deref()
                .or_else(|| candidates.first().map(String::as_str)),
            receipt.as_ref(),
            receipt_error.as_deref(),
        )
        .await?;
        Ok(OwnerTransactionInspection {
            document,
            receipt_loaded: receipt.is_some(),
            receipt_error,
        })
    }

    /// Reconcile one lifecycle row against its configured network. This is a
    /// read from the owner's perspective, but any observed terminal state is
    /// persisted so the activity record remains authoritative after restart.
    pub async fn refresh_transaction(&self, request_id: Uuid) -> Result<PendingTransaction> {
        let pending = Mutex::new(PendingStore::production(self.config.data_dir())?);
        let before = pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .get(request_id)?;
        let network = self.config.network_by_chain_id(before.chain_id.as_str())?;
        let refreshed = reconcile_record(&pending, &network, before.clone(), true).await?;
        if transaction_observation_changed(&before, &refreshed) {
            self.publish_transaction_status(&refreshed);
        }
        Ok(refreshed)
    }

    /// Submit or rebroadcast only the exact signed bytes already held in the
    /// encrypted lifecycle row. Policy and configuration changes cannot turn
    /// this into a different transaction.
    pub async fn rebroadcast_transaction(
        &self,
        request_id: Uuid,
    ) -> Result<OwnerTransactionAction> {
        require_current_acceptance(self.config.data_dir())?;
        let pending = Mutex::new(PendingStore::production(self.config.data_dir())?);
        let before = pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .get(request_id)?;
        let starting = before.clone();
        let wallet = self.config.wallet(&before.wallet_id)?;
        let network = self.config.network_by_chain_id(before.chain_id.as_str())?;
        let current = reconcile_record(&pending, &network, before, true).await?;
        if transaction_observation_changed(&starting, &current) {
            self.publish_transaction_status(&current);
        }
        let reconciled = current.clone();
        let claimed = match current.status {
            PendingStatus::Signed => pending
                .lock()
                .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                .claim_for_submission(request_id)?,
            PendingStatus::Broadcast => {
                let hash = current
                    .signed_transaction_hash
                    .as_deref()
                    .context("broadcast transaction is missing its signed hash")?;
                if transaction_known(&network, hash).await? {
                    return Ok(OwnerTransactionAction {
                        record: current,
                        broadcast: None,
                    });
                }
                pending
                    .lock()
                    .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                    .claim_broadcast_retry(request_id)?
            }
            _ => anyhow::bail!(
                "this transaction is {}; only one that is signed but unsent, or sent but not yet mined, can be sent again",
                current.status.label().to_lowercase()
            ),
        };
        let (record, broadcast) = submit_claimed(&pending, &wallet, &network, claimed).await?;
        if transaction_observation_changed(&reconciled, &record) {
            self.publish_transaction_status(&record);
        }
        Ok(OwnerTransactionAction {
            record,
            broadcast: Some(broadcast),
        })
    }

    /// Race an unconfirmed transaction with the core's bounded 0-value
    /// self-send cancellation. The desktop confirms the destructive intent;
    /// this method derives every signed field from the stored envelope and
    /// current chain state, exactly like the restricted agent operation.
    pub async fn attempt_transaction_cancellation(
        &self,
        request_id: Uuid,
    ) -> Result<OwnerTransactionAction> {
        require_current_acceptance(self.config.data_dir())?;
        let pending = Mutex::new(PendingStore::production(self.config.data_dir())?);
        let record = pending
            .lock()
            .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
            .get(request_id)?;
        let starting = record.clone();
        let wallet = self.config.wallet(&record.wallet_id)?;
        let network = self.config.network_by_chain_id(record.chain_id.as_str())?;
        let outcome = attempt_cancellation(
            &pending,
            &self.config,
            &wallet,
            &network,
            record,
            &OsKeyStore,
        )
        .await;
        let (record, broadcast) = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                // Cancellation begins by reconciling. A receipt may therefore
                // finalize the row immediately before the operation correctly
                // refuses to cancel an already-mined transaction. Publish the
                // persisted terminal state even though the requested action
                // returns an error.
                if let Ok(store) = pending.lock()
                    && let Ok(current) = store.get(request_id)
                    && transaction_observation_changed(&starting, &current)
                {
                    self.publish_transaction_status(&current);
                }
                return Err(error);
            }
        };
        if transaction_observation_changed(&starting, &record) {
            self.publish_transaction_status(&record);
        }
        Ok(OwnerTransactionAction {
            record,
            broadcast: Some(broadcast),
        })
    }

    fn publish_transaction_status(&self, record: &PendingTransaction) {
        let stage = match record.status {
            PendingStatus::AwaitingApproval => Some(crate::events::TransactionStage::Proposed),
            PendingStatus::Signed => Some(crate::events::TransactionStage::Signed),
            PendingStatus::Submitting | PendingStatus::Broadcast | PendingStatus::Cancelling => {
                Some(crate::events::TransactionStage::Broadcast)
            }
            PendingStatus::Confirmed | PendingStatus::Reverted if record.finalized_at.is_none() => {
                Some(crate::events::TransactionStage::Broadcast)
            }
            PendingStatus::Confirmed => Some(crate::events::TransactionStage::Confirmed),
            PendingStatus::Reverted => Some(crate::events::TransactionStage::Reverted),
            PendingStatus::Cancelled
                if record.settlement_transaction_hash.is_some()
                    && record.finalized_at.is_none() =>
            {
                Some(crate::events::TransactionStage::Broadcast)
            }
            PendingStatus::Cancelled => Some(crate::events::TransactionStage::Cancelled),
            PendingStatus::Replaced => Some(crate::events::TransactionStage::Replaced),
            PendingStatus::Rejected => None,
        };
        if let Some(stage) = stage {
            self.events.publish(DomainEventKind::Transaction {
                request_id: record.request_id,
                stage,
            });
        }
    }

    pub fn reviews(&self, wallet_id: Option<&str>) -> Result<OwnerReviewQueues> {
        Ok(OwnerReviewQueues {
            transactions: PendingStore::production(self.config.data_dir())?
                .awaiting_approval(wallet_id)?,
            typed_data: TypedDataStore::production(self.config.data_dir())?
                .awaiting_approval(wallet_id)?,
            messages: MessageStore::production(self.config.data_dir())?
                .awaiting_approval(wallet_id)?,
            policy_proposals: PolicyStore::production(self.config.data_dir())?
                .list_proposals()?
                .into_iter()
                .filter(|proposal| wallet_id.is_none_or(|wallet| proposal.wallet_id == wallet))
                .collect(),
            network_proposals: PolicyStore::production(self.config.data_dir())?
                .network_proposals()?,
            token_proposals: TokenStore::production(self.config.data_dir())?.proposals()?,
        })
    }

    pub async fn review_transaction(
        &self,
        request_id: Uuid,
        presenter: &dyn ReviewPresenter,
    ) -> Result<ApprovalOutcome> {
        let pending = PendingStore::production(self.config.data_dir())?;
        let request = pending.get(request_id)?;
        let data_dir = self.config.data_dir().to_path_buf();
        let wallet_id = request.wallet_id.clone();
        let wallet_address = request.execution_plan.sender;
        let read_policy = move || {
            PolicyStore::production(&data_dir)?
                .get_for_wallet(&wallet_id, wallet_address)?
                .context("wallet has no installed policy")
        };
        let tokens = TokenStore::production(self.config.data_dir())?;
        let result = approve_transaction(
            &self.config,
            pending,
            tokens,
            &read_policy,
            request,
            presenter,
            &PlatformHumanPresence,
            &OsKeyStore,
        )
        .await?;
        if matches!(result, ApprovalOutcome::Signed(_)) {
            self.events.publish(DomainEventKind::Transaction {
                request_id,
                stage: crate::events::TransactionStage::Signed,
            });
        }
        self.events
            .publish(DomainEventKind::ReviewChanged { request_id });
        Ok(result)
    }

    pub fn message_review_document(&self, request_id: Uuid) -> Result<ReviewDocument> {
        let request = MessageStore::production(self.config.data_dir())?.get(request_id)?;
        let display = describe_message(&request.message_bytes()?);
        let mut summary = ApprovalRequest::new(
            ApprovalKind::MessageSignature,
            "Review message signature",
            "This signature can prove account control. It does not submit a transaction.",
        )
        .fact("Wallet", request.wallet_id)
        .fact(
            "Chain context",
            request.chain_id.unwrap_or_else(|| "Not specified".into()),
        )
        .fact("Sent to the wallet as", request.encoding.label())
        .fact("Byte length", display.byte_length.to_string())
        .fact("Line count", display.line_count.to_string())
        .fact(
            "Requester",
            request
                .requester
                .unwrap_or_else(|| "Unknown requester".into()),
        )
        .digest(request.digest);
        summary.id = request_id;
        for warning in display.warnings {
            summary = summary.warning(warning);
        }
        let mut payloads = Vec::with_capacity(2);
        if let Some(escaped) = display.escaped_text {
            payloads.push(format!(
                "Visible text (unsafe characters escaped):\n{escaped}"
            ));
        }
        payloads.push(format!("Exact message bytes:\n{}", request.message_hex));
        Ok(ReviewDocument::from_request(summary, payloads))
    }

    pub fn queue_message(
        &self,
        wallet_id: &str,
        chain_id: u64,
        message: &[u8],
        encoding: ekubo_wallet_core::message::MessageEncoding,
        requester: &str,
    ) -> Result<PendingMessage> {
        let wallet = self.account(wallet_id)?;
        let queued = MessageStore::production(self.config.data_dir())?.create_for_wallet(
            &wallet,
            Some(&chain_id.to_string()),
            message,
            encoding,
            Some(requester),
        )?;
        self.events.publish(DomainEventKind::ReviewChanged {
            request_id: queued.request_id,
        });
        Ok(queued)
    }

    pub fn typed_data_review_document(&self, request_id: Uuid) -> Result<ReviewDocument> {
        let request = TypedDataStore::production(self.config.data_dir())?.get(request_id)?;
        let exact_json = serde_json::to_string_pretty(&request.typed_data)?;
        let dangerous_display = exact_json.chars().any(|character| {
            character != '\n' && ekubo_wallet_core::sanitize::is_disallowed(character)
        });
        let exact = escape_review_payload(&exact_json);
        let mut summary = ApprovalRequest::new(
            ApprovalKind::TypedDataSignature,
            "Review typed-data signature",
            "EIP-712 typed data may grant permissions or authorize off-chain actions.",
        )
        .fact("Wallet", request.wallet_id)
        .fact("Chain", request.chain_id)
        .fact(
            "Requester",
            request.requester.unwrap_or_else(|| "Unknown requester".into()),
        )
        .warning(
            "Review every type, domain, and value. Names are untrusted and Unicode may contain confusable or bidirectional characters.",
        )
        .digest(request.digest);
        summary.id = request_id;
        if dangerous_display {
            summary = summary.warning(
                "The typed data contains control, bidirectional, invisible, or glyph-changing characters. They are escaped in the exact payload below.",
            );
        }
        Ok(ReviewDocument::from_request(summary, vec![exact]))
    }

    pub fn queue_typed_data(
        &self,
        wallet_id: &str,
        chain_id: u64,
        payload: &serde_json::Value,
        requester: &str,
    ) -> Result<PendingTypedData> {
        let wallet = self.account(wallet_id)?;
        let (_, parsed_chain_id, digest) = parse_typed_data(payload)?;
        anyhow::ensure!(
            parsed_chain_id == chain_id,
            "typed-data domain chain does not match the request chain"
        );
        let queued = TypedDataStore::production(self.config.data_dir())?.create_for_wallet(
            &wallet,
            chain_id,
            payload,
            digest,
            Some(requester),
        )?;
        self.events.publish(DomainEventKind::ReviewChanged {
            request_id: queued.request_id,
        });
        Ok(queued)
    }

    pub(crate) fn config_store(&self) -> &ConfigStore {
        &self.config
    }

    pub(crate) fn event_bus(&self) -> EventBus {
        self.events.clone()
    }

    pub async fn sign_message(
        &self,
        request_id: Uuid,
        reviewed_digest: &str,
    ) -> Result<PendingMessage> {
        let mut store = MessageStore::production(self.config.data_dir())?;
        let request = store.get(request_id)?;
        ensure_reviewed_digest(reviewed_digest, &request.digest)?;
        let digest = request.digest.parse()?;
        let wallet = self.config.wallet(&request.wallet_id)?;
        let policies = PolicyStore::production(self.config.data_dir())?;
        let signed = sign_reviewed_message(
            &self.config,
            &policies,
            &mut store,
            &request,
            &wallet,
            digest,
            &PlatformHumanPresence,
            &OsKeyStore,
        )
        .await?;
        self.events
            .publish(DomainEventKind::ReviewChanged { request_id });
        Ok(signed)
    }

    pub fn reject_message(&self, request_id: Uuid) -> Result<PendingMessage> {
        let rejected = MessageStore::production(self.config.data_dir())?.reject(request_id)?;
        self.events
            .publish(DomainEventKind::ReviewChanged { request_id });
        Ok(rejected)
    }

    pub async fn sign_typed_data(
        &self,
        request_id: Uuid,
        reviewed_digest: &str,
    ) -> Result<PendingTypedData> {
        let mut store = TypedDataStore::production(self.config.data_dir())?;
        let request = store.get(request_id)?;
        ensure_reviewed_digest(reviewed_digest, &request.digest)?;
        let digest = request.digest.parse()?;
        let wallet = self.config.wallet(&request.wallet_id)?;
        let policies = PolicyStore::production(self.config.data_dir())?;
        let signed = sign_reviewed_typed_data(
            &self.config,
            &policies,
            &mut store,
            &request,
            &wallet,
            digest,
            &PlatformHumanPresence,
            &OsKeyStore,
        )
        .await?;
        self.events
            .publish(DomainEventKind::ReviewChanged { request_id });
        Ok(signed)
    }

    pub fn reject_typed_data(&self, request_id: Uuid) -> Result<PendingTypedData> {
        let rejected = TypedDataStore::production(self.config.data_dir())?.reject(request_id)?;
        self.events
            .publish(DomainEventKind::ReviewChanged { request_id });
        Ok(rejected)
    }

    pub fn discard_unsent_transaction(&self, request_id: Uuid) -> Result<PendingTransaction> {
        let discarded =
            PendingStore::production(self.config.data_dir())?.discard_unsent(request_id)?;
        self.events.publish(DomainEventKind::Transaction {
            request_id,
            stage: crate::events::TransactionStage::Cancelled,
        });
        Ok(discarded)
    }

    pub fn tokens(
        &self,
        chain_id: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredToken>> {
        TokenStore::production(self.config.data_dir())?.list(chain_id, limit, offset)
    }

    pub async fn add_token(&self, token: ListedToken) -> Result<StoredToken> {
        ensure!(
            contains_configured_chain(&self.config.load()?, token.chain_id),
            "chain {} is not a configured network",
            token.chain_id
        );
        let authorization = authorize_owner(OwnerAuthorizationScope::TokenMetadata).await?;
        ensure!(
            contains_configured_chain(&self.config.load()?, token.chain_id),
            "chain {} was removed during authentication",
            token.chain_id
        );
        let stored = TokenStore::production(self.config.data_dir())?.add_authorized(
            &token,
            "Manual entry",
            &authorization,
        )?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(stored)
    }

    pub fn remove_token(&self, reviewed: &StoredToken) -> Result<()> {
        let chain_id = reviewed
            .chain_id
            .parse::<u64>()
            .context("stored token has an invalid chain ID")?;
        ensure!(
            contains_configured_chain(&self.config.load()?, chain_id),
            "chain {chain_id} is not a configured network"
        );
        TokenStore::production(self.config.data_dir())?.remove_reviewed(reviewed)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    pub async fn import_token_list_for_review(
        &self,
        url: &str,
        requested_chain_ids: &[u64],
    ) -> Result<OwnerTokenListImport> {
        let chains_selected = self.enabled_token_import_chains(requested_chain_ids)?;
        let (parsed, host) =
            fetch_token_list_url(url, &chains_selected, FetchPolicy::production()).await?;
        let source_kind = ProposalSource::Served {
            host: &host,
            declared: parsed.declared_name.as_deref(),
        };
        let source = source_kind.label();
        let mut store = TokenStore::production(self.config.data_dir())?;
        let summary = store.propose(&parsed.tokens, &source_kind)?;
        let proposals = store
            .proposals()?
            .into_iter()
            .filter(|proposal| proposal.source == source)
            .collect();
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(OwnerTokenListImport {
            source,
            host,
            declared_version: parsed.declared_version,
            declared_timestamp: parsed.declared_timestamp,
            chains_selected,
            skipped_non_evm: parsed.skipped_non_evm,
            skipped_other_chain: parsed.skipped_other_chain,
            summary,
            proposals,
        })
    }

    fn enabled_token_import_chains(&self, requested: &[u64]) -> Result<Vec<u64>> {
        let mut chain_ids = if requested.is_empty() {
            self.config
                .load()?
                .networks
                .into_iter()
                .filter(|network| !network.disabled)
                .map(|network| network.chain_id)
                .collect::<Vec<_>>()
        } else {
            requested
                .iter()
                .map(|chain_id| {
                    self.config
                        .network_by_chain_id(&chain_id.to_string())
                        .map(|network| network.chain_id)
                })
                .collect::<Result<Vec<_>>>()?
        };
        chain_ids.sort_unstable();
        chain_ids.dedup();
        ensure!(
            !chain_ids.is_empty(),
            "enable at least one network before importing a token list"
        );
        Ok(chain_ids)
    }

    pub fn token_proposals(&self) -> Result<Vec<TokenProposal>> {
        TokenStore::production(self.config.data_dir())?.proposals()
    }

    pub async fn accept_token_proposals(&self, proposals: &[TokenProposal]) -> Result<u64> {
        ensure!(!proposals.is_empty(), "no token proposals were selected");
        for proposal in proposals {
            self.config
                .network_by_chain_id(&proposal.token.chain_id.to_string())?;
        }
        let authorization = authorize_owner(OwnerAuthorizationScope::TokenMetadata).await?;
        let inserted = TokenStore::production(self.config.data_dir())?
            .consume_proposals_authorized(proposals, &authorization)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(inserted)
    }

    pub fn reject_token_proposals(&self, proposals: &[TokenProposal]) -> Result<u64> {
        let identities = proposals
            .iter()
            .map(|proposal| {
                (
                    proposal.token.chain_id,
                    proposal.token.address,
                    proposal.proposed_at,
                )
            })
            .collect::<Vec<_>>();
        let removed =
            TokenStore::production(self.config.data_dir())?.discard_proposals(&identities)?;
        if removed > 0 {
            self.events.publish(DomainEventKind::ConfigurationChanged);
        }
        Ok(removed)
    }

    pub fn legal_status(&self) -> Result<LegalStatus> {
        LegalStore::production(self.config.data_dir())?.status()
    }

    #[must_use]
    pub fn legal_document(&self, document: LegalDocument) -> (String, String) {
        (document.text(), document.digest())
    }

    pub fn accept_legal(&self, document: LegalDocument, reviewed_digest: &str) -> Result<()> {
        LegalStore::production(self.config.data_dir())?.record_acceptance(document, reviewed_digest)
    }
}

fn escape_review_payload(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character != '\n' && ekubo_wallet_core::sanitize::is_disallowed(character) {
                character.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

fn ensure_optional_revision(reviewed: Option<u64>, current: Option<u64>) -> Result<()> {
    anyhow::ensure!(
        reviewed == current,
        "policy changed during review (reviewed {reviewed:?}, current {current:?})"
    );
    Ok(())
}

fn ensure_reviewed_digest(reviewed: &str, current: &str) -> Result<()> {
    anyhow::ensure!(reviewed == current, "request changed during review");
    Ok(())
}

pub const PRIVATE_KEY_REVEAL_DURATION: Duration = Duration::from_secs(30);

pub struct ExportLease {
    value: Arc<Mutex<zeroize::Zeroizing<String>>>,
    expires_at: Instant,
}

impl ExportLease {
    fn new(value: zeroize::Zeroizing<String>) -> Self {
        Self::new_for_duration(value, PRIVATE_KEY_REVEAL_DURATION)
    }

    fn new_for_duration(value: zeroize::Zeroizing<String>, duration: Duration) -> Self {
        let value = Arc::new(Mutex::new(value));
        let expiring = value.clone();
        std::thread::spawn(move || {
            std::thread::sleep(duration);
            if let Ok(mut value) = expiring.lock() {
                use zeroize::Zeroize as _;
                value.zeroize();
            }
        });
        Self {
            value,
            expires_at: Instant::now() + duration,
        }
    }

    #[must_use]
    pub fn concealed(&self) -> bool {
        Instant::now() >= self.expires_at
            || self.value.lock().map_or(true, |value| value.is_empty())
    }

    /// How much longer the key stays visible. A reveal that vanishes without
    /// warning reads as a bug; a countdown makes the deadline the user's to
    /// plan around.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        if self.concealed() {
            return Duration::ZERO;
        }
        self.expires_at.saturating_duration_since(Instant::now())
    }

    #[must_use]
    pub fn visible_value(&self) -> Option<zeroize::Zeroizing<String>> {
        if self.concealed() {
            return None;
        }
        self.value
            .lock()
            .ok()
            .map(|value| zeroize::Zeroizing::new(value.to_string()))
    }
}

pub struct ApplicationAuthority {
    owner: OwnerApi,
    agent: AgentApi,
    desktop: Arc<Mutex<DesktopStore>>,
    events: EventBus,
}

impl ApplicationAuthority {
    pub fn open(config: ConfigStore) -> Result<Self> {
        let desktop = Arc::new(Mutex::new(DesktopStore::production(config.data_dir())?));
        let events = EventBus::default();
        let global_quota = Arc::new(Mutex::new(GlobalAgentQuota::default()));
        Ok(Self {
            owner: OwnerApi {
                config: config.clone(),
                desktop: desktop.clone(),
                events: events.clone(),
            },
            agent: AgentApi {
                config,
                desktop: desktop.clone(),
                global_quota,
                events: events.clone(),
            },
            desktop,
            events,
        })
    }

    #[must_use]
    pub fn owner_api(&self) -> OwnerApi {
        self.owner.clone()
    }

    #[must_use]
    pub fn agent_api(&self) -> AgentApi {
        self.agent.clone()
    }

    #[must_use]
    pub fn desktop_store(&self) -> Arc<Mutex<DesktopStore>> {
        self.desktop.clone()
    }

    #[must_use]
    pub fn events(&self) -> EventBus {
        self.events.clone()
    }
}

#[cfg(test)]
#[path = "authority_test.rs"]
mod tests;
