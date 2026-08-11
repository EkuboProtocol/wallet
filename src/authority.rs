//! Long-lived application authority and compile-time capability surfaces.

use crate::{
    events::{DomainEventKind, EventBus},
    mcp::{GlobalAgentQuota, WalletMcpServer},
};
use alloy::primitives::Address;
use anyhow::{Context, Result};
use ekubo_wallet_core::{
    address_book::{AddressBookEntry, AddressBookStore},
    approval::{ApprovalKind, ApprovalRequest, ReviewDocument, ReviewPresenter},
    config::{
        ConfigStore, NetworkConfig, WalletConfig, WalletMetadata, remove_configured_network,
        replace_configured_network,
    },
    core::policy::WalletPolicy,
    custody::{CustodyService, OsKeyStore, PrivateKeyMaterial},
    desktop_store::{AgentKind, ClientToken, DesktopStore, McpClient, RegisteredClient},
    human_presence::{HumanPresence as _, PlatformHumanPresence, PresenceRequest},
    legal::{LegalDocument, LegalStatus, LegalStore},
    message::{MessageStore, PendingMessage, describe_message},
    orchestrator::{
        ApprovalOutcome, approve_transaction, sign_reviewed_message, sign_reviewed_typed_data,
    },
    pending::{PendingStore, PendingTransaction},
    policy_store::{PolicyStore, StoredPolicy},
    token_store::{StoredToken, TokenStore},
    typed_data::{PendingTypedData, TypedDataStore, parse_typed_data},
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

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

pub struct OwnerReviewQueues {
    pub transactions: Vec<PendingTransaction>,
    pub typed_data: Vec<PendingTypedData>,
    pub messages: Vec<PendingMessage>,
}

impl OwnerApi {
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
        let wallet = custody.create(wallet_id)?;
        self.initialize_policy(&wallet.id, policy).with_context(|| {
            format!(
                "account {} was created but policy initialization failed; signing remains disabled",
                wallet.id
            )
        })?;
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
        let wallet = custody.import(wallet_id, key)?;
        self.initialize_policy(&wallet.id, &WalletPolicy::require_approval_for_everything())?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(wallet)
    }

    fn initialize_policy(&self, wallet_id: &str, policy: &WalletPolicy) -> Result<()> {
        let mut policies = PolicyStore::production(self.config.data_dir())?;
        policies.purge(wallet_id)?;
        policies.put(wallet_id, policy, None)?;
        Ok(())
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
                "Transaction {} is {:?} on chain {} and may still reach the chain. Removal deletes the only local signed bytes and tracking state.",
                transaction.request_id, transaction.status, transaction.chain_id
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
        PolicyStore::production(self.config.data_dir())?.purge(wallet_id)?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(removed)
    }

    pub fn register_client(
        &self,
        name: &str,
        kind: AgentKind,
        managed_registration: Option<&serde_json::Value>,
    ) -> Result<RegisteredClient> {
        let registered = self
            .desktop()?
            .register_client(name, kind, managed_registration)?;
        self.events
            .publish(DomainEventKind::AgentConnectionChanged {
                client_id: registered.client.id,
            });
        Ok(registered)
    }

    pub fn rotate_client_token(&self, client_id: Uuid) -> Result<ClientToken> {
        let token = self.desktop()?.rotate_client_token(client_id)?;
        self.events
            .publish(DomainEventKind::AgentConnectionChanged { client_id });
        Ok(token)
    }

    pub fn repair_client_token(&self, client_id: Uuid) -> Result<ClientToken> {
        self.desktop()?.repair_client_token(client_id)
    }

    pub fn revoke_client(&self, client_id: Uuid) -> Result<()> {
        self.desktop()?.revoke_client(client_id)?;
        self.events
            .publish(DomainEventKind::AgentConnectionChanged { client_id });
        Ok(())
    }

    pub fn remove_client(&self, client_id: Uuid) -> Result<()> {
        self.desktop()?.remove_client(client_id)?;
        self.events
            .publish(DomainEventKind::AgentConnectionChanged { client_id });
        Ok(())
    }

    pub fn clients(&self) -> Result<Vec<McpClient>> {
        self.desktop()?.clients()
    }

    pub fn mcp_port(&self) -> Result<Option<u16>> {
        self.desktop()?.setting("mcp_port")
    }

    pub fn set_mcp_port(&self, port: u16) -> Result<()> {
        self.desktop()?.set_setting("mcp_port", &port)
    }

    pub fn policy(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        PolicyStore::production(self.config.data_dir())?.get(wallet_id)
    }

    pub async fn install_policy(
        &self,
        wallet_id: &str,
        policy: &WalletPolicy,
        reviewed_revision: u64,
    ) -> Result<StoredPolicy> {
        let before = self
            .policy(wallet_id)?
            .context("wallet has no installed policy")?;
        ensure_revision(reviewed_revision, before.revision)?;
        PlatformHumanPresence
            .confirm(&PresenceRequest::ReplacePolicy {
                wallet: wallet_id.to_owned(),
            })
            .await?;
        let mut store = PolicyStore::production(self.config.data_dir())?;
        let current = store.get(wallet_id)?.context("wallet policy disappeared")?;
        ensure_revision(reviewed_revision, current.revision)?;
        let installed = store.put(wallet_id, policy, Some(reviewed_revision))?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(installed)
    }

    pub fn networks(&self) -> Result<Vec<NetworkConfig>> {
        Ok(self.config.load()?.networks)
    }

    pub fn network_by_chain_id(&self, chain_id: u64) -> Result<NetworkConfig> {
        self.config.network_by_chain_id(&chain_id.to_string())
    }

    pub async fn install_network(&self, network: NetworkConfig) -> Result<()> {
        ekubo_wallet_core::config::validate_network(&network)?;
        PlatformHumanPresence
            .confirm(&PresenceRequest::ConfirmNetwork {
                network: network.name.clone(),
            })
            .await?;
        self.config
            .update(|config| replace_configured_network(&mut config.networks, network))?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(())
    }

    pub fn remove_network(&self, identifier: &str) -> Result<NetworkConfig> {
        let removed = self
            .config
            .update(|config| remove_configured_network(&mut config.networks, identifier))?;
        self.events.publish(DomainEventKind::ConfigurationChanged);
        Ok(removed)
    }

    pub fn transactions(
        &self,
        wallet_id: Option<&str>,
        limit: u16,
    ) -> Result<Vec<PendingTransaction>> {
        PendingStore::production(self.config.data_dir())?.list(wallet_id, limit)
    }

    pub fn reviews(&self, wallet_id: Option<&str>) -> Result<OwnerReviewQueues> {
        Ok(OwnerReviewQueues {
            transactions: PendingStore::production(self.config.data_dir())?
                .awaiting_approval(wallet_id)?,
            typed_data: TypedDataStore::production(self.config.data_dir())?
                .awaiting_approval(wallet_id)?,
            messages: MessageStore::production(self.config.data_dir())?
                .awaiting_approval(wallet_id)?,
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
        let read_policy = move || {
            PolicyStore::production(&data_dir)?
                .get(&wallet_id)?
                .context("wallet has no installed policy")
        };
        let tokens = TokenStore::production(self.config.data_dir())?;
        let result = approve_transaction(
            &self.config,
            pending,
            &tokens,
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

    pub fn reject_transaction(&self, request_id: Uuid) -> Result<PendingTransaction> {
        let rejected = PendingStore::production(self.config.data_dir())?.reject(request_id)?;
        self.events
            .publish(DomainEventKind::ReviewChanged { request_id });
        Ok(rejected)
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
        .fact("Encoding", format!("{:?}", request.encoding))
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
        let queued = MessageStore::production(self.config.data_dir())?.create(
            wallet_id,
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
        let (_, parsed_chain_id, digest) = parse_typed_data(payload)?;
        anyhow::ensure!(
            parsed_chain_id == chain_id,
            "typed-data domain chain does not match the request chain"
        );
        let queued = TypedDataStore::production(self.config.data_dir())?.create(
            wallet_id,
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

    pub fn search_tokens(
        &self,
        query: &str,
        chain_id: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredToken>> {
        TokenStore::production(self.config.data_dir())?.search(query, chain_id, limit)
    }

    pub fn remove_token(&self, chain_id: u64, address: Address) -> Result<bool> {
        TokenStore::production(self.config.data_dir())?.remove(chain_id, address)
    }

    pub fn address_book(
        &self,
        chain_id: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AddressBookEntry>> {
        AddressBookStore::production(self.config.data_dir())?.list(chain_id, limit, offset)
    }

    pub async fn save_address(
        &self,
        chain_id: u64,
        alias: &str,
        address: Address,
        note: Option<&str>,
    ) -> Result<AddressBookEntry> {
        PlatformHumanPresence
            .confirm(&PresenceRequest::SaveAddressBookEntry {
                alias: alias.to_owned(),
            })
            .await?;
        AddressBookStore::production(self.config.data_dir())?.upsert(chain_id, alias, address, note)
    }

    pub async fn remove_address(&self, chain_id: u64, alias: &str) -> Result<AddressBookEntry> {
        PlatformHumanPresence
            .confirm(&PresenceRequest::RemoveAddressBookEntry {
                alias: alias.to_owned(),
            })
            .await?;
        AddressBookStore::production(self.config.data_dir())?.remove(chain_id, alias)
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

fn ensure_revision(reviewed: u64, current: u64) -> Result<()> {
    anyhow::ensure!(
        reviewed == current,
        "policy changed during review (reviewed {reviewed}, current {current})"
    );
    Ok(())
}

fn ensure_reviewed_digest(reviewed: &str, current: &str) -> Result<()> {
    anyhow::ensure!(reviewed == current, "request changed during review");
    Ok(())
}

pub const PRIVATE_KEY_REVEAL_DURATION: Duration = Duration::from_secs(30);

pub trait Clipboard: Send + Sync + 'static {
    fn read_text(&self) -> Result<Option<String>>;
    fn write_text(&self, value: &str) -> Result<()>;
    fn clear(&self) -> Result<()>;
}

pub struct ExportLease {
    value: Arc<Mutex<zeroize::Zeroizing<String>>>,
    expires_at: Instant,
    duration: Duration,
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
            duration,
        }
    }

    #[must_use]
    pub fn concealed(&self) -> bool {
        Instant::now() >= self.expires_at
            || self.value.lock().map_or(true, |value| value.is_empty())
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

    pub fn copy_explicitly(&self, clipboard: Arc<dyn Clipboard>) -> Result<()> {
        let value = self.visible_value().context("private-key reveal expired")?;
        clipboard.write_text(&value)?;
        let expected = zeroize::Zeroizing::new(value.to_string());
        let duration = self.duration;
        std::thread::spawn(move || {
            std::thread::sleep(duration);
            if clipboard.read_text().ok().flatten().as_deref() == Some(expected.as_str()) {
                let _ = clipboard.clear();
            }
        });
        Ok(())
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
