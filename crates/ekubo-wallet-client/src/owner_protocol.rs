//! Closed, versioned desktop/service owner protocol.

use ekubo_wallet_core::token_store::{ListedToken, StoredToken, TokenProposal};
use ekubo_wallet_core::{config::NetworkConfig, core::policy::WalletPolicy, legal::LegalDocument};
use ekubo_wallet_core::{
    desktop_store::{AppearancePreference, GuidedSetupState},
    mcp_companions::CompanionSelection,
    policy_store::PolicyProposal,
};
use serde::{Deserialize, Serialize};

pub const OBJECT_PATH: &str = "/org/ekubo/Wallet/Owner";

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Request {
    CreateAccount {
        wallet_id: String,
    },
    AccountRemovalDocument {
        wallet_id: String,
    },
    RemoveAccount {
        reviewed: ekubo_wallet_core::config::WalletMetadata,
        reviewed_identity: String,
    },
    ReviewTransaction {
        request_id: uuid::Uuid,
    },
    TransactionReviewFrame {
        request_id: uuid::Uuid,
    },
    DecideTransactionReview {
        request_id: uuid::Uuid,
        frame_id: uuid::Uuid,
        reviewed_identity: String,
        choice: crate::transaction_review::TransactionReviewChoice,
    },
    SignMessage {
        request_id: uuid::Uuid,
        reviewed_digest: String,
    },
    RejectMessage {
        request_id: uuid::Uuid,
    },
    SignTypedData {
        request_id: uuid::Uuid,
        reviewed_digest: String,
    },
    RejectTypedData {
        request_id: uuid::Uuid,
    },
    DiscardUnsentTransaction {
        request_id: uuid::Uuid,
    },
    TransactionInspection {
        request_id: uuid::Uuid,
    },
    RefreshTransaction {
        request_id: uuid::Uuid,
    },
    Transactions {
        wallet_id: Option<String>,
        limit: u16,
    },
    Activity {
        wallet_id: Option<String>,
        limit: u16,
    },
    ActivityRecord {
        request_id: uuid::Uuid,
    },
    ActivitySources,
    Transaction {
        request_id: uuid::Uuid,
    },
    Message {
        request_id: uuid::Uuid,
    },
    TypedData {
        request_id: uuid::Uuid,
    },
    Reviews {
        wallet_id: Option<String>,
    },
    MessageReviewDocument {
        request_id: uuid::Uuid,
    },
    TypedDataReviewDocument {
        request_id: uuid::Uuid,
    },
    TransactionHeadlines {
        request_ids: Vec<uuid::Uuid>,
    },
    SavedTransactionSummaries {
        request_ids: Vec<uuid::Uuid>,
    },
    WaitForEvents {
        after: Option<crate::events::EventCursor>,
    },
    Automations,
    AutomationRuns {
        automation_id: uuid::Uuid,
        limit: usize,
    },
    DisableAutomation {
        automation_id: uuid::Uuid,
    },
    RelinkAutomation {
        automation_id: uuid::Uuid,
    },
    DeleteAutomation {
        automation_id: uuid::Uuid,
    },
    DryRunAutomation {
        automation_id: uuid::Uuid,
    },
    Tokens {
        chain_id: Option<u64>,
        limit: usize,
        offset: usize,
    },
    AddToken {
        token: ListedToken,
        approximate_usd_price: Option<f64>,
    },
    NativeTokenPrices,
    SetNativeTokenPrice {
        chain_id: u64,
        price: Option<f64>,
    },
    SetTokenPrice {
        reviewed: StoredToken,
        price: Option<f64>,
    },
    RemoveToken {
        reviewed: StoredToken,
    },
    ImportTokenListForReview {
        url: String,
        requested_chain_ids: Vec<u64>,
    },
    TokenProposals,
    AcceptTokenProposals {
        proposals: Vec<TokenProposal>,
    },
    RejectTokenProposals {
        proposals: Vec<TokenProposal>,
    },
    BeginDappSession {
        uri: String,
    },
    DappSessions,
    WaitDappSession {
        session_id: uuid::Uuid,
    },
    DisconnectDappSession {
        session_id: uuid::Uuid,
    },
    DappReviews,
    ApproveDappReview {
        session_id: uuid::Uuid,
        index: usize,
        reviewed_identity: String,
    },
    RejectDappReview {
        session_id: uuid::Uuid,
        reviewed_identity: String,
    },
    CloseDappReview {
        session_id: uuid::Uuid,
        reviewed_identity: String,
    },
    Snapshot,
    Accounts,
    Account {
        wallet_id: String,
    },
    Policy {
        wallet_id: String,
    },
    PolicyHistory {
        wallet_id: String,
    },
    InstallPolicy {
        wallet_id: String,
        policy: WalletPolicy,
        reviewed_revision: Option<u64>,
    },
    Networks,
    NetworkByChainId {
        chain_id: u64,
    },
    ResetNetworksToDefaults {
        reviewed: Vec<NetworkConfig>,
    },
    NetworkProposals,
    AcceptNetworkProposal {
        proposal: NetworkConfig,
    },
    RejectNetworkProposal {
        proposal: NetworkConfig,
    },
    PolicyProposals,
    ApplyPolicyProposal {
        proposal: Box<PolicyProposal>,
    },
    RejectPolicyProposal {
        proposal: Box<PolicyProposal>,
    },
    AddNetwork {
        network: NetworkConfig,
    },
    ReplaceNetwork {
        reviewed: NetworkConfig,
        replacement: Box<NetworkConfig>,
    },
    SetNetworkDisabled {
        reviewed: NetworkConfig,
        disabled: bool,
    },
    DetailedNotificationPreviews,
    SetDetailedNotificationPreviews {
        enabled: bool,
    },
    AppearancePreference,
    SetAppearancePreference {
        preference: AppearancePreference,
    },
    CompanionServers,
    SetCompanionServers {
        selection: CompanionSelection,
    },
    GuidedSetup,
    SetGuidedSetup {
        state: GuidedSetupState,
    },
    TestnetMode,
    SetTestnetMode {
        enabled: bool,
    },
    LegalStatus,
    LegalDocument {
        document: LegalDocument,
    },
    AcceptLegal {
        document: LegalDocument,
        reviewed_digest: String,
    },
}

#[cfg(test)]
#[path = "owner_protocol_test.rs"]
mod tests;
