//! Typed desktop operations over authenticated transport. All validation and
//! mutations execute in the service; this layer only carries intent and results.

use crate::{OwnerClient, owner_protocol::Request};
use anyhow::{Context as _, Result};
use ekubo_wallet_core::{
    config::{NetworkConfig, WalletConfig, WalletMetadata},
    core::policy::WalletPolicy,
    desktop_store::{AppearancePreference, GuidedSetupState},
    legal::{LegalDocument, LegalStatus},
    mcp_companions::CompanionSelection,
    policy_store::{PolicyProposal, StoredPolicy},
    token_store::{ListedToken, StoredToken, TokenProposal},
};

impl OwnerClient {
    /// Poll once. On initial connection or a history gap, refresh authoritative
    /// state before polling again from the returned cursor. Never use events as
    /// authorization or replay an ambiguous mutation when reconnecting.
    pub async fn wait_for_events(
        &self,
        after: Option<crate::events::EventCursor>,
    ) -> Result<crate::events::EventBatch> {
        self.call(&Request::WaitForEvents { after }).await
    }

    pub async fn automations(&self) -> Result<Vec<ekubo_wallet_core::automation::Automation>> {
        self.call(&Request::Automations).await
    }
    pub async fn automation_runs(
        &self,
        automation_id: uuid::Uuid,
        limit: usize,
    ) -> Result<Vec<ekubo_wallet_core::automation_store::AutomationRun>> {
        self.call(&Request::AutomationRuns {
            automation_id,
            limit,
        })
        .await
    }
    pub async fn disable_automation(
        &self,
        automation_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::automation::Automation> {
        self.call(&Request::DisableAutomation { automation_id })
            .await
    }
    pub async fn relink_automation(
        &self,
        automation_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::automation::Automation> {
        self.call(&Request::RelinkAutomation { automation_id })
            .await
    }
    pub async fn delete_automation(&self, automation_id: uuid::Uuid) -> Result<()> {
        self.call(&Request::DeleteAutomation { automation_id })
            .await
    }
    pub async fn dry_run_automation(
        &self,
        automation_id: uuid::Uuid,
    ) -> Result<crate::automation_report::AutomationDryRun> {
        self.call(&Request::DryRunAutomation { automation_id })
            .await
    }

    pub async fn tokens(
        &self,
        chain_id: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredToken>> {
        self.call(&Request::Tokens {
            chain_id,
            limit,
            offset,
        })
        .await
    }
    pub async fn add_token(
        &self,
        token: ListedToken,
        approximate_usd_price: Option<f64>,
    ) -> Result<StoredToken> {
        self.call(&Request::AddToken {
            token,
            approximate_usd_price,
        })
        .await
    }
    pub async fn native_token_prices(&self) -> Result<std::collections::BTreeMap<u64, f64>> {
        self.call(&Request::NativeTokenPrices).await
    }
    pub async fn set_native_token_price(&self, chain_id: u64, price: Option<f64>) -> Result<()> {
        self.call(&Request::SetNativeTokenPrice { chain_id, price })
            .await
    }
    pub async fn set_token_price(&self, reviewed: &StoredToken, price: Option<f64>) -> Result<()> {
        self.call(&Request::SetTokenPrice {
            reviewed: reviewed.clone(),
            price,
        })
        .await
    }
    pub async fn remove_token(&self, reviewed: &StoredToken) -> Result<()> {
        self.call(&Request::RemoveToken {
            reviewed: reviewed.clone(),
        })
        .await
    }
    pub async fn import_token_list_for_review(
        &self,
        url: &str,
        requested_chain_ids: &[u64],
    ) -> Result<crate::token_import::OwnerTokenListImport> {
        self.call(&Request::ImportTokenListForReview {
            url: url.into(),
            requested_chain_ids: requested_chain_ids.to_vec(),
        })
        .await
    }
    pub async fn token_proposals(&self) -> Result<Vec<TokenProposal>> {
        self.call(&Request::TokenProposals).await
    }
    pub async fn accept_token_proposals(&self, proposals: &[TokenProposal]) -> Result<u64> {
        self.call(&Request::AcceptTokenProposals {
            proposals: proposals.to_vec(),
        })
        .await
    }
    pub async fn reject_token_proposals(&self, proposals: &[TokenProposal]) -> Result<u64> {
        self.call(&Request::RejectTokenProposals {
            proposals: proposals.to_vec(),
        })
        .await
    }

    pub async fn begin_dapp_session(
        &self,
        uri: &str,
    ) -> Result<crate::dapp_session::SessionSummary> {
        self.call(&Request::BeginDappSession { uri: uri.into() })
            .await
    }

    pub async fn dapp_sessions(&self) -> Result<Vec<crate::dapp_session::SessionSummary>> {
        self.call(&Request::DappSessions).await
    }

    pub async fn wait_dapp_session(&self, session_id: uuid::Uuid) -> Result<()> {
        self.call(&Request::WaitDappSession { session_id }).await
    }

    pub async fn disconnect_dapp_session(
        &self,
        session_id: uuid::Uuid,
    ) -> Result<crate::dapp_session::SessionSummary> {
        self.call(&Request::DisconnectDappSession { session_id })
            .await
    }

    pub async fn dapp_reviews(&self) -> Result<Vec<crate::dapp_review::DappReview>> {
        self.call(&Request::DappReviews).await
    }

    pub async fn approve_dapp_review(
        &self,
        review: &crate::dapp_review::DappReview,
        index: usize,
    ) -> Result<()> {
        let choice = review
            .choices
            .get(index)
            .context("invalid dapp account choice")?;
        self.call(&Request::ApproveDappReview {
            session_id: review.session_id,
            index,
            reviewed_identity: choice.document.identity.clone(),
        })
        .await
    }

    pub async fn reject_dapp_review(&self, review: &crate::dapp_review::DappReview) -> Result<()> {
        self.call(&Request::RejectDappReview {
            session_id: review.session_id,
            reviewed_identity: review.unselected_document.identity.clone(),
        })
        .await
    }

    pub async fn close_dapp_review(&self, review: &crate::dapp_review::DappReview) -> Result<()> {
        self.call(&Request::CloseDappReview {
            session_id: review.session_id,
            reviewed_identity: review.unselected_document.identity.clone(),
        })
        .await
    }

    pub async fn snapshot(&self) -> Result<WalletConfig> {
        self.call(&Request::Snapshot).await
    }

    pub async fn accounts(&self) -> Result<Vec<WalletMetadata>> {
        self.call(&Request::Accounts).await
    }

    pub async fn account(&self, wallet_id: &str) -> Result<WalletMetadata> {
        self.call(&Request::Account {
            wallet_id: wallet_id.into(),
        })
        .await
    }

    pub async fn policy(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        self.call(&Request::Policy {
            wallet_id: wallet_id.into(),
        })
        .await
    }

    pub async fn policy_history(&self, wallet_id: &str) -> Result<Vec<StoredPolicy>> {
        self.call(&Request::PolicyHistory {
            wallet_id: wallet_id.into(),
        })
        .await
    }

    pub async fn install_policy(
        &self,
        wallet_id: &str,
        policy: &WalletPolicy,
        reviewed_revision: Option<u64>,
    ) -> Result<StoredPolicy> {
        self.call(&Request::InstallPolicy {
            wallet_id: wallet_id.into(),
            policy: policy.clone(),
            reviewed_revision,
        })
        .await
    }

    pub async fn networks(&self) -> Result<Vec<NetworkConfig>> {
        self.call(&Request::Networks).await
    }

    pub async fn network_by_chain_id(&self, chain_id: u64) -> Result<NetworkConfig> {
        self.call(&Request::NetworkByChainId { chain_id }).await
    }

    pub async fn reset_networks_to_defaults(
        &self,
        reviewed: &[NetworkConfig],
    ) -> Result<Vec<NetworkConfig>> {
        self.call(&Request::ResetNetworksToDefaults {
            reviewed: reviewed.to_vec(),
        })
        .await
    }

    pub async fn network_proposals(&self) -> Result<Vec<NetworkConfig>> {
        self.call(&Request::NetworkProposals).await
    }

    pub async fn accept_network_proposal(&self, proposal: &NetworkConfig) -> Result<()> {
        self.call(&Request::AcceptNetworkProposal {
            proposal: proposal.clone(),
        })
        .await
    }

    pub async fn reject_network_proposal(&self, proposal: &NetworkConfig) -> Result<bool> {
        self.call(&Request::RejectNetworkProposal {
            proposal: proposal.clone(),
        })
        .await
    }

    pub async fn policy_proposals(&self) -> Result<Vec<PolicyProposal>> {
        self.call(&Request::PolicyProposals).await
    }

    pub async fn apply_policy_proposal(&self, proposal: &PolicyProposal) -> Result<StoredPolicy> {
        self.call(&Request::ApplyPolicyProposal {
            proposal: Box::new(proposal.clone()),
        })
        .await
    }

    pub async fn reject_policy_proposal(&self, proposal: &PolicyProposal) -> Result<bool> {
        self.call(&Request::RejectPolicyProposal {
            proposal: Box::new(proposal.clone()),
        })
        .await
    }

    pub async fn add_network(&self, network: NetworkConfig) -> Result<()> {
        self.call(&Request::AddNetwork { network }).await
    }

    pub async fn replace_network(
        &self,
        reviewed: &NetworkConfig,
        replacement: NetworkConfig,
    ) -> Result<()> {
        self.call(&Request::ReplaceNetwork {
            reviewed: reviewed.clone(),
            replacement: Box::new(replacement),
        })
        .await
    }

    pub async fn set_network_disabled(
        &self,
        reviewed: &NetworkConfig,
        disabled: bool,
    ) -> Result<NetworkConfig> {
        self.call(&Request::SetNetworkDisabled {
            reviewed: reviewed.clone(),
            disabled,
        })
        .await
    }

    pub async fn detailed_notification_previews(&self) -> Result<bool> {
        self.call(&Request::DetailedNotificationPreviews).await
    }

    pub async fn set_detailed_notification_previews(&self, enabled: bool) -> Result<()> {
        self.call(&Request::SetDetailedNotificationPreviews { enabled })
            .await
    }

    pub async fn legal_status(&self) -> Result<LegalStatus> {
        self.call(&Request::LegalStatus).await
    }

    pub async fn appearance_preference(&self) -> Result<AppearancePreference> {
        self.call(&Request::AppearancePreference).await
    }

    pub async fn set_appearance_preference(&self, preference: AppearancePreference) -> Result<()> {
        self.call(&Request::SetAppearancePreference { preference })
            .await
    }

    pub async fn companion_servers(&self) -> Result<CompanionSelection> {
        self.call(&Request::CompanionServers).await
    }

    pub async fn set_companion_servers(&self, selection: &CompanionSelection) -> Result<()> {
        self.call(&Request::SetCompanionServers {
            selection: selection.clone(),
        })
        .await
    }

    pub async fn guided_setup(&self) -> Result<GuidedSetupState> {
        self.call(&Request::GuidedSetup).await
    }

    pub async fn set_guided_setup(&self, state: &GuidedSetupState) -> Result<()> {
        self.call(&Request::SetGuidedSetup {
            state: state.clone(),
        })
        .await
    }

    pub async fn testnet_mode(&self) -> Result<bool> {
        self.call(&Request::TestnetMode).await
    }

    pub async fn set_testnet_mode(&self, enabled: bool) -> Result<()> {
        self.call(&Request::SetTestnetMode { enabled }).await
    }

    pub async fn legal_document(&self, document: LegalDocument) -> Result<(String, String)> {
        self.call(&Request::LegalDocument { document }).await
    }

    pub async fn accept_legal(&self, document: LegalDocument, reviewed_digest: &str) -> Result<()> {
        self.call(&Request::AcceptLegal {
            document,
            reviewed_digest: reviewed_digest.into(),
        })
        .await
    }
}
