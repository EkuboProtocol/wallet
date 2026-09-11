//! Async desktop operations over one authority backend. Service-backed values
//! carry only the authenticated client: no local stores or authority fallback.
//! The local backend preserves macOS and pre-migration behavior. Startup must
//! select the service before opening local authority for an installed profile;
//! this adapter does not perform installation discovery itself.

use crate::authority::OwnerApi;
use anyhow::Result;
use ekubo_wallet_core::{
    config::{NetworkConfig, WalletConfig, WalletMetadata},
    core::policy::WalletPolicy,
    desktop_store::{AppearancePreference, GuidedSetupState},
    legal::{LegalDocument, LegalStatus},
    mcp_companions::CompanionSelection,
    policy_store::{PolicyProposal, StoredPolicy},
    token_store::{ListedToken, StoredToken, TokenProposal},
};

#[derive(Clone)]
pub enum DesktopOwner {
    Local(OwnerApi),
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    Service(ekubo_wallet_client::OwnerClient),
}

impl From<OwnerApi> for DesktopOwner {
    fn from(owner: OwnerApi) -> Self {
        Self::Local(owner)
    }
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "windows")),
    allow(
        clippy::match_single_binding,
        reason = "only the local backend exists on this platform"
    )
)]
impl DesktopOwner {
    /// The local installer consumes an in-process core authorization. A service
    /// profile must eventually install through its protected service updater;
    /// never mint a desktop proof or serialize this capability across IPC.
    pub async fn authorize_update_install(
        &self,
        review: &ekubo_wallet_core::update_trust::UpdateReview,
    ) -> Result<ekubo_wallet_core::update_trust::UpdateAuthorization> {
        match self {
            Self::Local(owner) => owner.authorize_update_install(review).await,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(_) => anyhow::bail!("service update installation is not implemented"),
        }
    }

    pub async fn portfolio(
        &self,
        wallet_id: Option<&str>,
    ) -> Result<ekubo_wallet_client::portfolio::OwnerPortfolioSnapshot> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.portfolio(wallet_id).await,
            Self::Local(owner) => owner.portfolio(wallet_id).await,
        }
    }

    pub async fn begin_private_key_export(
        &self,
        wallet_id: &str,
    ) -> Result<ekubo_wallet_client::export_lease::ExportLease> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.begin_private_key_export(wallet_id).await,
            Self::Local(owner) => owner.begin_private_key_export(wallet_id).await,
        }
    }

    pub async fn import_account(
        &self,
        wallet_id: &str,
        key: ekubo_wallet_client::import_key::ImportKey,
    ) -> Result<WalletMetadata> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.import_account(wallet_id, key).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.to_owned();
                tokio::task::spawn_blocking(move || {
                    owner.import_account(&wallet_id, key.into_material()?)
                })
                .await?
            }
        }
    }

    pub async fn create_account(&self, wallet_id: &str) -> Result<WalletMetadata> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.create_account(wallet_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.to_owned();
                tokio::task::spawn_blocking(move || {
                    owner.create_account(
                        &wallet_id,
                        &WalletPolicy::require_approval_for_everything(),
                    )
                })
                .await?
            }
        }
    }

    pub async fn review_transaction(
        &self,
        request_id: uuid::Uuid,
        presenter: &crate::gui_review::GuiReviewPresenter,
    ) -> Result<crate::authority::ReviewedTransaction> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => service_review::review(owner, request_id, presenter).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let presenter = presenter.clone();
                tokio::task::spawn_blocking(move || {
                    tokio::runtime::Handle::current()
                        .block_on(owner.review_transaction(request_id, &presenter))
                })
                .await?
            }
        }
    }

    pub async fn account_removal_document(
        &self,
        wallet_id: &str,
    ) -> Result<ekubo_wallet_client::account::OwnerAccountRemovalReview> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.account_removal_document(wallet_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.to_owned();
                tokio::task::spawn_blocking(move || owner.account_removal_document(&wallet_id))
                    .await?
            }
        }
    }

    pub async fn remove_account(
        &self,
        reviewed: &ekubo_wallet_client::account::OwnerAccountRemovalReview,
    ) -> Result<WalletMetadata> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.remove_account(reviewed).await,
            Self::Local(owner) => {
                let current = self.account_removal_document(&reviewed.wallet.id).await?;
                anyhow::ensure!(
                    current.wallet.instance_id == reviewed.wallet.instance_id
                        && current.wallet.address == reviewed.wallet.address
                        && current.document.identity == reviewed.document.identity,
                    "account changed; review its removal again"
                );
                owner.remove_account(&current.wallet).await
            }
        }
    }

    pub async fn sign_message(
        &self,
        request_id: uuid::Uuid,
        reviewed_digest: &str,
    ) -> Result<ekubo_wallet_core::message::PendingMessage> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.sign_message(request_id, reviewed_digest).await,
            Self::Local(owner) => owner.sign_message(request_id, reviewed_digest).await,
        }
    }

    pub async fn reject_message(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::message::PendingMessage> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.reject_message(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.reject_message(request_id)).await?
            }
        }
    }

    pub async fn sign_typed_data(
        &self,
        request_id: uuid::Uuid,
        reviewed_digest: &str,
    ) -> Result<ekubo_wallet_core::typed_data::PendingTypedData> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.sign_typed_data(request_id, reviewed_digest).await,
            Self::Local(owner) => owner.sign_typed_data(request_id, reviewed_digest).await,
        }
    }

    pub async fn reject_typed_data(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::typed_data::PendingTypedData> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.reject_typed_data(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.reject_typed_data(request_id)).await?
            }
        }
    }

    pub async fn discard_unsent_transaction(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::pending::PendingTransaction> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.discard_unsent_transaction(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.discard_unsent_transaction(request_id))
                    .await?
            }
        }
    }

    pub async fn transaction_inspection(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_client::activity::OwnerTransactionInspection> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.transaction_inspection(request_id).await,
            Self::Local(owner) => owner.transaction_inspection(request_id).await,
        }
    }

    pub async fn rebroadcast_transaction(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_client::activity::OwnerTransactionAction> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.rebroadcast_transaction(request_id).await,
            Self::Local(owner) => owner.rebroadcast_transaction(request_id).await,
        }
    }

    pub async fn attempt_transaction_cancellation(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_client::activity::OwnerTransactionAction> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.attempt_transaction_cancellation(request_id).await,
            Self::Local(owner) => owner.attempt_transaction_cancellation(request_id).await,
        }
    }

    pub async fn refresh_transaction(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::pending::PendingTransaction> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.refresh_transaction(request_id).await,
            Self::Local(owner) => owner.refresh_transaction(request_id).await,
        }
    }

    pub async fn transactions(
        &self,
        wallet_id: Option<&str>,
        limit: u16,
    ) -> Result<Vec<ekubo_wallet_core::pending::PendingTransaction>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.transactions(wallet_id, limit).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.map(str::to_owned);
                tokio::task::spawn_blocking(move || owner.transactions(wallet_id.as_deref(), limit))
                    .await?
            }
        }
    }

    pub async fn clear_activity_history(&self) -> Result<usize> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.clear_activity_history().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.clear_activity_history()).await?
            }
        }
    }

    pub async fn activity(
        &self,
        wallet_id: Option<&str>,
        limit: u16,
    ) -> Result<Vec<ekubo_wallet_client::activity::OwnerActivityRecord>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.activity(wallet_id, limit).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.map(str::to_owned);
                tokio::task::spawn_blocking(move || owner.activity(wallet_id.as_deref(), limit))
                    .await?
            }
        }
    }

    pub async fn activity_record(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_client::activity::OwnerActivityRecord> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.activity_record(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.activity_record(request_id)).await?
            }
        }
    }

    pub async fn activity_sources(&self) -> Result<std::collections::BTreeMap<uuid::Uuid, String>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.activity_sources().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.activity_sources()).await?
            }
        }
    }

    pub async fn transaction(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::pending::PendingTransaction> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.transaction(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.transaction(request_id)).await?
            }
        }
    }

    pub async fn message(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::message::PendingMessage> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.message(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.message(request_id)).await?
            }
        }
    }

    pub async fn typed_data(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::typed_data::PendingTypedData> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.typed_data(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.typed_data(request_id)).await?
            }
        }
    }

    pub async fn reviews(
        &self,
        wallet_id: Option<&str>,
    ) -> Result<ekubo_wallet_client::activity::OwnerReviewQueues> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.reviews(wallet_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.map(str::to_owned);
                tokio::task::spawn_blocking(move || owner.reviews(wallet_id.as_deref())).await?
            }
        }
    }

    pub async fn message_review_document(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::approval::ReviewDocument> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.message_review_document(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.message_review_document(request_id))
                    .await?
            }
        }
    }

    pub async fn typed_data_review_document(
        &self,
        request_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::approval::ReviewDocument> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.typed_data_review_document(request_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.typed_data_review_document(request_id))
                    .await?
            }
        }
    }

    pub async fn transaction_headlines(
        &self,
        request_ids: &[uuid::Uuid],
    ) -> Result<std::collections::BTreeMap<uuid::Uuid, String>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.transaction_headlines(request_ids).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let request_ids = request_ids.to_owned();
                tokio::task::spawn_blocking(move || {
                    let records = request_ids
                        .into_iter()
                        .map(|id| owner.transaction(id))
                        .collect::<Result<Vec<_>>>()?;
                    owner.transaction_headlines(&records.iter().collect::<Vec<_>>())
                })
                .await?
            }
        }
    }

    pub async fn transaction_previews(
        &self,
        request_ids: &[uuid::Uuid],
    ) -> Result<std::collections::BTreeMap<uuid::Uuid, String>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.transaction_previews(request_ids).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let request_ids = request_ids.to_owned();
                tokio::task::spawn_blocking(move || {
                    let records = request_ids
                        .into_iter()
                        .map(|id| owner.transaction(id))
                        .collect::<Result<Vec<_>>>()?;
                    owner.transaction_previews(&records.iter().collect::<Vec<_>>())
                })
                .await?
            }
        }
    }

    pub async fn saved_transaction_summaries(
        &self,
        request_ids: &[uuid::Uuid],
    ) -> Result<std::collections::BTreeMap<uuid::Uuid, String>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.saved_transaction_summaries(request_ids).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let request_ids = request_ids.to_owned();
                tokio::task::spawn_blocking(move || {
                    let records = request_ids
                        .into_iter()
                        .map(|id| owner.transaction(id))
                        .collect::<Result<Vec<_>>>()?;
                    owner.saved_transaction_summaries(&records.iter().collect::<Vec<_>>())
                })
                .await?
            }
        }
    }

    pub async fn automations(&self) -> Result<Vec<ekubo_wallet_core::automation::Automation>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.automations().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.automations()).await?
            }
        }
    }

    pub async fn automation_runs(
        &self,
        automation_id: uuid::Uuid,
        limit: usize,
    ) -> Result<Vec<ekubo_wallet_core::automation_store::AutomationRun>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.automation_runs(automation_id, limit).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.automation_runs(automation_id, limit))
                    .await?
            }
        }
    }

    pub async fn disable_automation(
        &self,
        automation_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::automation::Automation> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.disable_automation(automation_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.disable_automation(automation_id)).await?
            }
        }
    }

    pub async fn relink_automation(
        &self,
        automation_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_core::automation::Automation> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.relink_automation(automation_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.relink_automation(automation_id)).await?
            }
        }
    }

    pub async fn delete_automation(&self, automation_id: uuid::Uuid) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.delete_automation(automation_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.delete_automation(automation_id)).await?
            }
        }
    }

    pub async fn dry_run_automation(
        &self,
        automation_id: uuid::Uuid,
    ) -> Result<ekubo_wallet_client::automation_report::AutomationDryRun> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.dry_run_automation(automation_id).await,
            Self::Local(owner) => owner.dry_run_automation(automation_id).await,
        }
    }

    pub async fn tokens(
        &self,
        chain_id: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredToken>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.tokens(chain_id, limit, offset).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.tokens(chain_id, limit, offset)).await?
            }
        }
    }

    pub async fn add_token(
        &self,
        token: ListedToken,
        approximate_usd_price: Option<f64>,
    ) -> Result<StoredToken> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.add_token(token, approximate_usd_price).await,
            Self::Local(owner) => owner.add_token(token, approximate_usd_price).await,
        }
    }

    pub async fn native_token_prices(&self) -> Result<std::collections::BTreeMap<u64, f64>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.native_token_prices().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.native_token_prices()).await?
            }
        }
    }

    pub async fn set_native_token_price(&self, chain_id: u64, price: Option<f64>) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.set_native_token_price(chain_id, price).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.set_native_token_price(chain_id, price))
                    .await?
            }
        }
    }

    pub async fn set_token_price(&self, reviewed: &StoredToken, price: Option<f64>) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.set_token_price(reviewed, price).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let reviewed = reviewed.to_owned();
                tokio::task::spawn_blocking(move || owner.set_token_price(&reviewed, price)).await?
            }
        }
    }

    pub async fn remove_token(&self, reviewed: &StoredToken) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.remove_token(reviewed).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let reviewed = reviewed.to_owned();
                tokio::task::spawn_blocking(move || owner.remove_token(&reviewed)).await?
            }
        }
    }

    pub async fn import_token_list_for_review(
        &self,
        url: &str,
        requested_chain_ids: &[u64],
    ) -> Result<ekubo_wallet_client::token_import::OwnerTokenListImport> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => {
                owner
                    .import_token_list_for_review(url, requested_chain_ids)
                    .await
            }
            Self::Local(owner) => {
                owner
                    .import_token_list_for_review(url, requested_chain_ids)
                    .await
            }
        }
    }

    pub async fn token_proposals(&self) -> Result<Vec<TokenProposal>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.token_proposals().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.token_proposals()).await?
            }
        }
    }

    pub async fn accept_token_proposals(&self, proposals: &[TokenProposal]) -> Result<u64> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.accept_token_proposals(proposals).await,
            Self::Local(owner) => owner.accept_token_proposals(proposals).await,
        }
    }

    pub async fn reject_token_proposals(&self, proposals: &[TokenProposal]) -> Result<u64> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.reject_token_proposals(proposals).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let proposals = proposals.to_owned();
                tokio::task::spawn_blocking(move || owner.reject_token_proposals(&proposals))
                    .await?
            }
        }
    }

    pub async fn snapshot(&self) -> Result<WalletConfig> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.snapshot().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.snapshot()).await?
            }
        }
    }

    pub async fn accounts(&self) -> Result<Vec<WalletMetadata>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.accounts().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.accounts()).await?
            }
        }
    }

    pub async fn account(&self, wallet_id: &str) -> Result<WalletMetadata> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.account(wallet_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.to_owned();
                tokio::task::spawn_blocking(move || owner.account(&wallet_id)).await?
            }
        }
    }

    pub async fn policy(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.policy(wallet_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.to_owned();
                tokio::task::spawn_blocking(move || owner.policy(&wallet_id)).await?
            }
        }
    }

    pub async fn policy_history(&self, wallet_id: &str) -> Result<Vec<StoredPolicy>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.policy_history(wallet_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let wallet_id = wallet_id.to_owned();
                tokio::task::spawn_blocking(move || owner.policy_history(&wallet_id)).await?
            }
        }
    }

    pub async fn install_policy(
        &self,
        wallet_id: &str,
        policy: &WalletPolicy,
        reviewed_revision: Option<u64>,
    ) -> Result<StoredPolicy> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => {
                owner
                    .install_policy(wallet_id, policy, reviewed_revision)
                    .await
            }
            Self::Local(owner) => {
                owner
                    .install_policy(wallet_id, policy, reviewed_revision)
                    .await
            }
        }
    }

    pub async fn networks(&self) -> Result<Vec<NetworkConfig>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.networks().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.networks()).await?
            }
        }
    }

    pub async fn network_by_chain_id(&self, chain_id: u64) -> Result<NetworkConfig> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.network_by_chain_id(chain_id).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.network_by_chain_id(chain_id)).await?
            }
        }
    }

    pub async fn reset_networks_to_defaults(
        &self,
        reviewed: &[NetworkConfig],
    ) -> Result<Vec<NetworkConfig>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.reset_networks_to_defaults(reviewed).await,
            Self::Local(owner) => owner.reset_networks_to_defaults(reviewed).await,
        }
    }

    pub async fn network_proposals(&self) -> Result<Vec<NetworkConfig>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.network_proposals().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.network_proposals()).await?
            }
        }
    }

    pub async fn accept_network_proposal(&self, proposal: &NetworkConfig) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.accept_network_proposal(proposal).await,
            Self::Local(owner) => owner.accept_network_proposal(proposal).await,
        }
    }

    pub async fn reject_network_proposal(&self, proposal: &NetworkConfig) -> Result<bool> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.reject_network_proposal(proposal).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let proposal = proposal.to_owned();
                tokio::task::spawn_blocking(move || owner.reject_network_proposal(&proposal))
                    .await?
            }
        }
    }

    pub async fn policy_proposals(&self) -> Result<Vec<PolicyProposal>> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.policy_proposals().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.policy_proposals()).await?
            }
        }
    }

    pub async fn apply_policy_proposal(&self, proposal: &PolicyProposal) -> Result<StoredPolicy> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.apply_policy_proposal(proposal).await,
            Self::Local(owner) => owner.apply_policy_proposal(proposal).await,
        }
    }

    pub async fn reject_policy_proposal(&self, proposal: &PolicyProposal) -> Result<bool> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.reject_policy_proposal(proposal).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let proposal = proposal.to_owned();
                tokio::task::spawn_blocking(move || owner.reject_policy_proposal(&proposal)).await?
            }
        }
    }

    pub async fn add_network(&self, network: NetworkConfig) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.add_network(network).await,
            Self::Local(owner) => owner.add_network(network).await,
        }
    }

    pub async fn replace_network(
        &self,
        reviewed: &NetworkConfig,
        replacement: NetworkConfig,
    ) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.replace_network(reviewed, replacement).await,
            Self::Local(owner) => owner.replace_network(reviewed, replacement).await,
        }
    }

    pub async fn set_network_disabled(
        &self,
        reviewed: &NetworkConfig,
        disabled: bool,
    ) -> Result<NetworkConfig> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.set_network_disabled(reviewed, disabled).await,
            Self::Local(owner) => owner.set_network_disabled(reviewed, disabled).await,
        }
    }

    pub async fn detailed_notification_previews(&self) -> Result<bool> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.detailed_notification_previews().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.detailed_notification_previews()).await?
            }
        }
    }

    pub async fn set_detailed_notification_previews(&self, enabled: bool) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.set_detailed_notification_previews(enabled).await,
            Self::Local(owner) => owner.set_detailed_notification_previews(enabled).await,
        }
    }

    pub async fn legal_status(&self) -> Result<LegalStatus> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.legal_status().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.legal_status()).await?
            }
        }
    }

    pub async fn appearance_preference(&self) -> Result<AppearancePreference> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.appearance_preference().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.appearance_preference()).await?
            }
        }
    }

    pub async fn set_appearance_preference(&self, preference: AppearancePreference) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.set_appearance_preference(preference).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.set_appearance_preference(preference))
                    .await?
            }
        }
    }

    pub async fn companion_servers(&self) -> Result<CompanionSelection> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.companion_servers().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.companion_servers()).await?
            }
        }
    }

    pub async fn set_companion_servers(&self, selection: &CompanionSelection) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.set_companion_servers(selection).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let selection = selection.to_owned();
                tokio::task::spawn_blocking(move || owner.set_companion_servers(&selection)).await?
            }
        }
    }

    pub async fn guided_setup(&self) -> Result<GuidedSetupState> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.guided_setup().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.guided_setup()).await?
            }
        }
    }

    pub async fn set_guided_setup(&self, state: &GuidedSetupState) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.set_guided_setup(state).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let state = state.to_owned();
                tokio::task::spawn_blocking(move || owner.set_guided_setup(&state)).await?
            }
        }
    }

    pub async fn testnet_mode(&self) -> Result<bool> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.testnet_mode().await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.testnet_mode()).await?
            }
        }
    }

    pub async fn set_testnet_mode(&self, enabled: bool) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.set_testnet_mode(enabled).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || owner.set_testnet_mode(enabled)).await?
            }
        }
    }

    pub async fn legal_document(&self, document: LegalDocument) -> Result<(String, String)> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.legal_document(document).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                tokio::task::spawn_blocking(move || Ok(owner.legal_document(document))).await?
            }
        }
    }

    pub async fn accept_legal(&self, document: LegalDocument, reviewed_digest: &str) -> Result<()> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Self::Service(owner) => owner.accept_legal(document, reviewed_digest).await,
            Self::Local(owner) => {
                let owner = owner.clone();
                let reviewed_digest = reviewed_digest.to_owned();
                tokio::task::spawn_blocking(move || owner.accept_legal(document, &reviewed_digest))
                    .await?
            }
        }
    }
}

use ekubo_wallet_client::{
    activity::{OwnerActivityRecord, OwnerReviewQueues},
    desktop_snapshot::{ACTIVITY_LIMIT, AUTOMATION_RUN_LIMIT, SnapshotReader},
};
use ekubo_wallet_core::{
    approval::ReviewDocument, automation::Automation, automation_store::AutomationRun,
};
use std::collections::BTreeMap;
use uuid::Uuid;

impl SnapshotReader for DesktopOwner {
    async fn reviews(&self) -> Result<OwnerReviewQueues> {
        DesktopOwner::reviews(self, None).await
    }
    async fn automations(&self) -> Result<Vec<Automation>> {
        DesktopOwner::automations(self).await
    }
    async fn automation_runs(&self, automation_id: Uuid) -> Result<Vec<AutomationRun>> {
        DesktopOwner::automation_runs(self, automation_id, AUTOMATION_RUN_LIMIT).await
    }
    async fn activity(&self) -> Result<Vec<OwnerActivityRecord>> {
        DesktopOwner::activity(self, None, ACTIVITY_LIMIT).await
    }
    async fn activity_sources(&self) -> Result<BTreeMap<Uuid, String>> {
        DesktopOwner::activity_sources(self).await
    }
    async fn accounts(&self) -> Result<Vec<WalletMetadata>> {
        DesktopOwner::accounts(self).await
    }
    async fn legal_status(&self) -> Result<LegalStatus> {
        DesktopOwner::legal_status(self).await
    }
    async fn networks(&self) -> Result<Vec<NetworkConfig>> {
        DesktopOwner::networks(self).await
    }
    async fn policy(&self, wallet_id: &str) -> Result<Option<StoredPolicy>> {
        DesktopOwner::policy(self, wallet_id).await
    }
    async fn message_review_document(&self, request_id: Uuid) -> Result<ReviewDocument> {
        DesktopOwner::message_review_document(self, request_id).await
    }
    async fn typed_data_review_document(&self, request_id: Uuid) -> Result<ReviewDocument> {
        DesktopOwner::typed_data_review_document(self, request_id).await
    }
    async fn saved_transaction_summaries(
        &self,
        request_ids: &[Uuid],
    ) -> Result<BTreeMap<Uuid, String>> {
        DesktopOwner::saved_transaction_summaries(self, request_ids).await
    }
    async fn transaction_headlines(&self, request_ids: &[Uuid]) -> Result<BTreeMap<Uuid, String>> {
        DesktopOwner::transaction_headlines(self, request_ids).await
    }
    async fn native_token_prices(&self) -> Result<BTreeMap<u64, f64>> {
        DesktopOwner::native_token_prices(self).await
    }
}

#[cfg(test)]
#[path = "desktop_owner_test.rs"]
mod tests;

#[cfg(any(target_os = "linux", target_os = "windows", test))]
#[path = "service_review.rs"]
pub(crate) mod service_review;
