//! Closed owner operations for desktop IPC. There is no generic SQL, signing,
//! credential access, or client-supplied authorization proof in this protocol.

use crate::{authority::OwnerApi, dapp_runtime::DappRuntime};
use serde_json::Value;
use std::sync::Arc;

#[cfg(target_os = "linux")]
pub(crate) use crate::linux_owner_rpc::LinuxOwnerInterface;
#[cfg(target_os = "linux")]
pub(crate) use ekubo_wallet_client::owner_protocol::OBJECT_PATH;
pub use ekubo_wallet_client::owner_protocol::Request;

pub(crate) struct OwnerDispatcher {
    owner: OwnerApi,
    dapps: Arc<DappRuntime>,
    transactions: crate::transaction_reviews::TransactionReviews,
}

impl Drop for OwnerDispatcher {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl OwnerDispatcher {
    /// Encode authenticated replies directly. Exported material never enters
    /// the ordinary JSON Value tree, where its strings would not erase on drop.
    pub(crate) async fn encode(
        &self,
        request: Request,
    ) -> anyhow::Result<zeroize::Zeroizing<String>> {
        let encoded = match request {
            Request::BeginPrivateKeyExport { wallet_id } => {
                let lease = self.owner.begin_private_key_export(&wallet_id).await?;
                serde_json::to_string(&lease)?
            }
            request => serde_json::to_string(&self.dispatch(request).await?)?,
        };
        Ok(zeroize::Zeroizing::new(encoded))
    }

    /// Platform hosts close pending reviews before tearing down their owner
    /// transport. This also cancels preparation before any frame is published.
    pub(crate) fn shutdown(&self) -> anyhow::Result<()> {
        self.transactions.shutdown()
    }

    // Platform adapters establish caller identity and native authentication
    // context before entering this shared dispatcher. No transport handle or
    // Linux UID is part of the wallet operation protocol.
    pub(crate) fn new(owner: OwnerApi, dapps: Arc<DappRuntime>) -> Self {
        Self {
            owner,
            dapps,
            transactions: crate::transaction_reviews::TransactionReviews::default(),
        }
    }

    fn transaction_records(
        &self,
        ids: &[uuid::Uuid],
    ) -> anyhow::Result<Vec<ekubo_wallet_core::pending::PendingTransaction>> {
        anyhow::ensure!(
            ids.len() <= 1000,
            "at most 1000 transaction records can be read at once"
        );
        ids.iter().map(|id| self.owner.transaction(*id)).collect()
    }

    pub(crate) async fn dispatch(&self, request: Request) -> anyhow::Result<Value> {
        let owner = &self.owner;
        let reviews = self.dapps.reviews();
        Ok(match request {
            Request::BeginPrivateKeyExport { .. } => {
                anyhow::bail!("private-key export requires the direct reply encoder")
            }
            Request::ImportAccount { wallet_id, key } => {
                serde_json::to_value(owner.import_account(&wallet_id, key.into_material()?)?)?
            }
            Request::CreateAccount { wallet_id } => {
                // Preserve the desktop's initial policy. Creating an account
                // must not become a way to install caller-selected permissions.
                serde_json::to_value(owner.create_account(
                    &wallet_id,
                    &ekubo_wallet_core::core::policy::WalletPolicy::require_approval_for_everything(
                    ),
                )?)?
            }
            Request::AccountRemovalDocument { wallet_id } => {
                serde_json::to_value(owner.account_removal_document(&wallet_id)?)?
            }
            Request::RemoveAccount {
                reviewed,
                reviewed_identity,
            } => {
                let current = owner.account_removal_document(&reviewed.id)?;
                anyhow::ensure!(
                    current.wallet.instance_id == reviewed.instance_id
                        && current.wallet.address == reviewed.address
                        && current.document.identity == reviewed_identity,
                    "account changed; review its removal again"
                );
                // Core still authenticates natively and rechecks the exact
                // account under its lifecycle lock after authentication.
                serde_json::to_value(owner.remove_account(&current.wallet).await?)?
            }
            Request::ReviewTransaction { request_id } => {
                serde_json::to_value(Box::pin(self.transactions.review(owner, request_id)).await?)?
            }
            Request::TransactionReviewFrame { request_id } => {
                serde_json::to_value(self.transactions.frame(request_id)?)?
            }
            Request::DecideTransactionReview {
                request_id,
                frame_id,
                reviewed_identity,
                choice,
            } => {
                self.transactions.decide(
                    request_id,
                    frame_id,
                    &reviewed_identity,
                    choice,
                    &owner.event_bus(),
                )?;
                Value::Null
            }
            Request::SignMessage {
                request_id,
                reviewed_digest,
            } => serde_json::to_value(owner.sign_message(request_id, &reviewed_digest).await?)?,
            Request::RejectMessage { request_id } => {
                serde_json::to_value(owner.reject_message(request_id)?)?
            }
            Request::SignTypedData {
                request_id,
                reviewed_digest,
            } => serde_json::to_value(owner.sign_typed_data(request_id, &reviewed_digest).await?)?,
            Request::RejectTypedData { request_id } => {
                serde_json::to_value(owner.reject_typed_data(request_id)?)?
            }
            Request::DiscardUnsentTransaction { request_id } => {
                serde_json::to_value(owner.discard_unsent_transaction(request_id)?)?
            }
            Request::TransactionInspection { request_id } => {
                serde_json::to_value(Box::pin(owner.transaction_inspection(request_id)).await?)?
            }
            Request::RebroadcastTransaction { request_id } => {
                serde_json::to_value(owner.rebroadcast_transaction(request_id).await?)?
            }
            Request::AttemptTransactionCancellation { request_id } => {
                serde_json::to_value(owner.attempt_transaction_cancellation(request_id).await?)?
            }
            Request::Portfolio { wallet_id } => {
                serde_json::to_value(owner.portfolio(wallet_id.as_deref()).await?)?
            }
            Request::RefreshTransaction { request_id } => {
                serde_json::to_value(owner.refresh_transaction(request_id).await?)?
            }
            Request::Transactions { wallet_id, limit } => {
                serde_json::to_value(owner.transactions(wallet_id.as_deref(), limit)?)?
            }
            Request::ClearActivityHistory => serde_json::to_value(owner.clear_activity_history()?)?,
            Request::Activity { wallet_id, limit } => {
                serde_json::to_value(owner.activity(wallet_id.as_deref(), limit)?)?
            }
            Request::ActivityRecord { request_id } => {
                serde_json::to_value(owner.activity_record(request_id)?)?
            }
            Request::ActivitySources => serde_json::to_value(owner.activity_sources()?)?,
            Request::Transaction { request_id } => {
                serde_json::to_value(owner.transaction(request_id)?)?
            }
            Request::Message { request_id } => serde_json::to_value(owner.message(request_id)?)?,
            Request::TypedData { request_id } => {
                serde_json::to_value(owner.typed_data(request_id)?)?
            }
            Request::Reviews { wallet_id } => {
                serde_json::to_value(owner.reviews(wallet_id.as_deref())?)?
            }
            Request::MessageReviewDocument { request_id } => {
                serde_json::to_value(owner.message_review_document(request_id)?)?
            }
            Request::TypedDataReviewDocument { request_id } => {
                serde_json::to_value(owner.typed_data_review_document(request_id)?)?
            }
            Request::TransactionHeadlines { request_ids } => {
                let records = self.transaction_records(&request_ids)?;
                serde_json::to_value(
                    owner.transaction_headlines(&records.iter().collect::<Vec<_>>())?,
                )?
            }
            Request::SavedTransactionSummaries { request_ids } => {
                let records = self.transaction_records(&request_ids)?;
                serde_json::to_value(
                    owner.saved_transaction_summaries(&records.iter().collect::<Vec<_>>())?,
                )?
            }
            Request::WaitForEvents { after } => {
                serde_json::to_value(owner.event_bus().wait_since(after).await?)?
            }
            Request::Automations => serde_json::to_value(owner.automations()?)?,
            Request::AutomationRuns {
                automation_id,
                limit,
            } => serde_json::to_value(owner.automation_runs(automation_id, limit)?)?,
            Request::DisableAutomation { automation_id } => {
                serde_json::to_value(owner.disable_automation(automation_id)?)?
            }
            Request::RelinkAutomation { automation_id } => {
                serde_json::to_value(owner.relink_automation(automation_id)?)?
            }
            Request::DeleteAutomation { automation_id } => {
                owner.delete_automation(automation_id)?;
                Value::Null
            }
            Request::DryRunAutomation { automation_id } => {
                // The simulation future is large; keep it off every owner call frame.
                serde_json::to_value(Box::pin(owner.dry_run_automation(automation_id)).await?)?
            }
            Request::Tokens {
                chain_id,
                limit,
                offset,
            } => serde_json::to_value(owner.tokens(chain_id, limit, offset)?)?,
            Request::AddToken {
                token,
                approximate_usd_price,
            } => serde_json::to_value(owner.add_token(token, approximate_usd_price).await?)?,
            Request::NativeTokenPrices => serde_json::to_value(owner.native_token_prices()?)?,
            Request::SetNativeTokenPrice { chain_id, price } => {
                owner.set_native_token_price(chain_id, price)?;
                Value::Null
            }
            Request::SetTokenPrice { reviewed, price } => {
                owner.set_token_price(&reviewed, price)?;
                Value::Null
            }
            Request::RemoveToken { reviewed } => {
                owner.remove_token(&reviewed)?;
                Value::Null
            }
            Request::ImportTokenListForReview {
                url,
                requested_chain_ids,
            } => serde_json::to_value(
                owner
                    .import_token_list_for_review(&url, &requested_chain_ids)
                    .await?,
            )?,
            Request::TokenProposals => serde_json::to_value(owner.token_proposals()?)?,
            Request::AcceptTokenProposals { proposals } => {
                serde_json::to_value(owner.accept_token_proposals(&proposals).await?)?
            }
            Request::RejectTokenProposals { proposals } => {
                serde_json::to_value(owner.reject_token_proposals(&proposals)?)?
            }
            Request::BeginDappSession { uri } => serde_json::to_value(self.dapps.begin(&uri)?)?,
            Request::DappSessions => serde_json::to_value(self.dapps.sessions()?)?,
            Request::WaitDappSession { session_id } => {
                self.dapps.wait(session_id).await?;
                Value::Null
            }
            Request::DisconnectDappSession { session_id } => {
                serde_json::to_value(self.dapps.disconnect(session_id)?)?
            }

            Request::DappReviews => serde_json::to_value(reviews.pending()?)?,
            Request::ApproveDappReview {
                session_id,
                index,
                reviewed_identity,
            } => {
                reviews
                    .approve(owner, session_id, index, &reviewed_identity)
                    .await?;
                Value::Null
            }
            Request::RejectDappReview {
                session_id,
                reviewed_identity,
            } => {
                reviews.reject(session_id, &reviewed_identity)?;
                Value::Null
            }
            Request::CloseDappReview {
                session_id,
                reviewed_identity,
            } => {
                reviews.close(session_id, &reviewed_identity)?;
                Value::Null
            }
            Request::Snapshot => serde_json::to_value(owner.snapshot()?)?,
            Request::Accounts => serde_json::to_value(owner.accounts()?)?,
            Request::Account { wallet_id } => serde_json::to_value(owner.account(&wallet_id)?)?,
            Request::Policy { wallet_id } => serde_json::to_value(owner.policy(&wallet_id)?)?,
            Request::PolicyHistory { wallet_id } => {
                serde_json::to_value(owner.policy_history(&wallet_id)?)?
            }
            Request::InstallPolicy {
                wallet_id,
                policy,
                reviewed_revision,
            } => serde_json::to_value(
                owner
                    .install_policy(&wallet_id, &policy, reviewed_revision)
                    .await?,
            )?,
            Request::Networks => serde_json::to_value(owner.networks()?)?,
            Request::NetworkByChainId { chain_id } => {
                serde_json::to_value(owner.network_by_chain_id(chain_id)?)?
            }
            Request::ResetNetworksToDefaults { reviewed } => {
                serde_json::to_value(owner.reset_networks_to_defaults(&reviewed).await?)?
            }
            Request::NetworkProposals => serde_json::to_value(owner.network_proposals()?)?,
            Request::AcceptNetworkProposal { proposal } => {
                owner.accept_network_proposal(&proposal).await?;
                Value::Null
            }
            Request::RejectNetworkProposal { proposal } => {
                serde_json::to_value(owner.reject_network_proposal(&proposal)?)?
            }
            Request::PolicyProposals => serde_json::to_value(owner.policy_proposals()?)?,
            Request::ApplyPolicyProposal { proposal } => {
                serde_json::to_value(owner.apply_policy_proposal(&proposal).await?)?
            }
            Request::RejectPolicyProposal { proposal } => {
                serde_json::to_value(owner.reject_policy_proposal(&proposal)?)?
            }
            Request::AddNetwork { network } => {
                owner.add_network(network).await?;
                Value::Null
            }
            Request::ReplaceNetwork {
                reviewed,
                replacement,
            } => {
                owner.replace_network(&reviewed, *replacement).await?;
                Value::Null
            }
            Request::SetNetworkDisabled { reviewed, disabled } => {
                serde_json::to_value(owner.set_network_disabled(&reviewed, disabled).await?)?
            }
            Request::DetailedNotificationPreviews => {
                serde_json::to_value(owner.detailed_notification_previews()?)?
            }
            Request::SetDetailedNotificationPreviews { enabled } => {
                owner.set_detailed_notification_previews(enabled).await?;
                Value::Null
            }
            Request::AppearancePreference => serde_json::to_value(owner.appearance_preference()?)?,
            Request::SetAppearancePreference { preference } => {
                owner.set_appearance_preference(preference)?;
                Value::Null
            }
            Request::CompanionServers => serde_json::to_value(owner.companion_servers()?)?,
            Request::SetCompanionServers { selection } => {
                owner.set_companion_servers(&selection)?;
                Value::Null
            }
            Request::GuidedSetup => serde_json::to_value(owner.guided_setup()?)?,
            Request::SetGuidedSetup { state } => {
                owner.set_guided_setup(&state)?;
                Value::Null
            }
            Request::TestnetMode => serde_json::to_value(owner.testnet_mode()?)?,
            Request::SetTestnetMode { enabled } => {
                owner.set_testnet_mode(enabled)?;
                Value::Null
            }
            Request::LegalStatus => serde_json::to_value(owner.legal_status()?)?,
            Request::LegalDocument { document } => {
                serde_json::to_value(owner.legal_document(document))?
            }
            Request::AcceptLegal {
                document,
                reviewed_digest,
            } => {
                owner.accept_legal(document, &reviewed_digest)?;
                Value::Null
            }
        })
    }
}

#[cfg(test)]
pub(crate) async fn dispatch(
    owner: &OwnerApi,
    reviews: &crate::dapp_reviews::DappReviews,
    request: Request,
) -> anyhow::Result<Value> {
    let (_active, receiver) = tokio::sync::watch::channel(0);
    let dapps = Arc::new(DappRuntime::new(owner.clone(), reviews.clone(), receiver));
    OwnerDispatcher::new(owner.clone(), dapps)
        .dispatch(request)
        .await
}

#[cfg(test)]
#[path = "owner_rpc_test.rs"]
mod tests;

#[cfg(test)]
#[path = "owner_token_rpc_test.rs"]
mod token_tests;

#[cfg(test)]
#[path = "owner_automation_rpc_test.rs"]
mod automation_tests;

#[cfg(test)]
#[path = "owner_activity_rpc_test.rs"]
mod activity_tests;

#[cfg(test)]
#[path = "owner_signature_rpc_test.rs"]
mod signature_tests;

#[cfg(test)]
#[path = "owner_account_rpc_test.rs"]
mod account_tests;

#[cfg(test)]
#[path = "owner_portfolio_rpc_test.rs"]
mod portfolio_tests;
