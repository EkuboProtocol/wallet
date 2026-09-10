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
}

impl OwnerDispatcher {
    // Platform adapters establish caller identity and native authentication
    // context before entering this shared dispatcher. No transport handle or
    // Linux UID is part of the wallet operation protocol.
    pub(crate) fn new(owner: OwnerApi, dapps: Arc<DappRuntime>) -> Self {
        Self { owner, dapps }
    }

    pub(crate) async fn dispatch(&self, request: Request) -> anyhow::Result<Value> {
        let owner = &self.owner;
        let reviews = self.dapps.reviews();
        Ok(match request {
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
