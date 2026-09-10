use super::*;
use crate::dapp_reviews::DappReviews;

use ekubo_wallet_core::{core::policy::WalletPolicy, legal::LegalDocument};

#[tokio::test]
async fn a_stale_network_review_cannot_accept_or_discard_its_replacement() {
    use ekubo_wallet_core::{config::NetworkConfig, policy_store::PolicyStore};
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let old = owner.networks().unwrap().remove(0);
    let mut replacement = old.clone();
    replacement.display_name = Some("Updated proposal".into());
    PolicyStore::production(directory.path())
        .unwrap()
        .put_network_proposal(&replacement)
        .unwrap();
    assert_eq!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::RejectNetworkProposal {
                proposal: old.clone()
            }
        )
        .await
        .unwrap(),
        false
    );
    assert!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::AcceptNetworkProposal { proposal: old }
        )
        .await
        .is_err()
    );
    let current: Vec<NetworkConfig> = serde_json::from_value(
        dispatch(&owner, &DappReviews::default(), Request::NetworkProposals)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(current, vec![replacement.clone()]);
    assert_eq!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::RejectNetworkProposal {
                proposal: replacement
            }
        )
        .await
        .unwrap(),
        true
    );
    assert!(owner.network_proposals().unwrap().is_empty());
}

#[tokio::test]
async fn resetting_networks_requires_the_current_reviewed_set() {
    use ekubo_wallet_core::config::{NetworkConfig, default_networks};
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let reviewed = owner.networks().unwrap();
    owner
        .config()
        .update_for_test(|config| {
            config.networks[0].display_name = Some("Changed after review".into());
            Ok(())
        })
        .unwrap();
    let changed = owner.networks().unwrap();
    assert!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::ResetNetworksToDefaults { reviewed }
        )
        .await
        .is_err()
    );
    assert_eq!(owner.networks().unwrap(), changed);
    let reset: Vec<NetworkConfig> = serde_json::from_value(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::ResetNetworksToDefaults { reviewed: changed },
        )
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(reset, default_networks());
    assert_eq!(owner.networks().unwrap(), reset);
}

#[tokio::test]
async fn account_read_uses_the_bound_authority() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let accounts = dispatch(&owner, &DappReviews::default(), Request::Accounts)
        .await
        .unwrap();
    assert_eq!(accounts, serde_json::json!([]));
    assert!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::Account {
                wallet_id: "other-profile-account".into()
            }
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn legal_acceptance_still_requires_the_reviewed_digest() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let document = LegalDocument::TermsOfService;
    let response = dispatch(
        &owner,
        &DappReviews::default(),
        Request::LegalDocument { document },
    )
    .await
    .unwrap();
    assert!(response[0].as_str().unwrap().len() > 100);
    assert!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::AcceptLegal {
                document,
                reviewed_digest: "wrong".into()
            }
        )
        .await
        .is_err()
    );
    dispatch(
        &owner,
        &DappReviews::default(),
        Request::AcceptLegal {
            document,
            reviewed_digest: response[1].as_str().unwrap().into(),
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn policy_updates_reject_stale_reviews_without_changing_state() {
    use ekubo_wallet_core::{
        config::WalletMetadata,
        policy_store::{PolicyStore, StoredPolicy},
    };

    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    // Metadata only: this test never creates or accesses an account key.
    let wallet: WalletMetadata = serde_json::from_value(serde_json::json!({
        "instance_id": uuid::Uuid::new_v4(),
        "id": "primary",
        "address": "0x1111111111111111111111111111111111111111",
        "created_at": chrono::Utc::now(),
        "source": "created"
    }))
    .unwrap();
    owner
        .config()
        .update_for_test(|config| {
            config.wallets.push(wallet.clone());
            Ok(())
        })
        .unwrap();
    PolicyStore::production(directory.path())
        .unwrap()
        .register_wallet_without_policy(&wallet)
        .unwrap();
    let policy = WalletPolicy::require_approval_for_everything();
    let installed = dispatch(
        &owner,
        &DappReviews::default(),
        Request::InstallPolicy {
            wallet_id: wallet.id.clone(),
            policy: policy.clone(),
            reviewed_revision: None,
        },
    )
    .await
    .unwrap();
    let stored: StoredPolicy = serde_json::from_value(installed.clone()).unwrap();
    assert_eq!(stored.wallet_instance_id, wallet.instance_id);
    assert_eq!(stored.policy, policy);
    assert!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::InstallPolicy {
                wallet_id: wallet.id.clone(),
                policy,
                reviewed_revision: None,
            },
        )
        .await
        .is_err()
    );
    assert_eq!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::Policy {
                wallet_id: wallet.id
            }
        )
        .await
        .unwrap(),
        installed
    );
}

#[tokio::test]
async fn network_disable_rejects_changed_reviewed_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let reviewed = owner.networks().unwrap().remove(0);
    let mut forged = reviewed.clone();
    forged.display_name = Some("different reviewed profile".into());
    assert!(
        dispatch(
            &owner,
            &DappReviews::default(),
            Request::SetNetworkDisabled {
                reviewed: forged,
                disabled: true,
            },
        )
        .await
        .is_err()
    );
    assert_eq!(owner.networks().unwrap()[0], reviewed);
    dispatch(
        &owner,
        &DappReviews::default(),
        Request::SetNetworkDisabled {
            reviewed,
            disabled: true,
        },
    )
    .await
    .unwrap();
    assert!(owner.networks().unwrap()[0].disabled);
}
