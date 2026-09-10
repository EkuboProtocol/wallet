use super::*;
use crate::dapp_reviews::DappReviews;
use ekubo_wallet_core::{
    automation::{Automation, AutomationDefinition, AutomationState, CronSchedule},
    automation_store::{AutomationRun, AutomationStore, RunOutcome},
    config::WalletMetadata,
    core::policy::WalletPolicy,
    policy_store::PolicyStore,
};

async fn call<T: serde::de::DeserializeOwned>(
    owner: &OwnerApi,
    request: Request,
) -> anyhow::Result<T> {
    let wire = serde_json::to_vec(&request)?;
    let response = dispatch(
        owner,
        &DappReviews::default(),
        serde_json::from_slice(&wire)?,
    )
    .await?;
    Ok(serde_json::from_value(response)?)
}

#[tokio::test]
async fn automation_rpc_keeps_lifecycle_and_history_in_the_service() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet: WalletMetadata = serde_json::from_value(serde_json::json!({
        "instance_id": uuid::Uuid::new_v4(), "id": "primary",
        "address": "0x1111111111111111111111111111111111111111",
        "created_at": chrono::Utc::now(), "source": "created"
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
    let policy = owner
        .install_policy(
            &wallet.id,
            &WalletPolicy::require_approval_for_everything(),
            None,
        )
        .await
        .unwrap();
    let chain_id = owner.networks().unwrap()[0].chain_id;
    let definition = AutomationDefinition::new(
        "Synthetic automation",
        alloy::primitives::Bytes::from_static(&[0x00]),
        alloy::primitives::Bytes::new(),
        CronSchedule::parse("0 0 * * * *").unwrap(),
        chain_id,
    )
    .unwrap();
    let mut store = AutomationStore::production(directory.path()).unwrap();
    let installed = store
        .install(&wallet, "test", &definition, policy.revision)
        .unwrap()
        .automation;
    let listed: Vec<Automation> = call(&owner, Request::Automations).await.unwrap();
    assert_eq!(listed, vec![installed.clone()]);
    assert!(
        call::<()>(
            &owner,
            Request::DeleteAutomation {
                automation_id: installed.id
            }
        )
        .await
        .is_err()
    );
    let stopped: Automation = call(
        &owner,
        Request::DisableAutomation {
            automation_id: installed.id,
        },
    )
    .await
    .unwrap();
    assert_eq!(stopped.state, AutomationState::Disabled);
    let current_policy = owner
        .install_policy(&wallet.id, &WalletPolicy::deny_all(), Some(policy.revision))
        .await
        .unwrap();
    assert!(current_policy.revision > policy.revision);
    let restarted: Automation = call(
        &owner,
        Request::RelinkAutomation {
            automation_id: installed.id,
        },
    )
    .await
    .unwrap();
    assert_eq!(restarted.state, AutomationState::Enabled);
    assert_eq!(restarted.policy_revision, current_policy.revision);
    assert!(
        call::<()>(
            &owner,
            Request::DeleteAutomation {
                automation_id: installed.id
            }
        )
        .await
        .is_err()
    );
    store
        .record_run(
            installed.id,
            RunOutcome::Idle,
            "synthetic idle tick",
            None,
            0,
            chrono::Utc::now(),
        )
        .unwrap();
    let history: Vec<AutomationRun> = call(
        &owner,
        Request::AutomationRuns {
            automation_id: installed.id,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].outcome, RunOutcome::Idle);
    call::<Automation>(
        &owner,
        Request::DisableAutomation {
            automation_id: installed.id,
        },
    )
    .await
    .unwrap();
    call::<()>(
        &owner,
        Request::DeleteAutomation {
            automation_id: installed.id,
        },
    )
    .await
    .unwrap();
    assert!(store.get(installed.id).unwrap().is_none());
    assert!(store.runs(installed.id, 10).unwrap().is_empty());
    // No account key or network access: missing records fail before polling.
    assert!(
        call::<serde_json::Value>(
            &owner,
            Request::DryRunAutomation {
                automation_id: installed.id
            }
        )
        .await
        .is_err()
    );
}
