use super::*;
use crate::dapp_reviews::DappReviews;
use ekubo_wallet_core::token_store::{
    ListedToken, ProposalSource, StoredToken, TokenProposal, TokenStore,
};

async fn call<T: serde::de::DeserializeOwned>(
    owner: &OwnerApi,
    request: Request,
) -> anyhow::Result<T> {
    // Exercise the wire representation as well as service dispatch: reviewed
    // timestamps and metadata must survive the desktop round trip exactly.
    let request = serde_json::from_slice(&serde_json::to_vec(&request)?)?;
    serde_json::from_value(dispatch(owner, &DappReviews::default(), request).await?)
        .map_err(Into::into)
}

fn token(chain_id: u64) -> ListedToken {
    ListedToken {
        chain_id,
        address: alloy::primitives::Address::repeat_byte(0x42),
        symbol: "TEST".into(),
        name: Some("Synthetic token".into()),
        decimals: 18,
    }
}

#[tokio::test]
async fn stale_token_metadata_cannot_remove_or_reprice_a_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let chain_id = owner.networks().unwrap()[0].chain_id;
    let mut listed = token(chain_id);
    let reviewed: StoredToken = call(
        &owner,
        Request::AddToken {
            token: listed.clone(),
            approximate_usd_price: Some(1.0),
        },
    )
    .await
    .unwrap();
    call::<()>(
        &owner,
        Request::RemoveToken {
            reviewed: reviewed.clone(),
        },
    )
    .await
    .unwrap();
    listed.symbol = "REPLACED".into();
    let current: StoredToken = call(
        &owner,
        Request::AddToken {
            token: listed,
            approximate_usd_price: Some(2.0),
        },
    )
    .await
    .unwrap();
    assert!(
        call::<()>(
            &owner,
            Request::RemoveToken {
                reviewed: reviewed.clone()
            }
        )
        .await
        .is_err()
    );
    assert!(
        call::<()>(
            &owner,
            Request::SetTokenPrice {
                reviewed,
                price: Some(99.0)
            }
        )
        .await
        .is_err()
    );
    let store = TokenStore::production(directory.path()).unwrap();
    assert_eq!(
        store.get(chain_id, token(chain_id).address).unwrap(),
        Some(current.clone())
    );
    call::<()>(
        &owner,
        Request::SetTokenPrice {
            reviewed: current.clone(),
            price: Some(3.0),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        store
            .get(chain_id, token(chain_id).address)
            .unwrap()
            .unwrap()
            .approximate_usd_price,
        Some(3.0)
    );
    call::<()>(&owner, Request::RemoveToken { reviewed: current })
        .await
        .unwrap();
    assert!(
        store
            .get(chain_id, token(chain_id).address)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn stale_proposals_cannot_install_or_discard_changed_names() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let chain_id = owner.networks().unwrap()[0].chain_id;
    let mut listed = token(chain_id);
    let mut store = TokenStore::production(directory.path()).unwrap();
    store
        .propose(&[listed.clone()], &ProposalSource::Claimed("test"))
        .unwrap();
    let old: Vec<TokenProposal> = call(&owner, Request::TokenProposals).await.unwrap();
    listed.symbol = "CHANGED".into();
    store
        .propose(&[listed.clone()], &ProposalSource::Claimed("test"))
        .unwrap();
    let current: Vec<TokenProposal> = call(&owner, Request::TokenProposals).await.unwrap();
    assert!(
        call::<u64>(
            &owner,
            Request::AcceptTokenProposals {
                proposals: old.clone()
            }
        )
        .await
        .is_err()
    );
    assert_eq!(
        call::<u64>(&owner, Request::RejectTokenProposals { proposals: old })
            .await
            .unwrap(),
        0
    );
    assert_eq!(store.proposals().unwrap(), current);
    assert!(store.get(chain_id, listed.address).unwrap().is_none());
    let mut forged = current.clone();
    forged[0].token.decimals = 6;
    assert!(
        call::<u64>(&owner, Request::AcceptTokenProposals { proposals: forged })
            .await
            .is_err()
    );
    assert_eq!(
        call::<u64>(
            &owner,
            Request::AcceptTokenProposals {
                proposals: current.clone()
            }
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        store
            .get(chain_id, listed.address)
            .unwrap()
            .unwrap()
            .symbol
            .as_deref(),
        Some("CHANGED")
    );
    assert!(store.proposals().unwrap().is_empty());
    assert!(
        call::<u64>(&owner, Request::AcceptTokenProposals { proposals: current })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn token_operations_keep_network_and_price_validation_in_service() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let chain_id = owner.networks().unwrap()[0].chain_id;
    assert!(owner.network_by_chain_id(u64::MAX).is_err());
    assert!(
        call::<StoredToken>(
            &owner,
            Request::AddToken {
                token: token(u64::MAX),
                approximate_usd_price: None
            }
        )
        .await
        .is_err()
    );
    assert!(
        call::<()>(
            &owner,
            Request::SetNativeTokenPrice {
                chain_id: u64::MAX,
                price: Some(1.0)
            }
        )
        .await
        .is_err()
    );
    assert!(
        call::<()>(
            &owner,
            Request::SetNativeTokenPrice {
                chain_id,
                price: Some(-1.0)
            }
        )
        .await
        .is_err()
    );
    call::<()>(
        &owner,
        Request::SetNativeTokenPrice {
            chain_id,
            price: Some(12.0),
        },
    )
    .await
    .unwrap();
    let prices: std::collections::BTreeMap<u64, f64> =
        call(&owner, Request::NativeTokenPrices).await.unwrap();
    assert_eq!(prices.get(&chain_id), Some(&12.0));
    // Invalid selected chains must be rejected before attempting any URL fetch.
    assert!(
        call::<serde_json::Value>(
            &owner,
            Request::ImportTokenListForReview {
                url: "invalid URL; no network call".into(),
                requested_chain_ids: vec![u64::MAX],
            }
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("network")
    );
}
