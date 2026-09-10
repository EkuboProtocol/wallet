use super::*;
use crate::dapp_reviews::DappReviews;
use ekubo_wallet_client::portfolio::OwnerPortfolioSnapshot;

async fn portfolio(
    owner: &OwnerApi,
    wallet_id: Option<&str>,
) -> anyhow::Result<OwnerPortfolioSnapshot> {
    let request = serde_json::to_vec(&Request::Portfolio {
        wallet_id: wallet_id.map(str::to_owned),
    })?;
    Ok(serde_json::from_value(
        dispatch(
            owner,
            &DappReviews::default(),
            serde_json::from_slice(&request)?,
        )
        .await?,
    )?)
}

#[tokio::test]
async fn portfolio_filters_accounts_and_networks_and_preserves_read_errors() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    // A bound non-listening TCP socket refuses connections without contacting
    // any public RPC or risking another test acquiring this local port.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let endpoint = format!("http://{}", socket.local_addr().unwrap())
        .parse()
        .unwrap();
    owner
        .config()
        .update_for_test(|config| {
            let mut base = config.networks[0].clone();
            base.rpc_urls = vec![endpoint];
            base.aliases.clear();
            base.disabled = false;
            base.testnet = false;
            let mut disabled = base.clone();
            disabled.chain_id = 9002;
            disabled.name = "disabled".into();
            disabled.disabled = true;
            let mut testnet = base.clone();
            testnet.chain_id = 9003;
            testnet.name = "testnet".into();
            testnet.testnet = true;
            config.networks = vec![base, disabled, testnet];
            for (id, address) in [
                ("first", "0x1111111111111111111111111111111111111111"),
                ("second", "0x2222222222222222222222222222222222222222"),
            ] {
                config
                    .wallets
                    .push(serde_json::from_value(serde_json::json!({
                        "instance_id": uuid::Uuid::new_v4(), "id": id,
                        "address": address,
                        "created_at": chrono::Utc::now(), "source": "created"
                    }))?);
            }
            Ok(())
        })
        .unwrap();
    owner.set_testnet_mode(false).unwrap();
    let snapshot = portfolio(&owner, Some("second")).await.unwrap();
    assert_eq!(snapshot.accounts.len(), 1);
    assert_eq!(snapshot.accounts[0].wallet.id, "second");
    assert_eq!(snapshot.accounts[0].networks.len(), 1);
    let failed = &snapshot.accounts[0].networks[0];
    assert!(!failed.network.disabled && !failed.network.testnet);
    assert!(!failed.result.as_ref().unwrap_err().is_empty());
    assert!(
        portfolio(&owner, Some("missing"))
            .await
            .unwrap_err()
            .to_string()
            .contains("unknown account")
    );
    owner.set_testnet_mode(true).unwrap();
    let snapshot = portfolio(&owner, None).await.unwrap();
    assert_eq!(
        snapshot
            .accounts
            .iter()
            .map(|account| account.wallet.id.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    for account in snapshot.accounts {
        assert_eq!(account.networks.len(), 2);
        assert!(!account.networks[0].network.testnet);
        assert!(account.networks[1].network.testnet);
        assert!(
            account
                .networks
                .iter()
                .all(|network| !network.network.disabled && network.result.is_err())
        );
    }
}
