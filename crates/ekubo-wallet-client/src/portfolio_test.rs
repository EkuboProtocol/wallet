use super::*;

#[test]
fn portfolio_wire_preserves_exact_balances_and_partial_failures() {
    let network = ekubo_wallet_core::config::default_networks().remove(0);
    let exact = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let snapshot = OwnerPortfolioSnapshot {
        accounts: vec![OwnerPortfolioAccount {
            wallet: serde_json::from_value(serde_json::json!({
                "instance_id": "00000000-0000-0000-0000-000000000001",
                "id": "synthetic", "address": "0x1111111111111111111111111111111111111111",
                "created_at": "2026-01-01T00:00:00Z", "source": "created"
            }))
            .unwrap(),
            networks: vec![
                OwnerPortfolioNetwork {
                    network: network.clone(),
                    result: Ok(Portfolio {
                        address: "0x1111111111111111111111111111111111111111".into(),
                        chain_id: network.chain_id.to_string(),
                        network: network.name.clone(),
                        native_balance: exact.into(),
                        block_number: "9007199254740993".into(),
                        tokens: vec![ekubo_wallet_core::token_store::PortfolioToken {
                            address: "0x2222222222222222222222222222222222222222".into(),
                            symbol: None,
                            name: None,
                            decimals: None,
                            balance: exact.into(),
                            approximate_usd_price: None,
                        }],
                        tokens_checked: 20,
                        tokens_skipped: Some(3),
                        fork: None,
                    }),
                },
                OwnerPortfolioNetwork {
                    network,
                    result: Err("one unavailable network".into()),
                },
            ],
        }],
    };
    let decoded: OwnerPortfolioSnapshot =
        serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let balances = decoded.accounts[0].networks[0].result.as_ref().unwrap();
    assert_eq!(balances.native_balance, exact);
    assert_eq!(balances.tokens[0].balance, exact);
    assert_eq!(balances.tokens[0].decimals, None);
    assert_eq!(balances.block_number, "9007199254740993");
    assert_eq!(balances.tokens_skipped, Some(3));
    assert_eq!(
        decoded.accounts[0].networks[1].result.as_ref().unwrap_err(),
        "one unavailable network"
    );
}
