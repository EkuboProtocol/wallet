use super::*;

#[test]
fn position_pages_accept_api_quantities_and_normalize_addresses() {
    let page: ApiPage = serde_json::from_value(serde_json::json!({
        "data": [{
            "id": "0x01",
            "chain_id": "0x1",
            "positions_address": "0x2d9876a21af7545f8632c3af76ec90b5ad4b66d",
            "pool_key": {
                "token0": "0x0",
                "token1": "0x4c46e830bb56ce22735d5d8fc9cb90309317d0f",
                "fee": "0x0",
                "tick_spacing": "0x1",
                "extension": "0x0",
                "stableswap_params": null
            },
            "bounds": { "lower": 8_237_632, "upper": 8_653_474 },
            "pool_state": { "tick": 8_449_558 }
        }],
        "pagination": { "page": 1, "pageSize": 200, "totalPages": 1, "totalItems": 1 }
    }))
    .unwrap();

    let position = parse_position(page.data.into_iter().next().unwrap()).unwrap();
    assert_eq!(position.chain_id, 1);
    assert_eq!(position.id.len(), 66);
    assert_eq!(
        position.token0,
        "0x0000000000000000000000000000000000000000"
    );
    assert_eq!(
        position.token1,
        "0x04c46e830bb56ce22735d5d8fc9cb90309317d0f"
    );
    assert_eq!(position.current_tick, Some(8_449_558));
    assert_eq!(
        position.pool_config,
        B256::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            128, 0, 0, 1
        ])
    );
}

#[test]
fn position_url_is_fixed_to_the_public_index_and_one_enabled_chain() {
    let url = positions_url("0x1", 8453, 2).unwrap();
    assert_eq!(url.host_str(), Some("prod-api.ekubo.org"));
    assert_eq!(
        url.path(),
        "/positions/0x0000000000000000000000000000000000000001"
    );
    let query = url.query().unwrap();
    assert!(query.contains("state=opened"));
    assert!(query.contains("chainId=8453"));
    assert!(query.contains("pageSize=200"));
    assert!(query.contains("page=2"));
}

#[test]
fn malformed_or_oversized_api_identities_are_rejected() {
    assert!(normalize_address("not-an-address").is_err());
    assert!(normalize_address("0x10000000000000000000000000000000000000000").is_err());
    assert!(parse_quantity("0x10000000000000000").is_err());
}
