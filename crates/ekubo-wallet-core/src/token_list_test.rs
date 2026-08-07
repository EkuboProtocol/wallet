use super::*;
use alloy::primitives::address;

const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

#[test]
fn parses_the_standard_wrapped_shape() {
    let body = br#"{
        "name": "Uniswap Labs Default",
        "tokens": [
            {"chainId": 1, "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
             "symbol": "USDC", "name": "USD Coin", "decimals": 6}
        ]
    }"#;
    let parsed = parse_token_list(body).unwrap();
    assert_eq!(
        parsed.declared_name.as_deref(),
        Some("Uniswap Labs Default")
    );
    assert_eq!(parsed.skipped_non_evm, 0);
    assert_eq!(parsed.tokens.len(), 1);
    let token = &parsed.tokens[0];
    assert_eq!(token.chain_id, 1);
    assert_eq!(
        token.address,
        address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
    );
    assert_eq!(token.symbol, "USDC");
    assert_eq!(token.name.as_deref(), Some("USD Coin"));
    assert_eq!(token.decimals, 6);
}

#[test]
fn parses_a_bare_array() {
    let body =
        format!(r#"[{{"chainId": 1, "address": "{USDC}", "symbol": "USDC", "decimals": 6}}]"#);
    let parsed = parse_token_list(body.as_bytes()).unwrap();
    assert!(parsed.declared_name.is_none());
    assert_eq!(parsed.tokens.len(), 1);
    assert!(parsed.tokens[0].name.is_none());
}

/// Ekubo's API spells the field `chain_id` and writes it as `0x`-hex. A
/// wallet that rejected that would push the owner toward hand-editing the
/// list, which is the one step that turns a curator's claim into an agent's.
#[test]
fn accepts_the_snake_case_hex_shape_ekubos_api_returns() {
    let body = format!(
        r#"[{{"chain_id": "0x1", "address": "{USDC}", "symbol": "USDC",
              "name": "USDC", "decimals": 6, "logo_url": "https://example.com/l",
              "total_supply": 71781369987.4076, "usd_price": 1.0}}]"#
    );
    let parsed = parse_token_list(body.as_bytes()).unwrap();
    assert_eq!(parsed.tokens.len(), 1);
    assert_eq!(parsed.tokens[0].chain_id, 1);
}

#[test]
fn accepts_a_decimal_string_chain_id() {
    let body =
        format!(r#"[{{"chain_id": "8453", "address": "{USDC}", "symbol": "X", "decimals": 18}}]"#);
    assert_eq!(
        parse_token_list(body.as_bytes()).unwrap().tokens[0].chain_id,
        8453
    );
}

/// A curator adding a field must not break every wallet that reads the list.
#[test]
fn ignores_fields_it_does_not_know() {
    let body = format!(
        r#"{{"name": "L", "tokens": [{{"chainId": 1, "address": "{USDC}", "symbol": "X",
             "decimals": 6, "extensions": {{"bridgeInfo": {{"10": {{"a": "b"}}}}}}}}]}}"#
    );
    assert_eq!(parse_token_list(body.as_bytes()).unwrap().tokens.len(), 1);
}

/// Ekubo's canonical list carries Starknet rows whose addresses are 32 bytes.
/// Those are rows for another ecosystem, not malformed rows, so they are
/// dropped and counted instead of failing the list that carried them.
#[test]
fn skips_and_counts_non_evm_entries() {
    let body = format!(
        r#"[{{"chain_id": "0x1", "address": "{USDC}", "symbol": "USDC", "decimals": 6}},
            {{"chain_id": "0x534e5f4d41494e",
              "address": "0x33068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb",
              "symbol": "USDC", "decimals": 6}}]"#
    );
    let parsed = parse_token_list(body.as_bytes()).unwrap();
    assert_eq!(parsed.tokens.len(), 1);
    assert_eq!(parsed.skipped_non_evm, 1);
}

#[test]
fn a_list_of_only_non_evm_entries_is_an_error() {
    let body = br#"[{"chain_id": "0x534e5f4d41494e",
        "address": "0x33068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb",
        "symbol": "USDC", "decimals": 6}]"#;
    let error = parse_token_list(body).unwrap_err().to_string();
    assert!(error.contains("another ecosystem"), "{error}");
}

#[test]
fn rejects_an_empty_list() {
    let error = parse_token_list(b"[]").unwrap_err().to_string();
    assert!(error.contains("lists no tokens"), "{error}");
}

#[test]
fn rejects_bytes_that_are_not_a_token_list() {
    let error = parse_token_list(b"{\"hello\": true}")
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a token list"), "{error}");
}

#[test]
fn rejects_more_entries_than_one_import_may_verify() {
    let entry = format!(r#"{{"chainId": 1, "address": "{USDC}", "symbol": "X", "decimals": 6}}"#);
    let body = format!(
        "[{}]",
        std::iter::repeat_n(entry.as_str(), MAX_IMPORT_TOKENS + 1)
            .collect::<Vec<_>>()
            .join(",")
    );
    let error = parse_token_list(body.as_bytes()).unwrap_err().to_string();
    assert!(error.contains("one import may verify"), "{error}");
}

#[test]
fn rejects_a_body_over_the_byte_cap_before_parsing_it() {
    let body = vec![b' '; MAX_TOKEN_LIST_BYTES + 1];
    let error = parse_token_list(&body).unwrap_err().to_string();
    assert!(error.contains("larger than"), "{error}");
}

#[test]
fn rejects_a_chain_id_that_is_not_a_number() {
    let body = format!(
        r#"[{{"chain_id": "mainnet", "address": "{USDC}", "symbol": "X", "decimals": 6}}]"#
    );
    let error = parse_token_list(body.as_bytes()).unwrap_err().to_string();
    assert!(error.contains("is not a chain ID"), "{error}");
}
