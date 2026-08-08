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

/// The standard schema's `version` and `timestamp` are what tell an owner
/// which revision of a list they are being asked to accept, and a re-import
/// whether anything moved. They are reported, never acted on.
#[test]
fn reports_the_standard_schemas_version_and_timestamp() {
    let body = format!(
        r#"{{"name": "Uniswap Labs Default",
             "timestamp": "2026-08-01T00:00:00.000Z",
             "version": {{"major": 12, "minor": 3, "patch": 1}},
             "keywords": ["default"], "logoURI": "ipfs://Qm",
             "tokens": [{{"chainId": 1, "address": "{USDC}", "symbol": "USDC",
                          "name": "USD Coin", "decimals": 6}}]}}"#
    );
    let parsed = parse_token_list(body.as_bytes()).unwrap();
    assert_eq!(parsed.declared_version.as_deref(), Some("12.3.1"));
    assert_eq!(
        parsed.declared_timestamp.as_deref(),
        Some("2026-08-01T00:00:00.000Z")
    );
}

/// Ekubo's API returns a bare array, and plenty of wrapped lists omit the
/// version. Neither is an error, so both simply report nothing.
#[test]
fn a_list_without_a_version_reports_none() {
    let body = format!(
        r#"{{"name": "L", "tokens": [{{"chainId": 1, "address": "{USDC}",
             "symbol": "X", "decimals": 6}}]}}"#
    );
    let parsed = parse_token_list(body.as_bytes()).unwrap();
    assert!(parsed.declared_version.is_none());
    assert!(parsed.declared_timestamp.is_none());
}

/// A curator's malformed date must not fail a list whose entries are fine:
/// nothing here decides anything by the timestamp, so it travels verbatim.
#[test]
fn a_timestamp_is_passed_through_without_being_parsed() {
    let body = format!(
        r#"{{"name": "L", "timestamp": "last Tuesday",
             "tokens": [{{"chainId": 1, "address": "{USDC}", "symbol": "X", "decimals": 6}}]}}"#
    );
    let parsed = parse_token_list(body.as_bytes()).unwrap();
    assert_eq!(parsed.declared_timestamp.as_deref(), Some("last Tuesday"));
    assert_eq!(parsed.tokens.len(), 1);
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
    assert!(error.contains("one import may carry"), "{error}");
}

#[test]
fn rejects_a_body_over_the_byte_cap_before_parsing_it() {
    let body = vec![b' '; MAX_TOKEN_LIST_BYTES + 1];
    let error = parse_token_list(&body).unwrap_err().to_string();
    assert!(error.contains("larger than"), "{error}");
}

/// The case the filter exists for: charging the import cap against the whole
/// list refuses it without ever asking which chain the owner wanted, while
/// selecting first turns the same list into an import. Stated against the cap
/// rather than a fixed count, so it keeps testing the behaviour if the cap
/// moves again.
#[test]
fn a_list_over_the_import_cap_still_imports_one_chain() {
    let entry = |chain: u64| {
        format!(r#"{{"chainId": {chain}, "address": "{USDC}", "symbol": "X", "decimals": 6}}"#)
    };
    let wanted = MAX_IMPORT_TOKENS - 100;
    let rows: Vec<String> = std::iter::repeat_n(entry(1), wanted)
        .chain(std::iter::repeat_n(entry(8453), 500))
        .collect();
    let body = format!(r#"{{"name": "Big", "tokens": [{}]}}"#, rows.join(","));

    // Unfiltered, the list is over the cap and says so.
    let error = parse_token_list(body.as_bytes()).unwrap_err().to_string();
    assert!(error.contains("one import may carry"), "{error}");

    // Selecting a chain charges the cap against what the owner is handed.
    let parsed = parse_token_list_for_chains(body.as_bytes(), &[1]).unwrap();
    assert_eq!(parsed.tokens.len(), wanted);
    assert!(parsed.tokens.iter().all(|token| token.chain_id == 1));
    assert_eq!(parsed.skipped_other_chain, 500);
    assert_eq!(parsed.skipped_non_evm, 0);
}

/// Several chains at once, because an owner usually runs more than one.
#[test]
fn selects_every_chain_asked_for() {
    let entry = |chain: u64, symbol: &str| {
        format!(
            r#"{{"chainId": {chain}, "address": "{USDC}", "symbol": "{symbol}", "decimals": 6}}"#
        )
    };
    let body = format!(
        "[{}, {}, {}]",
        entry(1, "A"),
        entry(8453, "B"),
        entry(999, "C")
    );
    let parsed = parse_token_list_for_chains(body.as_bytes(), &[1, 8453]).unwrap();
    assert_eq!(parsed.tokens.len(), 2);
    assert_eq!(parsed.skipped_other_chain, 1);
}

/// An empty selection means every chain, so the filter is opt-in and a
/// single-chain list needs no ceremony.
#[test]
fn an_empty_selection_takes_every_chain() {
    let body = format!(
        r#"[{{"chainId": 1, "address": "{USDC}", "symbol": "A", "decimals": 6}},
            {{"chainId": 8453, "address": "{USDC}", "symbol": "B", "decimals": 6}}]"#
    );
    let parsed = parse_token_list_for_chains(body.as_bytes(), &[]).unwrap();
    assert_eq!(parsed.tokens.len(), 2);
    assert_eq!(parsed.skipped_other_chain, 0);
}

/// A selection that matches nothing is an error that says what the list did
/// carry, so the caller can pick a chain it actually names instead of
/// guessing at an empty result.
#[test]
fn selecting_a_chain_the_list_does_not_name_says_so() {
    let body = format!(r#"[{{"chainId": 1, "address": "{USDC}", "symbol": "A", "decimals": 6}}]"#);
    let error = parse_token_list_for_chains(body.as_bytes(), &[8453])
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("no tokens on the 1 chain selected"),
        "{error}"
    );
    assert!(error.contains("1 entry for other chains"), "{error}");
}

/// The selection cap is charged after filtering, and the fix it names has to
/// match the list: an overflow that is all on one chain cannot be fixed by
/// narrowing chains, so it must not be told to.
#[test]
fn a_single_chain_selection_over_the_cap_is_not_told_to_narrow_chains() {
    let entry = format!(r#"{{"chainId": 1, "address": "{USDC}", "symbol": "X", "decimals": 6}}"#);
    let body = format!(
        "[{}]",
        std::iter::repeat_n(entry.as_str(), MAX_IMPORT_TOKENS + 1)
            .collect::<Vec<_>>()
            .join(",")
    );
    let error = parse_token_list_for_chains(body.as_bytes(), &[1])
        .unwrap_err()
        .to_string();
    assert!(error.contains("one import may carry"), "{error}");
    assert!(!error.contains("select fewer chains"), "{error}");
    assert!(error.contains("more specific list"), "{error}");
}

/// With several chains selected, narrowing is a real fix and is offered.
#[test]
fn a_multi_chain_selection_over_the_cap_is_told_to_narrow_chains() {
    let entry = |chain: u64| {
        format!(r#"{{"chainId": {chain}, "address": "{USDC}", "symbol": "X", "decimals": 6}}"#)
    };
    let half = MAX_IMPORT_TOKENS / 2 + 1;
    let rows: Vec<String> = std::iter::repeat_n(entry(1), half)
        .chain(std::iter::repeat_n(entry(8453), half))
        .collect();
    let body = format!("[{}]", rows.join(","));
    let error = parse_token_list_for_chains(body.as_bytes(), &[1, 8453])
        .unwrap_err()
        .to_string();
    assert!(error.contains("select fewer chains"), "{error}");
}

/// A list too large to walk is refused before any of it is selected. This is
/// the structural bound rather than the import cap, and the two are different
/// numbers, so the message must not claim one import could carry this many.
#[test]
fn a_list_over_the_structural_cap_is_refused_before_selection() {
    let entry = format!(r#"{{"chainId": 1, "address": "{USDC}", "symbol": "X", "decimals": 6}}"#);
    let body = format!(
        "[{}]",
        std::iter::repeat_n(entry.as_str(), MAX_LIST_ENTRIES + 1)
            .collect::<Vec<_>>()
            .join(",")
    );
    let error = parse_token_list_for_chains(body.as_bytes(), &[8453])
        .unwrap_err()
        .to_string();
    assert!(error.contains("this wallet will read"), "{error}");
    assert!(!error.contains("one import may carry"), "{error}");
}

#[test]
fn rejects_a_chain_id_that_is_not_a_number() {
    let body = format!(
        r#"[{{"chain_id": "mainnet", "address": "{USDC}", "symbol": "X", "decimals": 6}}]"#
    );
    let error = parse_token_list(body.as_bytes()).unwrap_err().to_string();
    assert!(error.contains("is not a chain ID"), "{error}");
}
