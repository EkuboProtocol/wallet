//! Bounded, display-only discovery of open Ekubo liquidity positions.
//!
//! Ekubo position NFTs are not enumerable onchain, so the Portfolio tab asks
//! Ekubo's public index for the open positions owned by one address on one
//! enabled chain. The answer is presentation data only: no signing, policy,
//! simulation, or transaction path reads it, and nothing is persisted.

use anyhow::{Context as _, Result, bail, ensure};
use serde::Deserialize;
use std::time::Duration;

const POSITIONS_ENDPOINT: &str = "https://prod-api.ekubo.org/positions/";
const PAGE_SIZE: usize = 200;
const MAX_PAGES: usize = 5;
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexedEkuboPosition {
    pub id: String,
    pub chain_id: u64,
    pub positions_address: String,
    pub token0: String,
    pub token1: String,
    pub lower_tick: i64,
    pub upper_tick: i64,
    pub current_tick: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexedEkuboPositions {
    pub positions: Vec<IndexedEkuboPosition>,
    pub total_items: usize,
}

#[derive(Deserialize)]
struct ApiPage {
    data: Vec<ApiPosition>,
    pagination: ApiPagination,
}

#[derive(Deserialize)]
struct ApiPosition {
    id: String,
    chain_id: String,
    positions_address: String,
    pool_key: ApiPoolKey,
    bounds: ApiBounds,
    pool_state: Option<ApiPoolState>,
}

#[derive(Deserialize)]
struct ApiPoolKey {
    token0: String,
    token1: String,
}

#[derive(Deserialize)]
struct ApiBounds {
    lower: i64,
    upper: i64,
}

#[derive(Deserialize)]
struct ApiPoolState {
    tick: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiPagination {
    page: usize,
    page_size: usize,
    total_pages: usize,
    total_items: usize,
}

pub(crate) async fn fetch_open_positions(
    owner: &str,
    chain_id: u64,
) -> Result<IndexedEkuboPositions> {
    let client = reqwest::Client::builder()
        .connect_timeout(REQUEST_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(format!("ekubo-wallet/{}", crate::BUILD_VERSION))
        .build()
        .context("could not construct Ekubo position client")?;
    let mut positions = Vec::new();
    let mut page_number = 1;

    let total_items = loop {
        let url = positions_url(owner, chain_id, page_number)?;
        let response = client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .context("Ekubo position index could not be reached")?;
        ensure!(
            response.status().is_success(),
            "Ekubo position index returned HTTP {}",
            response.status().as_u16()
        );
        if let Some(length) = response.content_length() {
            ensure!(
                length <= MAX_RESPONSE_BYTES,
                "Ekubo position response is too large"
            );
        }
        let body = bounded_body(response).await?;
        let page: ApiPage =
            serde_json::from_slice(&body).context("Ekubo position response is not valid JSON")?;
        ensure!(
            page.pagination.page == page_number,
            "Ekubo position response returned the wrong page"
        );
        ensure!(
            page.pagination.page_size <= PAGE_SIZE,
            "Ekubo position response exceeded the requested page size"
        );
        let total_items = page.pagination.total_items;
        positions.extend(
            page.data
                .into_iter()
                .map(parse_position)
                .collect::<Result<Vec<_>>>()?,
        );

        if page_number >= page.pagination.total_pages
            || page_number >= MAX_PAGES
            || positions.len() >= total_items
        {
            break total_items;
        }
        page_number += 1;
    };

    Ok(IndexedEkuboPositions {
        positions,
        total_items,
    })
}

fn positions_url(owner: &str, chain_id: u64, page: usize) -> Result<reqwest::Url> {
    let owner = normalize_address(owner).context("wallet address is invalid")?;
    let mut url = reqwest::Url::parse(POSITIONS_ENDPOINT)
        .context("compiled Ekubo position endpoint is invalid")?
        .join(&owner)
        .context("wallet address could not be added to Ekubo position endpoint")?;
    url.query_pairs_mut()
        .append_pair("state", "opened")
        .append_pair("chainId", &chain_id.to_string())
        .append_pair("pageSize", &PAGE_SIZE.to_string())
        .append_pair("page", &page.to_string());
    Ok(url)
}

async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("Ekubo position response could not be read")?
    {
        let total = body.len() as u64 + chunk.len() as u64;
        ensure!(
            total <= MAX_RESPONSE_BYTES,
            "Ekubo position response is too large"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_position(position: ApiPosition) -> Result<IndexedEkuboPosition> {
    let chain_id = parse_quantity(&position.chain_id).context("position chain ID is invalid")?;
    let id = normalize_hex(&position.id, 32).context("position ID is invalid")?;
    let positions_address =
        normalize_address(&position.positions_address).context("positions address is invalid")?;
    let token0 = normalize_address(&position.pool_key.token0).context("token0 is invalid")?;
    let token1 = normalize_address(&position.pool_key.token1).context("token1 is invalid")?;
    ensure!(
        position.bounds.lower < position.bounds.upper,
        "position bounds are invalid"
    );
    Ok(IndexedEkuboPosition {
        id,
        chain_id,
        positions_address,
        token0,
        token1,
        lower_tick: position.bounds.lower,
        upper_tick: position.bounds.upper,
        current_tick: position.pool_state.map(|state| state.tick),
    })
}

fn parse_quantity(value: &str) -> Result<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        ensure!(!hex.is_empty(), "hex quantity is empty");
        return u64::from_str_radix(hex, 16).context("hex quantity is out of range");
    }
    value
        .parse::<u64>()
        .context("decimal quantity is out of range")
}

fn normalize_address(value: &str) -> Result<String> {
    normalize_hex(value, 20)
}

fn normalize_hex(value: &str, bytes: usize) -> Result<String> {
    let digits = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .context("hex value has no 0x prefix")?;
    if digits.is_empty()
        || digits.len() > bytes * 2
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("hex value has invalid digits or length");
    }
    Ok(format!(
        "0x{:0>width$}",
        digits.to_ascii_lowercase(),
        width = bytes * 2
    ))
}

#[cfg(test)]
#[path = "ekubo_positions_test.rs"]
mod tests;
