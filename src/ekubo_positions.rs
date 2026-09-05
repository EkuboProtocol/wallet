//! Bounded, display-only discovery of open Ekubo liquidity positions.
//!
//! Ekubo position NFTs are not enumerable onchain, so the Portfolio tab asks
//! Ekubo's public index for the open positions owned by one address on one
//! enabled chain. The answer is presentation data only: no signing, policy,
//! simulation, or transaction path reads it, and nothing is persisted.

use alloy::{
    eips::BlockId,
    network::TransactionBuilder as _,
    primitives::{Address, B256, Bytes, U256},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolCall as _,
};
use anyhow::{Context as _, Result, bail, ensure};
use ekubo_wallet_core::{
    config::NetworkConfig,
    rpc::{MULTICALL3_ADDRESS, ensure_serving_chain, try_clients},
};
use serde::Deserialize;
use std::{str::FromStr as _, time::Duration};

const POSITIONS_ENDPOINT: &str = "https://prod-api.ekubo.org/positions/";
const PAGE_SIZE: usize = 200;
const MAX_PAGES: usize = 5;
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_POSITION_CALLS_PER_BATCH: usize = 100;
const MAX_TICK_SPACING: u32 = 698_605;

sol! {
    struct PositionPoolKey {
        address token0;
        address token1;
        bytes32 config;
    }

    function getPositionFeesAndLiquidity(
        uint256 id,
        PositionPoolKey poolKey,
        int32 tickLower,
        int32 tickUpper
    ) external view returns (
        uint128 liquidity,
        uint128 principal0,
        uint128 principal1,
        uint128 fees0,
        uint128 fees1
    );

    struct PositionCall3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct PositionResult3 {
        bool success;
        bytes returnData;
    }

    function aggregate3(PositionCall3[] calls)
        external payable
        returns (PositionResult3[] returnData);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexedEkuboPosition {
    pub id: String,
    pub chain_id: u64,
    pub positions_address: String,
    pub token0: String,
    pub token1: String,
    pub pool_config: B256,
    pub lower_tick: i32,
    pub upper_tick: i32,
    pub current_tick: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexedEkuboPositionState {
    pub liquidity: u128,
    pub principal0: u128,
    pub principal1: u128,
    pub fees0: u128,
    pub fees1: u128,
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
    fee: String,
    tick_spacing: Option<String>,
    extension: String,
    stableswap_params: Option<ApiStableswapParams>,
}

#[derive(Deserialize)]
struct ApiStableswapParams {
    center_tick: i64,
    amplification: u64,
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
    let pool_config = parse_pool_config(&position.pool_key).context("pool config is invalid")?;
    let lower_tick = i32::try_from(position.bounds.lower).context("lower tick is out of range")?;
    let upper_tick = i32::try_from(position.bounds.upper).context("upper tick is out of range")?;
    let current_tick = position
        .pool_state
        .map(|state| i32::try_from(state.tick).context("current tick is out of range"))
        .transpose()?;
    ensure!(lower_tick < upper_tick, "position bounds are invalid");
    Ok(IndexedEkuboPosition {
        id,
        chain_id,
        positions_address,
        token0,
        token1,
        pool_config,
        lower_tick,
        upper_tick,
        current_tick,
    })
}

fn parse_pool_config(pool: &ApiPoolKey) -> Result<B256> {
    let extension = normalize_address(&pool.extension).context("extension is invalid")?;
    let extension = hex::decode(&extension[2..]).context("extension could not be decoded")?;
    let fee = parse_quantity(&pool.fee).context("fee is invalid")?;
    let type_config = match (&pool.tick_spacing, &pool.stableswap_params) {
        (Some(spacing), None) => {
            let spacing =
                u32::try_from(parse_quantity(spacing)?).context("tick spacing is out of range")?;
            ensure!(
                (1..=MAX_TICK_SPACING).contains(&spacing),
                "tick spacing is out of range"
            );
            0x8000_0000 | spacing
        }
        (None, Some(params)) => {
            ensure!(params.amplification <= 26, "amplification is out of range");
            ensure!(
                params.center_tick % 16 == 0,
                "stableswap center tick is not aligned"
            );
            let scaled = params.center_tick / 16;
            ensure!(
                (-8_388_608..=8_388_607).contains(&scaled),
                "stableswap center tick is out of range"
            );
            let encoded_center = i32::try_from(scaled)
                .context("stableswap center tick is out of range")?
                .cast_unsigned()
                & 0x00ff_ffff;
            let amplification =
                u32::try_from(params.amplification).context("amplification is out of range")?;
            (amplification << 24) | encoded_center
        }
        (None, None) => 0,
        (Some(_), Some(_)) => bail!("pool type is ambiguous"),
    };

    let mut config = [0_u8; 32];
    config[..20].copy_from_slice(&extension);
    config[20..28].copy_from_slice(&fee.to_be_bytes());
    config[28..].copy_from_slice(&type_config.to_be_bytes());
    Ok(B256::from(config))
}

pub(crate) async fn fetch_position_states(
    network: &NetworkConfig,
    positions: &[IndexedEkuboPosition],
) -> Vec<std::result::Result<IndexedEkuboPositionState, String>> {
    let mut states = Vec::with_capacity(positions.len());
    for chunk in positions.chunks(MAX_POSITION_CALLS_PER_BATCH) {
        match fetch_position_state_batch(network, chunk).await {
            Ok(batch) => states.extend(batch),
            Err(error) => {
                let error =
                    ekubo_wallet_core::sanitize::stripped_capped(&format!("{error:#}"), 500);
                states.extend((0..chunk.len()).map(|_| Err(error.clone())));
            }
        }
    }
    states
}

async fn fetch_position_state_batch(
    network: &NetworkConfig,
    positions: &[IndexedEkuboPosition],
) -> Result<Vec<std::result::Result<IndexedEkuboPositionState, String>>> {
    let calls = positions
        .iter()
        .map(position_call)
        .collect::<Result<Vec<_>>>()?;
    let encoded = aggregate3Call { calls }.abi_encode();
    let request = TransactionRequest::default()
        .with_to(MULTICALL3_ADDRESS)
        .with_input(encoded);
    let response = try_clients(network, move |client| {
        let request = request.clone();
        async move {
            tokio::time::timeout(
                RPC_TIMEOUT,
                ensure_serving_chain(client.as_ref(), network.chain_id),
            )
            .await
            .context("RPC chain check timed out")??;
            tokio::time::timeout(RPC_TIMEOUT, client.call(request, BlockId::pending()))
                .await
                .context("Ekubo position read timed out")?
                .context("Ekubo position read failed")
        }
    })
    .await?;
    let decoded = aggregate3Call::abi_decode_returns(&response)
        .context("Multicall3 returned undecodable Ekubo position data")?;
    ensure!(
        decoded.len() == positions.len(),
        "Multicall3 returned the wrong number of Ekubo positions"
    );
    Ok(decoded
        .into_iter()
        .map(|result| {
            if !result.success {
                return Err("Positions contract could not read this position".to_owned());
            }
            getPositionFeesAndLiquidityCall::abi_decode_returns(&result.returnData)
                .map(|values| IndexedEkuboPositionState {
                    liquidity: values.liquidity,
                    principal0: values.principal0,
                    principal1: values.principal1,
                    fees0: values.fees0,
                    fees1: values.fees1,
                })
                .map_err(|_| "Positions contract returned unreadable amounts".to_owned())
        })
        .collect())
}

fn position_call(position: &IndexedEkuboPosition) -> Result<PositionCall3> {
    let target = Address::from_str(&position.positions_address)
        .context("positions address could not be decoded")?;
    let token0 = Address::from_str(&position.token0).context("token0 could not be decoded")?;
    let token1 = Address::from_str(&position.token1).context("token1 could not be decoded")?;
    let id = U256::from_str(&position.id).context("position ID could not be decoded")?;
    let call_data = getPositionFeesAndLiquidityCall {
        id,
        poolKey: PositionPoolKey {
            token0,
            token1,
            config: position.pool_config,
        },
        tickLower: position.lower_tick,
        tickUpper: position.upper_tick,
    }
    .abi_encode();
    Ok(PositionCall3 {
        target,
        allowFailure: true,
        callData: Bytes::from(call_data),
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
