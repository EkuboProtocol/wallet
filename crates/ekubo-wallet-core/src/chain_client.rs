//! The small chain interface the wallet depends on.
//!
//! Wallet code speaks this trait rather than Alloy's generic provider API or
//! an RPC URL. The shipped implementation uses JSON-RPC, but an implementation
//! may verify responses, keep local state (for example a nonce high-water
//! mark), or use no RPC transport at all.

use alloy::{
    eips::{BlockId, BlockNumberOrTag, eip1559::Eip1559Estimation},
    primitives::{Address, B256, Bytes, U256},
    rpc::types::{
        Block, Transaction, TransactionReceipt, TransactionRequest,
        simulate::{SimulatePayload, SimulatedBlock},
    },
};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

pub type SharedChainClient = Arc<dyn ChainClient>;

/// One coherent view of an EVM chain.
///
/// Compound operations deliberately keep using the same client for all of
/// their calls. Failover chooses another client and restarts the operation;
/// it never splices one backend's pinned state into another's simulation.
#[async_trait]
pub trait ChainClient: Send + Sync {
    async fn chain_id(&self) -> Result<u64>;
    async fn block_number(&self) -> Result<u64>;
    async fn block_by_number(&self, block: BlockNumberOrTag) -> Result<Option<Block>>;
    async fn balance(&self, address: Address, block: BlockId) -> Result<U256>;
    async fn transaction_count(&self, address: Address, block: BlockId) -> Result<u64>;
    async fn code(&self, address: Address, block: BlockId) -> Result<Bytes>;
    async fn call(&self, request: TransactionRequest, block: BlockId) -> Result<Bytes>;
    async fn simulate_v1(
        &self,
        payload: SimulatePayload,
        block_number: Option<u64>,
    ) -> Result<Vec<SimulatedBlock>>;
    async fn estimate_eip1559_fees(&self) -> Result<Eip1559Estimation>;
    async fn estimate_gas(&self, request: TransactionRequest) -> Result<u64>;
    async fn transaction_receipt(&self, hash: B256) -> Result<Option<TransactionReceipt>>;
    async fn transaction_by_hash(&self, hash: B256) -> Result<Option<Transaction>>;
    async fn send_transaction(&self, bytes: Bytes) -> Result<B256>;
}
