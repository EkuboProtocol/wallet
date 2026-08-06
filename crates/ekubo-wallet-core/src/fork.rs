//! Temporary, in-memory simulation forks for agent workflows.
//!
//! A fork is nothing more than **an ordered list of already-simulated
//! execution plans plus one pinned parent block**. No resulting state is ever
//! stored. Every call replays the whole list through `eth_simulateV1`, whose
//! `block_state_calls` array already gives each `SimBlock` the state produced
//! by the previous one. The configured RPC therefore still executes every
//! opcode: there is no local EVM, no `eth_getProof`, and no way for fork state
//! to diverge from what that RPC would produce for the same calls.
//!
//! Replay is O(n²) in calls across a session, so a fork holds a single-digit
//! number of plans, expires quickly, and is capped per wallet.
//!
//! Forks have no bearing on policy or signatures. A fork cannot create a
//! pending request, cannot produce signed bytes, cannot mark anything
//! approved, and cannot satisfy a policy rule; submission re-simulates and
//! re-policy-checks against real chain state. Fork state is never shown at
//! approval time and never survives a restart.
//!
//! ## Block numbers
//!
//! `eth_simulateV1` assigns each `SimBlock` its own strictly increasing block
//! number, so applying a plan advances the simulated block by one. `block
//! .number` and `block.timestamp` observed inside step N are therefore not the
//! pinned parent's. That artifact is reported in every fork result rather than
//! hidden, and forks deliberately expose no block or time controls.

use crate::{
    config::NetworkConfig,
    core::execution_plan::ExecutionPlan,
    rpc::sanitized_rpc_error,
    simulation::{
        ExecutionMode, PlannedCall, delegation_override, effective_gas_limit, planned_call,
        planned_request, simulation_slot,
    },
};
use alloy::{
    consensus::BlockHeader,
    eips::BlockNumberOrTag,
    network::primitives::BlockResponse,
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{
        TransactionRequest,
        simulate::{SimCallResult, SimulatePayload},
    },
    sol,
    sol_types::SolCall,
};
use anyhow::{Context as _, Result, bail, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use schemars::JsonSchema;
use serde::Serialize;
use std::{collections::BTreeMap, time::Duration};
use uuid::Uuid;

/// Plans one fork may hold. Kept to a single digit because replay is
/// quadratic in the calls a session sends.
pub const MAX_PLANS_PER_FORK: usize = 8;
/// Concurrent forks one wallet may hold.
pub const MAX_FORKS_PER_WALLET: usize = 4;
/// Concurrent forks this process may hold across every wallet.
pub const MAX_FORKS: usize = 16;
/// How long a fork stays usable. Short, because the pinned parent block must
/// still be servable by the configured RPC for replay to work at all.
pub const FORK_TTL_SECONDS: i64 = 300;
/// Read calls one fork request may carry. The whole set shares the pinned
/// block's gas limit, so this is deliberately below the non-fork batch cap.
pub const MAX_FORK_READ_CALLS: usize = 64;

const FORK_RPC_TIMEOUT: Duration = Duration::from_mins(1);

/// The sentence every fork-backed result carries, so an agent is never misled
/// about what it is looking at.
pub const FORK_NOTE: &str = "Simulated state only: nothing observed through a fork exists on chain, is signed, is approved, or satisfies any policy rule. eth_simulateV1 advances the block by one per applied plan, so block.number and block.timestamp seen here are ahead of the pinned parent block.";

sol! {
    function getEthBalance(address addr) external view returns (uint256);
}

/// The pinned parent block of a fork, captured once at creation so replay
/// never has to re-read the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkParent {
    pub number: u64,
    pub hash: B256,
    pub gas_limit: u64,
}

/// One live fork session.
#[derive(Clone, Debug, PartialEq)]
pub struct ForkSession {
    pub fork_id: Uuid,
    pub wallet_id: String,
    pub wallet_address: Address,
    pub chain_id: u64,
    pub parent: ForkParent,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Validated plans already applied, in application order.
    pub plans: Vec<ExecutionPlan>,
}

impl ForkSession {
    /// The replayable form of everything already applied to this fork.
    #[must_use]
    pub fn preface(&self) -> ForkPreface {
        ForkPreface {
            fork_id: self.fork_id,
            wallet: self.wallet_address,
            chain_id: self.chain_id,
            parent: self.parent,
            calls: self
                .plans
                .iter()
                .map(|plan| planned_call(plan, self.wallet_address))
                .collect(),
            expires_at: self.expires_at,
        }
    }

    /// Whether another plan may still be applied.
    #[must_use]
    pub fn has_capacity(&self) -> bool {
        self.plans.len() < MAX_PLANS_PER_FORK
    }

    /// The fork as a read layered on top of everything applied so far sees
    /// it: the next simulated block after the last applied plan.
    #[must_use]
    pub fn read_context(&self) -> ForkContext {
        self.context(self.preface().simulated_block())
    }

    /// The fork as the most recently applied plan saw it: the block that
    /// plan executed in.
    #[must_use]
    pub fn applied_context(&self) -> ForkContext {
        self.context(
            self.parent
                .number
                .saturating_add(u64::try_from(self.plans.len()).unwrap_or(u64::MAX)),
        )
    }

    /// The agent-facing description of this fork at `simulated_block`.
    #[must_use]
    pub fn context(&self, simulated_block: u64) -> ForkContext {
        ForkContext {
            fork_id: self.fork_id,
            hypothetical: true,
            chain_id: self.chain_id.to_string(),
            parent_block_number: self.parent.number.to_string(),
            simulated_block_number: simulated_block.to_string(),
            applied_plans: u32::try_from(self.plans.len()).unwrap_or(u32::MAX),
            max_plans: u32::try_from(MAX_PLANS_PER_FORK).unwrap_or(u32::MAX),
            expires_at: self.expires_at,
            note: FORK_NOTE.into(),
        }
    }
}

/// Everything the RPC layer needs to replay a fork: the pinned parent and the
/// exact calls already applied on top of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkPreface {
    pub fork_id: Uuid,
    pub wallet: Address,
    pub chain_id: u64,
    pub parent: ForkParent,
    pub calls: Vec<PlannedCall>,
    pub expires_at: DateTime<Utc>,
}

impl ForkPreface {
    #[must_use]
    pub fn applied_plans(&self) -> usize {
        self.calls.len()
    }

    /// The simulated block a result produced on top of this preface lands in.
    /// Every applied plan consumed one block after the pinned parent.
    #[must_use]
    pub fn simulated_block(&self) -> u64 {
        self.parent
            .number
            .saturating_add(u64::try_from(self.calls.len()).unwrap_or(u64::MAX))
            .saturating_add(1)
    }

    /// True when replaying this fork requires the wallet to carry the
    /// canonical Calibur delegation designator.
    #[must_use]
    pub fn requires_calibur(&self) -> bool {
        self.calls
            .iter()
            .any(|call| call.mode == ExecutionMode::CaliburBatch)
    }
}

/// The fork provenance attached to every fork-backed tool result.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ForkContext {
    pub fork_id: Uuid,
    /// Always true. Present so a consumer cannot mistake fork output for
    /// real chain state by looking at one field.
    pub hypothetical: bool,
    pub chain_id: String,
    /// The real block whose state this fork is pinned to.
    pub parent_block_number: String,
    /// The simulated block this particular result was produced in.
    pub simulated_block_number: String,
    /// Plans applied to the fork when this result was produced.
    pub applied_plans: u32,
    pub max_plans: u32,
    pub expires_at: DateTime<Utc>,
    pub note: String,
}

/// Live forks, held only in this process.
#[derive(Debug, Default)]
pub struct ForkStore {
    sessions: BTreeMap<Uuid, ForkSession>,
}

impl ForkStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a fork pinned to `parent`, subject to the per-wallet and global
    /// caps. Expired forks are swept first so a caller is never blocked by
    /// sessions that no longer exist.
    pub fn create(
        &mut self,
        wallet_id: &str,
        wallet_address: Address,
        chain_id: u64,
        parent: ForkParent,
        now: DateTime<Utc>,
    ) -> Result<ForkSession> {
        self.prune(now);
        let held = self
            .sessions
            .values()
            .filter(|session| session.wallet_id == wallet_id)
            .count();
        ensure!(
            held < MAX_FORKS_PER_WALLET,
            "wallet {wallet_id} already holds {MAX_FORKS_PER_WALLET} simulation forks; discard one with wallet_discard_fork"
        );
        ensure!(
            self.sessions.len() < MAX_FORKS,
            "this wallet server already holds {MAX_FORKS} simulation forks; discard one with wallet_discard_fork"
        );
        let session = ForkSession {
            fork_id: Uuid::new_v4(),
            wallet_id: wallet_id.to_owned(),
            wallet_address,
            chain_id,
            parent,
            created_at: now,
            expires_at: now + TimeDelta::seconds(FORK_TTL_SECONDS),
            plans: Vec::new(),
        };
        self.sessions.insert(session.fork_id, session.clone());
        Ok(session)
    }

    /// Read a live fork. Expiry is enforced here, so an expired fork is
    /// indistinguishable from one that never existed.
    pub fn session(&mut self, fork_id: Uuid, now: DateTime<Utc>) -> Result<ForkSession> {
        self.prune(now);
        self.sessions.get(&fork_id).cloned().with_context(|| {
            format!("unknown or expired fork {fork_id}; open a new one with wallet_create_fork")
        })
    }

    /// Append a plan that has just simulated successfully on top of exactly
    /// `expected_applied` earlier plans. The count is rechecked so two
    /// concurrent simulations cannot interleave into an order neither of them
    /// actually simulated.
    pub fn append(
        &mut self,
        fork_id: Uuid,
        plan: ExecutionPlan,
        expected_applied: usize,
        now: DateTime<Utc>,
    ) -> Result<ForkSession> {
        self.prune(now);
        let session = self.sessions.get_mut(&fork_id).with_context(|| {
            format!("unknown or expired fork {fork_id}; open a new one with wallet_create_fork")
        })?;
        ensure!(
            session.plans.len() == expected_applied,
            "fork {fork_id} changed while this plan was simulating; simulate it again on the current fork"
        );
        ensure!(
            session.plans.len() < MAX_PLANS_PER_FORK,
            "fork {fork_id} already holds the maximum of {MAX_PLANS_PER_FORK} plans; open a new fork"
        );
        session.plans.push(plan);
        Ok(session.clone())
    }

    /// Drop a fork. Returns whether it existed.
    pub fn discard(&mut self, fork_id: Uuid) -> bool {
        self.sessions.remove(&fork_id).is_some()
    }

    /// Remove every expired fork.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.sessions.retain(|_, session| session.expires_at > now);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// The result of running read-only calls on top of a fork.
#[derive(Clone, Debug)]
pub struct ForkReadOutcome {
    pub results: Vec<SimCallResult>,
    /// The simulated block the read calls executed in.
    pub simulated_block: u64,
}

/// Read the pinned parent a new fork should use, verifying the RPC's chain
/// before anything is stored.
pub async fn pin_parent_block(network: &NetworkConfig) -> Result<ForkParent> {
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let (chain_id, block) = tokio::time::timeout(FORK_RPC_TIMEOUT, async {
        tokio::try_join!(
            provider.get_chain_id(),
            provider.get_block_by_number(BlockNumberOrTag::Latest),
        )
    })
    .await
    .context("fork parent-block RPC timed out")?
    .map_err(|error| sanitized_rpc_error(network, &error))?;
    ensure!(
        chain_id == network.chain_id,
        "RPC reports chain {chain_id}, not {}",
        network.chain_id
    );
    let block = block.context("RPC returned no latest block")?;
    let header = block.header();
    Ok(ForkParent {
        number: header.number(),
        hash: header.hash,
        gas_limit: header.gas_limit(),
    })
}

/// Execute read-only calls in one `SimBlock` layered on top of every plan the
/// fork has already applied.
///
/// The read block is discarded: nothing these calls do is ever appended to
/// the fork. Calls inside one block still observe each other, exactly as
/// transactions in a real block would.
pub async fn execute_reads(
    network: &NetworkConfig,
    preface: &ForkPreface,
    calls: Vec<TransactionRequest>,
) -> Result<ForkReadOutcome> {
    ensure!(!calls.is_empty(), "a fork read needs at least one call");
    ensure!(
        calls.len() <= MAX_FORK_READ_CALLS,
        "a fork read accepts at most {MAX_FORK_READ_CALLS} calls; the whole set shares the pinned block's gas limit"
    );
    ensure!(
        preface.chain_id == network.chain_id,
        "fork chain {} does not match the selected network {}",
        preface.chain_id,
        network.chain_id
    );
    let _permit = simulation_slot().await?;
    let gas_limit = effective_gas_limit(network, preface.parent.gas_limit)?;
    let per_call = gas_limit / u64::try_from(calls.len()).unwrap_or(1).max(1);
    ensure!(
        per_call >= 21_000,
        "the pinned block's gas limit cannot cover {} fork read calls",
        calls.len()
    );
    let calls = calls
        .into_iter()
        .map(|call| call.gas_limit(per_call))
        .collect::<Vec<_>>();

    let read_calls = calls.len();
    let mut blocks = replay_blocks(preface, gas_limit);
    blocks.push(alloy::rpc::types::simulate::SimBlock::default().extend_calls(calls));
    if preface.requires_calibur() {
        let first = std::mem::take(&mut blocks[0]);
        blocks[0] = delegation_override(first, preface.wallet);
    }
    let payload = SimulatePayload {
        block_state_calls: blocks,
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let simulated = tokio::time::timeout(
        FORK_RPC_TIMEOUT,
        provider.simulate(&payload).number(preface.parent.number),
    )
    .await
    .context("fork eth_simulateV1 request timed out")?
    .map_err(|error| sanitized_rpc_error(network, &error))?;

    let mut simulated = validate_replay(
        preface.parent,
        preface.calls.len(),
        Some(preface.fork_id),
        simulated,
    )?;
    let read_block = simulated.pop().expect("validated read block");
    ensure!(
        read_block.calls.len() == read_calls,
        "fork eth_simulateV1 returned {} call results for {read_calls} calls",
        read_block.calls.len(),
    );
    Ok(ForkReadOutcome {
        results: read_block.calls,
        simulated_block: preface.simulated_block(),
    })
}

/// The wallet's native balance as the fork sees it, read through the
/// canonical Multicall3 `getEthBalance` helper inside the fork.
pub async fn native_balance(
    network: &NetworkConfig,
    preface: &ForkPreface,
    address: Address,
) -> Result<(U256, u64)> {
    let request = TransactionRequest::default()
        .to(crate::rpc::MULTICALL3_ADDRESS)
        .input(alloy::rpc::types::TransactionInput::new(
            getEthBalanceCall { addr: address }.abi_encode().into(),
        ));
    let outcome = execute_reads(network, preface, vec![request]).await?;
    let result = outcome
        .results
        .first()
        .context("fork native-balance read returned no result")?;
    ensure!(
        result.status,
        "Multicall3 getEthBalance failed on this fork; the canonical Multicall3 may not be deployed on chain {}",
        network.chain_id
    );
    let balance = getEthBalanceCall::abi_decode_returns(&result.return_data)
        .context("Multicall3 getEthBalance returned undecodable data")?;
    Ok((balance, outcome.simulated_block))
}

/// One `SimBlock` per already-applied plan, each carrying that plan's exact
/// direct call or Calibur batch.
pub(crate) fn replay_blocks(
    preface: &ForkPreface,
    gas_limit: u64,
) -> Vec<alloy::rpc::types::simulate::SimBlock> {
    preface
        .calls
        .iter()
        .map(|call| {
            alloy::rpc::types::simulate::SimBlock::default().extend_calls([planned_request(
                call,
                preface.wallet,
                gas_limit,
                preface.chain_id,
            )])
        })
        .collect()
}

/// Check that the RPC replayed exactly the fork this process asked for: the
/// right number of blocks, linked to the pinned parent, numbered
/// consecutively, and with every already-applied plan still succeeding.
///
/// Replay is deterministic — the same pinned parent and the same calls — so a
/// divergence here means the RPC changed under the fork rather than that the
/// plans stopped working, and the fork must not be trusted further.
pub(crate) fn validate_replay<B>(
    parent: ForkParent,
    replayed: usize,
    fork_id: Option<Uuid>,
    blocks: Vec<alloy::rpc::types::simulate::SimulatedBlock<B>>,
) -> Result<Vec<alloy::rpc::types::simulate::SimulatedBlock<B>>>
where
    B: BlockResponse,
    B::Header: BlockHeader,
{
    let expected = replayed + 1;
    ensure!(
        blocks.len() == expected,
        "eth_simulateV1 returned {} blocks for {expected} requested blocks",
        blocks.len()
    );
    for (index, block) in blocks.iter().enumerate() {
        let header = block.inner.header();
        let expected_number = parent
            .number
            .saturating_add(u64::try_from(index).unwrap_or(u64::MAX))
            .saturating_add(1);
        ensure!(
            header.number() == expected_number,
            "eth_simulateV1 returned an unexpected simulated block number"
        );
        if index == 0 {
            ensure!(
                header.parent_hash() == parent.hash,
                "eth_simulateV1 response is not linked to the pinned parent block"
            );
        }
        if index < replayed {
            ensure!(
                block.calls.len() == 1,
                "fork replay block {index} returned {} call results for one call",
                block.calls.len()
            );
            if !block.calls[0].status {
                bail!(
                    "fork {} no longer replays: applied plan {} now fails against the pinned parent block. Discard it with wallet_discard_fork and open a new one.",
                    fork_id.unwrap_or_default(),
                    index + 1
                );
            }
        }
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::execution_plan::{
        DecimalU256, ExecutionStep, ExecutionStepKind, PlannedTransaction, SubmitCondition,
    };
    use alloy::primitives::Bytes;

    fn parent() -> ForkParent {
        ForkParent {
            number: 100,
            hash: B256::repeat_byte(0xab),
            gas_limit: 30_000_000,
        }
    }

    fn plan(calls: usize) -> ExecutionPlan {
        let sender = Address::repeat_byte(0x11);
        ExecutionPlan {
            schema_version: "1".into(),
            chain_id: DecimalU256::new("1").unwrap(),
            caip2_chain_id: "eip155:1".into(),
            sender,
            ordered_steps: (0..calls)
                .map(|index| ExecutionStep {
                    step: u32::try_from(index + 1).unwrap(),
                    kind: ExecutionStepKind::Execution,
                    submit_condition: SubmitCondition::Always,
                    transaction: PlannedTransaction {
                        chain_id: DecimalU256::new("1").unwrap(),
                        from: sender,
                        to: Address::repeat_byte(u8::try_from(index + 2).unwrap()),
                        data: Bytes::new(),
                        value: DecimalU256::new("0").unwrap(),
                        gas: None,
                    },
                    eip1193: None,
                    revert_decode: None,
                })
                .collect(),
            execution_policy: None,
            adapters: None,
            simulation_failure_policy: None,
        }
    }

    fn store_with_fork() -> (ForkStore, ForkSession, DateTime<Utc>) {
        let now = Utc::now();
        let mut store = ForkStore::new();
        let session = store
            .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
            .unwrap();
        (store, session, now)
    }

    #[test]
    fn a_new_fork_is_empty_and_pinned() {
        let (_, session, now) = store_with_fork();
        assert!(session.plans.is_empty());
        assert_eq!(session.parent.number, 100);
        assert_eq!(
            session.expires_at,
            now + TimeDelta::seconds(FORK_TTL_SECONDS)
        );
        let preface = session.preface();
        assert_eq!(preface.applied_plans(), 0);
        // With nothing applied, the first simulated block is the one that
        // directly follows the pinned parent, exactly like a one-shot
        // simulation.
        assert_eq!(preface.simulated_block(), 101);
        assert!(!preface.requires_calibur());
    }

    #[test]
    fn each_applied_plan_advances_the_simulated_block_by_one() {
        let (mut store, session, now) = store_with_fork();
        let session = store.append(session.fork_id, plan(1), 0, now).unwrap();
        assert_eq!(session.preface().simulated_block(), 102);
        let session = store.append(session.fork_id, plan(2), 1, now).unwrap();
        assert_eq!(session.preface().simulated_block(), 103);
        assert_eq!(session.context(103).applied_plans, 2);
        // A multi-call plan replays through Calibur, so replay needs the
        // delegation designator override.
        assert!(session.preface().requires_calibur());
    }

    #[test]
    fn appending_rejects_a_concurrently_changed_fork() {
        let (mut store, session, now) = store_with_fork();
        store.append(session.fork_id, plan(1), 0, now).unwrap();
        let error = store
            .append(session.fork_id, plan(1), 0, now)
            .expect_err("a stale applied count must not append");
        assert!(error.to_string().contains("changed while this plan"));
    }

    #[test]
    fn a_fork_stops_accepting_plans_at_its_cap() {
        let (mut store, session, now) = store_with_fork();
        for index in 0..MAX_PLANS_PER_FORK {
            let current = store.append(session.fork_id, plan(1), index, now).unwrap();
            assert_eq!(current.has_capacity(), index + 1 < MAX_PLANS_PER_FORK);
        }
        let error = store
            .append(session.fork_id, plan(1), MAX_PLANS_PER_FORK, now)
            .expect_err("the plan cap must hold");
        assert!(error.to_string().contains("maximum"));
    }

    #[test]
    fn forks_are_capped_per_wallet_and_globally() {
        let now = Utc::now();
        let mut store = ForkStore::new();
        for _ in 0..MAX_FORKS_PER_WALLET {
            store
                .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
                .unwrap();
        }
        let error = store
            .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
            .expect_err("the per-wallet cap must hold");
        assert!(error.to_string().contains("already holds"));
        // A different wallet is unaffected until the global cap.
        store
            .create("wallet-b", Address::repeat_byte(0x22), 1, parent(), now)
            .unwrap();
        assert_eq!(store.len(), MAX_FORKS_PER_WALLET + 1);
    }

    #[test]
    fn an_expired_fork_is_indistinguishable_from_one_that_never_existed() {
        let (mut store, session, now) = store_with_fork();
        let later = now + TimeDelta::seconds(FORK_TTL_SECONDS + 1);
        let error = store
            .session(session.fork_id, later)
            .expect_err("an expired fork must not resolve");
        assert!(error.to_string().contains("unknown or expired"));
        assert!(store.is_empty());
        let unknown = store
            .session(Uuid::new_v4(), now)
            .expect_err("an unknown fork must not resolve");
        assert!(unknown.to_string().contains("unknown or expired"));
    }

    #[test]
    fn expiry_frees_capacity_for_the_same_wallet() {
        let now = Utc::now();
        let mut store = ForkStore::new();
        for _ in 0..MAX_FORKS_PER_WALLET {
            store
                .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), now)
                .unwrap();
        }
        let later = now + TimeDelta::seconds(FORK_TTL_SECONDS + 1);
        store
            .create("wallet-a", Address::repeat_byte(0x11), 1, parent(), later)
            .expect("expired forks are swept before the cap is applied");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn discarding_is_idempotent() {
        let (mut store, session, _) = store_with_fork();
        assert!(store.discard(session.fork_id));
        assert!(!store.discard(session.fork_id));
    }

    #[test]
    fn replay_blocks_carry_one_exact_call_each() {
        let (mut store, session, now) = store_with_fork();
        store.append(session.fork_id, plan(1), 0, now).unwrap();
        let session = store.append(session.fork_id, plan(2), 1, now).unwrap();
        let preface = session.preface();
        let blocks = replay_blocks(&preface, 1_000_000);
        assert_eq!(blocks.len(), 2);
        for block in &blocks {
            assert_eq!(block.calls.len(), 1);
        }
        // The single-call plan runs directly at its own target; the two-call
        // plan runs through the wallet itself as a Calibur batch.
        assert_eq!(blocks[0].calls[0].to, Some(Address::repeat_byte(2).into()));
        assert_eq!(
            blocks[1].calls[0].to,
            Some(Address::repeat_byte(0x11).into())
        );
    }

    #[test]
    fn fork_context_always_marks_output_hypothetical() {
        let (_, session, _) = store_with_fork();
        let context = session.context(101);
        assert!(context.hypothetical);
        assert_eq!(context.parent_block_number, "100");
        assert_eq!(context.simulated_block_number, "101");
        assert_eq!(
            context.max_plans,
            u32::try_from(MAX_PLANS_PER_FORK).unwrap()
        );
        assert!(context.note.contains("nothing observed through a fork"));
    }
}
