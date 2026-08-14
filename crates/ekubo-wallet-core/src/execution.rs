use crate::{
    chain_client::ChainClient,
    config::{NetworkConfig, WalletMetadata},
    core::{
        execution_plan::ExecutionPlan,
        policy::{PolicyOutcome, denial_reasons, policy_outcome},
    },
    custody::{KeyStore, load_matching_signer},
    rpc::transaction_receipt_through,
    simulation::{CANONICAL_CALIBUR, ExecutionMode, PlannedCall, SimulationResult, planned_call},
};
use alloy::{
    consensus::{
        SignableTransaction, Transaction, TxEip1559, TxEip7702, TxEnvelope,
        transaction::SignerRecoverable,
    },
    eips::{eip2718::Decodable2718, eip2930::AccessList, eip7702::Authorization},
    network::TxSignerSync,
    primitives::{B256, TxKind, U256, keccak256},
    signers::{SignerSync, local::PrivateKeySigner},
};
use anyhow::{Context, Result, bail, ensure};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::json;
use std::{str::FromStr, time::Duration};

const RPC_TIMEOUT: Duration = Duration::from_secs(15);
const EIP7702_AUTHORIZATION_INTRINSIC_COST: u64 = 25_000;
/// What every transaction is charged before it does anything at all. A gas
/// ceiling under this cannot admit even a bare value transfer, which is what a
/// cancellation is.
const INTRINSIC_TRANSACTION_GAS: u64 = 21_000;
const SIMULATION_GAS_MULTIPLIER: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedExecution {
    pub digest: String,
    pub serialized_transaction: String,
    pub transaction_hash: String,
}

/// Exact transaction fields prepared without loading the signing key. An
/// exceptional approval reviews this object, and signing consumes it without
/// another fee or nonce lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedExecution {
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    planned: crate::simulation::PlannedCall,
    authorize_delegation: bool,
    plan_digest: String,
}

impl PreparedExecution {
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    #[must_use]
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    #[must_use]
    pub const fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    #[must_use]
    pub const fn max_priority_fee_per_gas(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    #[must_use]
    pub fn maximum_fee_wei(&self) -> String {
        (U256::from(self.gas_limit) * U256::from(self.max_fee_per_gas)).to_string()
    }

    #[must_use]
    pub const fn transaction_type(&self) -> &'static str {
        if self.authorize_delegation {
            "eip_7702"
        } else {
            "eip_1559"
        }
    }

    #[must_use]
    pub fn authorization_nonce(&self) -> Option<u64> {
        self.authorize_delegation.then(|| {
            self.nonce
                .checked_add(1)
                .expect("delegation nonce validated during preparation")
        })
    }

    /// Digest of every transaction field presented during exceptional review.
    /// This is separate from the portable execution-plan digest because nonce
    /// and fees are wallet-local preparation fields.
    #[must_use]
    pub fn review_digest(&self) -> String {
        let authorization = self.authorize_delegation.then(|| {
            json!({
                "chain_id": self.chain_id.to_string(),
                "implementation": format!("{CANONICAL_CALIBUR:#x}"),
                "nonce": self
                    .authorization_nonce()
                    .expect("authorization is present")
                    .to_string(),
            })
        });
        let canonical = json!({
            "version": 1,
            "plan_digest": self.plan_digest,
            "transaction_type": self.transaction_type(),
            "chain_id": self.chain_id.to_string(),
            "nonce": self.nonce.to_string(),
            "gas_limit": self.gas_limit.to_string(),
            "max_fee_per_gas": self.max_fee_per_gas.to_string(),
            "max_priority_fee_per_gas": self.max_priority_fee_per_gas.to_string(),
            "to": format!("{:#x}", self.planned.to),
            "value": self.planned.value.to_string(),
            "data": format!("0x{}", hex::encode(&self.planned.data)),
            "authorization": authorization,
        });
        format!(
            "{:#x}",
            keccak256(serde_json::to_vec(&canonical).expect("review fields serialize"))
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Success,
    Reverted,
    Pending,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct BroadcastResult {
    pub transaction_hash: String,
    pub receipt_status: ReceiptStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<String>,
    /// What the mined transaction cost. Present exactly when a receipt was
    /// read, which is also when `receipt_status` is not `Pending`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mined_fee: Option<crate::rpc::MinedFee>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast_error: Option<String>,
    /// Whether the absence a `broadcast_error` asserts was actually observed.
    ///
    /// Not serialized: this says something about how the wallet came to its
    /// conclusion rather than about the transaction, and only
    /// `reconcile::submit_claimed` needs it. `true` for every result that
    /// carries no `broadcast_error`, so the field is only ever read alongside
    /// one.
    #[serde(skip)]
    #[schemars(skip)]
    pub absence_established: bool,
}

/// What the chain said about an exact hash after a send failed.
///
/// Three answers, not two. Collapsing the third into `Absent` is finding
/// 202009: a raw-send timeout can happen *after* the node accepted the
/// transaction, and an observation that timed out or errored establishes
/// nothing either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Presence {
    /// The node holds this exact transaction.
    Held,
    /// The node was asked and does not have it.
    Absent,
    /// The node could not be asked, or did not answer.
    Unobserved,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SigningOverrides {
    allow_policy_override: bool,
    allow_simulation_failure: bool,
}

impl SigningOverrides {
    /// The automatic path: no override exists. Identical to `default()`,
    /// named so call sites read as the decision they are.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            allow_policy_override: false,
            allow_simulation_failure: false,
        }
    }

    /// Both human overrides — signing a plan no policy rule covers, and one
    /// whose simulation failed. Neither reaches a `deny` rule, which is
    /// refused below whatever these say.
    ///
    /// Crate-private because only the owner-review orchestrator may construct
    /// an exception; MCP presentation code cannot mint it.
    #[must_use]
    pub(crate) const fn reviewed() -> Self {
        Self {
            allow_policy_override: true,
            allow_simulation_failure: true,
        }
    }
}

/// Prepare fee and nonce fields through the configured RPC, then load the key
/// only after every upstream request has completed and sign locally.
pub(crate) async fn sign_execution<K: KeyStore + ?Sized>(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
    simulation: &SimulationResult,
    keys: &K,
    overrides: SigningOverrides,
) -> Result<SignedExecution> {
    let prepared = prepare_execution(wallet, network, plan, simulation, overrides).await?;
    sign_prepared_execution(
        wallet, network, plan, simulation, &prepared, keys, overrides,
    )
}

/// Resolve the exact nonce, gas limit, and EIP-1559 fee fields without loading
/// private key material.
pub async fn prepare_execution(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
    simulation: &SimulationResult,
    overrides: SigningOverrides,
) -> Result<PreparedExecution> {
    validate_preflight(wallet, network, plan, simulation, overrides)?;
    let planned = planned_call(plan, wallet.address);
    let gas_limit = signing_gas_limit(network, simulation)?;
    let prepared = crate::rpc::try_clients(network, |client| async move {
        let prepared = tokio::time::timeout(RPC_TIMEOUT, async {
            tokio::try_join!(
                client.chain_id(),
                client.transaction_count(wallet.address, alloy::eips::BlockId::pending()),
                client.estimate_eip1559_fees(),
            )
        })
        .await
        .context("transaction preparation RPC timed out")??;
        ensure!(
            prepared.0 == network.chain_id,
            "RPC reports chain {}, not {}",
            prepared.0,
            network.chain_id
        );
        Ok(prepared)
    })
    .await?;
    ensure!(
        prepared.2.max_fee_per_gas >= prepared.2.max_priority_fee_per_gas,
        "RPC returned invalid EIP-1559 fee fields"
    );
    // And the ceiling the owner set, if they set one. Nothing else bounds this
    // on the automatic path: no policy rule speaks about fees and no reviewer
    // sees them, so `gas_limit × max_fee_per_gas` was whatever an endpoint
    // cared to name.
    let max_fee_per_gas = capped_fee(network, prepared.2.max_fee_per_gas)?;
    let max_priority_fee_per_gas = prepared.2.max_priority_fee_per_gas.min(max_fee_per_gas);
    // The delegation the authorization is decided against is read here, not
    // taken from the simulation.
    //
    // A recorded simulation can be sent minutes after it was produced, and
    // nothing between the two rereads the account's code: `validate_send`
    // checks the wallet, the chain, the policy revision, the plan digest, and
    // the fork flag, and none of those move when a delegation does. So the
    // batch could be signed against an implementation that was never simulated
    // and never reviewed — or, if the delegation had been removed, spend a
    // nonce on a batch that cannot execute.
    //
    // A failed simulation is worse still: `base_failure_result` asserts
    // `will_authorize_delegation` from the execution mode alone, having
    // observed nothing at all, and that result is exactly the one a human is
    // asked to override.
    let authorize_delegation = delegation_at_send(wallet, network, &planned, simulation).await?;
    if authorize_delegation {
        prepared
            .1
            .checked_add(1)
            .context("authorization nonce overflow")?;
    }

    Ok(PreparedExecution {
        chain_id: network.chain_id,
        nonce: prepared.1,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        planned,
        authorize_delegation,
        plan_digest: simulation.digest.clone(),
    })
}

/// Whether this send should carry an EIP-7702 authorization, decided against
/// the account's delegation as it is now rather than as it was simulated.
///
/// Returns the authorization decision, and refuses outright when the *reviewed*
/// delegation context has changed: a plan simulated against no delegation, or
/// against one particular implementation, was reviewed on that basis, and a
/// different one at send time is a different transaction than the one anybody
/// agreed to. Recomputing the flag silently would sign it anyway.
async fn delegation_at_send(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    planned: &PlannedCall,
    simulation: &SimulationResult,
) -> Result<bool> {
    if planned.mode != ExecutionMode::CaliburBatch {
        // A direct call never authorizes anything, and `sign_prepared` refuses
        // the combination outright.
        return Ok(false);
    }
    let code = crate::rpc::try_clients(network, |client| async move {
        tokio::time::timeout(
            RPC_TIMEOUT,
            client.code(wallet.address, alloy::eips::BlockId::latest()),
        )
        .await
        .context("delegation recheck RPC timed out")?
    })
    .await?;
    authorization_for_send(
        &code,
        wallet.address,
        simulation.replaces_delegated_implementation.as_deref(),
    )
}

/// The decision [`delegation_at_send`] makes, without the request that feeds
/// it: given the account's code as it is now and the delegation the simulation
/// was evaluated against, whether to authorize — or whether the context moved
/// far enough that nothing should be signed.
///
/// Separate so every branch is testable without a stub endpoint. The branch
/// that mattered had no test at all, because it only exists between a
/// simulation and a send that happen at different times.
pub(crate) fn authorization_for_send(
    code: &alloy::primitives::Bytes,
    wallet: alloy::primitives::Address,
    recorded_replaces: Option<&str>,
) -> Result<bool> {
    let (authorize, replaces) = match crate::rpc::delegated_implementation(code) {
        // Already delegated to the implementation this batch targets, so the
        // authorization would be a no-op that still consumes a nonce.
        Some(address) if address == CANONICAL_CALIBUR => (false, None),
        Some(address) => (true, Some(format!("{address:#x}"))),
        None if code.is_empty() => (true, None),
        None => bail!(
            "wallet {wallet} has code that is not an EIP-7702 delegation designator, so this \
             batch cannot be sent"
        ),
    };
    ensure!(
        replaces.as_deref() == recorded_replaces,
        "the account's EIP-7702 delegation changed after this plan was simulated: the simulation \
         was evaluated against {}, and the account now has {}. Simulate the plan again and send \
         the new simulation.",
        recorded_replaces.unwrap_or("no delegation to replace"),
        replaces.as_deref().unwrap_or("no delegation to replace")
    );
    Ok(authorize)
}

/// Load the key and sign exactly the already-reviewed preparation fields.
pub(crate) fn sign_prepared_execution<K: KeyStore + ?Sized>(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
    simulation: &SimulationResult,
    prepared: &PreparedExecution,
    keys: &K,
    overrides: SigningOverrides,
) -> Result<SignedExecution> {
    validate_preflight(wallet, network, plan, simulation, overrides)?;
    ensure!(
        prepared.chain_id == network.chain_id,
        "prepared transaction chain mismatch"
    );
    ensure!(
        prepared.plan_digest == simulation.digest,
        "prepared transaction plan digest mismatch"
    );
    ensure!(
        prepared.planned == planned_call(plan, wallet.address),
        "prepared transaction call mismatch"
    );
    ensure!(
        prepared.authorize_delegation == simulation.will_authorize_delegation,
        "prepared delegation choice mismatch"
    );
    ensure!(
        prepared.gas_limit == signing_gas_limit(network, simulation)?,
        "prepared gas limit mismatch"
    );
    ensure!(
        prepared.max_fee_per_gas >= prepared.max_priority_fee_per_gas,
        "prepared EIP-1559 fee fields are invalid"
    );
    // Preparation may outlive a security-sensitive network update. Reapply
    // the current ceiling immediately before key use instead of trusting the
    // configuration that happened to be active when fees were fetched.
    capped_fee(network, prepared.max_fee_per_gas)?;

    // All RPC preparation completed before this function loads key material.
    let local_signer = load_matching_signer(keys, wallet)?;
    let mut signed_execution = sign_prepared(
        &local_signer,
        prepared.chain_id,
        prepared.nonce,
        prepared.gas_limit,
        prepared.max_fee_per_gas,
        prepared.max_priority_fee_per_gas,
        &prepared.planned,
        prepared.authorize_delegation,
    )?;
    signed_execution.digest.clone_from(&simulation.digest);
    validate_signed_execution(&signed_execution, wallet, network, plan)?;
    validate_signed_preparation(&signed_execution, prepared)?;
    Ok(signed_execution)
}

fn validate_preflight(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
    simulation: &SimulationResult,
    overrides: SigningOverrides,
) -> Result<()> {
    plan.validate()?;
    ensure!(
        plan.sender == wallet.address,
        "execution plan sender mismatch"
    );
    ensure!(
        plan.chain_id.as_str() == network.chain_id.to_string(),
        "execution plan chain mismatch"
    );
    ensure!(
        simulation.digest == format!("{:#x}", plan.digest()),
        "simulation digest does not match execution plan"
    );
    // A `deny` rule is not overridable. The owner already answered this
    // question when they wrote the rule, and an approval prompt that can talk
    // them out of it makes the rule decoration. Matching no rule is a
    // different thing — a question nobody has answered — and that is the one
    // an interactive human may still answer.
    match policy_outcome(&simulation.policy_findings) {
        PolicyOutcome::Rejected => {
            let reasons = denial_reasons(&simulation.policy_findings).join("; ");
            bail!(
                "the active wallet policy rejects this transaction outright, so it cannot be \
                 signed or approved: {reasons}. Change the policy if this should be permitted."
            );
        }
        PolicyOutcome::RequiresApproval => ensure!(
            overrides.allow_policy_override,
            "no policy rule covers this transaction, so it needs explicit human approval"
        ),
        PolicyOutcome::Allowed => {}
    }
    ensure!(
        simulation.simulation.success || overrides.allow_simulation_failure,
        "transaction simulation did not succeed"
    );
    ensure!(
        simulation.policy_revision > 0,
        "simulation has no active policy revision"
    );
    Ok(())
}

/// The highest gas limit this network will let a transaction carry.
///
/// The configured maximum when the owner set one, the block's own limit
/// otherwise, and never more than the block's limit either way — an envelope
/// above that is one no honest peer will accept.
///
/// Shared by the two paths that sign, because they had drifted: signing after
/// a simulation always fell back to the block limit, while cancellation
/// bounded nothing at all unless the network carried a configured maximum,
/// which most shipped profiles do not. On an ordinary network that left one
/// endpoint's `estimate_gas` deciding the signed gas limit by itself.
/// The gas limit a cancellation is signed with, from an endpoint's estimate.
///
/// Bounded above by the usable ceiling, as before, and now bounded below by
/// what the transaction actually costs. A cancellation is a zero-value
/// self-send: its intrinsic cost is exactly `INTRINSIC_TRANSACTION_GAS` and
/// nothing it does can be cheaper. An endpoint answering `0` -- or anything
/// under half that, since the multiplier is 2 -- produced an envelope below
/// the floor, which every honest peer rejects.
///
/// The rejection is not the damage. The envelope is persisted before it is
/// broadcast, so each one spends a slot in a history capped at
/// `MAX_CANCELLATION_ATTEMPTS`, and at the cap `reconcile` stops repricing and
/// rebroadcasts the newest stored envelope instead. Eight bad estimates leave
/// the owner permanently unable to cancel, resending an invalid envelope
/// forever while the transaction they were trying to stop mines.
///
/// Raised rather than refused, which is the opposite of `capped_fee` and for
/// the reason that function's comment gives: there, not signing is the safe
/// answer; here, not producing an envelope is the failure. Raising is exact
/// rather than a guess -- the floor is what the chain charges, not a number
/// chosen here -- and `usable_gas_ceiling` has already established the ceiling
/// is at least the intrinsic cost, so this can never exceed it.
fn cancellation_gas_limit(estimated_gas: u64, maximum: u64) -> u64 {
    estimated_gas
        .saturating_mul(CANCELLATION_GAS_MULTIPLIER)
        .min(maximum)
        .max(INTRINSIC_TRANSACTION_GAS)
}

fn usable_gas_ceiling(network: &NetworkConfig, block_maximum: u64) -> Result<u64> {
    let configured = network
        .max_gas_limit
        .as_deref()
        .map(str::parse::<u64>)
        .transpose()
        .context("configured maximum gas limit does not fit uint64")?
        .unwrap_or(block_maximum);
    let ceiling = configured.min(block_maximum);
    // A ceiling below the intrinsic cost of the simplest possible transaction
    // is not a ceiling, it is a refusal to sign anything. `block_maximum`
    // comes from whichever endpoint answered, and a small enough answer would
    // otherwise disqualify a plain value transfer — including the self-send a
    // cancellation is — while looking like an ordinary bound.
    ensure!(
        ceiling >= INTRINSIC_TRANSACTION_GAS,
        "the usable gas ceiling {ceiling} is below the {INTRINSIC_TRANSACTION_GAS} gas every \
         transaction costs before it does anything"
    );
    Ok(ceiling)
}

/// The owner's absolute ceiling on `maxFeePerGas`, applied to an
/// endpoint-supplied estimate.
///
/// Refusing rather than clamping. A clamped fee is an envelope that may never
/// mine, signed anyway and occupying the wallet's one in-flight slot for that
/// chain; the honest answer to "the market is above what you said you would
/// pay" is to say so and let the owner raise the ceiling or wait. That is the
/// opposite of the cancellation path's choice, and for the opposite reason:
/// there, not producing an envelope is the failure.
fn capped_fee(network: &NetworkConfig, max_fee_per_gas: u128) -> Result<u128> {
    let Some(ceiling) = network.max_fee_per_gas.as_deref() else {
        return Ok(max_fee_per_gas);
    };
    let ceiling: u128 = ceiling
        .parse()
        .context("configured maximum fee per gas does not fit uint128")?;
    ensure!(
        max_fee_per_gas <= ceiling,
        "the RPC's maximum fee of {max_fee_per_gas} wei per gas is above the {ceiling} wei \
         ceiling configured for {}; raise max_fee_per_gas for this network, or wait for the \
         market to come down",
        network.name
    );
    Ok(max_fee_per_gas)
}

fn signing_gas_limit(network: &NetworkConfig, simulation: &SimulationResult) -> Result<u64> {
    let used = simulation
        .simulation
        .gas_used
        .as_deref()
        .context("simulation did not provide gas usage")?
        .parse::<u64>()
        .context("simulated gas usage does not fit uint64")?;
    let block_maximum = simulation
        .simulation
        .block_gas_limit
        .as_deref()
        .context("simulation did not provide a block gas limit")?
        .parse::<u64>()
        .context("simulated block gas limit does not fit uint64")?;
    let maximum = usable_gas_ceiling(network, block_maximum)?;
    let authorization_cost = if simulation.will_authorize_delegation {
        EIP7702_AUTHORIZATION_INTRINSIC_COST
    } else {
        0
    };
    let baseline = used
        .checked_add(authorization_cost)
        .context("simulated gas limit overflow")?;
    ensure!(
        baseline <= maximum,
        "simulated gas {baseline} exceeds the network maximum gas limit {maximum}"
    );
    // The same floor `cancellation_gas_limit` applies, on the path that has
    // even less standing between it and the chain. `gas_used` is whatever the
    // endpoint reported: `execution_output` copies `max_used_gas` or
    // `gas_used` through untouched, and a successful simulation claiming `0`
    // multiplied to `0` and was signed. An envelope under the intrinsic cost
    // is rejected by every node before it executes, and the automatic path
    // records it -- taking the wallet's one in-flight slot for the chain until
    // something reconciles or cancels it, with no human anywhere in the
    // sequence to notice.
    //
    // A delegation pays its authorization on top of the intrinsic cost, so the
    // floor moves with it rather than being a constant.
    let floor = INTRINSIC_TRANSACTION_GAS
        .checked_add(authorization_cost)
        .context("intrinsic gas floor overflow")?;
    ensure!(
        floor <= maximum,
        "the {maximum} gas ceiling is below the {floor} gas this transaction costs before it \
         does anything"
    );
    Ok(baseline
        .saturating_mul(SIMULATION_GAS_MULTIPLIER)
        .min(maximum)
        .max(floor))
}

#[allow(clippy::too_many_arguments)]
fn sign_prepared(
    signer: &PrivateKeySigner,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    planned: &crate::simulation::PlannedCall,
    authorize_delegation: bool,
) -> Result<SignedExecution> {
    let (bytes, hash) = if authorize_delegation {
        ensure!(
            planned.mode == ExecutionMode::CaliburBatch,
            "direct transactions cannot authorize delegation"
        );
        let authorization = Authorization {
            chain_id: U256::from(chain_id),
            address: CANONICAL_CALIBUR,
            nonce: nonce
                .checked_add(1)
                .context("authorization nonce overflow")?,
        };
        let authorization_signature = signer
            .sign_hash_sync(&authorization.signature_hash())
            .context("failed to sign EIP-7702 authorization")?;
        let mut transaction = TxEip7702 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to: planned.to,
            value: planned.value,
            access_list: AccessList::default(),
            authorization_list: vec![authorization.into_signed(authorization_signature)],
            input: planned.data.clone(),
        };
        let signature = signer
            .sign_transaction_sync(&mut transaction)
            .context("failed to sign EIP-7702 transaction")?;
        let envelope = transaction.into_signed(signature);
        let hash = *envelope.hash();
        let mut bytes = Vec::with_capacity(envelope.eip2718_encoded_length());
        envelope.eip2718_encode(&mut bytes);
        (bytes, hash)
    } else {
        let mut transaction = TxEip1559 {
            chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to: TxKind::Call(planned.to),
            value: planned.value,
            access_list: AccessList::default(),
            input: planned.data.clone(),
        };
        let signature = signer
            .sign_transaction_sync(&mut transaction)
            .context("failed to sign EIP-1559 transaction")?;
        let envelope = transaction.into_signed(signature);
        let hash = *envelope.hash();
        let mut bytes = Vec::with_capacity(envelope.eip2718_encoded_length());
        envelope.eip2718_encode(&mut bytes);
        (bytes, hash)
    };
    ensure!(
        keccak256(&bytes) == hash,
        "signed transaction hash mismatch"
    );
    Ok(SignedExecution {
        digest: String::new(),
        serialized_transaction: format!("0x{}", hex::encode(bytes)),
        transaction_hash: format!("{hash:#x}"),
    })
}

pub fn validate_signed_execution(
    signed: &SignedExecution,
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
) -> Result<()> {
    ensure!(
        signed.digest == format!("{:#x}", plan.digest()),
        "signed execution digest does not match the pending plan"
    );
    let expected_hash =
        B256::from_str(&signed.transaction_hash).context("signed transaction hash is invalid")?;
    let bytes = decode_serialized(&signed.serialized_transaction)?;
    ensure!(
        keccak256(&bytes) == expected_hash,
        "signed transaction hash mismatch"
    );
    let envelope = decode_envelope(&bytes)?;
    ensure!(
        envelope
            .recover_signer()
            .context("failed to recover signed transaction sender")?
            == wallet.address,
        "signed transaction sender does not match wallet"
    );
    ensure!(
        envelope.chain_id() == Some(network.chain_id),
        "signed transaction chain does not match configured network"
    );
    let planned = planned_call(plan, wallet.address);
    ensure!(
        envelope.kind() == TxKind::Call(planned.to),
        "signed transaction target does not match pending plan"
    );
    ensure!(
        envelope.value() == planned.value,
        "signed transaction has an unexpected native value"
    );
    ensure!(
        envelope.input() == &planned.data,
        "signed transaction calldata does not match pending plan"
    );
    if let Some(maximum) = network.max_gas_limit.as_deref() {
        ensure!(
            envelope.gas_limit() <= maximum.parse::<u64>()?,
            "signed transaction exceeds configured maximum gas limit"
        );
    }
    if let Some(maximum) = network.max_fee_per_gas.as_deref() {
        ensure!(
            envelope.max_fee_per_gas() <= maximum.parse::<u128>()?,
            "signed transaction exceeds configured maximum fee per gas"
        );
    }
    // And from below. This function is the last thing between a freshly signed
    // envelope and the row that records it, and it checked every field except
    // whether the transaction can execute at all. The bound belongs here as
    // well as in `signing_gas_limit`, because this is what a caller reaches
    // for to ask "is this envelope sound" -- including callers that did not
    // compute the limit themselves.
    ensure!(
        envelope.gas_limit() >= INTRINSIC_TRANSACTION_GAS,
        "signed transaction carries {} gas, below the {INTRINSIC_TRANSACTION_GAS} every \
         transaction costs before it does anything; no node would execute it",
        envelope.gas_limit()
    );

    match (&envelope, planned.mode) {
        (TxEnvelope::Eip1559(_), _) => {}
        (TxEnvelope::Eip7702(transaction), ExecutionMode::CaliburBatch) => {
            let authorizations = transaction
                .authorization_list()
                .context("EIP-7702 transaction has no authorization list")?;
            ensure!(
                authorizations.len() == 1,
                "signed transaction has an unexpected authorization list"
            );
            let authorization = &authorizations[0];
            ensure!(
                *authorization.inner().address() == CANONICAL_CALIBUR,
                "signed authorization targets an unexpected implementation"
            );
            ensure!(
                authorization.inner().chain_id() == &U256::from(network.chain_id),
                "signed authorization chain does not match configured network"
            );
            ensure!(
                authorization.inner().nonce()
                    == envelope
                        .nonce()
                        .checked_add(1)
                        .context("signed transaction nonce cannot authorize delegation")?,
                "signed authorization nonce does not match transaction nonce"
            );
            ensure!(
                authorization
                    .recover_authority()
                    .context("failed to recover authorization signer")?
                    == wallet.address,
                "signed authorization was not produced by wallet"
            );
        }
        (TxEnvelope::Eip7702(_), ExecutionMode::Direct) => {
            anyhow::bail!("direct transaction unexpectedly uses EIP-7702 authorization");
        }
        _ => anyhow::bail!("signed transaction has an unsupported envelope type"),
    }
    Ok(())
}

fn validate_signed_preparation(
    signed: &SignedExecution,
    prepared: &PreparedExecution,
) -> Result<()> {
    let bytes = decode_serialized(&signed.serialized_transaction)?;
    let envelope = decode_envelope(&bytes)?;
    ensure!(
        envelope.nonce() == prepared.nonce,
        "signed transaction nonce does not match reviewed preparation"
    );
    ensure!(
        envelope.gas_limit() == prepared.gas_limit,
        "signed transaction gas limit does not match reviewed preparation"
    );
    ensure!(
        envelope.max_fee_per_gas() == prepared.max_fee_per_gas,
        "signed transaction maximum fee does not match reviewed preparation"
    );
    ensure!(
        envelope.max_priority_fee_per_gas() == Some(prepared.max_priority_fee_per_gas),
        "signed transaction priority fee does not match reviewed preparation"
    );
    ensure!(
        matches!(
            (&envelope, prepared.authorize_delegation),
            (TxEnvelope::Eip1559(_), false) | (TxEnvelope::Eip7702(_), true)
        ),
        "signed transaction type does not match reviewed preparation"
    );
    Ok(())
}

/// The nonce inside an exact stored signed envelope. Reconciliation compares
/// it against the chain's mined account nonce to detect replacement.
pub fn signed_transaction_nonce(serialized_transaction: &str) -> Result<u64> {
    let bytes = decode_serialized(serialized_transaction)?;
    Ok(decode_envelope(&bytes)?.nonce())
}

/// Same-nonce replacement floor. Nodes drop a replacement unless it outbids
/// the incumbent on both EIP-1559 fee fields — geth's default floor is 10% —
/// so bump by 12.5% (×9/8, integer-exact) to clear it with margin.
const REPLACEMENT_FEE_BUMP_NUMERATOR: u128 = 9;
const REPLACEMENT_FEE_BUMP_DENOMINATOR: u128 = 8;
/// Defense-in-depth ceiling for the one signing path that consults no policy:
/// a cancellation's fee never exceeds this multiple of the highest fee the
/// owner already committed to for this nonce.
///
/// Anchored to the incumbent envelopes and to nothing else. It used to include
/// the endpoint's own market estimate in the maximum it was capping, which
/// made the cap a function of the value it was bounding: an endpoint reporting
/// a market fee of `M` produced a selected fee of at least `M` against a cap
/// of at least `2M`, so the check passed for every `M` it could name. That is
/// not a ceiling, it is an assertion that two multiples of the same number are
/// ordered.
///
/// Four rather than two because the anchor is now strictly tighter, and gas
/// markets do move between the moment a transaction was signed and the moment
/// its sender wants it gone.
const CANCELLATION_FEE_CAP_MULTIPLIER: u128 = 4;
const CANCELLATION_GAS_MULTIPLIER: u64 = 2;

fn bumped_fee(fee: u128) -> u128 {
    fee.saturating_mul(REPLACEMENT_FEE_BUMP_NUMERATOR)
        .div_ceil(REPLACEMENT_FEE_BUMP_DENOMINATOR)
}

/// Fee selection for a cancellation, split from the RPC calls so the one
/// policy-free pricing decision is directly testable: outbid every incumbent
/// at the replacement floor, never price under the current market, never above
/// the cap the incumbents set, and keep the pair EIP-1559-consistent.
///
/// Nothing reviews this. There is no policy question a cancellation asks and
/// no approval screen it draws, so `market_max_fee` and `market_priority_fee`
/// — two numbers one endpoint chose — would otherwise reach a signature
/// unbounded. The incumbents are the other half of the input and are not:
/// they are envelopes this wallet signed for this nonce, so the fee the owner
/// already committed to is the anchor everything here is measured against.
///
/// Above the cap the market estimate is clamped rather than refused. The
/// replacement floor is 9/8 of an incumbent and the cap is four times one, so
/// a clamped fee still outbids what it is replacing — the envelope is always a
/// valid replacement, just possibly an underpriced one in a market that has
/// moved more than fourfold since. Refusing instead would let an endpoint deny
/// cancellation outright by reporting a large enough number, which is the
/// other half of the same attack.
fn cancellation_fees(
    incumbents: &[(u128, u128)],
    market_max_fee: u128,
    market_priority_fee: u128,
) -> Result<(u128, u128)> {
    let floor_max = incumbents.iter().map(|fees| bumped_fee(fees.0)).max();
    let floor_priority = incumbents.iter().map(|fees| bumped_fee(fees.1)).max();
    let incumbent_max = incumbents.iter().map(|fees| fees.0).max();
    let (floor_max, floor_priority, incumbent_max) = (
        floor_max.context("cancellation has no incumbent envelope to outbid")?,
        floor_priority.context("cancellation has no incumbent envelope to outbid")?,
        incumbent_max.context("cancellation has no incumbent envelope to outbid")?,
    );
    let cap = incumbent_max
        .saturating_mul(CANCELLATION_FEE_CAP_MULTIPLIER)
        .max(floor_max);
    let max_priority_fee_per_gas = market_priority_fee.max(floor_priority).min(cap);
    let max_fee_per_gas = market_max_fee
        .max(floor_max)
        .max(max_priority_fee_per_gas)
        .min(cap);
    ensure!(
        max_fee_per_gas >= floor_max && max_priority_fee_per_gas >= floor_priority,
        "cancellation cannot be priced above the envelope it replaces"
    );
    Ok((max_fee_per_gas, max_priority_fee_per_gas))
}

/// Prepare and sign a cancellation for an exact stored envelope: a 0-value
/// self-send with empty calldata and no authorization list, at the stuck
/// envelope's own nonce, priced to outbid it at the node's replacement floor.
///
/// Every field is derived from the stored envelopes and the chain — the
/// caller cannot steer the nonce, target, value, or calldata — which is why
/// this one signing path consults no policy: like rebroadcasting exact bytes,
/// it cannot expand what was already authorized, only narrow an in-flight
/// authorization to nothing at the cost of gas. Gas is estimated rather than
/// hardcoded because a wallet with an active EIP-7702 delegation executes its
/// implementation's code even on a plain self-send.
pub async fn sign_cancellation<K: KeyStore + ?Sized>(
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    original_serialized_transaction: &str,
    newest_cancellation: Option<&str>,
    keys: &K,
) -> Result<SignedExecution> {
    let original = decode_envelope(&decode_serialized(original_serialized_transaction)?)?;
    let nonce = original.nonce();
    let mut incumbents = Vec::with_capacity(2);
    for serialized in std::iter::once(original_serialized_transaction).chain(newest_cancellation) {
        let envelope = decode_envelope(&decode_serialized(serialized)?)?;
        ensure!(
            envelope
                .recover_signer()
                .context("failed to recover incumbent envelope sender")?
                == wallet.address,
            "cancellation target envelope was not signed by this wallet"
        );
        ensure!(
            envelope.chain_id() == Some(network.chain_id),
            "cancellation target envelope chain does not match configured network"
        );
        ensure!(
            envelope.nonce() == nonce,
            "cancellation envelopes disagree on the nonce"
        );
        incumbents.push((
            envelope.max_fee_per_gas(),
            envelope.max_priority_fee_per_gas().unwrap_or(0),
        ));
    }

    let planned = crate::simulation::PlannedCall {
        mode: ExecutionMode::Direct,
        to: wallet.address,
        data: alloy::primitives::Bytes::new(),
        value: U256::ZERO,
    };
    // The ceiling check lives inside the closure, so an endpoint whose numbers
    // do not survive it is an endpoint that failed and the next one is tried.
    // It used to run after failover returned, which made an inflated
    // estimate or a shrunken block limit fatal to the whole call rather than
    // to the endpoint that gave it — and the ordered strategy asks the same
    // endpoint first every time, so the answer never changed. A cancellation
    // is what an owner reaches for when a transaction they want stopped is
    // still live, which is the worst moment to have one endpoint decide the
    // envelope cannot be built.
    let (_chain_id, market, gas_limit) = crate::rpc::try_clients(network, |client| async move {
        let estimate_request = alloy::rpc::types::TransactionRequest::default()
            .from(wallet.address)
            .to(wallet.address)
            .value(U256::ZERO);
        let (chain_id, market, estimated_gas, head) = tokio::time::timeout(RPC_TIMEOUT, async {
            tokio::try_join!(
                client.chain_id(),
                client.estimate_eip1559_fees(),
                client.estimate_gas(estimate_request),
                client.block_by_number(alloy::eips::BlockNumberOrTag::Latest),
            )
        })
        .await
        .context("cancellation preparation RPC timed out")??;
        ensure!(
            chain_id == network.chain_id,
            "RPC reports chain {chain_id}, not {}",
            network.chain_id
        );
        // Read from the same endpoint and in the same breath as the
        // estimate it bounds, so an endpoint cannot answer one of the two
        // and have the other come from somewhere it does not control.
        let block_maximum = head
            .context("cancellation preparation could not read the chain head")?
            .header
            .gas_limit;
        // The same ceiling `signing_gas_limit` computes, and for the same
        // reason. This bound used to exist only when the network carried a
        // configured maximum, which most shipped profiles do not — so on
        // an ordinary network an endpoint's `estimate_gas` was the whole
        // of what decided the signed gas limit. A cancellation cannot be
        // simulated, so an endpoint that returns an absurd estimate
        // produces an envelope every honest peer rejects while spending
        // one of the eight attempts this wallet will ever make.
        let maximum = usable_gas_ceiling(network, block_maximum)?;
        ensure!(
            estimated_gas <= maximum,
            "estimated cancellation gas {estimated_gas} exceeds the maximum usable gas \
                 limit {maximum}"
        );
        Ok((
            chain_id,
            market,
            cancellation_gas_limit(estimated_gas, maximum),
        ))
    })
    .await?;
    let (max_fee_per_gas, max_priority_fee_per_gas) = cancellation_fees(
        &incumbents,
        market.max_fee_per_gas,
        market.max_priority_fee_per_gas,
    )?;

    // All RPC preparation completed before this function loads key material.
    let local_signer = load_matching_signer(keys, wallet)?;
    sign_prepared(
        &local_signer,
        network.chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        &planned,
        false,
    )
}

pub async fn broadcast_signed_execution(
    signed: &SignedExecution,
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
) -> Result<BroadcastResult> {
    validate_signed_execution(signed, wallet, network, plan)?;
    send_exact_bytes(signed, network).await
}

/// Validate that exact signed bytes are a well-formed cancellation for this
/// wallet — a 0-value self-send with empty calldata and no authorization
/// list — then broadcast them. Cancellations have no execution plan to
/// validate against, so the shape check here is the whole admission rule.
pub async fn broadcast_signed_cancellation(
    signed: &SignedExecution,
    wallet: &WalletMetadata,
    network: &NetworkConfig,
) -> Result<BroadcastResult> {
    let expected_hash =
        B256::from_str(&signed.transaction_hash).context("signed transaction hash is invalid")?;
    let bytes = decode_serialized(&signed.serialized_transaction)?;
    ensure!(
        keccak256(&bytes) == expected_hash,
        "signed transaction hash mismatch"
    );
    let envelope = decode_envelope(&bytes)?;
    ensure!(
        envelope
            .recover_signer()
            .context("failed to recover signed transaction sender")?
            == wallet.address,
        "cancellation sender does not match wallet"
    );
    ensure!(
        envelope.chain_id() == Some(network.chain_id),
        "cancellation chain does not match configured network"
    );
    ensure!(
        matches!(envelope, TxEnvelope::Eip1559(_)),
        "cancellation must not carry an authorization list"
    );
    ensure!(
        envelope.kind() == TxKind::Call(wallet.address)
            && envelope.value() == U256::ZERO
            && envelope.input().is_empty(),
        "cancellation must be a 0-value self-send with empty calldata"
    );
    send_exact_bytes(signed, network).await
}

/// Submit already-signed bytes, trying each configured endpoint until one
/// accepts them.
///
/// Broadcasting is the one path failover cannot express as "retry the read
/// elsewhere". Re-sending the identical signed bytes is safe — same nonce,
/// same signature, same hash, so a second acceptance is the first one
/// again — but a *rejection* has to be interpreted against the endpoint that
/// produced it, because "already known" and "nonce too low" describe a
/// submission that succeeded. So each endpoint runs the complete
/// send-and-reconcile below, and only an outcome that still reports a
/// broadcast error moves on to the next.
///
/// The first endpoint's error is the one reported when every endpoint fails:
/// it is the one that saw the transaction in the state closest to unsent.
async fn send_exact_bytes(
    signed: &SignedExecution,
    network: &NetworkConfig,
) -> Result<BroadcastResult> {
    let mut first_failure = None;
    for client in crate::rpc::clients_for(network) {
        let outcome = match send_exact_bytes_through(signed, network, client.as_ref()).await {
            Ok(outcome) => outcome,
            Err(error) => {
                if first_failure.is_none() {
                    first_failure = Some(Err(error));
                }
                continue;
            }
        };
        if outcome.broadcast_error.is_none() {
            return Ok(outcome);
        }
        if first_failure.is_none() {
            first_failure = Some(Ok(outcome));
        }
    }
    first_failure.unwrap_or_else(|| {
        Err(anyhow::anyhow!(
            "network {} has no RPC endpoint to broadcast through",
            network.name
        ))
    })
}

async fn send_exact_bytes_through(
    signed: &SignedExecution,
    network: &NetworkConfig,
    client: &dyn ChainClient,
) -> Result<BroadcastResult> {
    crate::rpc::ensure_serving_chain(client, network.chain_id).await?;
    let hash = B256::from_str(&signed.transaction_hash).context("invalid transaction hash")?;
    if let Ok(Some(receipt)) = transaction_receipt_through(client, network.chain_id, hash).await {
        return Ok(receipt_result(&signed.transaction_hash, receipt));
    }
    let known = tokio::time::timeout(RPC_TIMEOUT, client.transaction_by_hash(hash))
        .await
        .ok()
        .and_then(std::result::Result::ok)
        .flatten()
        .is_some();
    if !known {
        let bytes = decode_serialized(&signed.serialized_transaction)?;
        let failure =
            match tokio::time::timeout(RPC_TIMEOUT, client.send_transaction(bytes.into())).await {
                Ok(Ok(returned_hash)) if returned_hash == hash => None,
                Ok(Ok(_)) => Some("RPC returned an unexpected transaction hash".to_owned()),
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => Some("transaction submission RPC timed out".to_owned()),
            };
        if let Some(failure) = failure {
            return Ok(reconcile_failed_send(signed, network, client, hash, failure).await);
        }
    }
    if let Ok(Some(receipt)) = transaction_receipt_through(client, network.chain_id, hash).await {
        return Ok(receipt_result(&signed.transaction_hash, receipt));
    }
    Ok(BroadcastResult {
        transaction_hash: signed.transaction_hash.clone(),
        receipt_status: ReceiptStatus::Pending,
        block_number: None,
        mined_fee: None,
        broadcast_error: None,
        absence_established: true,
    })
}

/// Decide what a rejected or timed-out send actually means, by looking at the
/// chain again rather than trusting the rejection.
///
/// The receipt and mempool checks above are not atomic with the send. This
/// exact transaction can land in the window between them, and the node then
/// answers the send with `nonce too low`, `already known`, or `replacement
/// transaction underpriced` — all of which describe a submission that
/// succeeded. A timeout hides the same thing.
///
/// Reporting that as a broadcast failure is worse than useless: the natural
/// response to one is to prepare and submit a replacement, which risks
/// executing twice something that already executed once.
async fn reconcile_failed_send(
    signed: &SignedExecution,
    network: &NetworkConfig,
    client: &dyn ChainClient,
    hash: B256,
    failure: String,
) -> BroadcastResult {
    let receipt = transaction_receipt_through(client, network.chain_id, hash)
        .await
        .ok()
        .flatten();
    // `Ok(Ok(None))` is the node answering that it does not hold the
    // transaction. A timeout or a transport error is the node not answering,
    // and the two used to arrive here as the same `false`.
    let accepted = match tokio::time::timeout(RPC_TIMEOUT, client.transaction_by_hash(hash)).await {
        Ok(Ok(Some(_))) => Presence::Held,
        Ok(Ok(None)) => Presence::Absent,
        Ok(Err(_)) | Err(_) => Presence::Unobserved,
    };
    send_failure_outcome(&signed.transaction_hash, receipt, accepted, failure)
}

/// What a send failure means, given what the chain says afterwards.
///
/// Split out from the RPC calls so the decision itself is testable: it is the
/// part that has to be right.
pub(crate) fn send_failure_outcome(
    hash: &str,
    receipt: Option<crate::rpc::ReceiptStatus>,
    accepted: Presence,
    failure: String,
) -> BroadcastResult {
    // Mined already. The send was rejected because it had nothing left to do.
    if let Some(receipt) = receipt {
        return receipt_result(hash, receipt);
    }
    BroadcastResult {
        transaction_hash: hash.into(),
        receipt_status: ReceiptStatus::Pending,
        block_number: None,
        mined_fee: None,
        // `Held`: the node holds this exact transaction, so submission
        // succeeded and the rejection described an earlier attempt rather than
        // a problem with this one. That is indistinguishable from an ordinary
        // accepted send still waiting for a receipt, and is reported as one.
        //
        // `Unobserved` still reports the failure, because the caller asked for
        // a send and did not get one — but it says the absence was never
        // established, and `submit_claimed` will not spend that on a lifecycle
        // transition.
        broadcast_error: match accepted {
            Presence::Held => None,
            Presence::Absent | Presence::Unobserved => Some(failure),
        },
        absence_established: accepted != Presence::Unobserved,
    }
}

fn receipt_result(hash: &str, receipt: crate::rpc::ReceiptStatus) -> BroadcastResult {
    BroadcastResult {
        transaction_hash: hash.into(),
        receipt_status: if receipt.succeeded {
            ReceiptStatus::Success
        } else {
            ReceiptStatus::Reverted
        },
        block_number: Some(receipt.block_number.to_string()),
        mined_fee: Some(receipt.mined_fee()),
        broadcast_error: None,
        absence_established: true,
    }
}

fn decode_serialized(value: &str) -> Result<Vec<u8>> {
    let encoded = value
        .strip_prefix("0x")
        .context("serialized transaction must start with 0x")?;
    ensure!(
        !encoded.is_empty() && encoded.len().is_multiple_of(2),
        "serialized transaction must contain whole bytes"
    );
    hex::decode(encoded).context("serialized transaction is not hexadecimal")
}

fn decode_envelope(bytes: &[u8]) -> Result<TxEnvelope> {
    let mut slice = bytes;
    let envelope = TxEnvelope::decode_2718(&mut slice)
        .context("signed transaction is not a supported EIP-2718 envelope")?;
    ensure!(
        slice.is_empty(),
        "signed transaction contains trailing bytes"
    );
    Ok(envelope)
}

#[cfg(test)]
#[path = "execution_test.rs"]
mod tests;
