use crate::{
    config::{NetworkConfig, WalletMetadata},
    core::{execution_plan::ExecutionPlan, policy::FindingSeverity},
    custody::KeyStore,
    rpc::{transaction_receipt, verify_chain_id},
    simulation::{CANONICAL_CALIBUR, ExecutionMode, SimulationResult, planned_call},
};
use alloy::{
    consensus::{
        SignableTransaction, Transaction, TxEip1559, TxEip7702, TxEnvelope,
        transaction::SignerRecoverable,
    },
    eips::{eip2718::Decodable2718, eip2930::AccessList, eip7702::Authorization},
    network::TxSignerSync,
    primitives::{B256, TxKind, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
};
use anyhow::{Context, Result, ensure};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::json;
use std::{str::FromStr, time::Duration};

const RPC_TIMEOUT: Duration = Duration::from_secs(15);
const EIP7702_AUTHORIZATION_INTRINSIC_COST: u64 = 25_000;
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
    pub const fn authorizes_delegation(&self) -> bool {
        self.authorize_delegation
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SigningOverrides {
    pub allow_policy_override: bool,
    pub allow_simulation_failure: bool,
}

/// Prepare fee and nonce fields through the configured RPC, then load the key
/// only after every upstream request has completed and sign locally.
pub async fn sign_execution<K: KeyStore>(
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
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let prepared = tokio::time::timeout(RPC_TIMEOUT, async {
        tokio::try_join!(
            provider.get_chain_id(),
            provider.get_transaction_count(wallet.address).pending(),
            provider.estimate_eip1559_fees(),
        )
    })
    .await
    .context("transaction preparation RPC timed out")?
    .map_err(|error| sanitized_rpc_error(network, &error))?;
    ensure!(
        prepared.0 == network.chain_id,
        "RPC reports chain {}, not {}",
        prepared.0,
        network.chain_id
    );
    ensure!(
        prepared.2.max_fee_per_gas >= prepared.2.max_priority_fee_per_gas,
        "RPC returned invalid EIP-1559 fee fields"
    );
    if simulation.will_authorize_delegation {
        prepared
            .1
            .checked_add(1)
            .context("authorization nonce overflow")?;
    }

    Ok(PreparedExecution {
        chain_id: network.chain_id,
        nonce: prepared.1,
        gas_limit,
        max_fee_per_gas: prepared.2.max_fee_per_gas,
        max_priority_fee_per_gas: prepared.2.max_priority_fee_per_gas,
        planned,
        authorize_delegation: simulation.will_authorize_delegation,
        plan_digest: simulation.digest.clone(),
    })
}

/// Load the key and sign exactly the already-reviewed preparation fields.
pub fn sign_prepared_execution<K: KeyStore>(
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

    // All RPC preparation completed before this function loads key material.
    let material = keys.load(&wallet.id)?;
    let local_signer = material.signer();
    ensure!(
        local_signer.address() == wallet.address,
        "credential-store private key does not match wallet metadata"
    );
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
    let policy_blocked = simulation.policy_findings.iter().any(|finding| {
        finding.severity == FindingSeverity::Error && finding.code != "simulation_failed"
    });
    ensure!(
        !policy_blocked || overrides.allow_policy_override,
        "transaction was denied by the active wallet policy"
    );
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
    let configured = network
        .max_gas_limit
        .as_deref()
        .map(str::parse::<u64>)
        .transpose()
        .context("configured maximum gas limit does not fit uint64")?
        .unwrap_or(block_maximum);
    let maximum = configured.min(block_maximum);
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
    Ok(baseline
        .saturating_mul(SIMULATION_GAS_MULTIPLIER)
        .min(maximum))
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

pub async fn broadcast_signed_execution(
    signed: &SignedExecution,
    wallet: &WalletMetadata,
    network: &NetworkConfig,
    plan: &ExecutionPlan,
) -> Result<BroadcastResult> {
    validate_signed_execution(signed, wallet, network, plan)?;
    verify_chain_id(network).await?;
    if let Ok(Some(receipt)) = transaction_receipt(network, &signed.transaction_hash).await {
        return Ok(receipt_result(&signed.transaction_hash, receipt));
    }
    let hash = B256::from_str(&signed.transaction_hash).context("invalid transaction hash")?;
    let provider = ProviderBuilder::new().connect_http(network.rpc_url.clone());
    let known = tokio::time::timeout(RPC_TIMEOUT, provider.get_transaction_by_hash(hash))
        .await
        .ok()
        .and_then(std::result::Result::ok)
        .flatten()
        .is_some();
    if !known {
        let bytes = decode_serialized(&signed.serialized_transaction)?;
        match tokio::time::timeout(RPC_TIMEOUT, provider.send_raw_transaction(&bytes)).await {
            Ok(Ok(pending)) if pending.tx_hash() == &hash => {}
            Ok(Ok(_)) => {
                return Ok(BroadcastResult {
                    transaction_hash: signed.transaction_hash.clone(),
                    receipt_status: ReceiptStatus::Pending,
                    block_number: None,
                    broadcast_error: Some("RPC returned an unexpected transaction hash".into()),
                });
            }
            Ok(Err(error)) => {
                return Ok(BroadcastResult {
                    transaction_hash: signed.transaction_hash.clone(),
                    receipt_status: ReceiptStatus::Pending,
                    block_number: None,
                    broadcast_error: Some(sanitize_message(network, &error.to_string())),
                });
            }
            Err(_) => {
                return Ok(BroadcastResult {
                    transaction_hash: signed.transaction_hash.clone(),
                    receipt_status: ReceiptStatus::Pending,
                    block_number: None,
                    broadcast_error: Some("transaction submission RPC timed out".into()),
                });
            }
        }
    }
    if let Ok(Some(receipt)) = transaction_receipt(network, &signed.transaction_hash).await {
        return Ok(receipt_result(&signed.transaction_hash, receipt));
    }
    Ok(BroadcastResult {
        transaction_hash: signed.transaction_hash.clone(),
        receipt_status: ReceiptStatus::Pending,
        block_number: None,
        broadcast_error: None,
    })
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
        broadcast_error: None,
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

fn sanitized_rpc_error(network: &NetworkConfig, error: &impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!(
        "RPC request failed: {}",
        sanitize_message(network, &error.to_string())
    )
}

fn sanitize_message(network: &NetworkConfig, message: &str) -> String {
    message.replace(network.rpc_url.as_str(), "<rpc-url>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{CustodyStatus, WalletSource},
        core::execution_plan::ExecutionPlan,
    };
    use alloy::{primitives::Address, signers::local::PrivateKeySigner};
    use chrono::Utc;
    use serde_json::json;

    fn wallet(signer: &PrivateKeySigner) -> WalletMetadata {
        WalletMetadata {
            id: "primary".into(),
            address: signer.address(),
            created_at: Utc::now(),
            source: WalletSource::Created,
            custody: CustodyStatus::Sealed,
            exported_at: None,
        }
    }

    fn network() -> NetworkConfig {
        let mut network = crate::config::default_networks().remove(0);
        network.max_gas_limit = Some("1000000".into());
        network
    }

    fn plan(sender: Address, steps: usize) -> ExecutionPlan {
        let ordered_steps = (0..steps)
            .map(|index| {
                json!({
                    "step": index + 1,
                    "kind": "execution",
                    "submit_condition": "always",
                    "transaction": {
                        "chain_id": "1",
                        "from": sender,
                        "to": Address::repeat_byte(u8::try_from(index + 1).unwrap()),
                        "data": "0x1234",
                        "value": index.to_string(),
                    }
                })
            })
            .collect::<Vec<_>>();
        ExecutionPlan::parse(json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": sender,
            "ordered_steps": ordered_steps,
        }))
        .unwrap()
    }

    fn finalize_digest(mut signed: SignedExecution, plan: &ExecutionPlan) -> SignedExecution {
        signed.digest = format!("{:#x}", plan.digest());
        signed
    }

    #[test]
    fn signs_and_validates_exact_direct_transaction() {
        let local_signer = PrivateKeySigner::from_slice(&[7; 32]).unwrap();
        let wallet = wallet(&local_signer);
        let network = network();
        let plan = plan(wallet.address, 1);
        let signed_execution = finalize_digest(
            sign_prepared(
                &local_signer,
                1,
                3,
                100_000,
                20,
                2,
                &planned_call(&plan, wallet.address),
                false,
            )
            .unwrap(),
            &plan,
        );
        validate_signed_execution(&signed_execution, &wallet, &network, &plan).unwrap();
        assert!(signed_execution.serialized_transaction.starts_with("0x02"));
    }

    #[test]
    fn signs_and_validates_canonical_calibur_authorization() {
        let local_signer = PrivateKeySigner::from_slice(&[8; 32]).unwrap();
        let wallet = wallet(&local_signer);
        let network = network();
        let plan = plan(wallet.address, 2);
        let signed_execution = finalize_digest(
            sign_prepared(
                &local_signer,
                1,
                4,
                200_000,
                30,
                3,
                &planned_call(&plan, wallet.address),
                true,
            )
            .unwrap(),
            &plan,
        );
        validate_signed_execution(&signed_execution, &wallet, &network, &plan).unwrap();
        assert!(signed_execution.serialized_transaction.starts_with("0x04"));
    }

    #[test]
    fn rejects_tampered_plan_or_signed_bytes() {
        let local_signer = PrivateKeySigner::from_slice(&[9; 32]).unwrap();
        let wallet = wallet(&local_signer);
        let network = network();
        let plan = plan(wallet.address, 1);
        let mut signed_execution = finalize_digest(
            sign_prepared(
                &local_signer,
                1,
                0,
                100_000,
                20,
                2,
                &planned_call(&plan, wallet.address),
                false,
            )
            .unwrap(),
            &plan,
        );
        signed_execution.serialized_transaction.push_str("00");
        assert!(validate_signed_execution(&signed_execution, &wallet, &network, &plan).is_err());
    }

    #[test]
    fn review_digest_binds_every_prepared_transaction_field() {
        let local_signer = PrivateKeySigner::from_slice(&[10; 32]).unwrap();
        let wallet = wallet(&local_signer);
        let plan = plan(wallet.address, 1);
        let prepared = PreparedExecution {
            chain_id: 1,
            nonce: 7,
            gas_limit: 100_000,
            max_fee_per_gas: 30,
            max_priority_fee_per_gas: 3,
            planned: planned_call(&plan, wallet.address),
            authorize_delegation: false,
            plan_digest: format!("{:#x}", plan.digest()),
        };
        let expected = prepared.review_digest();
        let mut mutations = Vec::new();

        let mut changed = prepared.clone();
        changed.chain_id += 1;
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.nonce += 1;
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.gas_limit += 1;
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.max_fee_per_gas += 1;
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.max_priority_fee_per_gas += 1;
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.planned.to = Address::repeat_byte(0xaa);
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.planned.value += U256::from(1);
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.planned.data = vec![0xff].into();
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.authorize_delegation = true;
        mutations.push(changed);
        let mut changed = prepared.clone();
        changed.plan_digest = format!("{:#x}", B256::repeat_byte(0xbb));
        mutations.push(changed);

        assert!(
            mutations
                .iter()
                .all(|changed| changed.review_digest() != expected)
        );
    }

    #[test]
    fn signed_envelope_must_match_reviewed_preparation() {
        let local_signer = PrivateKeySigner::from_slice(&[11; 32]).unwrap();
        let wallet = wallet(&local_signer);
        let plan = plan(wallet.address, 1);
        let prepared = PreparedExecution {
            chain_id: 1,
            nonce: 8,
            gas_limit: 100_000,
            max_fee_per_gas: 30,
            max_priority_fee_per_gas: 3,
            planned: planned_call(&plan, wallet.address),
            authorize_delegation: false,
            plan_digest: format!("{:#x}", plan.digest()),
        };
        let signed = finalize_digest(
            sign_prepared(
                &local_signer,
                prepared.chain_id,
                prepared.nonce,
                prepared.gas_limit,
                prepared.max_fee_per_gas,
                prepared.max_priority_fee_per_gas,
                &prepared.planned,
                prepared.authorize_delegation,
            )
            .unwrap(),
            &plan,
        );
        validate_signed_preparation(&signed, &prepared).unwrap();

        let mut changed = prepared;
        changed.nonce += 1;
        assert!(validate_signed_preparation(&signed, &changed).is_err());
    }
}
