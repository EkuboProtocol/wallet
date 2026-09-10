//! Simulation facts for review rendering. This type has no prepared execution
//! authority or simulation-consumption handle and cannot be converted back into
//! a core simulation result.

use ekubo_wallet_core::{
    core::policy::{PolicyFinding, PolicyOutcome},
    fork::ForkContext,
    simulation::{BalanceChanges, ExecutionMode, SimulationExecution, SimulationResult},
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationDisplay {
    pub digest: String,
    /// True only when the policy allowed every call *and* the simulation
    /// succeeded, i.e. this signs with no prompt. `policy_outcome` says which
    /// of the two a `false` came from.
    pub allowed: bool,
    /// What the policy alone decided, independent of whether the simulation
    /// succeeded: signs automatically, needs a human, or is refused outright
    /// with no approval path at all.
    pub policy_outcome: PolicyOutcome,
    pub policy_findings: Vec<PolicyFinding>,
    pub policy_revision: u64,
    pub execution_mode: ExecutionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation: Option<String>,
    pub will_authorize_delegation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces_delegated_implementation: Option<String>,
    /// Display-only summary of the exact envelope policy evaluated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepared_transaction: Option<ekubo_wallet_core::execution::PreparedTransactionSummary>,
    pub simulation: SimulationExecution,
    pub token_spends: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_changes: Option<BalanceChanges>,
    /// Parent block number whose state was used by `eth_simulateV1`. On a
    /// fork this is still the fork's pinned parent; the block this plan
    /// actually executed in is `fork.simulated_block_number`.
    pub block_number: String,
    /// Present only when the plan was simulated on a temporary fork. Its
    /// presence means every number above is hypothetical: nothing was signed,
    /// approved, or authorized by simulating here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkContext>,
}

impl From<&SimulationResult> for SimulationDisplay {
    fn from(result: &SimulationResult) -> Self {
        Self {
            digest: result.digest.clone(),
            allowed: result.allowed,
            policy_outcome: result.policy_outcome,
            policy_findings: result.policy_findings.clone(),
            policy_revision: result.policy_revision,
            execution_mode: result.execution_mode,
            implementation: result.implementation.clone(),
            will_authorize_delegation: result.will_authorize_delegation,
            replaces_delegated_implementation: result.replaces_delegated_implementation.clone(),
            prepared_transaction: result.prepared_transaction.clone(),
            simulation: result.simulation.clone(),
            token_spends: result.token_spends.clone(),
            balance_changes: result.balance_changes.clone(),
            block_number: result.block_number.clone(),
            fork: result.fork.clone(),
        }
    }
}

#[cfg(test)]
#[path = "simulation_display_test.rs"]
mod tests;
