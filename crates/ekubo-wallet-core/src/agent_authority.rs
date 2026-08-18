//! Narrow signing capability for hostile agent-facing adapters.
//!
//! The desktop MCP server receives this value instead of a [`KeyStore`]. It
//! can ask the kernel to execute a freshly prepared policy decision or derive
//! an exact cancellation, but it cannot load key material or request an
//! arbitrary signature.

use crate::{
    config::{ConfigStore, NetworkConfig, WalletMetadata},
    core::{execution_plan::ExecutionPlan, policy::ReviewRequest},
    custody::{KeyStore, OsKeyStore},
    execution::BroadcastResult,
    orchestrator::{SendDisposition, execute_automatic},
    pending::{PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    reconcile::attempt_cancellation,
    simulation::SimulationResult,
};
use anyhow::Result;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct AgentExecutionAuthority {
    keys: Arc<dyn KeyStore>,
    policies: Arc<Mutex<PolicyStore>>,
}

impl AgentExecutionAuthority {
    #[must_use]
    pub fn production(policies: Arc<Mutex<PolicyStore>>) -> Self {
        Self {
            keys: Arc::new(OsKeyStore),
            policies,
        }
    }

    /// Construct the same narrow authority over an alternate sealed store.
    /// Used by tests; possession still exposes no raw-key operation through
    /// this type.
    #[must_use]
    pub fn over(keys: Arc<dyn KeyStore>, policies: Arc<Mutex<PolicyStore>>) -> Self {
        Self { keys, policies }
    }

    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn key_store_for_test(&self) -> &dyn KeyStore {
        &*self.keys
    }

    pub async fn execute(
        &self,
        config: &ConfigStore,
        pending: &Mutex<PendingStore>,
        wallet: &WalletMetadata,
        network: &NetworkConfig,
        plan: &ExecutionPlan,
        plan_source: Option<&str>,
        simulation: &SimulationResult,
        review_request: ReviewRequest,
    ) -> Result<SendDisposition> {
        execute_automatic(
            config,
            pending,
            &self.policies,
            &*self.keys,
            wallet,
            network,
            plan,
            plan_source,
            simulation,
            review_request,
        )
        .await
    }

    pub async fn cancel(
        &self,
        pending: &Mutex<PendingStore>,
        config: &ConfigStore,
        wallet: &WalletMetadata,
        network: &NetworkConfig,
        record: PendingTransaction,
    ) -> Result<(PendingTransaction, BroadcastResult)> {
        attempt_cancellation(pending, config, wallet, network, record, &*self.keys).await
    }
}
