//! Host-independent automation supervisor. The host supplies its bound profile
//! and event bus; all execution still uses core's narrow agent authority.

use crate::events::{DomainEventKind, EventBus};
use anyhow::{Context as _, Result};
use ekubo_wallet_core::{
    agent_authority::AgentExecutionAuthority,
    automation_scheduler::{AutomationScheduler, drive},
    automation_store::AutomationStore,
    config::ConfigStore,
    pending::PendingStore,
    policy_store::PolicyStore,
};
use std::sync::{Arc, Mutex};

/// Run until the host cancels this future. Initialization errors are returned
/// to the host, while transient per-tick failures retain core's retry behavior.
/// No client-supplied profile, policy copy, or owner capability is accepted.
pub async fn run(config: ConfigStore, events: EventBus) -> Result<()> {
    let data_dir = config.data_dir();
    let automations =
        Mutex::new(AutomationStore::production(data_dir).context("cannot open automation state")?);
    let pending = Mutex::new(
        PendingStore::production(data_dir).context("cannot open automation transaction state")?,
    );
    let policies = Arc::new(Mutex::new(
        PolicyStore::production(data_dir).context("cannot open automation signing policy")?,
    ));
    let scheduler =
        AutomationScheduler::new(AgentExecutionAuthority::production(Arc::clone(&policies)));
    drive(
        &scheduler,
        &config,
        &automations,
        &pending,
        &policies,
        |outcome| {
            // Match desktop behavior: idle passes publish nothing, and a pass
            // that completed work invalidates the automation view.
            if outcome.is_ok() {
                events.publish(DomainEventKind::AutomationsChanged {
                    wallet_id: String::new(),
                });
            }
        },
    )
    .await
}

#[cfg(test)]
#[path = "automation_runtime_test.rs"]
mod tests;
