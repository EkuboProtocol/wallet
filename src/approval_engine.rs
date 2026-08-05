//! Centralized approval decision engine.
//!
//! Consolidates policy evaluation, summary generation, and approval request assembly.
//! This module serves as the single point of truth for how execution plans are evaluated
//! and presented to users for approval.

use crate::{
    approval::{ApprovalKind, ApprovalRequest},
    approval_summary::TokenMetadataMap,
    config::NetworkConfig,
    core::{execution_plan::ExecutionPlan, policy::WalletPolicy},
    simulation::SimulationResult,
};
use anyhow::Result;

/// A policy evaluation result with the approval context.
#[derive(Clone, Debug)]
pub struct ApprovalContext {
    /// Whether the policy allows this action without exception review.
    pub allowed: bool,
    /// Human-readable policy findings explaining why or why not.
    pub findings: Vec<String>,
}

/// Evaluate an execution plan against a policy.
///
/// This function centralizes all policy decision logic. It returns an
/// `ApprovalContext` that indicates whether the plan is permitted and any
/// findings that should be displayed to the user.
pub fn evaluate_plan(
    _plan: &ExecutionPlan,
    _policy: &WalletPolicy,
    _network: &NetworkConfig,
    simulation: &SimulationResult,
) -> ApprovalContext {
    // The simulation result carries the policy evaluation result
    let allowed = simulation.allowed;
    let findings = simulation
        .policy_findings
        .iter()
        .map(|f| f.message.clone())
        .collect();

    ApprovalContext { allowed, findings }
}

/// Generate an approval request from a simulation result and token metadata.
///
/// Consolidates approval request assembly with title, summary, and facts
/// derived from the plan's simulation and metadata.
pub fn build_approval_request(
    kind: ApprovalKind,
    plan: &ExecutionPlan,
    simulation: &SimulationResult,
    _token_metadata: &TokenMetadataMap,
) -> Result<ApprovalRequest> {
    let mut request = ApprovalRequest::new(
        kind,
        format!("{:?} Request", kind),
        format!("Executing {:?} with {} step(s)", kind, plan.ordered_steps.len()),
    );

    // Add plan-specific facts
    request = request.fact("Steps", plan.ordered_steps.len().to_string());

    // Add simulation findings if any
    for finding in &simulation.policy_findings {
        request = request.warning(finding.message.clone());
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_context_represents_allowed_state() {
        let ctx = ApprovalContext {
            allowed: true,
            findings: vec![],
        };
        assert!(ctx.allowed);
        assert_eq!(ctx.findings.len(), 0);
    }

    #[test]
    fn approval_context_captures_findings() {
        let ctx = ApprovalContext {
            allowed: false,
            findings: vec!["Something went wrong".to_owned()],
        };
        assert!(!ctx.allowed);
        assert_eq!(ctx.findings.len(), 1);
    }
}
