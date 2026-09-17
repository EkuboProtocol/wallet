//! Display-only automation results. They carry no signing authority.

use chrono::{DateTime, Utc};
use ekubo_wallet_core::automation::PolledCall;

/// What an automation would do if it ticked right now.
///
/// Display-only. It carries no plan, no simulation handle, and nothing else
/// that could be sent: an owner reading a dry run is reading a report, and the
/// only way anything here reaches a chain is the automation's own next tick.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AutomationDryRun {
    pub ran_at: DateTime<Utc>,
    /// The block the poll observed, absent when the poll never ran.
    pub block_number: Option<u64>,
    /// Why the bytecode produced nothing readable: a revert, an undecodable
    /// return value, or an endpoint that could not be reached.
    pub failure: Option<String>,
    /// Empty is the healthy idle tick, not an error.
    pub calls: Vec<PolledCall>,
    /// Absent when there were no calls to judge.
    pub verdict: Option<AutomationDryRunVerdict>,
}

/// Whether the calls a dry run produced would actually have sent.
///
/// The question an owner asks of an automation is not "does the bytecode run"
/// but "would anything come of it", and those have different answers whenever
/// the policy moved after the automation was written.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AutomationDryRunVerdict {
    pub policy_revision: u64,
    /// True only when the policy allowed every call and the simulation
    /// succeeded — the exact condition a tick sends under.
    pub sends_automatically: bool,
    pub simulation_succeeded: bool,
    pub simulation_failure: Option<String>,
    pub findings: Vec<String>,
}
