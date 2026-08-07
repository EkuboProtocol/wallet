//! The signing policy: an unordered set of rules over the calls a plan makes.
//!
//! A rule is a handful of optional [`Predicate`] slots — `to`, `from`, `value`,
//! `calldata` — and an effect. A slot left out constrains nothing; the slots
//! present are `AND`ed. There is no ordering and no precedence between rules of
//! the same effect, because the decision is a fold rather than a scan:
//!
//! * any matching `deny` rule denies,
//! * otherwise any matching `allow` rule allows,
//! * otherwise the call is denied.
//!
//! Deny beating allow unconditionally is what lets the rule set stay a *set*.
//! A first-match-wins list would make a rule's meaning depend on its position,
//! so inserting a permissive rule could silently shadow a restrictive one — and
//! the permission diff a human reviews before installing a policy could not
//! then be a diff of the document. Here it can: two rule sets differ exactly in
//! the rules one has and the other does not.
//!
//! Every predicate is still decided from the execution plan's own bytes plus
//! the local, human-curated stores in [`PolicyContext`]. Nothing the RPC
//! reports — observed balances, transfer logs, gas, or whether the simulation
//! succeeded — reaches a policy decision, so a dishonest endpoint cannot relax
//! a rule by misreporting what a transaction did.
//!
//! There are no amounts here. A per-transaction ceiling is not a spending limit
//! when the same agent may ask again immediately, so the format does not offer
//! one and no wording in it should imply otherwise. What a rule bounds is
//! *which* calls may be made, not how much they may move.

use crate::core::{
    execution_plan::ExecutionPlan,
    predicate::{PolicyContext, Predicate},
};
use alloy::{
    dyn_abi::{DynSolType, DynSolValue},
    primitives::{U256, keccak256},
};
use anyhow::{Context, Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, str::FromStr};

#[derive(
    Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// One rule: a conjunction of predicate slots and the effect of matching them.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The contract or recipient being called.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Predicate>,
    /// The sending wallet. Rarely needed — a plan's sender is already bound to
    /// the selected wallet before a policy ever sees it — but available so one
    /// document can carry rules for several wallets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Predicate>,
    /// Native value attached to this call, in wei.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Predicate>,
    /// The call's calldata. `{"eq": "0x"}` is a plain native send; a
    /// `selector` predicate decodes it and constrains its arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calldata: Option<Predicate>,
}

impl Rule {
    fn matches(&self, call: &Call, context: &PolicyContext) -> bool {
        self.to
            .as_ref()
            .is_none_or(|predicate| predicate.matches(&call.to, context))
            && self
                .from
                .as_ref()
                .is_none_or(|predicate| predicate.matches(&call.from, context))
            && self
                .value
                .as_ref()
                .is_none_or(|predicate| predicate.matches(&call.value, context))
            && self
                .calldata
                .as_ref()
                .is_none_or(|predicate| predicate.matches(&call.calldata, context))
    }

    fn validate(&self) -> Result<()> {
        validate_label(self.label.as_deref())?;
        for (slot, predicate, ty) in self.slots() {
            predicate
                .check_applicable(&ty)
                .with_context(|| format!("predicate on `{slot}` is not applicable"))?;
        }
        Ok(())
    }

    fn slots(&self) -> Vec<(&'static str, &Predicate, DynSolType)> {
        let mut slots = Vec::new();
        if let Some(predicate) = &self.to {
            slots.push(("to", predicate, DynSolType::Address));
        }
        if let Some(predicate) = &self.from {
            slots.push(("from", predicate, DynSolType::Address));
        }
        if let Some(predicate) = &self.value {
            slots.push(("value", predicate, DynSolType::Uint(256)));
        }
        if let Some(predicate) = &self.calldata {
            slots.push(("calldata", predicate, DynSolType::Bytes));
        }
        slots
    }

    /// True when every call this rule matches is also matched by `other`.
    /// Conservative: `false` means "cannot prove it", never "definitely not".
    #[must_use]
    pub fn is_narrower_than(&self, other: &Self) -> bool {
        fn slot_narrower(mine: Option<&Predicate>, theirs: Option<&Predicate>) -> bool {
            match (mine, theirs) {
                (_, None) => true,
                (None, Some(_)) => false,
                (Some(mine), Some(theirs)) => mine.is_narrower_than(theirs),
            }
        }
        self.effect == other.effect
            && slot_narrower(self.to.as_ref(), other.to.as_ref())
            && slot_narrower(self.from.as_ref(), other.from.as_ref())
            && slot_narrower(self.value.as_ref(), other.value.as_ref())
            && slot_narrower(self.calldata.as_ref(), other.calldata.as_ref())
    }

    /// One reviewable line describing the authority this rule grants or takes
    /// away. An unconstrained `calldata` slot is called out explicitly: a rule
    /// naming a target but nothing about what may be sent to it permits every
    /// function that target has, including any batching entry point that
    /// forwards to somewhere else entirely.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        parts.push(match &self.to {
            Some(predicate) => format!("to {}", predicate.describe()),
            None => "to any address".to_string(),
        });
        if let Some(predicate) = &self.from {
            parts.push(format!("from {}", predicate.describe()));
        }
        parts.push(match &self.calldata {
            Some(predicate) => predicate.describe(),
            None => "any calldata, including batched calls to other contracts".to_string(),
        });
        if let Some(predicate) = &self.value {
            parts.push(format!("native value {}", predicate.describe()));
        }
        let effect = match self.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        };
        let label = self
            .label
            .as_ref()
            .map_or_else(String::new, |label| format!(" [{label}]"));
        format!("{effect}{label}: {}", parts.join("; "))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default = "default_max_calls")]
    pub max_calls_per_batch: u32,
    /// Applied to every call independently, on top of whichever rule matched.
    /// A guard rather than a grant: no rule can widen it. Omitted, it is
    /// `{"eq": "0"}`, so a document that never mentions native value never
    /// sends any.
    #[serde(default = "no_native_value")]
    pub native_value: Predicate,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl ChainPolicy {
    /// The addresses this chain's rules name outright, so the approval review
    /// can pre-query their balances and show what a plan moved.
    ///
    /// Display only, and deliberately not a policy input: a token absent here
    /// is still governed by the rules, it just has no balance queried ahead of
    /// time. Tokens that actually move are picked up from the simulation's
    /// transfer logs regardless.
    #[must_use]
    pub fn named_addresses(&self) -> Vec<alloy::primitives::Address> {
        let mut literals = std::collections::BTreeSet::new();
        for rule in &self.rules {
            if let Some(predicate) = &rule.to {
                predicate.literals(&mut literals);
            }
        }
        literals
            .iter()
            .filter_map(|literal| alloy::primitives::Address::from_str(literal).ok())
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletPolicy {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default = "policy_version")]
    pub version: u8,
    pub chains: BTreeMap<String, ChainPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct PolicyFinding {
    pub severity: FindingSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<u32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

/// One call, in the value domain predicates speak.
struct Call {
    to: DynSolValue,
    from: DynSolValue,
    value: DynSolValue,
    calldata: DynSolValue,
}

impl Call {
    fn of(step: &crate::core::execution_plan::ExecutionStep) -> Self {
        Self {
            to: DynSolValue::Address(step.transaction.to),
            from: DynSolValue::Address(step.transaction.from),
            value: DynSolValue::Uint(step.transaction.value.value(), 256),
            calldata: DynSolValue::Bytes(step.transaction.data.to_vec()),
        }
    }
}

impl WalletPolicy {
    /// The canonical identity of this policy document: keccak-256 over its
    /// canonical JSON serialization. Every surface that names a policy reports
    /// this one digest, so two surfaces can never disagree about which policy
    /// is being discussed.
    pub fn digest(&self) -> Result<String> {
        let canonical = serde_json::to_vec(self).context("failed to serialize policy")?;
        Ok(format!("0x{}", hex::encode(keccak256(&canonical))))
    }

    pub fn parse(input: Value) -> Result<Self> {
        let mut policy: Self = serde_json::from_value(input).context("invalid wallet policy")?;
        policy.normalize_and_validate()?;
        Ok(policy)
    }

    /// Everything signs automatically: one rule constraining nothing, and no
    /// guard on native value. Kept byte-identical to
    /// `examples/policies/allow-all-with-approval.template.json` by test.
    #[must_use]
    pub fn allow_all_with_approval() -> Self {
        Self {
            schema: None,
            version: 1,
            chains: BTreeMap::from([(
                "*".into(),
                ChainPolicy {
                    label: Some(
                        "Allow all actions automatically; approve only policy or simulation failures"
                            .into(),
                    ),
                    max_calls_per_batch: 4096,
                    native_value: Predicate::AnyValue,
                    rules: vec![Rule {
                        effect: Effect::Allow,
                        label: Some("Every call, with any calldata and any native value".into()),
                        to: None,
                        from: None,
                        value: None,
                        calldata: None,
                    }],
                },
            )]),
        }
    }

    /// Nothing signs automatically: no rules at all, so every call falls to the
    /// default deny and queues for explicit human approval in the CLI. Kept
    /// byte-identical to `examples/policies/deny-all.json` by test.
    #[must_use]
    pub fn require_approval_for_everything() -> Self {
        Self {
            schema: None,
            version: 1,
            chains: BTreeMap::from([(
                "*".into(),
                ChainPolicy {
                    label: Some(
                        "Deny every automatic signature; each transaction needs an explicit CLI approval"
                            .into(),
                    ),
                    max_calls_per_batch: 1,
                    native_value: no_native_value(),
                    rules: Vec::new(),
                },
            )]),
        }
    }

    /// The rules for a chain: an exact entry, else the `"*"` fallback. An exact
    /// entry replaces the fallback rather than extending it.
    #[must_use]
    pub fn chain(&self, chain_id: &str) -> Option<&ChainPolicy> {
        self.chains.get(chain_id).or_else(|| self.chains.get("*"))
    }

    fn normalize_and_validate(&mut self) -> Result<()> {
        ensure!(
            self.version == 1,
            "policy document format version must be 1"
        );
        if let Some(url) = self.schema.as_deref() {
            url::Url::parse(url).context("invalid policy schema URL")?;
        }
        for (chain_id, chain) in &self.chains {
            validate_chain_key(chain_id)?;
            ensure!(
                chain.max_calls_per_batch > 0 && chain.max_calls_per_batch <= 4096,
                "max_calls_per_batch must be between 1 and 4096"
            );
            validate_label(chain.label.as_deref())?;
            chain
                .native_value
                .check_applicable(&DynSolType::Uint(256))
                .context("native_value predicate is not applicable")?;
            for rule in &chain.rules {
                rule.validate()
                    .with_context(|| format!("invalid rule on chain {chain_id}"))?;
            }
        }
        Ok(())
    }
}

/// Grade every call in `plan` against `policy`.
///
/// The signature is the whole interface: a plan, a policy, and the resolved
/// local metadata the policy may consult. Nothing else is in scope, and
/// `tests/boundary.rs` pins this so a future parameter has to be argued for
/// rather than added.
#[must_use]
pub fn evaluate_policy(
    plan: &ExecutionPlan,
    policy: &WalletPolicy,
    context: &PolicyContext,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    let Some(chain) = policy.chain(plan.chain_id.as_str()) else {
        findings.push(error(
            "chain_not_allowed",
            format!("chain {} has no policy", plan.chain_id),
            None,
        ));
        return findings;
    };
    if plan.ordered_steps.len() > chain.max_calls_per_batch as usize {
        findings.push(error(
            "too_many_calls",
            format!(
                "batch has {} calls; maximum is {} on chain {}",
                plan.ordered_steps.len(),
                chain.max_calls_per_batch,
                plan.chain_id
            ),
            None,
        ));
    }

    for step in &plan.ordered_steps {
        let call = Call::of(step);
        if !chain.native_value.matches(&call.value, context) {
            findings.push(error(
                "native_value_not_allowed",
                format!(
                    "native value {} is not permitted on chain {}; this chain allows {}",
                    step.transaction.value,
                    plan.chain_id,
                    chain.native_value.describe()
                ),
                Some(step.step),
            ));
        }
        // Deny wins, so every rule is consulted even once an allow has matched.
        let mut allowed = false;
        let mut denied: Option<&Rule> = None;
        for rule in &chain.rules {
            if !rule.matches(&call, context) {
                continue;
            }
            match rule.effect {
                Effect::Deny => denied = denied.or(Some(rule)),
                Effect::Allow => allowed = true,
            }
        }
        if let Some(rule) = denied {
            findings.push(error(
                CALL_DENIED_CODE,
                format!(
                    "step {} to {} is denied on chain {} by rule: {}",
                    step.step,
                    step.transaction.to,
                    plan.chain_id,
                    rule.describe()
                ),
                Some(step.step),
            ));
        } else if !allowed {
            findings.push(error(
                CALL_NOT_ALLOWED_CODE,
                format!(
                    "step {} to {} matches no rule on chain {}",
                    step.step, step.transaction.to, plan.chain_id
                ),
                Some(step.step),
            ));
        }
    }

    findings
}

#[must_use]
pub fn policy_allows(findings: &[PolicyFinding]) -> bool {
    findings
        .iter()
        .all(|finding| finding.severity != FindingSeverity::Error)
}

/// The code on the finding that records a failed simulation. It is the one
/// error finding that is not a policy decision, so preflight can separate
/// "the policy denied this" from "the simulation did not succeed" and require
/// an explicit human override for each.
pub const SIMULATION_FAILED_CODE: &str = "simulation_failed";

/// A `deny` rule matched this call.
pub const CALL_DENIED_CODE: &str = "call_denied";

/// No rule matched this call at all.
pub const CALL_NOT_ALLOWED_CODE: &str = "call_not_allowed";

/// What the policy decided, and therefore what happens next.
///
/// The distinction between the two negative outcomes is the whole point. A
/// `deny` rule is the owner having spoken; nothing at signing time may talk
/// them out of it, or the rule was decoration. Matching no rule is the owner
/// having said nothing, which is a question rather than a refusal, so it is
/// exactly the case a human may still answer at the terminal.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    /// Every call matched an `allow` rule and every guard was satisfied. This
    /// signs automatically, with no prompt.
    Allowed,
    /// Nothing in the policy covers some call. It cannot sign automatically,
    /// but a human may approve it in the CLI.
    RequiresApproval,
    /// A `deny` rule matched. Nothing signs it and nothing queues: the policy
    /// has to change first. There is no approval prompt for this outcome.
    Rejected,
}

/// Classify findings into the outcome that decides what happens next.
///
/// A failed simulation is deliberately not a policy outcome — it is a separate
/// precondition with its own override — so it does not make a policy that
/// otherwise allows a plan read as one that does not.
#[must_use]
pub fn policy_outcome(findings: &[PolicyFinding]) -> PolicyOutcome {
    let errors = || {
        findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Error)
    };
    if errors().any(|finding| finding.code == CALL_DENIED_CODE) {
        return PolicyOutcome::Rejected;
    }
    if errors().any(|finding| finding.code != SIMULATION_FAILED_CODE) {
        return PolicyOutcome::RequiresApproval;
    }
    PolicyOutcome::Allowed
}

/// The rules that refused, so a message can name what has to change rather
/// than telling the user only that "policy denied" it.
#[must_use]
pub fn denial_reasons(findings: &[PolicyFinding]) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| {
            finding.severity == FindingSeverity::Error && finding.code == CALL_DENIED_CODE
        })
        .map(|finding| finding.message.clone())
        .collect()
}

/// The JSON Schema for policy documents, derived from the enforced types so it
/// cannot drift from what the wallet actually accepts.
#[must_use]
pub fn json_schema() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(WalletPolicy))
        .expect("policy schema serializes");
    if let Some(object) = schema.as_object_mut() {
        object.insert("title".into(), Value::String("Ekubo Wallet policy".into()));
        object.insert(
            "description".into(),
            Value::String(
                "Stateless per-call signing policy. Each chain holds an unordered set of rules: \
                 any matching deny rule denies, otherwise any matching allow rule allows, \
                 otherwise the call is denied. There are no amount limits, budgets, or spend \
                 counters — a rule bounds which calls may be made, not how much they move."
                    .into(),
            ),
        );
    }
    schema
}

/// A minimized, human-readable diff of what the proposed policy permits
/// relative to the current one, so a reviewer reads the signing authority they
/// are about to add or remove rather than comparing JSON documents.
///
/// Because rules form a set under deny-precedence, this is a set difference. A
/// rule that disappears is only reported as a loss when nothing remaining
/// subsumes it; when something does, it is reported as still covered, since
/// telling a reviewer they are tightening while they approve the opposite is
/// the failure mode this function exists to avoid.
#[must_use]
pub fn diff_policies(current: &WalletPolicy, proposed: &WalletPolicy) -> Vec<String> {
    let mut lines = Vec::new();
    let chain_keys: std::collections::BTreeSet<&String> = current
        .chains
        .keys()
        .chain(proposed.chains.keys())
        .collect();
    for key in chain_keys {
        let label = if key == "*" { "every chain (*)" } else { key };
        match (current.chains.get(key), proposed.chains.get(key)) {
            (None, Some(next)) => {
                lines.push(format!(
                    "+ chain {label}: now governed, up to {} call(s) per batch, native value {}",
                    next.max_calls_per_batch,
                    next.native_value.describe()
                ));
                for rule in &next.rules {
                    lines.push(format!("+ chain {label}: {}", rule.describe()));
                }
            }
            (Some(previous), None) => {
                if let Some(fallback) = (key != "*").then(|| proposed.chains.get("*")).flatten() {
                    lines.push(format!(
                        "~ chain {label}: loses its own rules and falls back to every chain (*)"
                    ));
                    for rule in &fallback.rules {
                        lines.push(format!(
                            "~ chain {label}: now covered by (*): {}",
                            rule.describe()
                        ));
                    }
                } else {
                    for rule in &previous.rules {
                        lines.push(format!("- chain {label}: {}", rule.describe()));
                    }
                }
            }
            (Some(previous), Some(next)) if previous != next => {
                diff_chain(&mut lines, label, previous, next);
            }
            _ => {}
        }
    }
    if lines.is_empty() {
        lines.push("No permission changes: the proposed policy is identical.".into());
    }
    lines
}

fn diff_chain(lines: &mut Vec<String>, label: &str, previous: &ChainPolicy, next: &ChainPolicy) {
    if previous.max_calls_per_batch != next.max_calls_per_batch {
        lines.push(format!(
            "~ chain {label}: calls per batch {} → {}",
            previous.max_calls_per_batch, next.max_calls_per_batch
        ));
    }
    if previous.native_value != next.native_value {
        lines.push(format!(
            "~ chain {label}: native value per call {} → {}",
            previous.native_value.describe(),
            next.native_value.describe()
        ));
    }
    for rule in &next.rules {
        if !previous.rules.contains(rule) {
            lines.push(format!("+ chain {label}: {}", rule.describe()));
        }
    }
    for rule in &previous.rules {
        if next.rules.contains(rule) {
            continue;
        }
        if let Some(cover) = next
            .rules
            .iter()
            .find(|candidate| rule.is_narrower_than(candidate))
        {
            lines.push(format!(
                "~ chain {label}: {} is still covered by: {}",
                rule.describe(),
                cover.describe()
            ));
        } else {
            lines.push(format!("- chain {label}: {}", rule.describe()));
        }
    }
}

fn error(code: &str, message: String, step: Option<u32>) -> PolicyFinding {
    PolicyFinding {
        severity: FindingSeverity::Error,
        code: code.into(),
        message,
        step,
    }
}

fn validate_chain_key(value: &str) -> Result<()> {
    if value == "*" {
        return Ok(());
    }
    // `all` over no bytes is vacuously true, so emptiness is checked first or
    // "" reads as a valid chain and quietly governs nothing.
    ensure!(
        value == "0"
            || (!value.is_empty()
                && !value.starts_with('0')
                && value.bytes().all(|b| b.is_ascii_digit())),
        "invalid chain policy key {value}"
    );
    U256::from_str(value).context("chain policy key must fit uint256")?;
    Ok(())
}

fn validate_label(value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        let length = value.chars().count();
        ensure!(
            length > 0 && length <= 160,
            "labels must contain 1-160 characters"
        );
    }
    Ok(())
}

fn no_native_value() -> Predicate {
    Predicate::Eq("0".into())
}

const fn policy_version() -> u8 {
    1
}

const fn default_max_calls() -> u32 {
    16
}

#[cfg(test)]
#[path = "policy_test.rs"]
mod tests;
