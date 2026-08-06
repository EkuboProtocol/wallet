use crate::core::execution_plan::ExecutionPlan;
use alloy::primitives::{Address, U256, keccak256};
use anyhow::{Context, Result, bail, ensure};
use num_bigint::BigUint;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    str::FromStr,
};

const MAX_UINT256: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedAddressPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SelectorPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub allow_empty_calldata: bool,
    #[serde(default)]
    pub allow_any_calldata: bool,
    #[serde(default)]
    pub allowed_selectors: BTreeMap<String, SelectorPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTokenPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default = "max_uint256")]
    pub max_amount: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSpenderPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub tokens: BTreeMap<String, ApprovalTokenPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TokenPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default = "zero")]
    pub max_spend_per_transaction: String,
    #[serde(default)]
    pub transfer_recipients: BTreeMap<String, NamedAddressPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativePolicy {
    #[serde(default = "zero")]
    pub max_value_per_transaction: String,
}

impl Default for NativePolicy {
    fn default() -> Self {
        Self {
            max_value_per_transaction: zero(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default = "default_max_calls")]
    pub max_calls_per_batch: u32,
    #[serde(default)]
    pub native: NativePolicy,
    #[serde(default)]
    pub targets: BTreeMap<String, TargetPolicy>,
    #[serde(default)]
    pub approval_spenders: BTreeMap<String, ApprovalSpenderPolicy>,
    #[serde(default)]
    pub tokens: BTreeMap<String, TokenPolicy>,
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

pub type TokenSpends = BTreeMap<String, BigUint>;

impl WalletPolicy {
    /// The canonical identity of this policy document: keccak-256 over its
    /// canonical JSON serialization. Every surface that names a policy —
    /// validation output, proposal review, replacement review — reports this
    /// one digest, so two surfaces can never disagree about which policy is
    /// being discussed.
    pub fn digest(&self) -> Result<String> {
        let canonical = serde_json::to_vec(self).context("failed to serialize policy")?;
        Ok(format!("0x{}", hex::encode(keccak256(&canonical))))
    }

    pub fn parse(input: Value) -> Result<Self> {
        let mut policy: Self = serde_json::from_value(drop_retired_settings(input))
            .context("invalid wallet policy")?;
        policy.normalize_and_validate()?;
        Ok(policy)
    }

    #[must_use]
    pub fn allow_all_with_approval() -> Self {
        let mut chains = BTreeMap::new();
        chains.insert(
            "*".into(),
            ChainPolicy {
                label: Some(
                    "Allow all actions automatically; approve only policy or simulation failures"
                        .into(),
                ),
                max_calls_per_batch: 4096,
                native: NativePolicy {
                    max_value_per_transaction: max_uint256(),
                },
                targets: BTreeMap::from([(
                    "*".into(),
                    TargetPolicy {
                        allow_empty_calldata: true,
                        allow_any_calldata: true,
                        ..TargetPolicy::default()
                    },
                )]),
                approval_spenders: BTreeMap::from([(
                    "*".into(),
                    ApprovalSpenderPolicy {
                        label: None,
                        tokens: BTreeMap::from([(
                            "*".into(),
                            ApprovalTokenPolicy {
                                label: None,
                                max_amount: max_uint256(),
                            },
                        )]),
                    },
                )]),
                tokens: BTreeMap::from([(
                    "*".into(),
                    TokenPolicy {
                        label: None,
                        max_spend_per_transaction: max_uint256(),
                        transfer_recipients: BTreeMap::from([(
                            "*".into(),
                            NamedAddressPolicy { label: None },
                        )]),
                    },
                )]),
            },
        );
        Self {
            schema: None,
            version: 2,
            chains,
        }
    }

    /// The profile in which nothing signs automatically: no targets, tokens,
    /// spenders, or native value are permitted on any chain, so every
    /// transaction queues for explicit human approval in the CLI. Kept
    /// byte-identical to `examples/policies/deny-all.json` by test.
    #[must_use]
    pub fn require_approval_for_everything() -> Self {
        let chains = BTreeMap::from([(
            "*".to_string(),
            ChainPolicy {
                label: Some(
                    "Deny every automatic signature; each transaction needs an explicit CLI approval"
                        .into(),
                ),
                max_calls_per_batch: 1,
                native: NativePolicy {
                    max_value_per_transaction: zero(),
                },
                targets: BTreeMap::new(),
                approval_spenders: BTreeMap::new(),
                tokens: BTreeMap::new(),
            },
        )]);
        Self {
            schema: None,
            version: 2,
            chains,
        }
    }

    #[must_use]
    pub fn chain(&self, chain_id: &str) -> Option<&ChainPolicy> {
        self.chains.get(chain_id).or_else(|| self.chains.get("*"))
    }

    fn normalize_and_validate(&mut self) -> Result<()> {
        ensure!(
            self.version == 2,
            "policy document format version must be 2"
        );
        validate_url(self.schema.as_deref())?;
        let mut chains = BTreeMap::new();
        for (chain_id, mut chain) in std::mem::take(&mut self.chains) {
            validate_chain_key(&chain_id)?;
            ensure!(
                chain.max_calls_per_batch > 0 && chain.max_calls_per_batch <= 4096,
                "max_calls_per_batch must be between 1 and 4096"
            );
            validate_label(chain.label.as_deref())?;
            validate_decimal(&chain.native.max_value_per_transaction)?;
            normalize_target_map(&mut chain.targets)?;
            normalize_spender_map(&mut chain.approval_spenders)?;
            normalize_token_map(&mut chain.tokens)?;
            ensure!(
                chains.insert(chain_id, chain).is_none(),
                "duplicate chain policy"
            );
        }
        self.chains = chains;
        Ok(())
    }
}

#[must_use]
pub fn evaluate_policy(
    plan: &ExecutionPlan,
    policy: &WalletPolicy,
    token_spends: Option<&TokenSpends>,
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
    let total_value = plan
        .ordered_steps
        .iter()
        .map(|step| BigUint::from_str(step.transaction.value.as_str()).unwrap())
        .sum::<BigUint>();
    if exceeds_limit(&total_value, &chain.native.max_value_per_transaction) {
        findings.push(error(
            "native_value_limit",
            format!(
                "native value {total_value} exceeds {} on chain {}",
                chain.native.max_value_per_transaction, plan.chain_id
            ),
            None,
        ));
    }

    for step in &plan.ordered_steps {
        let target = key(step.transaction.to);
        let data = step.transaction.data.as_ref();
        if data.is_empty() {
            let rule = exact_or_wildcard(&chain.targets, &target);
            if !rule.is_some_and(|rule| rule.allow_empty_calldata) {
                findings.push(error(
                    "target_not_allowed",
                    format!(
                        "{} does not permit empty calldata on chain {}",
                        step.transaction.to, plan.chain_id
                    ),
                    Some(step.step),
                ));
            }
            continue;
        }
        if data.len() >= 68 && data[..4] == [0x09, 0x5e, 0xa7, 0xb3] {
            let spender = Address::from_slice(&data[16..36]);
            let amount = U256::from_be_slice(&data[36..68]);
            evaluate_approval(
                chain,
                step.transaction.to,
                spender,
                amount,
                plan.chain_id.as_str(),
                Some(step.step),
                &mut findings,
            );
        } else if data.len() >= 68 && data[..4] == [0xa9, 0x05, 0x9c, 0xbb] {
            let recipient = Address::from_slice(&data[16..36]);
            let amount = U256::from_be_slice(&data[36..68]);
            evaluate_transfer(
                chain,
                step.transaction.to,
                recipient,
                amount,
                plan,
                step.step,
                &mut findings,
            );
        } else {
            let selector = if data.len() >= 4 {
                format!("0x{}", hex::encode(&data[..4]))
            } else {
                format!("0x{}", hex::encode(data))
            };
            evaluate_target_calldata(
                chain,
                step.transaction.to,
                &selector,
                plan,
                step.step,
                &mut findings,
            );
        }
    }

    let mut evaluated = BTreeSet::<String>::new();
    for (token, rule) in &chain.tokens {
        if token == "*" {
            continue;
        }
        let observed = token_spends.and_then(|spends| find_spend(spends, token));
        let Some(observed) = observed else {
            findings.push(error(
                "token_spend_not_measured",
                format!(
                    "{token} spend was not measured during simulation on chain {}",
                    plan.chain_id
                ),
                None,
            ));
            continue;
        };
        evaluated.insert(token.clone());
        if exceeds_limit(observed, &rule.max_spend_per_transaction) {
            findings.push(error(
                "token_spend_limit",
                format!(
                    "{token} observed spend {observed} exceeds {} on chain {}",
                    rule.max_spend_per_transaction, plan.chain_id
                ),
                None,
            ));
        }
    }
    for (token, observed) in token_spends.into_iter().flatten() {
        let normalized = normalize_address(token).unwrap_or_else(|_| token.to_ascii_lowercase());
        if evaluated.contains(&normalized) {
            continue;
        }
        let Some(rule) = exact_or_wildcard(&chain.tokens, &normalized) else {
            findings.push(error(
                "token_spend_not_allowed",
                format!(
                    "{normalized} has observed spend but no token policy on chain {}",
                    plan.chain_id
                ),
                None,
            ));
            continue;
        };
        if exceeds_limit(observed, &rule.max_spend_per_transaction) {
            findings.push(error(
                "token_spend_limit",
                format!(
                    "{normalized} observed spend {observed} exceeds {} on chain {}",
                    rule.max_spend_per_transaction, plan.chain_id
                ),
                None,
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

/// True when the findings carry a policy denial: any error finding other than
/// the simulation-failure record. Contrast [`policy_allows`], which treats
/// every error finding, simulation failure included, as blocking the
/// automatic path.
#[must_use]
pub fn policy_denies(findings: &[PolicyFinding]) -> bool {
    findings.iter().any(|finding| {
        finding.severity == FindingSeverity::Error && finding.code != SIMULATION_FAILED_CODE
    })
}

fn evaluate_approval(
    chain: &ChainPolicy,
    token: Address,
    spender: Address,
    amount: U256,
    chain_id: &str,
    step: Option<u32>,
    findings: &mut Vec<PolicyFinding>,
) {
    let spender_key = key(spender);
    let Some(spender_rule) = exact_or_wildcard(&chain.approval_spenders, &spender_key) else {
        findings.push(error(
            "approval_spender_not_allowed",
            format!("{spender} is not an allowed approval spender on chain {chain_id}"),
            step,
        ));
        return;
    };
    let token_key = key(token);
    let Some(token_rule) = exact_or_wildcard(&spender_rule.tokens, &token_key) else {
        findings.push(error(
            "approval_token_not_allowed",
            format!("{spender} may not receive approvals for token {token} on chain {chain_id}"),
            step,
        ));
        return;
    };
    let amount = BigUint::from_bytes_be(&amount.to_be_bytes::<32>());
    if exceeds_limit(&amount, &token_rule.max_amount) {
        findings.push(error(
            "approval_amount_limit",
            format!(
                "{token} approval {amount} exceeds {} for {spender} on chain {chain_id}",
                token_rule.max_amount
            ),
            step,
        ));
    }
}

fn evaluate_transfer(
    chain: &ChainPolicy,
    token: Address,
    recipient: Address,
    amount: U256,
    plan: &ExecutionPlan,
    step: u32,
    findings: &mut Vec<PolicyFinding>,
) {
    let token_key = key(token);
    let Some(rule) = exact_or_wildcard(&chain.tokens, &token_key) else {
        findings.push(error(
            "token_not_configured",
            format!("{token} has no token policy on chain {}", plan.chain_id),
            Some(step),
        ));
        return;
    };
    let recipient_key = key(recipient);
    if exact_or_wildcard(&rule.transfer_recipients, &recipient_key).is_none() {
        findings.push(error(
            "transfer_recipient_not_allowed",
            format!(
                "{recipient} is not an allowed recipient for {token} on chain {}",
                plan.chain_id
            ),
            Some(step),
        ));
    }
    // The spend checked after simulation is whatever the token reported about
    // itself, through its balance or its logs. A direct transfer also states
    // its amount in calldata, which is the one number the token contract does
    // not author, so the limit is enforced against that too. For a token
    // covered only by a `*` rule this is the sole spend check there is: the
    // wildcard is excluded from balance probes, and a token that emits no
    // canonical Transfer log produces no observation to evaluate.
    let declared = BigUint::from_bytes_be(&amount.to_be_bytes::<32>());
    if exceeds_limit(&declared, &rule.max_spend_per_transaction) {
        findings.push(error(
            "token_spend_limit",
            format!(
                "{token} transfer of {declared} exceeds {} on chain {}",
                rule.max_spend_per_transaction, plan.chain_id
            ),
            Some(step),
        ));
    }
}

fn evaluate_target_calldata(
    chain: &ChainPolicy,
    target: Address,
    selector: &str,
    plan: &ExecutionPlan,
    step: u32,
    findings: &mut Vec<PolicyFinding>,
) {
    let target_key = key(target);
    let Some(rule) = exact_or_wildcard(&chain.targets, &target_key) else {
        findings.push(error(
            "target_not_allowed",
            format!(
                "{target} is not an allowed target on chain {}",
                plan.chain_id
            ),
            Some(step),
        ));
        return;
    };
    if !rule.allow_any_calldata
        && !rule
            .allowed_selectors
            .contains_key(&selector.to_ascii_lowercase())
    {
        findings.push(error(
            "selector_not_allowed",
            format!(
                "{} is not allowed at {target} on chain {}",
                selector.to_ascii_lowercase(),
                plan.chain_id
            ),
            Some(step),
        ));
    }
}

/// The JSON Schema for policy documents, derived from the enforced types so
/// it cannot drift from what the wallet actually accepts.
#[must_use]
pub fn json_schema() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(WalletPolicy))
        .expect("policy schema serializes");
    if let Some(object) = schema.as_object_mut() {
        object.insert("title".into(), Value::String("Ekubo Wallet policy".into()));
        object.insert(
            "description".into(),
            Value::String(
                "Stateless per-transaction signing policy. Amounts are decimal strings in the \
                 asset's smallest unit. There are no daily limits, rolling windows, or spend \
                 counters."
                    .into(),
            ),
        );
    }
    schema
}

/// A minimized, human-readable diff of what the proposed policy permits
/// relative to the current one. Each line is one permission-level change,
/// prefixed `+` (granted), `-` (removed), or `~` (changed), so a reviewer
/// reads exactly what signing authority they are about to add or take away
/// without comparing JSON documents.
#[must_use]
pub fn diff_policies(current: &WalletPolicy, proposed: &WalletPolicy) -> Vec<String> {
    let mut lines = Vec::new();
    let chain_keys: BTreeSet<&String> = current
        .chains
        .keys()
        .chain(proposed.chains.keys())
        .collect();
    for key in chain_keys {
        let label = if key == "*" { "every chain (*)" } else { key };
        match (current.chains.get(key), proposed.chains.get(key)) {
            (None, Some(next)) => {
                for grant in chain_grants(next) {
                    lines.push(format!("+ chain {label}: {grant}"));
                }
            }
            (Some(previous), None) => {
                if let Some(fallback) = wildcard_successor(&proposed.chains, key) {
                    lines.push(format!(
                        "~ chain {label}: loses its own rules and falls back to every chain (*)"
                    ));
                    for grant in chain_grants(fallback) {
                        lines.push(format!("~ chain {label}: now covered by (*): {grant}"));
                    }
                } else {
                    for grant in chain_grants(previous) {
                        lines.push(format!("- chain {label}: {grant}"));
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

fn amount_text(value: &str) -> String {
    if value == MAX_UINT256 {
        "unlimited".into()
    } else {
        value.into()
    }
}

fn target_grant(target: &str, rule: &TargetPolicy) -> String {
    let mut parts = Vec::new();
    if rule.allow_any_calldata {
        parts.push("any calldata".to_string());
    } else if !rule.allowed_selectors.is_empty() {
        parts.push(format!(
            "selectors {}",
            rule.allowed_selectors
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if rule.allow_empty_calldata {
        parts.push("empty calldata (plain native sends)".to_string());
    }
    if parts.is_empty() {
        parts.push("no calldata".to_string());
    }
    format!("call target {target}: {}", parts.join("; "))
}

fn spender_grant(spender: &str, token: &str, rule: &ApprovalTokenPolicy) -> String {
    format!(
        "approvals to spender {spender} for token {token}: up to {}",
        amount_text(&rule.max_amount)
    )
}

fn token_grant(token: &str, rule: &TokenPolicy) -> String {
    let recipients = if rule.transfer_recipients.is_empty() {
        "no transfer recipients".to_string()
    } else {
        format!(
            "transfer recipients {}",
            rule.transfer_recipients
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    format!(
        "token {token}: spend up to {} per transaction; {recipients}",
        amount_text(&rule.max_spend_per_transaction)
    )
}

/// Every permission one chain policy grants, as standalone lines.
fn chain_grants(chain: &ChainPolicy) -> Vec<String> {
    let mut grants = Vec::new();
    if chain.native.max_value_per_transaction != "0" {
        grants.push(format!(
            "native value up to {} wei per transaction",
            amount_text(&chain.native.max_value_per_transaction)
        ));
    }
    grants.push(format!(
        "up to {} call(s) per batch",
        chain.max_calls_per_batch
    ));
    for (target, rule) in &chain.targets {
        grants.push(target_grant(target, rule));
    }
    for (spender, rule) in &chain.approval_spenders {
        for (token, token_rule) in &rule.tokens {
            grants.push(spender_grant(spender, token, token_rule));
        }
    }
    for (token, rule) in &chain.tokens {
        grants.push(token_grant(token, rule));
    }
    grants
}

fn diff_chain(lines: &mut Vec<String>, label: &str, previous: &ChainPolicy, next: &ChainPolicy) {
    if previous.native.max_value_per_transaction != next.native.max_value_per_transaction {
        lines.push(format!(
            "~ chain {label}: native value per transaction {} → {}",
            amount_text(&previous.native.max_value_per_transaction),
            amount_text(&next.native.max_value_per_transaction),
        ));
    }
    if previous.max_calls_per_batch != next.max_calls_per_batch {
        lines.push(format!(
            "~ chain {label}: calls per batch {} → {}",
            previous.max_calls_per_batch, next.max_calls_per_batch
        ));
    }

    let targets: BTreeSet<&String> = previous.targets.keys().chain(next.targets.keys()).collect();
    for target in targets {
        match (previous.targets.get(target), next.targets.get(target)) {
            (None, Some(rule)) => {
                lines.push(format!("+ chain {label}: {}", target_grant(target, rule)));
            }
            (Some(rule), None) => {
                if let Some(fallback) = wildcard_successor(&next.targets, target) {
                    lines.push(format!(
                        "~ chain {label}: target {target} falls back to (*): {}",
                        target_grant("*", fallback)
                    ));
                } else {
                    lines.push(format!("- chain {label}: {}", target_grant(target, rule)));
                }
            }
            (Some(old), Some(new)) if old != new => lines.push(format!(
                "~ chain {label}: {} (was: {})",
                target_grant(target, new),
                target_grant(target, old),
            )),
            _ => {}
        }
    }

    let spenders: BTreeSet<&String> = previous
        .approval_spenders
        .keys()
        .chain(next.approval_spenders.keys())
        .collect();
    for spender in spenders {
        let old_tokens = previous
            .approval_spenders
            .get(spender)
            .map(|rule| &rule.tokens);
        let new_tokens = next.approval_spenders.get(spender).map(|rule| &rule.tokens);
        let tokens: BTreeSet<&String> = old_tokens
            .into_iter()
            .flat_map(BTreeMap::keys)
            .chain(new_tokens.into_iter().flat_map(BTreeMap::keys))
            .collect();
        for token in tokens {
            let old = old_tokens.and_then(|tokens| tokens.get(token));
            let new = new_tokens.and_then(|tokens| tokens.get(token));
            match (old, new) {
                (None, Some(rule)) => {
                    lines.push(format!(
                        "+ chain {label}: {}",
                        spender_grant(spender, token, rule)
                    ));
                }
                (Some(rule), None) => {
                    // A token entry can lose its own rule two ways: the `*`
                    // token under the same spender takes over, or the spender
                    // itself disappears and the `*` spender takes over. Both
                    // resolve through `exact_or_wildcard`, so both widen.
                    let successor = new_tokens
                        .and_then(|tokens| wildcard_successor(tokens, token))
                        .or_else(|| {
                            wildcard_successor(&next.approval_spenders, spender)
                                .and_then(|fallback| exact_or_wildcard(&fallback.tokens, token))
                        });
                    if let Some(fallback) = successor {
                        lines.push(format!(
                            "~ chain {label}: {} falls back to {}",
                            spender_grant(spender, token, rule),
                            spender_grant("*", "*", fallback)
                        ));
                    } else {
                        lines.push(format!(
                            "- chain {label}: {}",
                            spender_grant(spender, token, rule)
                        ));
                    }
                }
                (Some(old), Some(new)) if old.max_amount != new.max_amount => {
                    lines.push(format!(
                        "~ chain {label}: approvals to spender {spender} for token {token}: up to {} (was {})",
                        amount_text(&new.max_amount),
                        amount_text(&old.max_amount),
                    ));
                }
                _ => {}
            }
        }
    }

    let tokens: BTreeSet<&String> = previous.tokens.keys().chain(next.tokens.keys()).collect();
    for token in tokens {
        match (previous.tokens.get(token), next.tokens.get(token)) {
            (None, Some(rule)) => {
                lines.push(format!("+ chain {label}: {}", token_grant(token, rule)));
            }
            (Some(rule), None) => {
                if let Some(fallback) = wildcard_successor(&next.tokens, token) {
                    lines.push(format!(
                        "~ chain {label}: token {token} falls back to (*): {}",
                        token_grant("*", fallback)
                    ));
                } else {
                    lines.push(format!("- chain {label}: {}", token_grant(token, rule)));
                }
            }
            (Some(old), Some(new)) if old != new => {
                if old.max_spend_per_transaction != new.max_spend_per_transaction {
                    lines.push(format!(
                        "~ chain {label}: token {token} spend per transaction {} → {}",
                        amount_text(&old.max_spend_per_transaction),
                        amount_text(&new.max_spend_per_transaction),
                    ));
                }
                let recipients: BTreeSet<&String> = old
                    .transfer_recipients
                    .keys()
                    .chain(new.transfer_recipients.keys())
                    .collect();
                for recipient in recipients {
                    match (
                        old.transfer_recipients.contains_key(recipient),
                        new.transfer_recipients.contains_key(recipient),
                    ) {
                        (false, true) => lines.push(format!(
                            "+ chain {label}: token {token} may transfer to {recipient}"
                        )),
                        (true, false) => {
                            if wildcard_successor(&new.transfer_recipients, recipient).is_some() {
                                lines.push(format!(
                                    "~ chain {label}: token {token} recipient {recipient} falls \
                                     back to (*), which permits any recipient"
                                ));
                            } else {
                                lines.push(format!(
                                    "- chain {label}: token {token} may transfer to {recipient}"
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Discard settings this format no longer has, so a wallet whose stored policy
/// predates their removal still opens after an upgrade.
///
/// `require_simulation`: every plan is simulated now and a simulation that does
/// not succeed always denies, so the field has nothing left to select and is
/// dropped whichever way it was set.
///
/// `approval_expiry_seconds`, top-level and per chain: a queued request no
/// longer expires. Nothing in this wallet decides what may be signed by reading
/// the local clock, which a machine's owner — or anything running as them — can
/// set to whatever they like. A request that must not execute after some moment
/// says so in the transaction it authorizes, where the chain enforces it.
fn drop_retired_settings(mut input: Value) -> Value {
    if let Some(object) = input.as_object_mut() {
        object.remove("require_simulation");
        object.remove("approval_expiry_seconds");
        if let Some(chains) = object.get_mut("chains").and_then(Value::as_object_mut) {
            for chain in chains.values_mut() {
                if let Some(chain) = chain.as_object_mut() {
                    chain.remove("approval_expiry_seconds");
                }
            }
        }
    }
    input
}

fn error(code: &str, message: String, step: Option<u32>) -> PolicyFinding {
    PolicyFinding {
        severity: FindingSeverity::Error,
        code: code.into(),
        message,
        step,
    }
}

fn normalize_target_map(map: &mut BTreeMap<String, TargetPolicy>) -> Result<()> {
    let mut output = BTreeMap::new();
    for (raw, mut rule) in std::mem::take(map) {
        validate_label(rule.label.as_deref())?;
        let mut selectors = BTreeMap::new();
        for (selector, label) in std::mem::take(&mut rule.allowed_selectors) {
            ensure!(
                selector.len() == 10
                    && selector.starts_with("0x")
                    && selector[2..].bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid four-byte selector {selector}"
            );
            validate_label(label.label.as_deref())?;
            ensure!(
                selectors
                    .insert(selector.to_ascii_lowercase(), label)
                    .is_none(),
                "duplicate selector"
            );
        }
        rule.allowed_selectors = selectors;
        insert_unique(&mut output, normalize_address_or_wildcard(&raw)?, rule)?;
    }
    *map = output;
    Ok(())
}

fn normalize_spender_map(map: &mut BTreeMap<String, ApprovalSpenderPolicy>) -> Result<()> {
    let mut output = BTreeMap::new();
    for (raw, mut rule) in std::mem::take(map) {
        validate_label(rule.label.as_deref())?;
        let mut tokens = BTreeMap::new();
        for (token, token_rule) in rule.tokens {
            validate_label(token_rule.label.as_deref())?;
            validate_decimal(&token_rule.max_amount)?;
            insert_unique(
                &mut tokens,
                normalize_address_or_wildcard(&token)?,
                token_rule,
            )?;
        }
        rule.tokens = tokens;
        insert_unique(&mut output, normalize_address_or_wildcard(&raw)?, rule)?;
    }
    *map = output;
    Ok(())
}

fn normalize_token_map(map: &mut BTreeMap<String, TokenPolicy>) -> Result<()> {
    let mut output = BTreeMap::new();
    for (raw, mut rule) in std::mem::take(map) {
        validate_label(rule.label.as_deref())?;
        validate_decimal(&rule.max_spend_per_transaction)?;
        let mut recipients = BTreeMap::new();
        for (recipient, recipient_rule) in rule.transfer_recipients {
            validate_label(recipient_rule.label.as_deref())?;
            insert_unique(
                &mut recipients,
                normalize_address_or_wildcard(&recipient)?,
                recipient_rule,
            )?;
        }
        rule.transfer_recipients = recipients;
        insert_unique(&mut output, normalize_address_or_wildcard(&raw)?, rule)?;
    }
    *map = output;
    Ok(())
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    match map.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(())
        }
        Entry::Occupied(entry) => {
            bail!("duplicate normalized policy key {}", entry.key())
        }
    }
}

fn exact_or_wildcard<'a, T>(map: &'a BTreeMap<String, T>, key: &str) -> Option<&'a T> {
    map.get(key).or_else(|| map.get("*"))
}

/// The rule a removed key would resolve to instead, if any.
///
/// Every lookup in this module goes through `exact_or_wildcard`, so an exact
/// entry disappearing while a `*` entry survives does not withdraw authority —
/// it hands the key to the wildcard, which is usually broader than the rule it
/// replaces. Rendering that as a removal tells the reviewer the opposite of
/// what they are approving, in the one artifact they are told to trust.
fn wildcard_successor<'a, T>(proposed: &'a BTreeMap<String, T>, key: &str) -> Option<&'a T> {
    if key == "*" {
        return None;
    }
    proposed.get("*")
}

fn find_spend<'a>(spends: &'a TokenSpends, token: &str) -> Option<&'a BigUint> {
    spends.get(token).or_else(|| {
        spends
            .iter()
            .find(|(address, _)| address.eq_ignore_ascii_case(token))
            .map(|(_, value)| value)
    })
}

fn key(address: Address) -> String {
    format!("{address:#x}")
}

fn normalize_address(raw: &str) -> Result<String> {
    let address = Address::from_str(raw).with_context(|| format!("invalid EVM address {raw}"))?;
    Ok(key(address))
}

fn normalize_address_or_wildcard(raw: &str) -> Result<String> {
    if raw == "*" {
        Ok("*".into())
    } else {
        normalize_address(raw)
    }
}

fn validate_decimal(value: &str) -> Result<()> {
    ensure!(
        value == "0" || (!value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())),
        "invalid canonical decimal quantity {value}"
    );
    // Length before value. `BigUint::from_str` is superlinear in radix 10, and
    // a canonical uint256 is at most `MAX_UINT256.len()` digits — so anything
    // longer is refused by the comparison below anyway, after being parsed.
    // There is one of these per token, per spender-token, and per chain in a
    // policy document, so the parse is not paid once.
    ensure!(
        value.len() <= MAX_UINT256.len(),
        "decimal quantity must fit uint256"
    );
    let parsed = BigUint::from_str(value).context("invalid decimal quantity")?;
    let maximum = BigUint::from_str(MAX_UINT256).unwrap();
    ensure!(parsed <= maximum, "decimal quantity must fit uint256");
    Ok(())
}

fn validate_chain_key(value: &str) -> Result<()> {
    if value == "*" {
        return Ok(());
    }
    ensure!(
        value == "0" || (!value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())),
        "invalid chain policy key {value}"
    );
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

fn validate_url(value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        url::Url::parse(value).context("invalid policy schema URL")?;
    }
    Ok(())
}

fn exceeds_limit(value: &BigUint, maximum: &str) -> bool {
    value > &BigUint::from_str(maximum).expect("validated policy maximum")
}

fn zero() -> String {
    "0".into()
}

fn max_uint256() -> String {
    MAX_UINT256.into()
}

const fn policy_version() -> u8 {
    2
}

const fn default_max_calls() -> u32 {
    16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::execution_plan::ExecutionPlan;
    use serde_json::json;

    fn transfer_plan() -> ExecutionPlan {
        transfer_plan_of(U256::from(1_u8))
    }

    fn transfer_plan_of(amount: U256) -> ExecutionPlan {
        let data = format!(
            "0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333{amount:064x}"
        );
        ExecutionPlan::parse(json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": data,
                    "value": "0"
                }
            }]
        }))
        .unwrap()
    }

    fn wildcard_token_policy(limit: &str) -> WalletPolicy {
        WalletPolicy::parse(json!({
            "chains": {
                "1": {
                    "targets": { "*": { "allow_any_calldata": true } },
                    "tokens": {
                        "*": {
                            "max_spend_per_transaction": limit,
                            "transfer_recipients": { "*": {} }
                        }
                    }
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn removing_a_rule_under_a_wildcard_reads_as_widening_not_narrowing() {
        // Dropping the exact entry for a target while `*` survives does not
        // take the permission away — `exact_or_wildcard` hands the target to
        // the wildcard, which here allows any calldata rather than one
        // selector. A `-` line would tell the reviewer they were tightening
        // the policy while they approved the opposite.
        let current = WalletPolicy::parse(json!({
            "chains": {
                "1": {
                    "targets": {
                        "0x2222222222222222222222222222222222222222": {
                            "allowed_selectors": { "0xa9059cbb": {} }
                        },
                        "*": { "allow_any_calldata": true }
                    }
                }
            }
        }))
        .unwrap();
        let proposed = WalletPolicy::parse(json!({
            "chains": {
                "1": { "targets": { "*": { "allow_any_calldata": true } } }
            }
        }))
        .unwrap();

        let diff = diff_policies(&current, &proposed);
        assert!(
            diff.iter().any(|line| line.contains("falls back to (*)")),
            "{diff:?}"
        );
        assert!(
            !diff
                .iter()
                .any(|line| line.starts_with("- chain 1: target 0x2222")),
            "a widening was rendered as a removal: {diff:?}"
        );
    }

    #[test]
    fn every_level_that_falls_back_says_so() {
        // Approval spenders, the tokens under them, and transfer recipients
        // all resolve through the same wildcard fallback, so all three have
        // to describe a removal that widens as a widening.
        let current = WalletPolicy::parse(json!({
            "chains": { "1": {
                "approval_spenders": {
                    "0x3333333333333333333333333333333333333333": {
                        "tokens": { "0x4444444444444444444444444444444444444444": { "max_amount": "5" } }
                    },
                    "*": { "tokens": { "*": { "max_amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935" } } }
                },
                "tokens": { "0x5555555555555555555555555555555555555555": {
                    "max_spend_per_transaction": "10",
                    "transfer_recipients": {
                        "0x6666666666666666666666666666666666666666": {},
                        "*": {}
                    }
                } }
            } }
        }))
        .unwrap();
        let proposed = WalletPolicy::parse(json!({
            "chains": { "1": {
                "approval_spenders": {
                    "*": { "tokens": { "*": { "max_amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935" } } }
                },
                "tokens": { "0x5555555555555555555555555555555555555555": {
                    "max_spend_per_transaction": "10",
                    "transfer_recipients": { "*": {} }
                } }
            } }
        }))
        .unwrap();

        let diff = diff_policies(&current, &proposed);
        let widenings = diff
            .iter()
            .filter(|line| line.contains("falls back"))
            .count();
        assert_eq!(widenings, 2, "{diff:?}");
        assert!(
            !diff.iter().any(|line| line.starts_with("- chain 1:")),
            "a widening was rendered as a removal: {diff:?}"
        );
    }

    #[test]
    fn removing_a_rule_with_no_wildcard_is_still_a_removal() {
        let current = WalletPolicy::parse(json!({
            "chains": {
                "1": {
                    "targets": {
                        "0x2222222222222222222222222222222222222222": {
                            "allow_any_calldata": true
                        }
                    }
                }
            }
        }))
        .unwrap();
        let proposed = WalletPolicy::parse(json!({ "chains": { "1": {} } })).unwrap();
        let diff = diff_policies(&current, &proposed);
        assert!(
            diff.iter().any(|line| line.starts_with("- chain 1:")),
            "{diff:?}"
        );
    }

    #[test]
    fn a_wildcard_token_rule_bounds_what_a_transfer_declares() {
        // A token whose Transfer event is not the canonical three-topic shape
        // produces no observed spend, and `*` is excluded from the balance
        // probes, so there was nothing for the limit to be measured against.
        // That made naming a token strictly stronger than covering it with a
        // wildcard — the opposite of what writing `*` reads like.
        let policy = wildcard_token_policy("1000000");
        let findings = evaluate_policy(
            &transfer_plan_of(U256::from(2_000_000_u64)),
            &policy,
            Some(&BTreeMap::new()),
        );
        assert!(!policy_allows(&findings), "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "token_spend_limit"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_transfer_within_the_wildcard_limit_still_passes() {
        let policy = wildcard_token_policy("1000000");
        let findings = evaluate_policy(
            &transfer_plan_of(U256::from(1_000_000_u64)),
            &policy,
            Some(&BTreeMap::new()),
        );
        assert!(policy_allows(&findings), "{findings:?}");
    }

    #[test]
    fn default_policy_allows_transfer_and_normalizes_keys() {
        let policy = WalletPolicy::allow_all_with_approval();
        let spends = BTreeMap::from([(
            "0x2222222222222222222222222222222222222222".into(),
            BigUint::from(1_u8),
        )]);
        assert!(policy_allows(&evaluate_policy(
            &transfer_plan(),
            &policy,
            Some(&spends)
        )));
    }

    #[test]
    fn exact_chain_replaces_wildcard() {
        let policy = WalletPolicy::parse(json!({
            "chains": {
                "*": { "targets": { "*": { "allow_any_calldata": true } } },
                "1": {}
            }
        }))
        .unwrap();
        assert!(!policy_allows(&evaluate_policy(
            &transfer_plan(),
            &policy,
            Some(&BTreeMap::new())
        )));
    }

    #[test]
    fn a_policy_written_against_the_retired_simulation_switch_still_opens() {
        // Simulation is unconditional now. A stored policy that still carries
        // the old field must keep parsing — failing here would lock the owner
        // out of their own wallet — and the field must not survive the parse
        // in either direction.
        for setting in [true, false] {
            let policy = WalletPolicy::parse(json!({
                "chains": { "1": { "tokens": { "*": {} } } },
                "require_simulation": setting
            }))
            .expect("a retired setting is discarded, not rejected");
            let round_trip = serde_json::to_value(&policy).unwrap();
            assert!(round_trip.get("require_simulation").is_none());
        }
    }

    #[test]
    fn a_policy_written_against_the_retired_approval_expiry_still_opens() {
        // Queued requests no longer expire, and no policy setting can give
        // them a deadline again. A stored policy that still carries the old
        // field — top level, per chain, or both — must keep parsing, because
        // failing here would lock the owner out of their own wallet, and the
        // field must not survive the parse in either direction.
        let policy = WalletPolicy::parse(json!({
            "chains": {
                "1": { "tokens": { "*": {} }, "approval_expiry_seconds": 300 },
                "*": { "approval_expiry_seconds": 60 }
            },
            "approval_expiry_seconds": 600
        }))
        .expect("a retired setting is discarded, not rejected");
        let round_trip = serde_json::to_value(&policy).unwrap();
        assert!(round_trip.get("approval_expiry_seconds").is_none());
        for chain in round_trip["chains"].as_object().unwrap().values() {
            assert!(chain.get("approval_expiry_seconds").is_none());
        }
    }

    #[test]
    fn policy_diff_is_minimized_and_permission_level() {
        let current = WalletPolicy::require_approval_for_everything();
        let proposed = WalletPolicy::parse(json!({
            "chains": {
                "*": {
                    "max_calls_per_batch": 1,
                    "native": { "max_value_per_transaction": "0" }
                },
                "1": {
                    "max_calls_per_batch": 4,
                    "native": { "max_value_per_transaction": "1000000000000000000" },
                    "approval_spenders": {
                        "0x000000000022d473030f116ddee9f6b43ac78ba3": {
                            "tokens": {
                                "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {
                                    "max_amount": "5000000"
                                }
                            }
                        }
                    },
                    "tokens": {
                        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {
                            "max_spend_per_transaction": "5000000",
                            "transfer_recipients": {
                                "0x3333333333333333333333333333333333333333": {}
                            }
                        }
                    }
                }
            }
        }))
        .unwrap();

        let diff = diff_policies(&current, &proposed);
        assert!(
            diff.iter()
                .any(|line| line.starts_with("+ chain 1:") && line.contains("native value up to"))
        );
        assert!(diff.iter().any(|line| {
            line.contains("approvals to spender 0x000000000022d473030f116ddee9f6b43ac78ba3")
                && line.contains("up to 5000000")
        }));
        assert!(diff.iter().any(|line| line.contains("transfer recipients")
            && line.contains("0x3333333333333333333333333333333333333333")));
        // The unchanged wildcard chain contributes nothing.
        assert!(!diff.iter().any(|line| line.contains("every chain (*)")));

        // Identical documents diff to an explicit no-change line.
        let unchanged = diff_policies(&current, &current);
        assert_eq!(unchanged.len(), 1);
        assert!(unchanged[0].contains("identical"));

        // Removing a grant shows as a removal, and unlimited reads as a word.
        let allow_all = WalletPolicy::allow_all_with_approval();
        let shrink = diff_policies(&allow_all, &current);
        assert!(
            shrink
                .iter()
                .any(|line| line.starts_with("- chain every chain (*)")
                    || line.starts_with("- chain"))
        );
        assert!(shrink.iter().any(|line| line.contains("unlimited")));
    }

    #[test]
    fn a_decimal_quantity_is_bounded_by_length_before_it_is_parsed() {
        // The largest canonical uint256 is 78 digits, so anything longer is
        // refused either way. What changes is the cost: `BigUint::from_str` is
        // superlinear in radix 10, and a policy carries one of these per token,
        // per spender-token, and per chain.
        assert!(validate_decimal(MAX_UINT256).is_ok());
        assert!(validate_decimal("0").is_ok());
        assert!(validate_decimal(&"9".repeat(MAX_UINT256.len() + 1)).is_err());
        // A value of the maximum length that is still above the ceiling is
        // caught by the comparison, as before.
        let over = "9".repeat(MAX_UINT256.len());
        assert!(validate_decimal(&over).is_err());
    }

    #[test]
    fn rejects_removed_stateful_daily_limits() {
        assert!(
            WalletPolicy::parse(json!({
                "chains": { "1": { "native": { "max_value_per_day": "1" } } }
            }))
            .is_err()
        );
        assert!(
            WalletPolicy::parse(json!({
                "chains": { "1": { "tokens": { "*": { "max_spend_per_day": "1" } } } }
            }))
            .is_err()
        );
    }
}
