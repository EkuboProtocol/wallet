use crate::core::execution_plan::ExecutionPlan;
use alloy::primitives::{Address, U256};
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
    #[serde(default = "zero")]
    pub max_spend_per_day: String,
    #[serde(default)]
    pub transfer_recipients: BTreeMap<String, NamedAddressPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativePolicy {
    #[serde(default = "zero")]
    pub max_value_per_transaction: String,
    #[serde(default = "zero")]
    pub max_value_per_day: String,
}

impl Default for NativePolicy {
    fn default() -> Self {
        Self {
            max_value_per_transaction: zero(),
            max_value_per_day: zero(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_expiry_seconds: Option<u32>,
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
    #[serde(default = "default_approval_expiry")]
    pub approval_expiry_seconds: u32,
    #[serde(default = "default_true")]
    pub require_simulation: bool,
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
    pub fn parse(input: Value) -> Result<Self> {
        let mut policy: Self = serde_json::from_value(input).context("invalid wallet policy")?;
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
                approval_expiry_seconds: None,
                max_calls_per_batch: 4096,
                native: NativePolicy {
                    max_value_per_transaction: max_uint256(),
                    max_value_per_day: max_uint256(),
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
                        max_spend_per_day: max_uint256(),
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
            approval_expiry_seconds: 600,
            require_simulation: true,
        }
    }

    #[must_use]
    pub fn chain(&self, chain_id: &str) -> Option<&ChainPolicy> {
        self.chains.get(chain_id).or_else(|| self.chains.get("*"))
    }

    #[must_use]
    pub fn approval_expiry_seconds(&self, chain_id: &str) -> u32 {
        self.chain(chain_id)
            .and_then(|chain| chain.approval_expiry_seconds)
            .unwrap_or(self.approval_expiry_seconds)
    }

    fn normalize_and_validate(&mut self) -> Result<()> {
        ensure!(
            self.version == 2,
            "policy document format version must be 2"
        );
        ensure!(
            self.approval_expiry_seconds > 0,
            "approval expiry must be positive"
        );
        validate_url(self.schema.as_deref())?;
        let mut chains = BTreeMap::new();
        for (chain_id, mut chain) in std::mem::take(&mut self.chains) {
            validate_chain_key(&chain_id)?;
            ensure!(
                chain.max_calls_per_batch > 0 && chain.max_calls_per_batch <= 4096,
                "max_calls_per_batch must be between 1 and 4096"
            );
            if let Some(expiry) = chain.approval_expiry_seconds {
                ensure!(expiry > 0, "approval expiry must be positive");
            }
            validate_label(chain.label.as_deref())?;
            validate_decimal(&chain.native.max_value_per_transaction)?;
            validate_decimal(&chain.native.max_value_per_day)?;
            normalize_target_map(&mut chain.targets)?;
            normalize_spender_map(&mut chain.approval_spenders)?;
            normalize_token_map(&mut chain.tokens, self.require_simulation)?;
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
                plan,
                step.step,
                &mut findings,
            );
        } else if data.len() >= 68 && data[..4] == [0xa9, 0x05, 0x9c, 0xbb] {
            let recipient = Address::from_slice(&data[16..36]);
            evaluate_transfer(
                chain,
                step.transaction.to,
                recipient,
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

fn evaluate_approval(
    chain: &ChainPolicy,
    token: Address,
    spender: Address,
    amount: U256,
    plan: &ExecutionPlan,
    step: u32,
    findings: &mut Vec<PolicyFinding>,
) {
    let spender_key = key(spender);
    let Some(spender_rule) = exact_or_wildcard(&chain.approval_spenders, &spender_key) else {
        findings.push(error(
            "approval_spender_not_allowed",
            format!(
                "{spender} is not an allowed approval spender on chain {}",
                plan.chain_id
            ),
            Some(step),
        ));
        return;
    };
    let token_key = key(token);
    let Some(token_rule) = exact_or_wildcard(&spender_rule.tokens, &token_key) else {
        findings.push(error(
            "approval_token_not_allowed",
            format!(
                "{spender} may not receive approvals for token {token} on chain {}",
                plan.chain_id
            ),
            Some(step),
        ));
        return;
    };
    let amount = BigUint::from_bytes_be(&amount.to_be_bytes::<32>());
    if exceeds_limit(&amount, &token_rule.max_amount) {
        findings.push(error(
            "approval_amount_limit",
            format!(
                "{token} approval {amount} exceeds {} for {spender} on chain {}",
                token_rule.max_amount, plan.chain_id
            ),
            Some(step),
        ));
    }
}

fn evaluate_transfer(
    chain: &ChainPolicy,
    token: Address,
    recipient: Address,
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

fn normalize_token_map(
    map: &mut BTreeMap<String, TokenPolicy>,
    require_simulation: bool,
) -> Result<()> {
    let mut output = BTreeMap::new();
    for (raw, mut rule) in std::mem::take(map) {
        ensure!(require_simulation, "token spend limits require simulation");
        validate_label(rule.label.as_deref())?;
        validate_decimal(&rule.max_spend_per_transaction)?;
        validate_decimal(&rule.max_spend_per_day)?;
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

const fn default_approval_expiry() -> u32 {
    600
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::execution_plan::ExecutionPlan;
    use serde_json::json;

    fn transfer_plan() -> ExecutionPlan {
        ExecutionPlan::parse(json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "submit_condition": "always",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0xa9059cbb00000000000000000000000033333333333333333333333333333333333333330000000000000000000000000000000000000000000000000000000000000001",
                    "value": "0"
                }
            }]
        })).unwrap()
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
    fn token_rules_require_simulation() {
        assert!(
            WalletPolicy::parse(json!({
                "chains": { "1": { "tokens": { "*": {} } } },
                "require_simulation": false
            }))
            .is_err()
        );
    }
}
