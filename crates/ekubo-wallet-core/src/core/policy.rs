//! The signing policy: an ordered list of rules over the calls a plan makes.
//!
//! A rule is a handful of optional [`Predicate`] slots — `chain_id`, `to`, `native_value`,
//! `calldata` — and an effect. A slot left out constrains nothing; the slots
//! present are `AND`ed. Rules are scanned from top to bottom:
//!
//! * the first matching `deny` rejects the call outright,
//! * the first matching `allow` signs it automatically,
//! * reaching the end queues the plan for a human.
//!
//! Those three lines are the three [`PolicyOutcome`]s, and the two negative
//! ones are not interchangeable: a `deny` forecloses — nothing signs it and
//! nothing queues — while matching no rule only withholds automatic signing
//! and leaves the question for the desktop application.
//!
//! Order is authority. Admission rejects a later rule when an earlier rule can
//! be proven to cover all of its matches, so ineffective fallback rules cannot
//! hide behind a broad permission.
//!
//! Every predicate is decided from the execution plan's own bytes plus the
//! signing wallet address in [`PolicyContext`]. Nothing the RPC
//! reports — observed balances, transfer logs, gas, or whether the simulation
//! succeeded — reaches a policy decision, so a dishonest endpoint cannot relax
//! a rule by misreporting what a transaction did.
//!
//! There are no cumulative spending budgets here. A rule may constrain the
//! native value or an integer ABI argument of one call, but the same agent may
//! ask again immediately. Those predicates bound *which* calls may be made;
//! they do not promise a daily, weekly, or lifetime spending ceiling.

use crate::core::{
    execution_plan::ExecutionPlan,
    predicate::{Match, PolicyContext, Predicate},
};
use alloy::{
    dyn_abi::{DynSolType, DynSolValue},
    primitives::{U256, keccak256},
};
use anyhow::{Context, Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

#[derive(
    Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// A matching call signs automatically, with no prompt.
    Allow,
    /// A matching call is refused outright: nothing signs, nothing queues, and
    /// no approval can override it. Use it to foreclose something, not to gate
    /// it — a call no rule covers already queues for human approval.
    Deny,
}

/// One rule: a conjunction of predicate slots and the effect of matching them.
/// Every slot is optional and an absent slot constrains nothing, so a rule
/// naming only `to` covers every function that contract has, including any
/// batching entry point that forwards elsewhere.
// Constructible only by deserialization (which validates) or by this crate,
// because a `Rule` a caller can write field by field is a `Rule` whose slots
// were never checked against their types. See the `admission` module. Kept out
// of the doc comment deliberately: it would otherwise be copied into the
// shipped JSON schema, which speaks to policy authors rather than to callers.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Rule {
    pub effect: Effect,
    /// 1-160 characters, shown verbatim in the permission diff the owner
    /// reviews. Say what the rule is for, not what it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The canonical numeric EVM chain ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<Predicate>,
    /// The contract or recipient being called.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Predicate>,
    /// Native value attached to this call, in wei.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_value: Option<Predicate>,
    /// The call's calldata. `{"eq": "0x"}` is a plain native send; a
    /// `selector` predicate decodes it and constrains its arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calldata: Option<Predicate>,
}

impl Rule {
    /// How this rule answers one call: every slot it constrains, conjoined.
    ///
    /// Three-valued so a selector that cannot safely decode this calldata does
    /// not consume the call: `Unreadable` falls through to later rules just as
    /// `No` does. An omitted slot constrains nothing and contributes `Yes`.
    fn evaluate(&self, call: &Call, context: &PolicyContext) -> Match {
        [
            (self.chain_id.as_ref(), &call.chain_id),
            (self.to.as_ref(), &call.to),
            (self.native_value.as_ref(), &call.native_value),
            (self.calldata.as_ref(), &call.calldata),
        ]
        .into_iter()
        .fold(Match::Yes, |answer, (predicate, value)| {
            predicate.map_or(answer, |predicate| {
                answer.and(predicate.evaluate(value, context))
            })
        })
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
        if let Some(predicate) = &self.chain_id {
            slots.push(("chain_id", predicate, DynSolType::Uint(256)));
        }
        if let Some(predicate) = &self.to {
            slots.push(("to", predicate, DynSolType::Address));
        }
        if let Some(predicate) = &self.native_value {
            slots.push(("native_value", predicate, DynSolType::Uint(256)));
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
        slot_narrower(self.chain_id.as_ref(), other.chain_id.as_ref())
            && slot_narrower(self.to.as_ref(), other.to.as_ref())
            && slot_narrower(self.native_value.as_ref(), other.native_value.as_ref())
            && slot_narrower(self.calldata.as_ref(), other.calldata.as_ref())
    }

    /// One reviewable line describing the authority this rule grants or takes
    /// away. An unconstrained `calldata` slot is called out explicitly: a rule
    /// naming a target but nothing about what may be sent to it permits every
    /// function that target has, including any batching entry point that
    /// forwards to somewhere else entirely.
    #[must_use]
    pub fn describe(&self) -> String {
        let effect = match self.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        };
        format!(
            "{effect}{}: {}",
            self.described_label(),
            self.described_constraints()
        )
    }

    /// The calls this rule picks out, with no word about what it then does to
    /// them — shared by `describe` and `describe_change`, which disagree only
    /// about the verb in front.
    fn described_constraints(&self) -> String {
        let mut parts = Vec::new();
        if let Some(predicate) = &self.chain_id {
            parts.push(format!("chain ID {}", predicate.describe()));
        }
        parts.push(match &self.to {
            Some(predicate) => format!("to {}", predicate.describe()),
            None => "to any address".to_string(),
        });
        parts.push(match &self.calldata {
            Some(predicate) => predicate.describe(),
            None => "any calldata, including batched calls to other contracts".to_string(),
        });
        if let Some(predicate) = &self.native_value {
            parts.push(format!("native value {}", predicate.describe()));
        }
        parts.join("; ")
    }

    fn described_label(&self) -> String {
        self.label
            .as_ref()
            .map_or_else(String::new, |label| format!(" [{label}]"))
    }

    /// One diff line saying how this rule appearing or disappearing moves the
    /// authority the policy grants.
    ///
    /// The marker is the direction of that move, not which side of the set
    /// difference the rule landed on, because those are opposites for half the
    /// rules there are. A `deny` that disappears hands authority back and a
    /// `deny` that appears takes it away, so keying `+` to "present in the
    /// proposal" printed a widening under a minus sign — on the one surface
    /// the desktop review tells the owner is authoritative.
    #[must_use]
    fn describe_change(&self, position: usize, added: bool) -> String {
        let (marker, verb) = match (self.effect, added) {
            (Effect::Allow, true) => ('+', "starts allowing"),
            (Effect::Allow, false) => ('-', "stops allowing"),
            (Effect::Deny, true) => ('-', "starts denying"),
            (Effect::Deny, false) => ('+', "stops denying"),
        };
        format!(
            "{marker} rule {position}: {verb}{}: {}",
            self.described_label(),
            self.described_constraints()
        )
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WalletPolicy {
    /// Optional URL of this schema, for editor completion only. Nothing is
    /// fetched from it.
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// The document format version. Must be 1.
    #[schemars(range(min = 1, max = 1))]
    pub version: u8,
    /// First matching rule wins. If no rule matches a call, its plan requires
    /// explicit owner approval.
    #[schemars(length(max = 256))]
    pub rules: Vec<Rule>,
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
    chain_id: DynSolValue,
    to: DynSolValue,
    native_value: DynSolValue,
    calldata: DynSolValue,
}

impl Call {
    fn of(plan: &ExecutionPlan, step: &crate::core::execution_plan::ExecutionStep) -> Self {
        Self {
            chain_id: DynSolValue::Uint(plan.chain_id.value(), 256),
            to: DynSolValue::Address(step.transaction.to),
            native_value: DynSolValue::Uint(step.transaction.value.value(), 256),
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

    /// The named entry point, kept because callers read better for it. It no
    /// longer carries the admission checks: deserializing a `WalletPolicy` at
    /// all runs them, so this and `serde_json::from_value` are the same door.
    pub fn parse(input: Value) -> Result<Self> {
        serde_json::from_value(input).context("invalid wallet policy")
    }

    /// Everything signs automatically: one rule constraining nothing, and no
    /// native-value restriction.
    #[must_use]
    pub fn allow_anything() -> Self {
        Self {
            schema: None,
            version: 1,
            rules: vec![Rule {
                effect: Effect::Allow,
                label: Some("Every transaction call".into()),
                chain_id: None,
                to: None,
                native_value: None,
                calldata: None,
            }],
        }
    }

    /// Nothing signs automatically: no rules at all, so every call reaches the
    /// owner-approval fallback in the application.
    #[must_use]
    pub fn require_approval_for_everything() -> Self {
        Self {
            schema: None,
            version: 1,
            rules: Vec::new(),
        }
    }

    /// A matcher-free deny is the explicit owner switch that disables all
    /// transaction execution while leaving message review unchanged.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            schema: None,
            version: 1,
            rules: vec![Rule {
                effect: Effect::Deny,
                label: Some("Disable transaction signing".into()),
                chain_id: None,
                to: None,
                native_value: None,
                calldata: None,
            }],
        }
    }

    #[must_use]
    pub fn named_addresses(&self, chain_id: U256) -> Vec<alloy::primitives::Address> {
        let context = PolicyContext::default();
        let chain = DynSolValue::Uint(chain_id, 256);
        let mut literals = std::collections::BTreeSet::new();
        for rule in &self.rules {
            if rule
                .chain_id
                .as_ref()
                .is_none_or(|predicate| predicate.matches(&chain, &context))
                && let Some(predicate) = &rule.to
            {
                predicate.literals(&mut literals);
            }
        }
        literals
            .iter()
            .filter_map(|literal| alloy::primitives::Address::from_str(literal).ok())
            .collect()
    }

    /// Everything that has to be true of a document before it may govern
    /// signing. Owned by the type rather than by one constructor, so there is
    /// no way to hold a `WalletPolicy` these checks have not passed.
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "policy document format version must be 1"
        );
        ensure!(
            self.rules.len() <= 256,
            "a policy may contain at most 256 rules"
        );
        if let Some(url) = self.schema.as_deref() {
            url::Url::parse(url).context("invalid policy schema URL")?;
        }
        for (index, rule) in self.rules.iter().enumerate() {
            rule.validate()
                .with_context(|| format!("invalid rule {}", index + 1))?;
            if let Some((earlier, _)) = self.rules[..index]
                .iter()
                .enumerate()
                .find(|(_, earlier)| rule.is_narrower_than(earlier))
            {
                anyhow::bail!(
                    "rule {} is unreachable because earlier rule {} matches everything it could match",
                    index + 1,
                    earlier + 1
                );
            }
        }
        Ok(())
    }
}

/// Deserialization is the admission boundary for every policy type.
///
/// Semantic checks — version, labels, shadowing, and whether each predicate is
/// applicable to its slot — belong on deserialization rather than only on one
/// constructor. Otherwise `serde_json::from_value::<WalletPolicy>` would be a
/// second, unchecked door into an authority-bearing type.
///
/// So the check moves onto the boundary every authority-bearing document
/// crosses. `WalletPolicy` deserializes through a private mirror and validates
/// the complete tree. `Rule` retains ordinary derived deserialization: holding
/// a fragment alone grants no authority, and complete documents validate it.
mod admission {
    use super::{Rule, WalletPolicy};
    use serde::{Deserialize, Deserializer, de::Error as _};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WalletPolicyFields {
        #[serde(rename = "$schema", default)]
        schema: Option<String>,
        version: u8,
        rules: Vec<Rule>,
    }

    impl<'de> Deserialize<'de> for WalletPolicy {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let fields = WalletPolicyFields::deserialize(deserializer)?;
            let policy = Self {
                schema: fields.schema,
                version: fields.version,
                rules: fields.rules,
            };
            policy
                .validate()
                .map_err(|error| D::Error::custom(format!("{error:#}")))?;
            Ok(policy)
        }
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
    for step in &plan.ordered_steps {
        let call = Call::of(plan, step);
        let mut decision = None;
        for (index, rule) in policy.rules.iter().enumerate() {
            let answer = rule.evaluate(&call, context);
            if answer.is_match() {
                decision = Some((index, rule));
                break;
            }
        }
        match decision {
            Some((index, rule)) if rule.effect == Effect::Deny => findings.push(error(
                CALL_DENIED_CODE,
                format!(
                    "step {} to {} is denied by first matching rule {}: {}",
                    step.step,
                    step.transaction.to,
                    index + 1,
                    rule.describe()
                ),
                Some(step.step),
            )),
            Some(_) => {}
            None => findings.push(error(
                CALL_NOT_ALLOWED_CODE,
                format!(
                    "step {} to {} matches no policy rule on chain {}",
                    step.step, step.transaction.to, plan.chain_id
                ),
                Some(step.step),
            )),
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

/// This plan's EIP-7702 authorization would replace a delegation the account
/// already has to some other implementation.
///
/// Not a rule the owner wrote, and not a rule they can write: the policy
/// language speaks about calls, and this is the one thing a plan does that is
/// not one of its calls. A batch carries an authorization as a property of the
/// transaction envelope, so an allowlist covering every call in the batch says
/// nothing about it, and the account's code is what a batch changes most
/// durably — it outlives the batch whether or not the batch succeeds.
///
/// So it is an error finding, which makes the outcome `RequiresApproval` and
/// sends the plan to the person with the replacement named in the review. It
/// is deliberately not `CALL_DENIED_CODE`: replacing a delegation is a
/// legitimate thing to want, it is just not a thing that happens because two
/// transfers were allowlisted.
pub const DELEGATION_REPLACED_CODE: &str = "delegation_replaced";

/// This plan's EIP-7702 authorization would give the account a delegation it
/// does not currently have.
///
/// A warning rather than an error, because a first delegation is what every
/// account's first batch legitimately does and blocking it would mean no
/// unattended batch could ever run. It exists because the *only* disclosure
/// of a delegation used to be [`DELEGATION_REPLACED_CODE`], and whether that
/// fired was decided by one `get_code_at` answer from one endpoint. An
/// endpoint that reports empty code for an account that is in fact delegated
/// elsewhere turns a reviewed replacement into a silent one: the wallet still
/// signs the authorization, and the replacement still happens on chain, but
/// nothing in the document said a delegation was involved at all.
///
/// The document always states that an authorization is being signed, so a
/// reader can notice one they did not expect.
pub const DELEGATION_AUTHORIZED_CODE: &str = "delegation_authorized";

/// What the policy decided, and therefore what happens next.
///
/// The distinction between the two negative outcomes is the whole point. A
/// `deny` rule is the owner having spoken; nothing at signing time may talk
/// them out of it, or the rule was decoration. Matching no rule is the owner
/// having said nothing, which is a question rather than a refusal, so it is
/// exactly the case a human may still answer in the desktop application.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    /// Every call matched an `allow` rule and every guard was satisfied. This
    /// signs automatically, with no prompt.
    Allowed,
    /// Nothing in the policy covers some call. It cannot sign automatically,
    /// but a human may approve it in the desktop application.
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
                "Ordered stateless per-call signing policy. The first matching rule decides each \
                 call: allow signs automatically, deny rejects without queuing, and reaching the \
                 end requires explicit owner approval. Omitted matchers mean anything and present \
                 matchers are ANDed. Native-value comparisons are per-call conditions, not \
                 cumulative spending budgets."
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
/// Order is authority, so the diff reports every changed position rather than
/// treating rules as an unordered set.
#[must_use]
pub fn diff_policies(current: &WalletPolicy, proposed: &WalletPolicy) -> Vec<String> {
    let mut lines = Vec::new();
    let count = current.rules.len().max(proposed.rules.len());
    for index in 0..count {
        match (current.rules.get(index), proposed.rules.get(index)) {
            (Some(previous), Some(next)) if previous != next => {
                lines.push(format!(
                    "~ rule {} changed: {} → {}",
                    index + 1,
                    previous.describe(),
                    next.describe()
                ));
            }
            (None, Some(next)) => lines.push(next.describe_change(index + 1, true)),
            (Some(previous), None) => lines.push(previous.describe_change(index + 1, false)),
            _ => {}
        }
    }
    if lines.is_empty() {
        lines.push("No permission changes: the proposed policy is identical.".into());
    }
    lines
}

fn error(code: &str, message: String, step: Option<u32>) -> PolicyFinding {
    PolicyFinding {
        severity: FindingSeverity::Error,
        code: code.into(),
        message,
        step,
    }
}

fn validate_label(value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        let length = value.chars().count();
        ensure!(
            length > 0 && length <= 160,
            "labels must contain 1-160 characters"
        );
        ensure!(
            crate::sanitize::stripped_capped(value, 160) == value,
            "labels may not contain control, bidirectional, or invisible formatting characters"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "policy_test.rs"]
mod tests;
