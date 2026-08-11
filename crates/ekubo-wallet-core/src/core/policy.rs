//! The signing policy: an unordered set of rules over the calls a plan makes.
//!
//! A rule is a handful of optional [`Predicate`] slots — `to`, `from`, `value`,
//! `calldata` — and an effect. A slot left out constrains nothing; the slots
//! present are `AND`ed. There is no ordering and no precedence between rules of
//! the same effect, because the decision is a fold rather than a scan:
//!
//! * any matching `deny` rule rejects the call outright,
//! * otherwise any matching `allow` rule signs it automatically,
//! * otherwise nothing signs automatically and the call queues for a human.
//!
//! Those three lines are the three [`PolicyOutcome`]s, and the two negative
//! ones are not interchangeable: a `deny` forecloses — nothing signs it and
//! nothing queues — while matching no rule only withholds automatic signing
//! and leaves the question for the terminal.
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
use std::{collections::BTreeMap, str::FromStr};

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
    /// How this rule answers one call: every slot it constrains, conjoined.
    ///
    /// Three-valued, because an `allow` and a `deny` ask different questions
    /// of the same answer — see [`Match`]. An omitted slot constrains nothing
    /// and contributes `Yes`.
    fn evaluate(&self, call: &Call, context: &PolicyContext) -> Match {
        [
            (self.to.as_ref(), &call.to),
            (self.from.as_ref(), &call.from),
            (self.value.as_ref(), &call.value),
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
    /// the CLI tells the reviewer is authoritative.
    #[must_use]
    fn describe_change(&self, chain: &str, added: bool) -> String {
        let (marker, verb) = match (self.effect, added) {
            (Effect::Allow, true) => ('+', "starts allowing"),
            (Effect::Allow, false) => ('-', "stops allowing"),
            (Effect::Deny, true) => ('-', "starts denying"),
            (Effect::Deny, false) => ('+', "stops denying"),
        };
        format!(
            "{marker} chain {chain}: {verb}{}: {}",
            self.described_label(),
            self.described_constraints()
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChainPolicy {
    /// 1-160 characters, shown to the owner reviewing this chain's authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// How many calls one atomic batch may carry, 1 to 4096. A plan with more
    /// queues for human approval; it is not rejected.
    #[serde(default = "default_max_calls")]
    #[schemars(range(min = 1, max = 4096))]
    pub max_calls_per_batch: u32,
    /// Applied to every call independently, on top of whichever rule matched.
    /// A guard rather than a grant: no rule can widen it, and a call it
    /// refuses queues for human approval rather than being rejected. Omitted,
    /// it is `{"eq": "0"}`, so a document that never mentions native value
    /// never sends any. It is a `uint256` in wei.
    #[serde(default = "no_native_value")]
    pub native_value: Predicate,
    /// An unordered set. Order carries no meaning and deny always beats allow,
    /// so a rule can be read without reading the rules around it.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl ChainPolicy {
    /// The bounds this chain's own fields have to respect. Held here rather
    /// than in [`WalletPolicy::validate`] so that a `ChainPolicy` deserialized
    /// on its own — out of a config fragment, a test, a future caller — is
    /// checked by the same code that checks one reached through a document.
    fn validate(&self) -> Result<()> {
        ensure!(
            self.max_calls_per_batch > 0 && self.max_calls_per_batch <= 4096,
            "max_calls_per_batch must be between 1 and 4096"
        );
        validate_label(self.label.as_deref())?;
        self.native_value
            .check_applicable(&DynSolType::Uint(256))
            .context("native_value predicate is not applicable")?;
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }

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

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WalletPolicy {
    /// Optional URL of this schema, for editor completion only. Nothing is
    /// fetched from it.
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// The document format version. Must be 1.
    #[serde(default = "policy_version")]
    #[schemars(range(min = 1, max = 1))]
    pub version: u8,
    /// Canonical decimal chain ID (no leading zeros), or `"*"` for every
    /// chain. An exact entry replaces `"*"` for that chain outright rather
    /// than extending it, so a permission on one chain never reaches another.
    /// A chain with neither entry is ungoverned: its plans queue for human
    /// approval.
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

    /// The named entry point, kept because callers read better for it. It no
    /// longer carries the admission checks: deserializing a `WalletPolicy` at
    /// all runs them, so this and `serde_json::from_value` are the same door.
    pub fn parse(input: Value) -> Result<Self> {
        serde_json::from_value(input).context("invalid wallet policy")
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

    /// Everything that has to be true of a document before it may govern
    /// signing. Owned by the type rather than by one constructor, so there is
    /// no way to hold a `WalletPolicy` these checks have not passed.
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "policy document format version must be 1"
        );
        if let Some(url) = self.schema.as_deref() {
            url::Url::parse(url).context("invalid policy schema URL")?;
        }
        for (chain_id, chain) in &self.chains {
            validate_chain_key(chain_id)?;
            chain
                .validate()
                .with_context(|| format!("invalid policy for chain {chain_id}"))?;
        }
        Ok(())
    }
}

/// Deserialization is the admission boundary for every policy type.
///
/// The semantic checks — version, chain keys, the batch ceiling, label
/// lengths, and whether each predicate is applicable to the slot it sits in —
/// used to hang off `WalletPolicy::parse` alone. That left the derived
/// `Deserialize` as a second door into the same authority-bearing types:
/// `serde_json::from_value::<WalletPolicy>` produced a policy that had passed
/// nothing, and `evaluate_policy` then read `max_calls_per_batch` from it
/// without asking, so a directly deserialized `5000` authorized automatic
/// signing of a batch four thousand calls past the documented ceiling. The
/// same door admitted predicates never checked against their slots.
///
/// So the check moves onto the boundary every authority-bearing document
/// crosses. `WalletPolicy` deserializes through a private mirror and validates
/// the complete tree. `Rule` and `ChainPolicy` retain ordinary derived
/// deserialization: holding either fragment alone grants no authority, and
/// validating each fragment during its parse only made a full policy walk its
/// rules three times.
mod admission {
    use super::{ChainPolicy, WalletPolicy, policy_version};
    use serde::{Deserialize, Deserializer, de::Error as _};
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WalletPolicyFields {
        #[serde(rename = "$schema", default)]
        schema: Option<String>,
        #[serde(default = "policy_version")]
        version: u8,
        chains: BTreeMap<String, ChainPolicy>,
    }

    impl<'de> Deserialize<'de> for WalletPolicy {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let fields = WalletPolicyFields::deserialize(deserializer)?;
            let policy = Self {
                schema: fields.schema,
                version: fields.version,
                chains: fields.chains,
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
        //
        // The two effects read the same answer differently, and that asymmetry
        // is the point. An `allow` needs certainty: only `Yes` grants. A `deny`
        // needs only suspicion, so a call encoded past the point this policy
        // can decode it still trips the rule written to stop it. Reading both
        // as a plain boolean let an unreadable encoding slip a denied call
        // through whatever broader `allow` was also present.
        let mut allowed = false;
        let mut denied: Option<&Rule> = None;
        for rule in &chain.rules {
            let answer = rule.evaluate(&call, context);
            match rule.effect {
                Effect::Deny if answer.is_suspected() => denied = denied.or(Some(rule)),
                Effect::Allow if answer.is_match() => allowed = true,
                _ => {}
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

/// A token the policy sets a limit on did not answer `balanceOf`, so how much
/// of it this plan moves could not be established.
///
/// An error, because the alternative is enforcing a spending limit against a
/// number the wallet does not have. A token that reverts its probe and emits
/// no standard `Transfer` log used to disappear from the review entirely — the
/// change set came back empty and the document said "none detected" for a
/// transaction that moved it. Silence is the one thing this must not be.
///
/// Scoped to tokens the *policy* speaks about, which is what makes failing
/// closed proportionate: these are the ones an owner wrote a limit for, and an
/// unreadable balance is exactly the case where that limit cannot be honoured.
pub const TOKEN_BALANCE_UNVERIFIED_CODE: &str = "token_balance_unverified";

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
                "Stateless per-call signing policy. Every call in a plan is graded on its own \
                 against one chain's unordered rule set: any matching deny rule rejects the plan \
                 outright — nothing signs, nothing queues, and no approval overrides it — \
                 otherwise any matching allow rule signs it automatically, otherwise the plan \
                 queues for explicit human approval in the CLI. Every other refusal (no rule, the \
                 native_value guard, max_calls_per_batch, an ungoverned chain) queues the same \
                 way; only a deny rule forecloses. There are no amount limits, budgets, or spend \
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
        // What governs a chain is its own entry if it has one and the `"*"`
        // fallback otherwise, so a chain appearing in or vanishing from the map
        // is a change of parent rather than a change from nothing. Diffing the
        // literal entries alone described the wrong pair: a chain taking its
        // own rules read as "now governed" — as though it had been ungoverned —
        // and hid the fallback whose authority it was actually replacing.
        match (current.chains.get(key), proposed.chains.get(key)) {
            (None, Some(next)) => {
                if let Some(fallback) = (key != "*").then(|| current.chains.get("*")).flatten() {
                    lines.push(format!(
                        "~ chain {label}: stops following every chain (*) and takes its own rules"
                    ));
                    diff_chain(&mut lines, label, fallback, next);
                } else {
                    lines.push(format!(
                        "+ chain {label}: now governed, up to {} call(s) per batch, native value {}",
                        next.max_calls_per_batch,
                        next.native_value.describe()
                    ));
                    for rule in &next.rules {
                        lines.push(rule.describe_change(label, true));
                    }
                }
            }
            (Some(previous), None) => {
                if let Some(fallback) = (key != "*").then(|| proposed.chains.get("*")).flatten() {
                    lines.push(format!(
                        "~ chain {label}: loses its own rules and falls back to every chain (*)"
                    ));
                    diff_chain(&mut lines, label, previous, fallback);
                } else {
                    for rule in &previous.rules {
                        lines.push(rule.describe_change(label, false));
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
            lines.push(rule.describe_change(label, true));
        }
    }
    for rule in &previous.rules {
        if next.rules.contains(rule) {
            continue;
        }
        // `is_narrower_than` compares effects, so a surviving cover is always
        // the same kind of rule: a dropped allow can only be covered by a
        // wider allow, and a dropped deny only by a wider deny.
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
            lines.push(rule.describe_change(label, false));
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
