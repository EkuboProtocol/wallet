//! Where a plan came from, and the rules that may constrain it.
//!
//! Every other policy matcher reads the plan's own bytes or the envelope
//! prepared to carry them. This one reads neither: it reads which adapter
//! handed the plan to core, and the small amount each adapter knows about
//! whoever asked. That is a different kind of fact and it is kept in a
//! different type for exactly that reason.
//!
//! # Proved and claimed are not the same word
//!
//! The channel is proved. Core is the thing being called, so it knows whether
//! `execute_automatic` was reached from the `WalletConnect` handler, an MCP
//! tool, or the automation scheduler; nothing a requester says can change
//! that. An automation's id is proved the same way — the scheduler is naming
//! a row the owner installed. A plan's host is proved by TLS in
//! [`crate::plan_fetch`].
//!
//! A dapp's domain and an agent's client are **claims**. `AppMetadata.url` is
//! typed by whoever wrote the dapp, and the harness kind is the `--client`
//! argument a local process passed to the stdio bridge. Both are useful and
//! neither is evidence. Two consequences the owner has to hold onto, both of
//! them written into `docs/policy-authoring.md` as well:
//!
//! * A `deny` on "any agent that is not Codex" is escaped by claiming Codex,
//!   and an `allow` for Codex is available to anything that says so. The
//!   threat model puts a same-user process in scope and grants it the local
//!   MCP IPC by design, so this separates honest harnesses from each other,
//!   not an attacker from the wallet.
//! * A domain is chosen by the dapp when it proposes a session. A rule naming
//!   one is only as good as the owner's care at the pairing screen that
//!   approved it.
//!
//! Because of that, the claimed fields are documented as claims everywhere
//! they surface: in this module, in the JSON Schema, and in the sentence
//! [`SourceMatcher::describe`] puts in the permission diff the owner reads.
//!
//! # Absence is a non-match
//!
//! A matcher that names a field at all — even as `any_value` — requires the
//! request to carry that field. A plan with no agent claim does not match
//! `{"agent": {"client": "any_value"}}`. This is what
//! [`crate::core::policy::Rule`]'s `delegation` slot already does for an
//! envelope with no authorization, and it has the property that matters:
//! adding a source matcher to a rule can only ever shrink what that rule
//! matches. So constraining an existing `allow` by source is provably a
//! tightening, and a permission that exists *only* because of a claim is a
//! widening that already demands owner authentication.

use crate::core::predicate::{Match, PolicyContext, StringPredicate};
use alloy::dyn_abi::DynSolValue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What core knows about who asked for one plan.
///
/// Constructed by the adapter that received the request and passed to
/// [`evaluate_policy`](crate::core::policy::evaluate_policy) beside the plan.
/// Deliberately not part of [`PolicyContext`], which resolves literals and
/// holds one address; this is a matched subject, like the prepared envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestSource {
    /// Nothing declared where this came from. Every [`SourceMatcher`] answers
    /// [`Match::No`], so a rule constraining the source never covers it.
    ///
    /// Reached by a pending row stored before this field existed, and by any
    /// caller that has not been taught to name itself. Both are the same
    /// situation from the policy's point of view: the wallet does not know,
    /// and a rule that assumed it did would be deciding on nothing.
    #[default]
    Unknown,
    /// A request from a dapp over a settled `WalletConnect` session.
    #[serde(rename = "walletconnect")]
    WalletConnect {
        /// Host of the URL the dapp gave for itself, lowercased. **Claimed.**
        /// Absent when the dapp named no URL or gave one that will not parse.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        domain: Option<String>,
    },
    /// A request from an MCP client over the local bridge.
    Agent {
        /// The harness kind the bridge passed on its `--client` argument.
        /// **Claimed.** Absent when nothing named one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client: Option<String>,
        /// Host that served the plan artifact, proved by TLS in
        /// [`crate::plan_fetch`]. Absent for a plan that was never fetched —
        /// one given inline, in particular — which is why constraining it is
        /// also how a rule refuses an inline plan.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plan_host: Option<String>,
    },
    /// A tick of an automation the owner installed.
    Automation {
        /// The installed automation's id. Proved: the scheduler is naming its
        /// own row.
        id: String,
    },
}

impl RequestSource {
    /// The `WalletConnect` source for a dapp claiming this URL.
    #[must_use]
    pub fn walletconnect(claimed_url: Option<&str>) -> Self {
        Self::WalletConnect {
            domain: claimed_url
                .and_then(|url| url::Url::parse(url).ok())
                .and_then(|url| url.host_str().map(str::to_lowercase)),
        }
    }

    /// The agent source for a bridge session and the artifact a plan came
    /// from.
    #[must_use]
    pub fn agent(claimed_client: Option<&str>, plan_host: Option<&str>) -> Self {
        Self::Agent {
            client: claimed_client.map(str::to_owned),
            plan_host: plan_host.map(str::to_lowercase),
        }
    }

    /// The source for one automation's tick.
    #[must_use]
    pub fn automation(id: &str) -> Self {
        Self::Automation { id: id.to_owned() }
    }
}

/// One `WalletConnect` request, optionally narrowed by the dapp's claimed
/// domain.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletConnectSource {
    /// Host of the URL the dapp gives for itself, lowercased and without a
    /// scheme, port, or path — `app.example.org`. **Self-asserted by the dapp**
    /// in its session proposal and attested by nothing. Present and
    /// unconstrained (`any_value`) means the dapp named some parsable URL;
    /// absent from the matcher means the rule does not care.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<StringPredicate>,
}

/// One MCP request, optionally narrowed by the harness claim or the host that
/// served the plan.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentSource {
    /// The harness kind: `codex`, `claude_code`, `claude_desktop`,
    /// `gemini_cli`, `cursor`, `opencode`, `grok_build`. **Self-identified**
    /// by the process that launched the bridge and attested by nothing; any
    /// local process may pass any of these. Useful for keeping one agent's
    /// rules off another agent's requests, not as a barrier against a hostile
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<StringPredicate>,
    /// Host that served the execution plan, proved by TLS. A plan given
    /// inline has no host, so constraining this at all also means "not an
    /// inline plan".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_host: Option<StringPredicate>,
}

/// One automation tick, optionally narrowed to particular installed
/// automations.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AutomationSource {
    /// The installed automation's id. Proved: nothing outside the wallet
    /// chooses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<StringPredicate>,
}

/// Which channel a rule applies to, and what it requires of that channel.
///
/// Tagged by channel rather than a flat bag of fields, so the channel and the
/// fields that only exist within it cannot come apart. There is no way to
/// write an automation rule that also constrains a dapp domain: that
/// combination would parse as a flat bag and then match nothing, forever,
/// silently.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceMatcher {
    /// A dapp over `WalletConnect`.
    #[serde(rename = "walletconnect")]
    WalletConnect(WalletConnectSource),
    /// An MCP client over the local bridge.
    Agent(AgentSource),
    /// An installed automation's scheduled tick.
    Automation(AutomationSource),
}

impl SourceMatcher {
    /// How `source` answers this matcher.
    ///
    /// The channel has to agree first, and then every field the matcher names
    /// has to be present and satisfied. A named field the request does not
    /// carry is [`Match::No`] rather than a pass.
    #[must_use]
    pub fn evaluate(&self, source: &RequestSource, context: &PolicyContext) -> Match {
        match (self, source) {
            (Self::WalletConnect(matcher), RequestSource::WalletConnect { domain }) => {
                field(matcher.domain.as_ref(), domain.as_deref(), context)
            }
            (Self::Agent(matcher), RequestSource::Agent { client, plan_host }) => {
                field(matcher.client.as_ref(), client.as_deref(), context).and(field(
                    matcher.plan_host.as_ref(),
                    plan_host.as_deref(),
                    context,
                ))
            }
            (Self::Automation(matcher), RequestSource::Automation { id }) => {
                field(matcher.id.as_ref(), Some(id.as_str()), context)
            }
            _ => Match::No,
        }
    }

    /// True when every request this matcher accepts is accepted by `other`.
    /// Conservative: `false` means "cannot prove it", never "definitely not".
    #[must_use]
    pub fn is_narrower_than(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::WalletConnect(mine), Self::WalletConnect(theirs)) => {
                field_narrower(mine.domain.as_ref(), theirs.domain.as_ref())
            }
            (Self::Agent(mine), Self::Agent(theirs)) => {
                field_narrower(mine.client.as_ref(), theirs.client.as_ref())
                    && field_narrower(mine.plan_host.as_ref(), theirs.plan_host.as_ref())
            }
            (Self::Automation(mine), Self::Automation(theirs)) => {
                field_narrower(mine.id.as_ref(), theirs.id.as_ref())
            }
            _ => false,
        }
    }

    /// One clause for the permission diff, naming the channel and saying out
    /// loud which parts of it are the requester's own account of itself.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::WalletConnect(matcher) => match &matcher.domain {
                Some(predicate) => format!(
                    "requested over WalletConnect by a dapp claiming the domain {}",
                    predicate.describe()
                ),
                None => "requested over WalletConnect by any dapp".to_owned(),
            },
            Self::Agent(matcher) => {
                let mut parts = vec![match &matcher.client {
                    Some(predicate) => format!(
                        "requested by an agent self-identifying as {}",
                        predicate.describe()
                    ),
                    None => "requested by any agent".to_owned(),
                }];
                if let Some(predicate) = &matcher.plan_host {
                    parts.push(format!("from a plan served by {}", predicate.describe()));
                }
                parts.join(", ")
            }
            Self::Automation(matcher) => match &matcher.id {
                Some(predicate) => {
                    format!("run by the installed automation {}", predicate.describe())
                }
                None => "run by any installed automation".to_owned(),
            },
        }
    }
}

/// One field of a matcher against the fact the request carried.
///
/// An unconstrained field passes. A constrained field over a fact the request
/// does not have is [`Match::No`]: the rule asked about something that is not
/// there, which is a mismatch and not a doubt.
fn field(
    predicate: Option<&StringPredicate>,
    value: Option<&str>,
    context: &PolicyContext,
) -> Match {
    let Some(predicate) = predicate else {
        return Match::Yes;
    };
    let Some(value) = value else {
        return Match::No;
    };
    predicate.evaluate(&DynSolValue::String(value.to_owned()), context)
}

/// Field-wise coverage, with the same reading of absence the rule slots use:
/// a field nobody constrains covers a field somebody does.
fn field_narrower(mine: Option<&StringPredicate>, theirs: Option<&StringPredicate>) -> bool {
    match (mine, theirs) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(mine), Some(theirs)) => mine.is_narrower_than(theirs),
    }
}

#[cfg(test)]
#[path = "source_test.rs"]
mod tests;
