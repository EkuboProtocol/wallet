use anyhow::{Result, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use uuid::Uuid;

/// The consequential operation presented to a human reviewer.
///
/// Every kind here is a moment the private key comes out of the credential
/// store, or leaves it for good. That is the boundary this whole review
/// exists to guard, and the reason it is worth reading: a prompt that also
/// appears before a saved alias or an edited RPC URL is a prompt people
/// learn to clear. Local configuration changes ask with
/// a terminal confirmation instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    Transaction,
    PolicyException,
    ExportPrivateKey,
    RemoveWallet,
    TypedDataSignature,
    MessageSignature,
}

/// One label/value pair in a human-readable approval summary. An empty label
/// continues the fact above it — calldata rows, for example — so a renderer
/// can indent continuations under one label instead of repeating it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalFact {
    pub label: String,
    pub value: String,
}

/// One titled group of facts in a review document: the calls of a plan, the
/// prepared transaction, the simulated balance changes. Sections exist so a
/// presenter can lay the document out — headings, aligned label columns —
/// without ever parsing labels; the content is still entirely
/// orchestrator-authored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSection {
    pub heading: String,
    pub facts: Vec<ApprovalFact>,
}

/// A server-authored snapshot of exactly what the user is being asked to approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub kind: ApprovalKind,
    pub title: String,
    pub summary: String,
    /// Header facts that identify the request, before any section.
    pub facts: Vec<ApprovalFact>,
    #[serde(default)]
    pub sections: Vec<ApprovalSection>,
    pub warnings: Vec<String>,
    pub digest: Option<String>,
}

impl ApprovalRequest {
    #[must_use]
    pub fn new(kind: ApprovalKind, title: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            kind,
            title: title.into(),
            summary: summary.into(),
            facts: Vec::new(),
            sections: Vec::new(),
            warnings: Vec::new(),
            digest: None,
        }
    }

    /// Add a fact to the open section, or to the header facts while no
    /// section has been started. The builder reads top to bottom like the
    /// finished document does.
    #[must_use]
    pub fn fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        let fact = ApprovalFact {
            label: label.into(),
            value: value.into(),
        };
        match self.sections.last_mut() {
            Some(section) => section.facts.push(fact),
            None => self.facts.push(fact),
        }
        self
    }

    /// Start a new titled section; subsequent facts belong to it.
    #[must_use]
    pub fn section(mut self, heading: impl Into<String>) -> Self {
        self.sections.push(ApprovalSection {
            heading: heading.into(),
            facts: Vec::new(),
        });
        self
    }

    #[must_use]
    pub fn warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    #[must_use]
    pub fn digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

/// Proof that a live human is present at an interactive terminal.
///
/// This is a capability, not a flag: it cannot be cloned, has no default,
/// and its only production constructor requires stdin, stdout, and stderr to
/// all be terminals. [`crate::execution::SigningOverrides::human`] — the only
/// way to sign a plan no policy rule covers, or one whose simulation failed —
/// demands one, so
/// no headless caller (the MCP server runs over stdio pipes) can mint the
/// overrides at all. Grep for `from_terminal` to enumerate every place a
/// human override can originate.
pub struct InteractiveProof(());

impl InteractiveProof {
    /// The only production constructor.
    pub fn from_terminal() -> Result<Self> {
        ensure!(
            std::io::stdin().is_terminal()
                && std::io::stdout().is_terminal()
                && std::io::stderr().is_terminal(),
            "this operation requires an interactive terminal"
        );
        Ok(Self(()))
    }

    /// Tests exercise the human path without a terminal.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use]
    pub fn for_tests() -> Self {
        Self(())
    }
}

/// Presents a server-authored request. It never receives signing material.
#[async_trait]
pub trait ApprovalUi: Send + Sync {
    async fn review(&self, request: &ApprovalRequest) -> Result<ApprovalDecision>;
}

/// Presents one transaction review — the complete server-authored document
/// plus the fresh simulation — and returns the decision. UI-neutral: the
/// terminal is one implementation; a future approval surface is another
/// adapter. A presenter never receives key material or store handles, and
/// never authors review content — the orchestrator builds the document, the
/// presenter only shows it.
///
/// `refresh` re-runs the simulation on demand. A presenter is free to ignore
/// it — a non-interactive one has nobody to ask — but a reviewer looking at a
/// document that failed to simulate has no other way to find out whether the
/// reason has passed.
#[async_trait]
pub trait ReviewPresenter: Send + Sync {
    async fn review_transaction(
        &self,
        request: &ApprovalRequest,
        simulation: &crate::simulation::SimulationResult,
        refresh: &dyn ReviewRefresh,
    ) -> Result<ApprovalDecision>;
}

/// Re-runs the simulation behind a review and re-authors its document.
///
/// This exists because a queued transaction is not queued only for reasons
/// about itself. A plan reaches review when its simulation failed, and that
/// failure is often about the moment rather than the plan: every configured
/// RPC endpoint was refusing requests, or the plan depends on an approval
/// that has since been mined. Without this, the reviewer's only options are
/// to approve a transaction nobody could simulate or to reject a transaction
/// that is fine, and both answers are guesses.
///
/// A refresh re-simulates **the same plan under the same policy revision**.
/// It cannot change what is being approved — the plan's digest and the policy
/// it is judged against are fixed when the request is queued — so the only
/// thing that can differ is what the chain now says about it. The
/// orchestrator signs whatever the last refresh produced, so what a reviewer
/// approved is what gets signed rather than a simulation they never saw.
#[async_trait]
pub trait ReviewRefresh: Send + Sync {
    async fn resimulate(&self) -> Result<Refreshed>;
}

/// One re-authored review: the new document and the simulation behind it.
#[derive(Clone, Debug)]
pub struct Refreshed {
    pub request: ApprovalRequest,
    pub simulation: crate::simulation::SimulationResult,
}

/// A refresh handle for presenters and tests that have nothing to re-run.
///
/// Answering "the review cannot be refreshed here" as an error keeps the
/// alternative — quietly returning the same document — from reading to a
/// reviewer as a refresh that found nothing changed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRefresh;

#[async_trait]
impl ReviewRefresh for NoRefresh {
    async fn resimulate(&self) -> Result<Refreshed> {
        anyhow::bail!("this review cannot be re-simulated")
    }
}

#[cfg(test)]
#[path = "approval_test.rs"]
mod tests;
