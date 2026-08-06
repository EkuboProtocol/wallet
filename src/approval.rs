use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{fmt::Write as _, io::IsTerminal};
use uuid::Uuid;

/// The consequential operation presented to a human reviewer.
///
/// Every kind here is a moment the private key comes out of the credential
/// store, or leaves it for good. That is the boundary this whole review
/// exists to guard, and the reason it is worth reading: a prompt that also
/// appears before a saved alias or an edited RPC URL is a prompt people
/// learn to clear. Local configuration changes ask with
/// [`crate::tui::Confirmation`] instead.
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

/// One label/value pair in a human-readable approval summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalFact {
    pub label: String,
    pub value: String,
}

/// A server-authored snapshot of exactly what the user is being asked to approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub kind: ApprovalKind,
    pub title: String,
    pub summary: String,
    pub facts: Vec<ApprovalFact>,
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
            warnings: Vec::new(),
            digest: None,
        }
    }

    #[must_use]
    pub fn fact(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.facts.push(ApprovalFact {
            label: label.into(),
            value: value.into(),
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
/// way to sign past a policy denial or a failed simulation — demands one, so
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
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
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
#[async_trait]
pub trait ReviewPresenter: Send + Sync {
    async fn review_transaction(
        &self,
        request: &ApprovalRequest,
        simulation: &crate::simulation::SimulationResult,
    ) -> Result<ApprovalDecision>;
}

/// Polished terminal fallback for direct CLI use and MCP clients without app UI.
#[derive(Debug, Default, Clone, Copy)]
pub struct TerminalApprovalUi;

#[async_trait]
impl ApprovalUi for TerminalApprovalUi {
    async fn review(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        let request = request.clone();
        tokio::task::spawn_blocking(move || review_in_terminal(&request))
            .await
            .context("terminal approval task failed")?
    }
}

fn review_in_terminal(request: &ApprovalRequest) -> Result<ApprovalDecision> {
    ensure!(
        std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && std::io::stderr().is_terminal(),
        "approval requires an interactive terminal"
    );

    crate::tui::init_prompt_theme();
    crate::tui::intro("Ekubo Wallet approval");

    let mut body = terminal_safe(&request.summary);
    for fact in &request.facts {
        write!(
            body,
            "\n{}: {}",
            terminal_safe(&fact.label),
            terminal_safe(&fact.value)
        )?;
    }
    if let Some(digest) = &request.digest {
        write!(body, "\nDigest: {}", terminal_safe(digest))?;
    }
    write!(body, "\nRequest: {}", request.id)?;

    crate::tui::note(terminal_safe(&request.title), body);
    for warning in &request.warnings {
        crate::tui::warning(terminal_safe(warning));
    }

    // Two named outcomes rather than a yes/no: at a `(y/N)` prompt the safe
    // answer is the one you get by not reading, and the destructive one is a
    // single character away. Here both outcomes are spelled out, the cursor
    // starts on the one that signs nothing, and approving takes a deliberate
    // move onto it. Esc and Ctrl+C read as rejection for the same reason: an
    // approval must be explicit.
    let approved = crate::tui::pick(
        "Approve or reject this action?",
        vec![
            "Reject — nothing is signed or submitted".to_owned(),
            "Approve — sign this exact action".to_owned(),
        ],
        2,
    )?
    .is_some_and(|choice| choice == 1);
    if approved {
        crate::tui::outro("Approved; owner authentication is still required.");
        Ok(ApprovalDecision::Approved)
    } else {
        crate::tui::outro_cancel("Rejected. Nothing was signed or submitted.");
        Ok(ApprovalDecision::Rejected)
    }
}

use crate::render::terminal_safe_line as terminal_safe;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_terminal_control_sequences() {
        assert_eq!(terminal_safe("safe\u{1b}[31m\ntext"), "safe [31m text");
    }

    #[test]
    fn request_builder_preserves_review_data() {
        let request = ApprovalRequest::new(ApprovalKind::Transaction, "Transfer", "Send funds")
            .fact("Recipient", "0xabc")
            .warning("Simulation changed a token allowance")
            .digest("0x1234");

        assert_eq!(request.facts[0].label, "Recipient");
        assert_eq!(request.warnings.len(), 1);
        assert_eq!(request.digest.as_deref(), Some("0x1234"));
    }
}
