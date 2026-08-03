use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt::Write as _, io::IsTerminal};
use uuid::Uuid;

/// The consequential operation presented to a human reviewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    Transaction,
    PolicyException,
    ExportPrivateKey,
    RemoveWallet,
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
    pub expires_at: DateTime<Utc>,
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
            expires_at: Utc::now() + TimeDelta::minutes(5),
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

/// Presents a server-authored request. It never receives signing material.
#[async_trait]
pub trait ApprovalUi: Send + Sync {
    async fn review(&self, request: &ApprovalRequest) -> Result<ApprovalDecision>;
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
    ensure!(Utc::now() < request.expires_at, "approval request expired");

    cliclack::intro("Ekubo Wallet approval")?;

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
    write!(
        body,
        "\nRequest: {}\nExpires: {}",
        request.id,
        request.expires_at.to_rfc3339()
    )?;

    cliclack::note(terminal_safe(&request.title), body)?;
    for warning in &request.warnings {
        cliclack::log::warning(terminal_safe(warning))?;
    }

    let approved = cliclack::confirm("Approve this action?")
        .initial_value(false)
        .interact()?;
    if approved {
        cliclack::outro("Approved; owner authentication is still required.")?;
        Ok(ApprovalDecision::Approved)
    } else {
        cliclack::outro_cancel("Rejected. Nothing was signed or submitted.")?;
        Ok(ApprovalDecision::Rejected)
    }
}

fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

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
        assert!(request.expires_at > Utc::now());
    }
}
