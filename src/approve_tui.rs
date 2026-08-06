//! The terminal implementation of the approval presentation seam.
//!
//! Everything here is presentation: the review document arrives fully
//! authored by the orchestrator, and the only output is a decision. The one
//! security property this module owns is the shape of the picker — two named
//! outcomes with the cursor starting on Reject, so approval always takes a
//! deliberate movement.

use crate::{
    approval::{ApprovalDecision, ApprovalRequest, ApprovalUi},
    sanitize::terminal_safe_line as terminal_safe,
};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use std::{fmt::Write as _, io::IsTerminal};

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
