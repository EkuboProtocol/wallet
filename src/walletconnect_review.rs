//! Review channel shared by desktop and headless `WalletConnect` hosts.

use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_core::{
    approval::ReviewDocument, config::WalletMetadata, human_presence::DappAuthorization,
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use walletconnect_session::ApprovedScope;

pub struct ProposalChoice {
    pub account: WalletMetadata,
    pub scope: ApprovedScope,
    pub document: ReviewDocument,
}

pub struct ProposalPrompt {
    pub session_id: Uuid,
    /// The same review with the account left blank, for the state the window
    /// opens in. Drawing one of the `choices` instead would name an account the
    /// owner has not chosen, on the screen whose entire question is which
    /// account to expose.
    pub unselected_document: ReviewDocument,
    pub choices: Vec<ProposalChoice>,
    pub response: oneshot::Sender<ProposalCommand>,
}

pub enum ProposalCommand {
    Approve {
        index: usize,
        authorization: DappAuthorization,
    },
    Reject,
    Close,
}

#[derive(Clone)]
pub struct ProposalPresenter {
    sender: mpsc::UnboundedSender<ProposalPrompt>,
}

impl ProposalPresenter {
    #[must_use]
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<ProposalPrompt>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }

    pub async fn review(
        &self,
        session_id: Uuid,
        unselected_document: ReviewDocument,
        choices: Vec<ProposalChoice>,
    ) -> Result<ProposalCommand> {
        ensure!(
            !choices.is_empty(),
            "connection review has no account choices"
        );
        let (response, decision) = oneshot::channel();
        self.sender
            .send(ProposalPrompt {
                session_id,
                unselected_document,
                choices,
                response,
            })
            .map_err(|_| anyhow::anyhow!("the WalletConnect review UI is unavailable"))?;
        decision
            .await
            .context("the WalletConnect review window closed")
    }
}
