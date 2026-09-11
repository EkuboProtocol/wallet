//! Display-only dapp proposals with a single-use decision handle. Native proofs
//! and approved session scopes never enter the desktop's review state.

use crate::{
    authority::OwnerApi,
    desktop_owner::DesktopOwner,
    walletconnect::{ProposalCommand, ProposalPrompt},
};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_client::dapp_review::{DappChoice, DappReview};
use ekubo_wallet_core::approval::ReviewDocument;
use tokio::sync::oneshot;

pub struct DesktopDappPrompt {
    pub unselected_document: ReviewDocument,
    pub choices: Vec<DappChoice>,
    pub response: DappReviewResponse,
}

pub enum DappDecision {
    Approve { index: Option<usize> },
    Reject,
    Close,
}

pub struct DappReviewResponse {
    // Retain the original documents independently of mutable UI display data.
    review: Box<DappReview>,
    backend: Backend,
}

enum Backend {
    Local {
        response: oneshot::Sender<ProposalCommand>,
    },
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    Service,
}

impl DesktopDappPrompt {
    #[must_use]
    pub fn local(prompt: ProposalPrompt) -> Self {
        let review = DappReview {
            session_id: prompt.session_id,
            unselected_document: prompt.unselected_document,
            choices: prompt
                .choices
                .into_iter()
                .map(|choice| DappChoice {
                    account: choice.account,
                    document: choice.document,
                })
                .collect(),
        };
        Self::new(
            review,
            Backend::Local {
                response: prompt.response,
            },
        )
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[must_use]
    pub fn service(review: DappReview) -> Self {
        Self::new(review, Backend::Service)
    }

    fn new(review: DappReview, backend: Backend) -> Self {
        Self {
            unselected_document: review.unselected_document.clone(),
            choices: review.choices.clone(),
            response: DappReviewResponse {
                review: Box::new(review),
                backend,
            },
        }
    }
}

#[cfg_attr(
    not(any(target_os = "linux", target_os = "windows")),
    allow(
        clippy::match_single_binding,
        reason = "only the local backend exists on this platform"
    )
)]
impl DappReviewResponse {
    #[must_use]
    pub fn is_closed(&self) -> bool {
        match &self.backend {
            Backend::Local { response, .. } => response.is_closed(),
            // The service revalidates liveness and exact document identity at
            // decision time. Session events must also retire expired UI reviews.
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Backend::Service => false,
        }
    }

    /// Consume the handle exactly once. A transport failure is surfaced without
    /// retrying the decision; only the service can authorize its stored proposal.
    pub async fn respond(self, owner: &DesktopOwner, decision: DappDecision) -> Result<()> {
        match (self.backend, owner) {
            (Backend::Local { response }, DesktopOwner::Local(owner)) => {
                respond_local(owner, *self.review, response, decision).await
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            (Backend::Service, DesktopOwner::Service(owner)) => {
                crate::desktop_owner::service_review::with_connection(owner, async |owner| {
                    match decision {
                        DappDecision::Approve { index } => {
                            owner
                                .approve_dapp_review(
                                    &self.review,
                                    index.context(
                                        "Select an account before approving the connection.",
                                    )?,
                                )
                                .await
                        }
                        DappDecision::Reject => owner.reject_dapp_review(&self.review).await,
                        DappDecision::Close => owner.close_dapp_review(&self.review).await,
                    }
                })
                .await
            }
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            _ => anyhow::bail!("dapp review authority backend changed; review it again"),
        }
    }
}

async fn respond_local(
    owner: &OwnerApi,
    review: DappReview,
    response: oneshot::Sender<ProposalCommand>,
    decision: DappDecision,
) -> Result<()> {
    ensure!(
        !response.is_closed(),
        "The connection proposal is no longer active."
    );
    let command = match decision {
        DappDecision::Approve { index } => {
            let authorization = async {
                let index = index.context("Select an account before approving the connection.")?;
                let choice = review
                    .choices
                    .get(index)
                    .context("The selected account is no longer available.")?;
                let authorization = owner
                    .authorize_dapp_connection(&choice.document, &choice.account)
                    .await?;
                Ok::<_, anyhow::Error>((index, authorization))
            }
            .await;
            match authorization {
                Ok((index, authorization)) => ProposalCommand::Approve {
                    index,
                    authorization,
                },
                Err(error) => {
                    let _ = response.send(ProposalCommand::Reject);
                    return Err(error);
                }
            }
        }
        DappDecision::Reject => ProposalCommand::Reject,
        DappDecision::Close => ProposalCommand::Close,
    };
    response
        .send(command)
        .map_err(|_| anyhow::anyhow!("The connection proposal is no longer active."))
}

#[cfg(test)]
#[path = "desktop_dapp_review_test.rs"]
mod tests;
