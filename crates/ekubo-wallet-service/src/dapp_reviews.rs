//! Service-owned dapp review queue. The client selects a stored document; only
//! core authentication can produce the proof delivered to the session handler.

use crate::{
    authority::OwnerApi,
    events::{DomainEventKind, EventBus},
    walletconnect_review::{ProposalCommand, ProposalPrompt},
};
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_client::dapp_review::{DappChoice, DappReview};
use ekubo_wallet_core::{
    approval::ReviewDocument, config::WalletMetadata, human_presence::DappAuthorization,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
};
use uuid::Uuid;

const MAX_REVIEWS: usize = 16;

#[derive(Default)]
struct State {
    pending: BTreeMap<Uuid, ProposalPrompt>,
    authenticating: BTreeSet<Uuid>,
    closed: bool,
}

#[derive(Clone, Default)]
pub struct DappReviews {
    state: Arc<Mutex<State>>,
}

struct Reservation {
    queue: DappReviews,
    session_id: Uuid,
}

struct CollectorLifetime(DappReviews);

impl Drop for CollectorLifetime {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.queue.state.lock() {
            state.authenticating.remove(&self.session_id);
        }
    }
}

impl DappReviews {
    /// One collector owns the channel for this broker's lifetime. Refresh only
    /// after insertion so the desktop cannot observe an event before its review.
    pub(crate) async fn collect(
        &self,
        mut incoming: tokio::sync::mpsc::UnboundedReceiver<ProposalPrompt>,
        events: EventBus,
    ) {
        let _lifetime = CollectorLifetime(self.clone());
        while let Some(prompt) = incoming.recv().await {
            let session_id = prompt.session_id;
            match self.insert(prompt) {
                Ok(()) => events.publish(DomainEventKind::WalletConnectChanged {
                    session_id: session_id.to_string(),
                }),
                Err(error) => tracing::warn!(%error, "dapp review could not be queued"),
            }
        }
    }

    /// Shutdown is terminal for this broker. Pending decisions close, and an
    /// authentication already in progress cannot deliver a later approval.
    pub fn shutdown(&self) -> Result<()> {
        let mut state = self.state()?;
        state.closed = true;
        state.pending.clear();
        Ok(())
    }

    fn state(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("dapp review queue lock was poisoned"))
    }

    pub(crate) fn insert(&self, prompt: ProposalPrompt) -> Result<()> {
        let mut state = self.state()?;
        ensure!(!state.closed, "dapp review broker is closed");
        state
            .pending
            .retain(|_, prompt| !prompt.response.is_closed());
        ensure!(
            !prompt.response.is_closed(),
            "dapp proposal is no longer active"
        );
        ensure!(
            !prompt.choices.is_empty(),
            "dapp proposal has no account choices"
        );
        ensure!(
            !state.pending.contains_key(&prompt.session_id)
                && !state.authenticating.contains(&prompt.session_id),
            "dapp session already has an active review"
        );
        ensure!(
            state.pending.len() + state.authenticating.len() < MAX_REVIEWS,
            "too many dapp reviews"
        );
        state.pending.insert(prompt.session_id, prompt);
        Ok(())
    }

    pub fn pending(&self) -> Result<Vec<DappReview>> {
        let mut state = self.state()?;
        state
            .pending
            .retain(|_, prompt| !prompt.response.is_closed());
        Ok(state
            .pending
            .values()
            .map(|prompt| DappReview {
                session_id: prompt.session_id,
                unselected_document: prompt.unselected_document.clone(),
                choices: prompt
                    .choices
                    .iter()
                    .map(|choice| DappChoice {
                        account: choice.account.clone(),
                        document: choice.document.clone(),
                    })
                    .collect(),
            })
            .collect())
    }

    fn take(
        &self,
        session_id: Uuid,
        index: Option<usize>,
        reviewed_identity: &str,
    ) -> Result<(ProposalPrompt, Reservation)> {
        let mut state = self.state()?;
        ensure!(!state.closed, "dapp review broker is closed");
        let prompt = state
            .pending
            .get(&session_id)
            .context("dapp proposal is no longer active")?;
        ensure!(
            !prompt.response.is_closed(),
            "dapp proposal is no longer active"
        );
        let document = if let Some(index) = index {
            &prompt
                .choices
                .get(index)
                .context("invalid dapp account choice")?
                .document
        } else {
            &prompt.unselected_document
        };
        ensure!(
            document.identity == reviewed_identity,
            "dapp proposal changed; review it again"
        );
        let prompt = state
            .pending
            .remove(&session_id)
            .expect("checked under the same lock");
        state.authenticating.insert(session_id);
        Ok((
            prompt,
            Reservation {
                queue: self.clone(),
                session_id,
            },
        ))
    }

    pub async fn approve(
        &self,
        owner: &OwnerApi,
        session_id: Uuid,
        index: usize,
        reviewed_identity: &str,
    ) -> Result<()> {
        self.approve_with(
            owner,
            session_id,
            index,
            reviewed_identity,
            |document, account| async move {
                owner.authorize_dapp_connection(&document, &account).await
            },
        )
        .await
    }

    async fn approve_with<F: std::future::Future<Output = Result<DappAuthorization>>>(
        &self,
        owner: &OwnerApi,
        session_id: Uuid,
        index: usize,
        reviewed_identity: &str,
        authenticate: impl FnOnce(ReviewDocument, WalletMetadata) -> F,
    ) -> Result<()> {
        let (prompt, _reservation) = self.take(session_id, Some(index), reviewed_identity)?;
        let choice = &prompt.choices[index];
        let authorization = async {
            verify_account(owner, &choice.account)?;
            let proof = authenticate(choice.document.clone(), choice.account.clone()).await?;
            verify_account(owner, &choice.account)?;
            Ok::<_, anyhow::Error>(proof)
        }
        .await;
        match authorization {
            Ok(authorization) => {
                // Serialize delivery with shutdown. A closing collector must
                // never leave a pending native challenge able to grant access.
                let state = self.state()?;
                ensure!(!state.closed, "dapp review broker is closed");
                prompt
                    .response
                    .send(ProposalCommand::Approve {
                        index,
                        authorization,
                    })
                    .map_err(|_| anyhow::anyhow!("dapp proposal is no longer active"))
            }
            Err(error) => {
                let _ = prompt.response.send(ProposalCommand::Reject);
                Err(error)
            }
        }
    }

    pub fn reject(&self, session_id: Uuid, reviewed_identity: &str) -> Result<()> {
        let (prompt, _reservation) = self.take(session_id, None, reviewed_identity)?;
        prompt
            .response
            .send(ProposalCommand::Reject)
            .map_err(|_| anyhow::anyhow!("dapp proposal is no longer active"))
    }

    pub fn close(&self, session_id: Uuid, reviewed_identity: &str) -> Result<()> {
        let (prompt, _reservation) = self.take(session_id, None, reviewed_identity)?;
        prompt
            .response
            .send(ProposalCommand::Close)
            .map_err(|_| anyhow::anyhow!("dapp proposal is no longer active"))
    }
}

fn verify_account(owner: &OwnerApi, reviewed: &WalletMetadata) -> Result<()> {
    let current = owner.account(&reviewed.id)?;
    ensure!(
        current.instance_id == reviewed.instance_id && current.address == reviewed.address,
        "selected account changed; review the dapp proposal again"
    );
    Ok(())
}

#[cfg(test)]
#[path = "dapp_reviews_test.rs"]
mod tests;
