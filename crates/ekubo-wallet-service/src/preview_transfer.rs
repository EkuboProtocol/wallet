//! Read-only evidence snapshots. Tokens identify data, never authorization.
use anyhow::{Context as _, Result, ensure};
use ekubo_wallet_client::preview_page::{MAX_EVIDENCE_BYTES, PAGE_BYTES, PreviewPage};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

const LIFETIME: Duration = Duration::from_secs(60);
const MAX_TRANSFERS: usize = 16;

struct Snapshot {
    text: String,
    expires: Instant,
}

#[derive(Default)]
struct State {
    snapshots: BTreeMap<Uuid, Snapshot>,
    closed: bool,
}

#[derive(Clone, Default)]
pub(crate) struct PreviewTransfers(Arc<Mutex<State>>);

impl PreviewTransfers {
    pub(crate) fn clear(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.closed = true;
            state.snapshots.clear();
        }
    }

    pub(crate) fn begin(&self, text: String) -> Result<PreviewPage> {
        ensure!(
            !text.is_empty() && text.len() <= MAX_EVIDENCE_BYTES,
            "preview evidence exceeds transfer budget"
        );
        let id = Uuid::new_v4();
        let first = page(id, &text, 0)?;
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("preview transfer lock poisoned"))?;
        ensure!(!state.closed, "preview transfers are stopped");
        if first.text.len() == text.len() {
            return Ok(first);
        }
        let now = Instant::now();
        state.snapshots.retain(|_, snapshot| snapshot.expires > now);
        let used: usize = state
            .snapshots
            .values()
            .map(|snapshot| snapshot.text.len())
            .sum();
        ensure!(
            state.snapshots.len() < MAX_TRANSFERS
                && text.len() <= MAX_EVIDENCE_BYTES.saturating_sub(used),
            "preview transfer storage is busy"
        );
        state.snapshots.insert(
            id,
            Snapshot {
                text,
                expires: now + LIFETIME,
            },
        );
        let weak = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            tokio::time::sleep(LIFETIME).await;
            if let Some(state) = weak.upgrade()
                && let Ok(mut state) = state.lock()
            {
                state.snapshots.remove(&id);
            }
        });
        Ok(first)
    }

    pub(crate) fn read(&self, id: Uuid, offset: usize) -> Result<PreviewPage> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("preview transfer lock poisoned"))?;
        ensure!(!state.closed, "preview transfers are stopped");
        let snapshot = state
            .snapshots
            .get(&id)
            .context("preview transfer is unavailable")?;
        if snapshot.expires <= Instant::now() {
            state.snapshots.remove(&id);
            anyhow::bail!("preview transfer expired");
        }
        let page = page(id, &snapshot.text, offset)?;
        if offset + page.text.len() == page.total_bytes {
            state.snapshots.remove(&id);
        }
        Ok(page)
    }
}

fn page(id: Uuid, text: &str, offset: usize) -> Result<PreviewPage> {
    ensure!(
        offset < text.len() && text.is_char_boundary(offset),
        "invalid preview page offset"
    );
    let mut end = offset.saturating_add(PAGE_BYTES).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(PreviewPage {
        transfer_id: id,
        offset,
        total_bytes: text.len(),
        text: text[offset..end].to_owned(),
    })
}

#[cfg(test)]
#[path = "preview_transfer_test.rs"]
mod tests;
